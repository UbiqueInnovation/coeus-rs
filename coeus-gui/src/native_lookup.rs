//! Exact, immutable DEX lookups shared by concurrent inspection requests.
use super::*;

type PoolLocation = (usize, usize);

pub(super) struct LookupIndex {
    files: Vec<Arc<DexFile>>,
    methods: HashMap<String, Vec<PoolLocation>>,
    fields: HashMap<String, PoolLocation>,
    classes: HashMap<String, PoolLocation>,
    strings: HashMap<String, PoolLocation>,
    method_callers: Mutex<HashMap<String, Vec<PoolLocation>>>,
}

impl LookupIndex {
    pub(super) fn matches(&self, files: &Files) -> bool {
        let current: Vec<_> = files.multi_dex.iter().flat_map(|dex| std::iter::once(&dex.primary).chain(dex.secondary.iter())).collect();
        current.len() == self.files.len() && current.iter().zip(&self.files).all(|(left, right)| Arc::ptr_eq(left, right))
    }
    pub(super) fn new(files: &Files) -> Self {
        let mut index = Self {
            files: files.multi_dex.iter().flat_map(|dex| std::iter::once(dex.primary.clone()).chain(dex.secondary.clone())).collect(),
            methods: HashMap::new(), fields: HashMap::new(), classes: HashMap::new(), strings: HashMap::new(),
            method_callers: Mutex::new(HashMap::new()),
        };
        for (file_index, file) in index.files.iter().enumerate() {
            for (method_index, method) in file.methods.iter().enumerate() {
                index.methods.entry(signature(file, method)).or_default().push((file_index, method_index));
            }
            for (field_index, field) in file.fields.iter().enumerate() {
                let label = format!("{}->{}", file.get_type_name(field.class_idx).unwrap_or("UNKNOWN"), field.name);
                index.fields.entry(label).or_insert((file_index, field_index));
            }
            for (type_index, _) in file.types.iter().enumerate() {
                if let Some(name) = file.get_type_name(type_index) {
                    index.classes.entry(name.to_string()).or_insert((file_index, type_index));
                }
            }
            for (string_index, string) in file.strings.iter().enumerate() {
                index.strings.entry(string.to_str_lossy().into_owned()).or_insert((file_index, string_index));
            }
        }
        index
    }

    pub(super) fn find(&self, kind: &str, label: &str) -> Option<NativeObject> {
        let &(file_index, pool_index) = match kind {
            "methods" => self.methods.get(label).and_then(|locations| locations.first()),
            "fields" => self.fields.get(label),
            "classes" => self.classes.get(label),
            "strings" => self.strings.get(label),
            _ => None,
        }?;
        let file = &self.files[file_index];
        match kind {
            "methods" => method_object(file, &file.methods[pool_index]).map(NativeObject::Method),
            "fields" => Some(NativeObject::Field(field_object(file, &file.fields[pool_index]))),
            "classes" => Some(NativeObject::Class(ClassObject {
                class: file.get_class_by_type(pool_index as u16).unwrap_or_else(|| Arc::new(ModelClass {
                    dex_identifier: file.identifier.clone(), class_idx: pool_index as u32,
                    class_name: label.to_string(), ..Default::default()
                })), file: file.clone(),
            })),
            "strings" => Some(NativeObject::String(StringObject { index: pool_index as u32, content: label.to_string(), file: file.clone() })),
            _ => None,
        }
    }

    pub(super) fn callers(&self, method: &MethodObject) -> Vec<NativeObject> {
        let label = method.signature();
        let cached = self.method_callers.lock().expect("xref cache lock").get(&label).cloned();
        let callers = cached.unwrap_or_else(|| {
            // Resolve this signature once per DEX, then compare numeric pool
            // indexes while scanning. Cache only requested targets so the first
            // xref does not build a reverse index for the entire application.
            let mut callers = Vec::new();
            if let Some(targets) = self.methods.get(&label) {
                for (file_index, file) in self.files.iter().enumerate() {
                    let targets: HashSet<_> = targets.iter().filter(|(index, _)| *index == file_index)
                        .map(|(_, index)| *index as u16).collect();
                    if targets.is_empty() { continue; }
                    for class in &file.classes {
                        for caller in &class.codes {
                            let Some(code) = &caller.code else { continue; };
                            if code.insns.iter().any(|(_, _, instruction)|
                                invoke_method_index(instruction).is_some_and(|index| targets.contains(&index))) {
                                callers.push((file_index, caller.method.method_idx as usize));
                            }
                        }
                    }
                }
            }
            self.method_callers.lock().expect("xref cache lock").insert(label, callers.clone());
            callers
        });
        callers.iter().filter_map(|&(file_index, method_index)| {
            let file = &self.files[file_index];
            method_object(file, &file.methods[method_index]).map(NativeObject::Method)
        }).collect()
    }
}

fn signature(file: &DexFile, method: &ModelMethod) -> String {
    format!("{}->{}{}", file.get_type_name(method.class_idx).unwrap_or("UNKNOWN"), method.method_name, method.proto_name)
}

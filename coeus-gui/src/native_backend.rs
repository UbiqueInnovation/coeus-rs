//! Native Rust implementation of the GUI backend.
//!
//! The Python bridge remains available for compatibility and comparison.  This
//! module deliberately keeps the same JSON request/response contract so the UI
//! does not need to know which implementation is selected.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;
use std::fs;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use coeus::coeus_analysis::analysis::{
    self, find_any, find_classes, find_fields, find_methods, find_strings, Context, Evidence,
    Location, ALL_TYPES,
};
use coeus::coeus_debug::models::Value as DebugValue;
use coeus::coeus_debug::models::{Composite, Event, SlotValue, StackFrame};
use coeus::coeus_debug::Runtime;
use coeus::coeus_emulation::vm::{runtime::StringClass, Register, Value as EmulationValue, VM};
use coeus::coeus_models::models::{
    AccessFlags, Class as ModelClass, DexFile, Field as ModelField, Files, Instruction,
    Method as ModelMethod, MethodData, Proto, TestFunction,
};
use coeus::coeus_parse::apk;
use coeus::coeus_parse::dex::encode::{
    editable_instruction_from_decoded, ensure_dex_strings, replace_dex_string, rewrite_method_code,
    CodeTarget, EditPosition, EditableInstruction, MethodEdit, SwitchForm, TargetPosition,
};
use coeus::coeus_parse::dex::{parse_dex_buf, ArrayView};
use coeus::coeus_parse::signing;
use regex::Regex;
use serde_json::{json, Value};
use ux::u4;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

type BackendResult = Result<Value, String>;

const MAX_RESULTS: usize = 1000;

const ANDROID_FRAMEWORK_CLASS_FILTERS: &[&str] = &[
    "Landroid/app",
    "Landroid/content",
    "Landroid/graphics",
    "Landroid/os",
    "Landroid/text",
    "Landroid/util",
    "Landroid/view",
    "Landroid/widget",
    "Landroid/animation",
    "Landroid/transition",
];
const LANGUAGE_RUNTIME_CLASS_FILTERS: &[&str] = &[
    "Lj$/time",
    "Lj$/util/",
    "Lkotlin/",
    "Lkotlinx/",
    "Landroidx/",
    "Lcom/sun",
];
const COMMON_LIBRARY_CLASS_FILTERS: &[&str] = &[
    "Lcom/google/protobuf",
    "Lcom/google/android",
    "Lokhttp3/internal",
    "Lokio/",
    "Lmoshi/",
    "Lorg/bouncycastle/",
];

struct SupergraphBuildOptions {
    exclude_android_framework: bool,
    exclude_language_runtime: bool,
    exclude_common_libraries: bool,
    additional_class_filters: Vec<String>,
    discover_dynamic_arguments: bool,
    dynamic_argument_classes: Vec<String>,
}

impl SupergraphBuildOptions {
    fn from_request(request: &Value) -> Self {
        let split = |key: &str| {
            value_string(request, key)
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        };
        Self {
            exclude_android_framework: request
                .get("exclude_android_framework")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            exclude_language_runtime: request
                .get("exclude_language_runtime")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            exclude_common_libraries: request
                .get("exclude_common_libraries")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            additional_class_filters: split("ignore"),
            discover_dynamic_arguments: request
                .get("discover_dynamic_arguments")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            dynamic_argument_classes: split("dynamic_argument_classes"),
        }
    }

    fn excluded_classes(&self) -> Vec<String> {
        let mut excluded = Vec::new();
        if self.exclude_android_framework {
            excluded.extend(
                ANDROID_FRAMEWORK_CLASS_FILTERS
                    .iter()
                    .map(|value| (*value).to_string()),
            );
        }
        if self.exclude_language_runtime {
            excluded.extend(
                LANGUAGE_RUNTIME_CLASS_FILTERS
                    .iter()
                    .map(|value| (*value).to_string()),
            );
        }
        if self.exclude_common_libraries {
            excluded.extend(
                COMMON_LIBRARY_CLASS_FILTERS
                    .iter()
                    .map(|value| (*value).to_string()),
            );
        }
        excluded.extend(self.additional_class_filters.iter().cloned());
        excluded
    }
}

#[derive(Clone)]
struct NativeAnalysis {
    files: Files,
    supergraph: Option<Arc<coeus::coeus_parse::dex::graph::Supergraph>>,
    history: Vec<String>,
}

impl NativeAnalysis {
    fn new(path: &str) -> Result<Self, String> {
        let files = coeus::coeus_parse::extraction::load_file(path, false, -1)
            .map_err(|error| format!("could not load {path}: {error}"))?;
        Ok(Self {
            files,
            supergraph: None,
            history: Vec::new(),
        })
    }

    fn package(&self) -> String {
        self.files.android_manifest.package.clone()
    }

    fn dex_names(&self) -> Vec<String> {
        self.files
            .multi_dex
            .iter()
            .flat_map(|multi_dex| {
                std::iter::once(multi_dex.primary.clone()).chain(multi_dex.secondary.clone())
            })
            .map(|dex| dex.get_dex_name().to_string())
            .collect()
    }

    fn set_manifest_xml(&mut self, xml: &str) -> Result<(), String> {
        apk::set_manifest_xml(&mut self.files, xml)?;
        self.history.push("set_manifest_xml".to_string());
        Ok(())
    }

    fn set_debuggable(&mut self, enabled: bool) -> Result<(), String> {
        apk::set_manifest_attribute(
            &mut self.files,
            "application",
            "debuggable",
            if enabled { "true" } else { "false" },
        )?;
        self.history.push(format!("set_debuggable {enabled}"));
        Ok(())
    }

    fn allow_plaintext_and_user_certificates(&mut self) -> Result<(), String> {
        apk::allow_plaintext_and_user_certificates(&mut self.files)?;
        self.history
            .push("allow_plaintext_and_user_certificates".to_string());
        Ok(())
    }

    fn write(&self, path: &str) -> Result<(), String> {
        apk::repack(&self.files, path).map_err(|error| error.to_string())
    }

    fn replace_loaded_dex(&mut self, dex_name: &str, bytes: Vec<u8>) -> Result<(), String> {
        for multi_dex in &mut self.files.multi_dex {
            if multi_dex.primary.get_dex_name() == dex_name
                || multi_dex.primary.file_name == dex_name
            {
                let file_name = multi_dex.primary.file_name.clone();
                let archive_name = multi_dex.primary.get_dex_name().to_string();
                let parsed = parse_dex_buf(&file_name, &ArrayView::new(&bytes), false)
                    .ok_or_else(|| "could not reparse edited DEX".to_string())?;
                multi_dex.primary = Arc::new(parsed);
                self.files.set_file(archive_name, bytes)?;
                self.supergraph = None;
                return Ok(());
            }
            if let Some(index) = multi_dex
                .secondary
                .iter()
                .position(|dex| dex.get_dex_name() == dex_name || dex.file_name == dex_name)
            {
                let file_name = multi_dex.secondary[index].file_name.clone();
                let archive_name = multi_dex.secondary[index].get_dex_name().to_string();
                let parsed = parse_dex_buf(&file_name, &ArrayView::new(&bytes), false)
                    .ok_or_else(|| "could not reparse edited DEX".to_string())?;
                multi_dex.secondary[index] = Arc::new(parsed);
                self.files.set_file(archive_name, bytes)?;
                self.supergraph = None;
                return Ok(());
            }
        }
        Err(format!("DEX not found: {dex_name}"))
    }

    fn loaded_dex_for_method(
        &self,
        method: &MethodObject,
    ) -> Result<(String, u32, Arc<DexFile>), String> {
        let method_idx = method.method.method_idx as u32;
        let dex = self
            .files
            .multi_dex
            .iter()
            .flat_map(|multi_dex| {
                std::iter::once(&multi_dex.primary).chain(multi_dex.secondary.iter())
            })
            .find(|dex| {
                dex.identifier == method.file.identifier || dex.file_name == method.file.file_name
            })
            .cloned()
            .ok_or_else(|| format!("DEX not found for method {}", method.signature()))?;
        Ok((dex.get_dex_name().to_string(), method_idx, dex))
    }

    fn replace_string(&mut self, string: &StringObject, replacement: &str) -> Result<(), String> {
        let dex_name = string.file.get_dex_name().to_string();
        let bytes = replace_dex_string(&string.file, string.index, replacement)
            .map_err(|error| error.to_string())?;
        self.replace_loaded_dex(&dex_name, bytes)?;
        self.history
            .push(format!("replace_string {}", string.index));
        Ok(())
    }

    fn edit_method(
        &mut self,
        method: &MethodObject,
        target_offset: u32,
        action: &str,
        factory: &str,
        arguments: &Value,
    ) -> Result<MethodObject, String> {
        let (dex_name, method_idx, dex) = self.loaded_dex_for_method(method)?;
        let target = method
            .instructions()
            .into_iter()
            .find(|instruction| instruction.offset == target_offset)
            .ok_or_else(|| format!("instruction offset is not present: {target_offset}"))?;

        let mut editing_dex = dex.clone();
        let string_values = if factory == "const_string_value" {
            vec![argument_text(arguments, "value", "")]
        } else {
            Vec::new()
        };
        if !string_values.is_empty() {
            let prepared =
                ensure_dex_strings(&dex, &string_values).map_err(|error| error.to_string())?;
            if prepared != dex.raw_data() {
                editing_dex = Arc::new(
                    parse_dex_buf(&dex_name, &ArrayView::new(&prepared), false)
                        .ok_or_else(|| "could not prepare edited string pool".to_string())?,
                );
            }
        }

        let after = CodeTarget {
            offset: target.offset,
            position: TargetPosition::After,
        };
        let mut typed_arguments = arguments.clone();
        let effective_factory = if factory == "const_string_value" {
            let value = argument_text(arguments, "value", "");
            let string_index = editing_dex
                .find_string_index(&value)
                .ok_or_else(|| format!("edited DEX string pool does not contain {value:?}"))?;
            typed_arguments["string_index"] = json!(string_index.to_string());
            if string_index <= u16::MAX as u32 {
                "const_string"
            } else {
                "const_string_jumbo"
            }
        } else {
            factory
        };
        let editable = if factory == "switch" {
            let register = typed_arguments
                .get("register")
                .and_then(Value::as_str)
                .unwrap_or("0")
                .parse::<u8>()
                .map_err(|_| "register must be an integer".to_string())?;
            let case_value = typed_arguments
                .get("case_value")
                .and_then(Value::as_str)
                .unwrap_or("0")
                .parse::<i32>()
                .map_err(|_| "case_value must be an integer".to_string())?;
            EditableInstruction::Switch {
                register,
                cases: [(case_value, after)].into_iter().collect(),
                default: None,
                form: SwitchForm::Auto,
            }
        } else {
            let instruction = build_instruction(effective_factory, &typed_arguments, after)?;
            editable_instruction(&editing_dex, method_idx, &instruction, after)?
        };
        let position = match action {
            "prepend" => EditPosition::Before,
            "insert_before" => EditPosition::Before,
            "insert_after" => EditPosition::After,
            "replace" => EditPosition::Replace,
            other => return Err(format!("unknown edit action: {other}")),
        };
        let anchor = if action == "prepend" {
            method
                .instructions()
                .first()
                .map(|item| item.offset)
                .unwrap_or(0)
        } else {
            target.offset
        };
        let bytes = rewrite_method_code(
            &editing_dex,
            method_idx,
            &[MethodEdit {
                anchor,
                position,
                instructions: vec![editable],
            }],
        )
        .map_err(|error| error.to_string())?;
        self.replace_loaded_dex(&dex_name, bytes)?;
        self.history.push(format!(
            "apply_edit {} at {target_offset}",
            method.signature()
        ));

        self.method_by_identity(&method.signature(), &dex_name)
            .ok_or_else(|| "edited method could not be found after reparsing".to_string())
    }

    fn method_by_identity(&self, signature: &str, dex_name: &str) -> Option<MethodObject> {
        self.files
            .multi_dex
            .iter()
            .flat_map(|multi_dex| {
                std::iter::once(&multi_dex.primary).chain(multi_dex.secondary.iter())
            })
            .filter(|dex| dex.get_dex_name() == dex_name || dex.file_name == dex_name)
            .flat_map(|dex| {
                dex.methods
                    .iter()
                    .map(|method| (dex.clone(), method.clone()))
            })
            .filter_map(|(file, method)| method_object(&file, &method))
            .find(|method| method.signature() == signature)
    }

    fn build_supergraph(&mut self, options: &SupergraphBuildOptions) -> Result<String, String> {
        let multi_dex = self
            .files
            .multi_dex
            .first()
            .ok_or_else(|| "the loaded APK contains no DEX files".to_string())?;
        let excluded = options.excluded_classes();
        let emulate_classes = options.discover_dynamic_arguments.then(|| {
            options
                .dynamic_argument_classes
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        });
        let binaries = Arc::new(self.files.binaries.clone());
        let graph = coeus::coeus_parse::dex::graph::information_graph::build_information_graph(
            multi_dex,
            binaries,
            &excluded.iter().map(String::as_str).collect::<Vec<_>>(),
            emulate_classes.as_deref(),
            None,
        )
        .map_err(|error| format!("could not build graph: {error:?}"))?;
        let graph = Arc::new(graph);
        let dot = graph.to_dot();
        self.supergraph = Some(graph);
        Ok(dot)
    }

    fn current_dex(&self, name: &str) -> Option<Arc<DexFile>> {
        self.files
            .multi_dex
            .iter()
            .flat_map(|multi_dex| {
                std::iter::once(&multi_dex.primary).chain(multi_dex.secondary.iter())
            })
            .find(|dex| dex.get_dex_name() == name || dex.file_name == name)
            .cloned()
    }
}

#[derive(Clone)]
struct NativeSplit {
    members: Vec<NativeAnalysis>,
    names: Vec<String>,
    base: usize,
    history: Vec<String>,
}

struct NativeDebugger {
    client: coeus::coeus_debug::jdwp::JdwpClient,
    runtime: Arc<Runtime>,
    last_step_id: Option<u32>,
    breakpoints: HashMap<(String, u32), u32>,
}

impl NativeDebugger {
    fn new(client: coeus::coeus_debug::jdwp::JdwpClient, runtime: Runtime) -> Self {
        Self {
            client,
            runtime: Arc::new(runtime),
            last_step_id: None,
            breakpoints: HashMap::new(),
        }
    }

    fn set_breakpoint(&mut self, method: &MethodObject, offset: u32) -> Result<u32, String> {
        let classes = self
            .client
            .get_class(&self.runtime, &method.class.class_name)
            .map_err(|error| format!("could not resolve debugger class: {error}"))?;
        let class = classes
            .first()
            .ok_or_else(|| format!("class {} is not loaded in the VM", method.class.class_name))?;
        let remote_name = format!("{}{}", method.method.method_name, method.method.proto_name);
        let command = class
            .set_breakpoint(&remote_name, offset as u64)
            .map_err(|error| format!("could not create breakpoint location: {error}"))?;
        let event_id = self
            .client
            .set_breakpoint(&self.runtime, command)
            .map_err(|error| format!("could not set breakpoint: {error}"))?;
        self.breakpoints
            .insert((method.signature(), offset), event_id);
        Ok(event_id)
    }

    fn clear_breakpoint(&mut self, method: &MethodObject, offset: u32) -> Result<(), String> {
        let key = (method.signature(), offset);
        let event_id = self
            .breakpoints
            .remove(&key)
            .ok_or_else(|| format!("breakpoint is not set at {}@0x{offset:x}", key.0))?;
        self.client
            .clear_breakpoint(&self.runtime, event_id)
            .map_err(|error| format!("could not clear breakpoint: {error}"))
    }
}

struct NativeStoppedFrame {
    frame: StackFrame,
    values: Vec<(u32, SlotValue)>,
}

struct NativeWait {
    receiver: mpsc::Receiver<Result<Option<StackFrame>, String>>,
    cancel: Arc<AtomicBool>,
}

#[derive(Clone)]
enum Session {
    Single(NativeAnalysis),
    Split(NativeSplit),
}

impl Session {
    fn base(&self) -> &NativeAnalysis {
        match self {
            Self::Single(analysis) => analysis,
            Self::Split(split) => &split.members[split.base],
        }
    }

    fn base_mut(&mut self) -> &mut NativeAnalysis {
        match self {
            Self::Single(analysis) => analysis,
            Self::Split(split) => &mut split.members[split.base],
        }
    }

    fn history(&self) -> Vec<String> {
        match self {
            Self::Single(analysis) => analysis.history.clone(),
            Self::Split(split) => {
                let mut history = split.history.clone();
                history.extend(
                    split
                        .members
                        .iter()
                        .flat_map(|member| member.history.clone()),
                );
                history
            }
        }
    }

    fn names(&self) -> Vec<String> {
        match self {
            Self::Single(_) => Vec::new(),
            Self::Split(split) => split.names.clone(),
        }
    }
}

#[derive(Clone)]
struct MethodObject {
    method: Arc<ModelMethod>,
    data: Option<Arc<MethodData>>,
    file: Arc<DexFile>,
    class: Arc<ModelClass>,
}

impl MethodObject {
    fn signature(&self) -> String {
        format!(
            "{}->{}{}",
            self.class.class_name, self.method.method_name, self.method.proto_name
        )
    }

    fn instructions(&self) -> Vec<NativeInstruction> {
        let Some(code) = self.data.as_ref().and_then(|data| data.code.as_ref()) else {
            return Vec::new();
        };
        code.insns
            .iter()
            .filter(|(_, _, instruction)| !is_payload(instruction))
            .map(|(size, offset, instruction)| NativeInstruction {
                instruction: instruction.clone(),
                offset: offset.0,
                size: instruction
                    .to_code_units()
                    .map(|units| units.len() as u32)
                    .unwrap_or(size.0 / 2),
            })
            .collect()
    }

    fn code(&self) -> String {
        self.data
            .as_ref()
            .map(|data| data.get_disassembly(&self.file))
            .unwrap_or_default()
    }
}

#[derive(Clone)]
struct ClassObject {
    class: Arc<ModelClass>,
    file: Arc<DexFile>,
}

#[derive(Clone)]
struct FieldObject {
    field: Arc<ModelField>,
    file: Arc<DexFile>,
    class: ClassObject,
}

#[derive(Clone)]
struct StringObject {
    index: u32,
    content: String,
    file: Arc<DexFile>,
}

#[derive(Clone)]
struct ProtoObject {
    proto: Arc<Proto>,
    file: Arc<DexFile>,
}

#[derive(Clone)]
struct FieldAccessObject {
    field: FieldObject,
    place: Location,
    instruction: String,
}

#[derive(Clone)]
struct NativeSymbolObject {
    symbol: String,
}

#[derive(Clone)]
struct NativeInstruction {
    instruction: Instruction,
    offset: u32,
    size: u32,
}

#[derive(Clone)]
struct EditSpec {
    method_id: String,
    offset: u32,
    action: String,
    factory: String,
}

#[derive(Clone)]
enum NativeObject {
    Method(MethodObject),
    Class(ClassObject),
    Field(FieldObject),
    String(StringObject),
    Proto(ProtoObject),
    FieldAccess(FieldAccessObject),
    Native(NativeSymbolObject),
    Edit(EditSpec),
}

#[derive(Clone)]
struct ObjectEntry {
    object: NativeObject,
    evidence: Option<Evidence>,
}

pub struct RustBackend {
    session: Option<Session>,
    analysis_revision: u64,
    objects: HashMap<String, ObjectEntry>,
    next_object_id: Arc<AtomicUsize>,
    notes: HashMap<String, String>,
    aliases: HashMap<String, String>,
    session_origin: Option<Value>,
    session_events: Vec<Value>,
    session_script_override: Option<String>,
    debugger: Option<Arc<Mutex<NativeDebugger>>>,
    debug_connecting: bool,
    debug_connect_result: Option<mpsc::Receiver<Result<NativeDebugger, String>>>,
    debug_apps_loading: bool,
    debug_apps_result: Option<mpsc::Receiver<Result<Vec<signing::DebuggableApp>, String>>>,
    debug_waiting: bool,
    debug_wait: Option<NativeWait>,
    debug_frame: Option<NativeStoppedFrame>,
}

/// Thread-safe native command executor. Inspection commands operate on a
/// snapshot so several expensive Coeus queries can run at once. Commands
/// which mutate the loaded analysis or control the debugger are serialized.
/// A read snapshot does not hold the operation gate while Coeus is working;
/// this keeps a long graph build from blocking unrelated state changes.
#[derive(Clone)]
pub struct RustBackendHandle {
    state: Arc<Mutex<RustBackend>>,
    operation_gate: Arc<RwLock<()>>,
}

impl RustBackendHandle {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(RustBackend::new())),
            operation_gate: Arc::new(RwLock::new(())),
        }
    }

    pub fn call(&self, request: Value) -> BackendResult {
        if parallel_read_operation(&request) {
            let (mut worker, revision) = {
                let _read_gate = self
                    .operation_gate
                    .read()
                    .map_err(|_| "native backend operation gate was poisoned".to_string())?;
                let state = self
                    .state
                    .lock()
                    .map_err(|_| "native backend state lock was poisoned".to_string())?;
                (state.snapshot(), state.analysis_revision)
            };
            let result = worker.call(request);
            if result.is_ok() {
                let _write_gate = self
                    .operation_gate
                    .write()
                    .map_err(|_| "native backend operation gate was poisoned".to_string())?;
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| "native backend state lock was poisoned".to_string())?;
                if state.analysis_revision == revision {
                    state.merge_parallel(worker);
                }
            }
            result
        } else {
            let _write_gate = self
                .operation_gate
                .write()
                .map_err(|_| "native backend operation gate was poisoned".to_string())?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| "native backend state lock was poisoned".to_string())?;
            state.analysis_revision = state.analysis_revision.wrapping_add(1);
            state.call(request)
        }
    }
}

impl RustBackend {
    pub fn new() -> Self {
        Self {
            session: None,
            analysis_revision: 0,
            objects: HashMap::new(),
            next_object_id: Arc::new(AtomicUsize::new(1)),
            notes: HashMap::new(),
            aliases: HashMap::new(),
            session_origin: None,
            session_events: Vec::new(),
            session_script_override: None,
            debugger: None,
            debug_connecting: false,
            debug_connect_result: None,
            debug_apps_loading: false,
            debug_apps_result: None,
            debug_waiting: false,
            debug_wait: None,
            debug_frame: None,
        }
    }

    fn snapshot(&self) -> Self {
        Self {
            session: self.session.clone(),
            analysis_revision: self.analysis_revision,
            objects: self.objects.clone(),
            next_object_id: self.next_object_id.clone(),
            notes: self.notes.clone(),
            aliases: self.aliases.clone(),
            session_origin: self.session_origin.clone(),
            session_events: self.session_events.clone(),
            session_script_override: self.session_script_override.clone(),
            debugger: None,
            debug_connecting: false,
            debug_connect_result: None,
            debug_apps_loading: false,
            debug_apps_result: None,
            debug_waiting: false,
            debug_wait: None,
            debug_frame: None,
        }
    }

    fn merge_parallel(&mut self, worker: Self) {
        self.objects.extend(worker.objects);
        match (&mut self.session, worker.session) {
            (Some(Session::Single(current)), Some(Session::Single(worker))) => {
                if worker.supergraph.is_some() {
                    current.supergraph = worker.supergraph;
                }
            }
            (Some(Session::Split(current)), Some(Session::Split(worker))) => {
                if let (Some(current_base), Some(worker_base)) = (
                    current.members.get_mut(current.base),
                    worker.members.get(worker.base),
                ) {
                    if worker_base.supergraph.is_some() {
                        current_base.supergraph = worker_base.supergraph.clone();
                    }
                }
            }
            _ => {}
        }
    }

    pub fn call(&mut self, request: Value) -> BackendResult {
        let operation = request
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| "request has no operation".to_string())?;
        match operation {
            "load" => self.load(value_string(&request, "path")),
            "load_split" => self.load_split(&request),
            "load_split_from_adb" => self.load_split_from_adb(&request),
            "history" => self.history_data(),
            "manifest" => self.manifest_data(),
            "set_manifest_xml" => self.set_manifest_xml(value_string(&request, "xml")),
            "set_debuggable" => self.set_debuggable(
                request
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
            "allow_plaintext_and_user_certificates" => self.allow_plaintext_and_user_certificates(),
            "write" => self.write(value_string(&request, "path")),
            "search" => self.search(
                optional_string(&request, "kind")
                    .unwrap_or("any")
                    .to_string(),
                value_string(&request, "query"),
            ),
            "resolve" => self.resolve(&request),
            "edit_search" => self.edit_search(&request),
            "describe" => self.describe(value_string(&request, "id")),
            "emulate" => self.emulate(&request),
            "xrefs" => self.cross_references(value_string(&request, "id")),
            "graph" => self.graph(&request),
            "graph_node_details" => self.graph_node_details(&request),
            "replace_string" => self.replace_string(&request),
            "edit_options" => self.edit_options(&request),
            "apply_edit" => self.apply_edit(&request),
            "adb_devices" => self.adb_devices(value_string(&request, "adb_path")),
            "adb_packages" => self.adb_packages(&request),
            "pull_apks" => self.pull_apks(&request),
            "install" => self.install_apk(&request),
            "install_split" => self.install_split(&request),
            "sign" => self.sign_apk(&request),
            "sign_split" => self.sign_split(&request),
            "sign_and_install" => self.sign_and_install(&request),
            "sign_and_install_split" => self.sign_and_install_split(&request),
            "generate_keystore" => self.generate_keystore(&request),
            "set_note" => self.set_note(&request),
            "set_alias" => self.set_alias(&request),
            "save_project" => self.save_project(&request),
            "load_project" => self.load_project(value_string(&request, "path")),
            "export_script" => self.export_script(value_string(&request, "path")),
            "debug_connect" => self.debug_connect(
                optional_string(&request, "host")
                    .unwrap_or("127.0.0.1")
                    .to_string(),
                request.get("port").and_then(Value::as_u64).unwrap_or(8000) as u16,
            ),
            "debug_attach" => self.debug_attach(&request),
            "debug_detach" => self.debug_detach(),
            "debug_connect_poll" => self.debug_connect_poll(),
            "debug_apps" => self.debug_apps(&request),
            "debug_apps_poll" => self.debug_apps_poll(),
            "debug_breakpoint" => self.debug_breakpoint(&request),
            "debug_breakpoint_skip" => self.debug_breakpoint_skip(&request),
            "debug_breakpoint_remove" => self.debug_breakpoint_remove(&request),
            "debug_wait" => self.debug_wait_start(),
            "debug_poll" => self.debug_poll(),
            "debug_resume" => self.debug_resume(),
            "debug_step" => self.debug_step(),
            "debug_set_value" => self.debug_set_value(&request),
            other => Err(format!("unknown operation: {other}")),
        }
    }

    fn reset_objects(&mut self) {
        self.objects.clear();
        self.next_object_id.store(1, Ordering::Relaxed);
        self.session_events.clear();
        self.session_script_override = None;
        self.notes.clear();
        self.aliases.clear();
    }

    fn record_event(&mut self, event: Value) {
        self.session_script_override = None;
        self.session_events.push(event);
    }

    fn load(&mut self, path: String) -> BackendResult {
        let analysis = NativeAnalysis::new(&path)?;
        self.session = Some(Session::Single(analysis));
        self.session_origin = Some(json!({"kind": "apk", "path": path}));
        self.reset_objects();
        Ok(self.session_data(path, false))
    }

    fn load_split(&mut self, request: &Value) -> BackendResult {
        let paths = request
            .get("paths")
            .and_then(Value::as_array)
            .ok_or_else(|| "select at least one APK for the split set".to_string())?
            .iter()
            .filter_map(Value::as_str)
            .filter(|path| !path.trim().is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return Err("select at least one APK for the split set".to_string());
        }
        let members = paths
            .iter()
            .map(|path| NativeAnalysis::new(path))
            .collect::<Result<Vec<_>, _>>()?;
        let names = paths
            .iter()
            .map(|path| {
                Path::new(path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(path)
                    .to_string()
            })
            .collect::<Vec<_>>();
        let base = names
            .iter()
            .position(|name| name == "base.apk" || name.starts_with("base-"))
            .unwrap_or(0);
        self.session = Some(Session::Split(NativeSplit {
            members,
            names,
            base,
            history: Vec::new(),
        }));
        self.session_origin = Some(json!({"kind": "split", "paths": paths}));
        self.reset_objects();
        Ok(self.session_data(paths.join(", "), true))
    }

    fn load_project(&mut self, path: String) -> BackendResult {
        let file =
            File::open(&path).map_err(|error| format!("could not open state archive: {error}"))?;
        let mut archive =
            ZipArchive::new(file).map_err(|error| format!("invalid .coeus archive: {error}"))?;
        let mut state_metadata = None;
        let mut gui_metadata = None;
        let mut saved_script = None;
        let mut apk_bytes = HashMap::new();
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .map_err(|error| format!("could not read state archive entry: {error}"))?;
            let entry_name = entry.name().to_string();
            if entry_name == "state.json" || entry_name == "gui/session.json" {
                let mut bytes = Vec::new();
                entry
                    .read_to_end(&mut bytes)
                    .map_err(|error| format!("could not read {entry_name}: {error}"))?;
                let value = serde_json::from_slice::<Value>(&bytes)
                    .map_err(|error| format!("invalid {entry_name}: {error}"))?;
                if entry_name == "state.json" {
                    state_metadata = Some(value);
                } else {
                    gui_metadata = Some(value);
                }
            } else if entry_name == "gui/session.py" {
                let mut bytes = Vec::new();
                entry
                    .read_to_end(&mut bytes)
                    .map_err(|error| format!("could not read gui/session.py: {error}"))?;
                saved_script = Some(
                    String::from_utf8(bytes)
                        .map_err(|error| format!("invalid gui/session.py: {error}"))?,
                );
            } else if let Some(name) = entry_name.strip_prefix("apks/") {
                if entry.is_dir()
                    || name.is_empty()
                    || name.contains('/')
                    || name.contains('\\')
                    || name == "."
                    || name == ".."
                {
                    return Err(format!("invalid APK member in state archive: {entry_name}"));
                }
                let mut bytes = Vec::new();
                entry
                    .read_to_end(&mut bytes)
                    .map_err(|error| format!("could not read APK member {entry_name}: {error}"))?;
                if apk_bytes.insert(name.to_string(), bytes).is_some() {
                    return Err(format!("duplicate APK member in state archive: {name}"));
                }
            }
        }
        let state_metadata = state_metadata
            .ok_or_else(|| ".coeus archive does not contain state.json".to_string())?;
        let saved_graph = gui_metadata
            .as_ref()
            .and_then(|metadata| metadata.get("graph"))
            .cloned()
            .unwrap_or(Value::Null);
        let members = state_metadata
            .get("members")
            .and_then(Value::as_array)
            .ok_or_else(|| "state metadata has no members list".to_string())?
            .iter()
            .map(|member| {
                member
                    .as_str()
                    .filter(|name| {
                        !name.is_empty()
                            && !name.contains('/')
                            && !name.contains('\\')
                            && *name != "."
                            && *name != ".."
                    })
                    .map(str::to_string)
                    .ok_or_else(|| "state metadata contains an invalid member name".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if members.is_empty() {
            return Err("state metadata contains no APK members".to_string());
        }
        for name in &members {
            if !apk_bytes.contains_key(name) {
                return Err(format!("state archive is missing APK member {name}"));
            }
        }

        let staging = temporary_directory("state")?;
        let result = (|| {
            let mut paths = Vec::with_capacity(members.len());
            for name in &members {
                let member_path = staging.join(name);
                fs::write(
                    &member_path,
                    apk_bytes.get(name).expect("validated state member"),
                )
                .map_err(|error| format!("could not materialize state member {name}: {error}"))?;
                paths.push(member_path);
            }
            let load_request = json!({
                "paths": paths
                    .iter()
                    .map(|member| member.to_string_lossy().to_string())
                    .collect::<Vec<_>>(),
            });
            let mut data = self.load_split(&load_request)?;
            let history = state_metadata
                .get("history")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if let Some(session) = self.session.as_mut() {
                match session {
                    Session::Single(analysis) => analysis.history = history.clone(),
                    Session::Split(split) => split.history = history,
                }
            }
            self.session_origin = Some(json!({"kind": "state", "path": path}));
            self.session_script_override = saved_script.filter(|script| !script.trim().is_empty());
            if let Some(metadata) = gui_metadata {
                if let Some(notes) = metadata.get("notes").and_then(Value::as_object) {
                    self.notes = notes
                        .iter()
                        .filter_map(|(key, value)| {
                            let value = value.as_str()?.to_string();
                            (!key.trim().is_empty() && !value.trim().is_empty())
                                .then(|| (key.clone(), value))
                        })
                        .collect();
                }
                if let Some(aliases) = metadata.get("aliases").and_then(Value::as_object) {
                    self.aliases = aliases
                        .iter()
                        .filter_map(|(key, value)| {
                            let value = value.as_str()?.to_string();
                            (!key.trim().is_empty() && !value.trim().is_empty())
                                .then(|| (key.clone(), value))
                        })
                        .collect();
                }
            }
            data["path"] = json!(path);
            data["notes"] = json!(self.notes);
            data["aliases"] = json!(self.aliases);
            data["split"] = json!(members.len() > 1);
            data["graph"] = saved_graph;
            data["history"] = json!(self
                .session
                .as_ref()
                .map(Session::history)
                .unwrap_or_default());
            Ok(data)
        })();
        let _ = fs::remove_dir_all(staging);
        result
    }

    fn load_split_from_adb(&mut self, request: &Value) -> BackendResult {
        let package = value_string(request, "package");
        if package.trim().is_empty() {
            return Err("enter a package name to pull its split APKs".to_string());
        }
        let serial = optional_string(request, "serial").map(str::to_string);
        let adb_path = optional_string(request, "adb_path").map(str::to_string);
        let staging = temporary_directory("adb")?;
        let paths = signing::pull_installed_apks(
            &package,
            &staging,
            serial.as_deref(),
            adb_path.as_deref().map(Path::new),
        )
        .map_err(|error| error.to_string())?;
        let load_request = json!({"paths": paths.iter().map(|path| path.to_string_lossy().to_string()).collect::<Vec<_>>()});
        let result = self.load_split(&load_request).map(|mut data| {
            data["path"] = json!(format!("ADB: {package}"));
            data["split"] = json!(true);
            data
        });
        let _ = fs::remove_dir_all(staging);
        self.session_origin = Some(json!({
            "kind": "adb",
            "package": package,
            "serial": serial,
            "adb_path": adb_path,
        }));
        result
    }

    fn session_data(&self, path: String, split: bool) -> Value {
        let base = self
            .session
            .as_ref()
            .expect("session set before metadata")
            .base();
        json!({
            "path": path,
            "package": base.package(),
            "dex": base.dex_names(),
            "files": base.files.file_names().len(),
            "manifest": base.files.manifest_content,
            "split": split,
            "members": self.session.as_ref().map(Session::names).unwrap_or_default(),
            "notes": self.notes,
            "aliases": self.aliases,
            "history": self.session.as_ref().map(Session::history).unwrap_or_default(),
        })
    }

    fn history_data(&self) -> BackendResult {
        Ok(json!({
            "history": self.session.as_ref().map(Session::history).unwrap_or_default(),
            "events": self.session_events,
            "script": self.session_script(),
        }))
    }

    fn analysis(&self) -> Result<&NativeAnalysis, String> {
        self.session
            .as_ref()
            .map(Session::base)
            .ok_or_else(|| "load an APK first".to_string())
    }

    fn analysis_mut(&mut self) -> Result<&mut NativeAnalysis, String> {
        self.session
            .as_mut()
            .map(Session::base_mut)
            .ok_or_else(|| "load an APK first".to_string())
    }

    fn manifest_data(&self) -> BackendResult {
        let analysis = self.analysis()?;
        Ok(json!({
            "xml": analysis.files.manifest_content,
            "package": analysis.package(),
            "history": self.session.as_ref().map(Session::history).unwrap_or_default(),
        }))
    }

    fn set_manifest_xml(&mut self, xml: String) -> BackendResult {
        self.analysis_mut()?.set_manifest_xml(&xml)?;
        self.record_event(json!({"operation": "set_manifest_xml", "xml": xml}));
        self.manifest_data()
    }

    fn set_debuggable(&mut self, enabled: bool) -> BackendResult {
        self.analysis_mut()?.set_debuggable(enabled)?;
        self.record_event(json!({"operation": "set_debuggable", "enabled": enabled}));
        self.manifest_data()
    }

    fn allow_plaintext_and_user_certificates(&mut self) -> BackendResult {
        self.analysis_mut()?
            .allow_plaintext_and_user_certificates()?;
        self.record_event(json!({"operation": "allow_plaintext_and_user_certificates"}));
        self.manifest_data()
    }

    fn write(&mut self, path: String) -> BackendResult {
        self.analysis()?.write(&path)?;
        self.record_event(json!({"operation": "write", "path": path}));
        Ok(
            json!({"path": path, "history": self.session.as_ref().map(Session::history).unwrap_or_default()}),
        )
    }

    fn search(&mut self, kind: String, query: String) -> BackendResult {
        let regex = Regex::new(if query.is_empty() { ".*" } else { &query })
            .map_err(|error| format!("invalid search regex: {error}"))?;
        let aliases = self
            .aliases
            .iter()
            .filter_map(|(key, alias)| {
                let (alias_kind, canonical) = key.split_once(':')?;
                let allowed = match kind.as_str() {
                    "any" => matches!(alias_kind, "method" | "class"),
                    "methods" => alias_kind == "method",
                    "classes" => alias_kind == "class",
                    _ => false,
                };
                (allowed && regex.is_match(alias)).then_some((
                    alias_kind.to_string(),
                    canonical.to_string(),
                    alias.clone(),
                ))
            })
            .collect::<Vec<_>>();
        let mut alias_evidence = Vec::new();
        {
            let analysis = self.analysis()?;
            for (alias_kind, canonical, alias) in aliases {
                let lookup = if alias_kind == "method" {
                    canonical
                        .split_once("->")
                        .and_then(|(_, member)| member.split_once('(').map(|(name, _)| name))
                        .unwrap_or_default()
                } else {
                    canonical.as_str()
                };
                let lookup_regex = Regex::new(&regex::escape(lookup))
                    .map_err(|error| format!("invalid alias lookup regex: {error}"))?;
                let found = if alias_kind == "method" {
                    find_methods(&lookup_regex, &analysis.files)
                } else {
                    find_classes(&lookup_regex, &analysis.files)
                };
                for evidence in found {
                    let object = object_from_evidence(&evidence)?;
                    if object_label(&object) == canonical {
                        alias_evidence.push((evidence, alias));
                        break;
                    }
                }
            }
        }
        let mut results = Vec::new();
        let mut seen = HashSet::new();
        for (evidence, alias) in alias_evidence {
            let mut result = self.result_from_evidence(evidence)?;
            let key = (
                value_string(&result, "kind"),
                value_string(&result, "label"),
            );
            if seen.insert(key) {
                result["alias"] = json!(true);
                result["alias_label"] = json!(alias);
                results.push(result);
            }
        }
        let analysis = self.analysis()?;
        let found = match kind.as_str() {
            "any" => find_any(&regex, &ALL_TYPES, &analysis.files),
            "methods" => find_methods(&regex, &analysis.files),
            "classes" => find_classes(&regex, &analysis.files),
            "fields" => find_fields(&regex, &analysis.files),
            "strings" => find_strings(&regex, &analysis.files),
            other => return Err(format!("unknown search kind: {other}")),
        };
        for evidence in found {
            let result = self.result_from_evidence(evidence)?;
            let key = (
                value_string(&result, "kind"),
                value_string(&result, "label"),
            );
            if seen.insert(key) {
                results.push(result);
            }
        }
        let count = results.len();
        results.truncate(MAX_RESULTS);
        Ok(json!({"results": results, "count": count}))
    }

    fn resolve(&mut self, request: &Value) -> BackendResult {
        let kind = optional_string(request, "kind").unwrap_or("method");
        let label = value_string(request, "label");
        if label.is_empty() {
            return Err(format!("could not resolve {kind}: empty label"));
        }
        let lookup = if kind == "method" {
            label
                .split_once("->")
                .and_then(|(_, member)| member.split_once('(').map(|(name, _)| name))
                .unwrap_or_default()
                .to_string()
        } else if kind == "class" {
            label.clone()
        } else {
            return Err("exact resolution is only supported for methods and classes".to_string());
        };
        let found = {
            let analysis = self.analysis()?;
            let regex = Regex::new(&regex::escape(&lookup))
                .map_err(|error| format!("invalid exact lookup regex: {error}"))?;
            if kind == "method" {
                find_methods(&regex, &analysis.files)
            } else {
                find_classes(&regex, &analysis.files)
            }
        };
        for evidence in found {
            let object = object_from_evidence(&evidence)?;
            if object_label(&object) == label {
                return self.result_from_evidence(evidence);
            }
        }
        Err(format!("could not resolve {kind}: {label}"))
    }

    fn edit_search(&mut self, request: &Value) -> BackendResult {
        let kind = optional_string(request, "kind")
            .unwrap_or("methods")
            .to_string();
        let query = value_string(request, "query");
        let dex_name = value_string(request, "dex");
        let analysis = self.analysis()?;
        let regex = Regex::new(if query.is_empty() { ".*" } else { &query })
            .map_err(|error| format!("invalid search regex: {error}"))?;
        let found = match kind.as_str() {
            "methods" => find_methods(&regex, &analysis.files),
            "classes" => find_classes(&regex, &analysis.files),
            "fields" => find_fields(&regex, &analysis.files),
            "strings" => find_strings(&regex, &analysis.files),
            other => return Err(format!("unknown edit picker search kind: {other}")),
        };
        let mut results = Vec::new();
        for evidence in found {
            let result = self.result_from_evidence(evidence)?;
            if !dex_name.is_empty() && result.get("dex").and_then(Value::as_str) != Some(&dex_name)
            {
                continue;
            }
            results.push(result);
            if results.len() == MAX_RESULTS {
                break;
            }
        }
        let count = results.len();
        Ok(json!({"results": results, "count": count}))
    }

    fn result_from_evidence(&mut self, evidence: Evidence) -> Result<Value, String> {
        let object = object_from_evidence(&evidence)?;
        let kind = object_kind(&object);
        let label = object_label(&object);
        let index = object_index(&object);
        let dex = object_dex_name(&object);
        let id = self.store(ObjectEntry {
            object,
            evidence: Some(evidence),
        });
        let mut result = json!({
            "id": id,
            "kind": kind,
            "label": label,
        });
        if let Some(index) = index {
            result["index"] = json!(index);
        }
        if let Some(dex) = dex {
            result["dex"] = json!(dex);
        }
        if let Some(note_key) = note_key(&kind, &label) {
            result["note_key"] = json!(note_key);
        }
        Ok(result)
    }

    fn store(&mut self, entry: ObjectEntry) -> String {
        let id = format!(
            "object-{}",
            self.next_object_id.fetch_add(1, Ordering::Relaxed)
        );
        self.objects.insert(id.clone(), entry);
        id
    }

    fn entry(&self, id: &str) -> Result<&ObjectEntry, String> {
        self.objects
            .get(id)
            .ok_or_else(|| format!("unknown object: {id}"))
    }

    fn describe(&mut self, id: String) -> BackendResult {
        let object = self.entry(&id)?.object.clone();
        let kind = object_kind(&object);
        let label = object_label(&object);
        let mut data = json!({"id": id, "kind": kind, "label": label});
        if let Some(note_key) = note_key(&kind, &label) {
            data["note_key"] = json!(note_key);
        }
        match &object {
            NativeObject::Method(method) => {
                data["code"] = json!(method.code());
                data["instructions"] = json!(self.instructions_json(&method)?);
                data["class"] = json!(method.class.class_name);
                data["method_key"] = json!(method.signature());
            }
            NativeObject::Class(class) => {
                let (code, line_method_ids, line_method_keys) =
                    self.class_source_with_method_ids(class)?;
                data["code"] = json!(code);
                data["line_method_ids"] = json!(line_method_ids);
                data["line_method_keys"] = json!(line_method_keys);
                data["class"] = json!(class.class.class_name);
            }
            NativeObject::FieldAccess(access) => {
                if let Some(method) = method_from_location(&access.place) {
                    let method_id = self.store(ObjectEntry {
                        object: NativeObject::Method(method.clone()),
                        evidence: None,
                    });
                    data["method_id"] = json!(method_id);
                    data["code"] = json!(method.code());
                }
            }
            NativeObject::String(string) => data["value"] = json!(string.content),
            NativeObject::Field(_)
            | NativeObject::Proto(_)
            | NativeObject::Native(_)
            | NativeObject::Edit(_) => {}
        }
        Ok(data)
    }

    fn emulate(&self, request: &Value) -> BackendResult {
        let id = value_string(request, "id");
        let object = self.entry(&id)?.object.clone();
        let NativeObject::Method(method) = object else {
            return Err("emulation is only available for methods".to_string());
        };
        let arguments = request
            .get("arguments")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let descriptors = parse_emulation_descriptors(&method.method.proto_name)?;
        if arguments.len() != descriptors.len() {
            return Ok(json!({
                "success": false,
                "error": format!("expected {} argument(s), received {}", descriptors.len(), arguments.len()),
            }));
        }
        let analysis = self.analysis()?;
        let runtime = analysis
            .files
            .multi_dex
            .iter()
            .flat_map(|multi_dex| {
                std::iter::once(multi_dex.primary.clone()).chain(multi_dex.secondary.clone())
            })
            .filter(|dex| dex.identifier != method.file.identifier)
            .collect::<Vec<_>>();
        let mut vm = VM::new(
            method.file.clone(),
            runtime,
            Arc::new(analysis.files.binaries.clone()),
        );
        let mut vm_arguments = Vec::with_capacity(descriptors.len() + 1);
        for (descriptor, argument) in descriptors.iter().zip(arguments.iter()) {
            let text = argument.as_str().unwrap_or_default();
            vm_arguments.push(native_emulation_argument(&mut vm, descriptor, text)?);
        }
        if !method
            .data
            .as_ref()
            .map(|data| data.access_flags.contains(AccessFlags::STATIC))
            .unwrap_or(false)
        {
            let receiver = vm
                .new_class_instance(&method.class.class_name)
                .map_err(|error| format!("could not allocate method receiver: {error:?}"))?;
            vm_arguments.insert(0, receiver);
        }
        let Some(data) = method.data.as_ref() else {
            return Ok(json!({"success": false, "error": "No method definition found"}));
        };
        let Some(code) = data.code.as_ref() else {
            return Ok(json!({"success": false, "error": "No method definition found"}));
        };
        match vm.start(
            method.method.method_idx as u32,
            &method.file.identifier,
            code,
            vm_arguments,
        ) {
            Ok(()) => {
                let value = vm.get_instance(vm.get_current_state().return_reg.clone());
                let result = value.as_string().unwrap_or_else(|| format!("{:?}", value));
                Ok(json!({
                    "success": true,
                    "result": result,
                    "return_type": method.method.proto_name.rsplit(')').next().unwrap_or(""),
                }))
            }
            Err(error) => Ok(json!({"success": false, "error": format!("VM failed: {error:?}")})),
        }
    }

    fn class_source_with_method_ids(
        &mut self,
        class: &ClassObject,
    ) -> Result<(String, Vec<Option<String>>, Vec<Option<String>>), String> {
        let (source_class, file, code) = {
            let analysis = self.analysis()?;
            let Some(multi_dex) = analysis.files.multi_dex.iter().find(|multi_dex| {
                multi_dex.primary.identifier == class.file.identifier
                    || multi_dex
                        .secondary
                        .iter()
                        .any(|dex| dex.identifier == class.file.identifier)
            }) else {
                return Ok((String::new(), Vec::new(), Vec::new()));
            };
            let file = multi_dex
                .dex_file_from_identifier(&class.file.identifier)
                .unwrap_or_else(|| class.file.clone());
            let source_class = if !class.class.codes.is_empty() {
                class.class.clone()
            } else {
                multi_dex
                    .classes()
                    .into_iter()
                    .find(|(_, candidate)| candidate.class_name == class.class.class_name)
                    .map(|(_, candidate)| candidate)
                    .unwrap_or_else(|| class.class.clone())
            };
            let code = source_class.get_disassembly(multi_dex);
            (source_class, file, code)
        };

        let lines = code.lines().collect::<Vec<_>>();
        let mut line_method_ids = vec![None; lines.len()];
        let mut line_method_keys = vec![None; lines.len()];
        let mut search_from = 0usize;
        for method_data in &source_class.codes {
            let method_code = method_data.get_disassembly(&file);
            let method_lines = method_code.lines().collect::<Vec<_>>();
            if method_lines.is_empty() || search_from >= lines.len() {
                continue;
            }
            let Some(relative_start) = lines[search_from..]
                .windows(method_lines.len())
                .position(|window| window == method_lines.as_slice())
            else {
                continue;
            };
            let start = search_from + relative_start;
            let method = method_object(&file, &method_data.method);
            let method_key = method.as_ref().map(MethodObject::signature);
            let method_id = method.map(|method| {
                self.store(ObjectEntry {
                    object: NativeObject::Method(method),
                    evidence: None,
                })
            });
            if let Some(method_id) = method_id {
                for line_method_id in &mut line_method_ids[start..start + method_lines.len()] {
                    *line_method_id = Some(method_id.clone());
                }
            }
            if let Some(method_key) = method_key {
                for line_method_key in &mut line_method_keys[start..start + method_lines.len()] {
                    *line_method_key = Some(method_key.clone());
                }
            }
            search_from = start + method_lines.len();
        }
        Ok((code, line_method_ids, line_method_keys))
    }

    fn instructions_json(&mut self, method: &MethodObject) -> Result<Vec<Value>, String> {
        method
            .instructions()
            .into_iter()
            .map(|instruction| {
                let text = instruction_text(&instruction, &method.file);
                let targets = self.instruction_targets(&text)?;
                Ok(json!({
                    "offset": instruction.offset,
                    "size": instruction.size,
                    "mnemonic": instruction.instruction.mnemonic_from_opcode(),
                    "text": text,
                    "targets": targets,
                }))
            })
            .collect()
    }

    fn instruction_targets(&mut self, text: &str) -> Result<Vec<Value>, String> {
        let mut targets = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let methods = Regex::new(r"(L[^\s,{}]+;->[^\s,{}(]+\([^)]*\)[^\s,{}]+)")
            .expect("static method reference regex");
        let fields = Regex::new(r"(L[^\s,{}]+;->[^\s,{}:]+:[^\s,{}]+)")
            .expect("static field reference regex");
        for reference in methods
            .captures_iter(text)
            .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
        {
            let method_name = reference
                .split("->")
                .nth(1)
                .and_then(|value| value.split('(').next())
                .unwrap_or_default();
            self.add_reference_matches(
                "methods",
                method_name.to_string(),
                Some(reference),
                &mut targets,
                &mut seen,
            )?;
        }
        for reference in fields
            .captures_iter(text)
            .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
        {
            let field_name = reference
                .split("->")
                .nth(1)
                .and_then(|value| value.split(':').next())
                .unwrap_or_default();
            self.add_reference_matches(
                "fields",
                field_name.to_string(),
                Some(reference),
                &mut targets,
                &mut seen,
            )?;
        }
        let classes = Regex::new(r"(\[*L[^\s,{};]+;)").expect("static class reference regex");
        for reference in classes
            .captures_iter(text)
            .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
        {
            self.add_reference_matches("classes", reference, None, &mut targets, &mut seen)?;
        }
        if text.trim_start().starts_with("const-string") {
            let strings =
                Regex::new(r#"\"((?:\\.|[^\"\\])*)\""#).expect("static string reference regex");
            for value in strings.captures_iter(text).filter_map(|capture| {
                capture
                    .get(1)
                    .map(|value| value.as_str().replace("\\\"", "\""))
            }) {
                self.add_reference_matches("strings", value, None, &mut targets, &mut seen)?;
            }
        }
        Ok(targets)
    }

    fn add_reference_matches(
        &mut self,
        kind: &str,
        query: String,
        expected: Option<String>,
        targets: &mut Vec<Value>,
        seen: &mut std::collections::HashSet<(String, String)>,
    ) -> Result<(), String> {
        let analysis = self.analysis()?;
        let regex = Regex::new(&regex::escape(&query)).map_err(|error| error.to_string())?;
        let found = match kind {
            "methods" => find_methods(&regex, &analysis.files),
            "classes" => find_classes(&regex, &analysis.files),
            "fields" => find_fields(&regex, &analysis.files),
            "strings" => find_strings(&regex, &analysis.files),
            _ => Vec::new(),
        };
        for evidence in found.into_iter().take(100) {
            let result = self.result_from_evidence(evidence)?;
            if expected.as_ref().is_some_and(|expected| {
                result.get("label").and_then(Value::as_str) != Some(expected)
            }) {
                continue;
            }
            let actual_kind = value_string(&result, "kind");
            let label = value_string(&result, "label");
            if seen.insert((actual_kind, label)) {
                targets.push(result);
            }
        }
        Ok(())
    }

    fn replace_string(&mut self, request: &Value) -> BackendResult {
        let id = value_string(request, "id");
        let replacement = value_string(request, "value");
        let object = self.entry(&id)?.object.clone();
        let NativeObject::String(string) = object else {
            return Err("string-pool editing requires a DEX string".to_string());
        };
        let dex_name = string.file.get_dex_name().to_string();
        self.analysis_mut()?.replace_string(&string, &replacement)?;
        let refreshed = self.analysis()?.current_dex(&dex_name);
        if let Some(entry) = self.objects.get_mut(&id) {
            if let NativeObject::String(string) = &mut entry.object {
                if let Some(file) = refreshed {
                    string.file = file;
                    string.content = replacement.clone();
                }
            }
        }
        self.record_event(json!({
            "operation": "replace_string",
            "dex": dex_name,
            "index": string.index,
            "replacement": replacement,
        }));
        Ok(
            json!({"id": id, "value": replacement, "history": self.session.as_ref().map(Session::history).unwrap_or_default()}),
        )
    }

    fn cross_references(&mut self, id: String) -> BackendResult {
        let evidence = self.entry(&id)?.evidence.clone();
        let Some(evidence) = evidence else {
            return Ok(json!({"results": [], "count": 0}));
        };
        let Some(context) = (if matches!(evidence, Evidence::CrossReference(_)) {
            evidence.get_place_context()
        } else {
            evidence.get_context()
        }) else {
            return Ok(json!({"results": [], "count": 0}));
        };
        let found =
            analysis::dex::find_cross_reference_array(&[context.clone()], &self.analysis()?.files);
        let count = found.len();
        let results = found
            .into_iter()
            .take(MAX_RESULTS)
            .map(|evidence| self.result_from_evidence(evidence))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({"results": results, "count": count}))
    }

    fn graph(&mut self, request: &Value) -> BackendResult {
        let kind = optional_string(request, "kind")
            .unwrap_or("callgraph")
            .to_string();
        if kind == "supergraph" {
            let options = SupergraphBuildOptions::from_request(request);
            let dot = self.analysis_mut()?.build_supergraph(&options)?;
            return Ok(json!({"kind": kind, "dot": dot}));
        }
        let id = value_string(request, "id");
        let object = self.entry(&id)?.object.clone();
        let NativeObject::Method(method) = object else {
            return Err("call graphs start from a method result".to_string());
        };
        if self.analysis()?.supergraph.is_none() {
            self.analysis_mut()?
                .build_supergraph(&SupergraphBuildOptions {
                    exclude_android_framework: true,
                    exclude_language_runtime: true,
                    exclude_common_libraries: true,
                    additional_class_filters: Vec::new(),
                    discover_dynamic_arguments: false,
                    dynamic_argument_classes: Vec::new(),
                })?;
        }
        let graph = self
            .analysis()?
            .supergraph
            .as_ref()
            .cloned()
            .ok_or_else(|| "could not build supergraph".to_string())?;
        let type_name = method
            .file
            .get_type_name(method.method.class_idx)
            .unwrap_or("UNKNOWN");
        let key = format!(
            "{}->{}_{}",
            type_name, method.method.method_name, method.method.proto_name
        );
        let method_key = graph
            .class_node_mapping
            .keys()
            .find(|value| value.contains(&key))
            .cloned()
            .ok_or_else(|| "method not found in supergraph".to_string())?;
        let ignore = value_string(request, "ignore")
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        let subgraph = coeus::coeus_parse::dex::graph::callgraph::callgraph_for_method(
            &graph.super_graph,
            graph.class_node_mapping[&method_key],
            &ignore,
        );
        Ok(json!({"kind": kind, "dot": subgraph.to_dot()}))
    }

    fn graph_node_details(&mut self, request: &Value) -> BackendResult {
        let label = value_string(request, "label");
        let node_id = request.get("node_id").cloned().unwrap_or(Value::Null);
        let mut kind = "node".to_string();
        let mut value = String::new();
        let pattern = Regex::new(r#"\b(method|class|field|string):\s*\"((?:\\.|[^\"\\])*)\""#)
            .expect("static graph node regex");
        if let Some(capture) = pattern.captures(&label) {
            kind = capture.get(1).unwrap().as_str().to_string();
            value = capture.get(2).unwrap().as_str().to_string();
        }
        let targets = if value.is_empty() {
            Vec::new()
        } else {
            let search_kind = match kind.as_str() {
                "method" => "methods",
                "class" => "classes",
                "field" => "fields",
                "string" => "strings",
                _ => "any",
            };
            let mut search_value = value.clone();
            let expected_label = if kind == "method" {
                let expected = Regex::new(r"\s+\(midx:\s*\d+\)\s*$")
                    .expect("static graph method index regex")
                    .replace(&value, "")
                    .to_string();
                if let Some((_, method)) = expected.split_once("->") {
                    search_value = method.split('(').next().unwrap_or_default().to_string();
                }
                expected
            } else if kind == "field" {
                if let Some((_, field)) = value.split_once("->") {
                    search_value = field.split(':').next().unwrap_or_default().to_string();
                }
                value.clone()
            } else {
                value.clone()
            };
            let candidates = self
                .search(search_kind.to_string(), regex::escape(&search_value))?
                .get("results")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let exact = candidates
                .iter()
                .filter(|result| {
                    result.get("kind").and_then(Value::as_str) == Some(kind.as_str())
                        && result.get("label").and_then(Value::as_str)
                            == Some(expected_label.as_str())
                })
                .cloned()
                .collect::<Vec<_>>();
            (if exact.is_empty() { candidates } else { exact })
                .into_iter()
                .take(20)
                .collect()
        };
        Ok(
            json!({"node_id": node_id, "kind": kind, "value": value, "label": label, "targets": targets}),
        )
    }

    fn edit_options(&mut self, request: &Value) -> BackendResult {
        let method_id = value_string(request, "id");
        let offset = value_u32(request, "offset")?;
        let object = self.entry(&method_id)?.object.clone();
        let NativeObject::Method(method) = object else {
            return Err("instruction edits require a method".to_string());
        };
        let target = method
            .instructions()
            .into_iter()
            .find(|instruction| instruction.offset == offset)
            .ok_or_else(|| format!("instruction offset is not present: {offset}"))?;
        let target_text = instruction_text(&target, &method.file);
        let registers = Regex::new(r"\bv(\d+)\b")
            .expect("static register regex")
            .captures_iter(&target_text)
            .filter_map(|capture| capture.get(1)?.as_str().parse::<u32>().ok())
            .collect::<Vec<_>>();
        let first_register = registers.first().copied().unwrap_or(0);
        let register_list = registers
            .iter()
            .map(|register| format!("v{register}"))
            .collect::<Vec<_>>()
            .join(", ");
        let register_count = if target_text.contains("..") && registers.len() >= 2 {
            registers.last().unwrap().saturating_sub(first_register) + 1
        } else {
            registers.len() as u32
        };
        let mut method_index = 0;
        let mut field_index = 0;
        for target in self.instruction_targets(&target_text)? {
            match value_string(&target, "kind").as_str() {
                "method" => {
                    method_index = target.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                    break;
                }
                "field" => {
                    field_index = target.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                }
                _ => {}
            }
        }
        let integer = |name: &str, label: &str, value: u32| json!({"name": name, "label": label, "kind": "integer", "value": value.to_string()});
        let text = |name: &str, label: &str, value: &str| json!({"name": name, "label": label, "kind": "text", "value": value});
        let picker = |name: &str, label: &str, value: u32, kind: &str| json!({"name": name, "label": label, "kind": "integer", "value": value.to_string(), "picker": kind});
        let candidates = vec![
            ("nop", "Replace with NOP", "replace", vec![]),
            ("return_void", "Return void", "replace", vec![]),
            (
                "return_value",
                "Return register",
                "replace",
                vec![integer("register", "Return register", 0)],
            ),
            (
                "throw",
                "Throw register",
                "replace",
                vec![integer("register", "Throw register", 0)],
            ),
            (
                "const_string_value",
                "const-string value",
                "replace",
                vec![
                    integer("register", "Destination register", 0),
                    text("value", "String value", ""),
                ],
            ),
            (
                "const_string",
                "const-string index",
                "replace",
                vec![
                    integer("register", "Destination register", 0),
                    picker("string_index", "String pool entry", 0, "strings"),
                ],
            ),
            (
                "const_string_jumbo",
                "const-string/jumbo index",
                "replace",
                vec![
                    integer("register", "Destination register", 0),
                    picker("string_index", "String pool entry", 0, "strings"),
                ],
            ),
            (
                "const_lit32",
                "const literal",
                "replace",
                vec![
                    integer("register", "Destination register", 0),
                    integer("value", "Literal value", 0),
                ],
            ),
            (
                "move_from16",
                "move/from16",
                "replace",
                vec![
                    integer("register", "Destination register", 0),
                    integer("source_register", "Source register", 0),
                ],
            ),
            (
                "move_object_from16",
                "move-object/from16",
                "replace",
                vec![
                    integer("register", "Destination register", 0),
                    integer("source_register", "Source register", 0),
                ],
            ),
            (
                "new_instance",
                "new-instance",
                "replace",
                vec![
                    integer("register", "Destination register", 0),
                    picker("type_index", "Class/type entry", 0, "classes"),
                ],
            ),
            (
                "check_cast",
                "check-cast",
                "replace",
                vec![
                    integer("register", "Register", 0),
                    picker("type_index", "Class/type entry", 0, "classes"),
                ],
            ),
            ("nop", "Insert NOP before", "insert_before", vec![]),
            ("nop", "Insert NOP after", "insert_after", vec![]),
            ("nop", "Prepend NOP at method entry", "prepend", vec![]),
        ];
        let mut candidates = candidates;
        for (factory, label) in [
            ("invoke_virtual", "invoke-virtual"),
            ("invoke_super", "invoke-super"),
            ("invoke_direct", "invoke-direct"),
            ("invoke_static", "invoke-static"),
            ("invoke_interface", "invoke-interface"),
        ] {
            candidates.push((
                factory,
                label,
                "replace",
                vec![
                    integer(
                        "register_count",
                        "Argument register count",
                        register_count.min(5),
                    ),
                    text("registers", "Argument registers", &register_list),
                    picker("method_index", "Target method", method_index, "methods"),
                ],
            ));
        }
        for (factory, label) in [
            ("invoke_virtual_range", "invoke-virtual/range"),
            ("invoke_super_range", "invoke-super/range"),
            ("invoke_direct_range", "invoke-direct/range"),
            ("invoke_static_range", "invoke-static/range"),
            ("invoke_interface_range", "invoke-interface/range"),
        ] {
            candidates.push((
                factory,
                label,
                "replace",
                vec![
                    integer("register_count", "Argument register count", register_count),
                    picker("method_index", "Target method", method_index, "methods"),
                    integer("first_register", "First argument register", first_register),
                ],
            ));
        }
        candidates.push((
            "invoke_custom",
            "invoke-custom",
            "replace",
            vec![
                integer(
                    "register_count",
                    "Argument register count",
                    register_count.min(5),
                ),
                text("registers", "Argument registers", &register_list),
                integer("call_site_index", "Call-site index", 0),
            ],
        ));
        for (factory, label) in [
            ("instance_get", "iget"),
            ("instance_get_wide", "iget-wide"),
            ("instance_get_object", "iget-object"),
            ("instance_get_boolean", "iget-boolean"),
            ("instance_get_byte", "iget-byte"),
            ("instance_get_char", "iget-char"),
            ("instance_get_short", "iget-short"),
        ] {
            candidates.push((
                factory,
                label,
                "replace",
                vec![
                    integer("register", "Destination register", first_register),
                    integer("object_register", "Object register", 0),
                    picker("field_index", "Target field", field_index, "fields"),
                ],
            ));
        }
        for (factory, label) in [
            ("instance_put", "iput"),
            ("instance_put_wide", "iput-wide"),
            ("instance_put_object", "iput-object"),
            ("instance_put_boolean", "iput-boolean"),
            ("instance_put_byte", "iput-byte"),
            ("instance_put_char", "iput-char"),
            ("instance_put_short", "iput-short"),
        ] {
            candidates.push((
                factory,
                label,
                "replace",
                vec![
                    integer("register", "Source register", first_register),
                    integer("object_register", "Object register", 0),
                    picker("field_index", "Target field", field_index, "fields"),
                ],
            ));
        }
        for (factory, label) in [
            ("static_get", "sget"),
            ("static_get_wide", "sget-wide"),
            ("static_get_object", "sget-object"),
            ("static_get_boolean", "sget-boolean"),
            ("static_get_byte", "sget-byte"),
            ("static_get_char", "sget-char"),
            ("static_get_short", "sget-short"),
            ("static_put", "sput"),
            ("static_put_wide", "sput-wide"),
            ("static_put_object", "sput-object"),
            ("static_put_boolean", "sput-boolean"),
            ("static_put_byte", "sput-byte"),
            ("static_put_char", "sput-char"),
            ("static_put_short", "sput-short"),
        ] {
            candidates.push((
                factory,
                label,
                "replace",
                vec![
                    integer("register", "Register", first_register),
                    picker("field_index", "Target field", field_index, "fields"),
                ],
            ));
        }
        for (factory, label) in [
            ("if_eq", "Insert if-eq"),
            ("if_ne", "Insert if-ne"),
            ("if_lt", "Insert if-lt"),
            ("if_le", "Insert if-le"),
            ("if_gt", "Insert if-gt"),
            ("if_ge", "Insert if-ge"),
        ] {
            candidates.push((
                factory,
                label,
                "insert_before",
                vec![
                    integer("left_register", "Left register", 0),
                    integer("right_register", "Right register", 0),
                ],
            ));
        }
        for (factory, label) in [
            ("if_eqz", "Insert if-eqz"),
            ("if_nez", "Insert if-nez"),
            ("if_ltz", "Insert if-ltz"),
            ("if_lez", "Insert if-lez"),
            ("if_gtz", "Insert if-gtz"),
            ("if_gez", "Insert if-gez"),
        ] {
            candidates.push((
                factory,
                label,
                "insert_before",
                vec![integer("register", "Register", 0)],
            ));
        }
        candidates.push((
            "goto",
            "Insert goto → after selected",
            "insert_before",
            vec![],
        ));
        candidates.push((
            "switch",
            "Insert switch case → after selected",
            "insert_before",
            vec![
                integer("register", "Switch register", 0),
                integer("case_value", "Case value", 0),
            ],
        ));
        let mut options = Vec::new();
        for (factory, label, action, arguments) in candidates {
            let spec = EditSpec {
                method_id: method_id.clone(),
                offset,
                action: action.to_string(),
                factory: factory.to_string(),
            };
            let id = self.store(ObjectEntry {
                object: NativeObject::Edit(spec),
                evidence: None,
            });
            options.push(json!({
                "group": edit_group(factory, action),
                "id": id,
                "label": label,
                "action": action,
                "width": instruction_width(factory, &arguments).unwrap_or(0),
                "arguments": arguments,
            }));
        }
        Ok(
            json!({"selected_offset": offset, "width": target.size, "options": options, "available": true, "dex": method.file.get_dex_name()}),
        )
    }

    fn apply_edit(&mut self, request: &Value) -> BackendResult {
        let id = value_string(request, "id");
        let option = self.entry(&id)?;
        let NativeObject::Edit(spec) = &option.object else {
            return Err("unknown edit node".to_string());
        };
        let spec = spec.clone();
        let object = self.entry(&spec.method_id)?.object.clone();
        let NativeObject::Method(method) = object else {
            return Err("edit target is not a method".to_string());
        };
        let arguments = request.get("arguments").unwrap_or(&Value::Null);
        let edited = self.analysis_mut()?.edit_method(
            &method,
            spec.offset,
            &spec.action,
            &spec.factory,
            arguments,
        )?;
        if let Some(entry) = self.objects.get_mut(&spec.method_id) {
            entry.object = NativeObject::Method(edited);
            entry.evidence = None;
        }
        self.record_event(json!({
            "operation": "apply_edit",
            "method": method.signature(),
            "offset": spec.offset,
            "action": spec.action,
            "factory": spec.factory,
            "arguments": arguments,
        }));
        self.describe(spec.method_id)
    }

    fn adb_devices(&self, adb_path: String) -> BackendResult {
        let executable = if adb_path.trim().is_empty() {
            "adb"
        } else {
            adb_path.as_str()
        };
        let output = Command::new(executable)
            .args(["devices", "-l"])
            .output()
            .map_err(|error| format!("could not execute adb: {error}"))?;
        if !output.status.success() {
            return Err(format!("adb devices failed: {}", output_text(&output)));
        }
        let devices = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let parts = line.split_whitespace().collect::<Vec<_>>();
                if parts.len() < 2 || parts[1] != "device" {
                    return None;
                }
                let model = parts[2..]
                    .iter()
                    .find_map(|part| part.strip_prefix("model:"))
                    .unwrap_or_default();
                let serial = parts[0];
                Some(json!({
                    "serial": serial,
                    "model": model,
                    "label": if model.is_empty() { serial.to_string() } else { format!("{serial} — {model}") },
                }))
            })
            .collect::<Vec<_>>();
        Ok(json!({"devices": devices}))
    }

    fn adb_packages(&self, request: &Value) -> BackendResult {
        let packages = signing::list_installed_packages(
            optional_string(request, "package_regex"),
            optional_string(request, "serial"),
            optional_path(request, "adb_path"),
        )
        .map_err(|error| error.to_string())?;
        Ok(json!({"packages": packages}))
    }

    fn pull_apks(&mut self, request: &Value) -> BackendResult {
        let package = value_string(request, "package");
        let output_dir = value_string(request, "output_dir");
        let paths = signing::pull_installed_apks(
            &package,
            &output_dir,
            optional_string(request, "serial"),
            optional_path(request, "adb_path"),
        )
        .map_err(|error| error.to_string())?;
        let load_request = json!({"paths": paths.iter().map(|path| path.to_string_lossy().to_string()).collect::<Vec<_>>()});
        let mut loaded = self.load_split(&load_request)?;
        loaded["path"] = json!(format!("ADB: {package}"));
        loaded["split"] = json!(true);
        self.session_origin = Some(json!({
            "kind": "adb",
            "package": package,
            "serial": optional_string(request, "serial"),
            "adb_path": optional_string(request, "adb_path"),
        }));
        Ok(json!({"loaded": loaded, "output_dir": output_dir, "paths": paths}))
    }

    fn install_apk(&self, request: &Value) -> BackendResult {
        let path = PathBuf::from(value_string(request, "path"));
        let output = signing::install_apks(
            std::slice::from_ref(&path),
            optional_string(request, "serial"),
            optional_path(request, "adb_path"),
            request
                .get("replace_existing")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            false,
        )
        .map_err(|error| error.to_string())?;
        Ok(
            json!({"path": path, "serial": optional_string(request, "serial").unwrap_or_default(), "output": output}),
        )
    }

    fn install_split(&self, request: &Value) -> BackendResult {
        let paths = self.split_output_paths(&value_string(request, "output_dir"))?;
        let output = signing::install_apks(
            &paths,
            optional_string(request, "serial"),
            optional_path(request, "adb_path"),
            request
                .get("replace_existing")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            false,
        )
        .map_err(|error| error.to_string())?;
        Ok(json!({
            "output_dir": value_string(request, "output_dir"),
            "serial": optional_string(request, "serial").unwrap_or_default(),
            "output": output,
            "split": true,
        }))
    }

    fn sign_apk(&mut self, request: &Value) -> BackendResult {
        let output = value_string(request, "output");
        self.analysis()?.write(&output)?;
        signing::sign_apk(
            &output,
            optional_path(request, "apksigner"),
            Path::new(&value_string(request, "keystore")),
            &value_string(request, "alias"),
            &value_string(request, "store_password"),
            optional_string(request, "key_password"),
        )
        .map_err(|error| error.to_string())?;
        Ok(json!({"path": output}))
    }

    fn sign_split(&mut self, request: &Value) -> BackendResult {
        let output_dir = value_string(request, "output_dir");
        let paths = self.write_split(&output_dir)?;
        for path in &paths {
            signing::sign_apk(
                path,
                optional_path(request, "apksigner"),
                Path::new(&value_string(request, "keystore")),
                &value_string(request, "alias"),
                &value_string(request, "store_password"),
                optional_string(request, "key_password"),
            )
            .map_err(|error| error.to_string())?;
        }
        Ok(json!({"output_dir": output_dir, "paths": paths, "split": true}))
    }

    fn sign_and_install(&mut self, request: &Value) -> BackendResult {
        let signed = self.sign_apk(request)?;
        let install_request = json!({
            "path": signed.get("path").cloned().unwrap_or(Value::Null),
            "serial": request.get("serial"),
            "adb_path": request.get("adb_path"),
            "replace_existing": request.get("replace_existing"),
        });
        let installed = self.install_apk(&install_request)?;
        Ok(merge_objects(signed, installed))
    }

    fn sign_and_install_split(&mut self, request: &Value) -> BackendResult {
        self.sign_split(request)?;
        let install_request = json!({
            "output_dir": request.get("output_dir"),
            "serial": request.get("serial"),
            "adb_path": request.get("adb_path"),
            "replace_existing": request.get("replace_existing"),
        });
        self.install_split(&install_request)
    }

    fn split_output_paths(&self, output_dir: &str) -> Result<Vec<PathBuf>, String> {
        let Some(Session::Split(split)) = &self.session else {
            return Err("load a split APK set first".to_string());
        };
        Ok(split
            .names
            .iter()
            .map(|name| Path::new(output_dir).join(name))
            .collect())
    }

    fn write_split(&mut self, output_dir: &str) -> Result<Vec<PathBuf>, String> {
        let paths = self.split_output_paths(output_dir)?;
        fs::create_dir_all(output_dir)
            .map_err(|error| format!("could not create output directory: {error}"))?;
        if let Some(Session::Split(split)) = &self.session {
            for (member, path) in split.members.iter().zip(&paths) {
                member.write(&path.to_string_lossy())?;
            }
        }
        Ok(paths)
    }

    fn save_project(&mut self, request: &Value) -> BackendResult {
        let path = value_string(request, "path");
        if path.trim().is_empty() {
            return Err("save project requires a path".to_string());
        }
        let graph = request.get("graph").cloned().unwrap_or(Value::Null);
        let (names, bytes) =
            match self.session.as_ref() {
                Some(Session::Single(analysis)) => (
                    vec!["base.apk".to_string()],
                    vec![apk::repack_to_bytes(&analysis.files)
                        .map_err(|error| format!("could not save APK member base.apk: {error}"))?],
                ),
                Some(Session::Split(split)) => {
                    let mut bytes = Vec::with_capacity(split.members.len());
                    for (name, member) in split.names.iter().zip(&split.members) {
                        bytes.push(apk::repack_to_bytes(&member.files).map_err(|error| {
                            format!("could not save APK member {name}: {error}")
                        })?);
                    }
                    (split.names.clone(), bytes)
                }
                None => return Err("load an APK before saving a project".to_string()),
            };
        let mut history = self
            .session
            .as_ref()
            .map(Session::history)
            .unwrap_or_default();
        history.push("save_state".to_string());
        let state_metadata = json!({
            "format_version": 1,
            "members": names,
            "history": history,
        });
        let gui_metadata = json!({
            "format_version": 1,
            "origin": self.session_origin,
            "events": self.session_events,
            "history": self.session.as_ref().map(Session::history).unwrap_or_default(),
            "notes": self.notes,
            "aliases": self.aliases,
            "graph": graph,
        });
        let script = self.session_script();
        let file = File::create(&path)
            .map_err(|error| format!("could not create state archive {path}: {error}"))?;
        let mut writer = ZipWriter::new(file);
        write_zip_entry(
            &mut writer,
            "state.json",
            state_metadata.to_string().as_bytes(),
        )?;
        for (name, data) in names.iter().zip(bytes) {
            write_zip_entry(&mut writer, &format!("apks/{name}"), &data)?;
        }
        write_zip_entry(
            &mut writer,
            "gui/session.json",
            gui_metadata.to_string().as_bytes(),
        )?;
        write_zip_entry(&mut writer, "gui/session.py", script.as_bytes())?;
        writer
            .finish()
            .map_err(|error| format!("could not finish state archive: {error}"))?;
        if let Some(session) = self.session.as_mut() {
            match session {
                Session::Single(analysis) => analysis.history.push("save_state".to_string()),
                Session::Split(split) => split.history.push("save_state".to_string()),
            }
        }
        Ok(json!({
            "path": path,
            "history": self.session.as_ref().map(Session::history).unwrap_or_default(),
            "script": script,
        }))
    }

    fn generate_keystore(&self, request: &Value) -> BackendResult {
        let directory = PathBuf::from(value_string(request, "directory"));
        if !directory.is_dir() {
            return Err(format!(
                "keystore folder does not exist: {}",
                directory.display()
            ));
        }
        let requested_filename = value_string(request, "filename");
        let filename = Path::new(&requested_filename)
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("debug.keystore");
        let path = directory.join(filename);
        if path.exists() {
            return Err(format!("keystore already exists: {}", path.display()));
        }
        let alias = value_string(request, "alias");
        let store_password = value_string(request, "store_password");
        if alias.trim().is_empty() {
            return Err("keystore alias must not be empty".to_string());
        }
        if store_password.is_empty() {
            return Err("keystore password must not be empty".to_string());
        }
        let key_password = optional_string(request, "key_password")
            .map(str::to_string)
            .unwrap_or_else(|| store_password.clone());
        let output = Command::new(if cfg!(windows) {
            "keytool.exe"
        } else {
            "keytool"
        })
        .args([
            "-genkeypair",
            "-noprompt",
            "-keystore",
            path.to_string_lossy().as_ref(),
            "-alias",
            &alias,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-storepass",
            &store_password,
            "-keypass",
            &key_password,
            "-dname",
            "CN=CoEUS Debug,O=CoEUS,C=US",
        ])
        .output()
        .map_err(|error| format!("could not execute keytool: {error}"))?;
        if !output.status.success() {
            let _ = fs::remove_file(&path);
            return Err(format!("keytool failed: {}", output_text(&output)));
        }
        Ok(json!({"path": path, "alias": alias}))
    }

    fn set_note(&mut self, request: &Value) -> BackendResult {
        let key = value_string(request, "key").trim().to_string();
        if key.is_empty() {
            return Err("note requires an annotated object".to_string());
        }
        let note = value_string(request, "note");
        if note.trim().is_empty() {
            self.notes.remove(&key);
        } else {
            self.notes.insert(key.clone(), note.clone());
        }
        Ok(json!({"key": key, "note": note}))
    }

    fn set_alias(&mut self, request: &Value) -> BackendResult {
        let key = value_string(request, "key").trim().to_string();
        if key.is_empty() {
            return Err("alias requires a class or method identity".to_string());
        }
        let alias = value_string(request, "alias").trim().to_string();
        if alias.is_empty() {
            self.aliases.remove(&key);
        } else {
            self.aliases.insert(key.clone(), alias.clone());
        }
        Ok(json!({"key": key, "alias": alias}))
    }

    fn debug_connect(&mut self, host: String, port: u16) -> BackendResult {
        if self.debug_connecting {
            return Ok(json!({"connecting": true, "host": host, "port": port}));
        }
        let (sender, receiver) = mpsc::channel();
        let connect_host = if host.trim().is_empty() {
            "127.0.0.1".to_string()
        } else {
            host.clone()
        };
        thread::spawn(move || {
            let result = coeus::coeus_debug::create_debugger(&connect_host, port)
                .map(|(client, runtime)| NativeDebugger::new(client, runtime))
                .map_err(|error| format!("could not connect to JDWP: {error}"));
            let _ = sender.send(result);
        });
        self.debug_connecting = true;
        self.debug_connect_result = Some(receiver);
        Ok(json!({"connecting": true, "host": host, "port": port}))
    }

    fn debug_attach(&mut self, request: &Value) -> BackendResult {
        if self.debug_connecting {
            return Ok(json!({
                "connecting": true,
                "port": request.get("port").and_then(Value::as_u64).unwrap_or(8000),
            }));
        }
        let pid = request
            .get("pid")
            .and_then(Value::as_u64)
            .ok_or_else(|| "debugger process ID must be an unsigned integer".to_string())?
            as u32;
        let port = request.get("port").and_then(Value::as_u64).unwrap_or(8000) as u16;
        let serial = optional_string(request, "serial").map(str::to_string);
        let adb_path = optional_string(request, "adb_path").map(str::to_string);
        let (sender, receiver) = mpsc::channel();
        let worker_serial = serial.clone();
        let worker_adb_path = adb_path.clone();
        thread::spawn(move || {
            let result = signing::forward_jdwp(
                pid,
                port,
                worker_serial.as_deref(),
                worker_adb_path.as_deref().map(Path::new),
            )
            .and_then(|_| {
                coeus::coeus_debug::create_debugger("127.0.0.1", port)
                    .map_err(|error| error.to_string())
            })
            .map(|(client, runtime)| NativeDebugger::new(client, runtime))
            .map_err(|error| format!("could not attach to JDWP process: {error}"));
            let _ = sender.send(result);
        });
        self.debug_connecting = true;
        self.debug_connect_result = Some(receiver);
        Ok(json!({"connecting": true, "port": port, "pid": pid}))
    }

    fn debug_connect_poll(&mut self) -> BackendResult {
        let Some(receiver) = self.debug_connect_result.take() else {
            return Ok(json!({
                "connecting": false,
                "connected": self.debugger.is_some(),
            }));
        };
        match receiver.try_recv() {
            Ok(Ok(debugger)) => {
                self.debug_connecting = false;
                if let Some(wait) = self.debug_wait.take() {
                    wait.cancel.store(true, Ordering::Relaxed);
                }
                if let Some(previous) = self.debugger.take() {
                    if let Ok(mut previous) = previous.lock() {
                        previous.client.close();
                    }
                }
                self.debugger = Some(Arc::new(Mutex::new(debugger)));
                self.debug_frame = None;
                self.debug_waiting = false;
                self.debug_wait = None;
                Ok(json!({"connecting": false, "connected": true}))
            }
            Ok(Err(error)) => {
                self.debug_connecting = false;
                Err(error)
            }
            Err(mpsc::TryRecvError::Empty) => {
                self.debug_connect_result = Some(receiver);
                Ok(json!({"connecting": true}))
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.debug_connecting = false;
                Err("debugger connection worker disconnected".to_string())
            }
        }
    }

    fn debug_detach(&mut self) -> BackendResult {
        if let Some(wait) = self.debug_wait.take() {
            wait.cancel.store(true, Ordering::Relaxed);
        }
        self.debug_waiting = false;
        self.debug_frame = None;
        if let Some(debugger) = self.debugger.take() {
            debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?
                .client
                .close();
        }
        Ok(json!({"connected": false, "detached": true}))
    }

    fn debug_apps(&mut self, request: &Value) -> BackendResult {
        if self.debug_apps_loading {
            return Ok(json!({"loading": true}));
        }
        let serial = optional_string(request, "serial").map(str::to_string);
        let adb_path = optional_string(request, "adb_path").map(str::to_string);
        let worker_serial = serial.clone();
        let worker_adb_path = adb_path.clone();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = signing::list_debuggable_apps(
                worker_serial.as_deref(),
                worker_adb_path.as_deref().map(Path::new),
            );
            let _ = sender.send(result);
        });
        self.debug_apps_loading = true;
        self.debug_apps_result = Some(receiver);
        Ok(json!({"loading": true}))
    }

    fn debug_apps_poll(&mut self) -> BackendResult {
        let Some(receiver) = self.debug_apps_result.take() else {
            return Ok(json!({"loading": false, "apps": []}));
        };
        match receiver.try_recv() {
            Ok(Ok(apps)) => {
                self.debug_apps_loading = false;
                let apps = apps
                    .into_iter()
                    .map(|app| {
                        json!({
                            "pid": app.pid,
                            "process": app.process_name,
                            "package": app.package_name.unwrap_or_default(),
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(json!({"loading": false, "apps": apps}))
            }
            Ok(Err(error)) => {
                self.debug_apps_loading = false;
                Err(error)
            }
            Err(mpsc::TryRecvError::Empty) => {
                self.debug_apps_result = Some(receiver);
                Ok(json!({"loading": true}))
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.debug_apps_loading = false;
                Err("JDWP app discovery worker disconnected".to_string())
            }
        }
    }

    fn debug_method(&self, id: &str) -> Result<MethodObject, String> {
        match &self.entry(id)?.object {
            NativeObject::Method(method) => Ok(method.clone()),
            _ => Err("breakpoints require a method".to_string()),
        }
    }

    fn debug_breakpoint(&mut self, request: &Value) -> BackendResult {
        let debugger = self
            .debugger
            .as_ref()
            .cloned()
            .ok_or_else(|| "connect a debugger first".to_string())?;
        let method_id = value_string(request, "id");
        let method = self.debug_method(&method_id)?;
        let offset = value_u32(request, "offset")?;
        let method_key = method.signature();
        let key = (method_key.clone(), offset);
        let active = {
            let debugger = debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?;
            debugger.breakpoints.contains_key(&key)
        };
        if active {
            debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?
                .clear_breakpoint(&method, offset)?;
            if let Some(wait) = self.debug_wait.take() {
                let no_breakpoints = debugger
                    .lock()
                    .map_err(|_| "debugger lock was poisoned".to_string())?
                    .breakpoints
                    .is_empty();
                if no_breakpoints {
                    wait.cancel.store(true, Ordering::Relaxed);
                    self.debug_waiting = false;
                } else {
                    self.debug_wait = Some(wait);
                }
            }
            return Ok(json!({
                "enabled": false,
                "method_id": method_id,
                "method_key": method_key,
                "offset": offset,
                "location": format!("{}@0x{offset:x}", method_key),
                "waiting": self.debug_waiting,
            }));
        }

        debugger
            .lock()
            .map_err(|_| "debugger lock was poisoned".to_string())?
            .set_breakpoint(&method, offset)?;
        let waiting = if self.debug_frame.is_none() {
            self.debug_wait_start()?
                .get("waiting")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        } else {
            false
        };
        Ok(json!({
            "enabled": true,
            "method_id": method_id,
            "method_key": method_key,
            "offset": offset,
            "location": format!("{}@0x{offset:x}", method_key),
            "waiting": waiting,
        }))
    }

    fn debug_breakpoint_skip(&mut self, request: &Value) -> BackendResult {
        let debugger = self
            .debugger
            .as_ref()
            .cloned()
            .ok_or_else(|| "connect a debugger first".to_string())?;
        let method_id = value_string(request, "id");
        let method = self.debug_method(&method_id)?;
        let offset = value_u32(request, "offset")?;
        let method_key = method.signature();
        let key = (method_key.clone(), offset);
        let skip = request.get("skip").and_then(Value::as_bool).unwrap_or(true);
        let active = {
            let debugger = debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?;
            debugger.breakpoints.contains_key(&key)
        };
        if skip && active {
            debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?
                .clear_breakpoint(&method, offset)?;
        } else if !skip && !active {
            debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?
                .set_breakpoint(&method, offset)?;
        }
        if skip {
            let no_breakpoints = debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?
                .breakpoints
                .is_empty();
            if no_breakpoints {
                if let Some(wait) = self.debug_wait.take() {
                    wait.cancel.store(true, Ordering::Relaxed);
                }
                self.debug_waiting = false;
            }
        } else if self.debug_frame.is_none() {
            self.debug_wait_start()?;
        }
        Ok(json!({
            "enabled": !skip,
            "method_id": method_id,
            "method_key": method_key,
            "offset": offset,
            "location": format!("{}@0x{offset:x}", method_key),
            "waiting": self.debug_waiting,
        }))
    }

    fn debug_breakpoint_remove(&mut self, request: &Value) -> BackendResult {
        let debugger = self
            .debugger
            .as_ref()
            .cloned()
            .ok_or_else(|| "connect a debugger first".to_string())?;
        let method_id = value_string(request, "id");
        let method = self.debug_method(&method_id)?;
        let offset = value_u32(request, "offset")?;
        let method_key = method.signature();
        let key = (method_key.clone(), offset);
        let active = {
            let debugger = debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?;
            debugger.breakpoints.contains_key(&key)
        };
        if active {
            debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?
                .clear_breakpoint(&method, offset)?;
        }
        let no_breakpoints = debugger
            .lock()
            .map_err(|_| "debugger lock was poisoned".to_string())?
            .breakpoints
            .is_empty();
        if no_breakpoints {
            if let Some(wait) = self.debug_wait.take() {
                wait.cancel.store(true, Ordering::Relaxed);
            }
            self.debug_waiting = false;
        }
        Ok(json!({
            "enabled": false,
            "removed": true,
            "method_id": method_id,
            "method_key": method_key,
            "offset": offset,
            "location": format!("{}@0x{offset:x}", method_key),
            "waiting": self.debug_waiting,
        }))
    }

    fn debug_wait_start(&mut self) -> BackendResult {
        let debugger = self
            .debugger
            .as_ref()
            .cloned()
            .ok_or_else(|| "connect a debugger first".to_string())?;
        if self.debug_waiting {
            return Ok(json!({"waiting": true}));
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let result = debug_wait_worker(debugger, worker_cancel);
            let _ = sender.send(result);
        });
        self.debug_waiting = true;
        self.debug_wait = Some(NativeWait { receiver, cancel });
        Ok(json!({"waiting": true}))
    }

    fn debug_poll(&mut self) -> BackendResult {
        let Some(wait) = self.debug_wait.take() else {
            return Ok(json!({"waiting": false}));
        };
        match wait.receiver.try_recv() {
            Ok(Ok(Some(frame))) => {
                self.debug_waiting = false;
                Ok(json!({
                    "waiting": false,
                    "frame": self.debug_frame_data(frame)?,
                }))
            }
            Ok(Ok(None)) => {
                self.debug_waiting = false;
                Ok(json!({"waiting": false}))
            }
            Ok(Err(error)) => {
                self.debug_waiting = false;
                Err(error)
            }
            Err(mpsc::TryRecvError::Empty) => {
                self.debug_wait = Some(wait);
                Ok(json!({"waiting": true}))
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.debug_waiting = false;
                Err("debugger wait worker disconnected".to_string())
            }
        }
    }

    fn debug_resume(&mut self) -> BackendResult {
        let debugger = self
            .debugger
            .as_ref()
            .cloned()
            .ok_or_else(|| "connect a debugger first".to_string())?;
        {
            let mut debugger_guard = debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?;
            let runtime = debugger_guard.runtime.clone();
            let client = &mut debugger_guard.client;
            client
                .resume(&runtime, 1)
                .map_err(|error| format!("could not resume debugger: {error}"))?;
        }
        self.debug_frame = None;
        self.debug_wait_start()
    }

    fn debug_step(&mut self) -> BackendResult {
        let frame = self
            .debug_frame
            .as_ref()
            .ok_or_else(|| "the debugger is not stopped at a frame".to_string())?;
        let thread_id = frame.frame.thread_id;
        let debugger = self
            .debugger
            .as_ref()
            .cloned()
            .ok_or_else(|| "connect a debugger first".to_string())?;
        {
            let mut debugger_guard = debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?;
            let runtime = debugger_guard.runtime.clone();
            let step_id = debugger_guard
                .client
                .step(&runtime, thread_id)
                .map_err(|error| format!("could not request debugger step: {error}"))?;
            debugger_guard.last_step_id = Some(step_id);
            let runtime = debugger_guard.runtime.clone();
            debugger_guard
                .client
                .resume(&runtime, 1)
                .map_err(|error| format!("could not resume debugger for step: {error}"))?;
        }
        self.debug_frame = None;
        self.debug_wait_start()
    }

    fn debug_frame_data(&mut self, frame: StackFrame) -> Result<Value, String> {
        let debugger = self
            .debugger
            .as_ref()
            .cloned()
            .ok_or_else(|| "connect a debugger first".to_string())?;
        let (class_name, method_name, method_signature) = {
            let mut debugger_guard = debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?;
            let runtime = debugger_guard.runtime.clone();
            let class_name = debugger_guard
                .client
                .get_class_name(&runtime, frame.location.class_id)
                .map_err(|error| format!("could not resolve stopped class: {error}"))?;
            let runtime = debugger_guard.runtime.clone();
            let classes = debugger_guard
                .client
                .get_class(&runtime, &class_name)
                .map_err(|error| format!("could not resolve stopped method: {error}"))?;
            let class = classes
                .first()
                .ok_or_else(|| format!("class {class_name} is not loaded in the VM"))?;
            let method = class
                .get_method(frame.location.method_id)
                .map_err(|error| format!("could not resolve stopped method: {error}"))?;
            (class_name, method.name.clone(), method.signature.clone())
        };
        let method = self
            .find_debug_method(&class_name, &method_name, &method_signature)
            .ok_or_else(|| {
                format!("method {method_name}{method_signature} is not present in the loaded APK")
            })?;
        let method_id = self.store(ObjectEntry {
            object: NativeObject::Method(method.clone()),
            evidence: None,
        });
        let mut values = Vec::new();
        let mut values_error = None;
        if let Some(code) = method.data.as_ref().and_then(|data| data.code.as_ref()) {
            let mut debugger_guard = debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?;
            let runtime = debugger_guard.runtime.clone();
            match frame.get_values_with_slots(code, &mut debugger_guard.client, &runtime) {
                Ok(found) => {
                    values = infer_debug_value_types(&method, frame.location.code_index, found);
                }
                Err(error) => values_error = Some(error.to_string()),
            }
        } else {
            values_error = Some("the stopped method has no register metadata".to_string());
        }
        let value_text = {
            let mut debugger_guard = debugger
                .lock()
                .map_err(|_| "debugger lock was poisoned".to_string())?;
            values
                .iter()
                .map(|(slot, value)| (*slot, debug_value_text(&mut debugger_guard, value)))
                .collect::<Vec<_>>()
        };
        self.debug_frame = Some(NativeStoppedFrame { frame, values });
        let mut result = json!({
            "class": class_name,
            "method": method_name,
            "method_id": method_id,
            "code_index": self.debug_frame.as_ref().map(|frame| frame.frame.location.code_index).unwrap_or_default(),
            "values": value_text
                .into_iter()
                .map(|(slot, value)| json!({"slot": slot, "value": value}))
                .collect::<Vec<_>>(),
        });
        if let Some(error) = values_error {
            result["values_error"] = json!(error);
        }
        Ok(result)
    }

    fn find_debug_method(
        &self,
        class_name: &str,
        method_name: &str,
        method_signature: &str,
    ) -> Option<MethodObject> {
        let analysis = self.analysis().ok()?;
        let mut fallback = None;
        for dex in analysis.files.multi_dex.iter().flat_map(|multi_dex| {
            std::iter::once(&multi_dex.primary).chain(multi_dex.secondary.iter())
        }) {
            for class in dex
                .classes
                .iter()
                .filter(|class| class.class_name == class_name)
            {
                for data in &class.codes {
                    if data.method.method_name != method_name {
                        continue;
                    }
                    let method = method_object(dex, &data.method)?;
                    if data.method.proto_name == method_signature {
                        return Some(method);
                    }
                    fallback = Some(method);
                }
            }
        }
        fallback
    }

    fn debug_set_value(&mut self, request: &Value) -> BackendResult {
        let slot = request
            .get("slot")
            .and_then(Value::as_u64)
            .ok_or_else(|| "slot must be an unsigned integer".to_string())?;
        let text = value_string(request, "value");
        let debugger = self
            .debugger
            .as_ref()
            .cloned()
            .ok_or_else(|| "connect a debugger first".to_string())?;
        let frame = self
            .debug_frame
            .as_ref()
            .ok_or_else(|| "the debugger is not stopped at a frame".to_string())?;
        let old_value = frame
            .values
            .iter()
            .find(|(value_slot, _)| *value_slot == slot as u32)
            .map(|(_, value)| value)
            .ok_or_else(|| format!("register v{slot} is not available"))?
            .clone();
        let mut debugger_guard = debugger
            .lock()
            .map_err(|_| "debugger lock was poisoned".to_string())?;
        let new_value = debug_slot_value(&mut debugger_guard, &text, &old_value)?;
        let runtime = debugger_guard.runtime.clone();
        frame
            .frame
            .set_value(
                &mut debugger_guard.client,
                &runtime,
                slot as u32,
                &new_value,
            )
            .map_err(|error| format!("could not update register v{slot}: {error}"))?;
        let display = debug_value_text(&mut debugger_guard, &new_value);
        drop(debugger_guard);
        if let Some(frame) = self.debug_frame.as_mut() {
            if let Some((_, value)) = frame
                .values
                .iter_mut()
                .find(|(value_slot, _)| *value_slot == slot as u32)
            {
                *value = new_value;
            }
        }
        Ok(json!({"slot": slot, "value": display}))
    }

    fn export_script(&self, path: String) -> BackendResult {
        let script = self.session_script();
        fs::write(&path, script)
            .map_err(|error| format!("could not write Coeus script {path}: {error}"))?;
        Ok(json!({"path": path}))
    }

    fn session_script(&self) -> String {
        if let Some(script) = &self.session_script_override {
            if self.session_events.is_empty() {
                return script.clone();
            }
        }
        let origin = self.session_origin.as_ref().unwrap_or(&Value::Null);
        let mut lines = vec![
            "# Generated by Coeus GUI. Review paths and values before running.".to_string(),
            "import re".to_string(),
            "from coeus_python import AnalyzeObject, DexInstruction, SplitApkSet".to_string(),
            String::new(),
        ];
        match origin.get("kind").and_then(Value::as_str) {
            Some("state") => {
                lines.push(format!(
                    "analysis = SplitApkSet.load_state({})",
                    python_literal(
                        origin
                            .get("path")
                            .unwrap_or(&Value::String("project.coeus".to_string(),))
                    )
                ));
                lines.push("ao = analysis.get_base_apk()".to_string());
            }
            Some("split") => {
                lines.push(format!(
                    "analysis = SplitApkSet({})",
                    python_literal(origin.get("paths").unwrap_or(&Value::Array(Vec::new())))
                ));
                lines.push("ao = analysis.get_base_apk()".to_string());
            }
            Some("adb") => {
                lines.push(format!(
                    "analysis = SplitApkSet.from_adb({}, {}, {})",
                    python_literal(
                        origin
                            .get("package")
                            .unwrap_or(&Value::String(String::new(),))
                    ),
                    python_literal(origin.get("serial").unwrap_or(&Value::Null)),
                    python_literal(origin.get("adb_path").unwrap_or(&Value::Null)),
                ));
                lines.push("ao = analysis.get_base_apk()".to_string());
            }
            _ => lines.push(format!(
                "ao = AnalyzeObject({}, False, -1)",
                python_literal(
                    origin
                        .get("path")
                        .unwrap_or(&Value::String("input.apk".to_string(),))
                )
            )),
        }
        lines.extend([
            String::new(),
            "def find_method(signature):".to_string(),
            "    name = signature.split('->', 1)[-1].split('(', 1)[0]".to_string(),
            "    for evidence in ao.find_methods(re.escape(name)):".to_string(),
            "        try:".to_string(),
            "            method = evidence.as_method()".to_string(),
            "            if method.signature() == signature:".to_string(),
            "                return method".to_string(),
            "        except Exception:".to_string(),
            "            pass".to_string(),
            "    raise RuntimeError('method not found: ' + signature)".to_string(),
            String::new(),
            "def find_string(dex_name, index):".to_string(),
            "    for evidence in ao.find_strings('.*'):".to_string(),
            "        try:".to_string(),
            "            value = evidence.as_string()".to_string(),
            "            if value.get_dex_name() == dex_name and value.get_index() == index:"
                .to_string(),
            "                return value".to_string(),
            "        except Exception:".to_string(),
            "            pass".to_string(),
            "    raise RuntimeError('string not found: {}:{}'.format(dex_name, index))".to_string(),
            String::new(),
        ]);
        for event in &self.session_events {
            let operation = event.get("operation").and_then(Value::as_str);
            match operation {
                Some("set_manifest_xml") => {
                    lines.push(format!(
                        "ao.set_manifest_xml({})",
                        python_literal(event.get("xml").unwrap_or(&Value::String(String::new())))
                    ));
                    lines.push(String::new());
                }
                Some("set_debuggable") => {
                    lines.push(format!(
                        "ao.set_debuggable({})",
                        python_literal(event.get("enabled").unwrap_or(&Value::Bool(false)))
                    ));
                    lines.push(String::new());
                }
                Some("allow_plaintext_and_user_certificates") => {
                    lines.push("ao.allow_plaintext_and_user_certificates()".to_string());
                    lines.push(String::new());
                }
                Some("replace_string") => {
                    lines.push(format!(
                        "ao.replace_string(find_string({}, {}), {})",
                        python_literal(event.get("dex").unwrap_or(&Value::String(String::new()))),
                        event.get("index").and_then(Value::as_u64).unwrap_or(0),
                        python_literal(
                            event
                                .get("replacement")
                                .unwrap_or(&Value::String(String::new()))
                        ),
                    ));
                    lines.push(String::new());
                }
                Some("apply_edit") => {
                    let factory = value_string(event, "factory");
                    let arguments = event.get("arguments").unwrap_or(&Value::Null);
                    let Some(replacement) = script_instruction(&factory, arguments) else {
                        lines.push(format!("# Unsupported recorded edit: {event}"));
                        lines.push(String::new());
                        continue;
                    };
                    lines.push(format!(
                        "method = find_method({})",
                        python_literal(
                            event.get("method").unwrap_or(&Value::String(String::new()))
                        )
                    ));
                    lines.push(format!("target = next(i for i in method.get_instructions() if i.get_offset() == {})", event.get("offset").and_then(Value::as_u64).unwrap_or(0)));
                    lines.push("editor = ao.edit_method(method)".to_string());
                    lines.push("after = editor.label_after(target)".to_string());
                    lines.push(format!("replacement = {replacement}"));
                    match event
                        .get("action")
                        .and_then(Value::as_str)
                        .unwrap_or("replace")
                    {
                        "prepend" => lines.push("editor.prepend([replacement])".to_string()),
                        "insert_before" => {
                            lines.push("editor.insert_before(target, [replacement])".to_string())
                        }
                        "insert_after" => {
                            lines.push("editor.insert_after(target, [replacement])".to_string())
                        }
                        _ => lines.push("editor.replace(target, [replacement])".to_string()),
                    }
                    lines.extend(["method = editor.commit(ao)".to_string(), String::new()]);
                }
                Some("write") => {
                    lines.push(format!(
                        "ao.write_apk({})",
                        python_literal(
                            event
                                .get("path")
                                .unwrap_or(&Value::String("edited.apk".to_string()))
                        )
                    ));
                    lines.push(String::new());
                }
                _ => {}
            }
        }
        lines.extend([
            "# Example output when no explicit write was recorded:".to_string(),
            "# ao.write_apk('edited.apk')".to_string(),
        ]);
        lines.join("\n") + "\n"
    }
}

fn debug_wait_worker(
    debugger: Arc<Mutex<NativeDebugger>>,
    cancel: Arc<AtomicBool>,
) -> Result<Option<StackFrame>, String> {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let mut debugger_guard = debugger
            .lock()
            .map_err(|_| "debugger lock was poisoned".to_string())?;
        let runtime = debugger_guard.runtime.clone();
        let packet = debugger_guard
            .client
            .wait_for_event_timeout(&runtime, Duration::from_millis(250))
            .map_err(|error| format!("JDWP event wait failed: {error}"))?;
        let Some(packet) = packet else {
            continue;
        };
        let composite = match Composite::try_from(packet) {
            Ok(composite) => composite,
            Err(_) => continue,
        };
        let mut step_event = false;
        let mut thread = None;
        let mut vm_start = false;
        for event in composite.events {
            match event {
                Event::SingleStep(data) => {
                    step_event = true;
                    thread = Some(data.get_thread());
                    break;
                }
                Event::Breakpoint(data) => {
                    thread = Some(data.get_thread());
                    break;
                }
                Event::VmStart(_) => vm_start = true,
                Event::VmDeath => return Ok(None),
            }
        }
        let Some(thread) = thread else {
            if vm_start {
                let runtime = debugger_guard.runtime.clone();
                debugger_guard
                    .client
                    .resume(&runtime, 1)
                    .map_err(|error| format!("could not resume VM after start: {error}"))?;
            }
            continue;
        };
        if step_event {
            if let Some(step_id) = debugger_guard.last_step_id.take() {
                let runtime = debugger_guard.runtime.clone();
                let _ = debugger_guard.client.clear_step(&runtime, step_id);
            }
        }
        let runtime = debugger_guard.runtime.clone();
        let frame = thread
            .get_top_frame(&mut debugger_guard.client, &runtime)
            .map_err(|error| format!("could not read stopped stack frame: {error}"))?;
        return Ok(Some(frame));
    }
}

fn parallel_read_operation(request: &Value) -> bool {
    matches!(
        request.get("op").and_then(Value::as_str),
        Some(
            "history"
                | "manifest"
                | "search"
                | "edit_search"
                | "describe"
                | "xrefs"
                | "graph"
                | "graph_node_details"
                | "edit_options"
                | "adb_devices"
                | "adb_packages"
        )
    )
}

/// JDWP reports a null local whose declared type is an object as a generic
/// `Object(0)`.  That loses the distinction between a String, an array and a
/// regular object, even though the DEX code still contains that information.
/// In particular, `invoke-virtual ...->getKeyId()Ljava/lang/String;` followed
/// by `move-result-object v7` must leave v7 as a String slot even when the
/// returned value is null.
fn infer_debug_value_types(
    method: &MethodObject,
    code_index: u64,
    values: Vec<(u32, SlotValue)>,
) -> Vec<(u32, SlotValue)> {
    let string_registers = debug_string_registers(method, code_index);
    values
        .into_iter()
        .map(|(slot, value)| {
            if string_registers.contains(&(slot as u16))
                && matches!(value.value, DebugValue::Object(_))
            {
                let object_id = match value.value {
                    DebugValue::Object(object_id) => object_id,
                    _ => unreachable!("the value was checked to be an object"),
                };
                (slot, DebugValue::String(object_id).into())
            } else {
                (slot, value)
            }
        })
        .collect()
}

fn debug_string_registers(
    method: &MethodObject,
    code_index: u64,
) -> std::collections::HashSet<u16> {
    let mut string_registers = std::collections::HashSet::new();
    let mut pending_invoke_returns_string = None;

    for native_instruction in method.instructions() {
        if native_instruction.offset as u64 > code_index {
            break;
        }

        match &native_instruction.instruction {
            instruction if invoke_method_index(instruction).is_some() => {
                pending_invoke_returns_string = invoke_method_index(instruction)
                    .and_then(|method_idx| method.file.methods.get(method_idx as usize))
                    .and_then(|target| method.file.protos.get(target.proto_idx as usize))
                    .and_then(|proto| method.file.get_type_name(proto.return_type_idx as usize))
                    .map(|return_type| return_type == "Ljava/lang/String;");
            }
            Instruction::MoveResultObject(register) => {
                if pending_invoke_returns_string == Some(true) {
                    string_registers.insert(*register as u16);
                } else {
                    string_registers.remove(&(*register as u16));
                }
                pending_invoke_returns_string = None;
            }
            Instruction::MoveResult(register) | Instruction::MoveResultWide(register) => {
                string_registers.remove(&(*register as u16));
                pending_invoke_returns_string = None;
            }
            Instruction::ConstString(register, _) | Instruction::ConstStringJumbo(register, _) => {
                string_registers.insert(*register as u16);
                pending_invoke_returns_string = None;
            }
            Instruction::MoveObject(destination, source) => {
                copy_debug_string_type(
                    &mut string_registers,
                    u16::from(*destination),
                    u16::from(*source),
                );
                pending_invoke_returns_string = None;
            }
            Instruction::MoveObjectFrom16(destination, source) => {
                copy_debug_string_type(&mut string_registers, u16::from(*destination), *source);
                pending_invoke_returns_string = None;
            }
            Instruction::MoveObject16(destination, source) => {
                copy_debug_string_type(&mut string_registers, *destination, *source);
                pending_invoke_returns_string = None;
            }
            Instruction::CheckCast(register, type_idx) => {
                if method.file.get_type_name(*type_idx) == Some("Ljava/lang/String;") {
                    string_registers.insert(*register as u16);
                } else {
                    string_registers.remove(&(*register as u16));
                }
                pending_invoke_returns_string = None;
            }
            Instruction::NewInstance(register, _) => {
                string_registers.remove(&(*register as u16));
                pending_invoke_returns_string = None;
            }
            _ => pending_invoke_returns_string = None,
        }
    }

    string_registers
}

fn copy_debug_string_type(
    string_registers: &mut std::collections::HashSet<u16>,
    destination: u16,
    source: u16,
) {
    if string_registers.contains(&source) {
        string_registers.insert(destination);
    } else {
        string_registers.remove(&destination);
    }
}

fn invoke_method_index(instruction: &Instruction) -> Option<u16> {
    match instruction {
        Instruction::InvokeVirtual(_, method_idx, _)
        | Instruction::InvokeSuper(_, method_idx, _)
        | Instruction::InvokeDirect(_, method_idx, _)
        | Instruction::InvokeStatic(_, method_idx, _)
        | Instruction::InvokeInterface(_, method_idx, _)
        | Instruction::InvokeVirtualRange(_, method_idx, _)
        | Instruction::InvokeSuperRange(_, method_idx, _)
        | Instruction::InvokeDirectRange(_, method_idx, _)
        | Instruction::InvokeStaticRange(_, method_idx, _)
        | Instruction::InvokeInterfaceRange(_, method_idx, _) => Some(*method_idx),
        _ => None,
    }
}

fn debug_value_text(debugger: &mut NativeDebugger, value: &SlotValue) -> String {
    match &value.value {
        DebugValue::Object(0) => "None".to_string(),
        DebugValue::Object(object_id) => debugger
            .client
            .get_object(&debugger.runtime, *object_id)
            .map(|object| format!("{}\\n@{}", object.signature, object.object_id))
            .unwrap_or_else(|error| format!("<{error}>")),
        DebugValue::String(0) | DebugValue::Array(0) => "None".to_string(),
        DebugValue::String(string_id) => debugger
            .client
            .get_string(&debugger.runtime, *string_id)
            .map(|value| format!("{value:?}"))
            .unwrap_or_else(|error| format!("<{error}>")),
        DebugValue::Array(array_id) => debugger
            .client
            .get_array(&debugger.runtime, *array_id)
            .map(|value| format!("{value:?}"))
            .unwrap_or_else(|error| format!("<{error}>")),
        DebugValue::Byte(value) => format!("{value:?}"),
        DebugValue::Short(value) => format!("{value:?}"),
        DebugValue::Int(value) => format!("{value:?}"),
        DebugValue::Long(value) => format!("{value:?}"),
        DebugValue::Float(value) => format!("{value:?}"),
        DebugValue::Double(value) => format!("{value:?}"),
        DebugValue::Boolean(value) => (if *value == 0 { "False" } else { "True" }).to_string(),
        DebugValue::Char(value) => format!("{value:?}"),
        DebugValue::Void => "<void>".to_string(),
        DebugValue::Reference(0) => "None".to_string(),
        DebugValue::Reference(reference) => format!("<reference @{reference}>"),
    }
}

fn parse_debug_integer(text: &str) -> Result<i64, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("value must not be empty".to_string());
    }
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let radix = if digits.starts_with("0x") || digits.starts_with("0X") {
        16
    } else if digits.starts_with("0o") || digits.starts_with("0O") {
        8
    } else if digits.starts_with("0b") || digits.starts_with("0B") {
        2
    } else {
        10
    };
    let digits = match radix {
        16 | 8 | 2 => &digits[2..],
        _ => digits,
    };
    let value = i64::from_str_radix(digits, radix)
        .map_err(|_| format!("{text:?} is not a valid integer"))?;
    if negative {
        value
            .checked_neg()
            .ok_or_else(|| format!("{text:?} is outside the supported integer range"))
    } else {
        Ok(value)
    }
}

fn debug_slot_value(
    debugger: &mut NativeDebugger,
    text: &str,
    old_value: &SlotValue,
) -> Result<SlotValue, String> {
    let normalized = text.trim();
    if matches!(
        normalized.to_ascii_lowercase().as_str(),
        "none" | "null" | "nil"
    ) {
        return match old_value.value {
            DebugValue::Object(_) => Ok(DebugValue::Object(0).into()),
            DebugValue::Array(_) => Ok(DebugValue::Array(0).into()),
            DebugValue::String(_) => Ok(DebugValue::String(0).into()),
            DebugValue::Reference(_) => {
                Err("thread and VM references cannot be edited from the GUI".to_string())
            }
            DebugValue::Void => Err("void registers cannot be edited".to_string()),
            _ => Err("None is only valid for reference registers".to_string()),
        };
    }
    let value = match &old_value.value {
        DebugValue::Boolean(_) => match text.trim().to_ascii_lowercase().as_str() {
            "true" => DebugValue::Boolean(1),
            "false" => DebugValue::Boolean(0),
            _ => return Err("boolean registers accept true or false".to_string()),
        },
        DebugValue::Byte(_) => DebugValue::Byte(
            parse_debug_integer(text)?
                .try_into()
                .map_err(|_| "value is outside the byte range".to_string())?,
        ),
        DebugValue::Short(_) => DebugValue::Short(
            parse_debug_integer(text)?
                .try_into()
                .map_err(|_| "value is outside the short range".to_string())?,
        ),
        DebugValue::Int(_) => DebugValue::Int(
            parse_debug_integer(text)?
                .try_into()
                .map_err(|_| "value is outside the integer range".to_string())?,
        ),
        DebugValue::Long(_) => DebugValue::Long(parse_debug_integer(text)?),
        DebugValue::Float(_) => DebugValue::Float(
            text.trim()
                .parse::<f32>()
                .map_err(|_| format!("{text:?} is not a valid float"))?,
        ),
        DebugValue::Double(_) => DebugValue::Double(
            text.trim()
                .parse::<f64>()
                .map_err(|_| format!("{text:?} is not a valid double"))?,
        ),
        DebugValue::Char(_) => {
            let trimmed = text.trim().trim_matches(['\'', '"']);
            let character = trimmed
                .chars()
                .next()
                .ok_or_else(|| "character registers accept one character".to_string())?;
            DebugValue::Char(character)
        }
        DebugValue::String(_) => DebugValue::String(
            debugger
                .client
                .create_string(&debugger.runtime, text)
                .map_err(|error| format!("could not create debugger string: {error}"))?,
        ),
        DebugValue::Object(_) => DebugValue::Object(parse_debug_reference(text)?),
        DebugValue::Array(_) => DebugValue::Array(parse_debug_reference(text)?),
        DebugValue::Reference(_) => {
            return Err("thread and VM references cannot be edited from the GUI".to_string())
        }
        DebugValue::Void => return Err("void registers cannot be edited".to_string()),
    };
    Ok(SlotValue::from(value))
}

fn parse_debug_reference(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let reference = text.rsplit('@').next().unwrap_or(text).trim();
    let (radix, digits) = if reference.starts_with("0x") || reference.starts_with("0X") {
        (16, &reference[2..])
    } else {
        (10, reference)
    };
    u64::from_str_radix(digits, radix)
        .map_err(|_| format!("{text:?} is not a valid object reference; use @<id>"))
}

fn python_literal(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(value) => {
            if *value {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(python_literal)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!(
                    "{}: {}",
                    python_literal(&Value::String(key.clone())),
                    python_literal(value)
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn script_integer(arguments: &Value, name: &str, default: &str) -> String {
    let value = arguments
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or(default);
    format!(
        "int({}, 0)",
        python_literal(&Value::String(value.to_string()))
    )
}

fn script_text(arguments: &Value, name: &str, default: &str) -> String {
    let value = arguments
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or(default);
    python_literal(&Value::String(value.to_string()))
}

fn script_instruction(factory: &str, arguments: &Value) -> Option<String> {
    let integer = |name: &str| script_integer(arguments, name, "0");
    let default_one = |name: &str| script_integer(arguments, name, "1");
    let text = |name: &str| script_text(arguments, name, "");
    let registers = || {
        argument_text(arguments, "registers", "")
            .split(|character: char| character == ',' || character.is_whitespace())
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                let value = value.trim().strip_prefix('v').unwrap_or(value.trim());
                format!(
                    "int({}, 0)",
                    python_literal(&Value::String(value.to_string()))
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    Some(match factory {
        "nop" => "DexInstruction.nop()".to_string(),
        "return_void" => "DexInstruction.return_void()".to_string(),
        "return_value" => format!("DexInstruction.return_value({})", integer("register")),
        "throw" => format!("DexInstruction.throw({})", integer("register")),
        "const_string_value" => format!(
            "DexInstruction.const_string_value({}, {})",
            integer("register"),
            text("value")
        ),
        "const_string" => format!(
            "DexInstruction.const_string({}, {})",
            integer("register"),
            integer("string_index")
        ),
        "const_string_jumbo" => format!(
            "DexInstruction.const_string_jumbo({}, {})",
            integer("register"),
            integer("string_index")
        ),
        "const_lit32" => format!(
            "DexInstruction.const_lit32({}, {})",
            integer("register"),
            integer("value")
        ),
        "move_from16" | "move_object_from16" => format!(
            "DexInstruction.{factory}({}, {})",
            integer("register"),
            integer("source_register")
        ),
        "new_instance" | "check_cast" => format!(
            "DexInstruction.{factory}({}, {})",
            integer("register"),
            integer("type_index")
        ),
        "invoke_virtual" | "invoke_super" | "invoke_direct" | "invoke_static"
        | "invoke_interface" => format!(
            "DexInstruction.{factory}({}, {}, {})",
            default_one("register_count"),
            integer("method_index"),
            format!("[{}]", registers())
        ),
        "invoke_custom" => format!(
            "DexInstruction.invoke_custom({}, {}, {})",
            default_one("register_count"),
            integer("call_site_index"),
            format!("[{}]", registers())
        ),
        "invoke_virtual_range"
        | "invoke_super_range"
        | "invoke_direct_range"
        | "invoke_static_range"
        | "invoke_interface_range" => format!(
            "DexInstruction.{factory}({}, {}, {})",
            default_one("register_count"),
            integer("method_index"),
            integer("first_register")
        ),
        "instance_get"
        | "instance_get_wide"
        | "instance_get_object"
        | "instance_get_boolean"
        | "instance_get_byte"
        | "instance_get_char"
        | "instance_get_short"
        | "instance_put"
        | "instance_put_wide"
        | "instance_put_object"
        | "instance_put_boolean"
        | "instance_put_byte"
        | "instance_put_char"
        | "instance_put_short" => format!(
            "DexInstruction.{factory}({}, {}, {})",
            integer("register"),
            integer("object_register"),
            integer("field_index")
        ),
        "static_get" | "static_get_wide" | "static_get_object" | "static_get_boolean"
        | "static_get_byte" | "static_get_char" | "static_get_short" | "static_put"
        | "static_put_wide" | "static_put_object" | "static_put_boolean" | "static_put_byte"
        | "static_put_char" | "static_put_short" => format!(
            "DexInstruction.{factory}({}, {})",
            integer("register"),
            integer("field_index")
        ),
        "if_eq" | "if_ne" | "if_lt" | "if_le" | "if_gt" | "if_ge" => format!(
            "DexInstruction.{factory}({}, {}, after)",
            integer("left_register"),
            integer("right_register")
        ),
        "if_eqz" | "if_nez" | "if_ltz" | "if_lez" | "if_gtz" | "if_gez" => {
            format!("DexInstruction.{factory}({}, after)", integer("register"))
        }
        "goto" => "DexInstruction.goto(after)".to_string(),
        "switch" => format!(
            "DexInstruction.switch({}, [({}, after)])",
            integer("register"),
            integer("case_value")
        ),
        _ => return None,
    })
}

fn object_from_evidence(evidence: &Evidence) -> Result<NativeObject, String> {
    if let Evidence::Instructions(instructions) = evidence {
        if let Context::DexField(field, file) = &instructions.context {
            return Ok(NativeObject::FieldAccess(FieldAccessObject {
                field: field_object(file, field),
                place: instructions.place.clone(),
                instruction: instructions
                    .instructions
                    .first()
                    .cloned()
                    .unwrap_or_default(),
            }));
        }
    }
    let context = if matches!(evidence, Evidence::CrossReference(_)) {
        evidence.get_place_context()
    } else {
        evidence.get_context()
    };
    match context {
        Some(Context::DexMethod(method, file)) => method_object(file, method)
            .map(NativeObject::Method)
            .ok_or_else(|| "could not construct method object".to_string()),
        Some(Context::DexClass(class, file)) => Ok(NativeObject::Class(ClassObject {
            class: class.clone(),
            file: file.clone(),
        })),
        Some(Context::DexType(index, name, file)) => Ok(NativeObject::Class(ClassObject {
            class: file.get_class_by_type(*index).unwrap_or_else(|| {
                Arc::new(ModelClass {
                    dex_identifier: file.identifier.clone(),
                    class_idx: *index,
                    class_name: name.clone(),
                    ..Default::default()
                })
            }),
            file: file.clone(),
        })),
        Some(Context::DexField(field, file)) | Some(Context::DexStaticField(field, file)) => {
            Ok(NativeObject::Field(field_object(file, field)))
        }
        Some(Context::DexString(index, file)) => Ok(NativeObject::String(StringObject {
            index: *index,
            content: file
                .get_string(*index as usize)
                .unwrap_or_default()
                .to_string(),
            file: file.clone(),
        })),
        Some(Context::DexProto(proto, file)) => Ok(NativeObject::Proto(ProtoObject {
            proto: proto.clone(),
            file: file.clone(),
        })),
        Some(Context::NativeLib(_, symbol, ..)) | Some(Context::NativeSymbol(_, symbol)) => {
            Ok(NativeObject::Native(NativeSymbolObject {
                symbol: symbol.to_string(),
            }))
        }
        _ => {
            // Cross-reference evidence is anchored by its location.  A few
            // older analysis paths do not populate a fully typed place
            // context, but a DEX-method location is still sufficient to open
            // and inspect the referencing method.
            if let Evidence::CrossReference(cross_reference) = evidence {
                if let Some(method) = method_from_location(&cross_reference.place) {
                    return Ok(NativeObject::Method(method));
                }
            }
            Err("unsupported evidence object".to_string())
        }
    }
}

fn method_object(file: &Arc<DexFile>, method: &Arc<ModelMethod>) -> Option<MethodObject> {
    let class = file.get_class_by_type(method.class_idx).unwrap_or_else(|| {
        Arc::new(ModelClass {
            dex_identifier: file.identifier.clone(),
            class_idx: method.class_idx as u32,
            class_name: file
                .get_type_name(method.class_idx)
                .unwrap_or("UNKNOWN")
                .to_string(),
            ..Default::default()
        })
    });
    let data = class
        .codes
        .iter()
        .find(|data| {
            data.method.method_name == method.method_name
                && data.method.proto_name == method.proto_name
        })
        .cloned()
        .or_else(|| file.get_method_by_idx(method.method_idx as u32));
    Some(MethodObject {
        method: method.clone(),
        data,
        file: file.clone(),
        class,
    })
}

fn field_object(file: &Arc<DexFile>, field: &Arc<ModelField>) -> FieldObject {
    let class = file.get_class_by_type(field.class_idx).unwrap_or_else(|| {
        Arc::new(ModelClass {
            dex_identifier: file.identifier.clone(),
            class_idx: field.class_idx as u32,
            class_name: file
                .get_type_name(field.class_idx)
                .unwrap_or("UNKNOWN")
                .to_string(),
            ..Default::default()
        })
    });
    FieldObject {
        field: field.clone(),
        file: file.clone(),
        class: ClassObject {
            class,
            file: file.clone(),
        },
    }
}

fn method_from_location(location: &Location) -> Option<MethodObject> {
    let Location::DexMethod(index, file) = location else {
        return None;
    };
    let method_data = file.get_method_by_idx(*index)?;
    method_object(file, &method_data.method)
}

fn object_kind(object: &NativeObject) -> String {
    match object {
        NativeObject::Method(_) => "method",
        NativeObject::Class(_) => "class",
        NativeObject::Field(_) => "field",
        NativeObject::String(_) => "string",
        NativeObject::Proto(_) => "proto",
        NativeObject::FieldAccess(_) => "field_access",
        NativeObject::Native(_) => "native",
        NativeObject::Edit(_) => "edit",
    }
    .to_string()
}

fn object_label(object: &NativeObject) -> String {
    match object {
        NativeObject::Method(method) => method.signature(),
        NativeObject::Class(class) => class.class.class_name.clone(),
        NativeObject::Field(field) => {
            format!("{}->{}", field.class.class.class_name, field.field.name)
        }
        NativeObject::String(string) => string.content.clone(),
        NativeObject::Proto(proto) => proto.proto.to_string(&proto.file),
        NativeObject::FieldAccess(access) => format!(
            "{} :: {}",
            access.field.class.class.class_name, access.instruction
        ),
        NativeObject::Native(native) => native.symbol.clone(),
        NativeObject::Edit(_) => "edit".to_string(),
    }
}

fn object_index(object: &NativeObject) -> Option<u32> {
    match object {
        NativeObject::Method(method) => Some(method.method.method_idx as u32),
        NativeObject::Class(class) => Some(class.class.class_idx),
        NativeObject::Field(field) => field
            .file
            .fields
            .iter()
            .position(|candidate| candidate.as_ref() == field.field.as_ref())
            .map(|index| index as u32),
        NativeObject::String(string) => Some(string.index),
        NativeObject::Proto(proto) => proto
            .file
            .protos
            .iter()
            .position(|candidate| candidate.as_ref() == proto.proto.as_ref())
            .map(|index| index as u32),
        _ => None,
    }
}

fn object_dex_name(object: &NativeObject) -> Option<String> {
    match object {
        NativeObject::Method(method) => Some(method.file.get_dex_name().to_string()),
        NativeObject::Class(class) => Some(class.file.get_dex_name().to_string()),
        NativeObject::Field(field) => Some(field.file.get_dex_name().to_string()),
        NativeObject::String(string) => Some(string.file.get_dex_name().to_string()),
        NativeObject::Proto(proto) => Some(proto.file.get_dex_name().to_string()),
        NativeObject::FieldAccess(access) => Some(access.field.file.get_dex_name().to_string()),
        _ => None,
    }
}

fn note_key(kind: &str, label: &str) -> Option<String> {
    matches!(kind, "method" | "class" | "string").then(|| format!("{kind}:{label}"))
}

fn is_payload(instruction: &Instruction) -> bool {
    matches!(
        instruction,
        Instruction::ArrayData(..)
            | Instruction::PackedSwitchData(..)
            | Instruction::SparseSwitchData(..)
            | Instruction::SwitchData(..)
    )
}

fn instruction_text(instruction: &NativeInstruction, file: &Arc<DexFile>) -> String {
    instruction.instruction.disassembly_from_opcode(
        instruction.offset as i32,
        &mut HashMap::new(),
        file.clone(),
    )
}

fn editable_instruction(
    dex: &DexFile,
    method_idx: u32,
    instruction: &Instruction,
    target: CodeTarget,
) -> Result<EditableInstruction, String> {
    match instruction {
        Instruction::Test(function, left, right, _) => Ok(EditableInstruction::Branch {
            instruction: Instruction::Test(*function, *left, *right, 0),
            target,
        }),
        Instruction::TestZero(function, register, _) => Ok(EditableInstruction::Branch {
            instruction: Instruction::TestZero(*function, *register, 0),
            target,
        }),
        Instruction::Goto8(_) | Instruction::Goto16(_) | Instruction::Goto32(_) => {
            Ok(EditableInstruction::Branch {
                instruction: instruction.clone(),
                target,
            })
        }
        Instruction::Switch(switch) => Ok(EditableInstruction::Switch {
            register: 0,
            cases: switch
                .targets
                .keys()
                .map(|key| (*key, target))
                .collect::<BTreeMap<_, _>>(),
            default: None,
            form: SwitchForm::Auto,
        }),
        _ => editable_instruction_from_decoded(dex, method_idx, target.offset, instruction)
            .map_err(|error| error.to_string()),
    }
}

fn build_instruction(
    factory: &str,
    arguments: &Value,
    _target: CodeTarget,
) -> Result<Instruction, String> {
    let integer = |name: &str, default: u32| -> Result<u32, String> {
        let raw = arguments
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_else(|| "");
        let raw = if raw.trim().is_empty() {
            return Ok(default);
        } else {
            raw
        };
        raw.trim()
            .parse::<u32>()
            .map_err(|_| format!("{name} must be an integer"))
    };
    let register = |name: &str| integer(name, 0).map(|value| value as u8);
    let u4_value = |name: &str| {
        let value = register(name)?;
        if value > 15 {
            return Err(format!("{name} must fit in four bits (0..15)"));
        }
        Ok(u4::new(value))
    };
    let register_list = || -> Result<Vec<u8>, String> {
        let raw = arguments
            .get("registers")
            .and_then(Value::as_str)
            .unwrap_or_default();
        raw.split(|character: char| character == ',' || character.is_whitespace())
            .filter(|part| !part.trim().is_empty())
            .map(|part| {
                let part = part.trim().trim_matches(['{', '}']);
                let digits = part.strip_prefix('v').unwrap_or(part);
                digits
                    .parse::<u8>()
                    .map_err(|_| format!("invalid invoke register {part:?}"))
            })
            .collect()
    };
    let invoke35 = |count_name: &str, index_name: &str| -> Result<(u4, u16, Vec<u8>), String> {
        let count = u4_value(count_name)?;
        let method = integer(index_name, 0)? as u16;
        let registers = register_list()?;
        if registers.len() != u8::from(count) as usize {
            return Err(format!(
                "{count_name} must match the number of invoke registers"
            ));
        }
        if registers.len() > 5 {
            return Err("35c invoke instructions accept at most five registers".to_string());
        }
        if registers.iter().any(|register| *register > 15) {
            return Err("35c invoke registers must fit in four bits (0..15)".to_string());
        }
        Ok((count, method, registers))
    };
    Ok(match factory {
        "nop" => Instruction::Nop,
        "return_void" => Instruction::ReturnVoid,
        "return_value" => Instruction::Return(register("register")?),
        "throw" => Instruction::Throw(register("register")?),
        "const_string_value" => {
            Instruction::ConstString(register("register")?, integer("string_index", 0)? as u16)
        }
        "const_string" => {
            Instruction::ConstString(register("register")?, integer("string_index", 0)? as u16)
        }
        "const_string_jumbo" => {
            Instruction::ConstStringJumbo(register("register")?, integer("string_index", 0)?)
        }
        "const_lit32" => {
            Instruction::ConstLit32(register("register")?, integer("value", 0)? as i32)
        }
        "move_from16" => {
            Instruction::MoveFrom16(register("register")?, integer("source_register", 0)? as u16)
        }
        "move_object_from16" => Instruction::MoveObjectFrom16(
            register("register")?,
            integer("source_register", 0)? as u16,
        ),
        "new_instance" => {
            Instruction::NewInstance(register("register")?, integer("type_index", 0)? as u16)
        }
        "check_cast" => {
            Instruction::CheckCast(register("register")?, integer("type_index", 0)? as u16)
        }
        "invoke_virtual" => {
            let (count, method, registers) = invoke35("register_count", "method_index")?;
            Instruction::InvokeVirtual(count, method, registers)
        }
        "invoke_super" => {
            let (count, method, registers) = invoke35("register_count", "method_index")?;
            Instruction::InvokeSuper(count, method, registers)
        }
        "invoke_direct" => {
            let (count, method, registers) = invoke35("register_count", "method_index")?;
            Instruction::InvokeDirect(count, method, registers)
        }
        "invoke_static" => {
            let (count, method, registers) = invoke35("register_count", "method_index")?;
            Instruction::InvokeStatic(count, method, registers)
        }
        "invoke_interface" => {
            let (count, method, registers) = invoke35("register_count", "method_index")?;
            Instruction::InvokeInterface(count, method, registers)
        }
        "invoke_custom" => {
            let (count, call_site, registers) = invoke35("register_count", "call_site_index")?;
            Instruction::InvokeCustom(count, call_site, registers)
        }
        "invoke_virtual_range" => Instruction::InvokeVirtualRange(
            register("register_count")?,
            integer("method_index", 0)? as u16,
            integer("first_register", 0)? as u16,
        ),
        "invoke_super_range" => Instruction::InvokeSuperRange(
            register("register_count")?,
            integer("method_index", 0)? as u16,
            integer("first_register", 0)? as u16,
        ),
        "invoke_direct_range" => Instruction::InvokeDirectRange(
            register("register_count")?,
            integer("method_index", 0)? as u16,
            integer("first_register", 0)? as u16,
        ),
        "invoke_static_range" => Instruction::InvokeStaticRange(
            register("register_count")?,
            integer("method_index", 0)? as u16,
            integer("first_register", 0)? as u16,
        ),
        "invoke_interface_range" => Instruction::InvokeInterfaceRange(
            register("register_count")?,
            integer("method_index", 0)? as u16,
            integer("first_register", 0)? as u16,
        ),
        "instance_get" => Instruction::InstanceGet(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_get_wide" => Instruction::InstanceGetWide(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_get_object" => Instruction::InstanceGetObject(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_get_boolean" => Instruction::InstanceGetBoolean(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_get_byte" => Instruction::InstanceGetByte(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_get_char" => Instruction::InstanceGetChar(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_get_short" => Instruction::InstanceGetShort(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_put" => Instruction::InstancePut(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_put_wide" => Instruction::InstancePutWide(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_put_object" => Instruction::InstancePutObject(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_put_boolean" => Instruction::InstancePutBoolean(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_put_byte" => Instruction::InstancePutByte(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_put_char" => Instruction::InstancePutChar(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "instance_put_short" => Instruction::InstancePutShort(
            u4_value("register")?,
            u4_value("object_register")?,
            integer("field_index", 0)? as u16,
        ),
        "static_get" => {
            Instruction::StaticGet(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_get_wide" => {
            Instruction::StaticGetWide(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_get_object" => {
            Instruction::StaticGetObject(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_get_boolean" => {
            Instruction::StaticGetBoolean(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_get_byte" => {
            Instruction::StaticGetByte(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_get_char" => {
            Instruction::StaticGetChar(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_get_short" => {
            Instruction::StaticGetShort(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_put" => {
            Instruction::StaticPut(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_put_wide" => {
            Instruction::StaticPutWide(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_put_object" => {
            Instruction::StaticPutObject(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_put_boolean" => {
            Instruction::StaticPutBoolean(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_put_byte" => {
            Instruction::StaticPutByte(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_put_char" => {
            Instruction::StaticPutChar(register("register")?, integer("field_index", 0)? as u16)
        }
        "static_put_short" => {
            Instruction::StaticPutShort(register("register")?, integer("field_index", 0)? as u16)
        }
        "if_eq" => Instruction::Test(
            TestFunction::Equal,
            u4_value("left_register")?,
            u4_value("right_register")?,
            0,
        ),
        "if_ne" => Instruction::Test(
            TestFunction::NotEqual,
            u4_value("left_register")?,
            u4_value("right_register")?,
            0,
        ),
        "if_lt" => Instruction::Test(
            TestFunction::LessThan,
            u4_value("left_register")?,
            u4_value("right_register")?,
            0,
        ),
        "if_le" => Instruction::Test(
            TestFunction::LessEqual,
            u4_value("left_register")?,
            u4_value("right_register")?,
            0,
        ),
        "if_gt" => Instruction::Test(
            TestFunction::GreaterThan,
            u4_value("left_register")?,
            u4_value("right_register")?,
            0,
        ),
        "if_ge" => Instruction::Test(
            TestFunction::GreaterEqual,
            u4_value("left_register")?,
            u4_value("right_register")?,
            0,
        ),
        "if_eqz" => Instruction::TestZero(TestFunction::Equal, register("register")?, 0),
        "if_nez" => Instruction::TestZero(TestFunction::NotEqual, register("register")?, 0),
        "if_ltz" => Instruction::TestZero(TestFunction::LessThan, register("register")?, 0),
        "if_lez" => Instruction::TestZero(TestFunction::LessEqual, register("register")?, 0),
        "if_gtz" => Instruction::TestZero(TestFunction::GreaterThan, register("register")?, 0),
        "if_gez" => Instruction::TestZero(TestFunction::GreaterEqual, register("register")?, 0),
        "goto" => Instruction::Goto8(0),
        "switch" => {
            return Err(
                "switch instruction creation is not supported by the native editor yet".to_string(),
            )
        }
        other => return Err(format!("unknown typed edit factory: {other}")),
    })
}

fn instruction_width(factory: &str, arguments: &[Value]) -> Option<u32> {
    let object = match factory {
        "nop" => Instruction::Nop,
        "return_void" => Instruction::ReturnVoid,
        _ => return None,
    };
    let _ = arguments;
    object.to_code_units().ok().map(|units| units.len() as u32)
}

fn edit_group(factory: &str, action: &str) -> &'static str {
    if action != "replace" {
        return "Placement";
    }
    if matches!(factory, "return_void" | "return_value" | "throw")
        || factory.starts_with("if_")
        || matches!(factory, "goto" | "switch")
    {
        "Control flow"
    } else if factory.starts_with("const_") {
        "Constants and strings"
    } else if factory.starts_with("move_") {
        "Register moves"
    } else if matches!(factory, "new_instance" | "check_cast") {
        "Objects and types"
    } else if factory.starts_with("invoke_") {
        "Function calls"
    } else if factory.starts_with("instance_") || factory.starts_with("static_") {
        "Fields"
    } else {
        "Basic"
    }
}

fn value_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn parse_emulation_descriptors(proto: &str) -> Result<Vec<String>, String> {
    let arguments = proto
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')').map(|(args, _)| args))
        .ok_or_else(|| format!("invalid method prototype: {proto}"))?;
    let bytes = arguments.as_bytes();
    let mut descriptors = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        while index < bytes.len() && bytes[index] == b'[' {
            index += 1;
        }
        if index >= bytes.len() {
            return Err(format!("invalid method prototype: {proto}"));
        }
        if bytes[index] == b'L' {
            let end = arguments[index..]
                .find(';')
                .ok_or_else(|| format!("invalid method prototype: {proto}"))?;
            index += end + 1;
        } else {
            index += 1;
        }
        descriptors.push(arguments[start..index].to_string());
    }
    Ok(descriptors)
}

fn native_emulation_argument(
    vm: &mut VM,
    descriptor: &str,
    text: &str,
) -> Result<Register, String> {
    let normalized = text.trim();
    match descriptor {
        "Z" => match normalized.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(Register::Literal(1)),
            "false" | "0" | "no" => Ok(Register::Literal(0)),
            _ => Err("boolean arguments must be true or false".to_string()),
        },
        "B" | "S" | "I" => normalized
            .parse::<i32>()
            .map(Register::Literal)
            .map_err(|_| format!("{text} is not an integer")),
        "J" => normalized
            .parse::<i64>()
            .map(Register::LiteralWide)
            .map_err(|_| format!("{text} is not a long integer")),
        "C" => {
            let value = if text.chars().count() == 1 {
                text.chars().next().unwrap_or_default() as i32
            } else {
                normalized
                    .parse::<i32>()
                    .map_err(|_| "character arguments must be one character or a code point")?
            };
            Ok(Register::Literal(value))
        }
        "Ljava/lang/String;" => {
            let instance = vm
                .new_instance(
                    descriptor.to_string(),
                    EmulationValue::Object(StringClass::new(text.to_string())),
                )
                .map_err(|error| format!("could not allocate string argument: {error:?}"))?;
            Ok(instance)
        }
        "[B" | "[C" => {
            let bytes = if let Some(hex) = normalized.strip_prefix("hex:") {
                hex.split_whitespace()
                    .collect::<String>()
                    .as_bytes()
                    .chunks(2)
                    .map(|chunk| {
                        u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16)
                            .map_err(|_| "invalid hexadecimal array argument".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                let values: Vec<i64> = serde_json::from_str(normalized)
                    .map_err(|_| "array arguments must be JSON numbers or hex:…".to_string())?;
                values
                    .into_iter()
                    .map(|value| {
                        u8::try_from(value)
                            .map_err(|_| "array values must be in the range 0..255".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?
            };
            vm.new_instance(descriptor.to_string(), EmulationValue::Array(bytes))
                .map_err(|error| format!("could not allocate array argument: {error:?}"))
        }
        descriptor if descriptor.starts_with('L') => {
            if matches!(normalized.to_ascii_lowercase().as_str(), "null" | "nil") {
                Ok(Register::Null)
            } else {
                vm.new_class_instance(descriptor)
                    .map_err(|error| format!("could not allocate object argument: {error:?}"))
            }
        }
        "F" | "D" => Err(format!("argument type {descriptor} is not supported yet")),
        _ => Err(format!("argument type {descriptor} is not supported yet")),
    }
}

fn value_u32(value: &Value, key: &str) -> Result<u32, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .ok_or_else(|| format!("{key} must be an unsigned integer"))
}

fn argument_text(value: &Value, key: &str, default: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_string()
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn optional_path<'a>(value: &'a Value, key: &str) -> Option<&'a Path> {
    optional_string(value, key).map(Path::new)
}

fn temporary_directory(label: &str) -> Result<PathBuf, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("coeus-{label}-{}-{timestamp}", std::process::id()));
    fs::create_dir_all(&path)
        .map_err(|error| format!("could not create temporary directory: {error}"))?;
    Ok(path)
}

fn output_text(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        stdout
    } else if stdout.is_empty() {
        stderr
    } else {
        format!("{stdout}\n{stderr}")
    }
}

fn merge_objects(left: Value, right: Value) -> Value {
    let mut object = left.as_object().cloned().unwrap_or_default();
    if let Some(right) = right.as_object() {
        object.extend(right.clone());
    }
    Value::Object(object)
}

fn write_zip_entry<W: Write + Seek>(
    writer: &mut ZipWriter<W>,
    name: &str,
    data: &[u8],
) -> Result<(), String> {
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    writer
        .start_file(name, options)
        .map_err(|error| format!("could not write ZIP entry {name}: {error}"))?;
    writer
        .write_all(data)
        .map_err(|error| format!("could not write ZIP entry {name}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_handle_accepts_parallel_read_commands() {
        let handle = Arc::new(RustBackendHandle::new());
        let workers = (0..8)
            .map(|_| {
                let handle = handle.clone();
                thread::spawn(move || handle.call(json!({"op": "history"})))
            })
            .collect::<Vec<_>>();
        for worker in workers {
            let result = worker.join().expect("parallel command thread panicked");
            assert!(result.is_ok(), "parallel command failed: {result:?}");
            assert_eq!(result.unwrap()["history"], json!([]));
        }
    }

    #[test]
    fn native_script_uses_python_values_and_replays_manifest_changes() {
        let mut backend = RustBackend::new();
        backend.session_origin = Some(json!({
            "kind": "adb",
            "package": "com.example.app",
            "serial": null,
            "adb_path": null,
        }));
        backend.record_event(json!({
            "operation": "set_debuggable",
            "enabled": true,
        }));
        let script = backend.session_script();
        assert!(script.contains("SplitApkSet.from_adb(\"com.example.app\", None, None)"));
        assert!(script.contains("ao.set_debuggable(True)"));
    }

    #[test]
    fn native_example_graph_returns_and_releases_backend_gate() {
        let handle = RustBackendHandle::new();
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../examples/debugger_test/app-debug.apk")
            .to_string_lossy()
            .to_string();
        handle
            .call(json!({"op": "load", "path": path}))
            .expect("example DEX should load");
        handle
            .call(json!({"op": "graph", "kind": "supergraph", "ignore": ""}))
            .expect("example supergraph should build");
        handle
            .call(json!({"op": "history"}))
            .expect("backend gate should be released after graph build");
    }

    #[test]
    fn native_detach_is_idempotent_without_a_debugger() {
        let handle = RustBackendHandle::new();
        let result = handle
            .call(json!({"op": "debug_detach"}))
            .expect("detaching without a connection should be harmless");
        assert_eq!(result, json!({"connected": false, "detached": true}));
    }
}

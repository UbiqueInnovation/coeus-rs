use std::{
    collections::HashMap,
    fs, io,
    path::Path,
    sync::{Arc, Mutex},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::{json, Value};
use time::OffsetDateTime;
use typst::{
    diag::{FileError, FileResult},
    foundations::{Bytes, Datetime},
    syntax::{FileId, Source, VirtualPath},
    text::{Font, FontBook},
    utils::LazyHash,
    Library, LibraryExt,
};
use typst_pdf::PdfOptions;

const BUNDLED_SMALI_SYNTAX_PATH: &str = "coeus/syntaxes/smali.sublime-syntax";
const BUNDLED_SMALI_SYNTAX: &[u8] =
    include_bytes!("../assets/syntaxes/smali.sublime-syntax");

/// A file in the document's portable, virtual Typst workspace.
#[derive(Clone)]
pub struct DocumentationFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct DocumentationCodeSample {
    pub title: String,
    pub language: String,
    pub code: String,
}

/// GUI state for the documentation editor. The state is intentionally made
/// independent of the APK analysis backend so a project can be reopened with
/// either the Python or native backend without changing the document.
pub struct DocumentationState {
    pub title: String,
    pub source: String,
    pub include_history: bool,
    pub files: Vec<DocumentationFile>,
    pub folders: Vec<String>,
    pub selected_file: Option<usize>,
    pub new_file_path: String,
    pub code_samples: Vec<DocumentationCodeSample>,
    pub rendered_pdf: Option<Vec<u8>>,
    pub rendered_preview: Option<Vec<Vec<u8>>>,
    pub render_error: Option<String>,
}

impl Default for DocumentationState {
    fn default() -> Self {
        Self {
            title: "Coeus investigation".to_string(),
            source: "= Coeus investigation\n\n".to_string(),
            include_history: true,
            files: Vec::new(),
            folders: Vec::new(),
            selected_file: None,
            new_file_path: "notes.typ".to_string(),
            code_samples: Vec::new(),
            rendered_pdf: None,
            rendered_preview: None,
            render_error: None,
        }
    }
}

impl DocumentationState {
    pub fn from_value(value: Option<&Value>) -> Self {
        let Some(value) = value.filter(|value| value.is_object()) else {
            return Self::default();
        };
        let mut state = Self {
            title: value_string(value, "title"),
            source: value_string(value, "source"),
            include_history: value
                .get("include_history")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            ..Self::default()
        };
        if state.title.trim().is_empty() {
            state.title = "Coeus investigation".to_string();
        }
        if state.source.is_empty() {
            state.source = "= Coeus investigation\n\n".to_string();
        }
        if let Some(folders) = value.get("folders").and_then(Value::as_array) {
            state.folders = folders
                .iter()
                .filter_map(Value::as_str)
                .filter_map(normalize_virtual_path)
                .collect();
        }
        if let Some(files) = value.get("files").and_then(Value::as_array) {
            for file in files {
                let Some(path) = file
                    .get("path")
                    .and_then(Value::as_str)
                    .and_then(normalize_virtual_path)
                else {
                    continue;
                };
                let bytes = file
                    .get("content_base64")
                    .and_then(Value::as_str)
                    .and_then(|content| BASE64.decode(content).ok())
                    .or_else(|| {
                        file.get("content")
                            .and_then(Value::as_str)
                            .map(|content| content.as_bytes().to_vec())
                    })
                    .unwrap_or_default();
                state.add_file(path, bytes);
            }
        }
        if let Some(samples) = value.get("code_samples").and_then(Value::as_array) {
            state.code_samples = samples
                .iter()
                .filter_map(|sample| {
                    let code = sample.get("code").and_then(Value::as_str)?.to_string();
                    if code.is_empty() {
                        return None;
                    }
                    Some(DocumentationCodeSample {
                        title: value_string(sample, "title"),
                        language: value_string(sample, "language"),
                        code,
                    })
                })
                .collect();
        }
        state
    }

    pub fn to_value(&self) -> Value {
        json!({
            "format_version": 1,
            "title": self.title,
            "source": self.source,
            "include_history": self.include_history,
            "folders": self.folders,
            "files": self.files.iter().map(|file| json!({
                "path": file.path,
                "content_base64": BASE64.encode(&file.bytes),
            })).collect::<Vec<_>>(),
            "code_samples": self.code_samples.iter().map(|sample| json!({
                "title": sample.title,
                "language": sample.language,
                "code": sample.code,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn additional_files(&self) -> HashMap<String, Vec<u8>> {
        self.files
            .iter()
            .map(|file| (file.path.clone(), file.bytes.clone()))
            .collect()
    }

    pub fn renderer_files(&self) -> HashMap<String, Vec<u8>> {
        let mut files = self.additional_files();
        files
            .entry(BUNDLED_SMALI_SYNTAX_PATH.to_string())
            .or_insert_with(|| BUNDLED_SMALI_SYNTAX.to_vec());
        files
    }

    pub fn add_file(&mut self, path: String, bytes: Vec<u8>) {
        let Some(path) = normalize_virtual_path(&path) else {
            return;
        };
        if let Some(file) = self.files.iter_mut().find(|file| file.path == path) {
            file.bytes = bytes;
        } else {
            self.files.push(DocumentationFile { path, bytes });
        }
        self.files.sort_by(|left, right| left.path.cmp(&right.path));
    }

    pub fn add_empty_file(&mut self) -> Result<(), String> {
        let path = self.new_file_path.trim();
        let Some(path) = normalize_virtual_path(path) else {
            return Err("enter a relative virtual file path".to_string());
        };
        if path == "main.typ" {
            return Err("main.typ is the document editor; choose another file".to_string());
        }
        self.add_file(path.clone(), Vec::new());
        self.selected_file = self.files.iter().position(|file| file.path == path);
        Ok(())
    }

    pub fn remove_selected_file(&mut self) {
        let Some(index) = self.selected_file.take() else {
            return;
        };
        if index < self.files.len() {
            self.files.remove(index);
        }
    }

    pub fn import_file(&mut self, path: &Path) -> Result<(), String> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "selected file has no valid name".to_string())?;
        let virtual_path = normalize_virtual_path(name)
            .ok_or_else(|| "selected file has an invalid name".to_string())?;
        let bytes = fs::read(path).map_err(|error| format!("could not read file: {error}"))?;
        self.add_file(virtual_path.clone(), bytes);
        self.selected_file = self.files.iter().position(|file| file.path == virtual_path);
        Ok(())
    }

    pub fn import_folder(&mut self, path: &Path) -> Result<(), String> {
        let folder_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "selected folder has no valid name".to_string())?;
        let prefix = normalize_virtual_path(folder_name)
            .ok_or_else(|| "selected folder has an invalid name".to_string())?;
        self.folders.push(prefix.clone());
        self.folders.sort();
        self.folders.dedup();
        let mut imported = Vec::new();
        collect_folder_files(path, path, Path::new(&prefix), &mut imported)
            .map_err(|error| format!("could not import folder: {error}"))?;
        for (virtual_path, bytes) in imported {
            self.add_file(virtual_path, bytes);
        }
        Ok(())
    }

    pub fn insert_note(&mut self, location: &str, note: &str) {
        let title = if location.trim().is_empty() {
            "Investigation note".to_string()
        } else {
            location.to_string()
        };
        append_fragment(
            &mut self.source,
            &format!(
                "#block(fill: luma(95%), inset: 10pt, radius: 5pt)[\n  #strong[#text({})]\n  #text({})\n]\n",
                typst_string(&format!("Note — {title}")),
                typst_string(note),
            ),
        );
    }

    pub fn insert_code_sample(&mut self, sample: &DocumentationCodeSample) {
        append_fragment(
            &mut self.source,
            &format!(
                "#heading(level: 3)[#text({})]\n#raw(lang: {}, {})\n\n",
                typst_string(&sample.title),
                typst_string(&sample.language),
                typst_string(&sample.code),
            ),
        );
    }

    pub fn source_for_render(&self, history: &[String]) -> String {
        let mut source = format!(
            "#set raw(syntaxes: {})\n{}",
            typst_string(BUNDLED_SMALI_SYNTAX_PATH),
            self.source
        );
        if self.include_history && !history.is_empty() {
            append_fragment(&mut source, &history_fragment(history));
        }
        source
    }
}

/// Render the virtual workspace with the same Typst PDF engine used by the
/// Kapun PDF crate. The Kapun function is currently UniFFI-exported but not a
/// public Rust function, so this small World keeps the GUI independent while
/// retaining the same Typst version and embedded font set.
pub struct RenderedDocumentation {
    pub pdf: Vec<u8>,
    pub preview: Vec<Vec<u8>>,
}

#[derive(Clone, Copy)]
pub struct TypstHighlightSpan {
    pub start: usize,
    pub end: usize,
    pub tag: typst::syntax::Tag,
}

#[derive(Clone)]
pub struct TypstCompletion {
    pub from: usize,
    pub label: String,
    pub apply: String,
    pub detail: Option<String>,
    pub kind: String,
}

pub fn typst_highlight_spans(source: &str) -> Vec<TypstHighlightSpan> {
    let source = Source::detached(source);
    let mut spans = Vec::new();
    collect_highlight_spans(&typst::syntax::LinkedNode::new(source.root()), None, &mut spans);
    spans
}

pub fn typst_completions(
    source: &str,
    additional_files: HashMap<String, Vec<u8>>,
    cursor: usize,
    explicit: bool,
) -> Vec<TypstCompletion> {
    let world = VirtualWorld::new(source, additional_files);
    let cursor = cursor.min(source.len());
    typst_ide::autocomplete(&world, None, &world.source, cursor, explicit)
        .map(|(from, completions)| {
            completions
                .into_iter()
                .map(|completion| TypstCompletion {
                    from,
                    label: completion.label.to_string(),
                    apply: completion
                        .apply
                        .unwrap_or_else(|| completion.label.clone())
                        .to_string(),
                    detail: completion.detail.map(|detail| detail.to_string()),
                    kind: format!("{:?}", completion.kind),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn render_typst_outputs(
    source: &str,
    additional_files: HashMap<String, Vec<u8>>,
) -> Result<RenderedDocumentation, String> {
    let world = VirtualWorld::new(source, additional_files);
    let document = typst::compile(&world)
        .output
        .map_err(|diagnostics| format!("Typst compilation failed: {diagnostics:?}"))?;
    let pdf = typst_pdf::pdf(&document, &PdfOptions::default())
        .map_err(|diagnostics| format!("PDF rendering failed: {diagnostics:?}"))?;
    let preview = document
        .pages
        .iter()
        .map(|page| {
            typst_render::render(page, 1.5)
                .encode_png()
                .map_err(|error| format!("PNG preview rendering failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RenderedDocumentation { pdf, preview })
}

pub fn render_typst(
    source: &str,
    additional_files: HashMap<String, Vec<u8>>,
) -> Result<Vec<u8>, String> {
    Ok(render_typst_outputs(source, additional_files)?.pdf)
}

struct VirtualWorld {
    source: Source,
    library: LazyHash<Library>,
    book: LazyHash<FontBook>,
    fonts: Vec<Font>,
    files: Arc<Mutex<HashMap<FileId, VirtualFile>>>,
    time: OffsetDateTime,
}

#[derive(Clone)]
struct VirtualFile {
    bytes: Bytes,
    source: Option<Source>,
}

impl VirtualWorld {
    fn new(source: &str, additional_files: HashMap<String, Vec<u8>>) -> Self {
        let (book, fonts) = load_fonts();
        let files = additional_files
            .into_iter()
            .map(|(path, bytes)| {
                (
                    FileId::new(None, VirtualPath::new(path)),
                    VirtualFile {
                        bytes: Bytes::new(bytes),
                        source: None,
                    },
                )
            })
            .collect();
        Self {
            source: Source::detached(source),
            library: LazyHash::new(Library::default()),
            book: LazyHash::new(book),
            fonts,
            files: Arc::new(Mutex::new(files)),
            time: OffsetDateTime::now_utc(),
        }
    }

    fn file(&self, id: FileId) -> FileResult<VirtualFile> {
        self.files
            .lock()
            .map_err(|_| FileError::AccessDenied)?
            .get(&id)
            .cloned()
            .ok_or(FileError::AccessDenied)
    }
}

impl typst::World for VirtualWorld {
    fn library(&self) -> &LazyHash<Library> {
        &self.library
    }

    fn book(&self) -> &LazyHash<FontBook> {
        &self.book
    }

    fn main(&self) -> FileId {
        self.source.id()
    }

    fn source(&self, id: FileId) -> FileResult<Source> {
        if id == self.source.id() {
            return Ok(self.source.clone());
        }
        let file = self.file(id)?;
        if let Some(source) = file.source {
            return Ok(source);
        }
        let contents = std::str::from_utf8(&file.bytes).map_err(|_| FileError::InvalidUtf8)?;
        Ok(Source::new(
            id,
            contents.trim_start_matches('\u{feff}').into(),
        ))
    }

    fn file(&self, id: FileId) -> FileResult<Bytes> {
        Ok(self.file(id)?.bytes)
    }

    fn font(&self, id: usize) -> Option<Font> {
        self.fonts.get(id).cloned()
    }

    fn today(&self, offset: Option<i64>) -> Option<Datetime> {
        let offset = offset.unwrap_or(0);
        let offset = time::UtcOffset::from_hms(offset.try_into().ok()?, 0, 0).ok()?;
        Some(Datetime::Date(self.time.checked_to_offset(offset)?.date()))
    }
}

impl typst_ide::IdeWorld for VirtualWorld {
    fn upcast(&self) -> &dyn typst::World {
        self
    }

    fn files(&self) -> Vec<FileId> {
        let mut files = self
            .files
            .lock()
            .map(|files| files.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        files.push(self.source.id());
        files
    }
}

fn collect_highlight_spans(
    node: &typst::syntax::LinkedNode<'_>,
    inherited: Option<typst::syntax::Tag>,
    spans: &mut Vec<TypstHighlightSpan>,
) {
    let tag = typst::syntax::highlight(node).or(inherited);
    if !node.text().is_empty() {
        if let Some(tag) = tag {
            let range = node.range();
            spans.push(TypstHighlightSpan {
                start: range.start,
                end: range.end,
                tag,
            });
        }
        return;
    }
    for child in node.children() {
        collect_highlight_spans(&child, tag, spans);
    }
}

fn load_fonts() -> (FontBook, Vec<Font>) {
    let mut fonts = Vec::new();
    for data in typst_assets::fonts() {
        let bytes = Bytes::new(data);
        for font in Font::iter(bytes) {
            fonts.push(font);
        }
    }
    let book = FontBook::from_fonts(&fonts);
    (book, fonts)
}

fn value_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn append_fragment(source: &mut String, fragment: &str) {
    if !source.ends_with('\n') {
        source.push('\n');
    }
    if !source.ends_with("\n\n") {
        source.push('\n');
    }
    source.push_str(fragment);
}

fn typst_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => escaped.push(' '),
            character => escaped.push(character),
        }
    }
    format!("\"{escaped}\"")
}

fn history_fragment(history: &[String]) -> String {
    let mut fragment = String::from(
        "#heading(level: 2)[Change history]\n#table(\n  columns: (auto, 1fr),\n  stroke: .5pt + luma(75%),\n  [#strong[#text(\"Revision\")]], [#strong[#text(\"Change\")]],\n",
    );
    for (index, entry) in history.iter().enumerate() {
        fragment.push_str(&format!(
            "  [#text({})], [#text({})],\n",
            typst_string(&(index + 1).to_string()),
            typst_string(entry),
        ));
    }
    fragment.push_str(")\n");
    fragment
}

fn normalize_virtual_path(path: &str) -> Option<String> {
    let path = path.replace('\\', "/");
    let mut parts = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains(':') {
            return None;
        }
        parts.push(part);
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn collect_folder_files(
    root: &Path,
    current: &Path,
    prefix: &Path,
    files: &mut Vec<(String, Vec<u8>)>,
) -> io::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_folder_files(root, &path, prefix, files)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).unwrap_or(path.as_path());
            let virtual_path = prefix.join(relative);
            let Some(virtual_path) = normalize_virtual_path(&virtual_path.to_string_lossy()) else {
                continue;
            };
            files.push((virtual_path, fs::read(path)?));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typst_strings_escape_markup_inputs() {
        let value = typst_string("a\\b\"c\nd");
        assert_eq!(value, "\"a\\\\b\\\"c\\nd\"");
    }

    #[test]
    fn virtual_paths_reject_parent_traversal() {
        assert!(normalize_virtual_path("../secret.typ").is_none());
        assert_eq!(
            normalize_virtual_path("folder\\main.typ"),
            Some("folder/main.typ".to_string())
        );
    }

    #[test]
    fn inserted_material_compiles_to_pdf() {
        let mut state = DocumentationState::default();
        state.insert_note("method:Ldemo;->run()V", "Check this branch.");
        state.insert_code_sample(&DocumentationCodeSample {
            title: "Sample".to_string(),
            language: "smali".to_string(),
            code: "return-void".to_string(),
        });
        let pdf = render_typst(
            &state.source_for_render(&["apply_edit Ldemo;->run()V".to_string()]),
            state.renderer_files(),
        )
        .expect("inserted Typst should compile");
        assert!(pdf.starts_with(b"%PDF-"));
    }

    #[test]
    fn png_preview_contains_every_typst_page() {
        let rendered = render_typst_outputs(
            "= First page\n#pagebreak()\n= Second page\n",
            HashMap::new(),
        )
        .expect("multi-page Typst should render");
        assert_eq!(rendered.preview.len(), 2);
        assert!(rendered
            .preview
            .iter()
            .all(|page| page.starts_with(b"\x89PNG\r\n\x1a\n")));
        assert!(rendered.preview.iter().all(|page| {
            let image = image::load_from_memory_with_format(page, image::ImageFormat::Png)
                .expect("Typst PNG preview should be decodable by the GUI");
            image.width() > 0 && image.height() > 0
        }));
    }

    #[test]
    fn typst_syntax_highlighting_returns_tagged_spans() {
        let spans = typst_highlight_spans("= Heading\n#let answer = 42\n");
        assert!(spans.iter().any(|span| span.tag == typst::syntax::Tag::Heading));
        assert!(spans.iter().any(|span| span.tag == typst::syntax::Tag::Keyword));
        assert!(spans.iter().any(|span| span.tag == typst::syntax::Tag::Number));
    }

    #[test]
    fn typst_ide_returns_completions_for_explicit_markup_request() {
        let source = "#";
        let completions = typst_completions(source, HashMap::new(), source.len(), true);
        assert!(!completions.is_empty());
        assert!(completions.iter().all(|completion| completion.from <= source.len()));
    }
}

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use eframe::egui::text::{LayoutJob, TextFormat};
use eframe::egui::{self, Color32, FontId, Key, Rect, RichText, Sense, Stroke, Vec2};
use regex::Regex;
use serde_json::{json, Value};

mod native_backend;
mod theme;
use native_backend::RustBackendHandle;

const BRIDGE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/bridge.py");

type Response = Result<Value, String>;

struct PendingRequest {
    request_id: u64,
    operation: String,
    receiver: mpsc::Receiver<Response>,
}

struct PythonBridge {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl PythonBridge {
    fn spawn() -> Result<Self, String> {
        let python = std::env::var("COEUS_PYTHON").unwrap_or_else(|_| "python3".to_string());
        if !std::path::Path::new(BRIDGE_PATH).exists() {
            return Err(format!("Python bridge is missing at {BRIDGE_PATH}"));
        }
        let mut child = Command::new(&python)
            .arg("-u")
            .arg(BRIDGE_PATH)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("could not start {python}: {error}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "Python bridge stdin was not available".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "Python bridge stdout was not available".to_string())?;
        Ok(Self {
            _child: child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn call(&mut self, request: Value) -> Response {
        let line = serde_json::to_string(&request).map_err(|error| error.to_string())?;
        writeln!(self.stdin, "{line}").map_err(|error| format!("bridge write failed: {error}"))?;
        self.stdin
            .flush()
            .map_err(|error| format!("bridge flush failed: {error}"))?;
        let mut output = String::new();
        let bytes = self
            .stdout
            .read_line(&mut output)
            .map_err(|error| format!("bridge read failed: {error}"))?;
        if bytes == 0 {
            return Err("Python bridge exited unexpectedly".to_string());
        }
        let response: Value = serde_json::from_str(&output)
            .map_err(|error| format!("invalid bridge response: {error}: {output}"))?;
        if response.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            Ok(response.get("data").cloned().unwrap_or(Value::Null))
        } else {
            Err(response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown Python bridge error")
                .to_string())
        }
    }
}

enum Backend {
    Python(Arc<Mutex<PythonBridge>>),
    Rust(Arc<RustBackendHandle>),
}

struct Bridge {
    backend: Backend,
}

impl Backend {
    fn name(&self) -> &'static str {
        match self {
            Self::Python(_) => "python",
            Self::Rust(_) => "rust",
        }
    }
}

impl Bridge {
    fn spawn() -> Result<Self, String> {
        let selected = std::env::var("COEUS_GUI_BACKEND")
            .unwrap_or_else(|_| "python".to_string())
            .to_ascii_lowercase();
        let backend = match selected.as_str() {
            "python" => Backend::Python(Arc::new(Mutex::new(PythonBridge::spawn()?))),
            "rust" | "native" => Backend::Rust(Arc::new(RustBackendHandle::new())),
            other => {
                return Err(format!(
                    "unknown COEUS_GUI_BACKEND={other}; expected python or rust"
                ))
            }
        };
        Ok(Self { backend })
    }

    fn call(&self, request: Value) -> Response {
        match &self.backend {
            Backend::Python(bridge) => bridge
                .lock()
                .map_err(|_| "Python bridge lock was poisoned".to_string())?
                .call(request),
            Backend::Rust(backend) => backend.call(request),
        }
    }

    fn name(&self) -> &'static str {
        self.backend.name()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Search,
    Notes,
    Code,
    Graph,
    Debugger,
    Manifest,
    Deploy,
    Adb,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SearchKind {
    Any,
    Methods,
    Classes,
    Fields,
    Strings,
}

impl SearchKind {
    fn api_name(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Methods => "methods",
            Self::Classes => "classes",
            Self::Fields => "fields",
            Self::Strings => "strings",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Any => "Everything",
            Self::Methods => "Methods",
            Self::Classes => "Classes",
            Self::Fields => "Fields",
            Self::Strings => "Strings",
        }
    }
}

#[derive(Clone)]
struct ResultRow {
    id: String,
    kind: String,
    label: String,
    note_key: String,
    is_alias: bool,
}

type NavigationEntry = ResultRow;

#[derive(Clone)]
struct InstructionRow {
    offset: u64,
    size: u64,
    mnemonic: String,
    text: String,
    targets: Vec<NavigationTarget>,
}

#[derive(Clone)]
struct NavigationTarget {
    id: String,
    kind: String,
    label: String,
    note_key: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NavigationKind {
    Automatic,
    Class,
    Method,
    Field,
    String,
}

impl NavigationKind {
    fn label(self) -> &'static str {
        match self {
            Self::Automatic => "Automatic",
            Self::Class => "Class",
            Self::Method => "Method",
            Self::Field => "Field",
            Self::String => "String",
        }
    }

    fn matches(self, kind: &str) -> bool {
        match self {
            Self::Automatic => true,
            Self::Class => kind == "class",
            Self::Method => kind == "method",
            Self::Field => kind == "field",
            Self::String => kind == "string",
        }
    }
}

#[derive(Clone)]
enum CodeAction {
    Navigate(NavigationTarget),
    Emulate(NavigationTarget),
    EmulateWithStaticArguments {
        target: NavigationTarget,
        source_method_id: Option<String>,
        offset: Option<u64>,
    },
    Xrefs(NavigationTarget),
    EnclosingMethodXrefs,
    ToggleBreakpoint,
    EditNote(NavigationTarget),
}

#[derive(Clone)]
struct CodeInteraction {
    offset: u64,
    method_id: Option<String>,
    action: Option<CodeAction>,
}

#[derive(Clone)]
struct EditArgument {
    name: String,
    label: String,
    kind: String,
    value: String,
    picker: Option<SearchKind>,
}

#[derive(Clone)]
struct EditOption {
    id: String,
    group: String,
    label: String,
    action: String,
    width: u64,
    arguments: Vec<EditArgument>,
}

#[derive(Clone)]
struct EditRequest {
    id: String,
    arguments: Vec<EditArgument>,
}

#[derive(Clone)]
struct EditPickerResult {
    kind: String,
    label: String,
    index: Option<u64>,
}

#[derive(Clone)]
struct EditPicker {
    argument_name: String,
    argument_label: String,
    kind: SearchKind,
    dex_name: String,
    query: String,
    results: Vec<EditPickerResult>,
    result_count: usize,
    searched: bool,
}

impl EditPicker {
    fn new(
        argument_name: String,
        argument_label: String,
        kind: SearchKind,
        dex_name: String,
    ) -> Self {
        Self {
            argument_name,
            argument_label,
            kind,
            dex_name,
            query: ".*".to_string(),
            results: Vec::new(),
            result_count: 0,
            searched: false,
        }
    }
}

#[derive(Clone)]
enum SearchAction {
    Open(ResultRow),
    Xrefs(ResultRow),
    EditNote(ResultRow),
    EditAlias(ResultRow),
}

#[derive(Clone)]
enum NoteLocation {
    Offset(u64),
    Line(usize),
}

#[derive(Clone)]
struct PendingNoteNavigation {
    kind: String,
    label: String,
    location: Option<NoteLocation>,
}

struct CodeState {
    method_id: Option<String>,
    method_key: Option<String>,
    kind: String,
    title: String,
    identity_title: String,
    code: String,
    lines: Vec<String>,
    line_method_ids: Vec<Option<String>>,
    line_method_keys: Vec<Option<String>>,
    search_query: String,
    search_matches: Vec<usize>,
    search_index: usize,
    search_scroll_pending: bool,
    search_error: Option<String>,
    instructions: Vec<InstructionRow>,
    selected_offset: Option<u64>,
    highlighted_offset: Option<u64>,
    highlight_scroll_pending: bool,
    annotated_line: Option<usize>,
    annotated_line_scroll_pending: bool,
    breakpoints: HashSet<(String, u64)>,
    selected_method_id: Option<String>,
    edit_options: Vec<EditOption>,
    edit_form: Option<EditOption>,
    edit_dex_name: String,
    edit_available: bool,
    edit_reason: String,
}

impl Default for CodeState {
    fn default() -> Self {
        Self {
            method_id: None,
            method_key: None,
            kind: String::new(),
            title: String::new(),
            identity_title: String::new(),
            code: String::new(),
            lines: Vec::new(),
            line_method_ids: Vec::new(),
            line_method_keys: Vec::new(),
            search_query: String::new(),
            search_matches: Vec::new(),
            search_index: 0,
            search_scroll_pending: false,
            search_error: None,
            instructions: Vec::new(),
            selected_offset: None,
            highlighted_offset: None,
            highlight_scroll_pending: false,
            annotated_line: None,
            annotated_line_scroll_pending: false,
            breakpoints: HashSet::new(),
            selected_method_id: None,
            edit_options: Vec::new(),
            edit_form: None,
            edit_dex_name: String::new(),
            edit_available: false,
            edit_reason: "Loading instruction nodes…".to_string(),
        }
    }
}

struct GraphState {
    kind: String,
    dot: String,
    nodes: Vec<(usize, String)>,
    node_index: HashMap<usize, usize>,
    edges: Vec<(usize, usize)>,
    edge_index: HashMap<usize, Vec<(usize, usize)>>,
    layout_edge_index: HashMap<(i32, i32), Vec<(usize, usize)>>,
    layout_long_edges: Vec<(usize, usize)>,
    layout: HashMap<usize, Vec2>,
    layout_index: HashMap<(i32, i32), Vec<usize>>,
    layout_min: Vec2,
    layout_max: Vec2,
    minimap_nodes: Vec<(usize, Vec2, GraphNodeKind)>,
    minimap_edges: Vec<(Vec2, Vec2, GraphEdgeKind)>,
    total_nodes: usize,
    total_edges: usize,
    zoom: f32,
    fit_to_view: bool,
    node_filters: HashSet<GraphNodeKind>,
    exclude_android_framework: bool,
    exclude_language_runtime: bool,
    exclude_common_libraries: bool,
    additional_class_filters: String,
    discover_dynamic_arguments: bool,
    dynamic_argument_classes: String,
    node_search: String,
    node_search_cache_query: String,
    node_search_results: Vec<(usize, String, String)>,
    focus_node: Option<usize>,
    last_edge_click: Option<(usize, usize, usize)>,
}

impl Default for GraphState {
    fn default() -> Self {
        Self {
            kind: String::new(),
            dot: String::new(),
            nodes: Vec::new(),
            node_index: HashMap::new(),
            edges: Vec::new(),
            edge_index: HashMap::new(),
            layout_edge_index: HashMap::new(),
            layout_long_edges: Vec::new(),
            layout: HashMap::new(),
            layout_index: HashMap::new(),
            layout_min: Vec2::ZERO,
            layout_max: Vec2::new(250.0, 72.0),
            minimap_nodes: Vec::new(),
            minimap_edges: Vec::new(),
            total_nodes: 0,
            total_edges: 0,
            zoom: 1.0,
            fit_to_view: true,
            node_filters: all_graph_node_kinds().into_iter().collect(),
            exclude_android_framework: true,
            exclude_language_runtime: true,
            exclude_common_libraries: true,
            additional_class_filters: String::new(),
            discover_dynamic_arguments: false,
            dynamic_argument_classes: String::new(),
            node_search: String::new(),
            node_search_cache_query: String::new(),
            node_search_results: Vec::new(),
            focus_node: None,
            last_edge_click: None,
        }
    }
}

#[derive(Clone)]
struct GraphNodeDetails {
    node_id: usize,
    kind: String,
    value: String,
    label: String,
    targets: Vec<NavigationTarget>,
    loading: bool,
}

struct GraphRenderNode {
    ids: Vec<usize>,
    rect: Rect,
    kind: GraphNodeKind,
    label: String,
}

#[derive(Clone)]
struct DebugApp {
    pid: u64,
    process: String,
    package: String,
}

struct DebugState {
    port: String,
    serial: String,
    adb_path: String,
    connected: bool,
    connecting: bool,
    apps_loading: bool,
    waiting: bool,
    floating_open: bool,
    frame: Option<Value>,
    values: Vec<(u64, String, String)>,
    edits: HashMap<u64, String>,
    pending_value: Option<(u64, String)>,
    apps: Vec<DebugApp>,
    breakpoints: Vec<DebugBreakpoint>,
    last_poll: Instant,
}

#[derive(Clone)]
struct DebugBreakpoint {
    method_id: String,
    method_key: String,
    offset: u64,
    enabled: bool,
}

struct StringEditorState {
    id: Option<String>,
    original: String,
    replacement: String,
}

#[derive(Clone)]
struct NoteEditor {
    key: String,
    kind: String,
    label: String,
    text: String,
}

#[derive(Clone)]
struct NotePopup {
    key: String,
    kind: String,
    label: String,
    text: String,
}

#[derive(Clone)]
struct AliasEditor {
    key: String,
    kind: String,
    label: String,
    text: String,
}

#[derive(Clone)]
struct EmulationArgument {
    descriptor: String,
    value: String,
}

#[derive(Clone)]
struct EmulationGuess {
    label: String,
    arguments: Vec<String>,
}

#[derive(Clone)]
struct EmulationEditor {
    method_id: String,
    method_label: String,
    arguments: Vec<EmulationArgument>,
    guesses: Vec<EmulationGuess>,
}

#[derive(Clone)]
struct EmulationResult {
    method_label: String,
    success: bool,
    output: String,
}

struct DisassemblyAlias {
    line: String,
    range: (usize, usize),
    canonical: String,
}

#[derive(Clone, Default)]
struct DeployDevice {
    serial: String,
    label: String,
}

struct DeployState {
    keystore: String,
    alias: String,
    store_password: String,
    key_password: String,
    apksigner: String,
    adb_path: String,
    serial: String,
    output: String,
    split_output_dir: String,
    replace_existing: bool,
    devices: Vec<DeployDevice>,
}

struct AdbState {
    adb_path: String,
    serial: String,
    package_filter: String,
    selected_package: String,
    output_dir: String,
    devices: Vec<DeployDevice>,
    packages: Vec<String>,
}

impl Default for AdbState {
    fn default() -> Self {
        Self {
            adb_path: String::new(),
            serial: String::new(),
            package_filter: String::new(),
            selected_package: String::new(),
            output_dir: String::new(),
            devices: Vec::new(),
            packages: Vec::new(),
        }
    }
}

impl Default for DeployState {
    fn default() -> Self {
        Self {
            keystore: String::new(),
            alias: "androiddebugkey".to_string(),
            store_password: String::new(),
            key_password: String::new(),
            apksigner: String::new(),
            adb_path: String::new(),
            serial: String::new(),
            output: String::new(),
            split_output_dir: String::new(),
            replace_existing: true,
            devices: Vec::new(),
        }
    }
}

impl Default for StringEditorState {
    fn default() -> Self {
        Self {
            id: None,
            original: String::new(),
            replacement: String::new(),
        }
    }
}

impl Default for DebugState {
    fn default() -> Self {
        Self {
            port: "8000".to_string(),
            serial: String::new(),
            adb_path: String::new(),
            connected: false,
            connecting: false,
            apps_loading: false,
            waiting: false,
            floating_open: false,
            frame: None,
            values: Vec::new(),
            edits: HashMap::new(),
            pending_value: None,
            apps: Vec::new(),
            breakpoints: Vec::new(),
            last_poll: Instant::now(),
        }
    }
}

struct CoeusApp {
    bridge: Option<Arc<Bridge>>,
    startup_error: Option<String>,
    pending: Vec<PendingRequest>,
    next_request_id: u64,
    latest_view_request: u64,
    tab: Tab,
    path: String,
    output_path: String,
    search: String,
    search_kind: SearchKind,
    results: Vec<ResultRow>,
    result_count: usize,
    selected_id: Option<String>,
    described_result: Option<ResultRow>,
    xrefs: Vec<ResultRow>,
    info: Option<Value>,
    session_history: Vec<String>,
    graph: GraphState,
    code: CodeState,
    debug: DebugState,
    string_editor: StringEditorState,
    status: String,
    last_error: Option<String>,
    completed_search: Option<String>,
    submitted_search: Option<String>,
    focus_search: bool,
    sidebar_collapsed: bool,
    instruction_pane_collapsed: bool,
    navigation_kind: NavigationKind,
    navigation_history: Vec<NavigationEntry>,
    navigation_cursor: Option<usize>,
    navigation_replay: Option<String>,
    edit_picker: Option<EditPicker>,
    graph_node_details: Option<GraphNodeDetails>,
    description_cache: HashMap<String, Value>,
    notes: HashMap<String, String>,
    aliases: HashMap<String, String>,
    note_editor: Option<NoteEditor>,
    note_popup: Option<NotePopup>,
    alias_editor: Option<AliasEditor>,
    emulation_editor: Option<EmulationEditor>,
    emulation_result: Option<EmulationResult>,
    emulation_pending_label: Option<String>,
    pending_note_navigation: Option<PendingNoteNavigation>,
    manifest_xml: String,
    manifest_dirty: bool,
    session_dirty: bool,
    pending_after_save: Option<(String, Value)>,
    deploy: DeployState,
    split_mode: bool,
    split_members: Vec<String>,
    adb: AdbState,
}

impl CoeusApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::install(&cc.egui_ctx);
        Self::with_bridge(Bridge::spawn())
    }

    fn with_bridge(bridge: Result<Bridge, String>) -> Self {
        match bridge {
            Ok(bridge) => {
                let backend_name = bridge.name();
                Self {
                    bridge: Some(Arc::new(bridge)),
                    startup_error: None,
                    pending: Vec::new(),
                    next_request_id: 0,
                    latest_view_request: 0,
                    tab: Tab::Search,
                    path: String::new(),
                    output_path: String::new(),
                    search: ".*".to_string(),
                    search_kind: SearchKind::Methods,
                    results: Vec::new(),
                    result_count: 0,
                    selected_id: None,
                    described_result: None,
                    xrefs: Vec::new(),
                    info: None,
                    session_history: Vec::new(),
                    graph: GraphState::default(),
                    code: CodeState::default(),
                    debug: DebugState::default(),
                    string_editor: StringEditorState::default(),
                    status: format!("Ready — {backend_name} backend; choose an APK to begin"),
                    last_error: None,
                    completed_search: None,
                    submitted_search: None,
                    focus_search: false,
                    sidebar_collapsed: false,
                    instruction_pane_collapsed: false,
                    navigation_kind: NavigationKind::Automatic,
                    navigation_history: Vec::new(),
                    navigation_cursor: None,
                    navigation_replay: None,
                    edit_picker: None,
                    graph_node_details: None,
                    description_cache: HashMap::new(),
                    notes: HashMap::new(),
                    aliases: HashMap::new(),
                    note_editor: None,
                    note_popup: None,
                    alias_editor: None,
                    emulation_editor: None,
                    emulation_result: None,
                    emulation_pending_label: None,
                    pending_note_navigation: None,
                    manifest_xml: String::new(),
                    manifest_dirty: false,
                    session_dirty: false,
                    pending_after_save: None,
                    deploy: DeployState::default(),
                    split_mode: false,
                    split_members: Vec::new(),
                    adb: AdbState::default(),
                }
            }
            Err(error) => Self {
                bridge: None,
                startup_error: Some(error.clone()),
                pending: Vec::new(),
                next_request_id: 0,
                latest_view_request: 0,
                tab: Tab::Search,
                path: String::new(),
                output_path: String::new(),
                search: ".*".to_string(),
                search_kind: SearchKind::Methods,
                results: Vec::new(),
                result_count: 0,
                selected_id: None,
                described_result: None,
                xrefs: Vec::new(),
                info: None,
                session_history: Vec::new(),
                graph: GraphState::default(),
                code: CodeState::default(),
                debug: DebugState::default(),
                string_editor: StringEditorState::default(),
                status: error.clone(),
                last_error: Some(error),
                completed_search: None,
                submitted_search: None,
                focus_search: false,
                sidebar_collapsed: false,
                instruction_pane_collapsed: false,
                navigation_kind: NavigationKind::Automatic,
                navigation_history: Vec::new(),
                navigation_cursor: None,
                navigation_replay: None,
                edit_picker: None,
                graph_node_details: None,
                description_cache: HashMap::new(),
                notes: HashMap::new(),
                aliases: HashMap::new(),
                note_editor: None,
                note_popup: None,
                alias_editor: None,
                emulation_editor: None,
                emulation_result: None,
                emulation_pending_label: None,
                pending_note_navigation: None,
                manifest_xml: String::new(),
                manifest_dirty: false,
                session_dirty: false,
                pending_after_save: None,
                deploy: DeployState::default(),
                split_mode: false,
                split_members: Vec::new(),
                adb: AdbState::default(),
            },
        }
    }

    fn busy(&self) -> bool {
        self.pending.iter().any(|request| {
            !matches!(
                request.operation.as_str(),
                "debug_breakpoint" | "debug_breakpoint_skip" | "debug_breakpoint_remove"
            )
        })
    }

    fn debug_breakpoint_pending(&self) -> bool {
        self.pending.iter().any(|request| {
            matches!(
                request.operation.as_str(),
                "debug_breakpoint" | "debug_breakpoint_skip" | "debug_breakpoint_remove"
            )
        })
    }

    fn can_overlap_request(op: &str) -> bool {
        matches!(
            op,
            "history"
                | "manifest"
                | "search"
                | "resolve"
                | "edit_search"
                | "describe"
                | "xrefs"
                | "graph"
                | "graph_node_details"
                | "edit_options"
                | "debug_breakpoint"
                | "debug_breakpoint_skip"
                | "debug_breakpoint_remove"
                | "adb_devices"
                | "adb_packages"
        )
    }

    fn source_directory(&self) -> Option<String> {
        let source = self.path.split(',').next()?.trim();
        if source.is_empty() {
            return None;
        }
        if source.starts_with("ADB:") {
            return Some("coeus-session.coeus".to_string());
        }
        let path = Path::new(source);
        path.parent().map(|parent| parent.display().to_string())
    }

    fn request_generate_keystore(&mut self) {
        let Some(directory) = self.source_directory() else {
            self.status =
                "Open a local APK or Coeus project before generating a keystore".to_string();
            return;
        };
        self.request(
            "generate_keystore",
            json!({
                "op": "generate_keystore",
                "directory": directory,
                "alias": self.deploy.alias,
                "store_password": self.deploy.store_password,
                "key_password": if self.deploy.key_password.is_empty() {
                    Value::Null
                } else {
                    Value::String(self.deploy.key_password.clone())
                },
                "filename": "debug.keystore",
            }),
        );
    }

    fn open_apk_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Android package", &["apk"])
            .pick_file()
        {
            self.path = path.display().to_string();
            self.output_path.clear();
            let path = self.path.clone();
            self.request("load", json!({"op": "load", "path": path}));
        }
    }

    fn open_split_dialog(&mut self) {
        if let Some(paths) = rfd::FileDialog::new()
            .add_filter("Android packages", &["apk"])
            .pick_files()
        {
            self.path = paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            self.output_path.clear();
            self.request(
                "load_split",
                json!({
                    "op": "load_split",
                    "paths": paths
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>(),
                }),
            );
        }
    }

    fn load_selected_path(&mut self) {
        if self.path.trim().is_empty() {
            return;
        }
        let path = self.path.trim().to_string();
        let operation = if path.to_lowercase().ends_with(".coeus") {
            "load_project"
        } else {
            "load"
        };
        self.request(operation, json!({"op": operation, "path": path}));
    }

    fn open_project_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Coeus project", &["coeus"])
            .pick_file()
        {
            let path = path.display().to_string();
            self.path = path.clone();
            self.output_path.clear();
            self.request("load_project", json!({"op": "load_project", "path": path}));
        }
    }

    fn save_project_dialog(&mut self) {
        if self.info.is_none() || self.busy() {
            return;
        }
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Coeus project", &["coeus"])
            .set_file_name("project.coeus")
            .save_file()
        {
            let request = self.save_project_request(path.display().to_string());
            self.request("save_project", request);
        }
    }

    fn save_project_in_place(&mut self) {
        if self.info.is_none() || self.busy() || !self.path.to_ascii_lowercase().ends_with(".coeus")
        {
            return;
        }
        let path = self.path.clone();
        let request = self.save_project_request(path);
        self.request("save_project", request);
    }

    fn session_save_path(&self) -> Option<String> {
        let source = self.path.split(',').next()?.trim();
        if source.is_empty() || source.starts_with("ADB:") {
            return None;
        }
        if source.to_ascii_lowercase().ends_with(".coeus") {
            Some(source.to_string())
        } else {
            Some(format!("{source}.coeus"))
        }
    }

    fn request_after_session_save(&mut self, operation: &str, request: Value) {
        let Some(path) = self.session_save_path() else {
            self.status = "Open an APK or project before deploying".to_string();
            return;
        };
        self.pending_after_save = Some((operation.to_string(), request));
        let request = self.save_project_request(path);
        self.request("save_project", request);
        self.status = "Saving the current session before deployment…".to_string();
    }

    fn export_script_dialog(&mut self) {
        if self.info.is_none() || self.busy() {
            return;
        }
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Python script", &["py"])
            .set_file_name("coeus_session.py")
            .save_file()
        {
            self.request(
                "export_script",
                json!({"op": "export_script", "path": path.display().to_string()}),
            );
        }
    }

    fn write_apk_dialog(&mut self) {
        if self.info.is_none() || self.busy() {
            return;
        }
        let output = if self.output_path.trim().is_empty() {
            rfd::FileDialog::new()
                .add_filter("Android package", &["apk"])
                .set_file_name("edited.apk")
                .save_file()
                .map(|path| path.display().to_string())
        } else {
            Some(self.output_path.trim().to_string())
        };
        if let Some(path) = output {
            self.output_path = path.clone();
            self.request("write", json!({"op": "write", "path": path}));
        }
    }

    fn request(&mut self, op: &str, request: Value) {
        if self.busy() && !Self::can_overlap_request(op) {
            self.status = "Waiting for the current Coeus operation…".to_string();
            return;
        }
        self.next_request_id = self.next_request_id.wrapping_add(1);
        let request_id = self.next_request_id;
        if matches!(op, "describe" | "graph") {
            self.latest_view_request = request_id;
        }
        if op == "describe" {
            if let Some(id) = request.get("id").and_then(Value::as_str) {
                if let Some(data) = self.description_cache.get(id).cloned() {
                    self.status = "Loaded disassembly from the GUI cache".to_string();
                    self.finish(request_id, "describe".to_string(), Ok(data));
                    return;
                }
            }
        }
        let Some(bridge) = self.bridge.as_ref().cloned() else {
            self.status = "The selected analysis backend is unavailable".to_string();
            return;
        };
        if op == "search" {
            self.submitted_search = request
                .get("query")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        let (sender, receiver) = mpsc::channel();
        let name = op.to_string();
        thread::spawn(move || {
            let result = bridge.call(request);
            let _ = sender.send(result);
        });
        self.pending.push(PendingRequest {
            request_id,
            operation: name.clone(),
            receiver,
        });
        self.status = format!("Running {name}…");
    }

    fn poll(&mut self) {
        let mut completed = Vec::new();
        for (index, pending) in self.pending.iter().enumerate() {
            match pending.receiver.try_recv() {
                Ok(result) => {
                    completed.push((index, pending.request_id, pending.operation.clone(), result))
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    completed.push((
                        index,
                        pending.request_id,
                        pending.operation.clone(),
                        Err("The analysis backend disconnected".to_string()),
                    ));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        for (index, _, _, _) in completed.iter().rev() {
            self.pending.remove(*index);
        }
        for (_, request_id, operation, result) in completed {
            self.finish(request_id, operation, result);
            self.dispatch_pending_debug_value();
        }
    }

    fn finish(&mut self, request_id: u64, operation: String, result: Response) {
        // Graphs and disassemblies intentionally run concurrently. Ignore a
        // response for an older view request so a slow disassembly cannot
        // switch the UI back to Code after a newer graph request completed
        // (and vice versa).
        if matches!(operation.as_str(), "describe" | "graph")
            && request_id != self.latest_view_request
        {
            return;
        }
        match result {
            Ok(data) => {
                self.last_error = None;
                if let Some(history) = data.get("history").and_then(Value::as_array) {
                    self.session_history = history
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect();
                }
                match operation.as_str() {
                    "load" | "load_split" | "load_split_from_adb" | "load_project" => {
                        let package = value_string(&data, "package");
                        let manifest_xml = value_string(&data, "manifest");
                        let saved_graph = data.get("graph").cloned();
                        let split_mode =
                            data.get("split").and_then(Value::as_bool).unwrap_or(false);
                        let split_members = data
                            .get("members")
                            .and_then(Value::as_array)
                            .map(|members| {
                                members
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_string)
                                    .collect()
                            })
                            .unwrap_or_default();
                        if self.output_path.is_empty() {
                            self.output_path =
                                format!("{}.edited.apk", self.path.trim_end_matches(".apk"));
                        }
                        if self.deploy.output.is_empty() {
                            self.deploy.output =
                                format!("{}.signed.apk", self.path.trim_end_matches(".apk"));
                        }
                        self.notes = notes_map(&data);
                        self.aliases = aliases_map(&data);
                        self.info = Some(data);
                        self.results.clear();
                        self.result_count = 0;
                        self.completed_search = None;
                        self.tab = Tab::Search;
                        self.xrefs.clear();
                        self.selected_id = None;
                        self.described_result = None;
                        self.code = CodeState::default();
                        self.graph = GraphState::default();
                        self.restore_saved_graph(saved_graph.as_ref());
                        self.string_editor = StringEditorState::default();
                        self.navigation_history.clear();
                        self.navigation_cursor = None;
                        self.navigation_replay = None;
                        self.edit_picker = None;
                        self.graph_node_details = None;
                        self.description_cache.clear();
                        self.note_editor = None;
                        self.note_popup = None;
                        self.alias_editor = None;
                        self.emulation_editor = None;
                        self.emulation_result = None;
                        self.emulation_pending_label = None;
                        self.manifest_xml = manifest_xml;
                        self.manifest_dirty = false;
                        self.session_dirty = false;
                        self.pending_after_save = None;
                        self.split_mode = split_mode;
                        self.split_members = split_members;
                        self.deploy.devices.clear();
                        self.deploy.serial.clear();
                        if self.deploy.split_output_dir.is_empty() {
                            self.deploy.split_output_dir = format!(
                                "{}.signed-apks",
                                if package.is_empty() {
                                    "split"
                                } else {
                                    &package
                                }
                            );
                        }
                        self.status = if package.is_empty() {
                            "APK loaded".to_string()
                        } else {
                            format!("Loaded {package}")
                        };
                    }
                    "write" => {
                        self.status =
                            format!("Wrote edited APK to {}", value_string(&data, "path"));
                    }
                    "save_project" => {
                        let saved_path = value_string(&data, "path");
                        if !saved_path.is_empty() {
                            self.path = saved_path.clone();
                        }
                        self.session_dirty = false;
                        self.status = format!("Saved Coeus project to {saved_path}");
                        if let Some((next_operation, next_request)) = self.pending_after_save.take()
                        {
                            self.request(&next_operation, next_request);
                        }
                    }
                    "set_note" => {
                        let key = value_string(&data, "key");
                        let note = value_string(&data, "note");
                        if !key.is_empty() {
                            if note.trim().is_empty() {
                                self.notes.remove(&key);
                            } else {
                                self.notes.insert(key, note);
                            }
                        }
                        self.status = "Annotation saved".to_string();
                        self.session_dirty = true;
                    }
                    "set_alias" => {
                        let key = value_string(&data, "key");
                        let alias = value_string(&data, "alias");
                        if !key.is_empty() {
                            if alias.trim().is_empty() {
                                self.aliases.remove(&key);
                            } else {
                                self.aliases.insert(key, alias);
                            }
                        }
                        self.status = "Alias saved".to_string();
                        self.session_dirty = true;
                    }
                    "export_script" => {
                        self.status =
                            format!("Exported Coeus script to {}", value_string(&data, "path"));
                    }
                    "generate_keystore" => {
                        self.deploy.keystore = value_string(&data, "path");
                        self.status =
                            format!("Generated keystore at {}", value_string(&data, "path"));
                    }
                    "resolve" => {
                        let id = value_string(&data, "id");
                        if id.is_empty() {
                            self.pending_note_navigation = None;
                            self.status = "Could not resolve the note location".to_string();
                        } else {
                            self.selected_id = Some(id.clone());
                            self.tab = Tab::Code;
                            self.request("describe", json!({"op": "describe", "id": id}));
                        }
                    }
                    "emulate" => {
                        let success = data
                            .get("success")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let output = if success {
                            value_string(&data, "result")
                        } else {
                            value_string(&data, "error")
                        };
                        let method_label = self
                            .emulation_pending_label
                            .take()
                            .unwrap_or_else(|| self.code.identity_title.clone());
                        self.emulation_result = Some(EmulationResult {
                            method_label,
                            success,
                            output: if output.is_empty() {
                                if success {
                                    "The method returned no displayable value.".to_string()
                                } else {
                                    "The emulator reported an unspecified failure.".to_string()
                                }
                            } else {
                                output
                            },
                        });
                        self.status = if success {
                            "Method emulation succeeded".to_string()
                        } else {
                            "Method emulation failed".to_string()
                        };
                    }
                    "emulation_options" => {
                        let analysis_limited = data
                            .get("analysis_limited")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                            || data
                                .get("truncated")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                        let guesses = data
                            .get("options")
                            .and_then(Value::as_array)
                            .map(|options| {
                                options
                                    .iter()
                                    .map(|option| EmulationGuess {
                                        label: value_string(option, "label"),
                                        arguments: option
                                            .get("arguments")
                                            .and_then(Value::as_array)
                                            .map(|arguments| {
                                                arguments
                                                    .iter()
                                                    .map(|argument| {
                                                        argument
                                                            .as_str()
                                                            .unwrap_or_default()
                                                            .to_string()
                                                    })
                                                    .collect()
                                            })
                                            .unwrap_or_default(),
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        if let Some(editor) = self.emulation_editor.as_mut() {
                            editor.guesses = guesses;
                            self.status = if editor.guesses.is_empty() {
                                if analysis_limited {
                                    "Static flow analysis reached its work limit without finding usable argument sets".to_string()
                                } else {
                                    "Static flow analysis found no usable argument sets".to_string()
                                }
                            } else {
                                format!(
                                    "Static flow analysis found {} possible argument set(s){}",
                                    editor.guesses.len(),
                                    if analysis_limited {
                                        " before reaching its work limit"
                                    } else {
                                        ""
                                    }
                                )
                            };
                        }
                    }
                    "emulate_batch" => {
                        let method_label = self
                            .emulation_pending_label
                            .take()
                            .unwrap_or_else(|| self.code.identity_title.clone());
                        let output = data
                            .get("results")
                            .and_then(Value::as_array)
                            .map(|results| {
                                results
                                    .iter()
                                    .enumerate()
                                    .map(|(index, result)| {
                                        let arguments = result
                                            .get("arguments")
                                            .and_then(Value::as_array)
                                            .map(|arguments| {
                                                arguments
                                                    .iter()
                                                    .map(|argument| {
                                                        argument.as_str().unwrap_or_default()
                                                    })
                                                    .collect::<Vec<_>>()
                                                    .join(", ")
                                            })
                                            .unwrap_or_default();
                                        let success = result
                                            .get("success")
                                            .and_then(Value::as_bool)
                                            .unwrap_or(false);
                                        let value = if success {
                                            value_string(result, "result")
                                        } else {
                                            value_string(result, "error")
                                        };
                                        format!(
                                            "{}. [{}] {}: {}",
                                            index + 1,
                                            arguments,
                                            if success { "returned" } else { "failed" },
                                            if value.is_empty() {
                                                "(no displayable value)"
                                            } else {
                                                &value
                                            }
                                        )
                                    })
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            })
                            .unwrap_or_else(|| "No emulation results were returned.".to_string());
                        self.emulation_result = Some(EmulationResult {
                            method_label,
                            success: data
                                .get("success")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            output,
                        });
                        self.status = "Finished emulating all static argument sets".to_string();
                    }
                    "search" => {
                        self.completed_search = self.submitted_search.take();
                        self.result_count =
                            data.get("count").and_then(Value::as_u64).unwrap_or(0) as usize;
                        self.results = result_rows(&data);
                        self.status = format!("Found {} result(s)", self.result_count);
                        if let Some(pending) = self.pending_note_navigation.clone() {
                            if let Some(result) = self
                                .results
                                .iter()
                                .find(|result| {
                                    result.kind == pending.kind && result.label == pending.label
                                })
                                .cloned()
                            {
                                self.selected_id = Some(result.id.clone());
                                self.request("describe", json!({"op":"describe", "id":result.id}));
                            } else {
                                self.pending_note_navigation = None;
                                self.status = format!(
                                    "Could not resolve the note location: {}",
                                    pending.label
                                );
                            }
                        }
                    }
                    "edit_search" => {
                        if let Some(picker) = self.edit_picker.as_mut() {
                            picker.result_count =
                                data.get("count").and_then(Value::as_u64).unwrap_or(0) as usize;
                            picker.results = picker_result_rows(&data);
                            picker.searched = true;
                            self.status = format!(
                                "Found {} {} for the edit picker",
                                picker.result_count,
                                picker.kind.label().to_lowercase()
                            );
                        }
                    }
                    "describe" => {
                        let id = value_string(&data, "id");
                        if !id.is_empty() {
                            self.description_cache.insert(id, data.clone());
                        }
                        self.apply_description(&data);
                    }
                    "replace_string" => {
                        let id = value_string(&data, "id");
                        let value = value_string(&data, "value");
                        self.string_editor.original = value.clone();
                        self.string_editor.replacement = value.clone();
                        for result in &mut self.results {
                            if result.id == id {
                                result.label = value.clone();
                            }
                        }
                        if let Some(result) = &mut self.described_result {
                            if result.id == id {
                                result.label = value.clone();
                            }
                        }
                        self.description_cache.clear();
                        self.status = "Replaced the DEX string-pool entry".to_string();
                        self.session_dirty = true;
                    }
                    "manifest" => {
                        self.manifest_xml = value_string(&data, "xml");
                        self.manifest_dirty = false;
                        self.status = "Manifest reloaded".to_string();
                    }
                    "set_manifest_xml"
                    | "set_debuggable"
                    | "allow_plaintext_and_user_certificates" => {
                        self.manifest_xml = value_string(&data, "xml");
                        self.manifest_dirty = false;
                        self.description_cache.clear();
                        self.status = match operation.as_str() {
                            "set_manifest_xml" => "Manifest XML applied".to_string(),
                            "set_debuggable" => "Manifest debuggable flag updated".to_string(),
                            _ => "Plaintext traffic and user certificates enabled".to_string(),
                        };
                        self.session_dirty = true;
                    }
                    "xrefs" => {
                        self.xrefs = result_rows(&data);
                        self.status = format!("Found {} cross-reference(s)", self.xrefs.len());
                    }
                    "edit_options" => {
                        self.code.edit_form = None;
                        self.code.edit_dex_name = value_string(&data, "dex");
                        self.code.edit_available = data
                            .get("available")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        self.code.edit_reason = value_string(&data, "reason");
                        self.code.edit_options = data
                            .get("options")
                            .and_then(Value::as_array)
                            .map(|items| {
                                items
                                    .iter()
                                    .map(|item| EditOption {
                                        id: value_string(item, "id"),
                                        group: value_string(item, "group"),
                                        label: value_string(item, "label"),
                                        action: value_string(item, "action"),
                                        width: item
                                            .get("width")
                                            .and_then(Value::as_u64)
                                            .unwrap_or(0),
                                        arguments: item
                                            .get("arguments")
                                            .and_then(Value::as_array)
                                            .map(|arguments| {
                                                arguments
                                                    .iter()
                                                    .map(|argument| EditArgument {
                                                        name: value_string(argument, "name"),
                                                        label: value_string(argument, "label"),
                                                        kind: value_string(argument, "kind"),
                                                        value: value_string(argument, "value"),
                                                        picker: edit_picker_kind(argument),
                                                    })
                                                    .collect()
                                            })
                                            .unwrap_or_default(),
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        self.status = if self.code.edit_available {
                            "Instruction nodes are ready".to_string()
                        } else {
                            self.code.edit_reason.clone()
                        };
                    }
                    "apply_edit" => {
                        self.apply_description(&data);
                        self.code.edit_options.clear();
                        self.code.edit_form = None;
                        self.description_cache.clear();
                        self.status =
                            "Applied structured instruction edit and reparsed the DEX".to_string();
                        self.session_dirty = true;
                    }
                    "graph" => {
                        self.graph.kind = value_string(&data, "kind");
                        self.graph.dot = value_string(&data, "dot");
                        let (nodes, edges, total_nodes, total_edges) = parse_dot(&self.graph.dot);
                        self.graph.nodes = nodes;
                        self.graph.node_index = self
                            .graph
                            .nodes
                            .iter()
                            .enumerate()
                            .map(|(index, (id, _))| (*id, index))
                            .collect();
                        self.graph.edges = edges;
                        self.graph.edge_index = graph_edge_index(&self.graph.edges);
                        self.graph.total_nodes = total_nodes;
                        self.graph.total_edges = total_edges;
                        self.graph.node_filters = all_graph_node_kinds().into_iter().collect();
                        self.graph.node_search.clear();
                        self.graph.node_search_cache_query.clear();
                        self.graph.node_search_results.clear();
                        self.graph.focus_node = None;
                        self.graph.last_edge_click = None;
                        self.rebuild_graph_layout();
                        self.graph_node_details = None;
                        self.graph.zoom = 1.0;
                        self.graph.fit_to_view = true;
                        self.session_dirty = true;
                        self.status = format!(
                            "{} graph loaded ({} of {} nodes, {} edges)",
                            self.graph.kind,
                            self.graph.nodes.len(),
                            self.graph.total_nodes,
                            self.graph.total_edges
                        );
                    }
                    "graph_node_details" => {
                        if let Some(details) = self.graph_node_details.as_mut() {
                            details.kind = value_string(&data, "kind");
                            details.value = value_string(&data, "value");
                            details.label = value_string(&data, "label");
                            details.targets = data
                                .get("targets")
                                .and_then(Value::as_array)
                                .map(|targets| {
                                    targets
                                        .iter()
                                        .map(|target| {
                                            let kind = value_string(target, "kind");
                                            let label = value_string(target, "label");
                                            let note_key = value_string(target, "note_key");
                                            NavigationTarget {
                                                id: value_string(target, "id"),
                                                note_key: if note_key.is_empty() {
                                                    annotation_key(&kind, &label)
                                                } else {
                                                    note_key
                                                },
                                                kind,
                                                label,
                                            }
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            details.loading = false;
                        }
                        self.status = "Graph node details loaded".to_string();
                    }
                    "adb_devices" => {
                        let devices: Vec<DeployDevice> = data
                            .get("devices")
                            .and_then(Value::as_array)
                            .map(|devices| {
                                devices
                                    .iter()
                                    .map(|device| DeployDevice {
                                        serial: value_string(device, "serial"),
                                        label: value_string(device, "label"),
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        self.deploy.devices = devices.clone();
                        self.adb.devices = devices;
                        if self.deploy.serial.is_empty() {
                            self.deploy.serial = self
                                .deploy
                                .devices
                                .first()
                                .map(|device| device.serial.clone())
                                .unwrap_or_default();
                        }
                        if self.adb.serial.is_empty() {
                            self.adb.serial = self
                                .adb
                                .devices
                                .first()
                                .map(|device| device.serial.clone())
                                .unwrap_or_default();
                        }
                        self.status = format!(
                            "Found {} connected ADB device(s)",
                            self.deploy.devices.len()
                        );
                    }
                    "adb_packages" => {
                        self.adb.packages = data
                            .get("packages")
                            .and_then(Value::as_array)
                            .map(|packages| {
                                packages
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_string)
                                    .collect()
                            })
                            .unwrap_or_default();
                        if self.adb.selected_package.is_empty() {
                            self.adb.selected_package =
                                self.adb.packages.first().cloned().unwrap_or_default();
                        }
                        self.status = format!(
                            "Found {} installed package(s) on the ADB device",
                            self.adb.packages.len()
                        );
                    }
                    "pull_apks" => {
                        if let Some(loaded) = data.get("loaded").cloned() {
                            self.finish(
                                self.next_request_id,
                                "load_split_from_adb".to_string(),
                                Ok(loaded),
                            );
                        }
                        self.status = format!(
                            "Pulled {} APK member(s) into {}",
                            data.get("paths")
                                .and_then(Value::as_array)
                                .map(|paths| paths.len())
                                .unwrap_or(0),
                            value_string(&data, "output_dir")
                        );
                    }
                    "sign" => {
                        self.status = format!("Signed APK at {}", value_string(&data, "path"));
                    }
                    "install" => {
                        self.status = format!(
                            "Installed APK on {}",
                            if value_string(&data, "serial").is_empty() {
                                "the default ADB device".to_string()
                            } else {
                                value_string(&data, "serial")
                            }
                        );
                    }
                    "sign_and_install" => {
                        self.status = format!(
                            "Signed and installed APK on {}",
                            if value_string(&data, "serial").is_empty() {
                                "the default ADB device".to_string()
                            } else {
                                value_string(&data, "serial")
                            }
                        );
                    }
                    "sign_split" => {
                        self.status = format!(
                            "Signed {} split APK member(s) into {}",
                            data.get("paths")
                                .and_then(Value::as_array)
                                .map(|paths| paths.len())
                                .unwrap_or(0),
                            value_string(&data, "output_dir")
                        );
                    }
                    "install_split" => {
                        self.status = format!(
                            "Installed split APK set on {}",
                            if value_string(&data, "serial").is_empty() {
                                "the default ADB device".to_string()
                            } else {
                                value_string(&data, "serial")
                            }
                        );
                    }
                    "sign_and_install_split" => {
                        self.status = format!(
                            "Signed and installed split APK set on {}",
                            if value_string(&data, "serial").is_empty() {
                                "the default ADB device".to_string()
                            } else {
                                value_string(&data, "serial")
                            }
                        );
                    }
                    "debug_connect" | "debug_attach" => {
                        self.debug.connecting = data
                            .get("connecting")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        if !self.debug.connecting
                            && data.get("connected").and_then(Value::as_bool) == Some(true)
                        {
                            self.debug.connected = true;
                            self.debug.breakpoints.clear();
                            self.code.breakpoints.clear();
                            self.code.highlighted_offset = None;
                            self.code.highlight_scroll_pending = false;
                            self.status = "Debugger connected".to_string();
                        } else {
                            self.status = "Connecting to the JDWP debugger…".to_string();
                        }
                    }
                    "debug_connect_poll" => {
                        self.debug.connecting = data
                            .get("connecting")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        if data.get("connected").and_then(Value::as_bool) == Some(true) {
                            self.debug.connected = true;
                            self.debug.breakpoints.clear();
                            self.code.breakpoints.clear();
                            self.debug.frame = None;
                            self.debug.values.clear();
                            self.debug.edits.clear();
                            self.debug.pending_value = None;
                            self.debug.floating_open = false;
                            self.code.highlighted_offset = None;
                            self.code.highlight_scroll_pending = false;
                            self.status = "Debugger connected".to_string();
                        }
                    }
                    "debug_detach" => {
                        self.debug.connected = false;
                        self.debug.connecting = false;
                        self.debug.waiting = false;
                        self.debug.apps_loading = false;
                        self.debug.frame = None;
                        self.debug.values.clear();
                        self.debug.edits.clear();
                        self.debug.pending_value = None;
                        self.debug.floating_open = false;
                        self.code.highlighted_offset = None;
                        self.code.highlight_scroll_pending = false;
                        self.code.breakpoints.clear();
                        self.debug.breakpoints.clear();
                        self.status = "Debugger detached".to_string();
                    }
                    "debug_apps" => {
                        self.debug.apps_loading = data
                            .get("loading")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        self.status = "Looking for JDWP processes…".to_string();
                    }
                    "debug_apps_poll" => {
                        self.debug.apps_loading = data
                            .get("loading")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        if !self.debug.apps_loading {
                            self.debug.apps = data
                                .get("apps")
                                .and_then(Value::as_array)
                                .map(|apps| {
                                    apps.iter()
                                        .map(|app| DebugApp {
                                            pid: value_u64(app, "pid"),
                                            process: value_string(app, "process"),
                                            package: value_string(app, "package"),
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            self.status =
                                format!("Found {} JDWP process(es)", self.debug.apps.len());
                        }
                    }
                    "debug_breakpoint" | "debug_breakpoint_skip" | "debug_breakpoint_remove" => {
                        let offset = value_u64(&data, "offset");
                        let enabled = data.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                        let method_id = value_string(&data, "method_id");
                        let method_id = if method_id.is_empty() {
                            self.code
                                .selected_method_id
                                .clone()
                                .or_else(|| self.code.method_id.clone())
                                .unwrap_or_default()
                        } else {
                            method_id
                        };
                        let method_key = value_string(&data, "method_key");
                        let method_key = if method_key.is_empty() {
                            method_id.clone()
                        } else {
                            method_key
                        };
                        if enabled {
                            if !method_key.is_empty() {
                                self.code.breakpoints.insert((method_key.clone(), offset));
                            }
                        } else {
                            if !method_key.is_empty() {
                                self.code.breakpoints.remove(&(method_key.clone(), offset));
                            }
                        }
                        if !method_key.is_empty() {
                            if matches!(
                                operation.as_str(),
                                "debug_breakpoint" | "debug_breakpoint_remove"
                            ) && !enabled
                            {
                                self.debug.breakpoints.retain(|breakpoint| {
                                    !(breakpoint.method_key == method_key
                                        && breakpoint.offset == offset)
                                });
                            } else if let Some(breakpoint) =
                                self.debug.breakpoints.iter_mut().find(|breakpoint| {
                                    breakpoint.method_key == method_key
                                        && breakpoint.offset == offset
                                })
                            {
                                breakpoint.enabled = enabled;
                                breakpoint.method_id = method_id.clone();
                            } else {
                                self.debug.breakpoints.push(DebugBreakpoint {
                                    method_id: method_id.clone(),
                                    method_key: method_key.clone(),
                                    offset,
                                    enabled,
                                });
                            }
                        }
                        self.debug.waiting = data
                            .get("waiting")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        self.debug.last_poll = Instant::now();
                        self.status = if operation == "debug_breakpoint_skip" && !enabled {
                            format!("Breakpoint skipped at {}", value_string(&data, "location"))
                        } else if operation == "debug_breakpoint_skip" {
                            format!("Breakpoint enabled at {}", value_string(&data, "location"))
                        } else if !enabled {
                            format!("Breakpoint cleared at {}", value_string(&data, "location"))
                        } else if self.debug.waiting {
                            format!(
                                "Breakpoint set at {}; waiting for an event…",
                                value_string(&data, "location")
                            )
                        } else {
                            format!("Breakpoint set at {}", value_string(&data, "location"))
                        };
                    }
                    "debug_wait" | "debug_resume" | "debug_step" => {
                        if matches!(operation.as_str(), "debug_resume" | "debug_step") {
                            self.clear_debug_frame();
                        }
                        self.debug.waiting =
                            data.get("waiting").and_then(Value::as_bool).unwrap_or(true);
                        self.debug.last_poll = Instant::now();
                        self.status = "Waiting for a breakpoint or single-step event…".to_string();
                    }
                    "debug_poll" => {
                        self.debug.waiting = data
                            .get("waiting")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        if let Some(frame) = data.get("frame") {
                            self.apply_frame(frame);
                            self.status = "Debugger stopped at an event".to_string();
                        } else if data.get("timeout").and_then(Value::as_bool) == Some(true) {
                            self.status =
                                "Debugger wait timed out; press Wait to continue".to_string();
                        }
                    }
                    "debug_set_value" => {
                        let slot = value_u64(&data, "slot");
                        let value = value_string(&data, "value");
                        if let Some((_, observed, edited)) = self
                            .debug
                            .values
                            .iter_mut()
                            .find(|(item, _, _)| *item == slot)
                        {
                            *observed = value.clone();
                            *edited = value.clone();
                        }
                        self.debug.edits.insert(slot, value);
                        self.status = format!("Updated register v{slot}");
                    }
                    _ => {
                        self.status = format!("Completed {operation}");
                    }
                }
            }
            Err(error) => {
                if operation == "describe" {
                    self.navigation_replay = None;
                }
                if matches!(operation.as_str(), "search" | "resolve" | "describe") {
                    self.pending_note_navigation = None;
                }
                if operation == "debug_connect"
                    || operation == "debug_attach"
                    || operation == "debug_connect_poll"
                {
                    self.debug.connecting = false;
                }
                if operation == "debug_detach" {
                    self.debug.connected = false;
                    self.debug.connecting = false;
                    self.debug.waiting = false;
                }
                if operation == "save_project" {
                    self.pending_after_save = None;
                }
                if operation == "debug_apps" || operation == "debug_apps_poll" {
                    self.debug.apps_loading = false;
                }
                if operation == "debug_poll" {
                    self.debug.waiting = false;
                }
                if matches!(operation.as_str(), "emulate" | "emulate_batch") {
                    let method_label = self
                        .emulation_pending_label
                        .take()
                        .unwrap_or_else(|| self.code.identity_title.clone());
                    self.emulation_result = Some(EmulationResult {
                        method_label,
                        success: false,
                        output: error.clone(),
                    });
                }
                self.last_error = Some(error.clone());
                self.status = error;
            }
        }
    }

    fn apply_description(&mut self, data: &Value) {
        let id = value_string(data, "id");
        let kind = value_string(data, "kind");
        let code = value_string(data, "code");
        let label = value_string(data, "label");
        // A stopped frame requests its method description asynchronously. A
        // later description response must not clear the execution marker that
        // was set when the frame arrived; ordinary navigation still resets it.
        let is_debug_frame_description = self
            .debug
            .frame
            .as_ref()
            .map(|frame| value_string(frame, "method_id") == id)
            .unwrap_or(false);
        let debug_highlight = is_debug_frame_description.then(|| {
            (
                self.code.highlighted_offset,
                self.code.highlight_scroll_pending,
            )
        });
        let result = ResultRow {
            id: id.clone(),
            kind: kind.clone(),
            label: label.clone(),
            note_key: value_string(data, "note_key"),
            is_alias: data.get("alias").and_then(Value::as_bool).unwrap_or(false),
        };
        let result = ResultRow {
            note_key: if result.note_key.is_empty() {
                annotation_key(&result.kind, &result.label)
            } else {
                result.note_key
            },
            ..result
        };
        self.described_result = Some(result.clone());
        self.record_navigation(result);
        if kind == "string" {
            let value = value_string(data, "value");
            self.string_editor.id = Some(id.clone());
            self.string_editor.original = value.clone();
            self.string_editor.replacement = value;
        } else {
            self.string_editor.id = None;
            self.string_editor.original.clear();
            self.string_editor.replacement.clear();
        }
        self.code.kind = kind.clone();
        self.code.method_id = (kind == "method").then_some(id.clone());
        let method_key = value_string(data, "method_key");
        self.code.method_key = if method_key.is_empty() {
            (kind == "method")
                .then(|| value_string(data, "label"))
                .filter(|label| !label.is_empty())
                .or_else(|| self.code.method_id.clone())
        } else {
            Some(method_key)
        };
        self.code.selected_method_id = self.code.method_id.clone();
        self.code.identity_title = label.clone();
        self.code.title = self.display_label(&kind, &label);
        self.code.code = code.clone();
        self.code.lines = code.lines().map(str::to_string).collect();
        self.code.line_method_ids = data
            .get("line_method_ids")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        self.code.line_method_keys = data
            .get("line_method_keys")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        self.code.highlighted_offset = debug_highlight.and_then(|(offset, _)| offset);
        self.code.highlight_scroll_pending =
            debug_highlight.map(|(_, pending)| pending).unwrap_or(false);
        self.code.annotated_line = None;
        self.code.annotated_line_scroll_pending = false;
        if let Some(pending) = self.pending_note_navigation.clone() {
            if pending.kind == kind && pending.label == label {
                match pending.location {
                    Some(NoteLocation::Offset(offset)) => {
                        self.code.highlighted_offset = Some(offset);
                        self.code.highlight_scroll_pending = true;
                    }
                    Some(NoteLocation::Line(line)) => {
                        self.code.annotated_line = Some(line.saturating_sub(1));
                        self.code.annotated_line_scroll_pending = true;
                    }
                    None => {}
                }
                self.pending_note_navigation = None;
                self.status = "Opened the note location".to_string();
            }
        }
        self.code.instructions = data
            .get("instructions")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| InstructionRow {
                        offset: value_u64(item, "offset"),
                        size: value_u64(item, "size"),
                        mnemonic: value_string(item, "mnemonic"),
                        text: value_string(item, "text"),
                        targets: item
                            .get("targets")
                            .and_then(Value::as_array)
                            .map(|targets| {
                                targets
                                    .iter()
                                    .map(|target| {
                                        let kind = value_string(target, "kind");
                                        let label = value_string(target, "label");
                                        let note_key = value_string(target, "note_key");
                                        NavigationTarget {
                                            id: value_string(target, "id"),
                                            note_key: if note_key.is_empty() {
                                                annotation_key(&kind, &label)
                                            } else {
                                                note_key
                                            },
                                            kind,
                                            label,
                                        }
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.refresh_code_search(true);
        self.code.selected_offset = self.code.instructions.first().map(|item| item.offset);
        self.code.edit_options.clear();
        self.code.edit_form = None;
        self.code.edit_dex_name.clear();
        self.code.edit_available = false;
        self.code.edit_reason = "Loading instruction nodes…".to_string();
        self.tab = if kind == "string" {
            Tab::Search
        } else {
            Tab::Code
        };
        if kind == "method" {
            if let (Some(method_id), Some(offset)) =
                (self.code.method_id.clone(), self.code.selected_offset)
            {
                self.request(
                    "edit_options",
                    json!({"op":"edit_options", "id":method_id, "offset":offset}),
                );
            }
        }
    }

    fn refresh_code_search(&mut self, reset_index: bool) {
        if reset_index {
            self.code.search_index = 0;
        }
        self.code.search_error = None;
        self.code.search_matches.clear();
        let query = self.code.search_query.trim();
        if query.is_empty() {
            self.code.search_scroll_pending = false;
            return;
        }
        let pattern = match Regex::new(query) {
            Ok(pattern) => pattern,
            Err(error) => {
                self.code.search_error = Some(error.to_string());
                self.code.search_scroll_pending = false;
                return;
            }
        };
        self.code.search_matches = self
            .code
            .lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| pattern.is_match(line).then_some(index))
            .collect();
        if self.code.search_matches.is_empty() {
            self.code.search_scroll_pending = false;
        } else {
            self.code.search_index = self
                .code
                .search_index
                .min(self.code.search_matches.len().saturating_sub(1));
            self.code.search_scroll_pending = true;
        }
    }

    fn move_code_search(&mut self, direction: isize) {
        if self.code.search_matches.is_empty() {
            return;
        }
        let count = self.code.search_matches.len() as isize;
        self.code.search_index =
            ((self.code.search_index as isize + direction).rem_euclid(count)) as usize;
        self.code.search_scroll_pending = true;
    }

    fn record_navigation(&mut self, entry: NavigationEntry) {
        // A debugger frame can also describe a method. Only objects explicitly
        // selected by the explorer participate in browsing history.
        if self.selected_id.as_deref() != Some(entry.id.as_str()) {
            return;
        }

        if self.navigation_replay.as_deref() == Some(entry.id.as_str()) {
            self.navigation_replay = None;
            return;
        }

        let already_current = self
            .navigation_cursor
            .and_then(|cursor| self.navigation_history.get(cursor))
            .map(|current| current.id == entry.id)
            .unwrap_or(false);
        if already_current {
            return;
        }

        self.navigation_replay = None;
        if let Some(cursor) = self.navigation_cursor {
            self.navigation_history.truncate(cursor + 1);
        } else {
            self.navigation_history.clear();
        }
        self.navigation_history.push(entry);
        self.navigation_cursor = Some(self.navigation_history.len() - 1);
    }

    fn navigate_history(&mut self, direction: isize) {
        if self.busy() {
            self.status = "Waiting for the current Coeus operation…".to_string();
            return;
        }
        let Some(cursor) = self.navigation_cursor else {
            return;
        };
        let target = cursor as isize + direction;
        if target < 0 || target >= self.navigation_history.len() as isize {
            return;
        }
        let target = target as usize;
        let entry = self.navigation_history[target].clone();
        self.navigation_cursor = Some(target);
        self.navigation_replay = Some(entry.id.clone());
        self.selected_id = Some(entry.id.clone());
        self.request("describe", json!({"op":"describe", "id":entry.id}));
    }

    fn apply_frame(&mut self, frame: &Value) {
        self.debug.frame = Some(frame.clone());
        self.debug.floating_open = true;
        self.debug.values = frame
            .get("values")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .map(|value| {
                        let slot = value_u64(value, "slot");
                        let text = value_string(value, "value");
                        (
                            slot,
                            text.clone(),
                            self.debug.edits.get(&slot).cloned().unwrap_or(text),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let method_id = value_string(frame, "method_id");
        self.debug.waiting = false;
        self.request("describe", json!({"op":"describe", "id":method_id}));
        self.code.highlighted_offset = Some(value_u64(frame, "code_index"));
        self.code.highlight_scroll_pending = true;
    }

    fn clear_debug_frame(&mut self) {
        self.debug.frame = None;
        self.debug.values.clear();
        self.debug.edits.clear();
        self.debug.pending_value = None;
        self.code.highlighted_offset = None;
        self.code.highlight_scroll_pending = false;
    }

    fn request_debug_control(&mut self, operation: &str) {
        if self.debug_breakpoint_pending() {
            self.status = "Waiting for the breakpoint request to finish…".to_string();
            return;
        }
        self.clear_debug_frame();
        self.request(operation, json!({"op": operation}));
    }

    fn queue_debug_value(&mut self, slot: u64, value: String) {
        self.debug.pending_value = Some((slot, value));
        self.dispatch_pending_debug_value();
    }

    fn dispatch_pending_debug_value(&mut self) {
        if self.busy() || self.debug.waiting || self.debug.frame.is_none() {
            return;
        }
        let Some((slot, value)) = self.debug.pending_value.take() else {
            return;
        };
        self.request(
            "debug_set_value",
            json!({"op":"debug_set_value", "slot":slot, "value":value}),
        );
    }

    fn selected_result(&self) -> Option<ResultRow> {
        let id = self.selected_id.as_ref()?;
        if let Some(result) = &self.described_result {
            if &result.id == id {
                return Some(result.clone());
            }
        }
        self.results
            .iter()
            .chain(self.xrefs.iter())
            .find(|result| &result.id == id)
            .cloned()
    }

    fn preferred_navigation_target(&self, offset: u64) -> Option<NavigationTarget> {
        let instruction = self
            .code
            .instructions
            .iter()
            .find(|instruction| instruction.offset == offset)?;
        instruction
            .targets
            .iter()
            .find(|target| self.navigation_kind.matches(&target.kind))
            .cloned()
    }

    fn open_note_editor(&mut self, target: &ResultRow) {
        if target.note_key.is_empty() {
            return;
        }
        self.note_editor = Some(NoteEditor {
            key: target.note_key.clone(),
            kind: target.kind.clone(),
            label: target.label.clone(),
            text: self
                .notes
                .get(&target.note_key)
                .cloned()
                .unwrap_or_default(),
        });
    }

    fn alias_for(&self, kind: &str, label: &str) -> Option<String> {
        self.aliases
            .get(&alias_key(kind, label))
            .filter(|alias| !alias.trim().is_empty())
            .cloned()
    }

    fn display_label(&self, kind: &str, label: &str) -> String {
        if let Some(alias) = self.alias_for(kind, label) {
            return alias;
        }
        if kind == "method" {
            if let Some((class, member)) = label.split_once("->") {
                if let Some(class_alias) = self.alias_for("class", class) {
                    return format!("{class_alias}->{member}");
                }
            }
        }
        label.to_string()
    }

    fn disassembly_alias(&self, line: &str) -> Option<DisassemblyAlias> {
        let (kind, canonical, alias, name) = if self.code.kind == "method" {
            let canonical = self.code.identity_title.as_str();
            (
                "method",
                canonical,
                self.alias_for("method", canonical),
                method_name_for_search(canonical),
            )
        } else if self.code.kind == "class" {
            let canonical = self.code.identity_title.as_str();
            (
                "class",
                canonical,
                self.alias_for("class", canonical),
                canonical.to_string(),
            )
        } else {
            return None;
        };
        let alias = alias.filter(|alias| !alias.trim().is_empty())?;
        let marker = if kind == "method" {
            line.trim_start().starts_with(".method")
        } else {
            line.trim_start().starts_with(".class")
        };
        if !marker {
            return None;
        }
        let start = line.match_indices(&name).find_map(|(start, _)| {
            let before_ok = line[..start]
                .chars()
                .next_back()
                .map(|character| character.is_whitespace())
                .unwrap_or(true);
            let end = start + name.len();
            let after_ok = if kind == "method" {
                line[end..].starts_with('(')
            } else {
                line[end..]
                    .chars()
                    .next()
                    .map(|character| character.is_whitespace())
                    .unwrap_or(true)
            };
            (before_ok && after_ok).then_some(start)
        })?;
        let end = start + name.len();
        let mut rendered = String::with_capacity(line.len() + alias.len());
        rendered.push_str(&line[..start]);
        rendered.push_str(&alias);
        rendered.push_str(&line[end..]);
        Some(DisassemblyAlias {
            line: rendered,
            range: (start, start + alias.len()),
            canonical: canonical.to_string(),
        })
    }

    fn open_alias_editor(&mut self, target: &ResultRow) {
        if !matches!(target.kind.as_str(), "method" | "class") {
            return;
        }
        let key = alias_key(&target.kind, &target.label);
        self.alias_editor = Some(AliasEditor {
            key: key.clone(),
            kind: target.kind.clone(),
            label: target.label.clone(),
            text: self.aliases.get(&key).cloned().unwrap_or_default(),
        });
    }

    fn open_alias_editor_target(&mut self, target: &NavigationTarget) {
        let result = ResultRow {
            id: target.id.clone(),
            kind: target.kind.clone(),
            label: target.label.clone(),
            note_key: target.note_key.clone(),
            is_alias: false,
        };
        self.open_alias_editor(&result);
    }

    fn open_target_note_editor(&mut self, target: &NavigationTarget) {
        if target.note_key.is_empty() {
            return;
        }
        self.note_editor = Some(NoteEditor {
            key: target.note_key.clone(),
            kind: target.kind.clone(),
            label: target.label.clone(),
            text: self
                .notes
                .get(&target.note_key)
                .cloned()
                .unwrap_or_default(),
        });
    }

    fn code_line_note_key(&self, index: usize, line: &str) -> String {
        let method_key = self
            .code
            .line_method_keys
            .get(index)
            .and_then(|key| key.as_deref())
            .or(self.code.method_key.as_deref());
        if let (Some(method_key), Some(offset)) = (method_key, parse_code_offset(line)) {
            format!("code:{method_key}:offset:{offset:x}")
        } else if self.code.kind == "class" {
            format!("code:class:{}:line:{}", self.code.identity_title, index + 1)
        } else {
            format!(
                "code:{}:line:{}",
                self.code
                    .method_key
                    .as_deref()
                    .unwrap_or(&self.code.identity_title),
                index + 1
            )
        }
    }

    fn open_code_line_note_editor(&mut self, index: usize, line: &str) {
        let key = self.code_line_note_key(index, line);
        self.note_editor = Some(NoteEditor {
            key: key.clone(),
            kind: "code line".to_string(),
            label: format!("{} · line {}", self.code.title, index + 1),
            text: self.notes.get(&key).cloned().unwrap_or_default(),
        });
    }

    fn open_note_key_editor(&mut self, key: &str) {
        let (kind, label) = parse_note_location(key)
            .map(|(kind, label, _)| (kind, label))
            .unwrap_or_else(|| ("note".to_string(), key.to_string()));
        let editor_kind = if kind == "code" {
            "code line".to_string()
        } else {
            kind.clone()
        };
        self.note_editor = Some(NoteEditor {
            key: key.to_string(),
            kind: editor_kind,
            label,
            text: self.notes.get(key).cloned().unwrap_or_default(),
        });
    }

    fn navigate_to_note(&mut self, key: &str) {
        let Some((kind, label, location)) = parse_note_location(key) else {
            self.status = "This note has no navigable location".to_string();
            return;
        };
        let (search_kind, api_kind) = match kind.as_str() {
            "method" => (SearchKind::Methods, "methods"),
            "class" => (SearchKind::Classes, "classes"),
            "string" => (SearchKind::Strings, "strings"),
            "code" => {
                // Code note keys carry either a method signature or a class name
                // in their label. Class line keys are identified by their key
                // prefix before parsing the common `code` kind.
                if key.strip_prefix("code:class:").is_some() {
                    (SearchKind::Classes, "classes")
                } else {
                    (SearchKind::Methods, "methods")
                }
            }
            _ => {
                self.status = format!("Cannot navigate to {kind} notes");
                return;
            }
        };
        self.pending_note_navigation = Some(PendingNoteNavigation {
            kind: if kind == "code" {
                if key.strip_prefix("code:class:").is_some() {
                    "class".to_string()
                } else {
                    "method".to_string()
                }
            } else {
                kind
            },
            label,
            location,
        });
        if self
            .pending_note_navigation
            .as_ref()
            .is_some_and(|pending| pending.kind == "method")
        {
            let label = self
                .pending_note_navigation
                .as_ref()
                .map(|pending| pending.label.clone())
                .unwrap_or_default();
            self.tab = Tab::Code;
            self.request(
                "resolve",
                json!({"op": "resolve", "kind": "method", "label": label}),
            );
            self.status = "Opening the exact method…".to_string();
            return;
        }
        let search_label = self
            .pending_note_navigation
            .as_ref()
            .map(|pending| {
                if pending.kind == "method" {
                    method_name_for_search(&pending.label)
                } else {
                    pending.label.clone()
                }
            })
            .unwrap_or_default();
        // Method search indexes the method name, while note keys retain the
        // complete signature. Search by the indexed name, then keep the exact
        // signature match in the response below.
        let query = regex::escape(&search_label);
        self.search = query.clone();
        self.search_kind = search_kind;
        self.tab = Tab::Search;
        self.request(
            "search",
            json!({"op":"search", "kind":api_kind, "query":query}),
        );
        self.status = "Finding the note location…".to_string();
    }

    fn show_note_chip(&mut self, ui: &mut egui::Ui, kind: &str, key: &str, label: &str) {
        let Some(note) = self.notes.get(key).cloned() else {
            return;
        };
        let compact = shorten(&note.replace('\n', " "), 30);
        let chip = if ui.available_width() >= 220.0 {
            format!("🗒 {compact}")
        } else {
            "🗒".to_string()
        };
        let response = ui
            .add(
                egui::Button::new(
                    RichText::new(chip)
                        .small()
                        .color(Color32::from_rgb(75, 55, 15)),
                )
                .fill(Color32::from_rgb(236, 199, 92))
                .stroke(Stroke::new(1.0, Color32::from_rgb(180, 140, 45)))
                .min_size(Vec2::new(28.0, 20.0)),
            )
            .on_hover_text(format!("Open note for {kind}: {label}"));
        if response.clicked() {
            self.note_popup = Some(NotePopup {
                key: key.to_string(),
                kind: kind.to_string(),
                label: label.to_string(),
                text: note,
            });
        }
    }

    fn current_annotation_target(&self) -> Option<ResultRow> {
        let result = self.described_result.as_ref()?;
        if result.note_key.is_empty() {
            None
        } else {
            Some(result.clone())
        }
    }

    fn show_note_editor(&mut self, ctx: &egui::Context) {
        let Some(mut editor) = self.note_editor.clone() else {
            return;
        };
        let mut close = false;
        let mut save = None;
        egui::Window::new(format!("Note · {}", editor.kind))
            .id(egui::Id::new(("annotation-editor", editor.key.clone())))
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.label(RichText::new(&editor.label).strong().monospace());
                ui.label(
                    RichText::new(if editor.kind == "code line" {
                        "This note is attached to this disassembly line."
                    } else {
                        "This note follows the same object in search results, cross-references, and code references."
                    })
                        .small()
                        .color(theme::MUTED),
                );
                ui.add(
                    egui::TextEdit::multiline(&mut editor.text)
                        .desired_rows(8)
                        .desired_width(f32::INFINITY)
                        .hint_text("What matters about this object?"),
                );
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!self.busy(), egui::Button::new("Save note"))
                        .clicked()
                    {
                        save = Some((editor.key.clone(), editor.text.clone()));
                    }
                    if ui
                        .add_enabled(!self.busy(), egui::Button::new("Remove note"))
                        .clicked()
                    {
                        save = Some((editor.key.clone(), String::new()));
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if let Some((key, note)) = save {
            if note.trim().is_empty() {
                self.notes.remove(&key);
            } else {
                self.notes.insert(key.clone(), note.clone());
            }
            self.note_editor = None;
            self.request(
                "set_note",
                json!({"op": "set_note", "key": key, "note": note}),
            );
        } else if close {
            self.note_editor = None;
        } else {
            self.note_editor = Some(editor);
        }
    }

    fn open_emulation_target(
        &mut self,
        method_id: String,
        method_label: String,
        method_key: String,
    ) {
        let descriptors = parse_method_descriptors(&method_key);
        self.emulation_result = None;
        self.emulation_pending_label = Some(method_label.clone());
        self.emulation_editor = Some(EmulationEditor {
            method_id,
            method_label,
            arguments: descriptors
                .into_iter()
                .map(|descriptor| EmulationArgument {
                    value: emulation_default_value(&descriptor),
                    descriptor,
                })
                .collect(),
            guesses: Vec::new(),
        });
    }

    fn open_static_emulation_target(
        &mut self,
        method_id: String,
        method_label: String,
        method_key: String,
        source_method_id: Option<String>,
        offset: Option<u64>,
    ) {
        self.open_emulation_target(method_id.clone(), method_label, method_key);
        let mut request = json!({
            "op": "emulation_options",
            "id": method_id,
        });
        if let Some(source_method_id) = source_method_id {
            request["source_id"] = json!(source_method_id);
        }
        if let Some(offset) = offset {
            request["offset"] = json!(offset);
        }
        self.request("emulation_options", request);
    }

    fn open_emulation(&mut self) {
        let Some(method_id) = self.code.method_id.clone() else {
            return;
        };
        let method_label = self.code.identity_title.clone();
        let method_key = self
            .code
            .method_key
            .clone()
            .unwrap_or_else(|| method_label.clone());
        self.open_emulation_target(method_id, method_label, method_key);
    }

    fn show_emulation_editor(&mut self, ctx: &egui::Context) {
        let Some(mut editor) = self.emulation_editor.clone() else {
            return;
        };
        let mut close = false;
        let mut run = false;
        let mut run_arguments = None;
        let mut run_all = false;
        let mut use_guess = None;
        egui::Window::new("Emulate method")
            .id(egui::Id::new(("emulation-editor", editor.method_id.clone())))
            .collapsible(false)
            .resizable(true)
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.add(egui::Label::new(RichText::new(&editor.method_label).strong().monospace()).wrap());
                ui.label(
                    RichText::new(
                        "Enter primitive values, strings, or byte arrays (JSON, for example [1, 2] or hex:0011). Object arguments are allocated as empty instances; use null when needed.",
                    )
                    .small()
                    .color(theme::MUTED),
                );
                ui.separator();
                if editor.arguments.is_empty() {
                    ui.label("This method has no arguments.");
                } else {
                    for (index, argument) in editor.arguments.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(format!("arg{}", index));
                            ui.label(
                                RichText::new(&argument.descriptor)
                                    .monospace()
                                    .color(theme::MUTED),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut argument.value)
                                    .desired_width(360.0)
                                    .hint_text("value"),
                            );
                        });
                    }
                }
                if !editor.guesses.is_empty()
                    || self
                        .pending
                        .iter()
                        .any(|pending| pending.operation == "emulation_options")
                {
                    ui.separator();
                    ui.label(RichText::new("Static flow argument guesses").strong());
                    ui.label(
                        RichText::new(
                            "These are possible argument sets found at statically analysed call sites. Unknown values are shown with safe defaults such as null or 0.",
                        )
                        .small()
                        .color(theme::MUTED),
                    );
                    if self
                        .pending
                        .iter()
                        .any(|pending| pending.operation == "emulation_options")
                    {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Analysing possible call arguments…");
                        });
                    }
                    for (index, guess) in editor.guesses.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("{}.", index + 1))
                                    .small()
                                    .color(theme::MUTED),
                            );
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&guess.label).monospace().small(),
                                )
                                .truncate(),
                            );
                            if ui.small_button("Use").clicked() {
                                use_guess = Some(index);
                            }
                            if ui.small_button("Run").clicked() {
                                run_arguments = Some(guess.arguments.clone());
                            }
                        });
                    }
                    if ui
                        .add_enabled(
                            !self.busy() && !editor.guesses.is_empty(),
                            egui::Button::new("Run all guessed argument sets"),
                        )
                        .clicked()
                    {
                        run_all = true;
                    }
                }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!self.busy(), egui::Button::new("Run emulation"))
                        .clicked()
                    {
                        run = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if run {
            run_arguments = Some(
                editor
                    .arguments
                    .iter()
                    .map(|argument| argument.value.clone())
                    .collect::<Vec<_>>(),
            );
        }
        if let Some(index) = use_guess {
            if let Some(guess) = editor.guesses.get(index) {
                for (argument, value) in editor.arguments.iter_mut().zip(&guess.arguments) {
                    argument.value = value.clone();
                }
            }
        }
        if run_all {
            let method_id = editor.method_id.clone();
            let argument_sets = editor
                .guesses
                .iter()
                .map(|guess| guess.arguments.clone())
                .collect::<Vec<_>>();
            self.emulation_editor = None;
            self.request(
                "emulate_batch",
                json!({
                    "op": "emulate_batch",
                    "id": method_id,
                    "arguments_sets": argument_sets,
                }),
            );
        } else if let Some(arguments) = run_arguments {
            let method_id = editor.method_id.clone();
            self.emulation_editor = None;
            self.request(
                "emulate",
                json!({"op": "emulate", "id": method_id, "arguments": arguments}),
            );
        } else if close {
            self.emulation_editor = None;
        } else {
            self.emulation_editor = Some(editor);
        }
    }

    fn show_emulation_result(&mut self, ctx: &egui::Context) {
        let Some(snapshot) = self.emulation_result.clone() else {
            return;
        };
        let mut close = false;
        egui::Window::new(if snapshot.success {
            "Emulation succeeded"
        } else {
            "Emulation failed"
        })
        .id(egui::Id::new((
            "emulation-result",
            snapshot.method_label.clone(),
        )))
        .collapsible(false)
        .resizable(true)
        .default_width(560.0)
        .show(ctx, |ui| {
            ui.add(
                egui::Label::new(RichText::new(&snapshot.method_label).strong().monospace()).wrap(),
            );
            ui.separator();
            ui.colored_label(
                if snapshot.success {
                    theme::SUCCESS
                } else {
                    theme::ERROR
                },
                if snapshot.success {
                    "Success"
                } else {
                    "Failure"
                },
            );
            ui.add(egui::Label::new(&snapshot.output).wrap());
            if ui.button("Close").clicked() {
                close = true;
            }
        });
        if close {
            self.emulation_result = None;
        }
    }

    fn show_note_popup(&mut self, ctx: &egui::Context) {
        let Some(snapshot) = self.note_popup.clone() else {
            return;
        };
        let mut close = false;
        let mut edit = false;
        egui::Window::new(format!("Note · {}", snapshot.kind))
            .id(egui::Id::new(("annotation-popup", snapshot.key.clone())))
            .collapsible(false)
            .resizable(true)
            .default_width(440.0)
            .show(ctx, |ui| {
                ui.label(RichText::new(&snapshot.label).strong().monospace());
                ui.separator();
                ui.add(egui::Label::new(&snapshot.text).wrap());
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Edit note").clicked() {
                        edit = true;
                    }
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
            });
        if edit {
            self.note_popup = None;
            let target = ResultRow {
                id: String::new(),
                kind: snapshot.kind,
                label: snapshot.label,
                note_key: snapshot.key,
                is_alias: false,
            };
            self.open_note_editor(&target);
        } else if close {
            self.note_popup = None;
        }
    }

    fn show_alias_editor(&mut self, ctx: &egui::Context) {
        let Some(mut editor) = self.alias_editor.clone() else {
            return;
        };
        let mut close = false;
        let mut save = None;
        egui::Window::new(format!("Alias · {}", editor.kind))
            .id(egui::Id::new(("alias-editor", editor.key.clone())))
            .collapsible(false)
            .resizable(false)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.label(RichText::new(&editor.label).strong().monospace());
                ui.label(
                    RichText::new(
                        "This alias is stored in the Coeus GUI project and does not modify the APK or DEX.",
                    )
                    .small()
                    .color(theme::MUTED),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut editor.text)
                        .desired_width(f32::INFINITY)
                        .hint_text("Friendly class or method name"),
                );
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!self.busy(), egui::Button::new("Save alias"))
                        .clicked()
                    {
                        save = Some((editor.key.clone(), editor.text.trim().to_string()));
                    }
                    if ui
                        .add_enabled(!self.busy(), egui::Button::new("Remove alias"))
                        .clicked()
                    {
                        save = Some((editor.key.clone(), String::new()));
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if let Some((key, alias)) = save {
            if alias.trim().is_empty() {
                self.aliases.remove(&key);
            } else {
                self.aliases.insert(key.clone(), alias.clone());
            }
            self.alias_editor = None;
            self.request(
                "set_alias",
                json!({"op": "set_alias", "key": key, "alias": alias}),
            );
            self.status = "Saving alias…".to_string();
        } else if close {
            self.alias_editor = None;
        } else {
            self.alias_editor = Some(editor);
        }
    }

    fn filtered_graph_nodes(&self) -> Vec<(usize, String)> {
        self.graph
            .nodes
            .iter()
            .filter(|(_, label)| self.graph.node_filters.contains(&graph_node_kind(label)))
            .cloned()
            .collect()
    }

    fn rebuild_graph_layout(&mut self) {
        let nodes = self.filtered_graph_nodes();
        let visible_ids = nodes.iter().map(|(id, _)| *id).collect::<HashSet<_>>();
        let edges = self
            .graph
            .edges
            .iter()
            .filter(|(from, to)| visible_ids.contains(from) && visible_ids.contains(to))
            .cloned()
            .collect::<Vec<_>>();
        self.graph.layout = if self.graph.kind == "supergraph" {
            layout_clustered_graph(&nodes, &edges)
        } else {
            layout_graph(&nodes, &edges)
        };
        let (layout_min, layout_max) = layout_bounds(
            nodes.iter().map(|(id, _)| *id),
            &self.graph.layout,
            GRAPH_NODE_SIZE,
        );
        let (layout_edge_index, layout_long_edges) =
            graph_layout_edge_index(&edges, &self.graph.layout);
        let node_step = (nodes.len() / 2500).max(1);
        let minimap_nodes = nodes
            .iter()
            .step_by(node_step)
            .filter_map(|(id, label)| {
                self.graph
                    .layout
                    .get(id)
                    .map(|position| (*id, *position, graph_node_kind(label)))
            })
            .collect::<Vec<_>>();
        let edge_step = (edges.len() / 1500).max(1);
        let minimap_edges = edges
            .iter()
            .step_by(edge_step)
            .filter_map(|(from, to)| {
                let from_position = *self.graph.layout.get(from)?;
                let to_position = *self.graph.layout.get(to)?;
                let from_label = label_for_node(*from, &self.graph.node_index, &self.graph.nodes)
                    .unwrap_or_default();
                let to_label = label_for_node(*to, &self.graph.node_index, &self.graph.nodes)
                    .unwrap_or_default();
                Some((
                    from_position,
                    to_position,
                    graph_edge_kind(from_label, to_label),
                ))
            })
            .collect::<Vec<_>>();
        self.graph.layout_min = layout_min;
        self.graph.layout_max = layout_max;
        self.graph.layout_index = graph_layout_index(&nodes, &self.graph.layout);
        self.graph.layout_edge_index = layout_edge_index;
        self.graph.layout_long_edges = layout_long_edges;
        self.graph.minimap_nodes = minimap_nodes;
        self.graph.minimap_edges = minimap_edges;
    }

    fn supergraph_request(&self) -> Value {
        json!({
            "op": "graph",
            "kind": "supergraph",
            "ignore": self.graph.additional_class_filters,
            "exclude_android_framework": self.graph.exclude_android_framework,
            "exclude_language_runtime": self.graph.exclude_language_runtime,
            "exclude_common_libraries": self.graph.exclude_common_libraries,
            "discover_dynamic_arguments": self.graph.discover_dynamic_arguments,
            "dynamic_argument_classes": self.graph.dynamic_argument_classes,
        })
    }

    fn graph_session_data(&self) -> Value {
        if self.graph.dot.is_empty() {
            return Value::Null;
        }
        let node_filters = all_graph_node_kinds()
            .into_iter()
            .filter(|kind| self.graph.node_filters.contains(kind))
            .map(|kind| kind.label())
            .collect::<Vec<_>>();
        json!({
            "kind": self.graph.kind,
            "dot": self.graph.dot,
            "node_filters": node_filters,
            "options": {
                "exclude_android_framework": self.graph.exclude_android_framework,
                "exclude_language_runtime": self.graph.exclude_language_runtime,
                "exclude_common_libraries": self.graph.exclude_common_libraries,
                "additional_class_filters": self.graph.additional_class_filters,
                "discover_dynamic_arguments": self.graph.discover_dynamic_arguments,
                "dynamic_argument_classes": self.graph.dynamic_argument_classes,
            },
        })
    }

    fn save_project_request(&self, path: String) -> Value {
        json!({
            "op": "save_project",
            "path": path,
            "graph": self.graph_session_data(),
        })
    }

    fn restore_saved_graph(&mut self, saved_graph: Option<&Value>) {
        let Some(saved_graph) = saved_graph.filter(|value| value.is_object()) else {
            return;
        };
        let dot = value_string(saved_graph, "dot");
        if dot.is_empty() {
            return;
        }
        self.graph.kind = value_string(saved_graph, "kind");
        self.graph.dot = dot;
        let (nodes, edges, total_nodes, total_edges) = parse_dot(&self.graph.dot);
        self.graph.nodes = nodes;
        self.graph.node_index = self
            .graph
            .nodes
            .iter()
            .enumerate()
            .map(|(index, (id, _))| (*id, index))
            .collect();
        self.graph.edges = edges;
        self.graph.edge_index = graph_edge_index(&self.graph.edges);
        self.graph.total_nodes = total_nodes;
        self.graph.total_edges = total_edges;
        if let Some(filters) = saved_graph.get("node_filters").and_then(Value::as_array) {
            self.graph.node_filters = filters
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|label| {
                    all_graph_node_kinds()
                        .into_iter()
                        .find(|kind| kind.label() == label)
                })
                .collect();
        }
        if let Some(options) = saved_graph.get("options") {
            if let Some(value) = options
                .get("exclude_android_framework")
                .and_then(Value::as_bool)
            {
                self.graph.exclude_android_framework = value;
            }
            if let Some(value) = options
                .get("exclude_language_runtime")
                .and_then(Value::as_bool)
            {
                self.graph.exclude_language_runtime = value;
            }
            if let Some(value) = options
                .get("exclude_common_libraries")
                .and_then(Value::as_bool)
            {
                self.graph.exclude_common_libraries = value;
            }
            if let Some(value) = options
                .get("additional_class_filters")
                .and_then(Value::as_str)
            {
                self.graph.additional_class_filters = value.to_string();
            }
            if let Some(value) = options
                .get("discover_dynamic_arguments")
                .and_then(Value::as_bool)
            {
                self.graph.discover_dynamic_arguments = value;
            }
            if let Some(value) = options
                .get("dynamic_argument_classes")
                .and_then(Value::as_str)
            {
                self.graph.dynamic_argument_classes = value.to_string();
            }
        }
        self.rebuild_graph_layout();
        self.graph.zoom = 1.0;
        self.graph.fit_to_view = true;
    }

    fn show_welcome(&mut self, ui: &mut egui::Ui) {
        ui.add_space(28.0);
        theme::eyebrow(ui, "COEUS EXPLORER");
        ui.add_space(10.0);
        ui.label(
            RichText::new("Understand what’s inside.")
                .size(34.0)
                .strong(),
        );
        ui.label(
            RichText::new("Explore Android apps, trace behavior, and make precise changes.")
                .size(16.0)
                .color(theme::MUTED),
        );
        ui.add_space(28.0);
        theme::card().show(ui, |ui| {
            ui.set_width((ui.available_width() - 4.0).max(1.0));
            ui.label(RichText::new("Start an investigation").size(20.0).strong());
            ui.label(
                RichText::new("Open an APK, a split package set, or a saved Coeus project.")
                    .color(theme::MUTED),
            );
            ui.add_space(12.0);
            ui.add_enabled_ui(!self.busy() && self.bridge.is_some(), |ui| {
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add(theme::primary("Open APK…"))
                        .on_hover_text("Open an Android package · Cmd/Ctrl+O")
                        .clicked()
                    {
                        self.open_apk_dialog();
                    }
                    if ui.button("Open split APKs…").clicked() {
                        self.open_split_dialog();
                    }
                    if ui.button("Open project…").clicked() {
                        self.open_project_dialog();
                    }
                });
            });
            if self.busy() {
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Preparing your workspace…");
                });
            }
            ui.add_space(8.0);
            if ui.link("Browse apps on a connected device").clicked() {
                self.tab = Tab::Adb;
            }
        });
        ui.add_space(28.0);
        let steps = [
            ("01 / EXPLORE", "Find the code that matters", "Search methods, classes, fields and strings. Follow cross-references to see how they connect."),
            ("02 / UNDERSTAND", "Follow the behavior", "Inspect decoded source, visualize call graphs and examine live debugger frames."),
            ("03 / REFINE", "Keep your work together", "Edit instructions and manifests, add notes, and save a portable project with its history."),
        ];
        if ui.available_width() > 700.0 {
            ui.columns(3, |columns| {
                for (column, (step, title, detail)) in columns.iter_mut().zip(steps) {
                    theme::eyebrow(column, step);
                    column.label(RichText::new(title).strong());
                    column.label(RichText::new(detail).color(theme::MUTED));
                }
            });
        } else {
            for (step, title, detail) in steps {
                theme::eyebrow(ui, step);
                ui.label(RichText::new(title).strong());
                ui.label(RichText::new(detail).color(theme::MUTED));
                ui.add_space(12.0);
            }
        }
        ui.add_space(28.0);
        ui.separator();
        ui.label(
            RichText::new(
                "Cmd/Ctrl+O  Open APK     Cmd/Ctrl+F  Focus search     Cmd/Ctrl+S  Save project",
            )
            .small()
            .color(theme::MUTED),
        );
    }

    fn show_status(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("workspace-status")
            .frame(
                egui::Frame::new()
                    .fill(theme::SURFACE)
                    .inner_margin(egui::Margin::symmetric(14, 8)),
            )
            .show(ctx, |ui| {
                if let Some(error) = self.last_error.clone() {
                    ui.horizontal(|ui| {
                        ui.colored_label(theme::ERROR, "Operation failed");
                        if ui.small_button("Copy details").clicked() {
                            ui.ctx().copy_text(error.clone());
                        }
                        if ui.small_button("Dismiss").clicked() {
                            self.last_error = None;
                        }
                    });
                    egui::ScrollArea::vertical()
                        .id_salt("operation-error")
                        .max_height(64.0)
                        .show(ui, |ui| {
                            ui.label(RichText::new(error).small().color(theme::ERROR));
                        });
                    ui.separator();
                }
                ui.horizontal(|ui| {
                    if self.busy() {
                        ui.spinner();
                    } else {
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(12.0), Sense::hover());
                        ui.painter().circle_filled(
                            rect.center(),
                            3.5,
                            if self.last_error.is_some() {
                                theme::ERROR
                            } else {
                                theme::SUCCESS
                            },
                        );
                    }
                    let status = if self.busy() {
                        format!("{}  ·  {} active", self.status, self.pending.len())
                    } else {
                        self.status.clone()
                    };
                    let reserved = 220.0
                        + if self.manifest_dirty { 150.0 } else { 0.0 }
                        + if self.session_dirty { 150.0 } else { 0.0 };
                    ui.allocate_ui_with_layout(
                        Vec2::new((ui.available_width() - reserved).max(80.0), 20.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&status).small().color(theme::MUTED),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&status);
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.session_dirty {
                            if ui
                                .add_enabled(!self.busy(), egui::Button::new("Save session"))
                                .on_hover_text("Save the current APK state and GUI annotations")
                                .clicked()
                            {
                                if let Some(path) = self.session_save_path() {
                                    self.request("save_project", self.save_project_request(path));
                                }
                            }
                            ui.label(
                                RichText::new("Unsaved session changes")
                                    .small()
                                    .color(theme::WARNING),
                            );
                            ui.separator();
                        }
                        ui.label(
                            RichText::new(if self.debug.connected {
                                "Debugger connected"
                            } else {
                                "Debugger offline"
                            })
                            .small()
                            .color(theme::MUTED),
                        );
                        if self.manifest_dirty {
                            ui.separator();
                            if ui
                                .selectable_label(
                                    false,
                                    RichText::new("Manifest edits pending")
                                        .small()
                                        .color(theme::WARNING),
                                )
                                .clicked()
                            {
                                self.tab = Tab::Manifest;
                            }
                        }
                    });
                });
            });
    }

    fn show_sidebar(&mut self, ctx: &egui::Context) {
        if self.sidebar_collapsed {
            egui::SidePanel::left("project-sidebar-collapsed")
                .resizable(false)
                .exact_width(38.0)
                .show(ctx, |ui| {
                    if ui
                        .add(egui::Button::new("»").min_size(Vec2::new(28.0, 28.0)))
                        .on_hover_text("Show project and search pane")
                        .clicked()
                    {
                        self.sidebar_collapsed = false;
                    }
                });
            return;
        }
        let max_sidebar_width = (ctx.screen_rect().width() * 0.30).max(1.0);
        egui::SidePanel::left("project-sidebar")
            .resizable(true)
            .default_width(310.0)
            .min_width(240.0)
            .max_width(max_sidebar_width.max(240.0))
            .frame(theme::panel())
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(
                        RichText::new("coeus").size(25.0)
                            .strong()
                            .color(Color32::from_rgb(120, 190, 255)),
                    );
                    if ui
                        .small_button("«")
                        .on_hover_text("Collapse project and search pane")
                        .clicked()
                    {
                        self.sidebar_collapsed = true;
                    }
                });
                ui.label(RichText::new("ANDROID ANALYSIS WORKSPACE").size(10.0).color(theme::MUTED));
                ui.add_space(10.0);
                theme::eyebrow(ui, "PROJECT");
                ui.horizontal(|ui| {
                    if ui.add_enabled(!self.busy() && self.bridge.is_some(), theme::primary("Open APK…")).clicked() {
                        self.open_apk_dialog();
                    }
                    if ui.add_enabled(!self.busy() && self.bridge.is_some(), egui::Button::new("Open project…")).clicked() {
                        self.open_project_dialog();
                    }
                });
                ui.collapsing("Paths & output", |ui| {
                    ui.label("APK or project");
                    ui.add(egui::TextEdit::singleline(&mut self.path).min_size(Vec2::new(0.0, 30.0)).margin(Vec2::new(8.0, 6.0))
                        .hint_text("/path/to/app.apk").desired_width(f32::INFINITY));
                    if ui.add_enabled(!self.busy() && !self.path.trim().is_empty(), egui::Button::new("Load path")).clicked() {
                        self.load_selected_path();
                    }
                    if self.info.is_some() {
                        ui.label("Edited APK output");
                        ui.add(egui::TextEdit::singleline(&mut self.output_path).min_size(Vec2::new(0.0, 30.0)).margin(Vec2::new(8.0, 6.0))
                            .hint_text("edited output APK").desired_width(f32::INFINITY));
                    }
                });
                if let Some(error) = &self.startup_error {
                    ui.add_space(8.0);
                    ui.colored_label(Color32::from_rgb(255, 150, 140), error);
                }
                if let Some(info) = &self.info {
                    ui.add_space(8.0);
                    let package = value_string(info, "package");
                    let title = if package.is_empty() {
                        Path::new(&self.path).file_name().and_then(|name| name.to_str()).unwrap_or("Loaded application").to_string()
                    } else { package };
                    ui.add(egui::Label::new(RichText::new(title).strong()).truncate()).on_hover_text(&self.path);
                    ui.label(format!("{} archive files", value_u64(info, "files")));
                    if let Some(dex) = info.get("dex").and_then(Value::as_array) {
                        ui.label(format!("{} DEX file(s)", dex.len()));
                    }
                }
                if self.info.is_some() {
                    let history_title = format!(
                        "Session history ({})",
                        self.session_history.len()
                    );
                    ui.collapsing(history_title, |ui| {
                        if self.session_history.is_empty() {
                            ui.label(
                                RichText::new("No Coeus operations recorded yet.")
                                    .small()
                                    .color(theme::MUTED),
                            );
                        } else {
                            egui::ScrollArea::vertical()
                                .id_salt("session-history")
                                .max_height(150.0)
                                .show(ui, |ui| {
                                    for (index, entry) in self.session_history.iter().enumerate() {
                                        ui.label(
                                            RichText::new(format!("{}  {}", index + 1, entry))
                                                .monospace()
                                                .small(),
                                        );
                                    }
                                });
                        }
                        ui.label(
                            RichText::new(
                                "Save project… embeds the edited APKs, this history, and a replayable coeus_session.py.",
                            )
                            .small()
                            .color(theme::MUTED),
                        );
                    });
                }
                ui.separator();
                ui.add_space(4.0);
                theme::eyebrow(ui, "EXPLORE");
                ui.add_enabled_ui(self.info.is_some(), |ui| {
                    egui::ComboBox::from_id_salt("search-kind")
                        .width(ui.available_width())
                        .selected_text(self.search_kind.label())
                        .show_ui(ui, |ui| {
                            for kind in [SearchKind::Any, SearchKind::Methods, SearchKind::Classes, SearchKind::Fields, SearchKind::Strings] {
                                ui.selectable_value(&mut self.search_kind, kind, kind.label());
                            }
                        });
                    let response = ui.add(egui::TextEdit::singleline(&mut self.search).min_size(Vec2::new(0.0, 30.0)).margin(Vec2::new(8.0, 6.0))
                        .id_salt("workspace-search")
                        .desired_width(f32::INFINITY)
                        .hint_text("Search with a regular expression"));
                    if self.focus_search {
                        response.request_focus();
                        self.focus_search = false;
                    }
                    let invalid = search_validation(&self.search).err();
                    let searching = self.pending.iter().any(|request| request.operation == "search");
                    let submit = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
                    let button = ui.add_enabled(!self.busy() && invalid.is_none(),
                        egui::Button::new(if searching { "Searching…" } else { "Search" })
                            .min_size(Vec2::new(ui.available_width(), 32.0)));
                    if (submit || button.clicked()) && !self.busy() && invalid.is_none() {
                        self.request("search", json!({"op":"search", "kind":self.search_kind.api_name(), "query":self.search}));
                    }
                    if let Some(error) = invalid {
                        ui.label(RichText::new(error).small().color(theme::ERROR));
                    } else {
                        ui.label(RichText::new("Regex · e.g. onCreate|decrypt · .* for all").small().color(theme::MUTED));
                    }
                });
                if self.info.is_none() {
                    ui.label(RichText::new("Open an APK to explore its contents.").small().color(theme::MUTED));
                } else if self.results.is_empty() {
                    if let Some(query) = &self.completed_search {
                        ui.add_space(12.0);
                        ui.label(RichText::new("No matches").strong());
                        ui.label(RichText::new(format!("No results for {query:?}. Try a broader expression or a different type.")).small().color(theme::MUTED));
                    }
                }
                if !self.results.is_empty() {
                    ui.add_space(8.0);
                    ui.label(RichText::new(format!("{} of {} results", self.results.len(), self.result_count)).strong());
                    let mut picked = None;
                    let mut action = None;
                    egui::ScrollArea::vertical()
                        .id_salt("results")
                        .auto_shrink([false, false])
                        .max_height(ui.available_height().max(1.0))
                        .show(ui, |ui| {
                            ui.spacing_mut().item_spacing.y = 4.0;
                            for result in self.results.clone() {
                                let selected = self.selected_id.as_ref() == Some(&result.id);
                                let response = ui.horizontal(|ui| {
                                    let has_note = self.notes.contains_key(&result.note_key);
                                    let width = (ui.available_width() - if has_note { 58.0 } else { 0.0 }).max(80.0);
                                    let display_label = self.display_label(&result.kind, &result.label);
                                    let response = result_row(ui, &result, &display_label, selected, width)
                                        .on_hover_text(if display_label == result.label {
                                            result.label.clone()
                                        } else {
                                            format!("{}\n{}", display_label, result.label)
                                        });
                                    self.show_note_chip(
                                        ui,
                                        &result.kind,
                                        &result.note_key,
                                        &display_label,
                                    );
                                    response
                                }).inner;
                                if response.clicked() {
                                    picked = Some(result.clone());
                                }
                                response.context_menu(|ui| {
                                    if ui.button("Open code").clicked() {
                                        action = Some(SearchAction::Open(result.clone()));
                                        ui.close_menu();
                                    }
                                    if ui.button("Find cross-references").clicked() {
                                        action = Some(SearchAction::Xrefs(result.clone()));
                                        ui.close_menu();
                                    }
                                    if !result.note_key.is_empty()
                                        && ui
                                            .button(if self.notes.contains_key(&result.note_key) {
                                                "Edit note"
                                            } else {
                                                "Add note"
                                            })
                                            .clicked()
                                    {
                                        action = Some(SearchAction::EditNote(result.clone()));
                                        ui.close_menu();
                                    }
                                    if matches!(result.kind.as_str(), "method" | "class")
                                        && ui
                                            .button(if self.alias_for(&result.kind, &result.label).is_some() {
                                                "Edit alias"
                                            } else {
                                                "Assign alias"
                                            })
                                            .clicked()
                                    {
                                        action = Some(SearchAction::EditAlias(result.clone()));
                                        ui.close_menu();
                                    }
                                });
                            }
                        });
                    if let Some(action) = action {
                        match action {
                            SearchAction::Open(result) => {
                                self.selected_id = Some(result.id.clone());
                                self.request(
                                    "describe",
                                    json!({"op":"describe", "id":result.id}),
                                );
                            }
                            SearchAction::Xrefs(result) => {
                                self.selected_id = Some(result.id.clone());
                                self.request(
                                    "xrefs",
                                    json!({"op":"xrefs", "id":result.id}),
                                );
                            }
                            SearchAction::EditNote(result) => self.open_note_editor(&result),
                            SearchAction::EditAlias(result) => self.open_alias_editor(&result),
                        }
                    } else if let Some(result) = picked {
                        self.selected_id = Some(result.id.clone());
                        self.request("describe", json!({"op":"describe", "id":result.id}));
                    }
                }
            });
    }

    fn show_tabs(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("tabs")
            .frame(theme::panel())
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.menu_button("File", |ui| {
                        if ui
                            .add_enabled(!self.busy(), egui::Button::new("Open APK…"))
                            .clicked()
                        {
                            self.open_apk_dialog();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(!self.busy(), egui::Button::new("Open split APKs…"))
                            .clicked()
                        {
                            self.open_split_dialog();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                !self.busy() && !self.path.trim().is_empty(),
                                egui::Button::new("Load selected path"),
                            )
                            .clicked()
                        {
                            self.load_selected_path();
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .add_enabled(!self.busy(), egui::Button::new("Open project…"))
                            .clicked()
                        {
                            self.open_project_dialog();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.info.is_some()
                                    && !self.busy()
                                    && self.path.to_ascii_lowercase().ends_with(".coeus"),
                                egui::Button::new("Save project"),
                            )
                            .clicked()
                        {
                            self.save_project_in_place();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.info.is_some() && !self.busy(),
                                egui::Button::new("Save project as…"),
                            )
                            .clicked()
                        {
                            self.save_project_dialog();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.info.is_some() && !self.busy(),
                                egui::Button::new("Export script…"),
                            )
                            .clicked()
                        {
                            self.export_script_dialog();
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .add_enabled(
                                self.info.is_some() && !self.busy(),
                                egui::Button::new("Write edited APK…"),
                            )
                            .clicked()
                        {
                            self.write_apk_dialog();
                            ui.close_menu();
                        }
                    });
                    ui.separator();
                    let can_go_back = self
                        .navigation_cursor
                        .map(|cursor| cursor > 0)
                        .unwrap_or(false);
                    let can_go_forward = self
                        .navigation_cursor
                        .map(|cursor| cursor + 1 < self.navigation_history.len())
                        .unwrap_or(false);
                    let back = ui.add_enabled(
                        can_go_back,
                        egui::Button::new("").min_size(Vec2::new(28.0, 24.0)),
                    );
                    paint_navigation_arrow(ui, &back, true, can_go_back);
                    if back
                        .on_hover_text(
                            "Go to the previously visited class, method, field, or string",
                        )
                        .clicked()
                    {
                        self.navigate_history(-1);
                    }
                    let forward = ui.add_enabled(
                        can_go_forward,
                        egui::Button::new("").min_size(Vec2::new(28.0, 24.0)),
                    );
                    paint_navigation_arrow(ui, &forward, false, can_go_forward);
                    if forward
                        .on_hover_text("Go to the next item in the navigation history")
                        .clicked()
                    {
                        self.navigate_history(1);
                    }
                    if !self.navigation_history.is_empty() {
                        let position = self.navigation_cursor.map(|cursor| cursor + 1).unwrap_or(0);
                        ui.label(
                            RichText::new(format!("{position}/{}", self.navigation_history.len()))
                                .small()
                                .color(theme::MUTED),
                        );
                    }
                    ui.separator();
                    for (tab, label) in [
                        (Tab::Search, "Search"),
                        (Tab::Notes, "Notes"),
                        (Tab::Code, "Code / Edit"),
                        (Tab::Graph, "Graphs"),
                        (Tab::Debugger, "Debugger"),
                        (Tab::Manifest, "Manifest"),
                        (Tab::Deploy, "Sign / Install"),
                        (Tab::Adb, "ADB"),
                    ] {
                        if ui
                            .selectable_label(self.tab == tab, RichText::new(label).strong())
                            .clicked()
                        {
                            self.tab = tab;
                        }
                    }
                    if self.tab != Tab::Debugger
                        && (self.debug.frame.is_some() || self.debug.waiting)
                        && !self.debug.floating_open
                        && ui
                            .button("Show debugger")
                            .on_hover_text(
                                "Open the debugger window without leaving the current tab",
                            )
                            .clicked()
                    {
                        self.debug.floating_open = true;
                    }
                });
            });
    }

    fn show_search(&mut self, ui: &mut egui::Ui) {
        theme::eyebrow(ui, "EXPLORE / INSPECT");
        ui.heading("Search & cross-references");
        ui.label(
            RichText::new("Follow methods, classes and strings through your application.")
                .color(theme::MUTED),
        );
        if self.selected_result().is_none() {
            theme::empty_state(ui, "Find your starting point", "Search in the sidebar, then select a result to inspect its source. Right-click a result to find cross-references or add a note.");
            ui.add_space(16.0);
            ui.horizontal_wrapped(|ui| {
                for (label, query, kind) in [
                    (
                        "Entry points",
                        "onCreate|onStart|onResume",
                        SearchKind::Methods,
                    ),
                    (
                        "Cryptography",
                        "encrypt|decrypt|Cipher",
                        SearchKind::Methods,
                    ),
                    ("URLs", "https?://", SearchKind::Strings),
                ] {
                    if ui
                        .add_enabled(!self.busy(), egui::Button::new(label))
                        .clicked()
                    {
                        self.search = query.to_string();
                        self.search_kind = kind;
                        self.sidebar_collapsed = false;
                        self.request(
                            "search",
                            json!({"op":"search", "kind":kind.api_name(), "query":query}),
                        );
                    }
                }
            });
        }
        let mut string_replacement = None;
        if let Some(result) = self.selected_result() {
            let display_label = self.display_label(&result.kind, &result.label);
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::Label::new(RichText::new(&display_label).strong().monospace()).truncate(),
                );
                self.show_note_chip(ui, &result.kind, &result.note_key, &display_label);
                if !result.note_key.is_empty()
                    && ui
                        .button(if self.notes.contains_key(&result.note_key) {
                            "Edit note"
                        } else {
                            "Add note"
                        })
                        .clicked()
                {
                    self.open_note_editor(&result);
                }
                if matches!(result.kind.as_str(), "method" | "class")
                    && ui
                        .button(if self.alias_for(&result.kind, &result.label).is_some() {
                            "Edit alias"
                        } else {
                            "Assign alias"
                        })
                        .clicked()
                {
                    self.open_alias_editor(&result);
                }
            });
            ui.horizontal(|ui| {
                if ui.button("Open code").clicked() {
                    self.request("describe", json!({"op":"describe", "id":result.id}));
                }
                if ui.button("Find xrefs").clicked() {
                    self.request("xrefs", json!({"op":"xrefs", "id":result.id}));
                }
            });
            if result.kind == "string" && self.string_editor.id.as_ref() == Some(&result.id) {
                ui.collapsing("String pool editor", |ui| {
                    ui.label(
                        "This replaces the DEX string-pool entry and updates all references to it.",
                    );
                    ui.label(
                        RichText::new(format!("Original: {}", self.string_editor.original))
                            .monospace()
                            .small(),
                    );
                    ui.add(
                        egui::TextEdit::multiline(&mut self.string_editor.replacement)
                            .desired_rows(3)
                            .desired_width(f32::INFINITY),
                    );
                    if ui.button("Apply string-pool replacement").clicked() {
                        string_replacement =
                            Some((result.id.clone(), self.string_editor.replacement.clone()));
                    }
                });
            }
        }
        if let Some((id, value)) = string_replacement {
            self.request(
                "replace_string",
                json!({"op":"replace_string", "id":id, "value":value}),
            );
        }
        if !self.xrefs.is_empty() {
            ui.separator();
            ui.heading(format!("Cross-references ({})", self.xrefs.len()));
            let mut picked = None;
            egui::CollapsingHeader::new("References")
                .default_open(true)
                .show(ui, |ui| {
                    for result in self.xrefs.clone() {
                        let display_label = self.display_label(&result.kind, &result.label);
                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(
                                    false,
                                    RichText::new(&display_label).monospace().color(
                                        if self.notes.contains_key(&result.note_key) {
                                            Color32::from_rgb(255, 220, 125)
                                        } else {
                                            Color32::WHITE
                                        },
                                    ),
                                )
                                .clicked()
                            {
                                picked = Some(result.clone());
                            }
                            self.show_note_chip(ui, &result.kind, &result.note_key, &display_label);
                            if matches!(result.kind.as_str(), "method" | "class")
                                && ui
                                    .small_button(
                                        if self.alias_for(&result.kind, &result.label).is_some() {
                                            "alias"
                                        } else {
                                            "＋ alias"
                                        },
                                    )
                                    .clicked()
                            {
                                self.open_alias_editor(&result);
                            }
                        });
                    }
                });
            if let Some(result) = picked {
                self.selected_id = Some(result.id.clone());
                self.request("describe", json!({"op":"describe", "id":result.id}));
            }
        }
    }

    fn show_notes(&mut self, ui: &mut egui::Ui) {
        theme::eyebrow(ui, "ANNOTATIONS");
        ui.heading("Notes");
        ui.label(
            RichText::new("Review saved notes and jump back to the object or disassembly line where each note was attached.")
                .color(theme::MUTED),
        );
        ui.add_space(12.0);
        if self.notes.is_empty() {
            theme::empty_state(
                ui,
                "No notes yet",
                "Add a note from a search result, cross-reference, or disassembly line and it will appear here.",
            );
            return;
        }
        let mut entries = self
            .notes
            .iter()
            .map(|(key, note)| (key.clone(), note.clone()))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        ui.label(
            RichText::new(format!("{} saved note(s)", entries.len()))
                .small()
                .color(theme::MUTED),
        );
        ui.add_space(6.0);
        for (key, note) in entries {
            let parsed = parse_note_location(&key);
            let (location_label, location_detail) =
                if let Some((kind, label, location)) = parsed.clone() {
                    let display_kind = if kind == "code" {
                        if key.starts_with("code:class:") {
                            "class"
                        } else {
                            "method"
                        }
                    } else {
                        kind.as_str()
                    };
                    let display_label = self.display_label(display_kind, &label);
                    let detail = match location {
                        Some(NoteLocation::Offset(offset)) => {
                            format!("instruction offset 0x{offset:x}")
                        }
                        Some(NoteLocation::Line(line)) => format!("line {line}"),
                        None => "object".to_string(),
                    };
                    (format!("{} · {}", display_kind, display_label), detail)
                } else {
                    (key.clone(), "unresolved note key".to_string())
                };
            egui::Frame::group(ui.style())
                .fill(theme::SURFACE)
                .stroke(Stroke::new(1.0, theme::BORDER))
                .corner_radius(8)
                .inner_margin(10)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&location_label).strong().monospace());
                        ui.label(RichText::new(location_detail).small().color(theme::MUTED));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Edit").clicked() {
                                self.open_note_key_editor(&key);
                            }
                            if ui
                                .add_enabled(
                                    parsed.is_some() && !self.busy(),
                                    egui::Button::new("Go to location"),
                                )
                                .clicked()
                            {
                                self.navigate_to_note(&key);
                            }
                        });
                    });
                    ui.add_space(4.0);
                    ui.add(egui::Label::new(note).wrap());
                });
            ui.add_space(8.0);
        }
    }

    fn show_code(&mut self, ctx: &egui::Context) {
        let has_method = self.code.method_id.is_some();
        let mut code_interaction = None;
        let mut chosen_edit: Option<EditRequest> = None;

        // Keep the edit nodes in a real side panel so they remain attached to
        // the code view while the source itself scrolls. This also lets the
        // panel use the complete height of the central work area.
        if has_method && self.instruction_pane_collapsed {
            egui::SidePanel::left("instruction-node-pane-collapsed")
                .resizable(false)
                .exact_width(36.0)
                .show(ctx, |ui| {
                    if ui
                        .add(egui::Button::new("»").min_size(Vec2::new(28.0, 28.0)))
                        .on_hover_text("Show instruction replacement nodes")
                        .clicked()
                    {
                        self.instruction_pane_collapsed = false;
                    }
                });
        } else if has_method {
            egui::SidePanel::left("instruction-node-pane")
                .resizable(true)
                .default_width(340.0)
                .min_width(200.0)
                .max_width((ctx.available_rect().width() * 0.4).max(200.0))
                .frame(theme::panel())
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Replacement nodes").strong());
                        if ui
                            .small_button("«")
                            .on_hover_text("Collapse instruction replacement nodes")
                            .clicked()
                        {
                            self.instruction_pane_collapsed = true;
                        }
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .id_salt("instruction-controls")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            self.show_instruction_nodes(ui, &mut chosen_edit);
                        });
                });
        }

        egui::CentralPanel::default().frame(theme::workspace()).show(ctx, |ui| {
            theme::eyebrow(ui, "SOURCE / EDIT");
            ui.heading(if self.code.kind == "class" { "Class source" } else { "Smali source" });
            if !self.code.title.is_empty() {
                ui.add(
                    egui::Label::new(
                        RichText::new(&self.code.title)
                            .monospace()
                            .color(Color32::from_rgb(160, 210, 255)),
                    )
                    .wrap(),
                );
            }
            ui.horizontal_wrapped(|ui| {
                if let Some(target) = self.current_annotation_target() {
                    let display_label = self.display_label(&target.kind, &target.label);
                    self.show_note_chip(
                        ui,
                        &target.kind,
                        &target.note_key,
                        &display_label,
                    );
                    if ui
                        .button(if self.notes.contains_key(&target.note_key) {
                            "Edit note"
                        } else {
                            "Add note"
                        })
                        .clicked()
                    {
                        self.open_note_editor(&target);
                    }
                    if matches!(target.kind.as_str(), "method" | "class")
                        && ui
                            .button(if self.alias_for(&target.kind, &target.label).is_some() {
                                "Edit alias"
                            } else {
                                "Assign alias"
                            })
                            .clicked()
                    {
                        self.open_alias_editor(&target);
                    }
                }
                if let Some(method_id) = &self.code.method_id {
                    if ui.button("Call graph").clicked() {
                        self.request(
                            "graph",
                            json!({"op":"graph", "kind":"callgraph", "id":method_id, "ignore":""}),
                        );
                        self.tab = Tab::Graph;
                    }
                    if ui
                        .add_enabled(!self.busy(), egui::Button::new("Emulate"))
                        .on_hover_text("Run this method in the embedded DexVm")
                        .clicked()
                    {
                        self.open_emulation();
                    }
                }
                if ui
                    .add_enabled(has_method, egui::Button::new(if self.instruction_pane_collapsed {
                        "Show nodes"
                    } else {
                        "Hide nodes"
                    }))
                    .clicked()
                {
                    self.instruction_pane_collapsed = !self.instruction_pane_collapsed;
                }
                if ui.button("Supergraph").clicked() && self.info.is_some() {
                    let request = self.supergraph_request();
                    self.request("graph", request);
                    self.tab = Tab::Graph;
                }
            });
            ui.label(
                RichText::new(
                    "Inspection is syntax-highlighted. Select an instruction to see typed method-change nodes.",
                )
                .small()
                .color(theme::MUTED),
            );
            ui.horizontal_wrapped(|ui| {
                ui.label("Find in code");
                let changed = ui
                    .add(
                        egui::TextEdit::singleline(&mut self.code.search_query)
                            .desired_width(280.0)
                            .hint_text("regex, e.g. invoke|decrypt"),
                    )
                    .changed();
                if changed {
                    self.refresh_code_search(true);
                }
                if ui
                    .add_enabled(
                        !self.code.search_matches.is_empty(),
                        egui::Button::new("Previous"),
                    )
                    .clicked()
                {
                    self.move_code_search(-1);
                }
                if ui
                    .add_enabled(
                        !self.code.search_matches.is_empty(),
                        egui::Button::new("Next"),
                    )
                    .clicked()
                {
                    self.move_code_search(1);
                }
                if self.code.search_query.trim().is_empty() {
                    ui.label(RichText::new("Search the current class or method").small().color(theme::MUTED));
                } else if let Some(error) = self.code.search_error.clone() {
                    ui.colored_label(theme::ERROR, format!("Invalid regex: {error}"));
                } else {
                    ui.label(
                        RichText::new(if self.code.search_matches.is_empty() {
                            "No matches".to_string()
                        } else {
                            format!(
                                "{}/{}",
                                self.code.search_index.saturating_add(1),
                                self.code.search_matches.len()
                            )
                        })
                        .small()
                        .color(theme::MUTED),
                    );
                }
            });
            ui.add_space(6.0);

            if has_method {
                ui.horizontal(|ui| {
                    ui.label("Command-click / right-click navigation target:");
                    egui::ComboBox::from_id_salt("code-navigation-kind")
                        .selected_text(self.navigation_kind.label())
                        .show_ui(ui, |ui| {
                            for kind in [
                                NavigationKind::Automatic,
                                NavigationKind::Class,
                                NavigationKind::Method,
                                NavigationKind::Field,
                                NavigationKind::String,
                            ] {
                                ui.selectable_value(&mut self.navigation_kind, kind, kind.label());
                            }
                        });
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("smali (read-only)")
                            .small()
                            .color(theme::MUTED),
                    );
                    if let Some(offset) = self.code.highlighted_offset {
                        ui.label(
                            RichText::new(format!("current execution: @0x{offset:x}"))
                                .small()
                                .strong()
                                .color(theme::WARNING)
                                .monospace(),
                        );
                    }
                });
                let available = ui.available_size();
                ui.allocate_ui_with_layout(
                    available,
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        code_interaction = self.render_code_lines(ui);
                    },
                );
            } else if self.code.kind == "class" && !self.code.lines.is_empty() {
                ui.label(
                    RichText::new("class source (read-only)")
                        .small()
                        .color(theme::MUTED),
                );
                let available = ui.available_size();
                ui.allocate_ui_with_layout(
                    available,
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        code_interaction = self.render_code_lines(ui);
                    },
                );
            } else {
                theme::empty_state(ui, "Select a method or class", "Open a search result to inspect its decoded source. Method instructions can be selected to reveal available edits.");
                if ui.button("Focus search").clicked() {
                    self.sidebar_collapsed = false;
                    self.focus_search = true;
                }
            }
        });

        if let Some(interaction) = code_interaction {
            self.code.selected_offset = Some(interaction.offset);
            self.code.selected_method_id = interaction.method_id.clone();
            match interaction.action {
                Some(CodeAction::Navigate(target)) => {
                    self.selected_id = Some(target.id.clone());
                    self.request("describe", json!({"op":"describe", "id":target.id}));
                }
                Some(CodeAction::Emulate(target)) => {
                    self.open_emulation_target(target.id, target.label.clone(), target.label);
                }
                Some(CodeAction::EmulateWithStaticArguments {
                    target,
                    source_method_id,
                    offset,
                }) => {
                    self.open_static_emulation_target(
                        target.id,
                        target.label.clone(),
                        target.label,
                        source_method_id,
                        offset,
                    );
                }
                Some(CodeAction::Xrefs(target)) => {
                    self.request("xrefs", json!({"op":"xrefs", "id":target.id}));
                }
                Some(CodeAction::EnclosingMethodXrefs) => {
                    if let Some(method_id) = self.code.method_id.clone() {
                        self.request("xrefs", json!({"op":"xrefs", "id":method_id}));
                    }
                }
                Some(CodeAction::ToggleBreakpoint) => {
                    if let Some(method_id) = interaction
                        .method_id
                        .or_else(|| self.code.method_id.clone())
                    {
                        self.request(
                            "debug_breakpoint",
                            json!({"op":"debug_breakpoint", "id":method_id, "offset":interaction.offset}),
                        );
                    }
                }
                Some(CodeAction::EditNote(target)) => self.open_target_note_editor(&target),
                None => {
                    if let Some(method_id) = self.code.method_id.clone() {
                        self.code.edit_form = None;
                        self.request(
                            "edit_options",
                            json!({"op":"edit_options", "id":method_id, "offset":interaction.offset}),
                        );
                    }
                }
            }
        }
        if let Some(option) = chosen_edit {
            let arguments = option
                .arguments
                .into_iter()
                .map(|argument| (argument.name, Value::String(argument.value)))
                .collect::<serde_json::Map<_, _>>();
            self.request(
                "apply_edit",
                json!({"op":"apply_edit", "id":option.id, "arguments":arguments}),
            );
        }
    }

    fn show_instruction_nodes(&mut self, ui: &mut egui::Ui, chosen_edit: &mut Option<EditRequest>) {
        ui.vertical(|ui| {
            theme::eyebrow(ui, "SELECTED INSTRUCTION");
            if let Some(offset) = self.code.selected_offset {
                let selected = self
                    .code
                    .instructions
                    .iter()
                    .find(|instruction| instruction.offset == offset)
                    .cloned();
                if let Some(instruction) = selected {
                    ui.label(
                        RichText::new(format!(
                            "@0x{:x} · {} · {} code units",
                            instruction.offset, instruction.mnemonic, instruction.size
                        ))
                        .strong(),
                    );
                    ui.add(
                        egui::Label::new(RichText::new(&instruction.text).monospace().small())
                            .wrap(),
                    );
                    ui.add_space(6.0);
                    if !self.code.edit_available {
                        ui.label(
                            RichText::new(&self.code.edit_reason)
                                .small()
                                .color(theme::WARNING),
                        );
                    } else {
                        let mut groups: Vec<(String, Vec<EditOption>)> = Vec::new();
                        for option in self.code.edit_options.clone() {
                            let group = if option.group.is_empty() {
                                "Other".to_string()
                            } else {
                                option.group.clone()
                            };
                            if let Some((_, options)) =
                                groups.iter_mut().find(|(name, _)| *name == group)
                            {
                                options.push(option);
                            } else {
                                groups.push((group, vec![option]));
                            }
                        }
                        let mut open_picker: Option<(String, String, SearchKind, String)> = None;
                        egui::ScrollArea::vertical()
                            .id_salt(("instruction-edit-options", offset))
                            .auto_shrink([false, false])
                            .max_height(ui.available_height().max(120.0))
                            .show(ui, |ui| {
                                for (group, options) in groups {
                                    ui.collapsing(
                                        RichText::new(format!(
                                            "{} ({})",
                                            group,
                                            options.len()
                                        ))
                                        .strong(),
                                        |ui| {
                                            for option in options {
                                                ui.push_id(option.id.clone(), |ui| {
                                                    let label = format!(
                                                        "{}  ·  {} · {}w",
                                                        option.label, option.action, option.width
                                                    );
                                                    if ui
                                                        .add(
                                                            egui::Button::new(label)
                                                                .wrap()
                                                                .min_size(Vec2::new(230.0, 28.0)),
                                                        )
                                                        .clicked()
                                                    {
                                                        if option.arguments.is_empty() {
                                                            *chosen_edit = Some(EditRequest {
                                                                id: option.id.clone(),
                                                                arguments: Vec::new(),
                                                            });
                                                        } else {
                                                            self.code.edit_form = Some(option);
                                                        }
                                                    }
                                                });
                                            }
                                        },
                                    );
                                }
                                if let Some(mut form) = self.code.edit_form.clone() {
                                    ui.separator();
                                    ui.label(
                                        RichText::new(format!("Configure {}", form.label))
                                            .strong(),
                                    );
                                    ui.label(
                                        RichText::new(
                                            "Arguments are passed to the typed instruction factory; no raw smali is evaluated.",
                                        )
                                        .small()
                                        .color(theme::MUTED),
                                    );
                                    for argument in &mut form.arguments {
                                        ui.horizontal(|ui| {
                                            ui.label(&argument.label);
                                            let desired_width = if argument.kind == "text" {
                                                260.0
                                            } else {
                                                150.0
                                            };
                                            ui.add(
                                                egui::TextEdit::singleline(&mut argument.value).min_size(Vec2::new(0.0, 30.0)).margin(Vec2::new(8.0, 6.0))
                                                    .desired_width(desired_width),
                                            );
                            if let Some(kind) = argument.picker {
                                if ui.button("Choose…").clicked() {
                                    open_picker = Some((
                                        argument.name.clone(),
                                        argument.label.clone(),
                                        kind,
                                        self.code.edit_dex_name.clone(),
                                    ));
                                }
                                            }
                                        });
                                    }
                                    ui.horizontal(|ui| {
                                        if ui.button("Apply configured edit").clicked() {
                                            *chosen_edit = Some(EditRequest {
                                                id: form.id.clone(),
                                                arguments: form.arguments.clone(),
                                            });
                                            self.code.edit_form = None;
                                        }
                                        if ui.button("Cancel").clicked() {
                                            self.code.edit_form = None;
                                        }
                                    });
                                    if chosen_edit.is_none() && self.code.edit_form.is_some() {
                                        self.code.edit_form = Some(form);
                                    }
                                }
                            });
                        if let Some((argument_name, argument_label, kind, dex_name)) = open_picker {
                            self.edit_picker = Some(EditPicker::new(
                                argument_name,
                                argument_label,
                                kind,
                                dex_name,
                            ));
                        }
                    }
                }
            }
            ui.add_space(10.0);
            ui.label(RichText::new("Shortcuts").strong());
            ui.label("B — set or clear a breakpoint on the selected instruction");
            ui.label("F5 — resume    F10 — single-step");
        });
    }

    fn show_edit_picker(&mut self, ctx: &egui::Context) {
        let Some(mut picker) = self.edit_picker.clone() else {
            return;
        };
        let mut request_search = !picker.searched;
        picker.searched = true;
        let mut close = false;
        let mut chosen = None;
        egui::Window::new(format!("Choose {}", picker.argument_label))
            .id(egui::Id::new("edit-pool-picker"))
            .collapsible(false)
            .resizable(true)
            .default_width(620.0)
            .show(ctx, |ui| {
                ui.label(
                    "Search uses the same Coeus regex finders as the left pane. Select an entry to use its relative DEX index.",
                );
                ui.label(
                    RichText::new(format!("Scoped to {}", picker.dex_name))
                        .small()
                        .color(theme::MUTED),
                );
                ui.horizontal(|ui| {
                    ui.label(picker.kind.label());
                    ui.add(
                        egui::TextEdit::singleline(&mut picker.query).min_size(Vec2::new(0.0, 30.0)).margin(Vec2::new(8.0, 6.0))
                            .hint_text("regex, e.g. decrypt or Lfoo/Bar;"),
                    );
                    if ui.button("Find").clicked() {
                        request_search = true;
                    }
                });
                if self
                    .pending
                    .iter()
                    .any(|pending| pending.operation == "edit_search")
                {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Searching…");
                    });
                }
                ui.label(
                    RichText::new(format!(
                        "{} result(s) — entries without an index are unavailable",
                        picker.result_count
                    ))
                    .small()
                    .color(theme::MUTED),
                );
                egui::ScrollArea::vertical()
                    .id_salt("edit-pool-picker-results")
                    .max_height(420.0)
                    .show(ui, |ui| {
                        for result in picker.results.clone() {
                            let index = result
                                .index
                                .map(|index| format!("#{index}"))
                                .unwrap_or_else(|| "<no index>".to_string());
                            let label = format!(
                                "[{kind}] {index}  {value}",
                                kind = result.kind,
                                value = shorten(&result.label, 88)
                            );
                            if ui
                                .add_enabled(
                                    result.index.is_some(),
                                    egui::Button::new(
                                        RichText::new(label).monospace().size(12.0),
                                    )
                                    .wrap(),
                                )
                                .clicked()
                            {
                                chosen = Some(result);
                            }
                        }
                    });
                if ui.button("Close").clicked() {
                    close = true;
                }
            });

        if let Some(result) = chosen {
            if let Some(form) = self.code.edit_form.as_mut() {
                if let Some(argument) = form
                    .arguments
                    .iter_mut()
                    .find(|argument| argument.name == picker.argument_name)
                {
                    if let Some(index) = result.index {
                        argument.value = index.to_string();
                        self.status = format!(
                            "Selected {} at relative DEX index {}",
                            shorten(&result.label, 72),
                            index
                        );
                    }
                }
            }
            self.edit_picker = None;
        } else if close {
            self.edit_picker = None;
        } else {
            let query = picker.query.clone();
            let kind = picker.kind.api_name();
            self.edit_picker = Some(picker);
            if request_search {
                self.request(
                    "edit_search",
                    json!({"op":"edit_search", "kind":kind, "query":query, "dex":self.edit_picker.as_ref().map(|picker| picker.dex_name.clone()).unwrap_or_default()}),
                );
            }
        }
    }

    fn render_code_lines(&mut self, ui: &mut egui::Ui) -> Option<CodeInteraction> {
        let lines = self.code.lines.clone();
        let breakpoints = self.code.breakpoints.clone();
        let selected = self.code.selected_offset;
        let highlighted = self.code.highlighted_offset;
        let should_scroll = self.code.highlight_scroll_pending;
        let annotated_line = self.code.annotated_line;
        let should_scroll_annotation = self.code.annotated_line_scroll_pending;
        let search_matches = self.code.search_matches.clone();
        let search_index = self.code.search_index;
        let should_scroll_search = self.code.search_scroll_pending;
        let can_change_breakpoint =
            self.debug.connected && !self.busy() && !self.debug_breakpoint_pending();
        let mut interaction = None;
        let mut highlighted_visible = false;
        let mut annotated_visible = false;
        let mut search_visible = false;
        egui::Frame::new()
            .fill(theme::BACKGROUND)
            .stroke(Stroke::new(1.0, theme::BORDER))
            .corner_radius(8)
            .inner_margin(8)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.spacing_mut().interact_size.y = 20.0;
                ui.spacing_mut().button_padding = Vec2::new(4.0, 2.0);
                egui::ScrollArea::both()
                    .id_salt("smali-code")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.vertical(|ui| {
                            for (index, line) in lines.iter().enumerate() {
                                let disassembly_alias = self.disassembly_alias(line);
                                let displayed_line = disassembly_alias
                                    .as_ref()
                                    .map(|alias| alias.line.as_str())
                                    .unwrap_or(line.as_str());
                                let alias_range =
                                    disassembly_alias.as_ref().map(|alias| alias.range);
                                let alias_hover = disassembly_alias
                                    .as_ref()
                                    .map(|alias| format!("Alias for {}", alias.canonical));
                                let offset = parse_code_offset(line);
                                let line_method_id = self
                                    .code
                                    .line_method_ids
                                    .get(index)
                                    .cloned()
                                    .flatten()
                                    .or_else(|| self.code.method_id.clone());
                                let line_method_key = self
                                    .code
                                    .line_method_keys
                                    .get(index)
                                    .cloned()
                                    .flatten()
                                    .or_else(|| self.code.method_key.clone())
                                    .or_else(|| line_method_id.clone());
                                let is_selected = offset.is_some() && offset == selected;
                                let is_highlighted = offset.is_some() && offset == highlighted;
                                let is_annotated = annotated_line == Some(index);
                                let is_search_match = search_matches.contains(&index);
                                let is_current_search_match =
                                    search_matches.get(search_index).copied() == Some(index);
                                let line_note_key = self.code_line_note_key(index, line);
                                let line_note_label =
                                    format!("{} · line {}", self.code.title, index + 1);
                                let has_line_note = self.notes.contains_key(&line_note_key);
                                let can_toggle_breakpoint = can_change_breakpoint
                                    && offset.is_some()
                                    && line_method_id.is_some();
                                let is_breakpoint = match (offset, line_method_key.as_ref()) {
                                    (Some(offset), Some(method_key)) => {
                                        breakpoints.contains(&(method_key.clone(), offset))
                                    }
                                    _ => false,
                                };
                                let fill = if is_highlighted {
                                    Color32::from_rgb(75, 65, 30)
                                } else if is_annotated {
                                    Color32::from_rgb(70, 55, 30)
                                } else if is_current_search_match {
                                    Color32::from_rgb(52, 70, 42)
                                } else if is_search_match {
                                    Color32::from_rgb(36, 52, 38)
                                } else if is_selected {
                                    Color32::from_rgb(30, 58, 82)
                                } else {
                                    Color32::TRANSPARENT
                                };
                                let line_response = egui::Frame::NONE
                                    .fill(fill)
                                    .stroke(if is_highlighted {
                                        Stroke::new(1.0, theme::WARNING)
                                    } else if is_annotated {
                                        Stroke::new(1.0, theme::WARNING)
                                    } else if is_current_search_match {
                                        Stroke::new(1.0, theme::SUCCESS)
                                    } else {
                                        Stroke::NONE
                                    })
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.add_sized(
                                                [34.0, 20.0],
                                                egui::Label::new(
                                                    RichText::new(format!("{}", index + 1))
                                                        .small()
                                                        .color(if is_highlighted {
                                                            theme::WARNING
                                                        } else {
                                                            theme::MUTED
                                                        }),
                                                ),
                                            );
                                            if let Some(offset) = offset {
                                                let marker_response = ui.add_enabled(
                                                    can_toggle_breakpoint,
                                                    egui::Button::new("")
                                                        .frame(false)
                                                        .min_size(Vec2::new(22.0, 20.0)),
                                                );
                                                let marker_color = if is_breakpoint {
                                                    theme::ERROR
                                                } else {
                                                    theme::MUTED
                                                };
                                                if is_breakpoint {
                                                    ui.painter().circle_filled(
                                                        marker_response.rect.center(),
                                                        4.0,
                                                        marker_color,
                                                    );
                                                } else {
                                                    ui.painter().circle_stroke(
                                                        marker_response.rect.center(),
                                                        4.0,
                                                        Stroke::new(1.0, marker_color),
                                                    );
                                                }
                                                marker_response.widget_info(|| {
                                                    egui::WidgetInfo::labeled(
                                                        egui::WidgetType::Button,
                                                        can_toggle_breakpoint,
                                                        if is_breakpoint {
                                                            "Clear breakpoint"
                                                        } else {
                                                            "Set breakpoint"
                                                        },
                                                    )
                                                });
                                                if marker_response
                                            .on_hover_text(if can_toggle_breakpoint {
                                                if is_breakpoint {
                                                    "Clear breakpoint"
                                                } else {
                                                    "Set breakpoint"
                                                }
                                            } else if !self.debug.connected {
                                                "Connect the debugger before changing breakpoints"
                                            } else {
                                                "This line is not associated with a method"
                                            })
                                            .clicked()
                                        {
                                            interaction = Some(CodeInteraction {
                                                offset,
                                                method_id: line_method_id.clone(),
                                                action: Some(CodeAction::ToggleBreakpoint),
                                            });
                                        }
                                                let mut response = ui.add(
                                                    egui::Label::new(highlight_smali_with_alias(
                                                        displayed_line,
                                                        alias_range,
                                                    ))
                                                    .sense(Sense::click()),
                                                );
                                                if let Some(hover) = alias_hover.clone() {
                                                    response = response.on_hover_text(hover);
                                                }
                                                if response.clicked() {
                                                    let command_click =
                                                        ui.input(|input| input.modifiers.command);
                                                    let action = if command_click {
                                                        self.preferred_navigation_target(offset)
                                                            .map(CodeAction::Navigate)
                                                    } else {
                                                        None
                                                    };
                                                    interaction = Some(CodeInteraction {
                                                        offset,
                                                        method_id: line_method_id.clone(),
                                                        action,
                                                    });
                                                }
                                                if has_line_note {
                                                    self.show_note_chip(
                                                        ui,
                                                        "code line",
                                                        &line_note_key,
                                                        &line_note_label,
                                                    );
                                                } else if ui
                                                    .small_button("＋ note")
                                                    .on_hover_text("Add a note to this line")
                                                    .clicked()
                                                {
                                                    self.open_code_line_note_editor(index, line);
                                                }
                                                let targets = self
                                                    .code
                                                    .instructions
                                                    .iter()
                                                    .find(|instruction| {
                                                        instruction.offset == offset
                                                    })
                                                    .map(|instruction| instruction.targets.clone())
                                                    .unwrap_or_default();
                                                let enclosing_method_target = line_method_id
                                                    .clone()
                                                    .map(|id| NavigationTarget {
                                                        id,
                                                        kind: "method".to_string(),
                                                        label: line_method_key
                                                            .clone()
                                                            .unwrap_or_else(|| line.clone()),
                                                        note_key: String::new(),
                                                    });
                                                response.context_menu(|ui| {
                                                    if ui
                                                        .button(if has_line_note {
                                                            "Edit note for this line"
                                                        } else {
                                                            "Add note for this line"
                                                        })
                                                        .clicked()
                                                    {
                                                        self.open_code_line_note_editor(
                                                            index, line,
                                                        );
                                                        ui.close_menu();
                                                    }
                                                    if let Some(target) =
                                                        enclosing_method_target.clone()
                                                    {
                                                        if ui
                                                            .button("Open method disassembly")
                                                            .clicked()
                                                        {
                                                            interaction = Some(CodeInteraction {
                                                                offset,
                                                                method_id: Some(target.id.clone()),
                                                                action: Some(CodeAction::Navigate(
                                                                    target.clone(),
                                                                )),
                                                            });
                                                            ui.close_menu();
                                                        }
                                                        if ui
                                                            .button("Emulate method")
                                                            .clicked()
                                                        {
                                                            interaction = Some(CodeInteraction {
                                                                offset,
                                                                method_id: Some(target.id.clone()),
                                                                action: Some(CodeAction::Emulate(
                                                                    target.clone(),
                                                                )),
                                                            });
                                                            ui.close_menu();
                                                        }
                                                        if ui
                                                            .button("Emulate with static argument guesses")
                                                            .clicked()
                                                        {
                                                            interaction = Some(CodeInteraction {
                                                                offset,
                                                                method_id: Some(target.id.clone()),
                                                                action: Some(
                                                                    CodeAction::EmulateWithStaticArguments {
                                                                        target,
                                                                        source_method_id: None,
                                                                        offset: None,
                                                                    },
                                                                ),
                                                            });
                                                            ui.close_menu();
                                                        }
                                                    }
                                                    ui.separator();
                                                    if ui
                                                        .button("Find xrefs for enclosing method")
                                                        .clicked()
                                                    {
                                                        interaction = Some(CodeInteraction {
                                                            offset,
                                                            method_id: line_method_id.clone(),
                                                            action: Some(
                                                                CodeAction::EnclosingMethodXrefs,
                                                            ),
                                                        });
                                                        ui.close_menu();
                                                    }
                                                    if !targets.is_empty() {
                                                        ui.separator();
                                                        ui.label("Navigate to");
                                                        for target in &targets {
                                                            let display_label = self.display_label(
                                                                &target.kind,
                                                                &target.label,
                                                            );
                                                            if ui
                                                                .button(format!(
                                                                    "{}: {}",
                                                                    target.kind,
                                                                    shorten(&display_label, 46)
                                                                ))
                                                                .clicked()
                                                            {
                                                                interaction =
                                                                    Some(CodeInteraction {
                                                                        offset,
                                                                        method_id: line_method_id
                                                                            .clone(),
                                                                        action: Some(
                                                                            CodeAction::Navigate(
                                                                                target.clone(),
                                                                            ),
                                                                        ),
                                                                    });
                                                                ui.close_menu();
                                                            }
                                                            if target.kind == "method" {
                                                                if ui
                                                                    .button(format!(
                                                                        "Open method: {}",
                                                                        shorten(&display_label, 42)
                                                                    ))
                                                                    .clicked()
                                                                {
                                                                    interaction =
                                                                        Some(CodeInteraction {
                                                                            offset,
                                                                            method_id: line_method_id
                                                                                .clone(),
                                                                            action: Some(
                                                                                CodeAction::Navigate(
                                                                                    target.clone(),
                                                                                ),
                                                                            ),
                                                                        });
                                                                    ui.close_menu();
                                                                }
                                                                if ui
                                                                    .button(format!(
                                                                        "Emulate method: {}",
                                                                        shorten(&display_label, 38)
                                                                    ))
                                                                    .clicked()
                                                                {
                                                                    interaction =
                                                                        Some(CodeInteraction {
                                                                            offset,
                                                                            method_id: line_method_id
                                                                                .clone(),
                                                                            action: Some(
                                                                                CodeAction::Emulate(
                                                                                    target.clone(),
                                                                                ),
                                                                            ),
                                                                        });
                                                                    ui.close_menu();
                                                                }
                                                                if ui
                                                                    .button(format!(
                                                                        "Guess args and emulate: {}",
                                                                        shorten(&display_label, 32)
                                                                    ))
                                                                    .clicked()
                                                                {
                                                                    interaction =
                                                                        Some(CodeInteraction {
                                                                            offset,
                                                                            method_id: line_method_id
                                                                                .clone(),
                                                                            action: Some(
                                                                                CodeAction::EmulateWithStaticArguments {
                                                                                    target: target.clone(),
                                                                                    source_method_id: line_method_id
                                                                                        .clone(),
                                                                                    offset: Some(offset),
                                                                                },
                                                                            ),
                                                                        });
                                                                    ui.close_menu();
                                                                }
                                                            }
                                                        }
                                                        ui.separator();
                                                        ui.label("Find xrefs to");
                                                        for target in &targets {
                                                            let display_label = self.display_label(
                                                                &target.kind,
                                                                &target.label,
                                                            );
                                                            if ui
                                                                .button(format!(
                                                                    "{} xrefs: {}",
                                                                    target.kind,
                                                                    shorten(&display_label, 38)
                                                                ))
                                                                .clicked()
                                                            {
                                                                interaction =
                                                                    Some(CodeInteraction {
                                                                        offset,
                                                                        method_id: line_method_id
                                                                            .clone(),
                                                                        action: Some(
                                                                            CodeAction::Xrefs(
                                                                                target.clone(),
                                                                            ),
                                                                        ),
                                                                    });
                                                                ui.close_menu();
                                                            }
                                                        }
                                                        for target in &targets {
                                                            let display_label = self.display_label(
                                                                &target.kind,
                                                                &target.label,
                                                            );
                                                            if !target.note_key.is_empty()
                                                                && ui
                                                                    .button(format!(
                                                                        "{} note for {}",
                                                                        if self.notes.contains_key(
                                                                            &target.note_key
                                                                        ) {
                                                                            "Edit"
                                                                        } else {
                                                                            "Add"
                                                                        },
                                                                        shorten(&display_label, 38)
                                                                    ))
                                                                    .clicked()
                                                            {
                                                                interaction =
                                                                    Some(CodeInteraction {
                                                                        offset,
                                                                        method_id: line_method_id
                                                                            .clone(),
                                                                        action: Some(
                                                                            CodeAction::EditNote(
                                                                                target.clone(),
                                                                            ),
                                                                        ),
                                                                    });
                                                                ui.close_menu();
                                                            }
                                                            if matches!(
                                                                target.kind.as_str(),
                                                                "method" | "class"
                                                            ) && ui
                                                                .button(
                                                                    if self
                                                                        .alias_for(
                                                                            &target.kind,
                                                                            &target.label,
                                                                        )
                                                                        .is_some()
                                                                    {
                                                                        format!(
                                                                            "Edit alias for {}",
                                                                            shorten(
                                                                                &display_label,
                                                                                32
                                                                            )
                                                                        )
                                                                    } else {
                                                                        format!(
                                                                            "Assign alias to {}",
                                                                            shorten(
                                                                                &display_label,
                                                                                30
                                                                            )
                                                                        )
                                                                    },
                                                                )
                                                                .clicked()
                                                            {
                                                                self.open_alias_editor_target(
                                                                    target,
                                                                );
                                                                ui.close_menu();
                                                            }
                                                        }
                                                    }
                                                });
                                                for target in &targets {
                                                    let display_label = self
                                                        .display_label(&target.kind, &target.label);
                                                    self.show_note_chip(
                                                        ui,
                                                        &target.kind,
                                                        &target.note_key,
                                                        &display_label,
                                                    );
                                                }
                                            } else {
                                                let response = ui.add(egui::Label::new(
                                                    highlight_smali_with_alias(
                                                        displayed_line,
                                                        alias_range,
                                                    ),
                                                ));
                                                if let Some(hover) = alias_hover {
                                                    response.on_hover_text(hover);
                                                }
                                            }
                                        });
                                    });
                                if is_highlighted && should_scroll {
                                    ui.scroll_to_rect(
                                        line_response.response.rect,
                                        Some(egui::Align::Center),
                                    );
                                    highlighted_visible = true;
                                }
                                if is_annotated && should_scroll_annotation {
                                    ui.scroll_to_rect(
                                        line_response.response.rect,
                                        Some(egui::Align::Center),
                                    );
                                    annotated_visible = true;
                                }
                                if is_current_search_match && should_scroll_search {
                                    ui.scroll_to_rect(
                                        line_response.response.rect,
                                        Some(egui::Align::Center),
                                    );
                                    search_visible = true;
                                }
                            }
                        });
                    });
            });
        if should_scroll && highlighted_visible {
            self.code.highlight_scroll_pending = false;
        }
        if should_scroll_annotation && annotated_visible {
            self.code.annotated_line_scroll_pending = false;
        }
        if should_scroll_search && search_visible {
            self.code.search_scroll_pending = false;
        }
        interaction
    }

    fn show_graph(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.heading("Graph explorer");
            if ui
                .add_enabled(
                    self.code.method_id.is_some() && !self.busy(),
                    egui::Button::new("Method call graph"),
                )
                .clicked()
            {
                if let Some(method_id) = self.code.method_id.clone() {
                    self.request(
                        "graph",
                        json!({"op":"graph", "kind":"callgraph", "id":method_id, "ignore":""}),
                    );
                }
            }
            if ui
                .add_enabled(
                    self.info.is_some() && !self.busy(),
                    egui::Button::new("Build supergraph"),
                )
                .clicked()
            {
                let request = self.supergraph_request();
                self.request("graph", request);
            }
            if ui
                .add_enabled(
                    !self.graph.nodes.is_empty(),
                    egui::Button::new("Fit to view"),
                )
                .clicked()
            {
                self.graph.fit_to_view = true;
            }
            let zoom_response =
                ui.add(egui::Slider::new(&mut self.graph.zoom, 0.03..=3.0).text("zoom"));
            if zoom_response.changed() {
                self.graph.fit_to_view = false;
            }
        });
        let build_options_before = (
            self.graph.exclude_android_framework,
            self.graph.exclude_language_runtime,
            self.graph.exclude_common_libraries,
            self.graph.additional_class_filters.clone(),
            self.graph.discover_dynamic_arguments,
            self.graph.dynamic_argument_classes.clone(),
        );
        ui.collapsing("Supergraph build options", |ui| {
            ui.label(
                RichText::new(
                    "These options are used the next time you build the supergraph. Class filters match DEX descriptors or package prefixes.",
                )
                .small()
                .color(theme::MUTED),
            );
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(
                    &mut self.graph.exclude_android_framework,
                    "Filter Android UI/framework classes",
                )
                .on_hover_text(
                    "Excludes common android.app/content/graphics/os/text/util/view/widget packages; java.security and javax.crypto remain available.",
                );
                ui.checkbox(
                    &mut self.graph.exclude_language_runtime,
                    "Filter language/runtime internals",
                )
                .on_hover_text("Filters Kotlin, desugared Java, AndroidX, and JDK implementation classes.");
                ui.checkbox(
                    &mut self.graph.exclude_common_libraries,
                    "Filter common bundled libraries",
                )
                .on_hover_text("Filters generated/support-heavy protobuf, Google, OkHttp, Moshi, Okio, and Bouncy Castle packages.");
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Additional class filters");
                ui.add(
                    egui::TextEdit::singleline(&mut self.graph.additional_class_filters)
                        .desired_width(360.0)
                        .hint_text("comma-separated prefixes, e.g. Lcom/example/generated"),
                );
            });
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(
                    &mut self.graph.discover_dynamic_arguments,
                    "Discover dynamic arguments and returns",
                )
                .on_hover_text(
                    "Emulates included methods and class initializers to add runtime-discovered argument and return values; this can make graph building substantially slower.",
                );
                if self.graph.discover_dynamic_arguments {
                    ui.label("Classes");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.graph.dynamic_argument_classes)
                            .desired_width(300.0)
                            .hint_text("blank = all included classes; otherwise exact descriptors"),
                    );
                }
            });
        });
        let build_options_after = (
            self.graph.exclude_android_framework,
            self.graph.exclude_language_runtime,
            self.graph.exclude_common_libraries,
            self.graph.additional_class_filters.clone(),
            self.graph.discover_dynamic_arguments,
            self.graph.dynamic_argument_classes.clone(),
        );
        if build_options_before != build_options_after {
            self.session_dirty = true;
        }
        if self.graph.nodes.is_empty() {
            theme::empty_state(ui, "See how the pieces connect", "Build a supergraph to explore the application, or open a method from search and build its call graph.");
            return;
        }
        let mut filters = self.graph.node_filters.clone();
        let mut filters_changed = false;
        ui.collapsing("Node filters", |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("Show all").clicked() {
                    filters = all_graph_node_kinds().into_iter().collect();
                    filters_changed = true;
                }
                if ui.button("Hide all").clicked() {
                    filters.clear();
                    filters_changed = true;
                }
                ui.label("Choose which node types are visible");
            });
            ui.horizontal_wrapped(|ui| {
                for kind in all_graph_node_kinds() {
                    let mut enabled = filters.contains(&kind);
                    if ui.checkbox(&mut enabled, kind.label()).changed() {
                        if enabled {
                            filters.insert(kind);
                        } else {
                            filters.remove(&kind);
                        }
                        filters_changed = true;
                    }
                }
            });
        });
        if filters_changed {
            self.graph.node_filters = filters;
            self.graph.node_search_cache_query.clear();
            self.graph.node_search_results.clear();
            self.rebuild_graph_layout();
            self.graph.fit_to_view = true;
            self.session_dirty = true;
        }
        if self.graph.dot.is_empty() {
            ui.add_space(20.0);
            ui.centered_and_justified(|ui| {
                ui.label("Build a callgraph from Code or load the complete supergraph.")
            });
            return;
        }
        let search_response = ui
            .add(
                egui::TextEdit::singleline(&mut self.graph.node_search)
                    .desired_width(ui.available_width().min(520.0))
                    .hint_text("Find a node by class, method, field, string, or descriptor"),
            )
            .on_hover_text("Search visible graph nodes; press Enter to center the first match");
        let search_query = self.graph.node_search.trim().to_string();
        if search_query.is_empty() {
            self.graph.node_search_cache_query.clear();
            self.graph.node_search_results.clear();
        } else if self.graph.node_search_cache_query != search_query {
            self.graph.node_search_results =
                graph_search_matches(&self.graph.nodes, &self.graph.node_filters, &search_query);
            self.graph.node_search_cache_query = search_query.clone();
        }
        let search_matches = &self.graph.node_search_results;
        let activate_first =
            search_response.has_focus() && ui.input(|input| input.key_pressed(Key::Enter));
        let mut focus_node = activate_first
            .then(|| search_matches.first().map(|(id, _, _)| *id))
            .flatten();
        if !search_matches.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{} matching visible node{}",
                        search_matches.len(),
                        if search_matches.len() == 1 { "" } else { "s" }
                    ))
                    .small()
                    .color(theme::MUTED),
                );
                if ui.button("Center first").clicked() {
                    focus_node = search_matches.first().map(|(id, _, _)| *id);
                }
            });
            egui::ScrollArea::vertical()
                .id_salt("graph-node-search-results")
                .max_height(128.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for (id, display, label) in search_matches.iter().take(100) {
                        let response = ui
                            .selectable_label(false, format!("#{id}  {}", shorten(display, 96)))
                            .on_hover_text(label);
                        if response.clicked() {
                            focus_node = Some(*id);
                        }
                    }
                });
        } else if !search_query.is_empty() {
            ui.label(
                RichText::new("No visible nodes match that search")
                    .small()
                    .color(theme::WARNING),
            );
        }
        if let Some(node_id) = focus_node {
            self.graph.focus_node = Some(node_id);
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} nodes · {} edges · off-screen nodes are rendered as you scroll",
                    self.graph.nodes.len(),
                    self.graph.edges.len()
                ))
                .small()
                .color(theme::TEXT),
            );
            ui.separator();
            for edge_kind in all_graph_edge_kinds() {
                let (color, width) = graph_edge_style(edge_kind);
                let (swatch, painter) = ui.allocate_painter(
                    Vec2::new(24.0, ui.spacing().interact_size.y),
                    Sense::hover(),
                );
                let line_rect = swatch.rect.shrink2(Vec2::new(2.0, 0.0));
                painter.line_segment(
                    [line_rect.left_center(), line_rect.right_center()],
                    Stroke::new(width, color),
                );
                ui.label(edge_kind.label());
            }
            ui.separator();
            ui.label(
                RichText::new("Cmd + scroll to zoom · click or drag the minimap to navigate")
                    .small()
                    .color(theme::MUTED),
            );
        });
        let graph_width = ui.available_width().max(1.0);
        let graph_height = (ui.available_height() - 32.0).max(240.0);
        egui::Resize::default()
            .id_salt("graph-pane-full-height")
            .default_width(graph_width)
            .default_height(graph_height)
            .max_width(graph_width)
            .min_height(240.0)
            .max_height(graph_height)
            .resizable([false, true])
            .show(ui, |ui| self.render_graph_canvas(ui));
        ui.collapsing("Raw DOT", |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut self.graph.dot)
                    .font(FontId::monospace(11.0))
                    .desired_rows(8),
            );
        });
    }

    fn render_graph_canvas(&mut self, ui: &mut egui::Ui) {
        let viewport = ui.available_size();
        let base_node_size = GRAPH_NODE_SIZE;
        let min = self.graph.layout_min;
        let max = self.graph.layout_max;
        let logical_size = (max - min).max(Vec2::new(1.0, 1.0));
        let fit_zoom = ((viewport.x - 96.0) / logical_size.x)
            .min((viewport.y - 96.0) / logical_size.y)
            .clamp(0.03, 1.5);
        let mut zoom = if self.graph.fit_to_view {
            fit_zoom
        } else {
            self.graph.zoom
        };
        let previous_zoom = zoom;
        let canvas_view = Rect::from_min_size(ui.cursor().min, viewport).intersect(ui.clip_rect());
        let cmd_zoom_delta = ui
            .ctx()
            .input_mut(|input| graph_scroll_zoom(input, canvas_view));
        if (cmd_zoom_delta - 1.0).abs() > f32::EPSILON {
            zoom = (zoom * cmd_zoom_delta).clamp(0.03, 3.0);
            self.graph.fit_to_view = false;
        }
        self.graph.zoom = zoom;
        let canvas = Vec2::new(
            (logical_size.x * zoom + 80.0).max(viewport.x),
            (logical_size.y * zoom + 80.0).max(viewport.y).max(320.0),
        );
        let graph_layout = &self.graph.layout;
        let graph_layout_index = &self.graph.layout_index;
        let graph_node_index = &self.graph.node_index;
        let graph_nodes = &self.graph.nodes;
        let graph_node_filters = &self.graph.node_filters;
        let graph_layout_edge_index = &self.graph.layout_edge_index;
        let graph_layout_long_edges = &self.graph.layout_long_edges;
        let graph_minimap_nodes = &self.graph.minimap_nodes;
        let graph_minimap_edges = &self.graph.minimap_edges;
        let mut clicked_node = None;
        let focus_node = self.graph.focus_node.take();
        let last_edge_click = self.graph.last_edge_click;
        let mut next_edge_click = None;
        let mut cluster_zoom_requested = false;
        let mut minimap_target = None;
        egui::Frame::new()
            .fill(theme::BACKGROUND)
            .stroke(Stroke::new(1.0, theme::BORDER))
            .corner_radius(8)
            .inner_margin(8)
            .show(ui, |ui| {
                let mut scroll = egui::ScrollArea::both()
                    .id_salt("graph-canvas")
                    .auto_shrink([false, false]);
                if zoom != previous_zoom {
                    let state = egui::scroll_area::State::load(
                        ui.ctx(),
                        ui.make_persistent_id("graph-canvas"),
                    )
                    .unwrap_or_default();
                    let anchor = ui
                        .input(|input| input.pointer.hover_pos())
                        .unwrap_or(ui.clip_rect().center())
                        - ui.cursor().min;
                    let offset = (state.offset + anchor - Vec2::splat(40.0))
                        * (zoom / previous_zoom)
                        + Vec2::splat(40.0)
                        - anchor;
                    scroll = scroll.scroll_offset(offset.max(Vec2::ZERO));
                }
                let mut output = scroll.show(ui, |ui| {
                    let (rect, _) = ui.allocate_exact_size(canvas, Sense::hover());
                    let painter = ui.painter_at(rect);
                    let viewport_rect = ui.clip_rect();
                    let minimap_size = Vec2::new(
                        228.0_f32.min((viewport_rect.width() - 16.0).max(32.0)),
                        158.0_f32.min((viewport_rect.height() - 16.0).max(32.0)),
                    );
                    let minimap_rect = Rect::from_min_size(
                        viewport_rect.max - minimap_size - Vec2::splat(8.0),
                        minimap_size,
                    );
                    let pointer_over_minimap = ui.input(|input| {
                        input
                            .pointer
                            .hover_pos()
                            .is_some_and(|point| minimap_rect.contains(point))
                    });
                    let track_edge_click =
                        !pointer_over_minimap && ui.input(|input| input.pointer.primary_clicked());
                    let mut edge_hit_segments = Vec::new();
                    let origin = rect.left_top() + Vec2::new(40.0, 40.0) - min * zoom;
                    let clip_rect = ui.clip_rect().expand(24.0);
                    let node_rect = |id: usize| {
                        graph_layout.get(&id).map(|position| {
                            Rect::from_center_size(origin + *position * zoom, base_node_size * zoom)
                        })
                    };
                    let logical_clip_min =
                        (clip_rect.min - rect.left_top() - Vec2::splat(40.0)) / zoom + min;
                    let logical_clip_max =
                        (clip_rect.max - rect.left_top() - Vec2::splat(40.0)) / zoom + min;
                    let query_min = logical_clip_min - base_node_size / 2.0;
                    let query_max = logical_clip_max + base_node_size / 2.0;
                    let min_cell = (
                        (query_min.x / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
                        (query_min.y / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
                    );
                    let max_cell = (
                        (query_max.x / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
                        (query_max.y / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
                    );
                    let overview_mode = zoom < 0.35;
                    let visible_nodes = if overview_mode {
                        graph_minimap_nodes
                            .iter()
                            .filter_map(|(id, _, _)| {
                                let index = graph_node_index.get(id)?;
                                let (_, label) = graph_nodes.get(*index)?;
                                let node_rect = node_rect(*id)?;
                                (node_rect.intersects(clip_rect)
                                    && graph_node_filters.contains(&graph_node_kind(label)))
                                .then_some((*id, label.as_str()))
                            })
                            .collect::<Vec<_>>()
                    } else {
                        let candidate_ids = (min_cell.1..=max_cell.1)
                            .flat_map(|cell_y| {
                                (min_cell.0..=max_cell.0).flat_map(move |cell_x| {
                                    graph_layout_index
                                        .get(&(cell_x, cell_y))
                                        .into_iter()
                                        .flatten()
                                        .copied()
                                })
                            })
                            .collect::<Vec<_>>();
                        candidate_ids
                            .into_iter()
                            // A dense supergraph can contain far more nodes than can
                            // be meaningfully interacted with at this zoom level.
                            // Keep the frame bounded while the minimap still exposes
                            // the complete layout.
                            .take(MAX_RENDERED_GRAPH_NODES)
                            .filter_map(|id| {
                                let index = graph_node_index.get(&id)?;
                                let (_, label) = graph_nodes.get(*index)?;
                                graph_node_filters
                                    .contains(&graph_node_kind(label))
                                    .then_some((id, label.as_str()))
                            })
                            .collect::<Vec<_>>()
                    };
                    let mut node_rects = HashMap::new();
                    for (id, _) in &visible_nodes {
                        let Some(rect) = node_rect(*id) else {
                            continue;
                        };
                        if rect.intersects(clip_rect) {
                            node_rects.insert(*id, rect);
                        }
                    }
                    let cluster_size = if zoom < 0.72 {
                        Some((34.0 - zoom * 10.0).max(24.0))
                    } else {
                        None
                    };
                    let mut grouped_nodes = HashMap::<(i32, i32), Vec<usize>>::new();
                    for (id, node_rect) in &node_rects {
                        let key = cluster_size
                            .map(|size| {
                                (
                                    (node_rect.center().x / size).floor() as i32,
                                    (node_rect.center().y / size).floor() as i32,
                                )
                            })
                            .unwrap_or((*id as i32, 0));
                        grouped_nodes.entry(key).or_default().push(*id);
                    }
                    let mut render_nodes = Vec::with_capacity(grouped_nodes.len());
                    let mut node_group_rects = HashMap::new();
                    for ids in grouped_nodes.into_values() {
                        let center = ids
                            .iter()
                            .filter_map(|id| node_rects.get(id))
                            .map(Rect::center)
                            .fold(Vec2::ZERO, |sum, center| sum + center.to_vec2())
                            / ids.len().max(1) as f32;
                        let first_id = ids[0];
                        let first_label = label_for_node(first_id, graph_node_index, graph_nodes)
                            .unwrap_or_default();
                        let first_kind = graph_node_kind(first_label);
                        let same_kind = ids.iter().all(|id| {
                            label_for_node(*id, graph_node_index, graph_nodes).map(graph_node_kind)
                                == Some(first_kind)
                        });
                        let kind = if same_kind {
                            first_kind
                        } else {
                            GraphNodeKind::Other
                        };
                        let rect = if ids.len() == 1 {
                            node_rects[&first_id]
                        } else {
                            Rect::from_center_size(
                                center.to_pos2(),
                                Vec2::new(cluster_size.unwrap_or(32.0), 24.0),
                            )
                        };
                        let label = if ids.len() == 1 {
                            first_label.to_string()
                        } else if overview_mode {
                            format!("{}+ nodes", ids.len())
                        } else {
                            format!("{} nodes", ids.len())
                        };
                        for id in &ids {
                            node_group_rects.insert(*id, rect);
                        }
                        render_nodes.push(GraphRenderNode {
                            ids,
                            rect,
                            kind,
                            label,
                        });
                    }
                    let mut edges = HashSet::with_capacity(MAX_RENDERED_GRAPH_EDGES);
                    if !overview_mode {
                        let edge_query_min = logical_clip_min - base_node_size;
                        let edge_query_max = logical_clip_max + base_node_size;
                        let edge_min_cell = (
                            (edge_query_min.x / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
                            (edge_query_min.y / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
                        );
                        let edge_max_cell = (
                            (edge_query_max.x / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
                            (edge_query_max.y / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
                        );
                        'edge_cells: for cell_y in edge_min_cell.1..=edge_max_cell.1 {
                            for cell_x in edge_min_cell.0..=edge_max_cell.0 {
                                if edges.len() >= MAX_RENDERED_GRAPH_EDGES {
                                    break 'edge_cells;
                                }
                                if let Some(cell_edges) =
                                    graph_layout_edge_index.get(&(cell_x, cell_y))
                                {
                                    for edge in cell_edges {
                                        if edges.len() >= MAX_RENDERED_GRAPH_EDGES {
                                            break 'edge_cells;
                                        }
                                        edges.insert(*edge);
                                    }
                                }
                            }
                        }
                        if edges.len() < MAX_RENDERED_GRAPH_EDGES {
                            edges.extend(
                                graph_layout_long_edges
                                    .iter()
                                    .take(MAX_RENDERED_GRAPH_EDGES - edges.len())
                                    .copied(),
                            );
                        }
                    }
                    let label_for = |id: usize| {
                        label_for_node(id, graph_node_index, graph_nodes).unwrap_or_default()
                    };
                    let edge_segment = |from_rect: Rect, to_rect: Rect| {
                        let direction = to_rect.center() - from_rect.center();
                        if direction.length_sq() <= f32::EPSILON {
                            return None;
                        }
                        let unit = direction.normalized();
                        Some((
                            rect_boundary_point(from_rect, unit),
                            rect_boundary_point(to_rect, -unit),
                        ))
                    };
                    let draw_edge = |from_rect: Rect,
                                     to_rect: Rect,
                                     edge_kind: GraphEdgeKind,
                                     width_scale: f32| {
                        let Some((start, end)) = edge_segment(from_rect, to_rect) else {
                            return;
                        };
                        let unit = (to_rect.center() - from_rect.center()).normalized();
                        if !Rect::from_two_pos(start, end)
                            .expand(4.0)
                            .intersects(clip_rect)
                        {
                            return;
                        }
                        let (edge_color, edge_width) = graph_edge_style(edge_kind);
                        painter.line_segment(
                            [start, end],
                            Stroke::new(edge_width * width_scale, edge_color),
                        );
                        let arrow_size = (11.0 * zoom).clamp(5.0, 14.0);
                        let side = Vec2::new(-unit.y, unit.x);
                        let arrow_base = end - unit * arrow_size;
                        painter.add(egui::Shape::convex_polygon(
                            vec![
                                end,
                                arrow_base + side * arrow_size * 0.55,
                                arrow_base - side * arrow_size * 0.55,
                            ],
                            edge_color,
                            Stroke::NONE,
                        ));
                    };
                    if overview_mode {
                        let endpoint_size = Vec2::splat(8.0);
                        for &(from_position, to_position, edge_kind) in graph_minimap_edges {
                            draw_edge(
                                Rect::from_center_size(
                                    origin + from_position * zoom,
                                    endpoint_size,
                                ),
                                Rect::from_center_size(origin + to_position * zoom, endpoint_size),
                                edge_kind,
                                0.7,
                            );
                        }
                    } else if let Some(cluster_size) = cluster_size {
                        let mut grouped_edges = HashMap::<
                            ((i32, i32), (i32, i32), GraphEdgeKind),
                            (Vec2, Vec2, usize, usize, usize),
                        >::new();
                        for &(from, to) in &edges {
                            let (Some(from_rect), Some(to_rect)) = (node_rect(from), node_rect(to))
                            else {
                                continue;
                            };
                            let edge_kind = graph_edge_kind(label_for(from), label_for(to));
                            let from_center = node_group_rects
                                .get(&from)
                                .map(Rect::center)
                                .unwrap_or_else(|| from_rect.center());
                            let to_center = node_group_rects
                                .get(&to)
                                .map(Rect::center)
                                .unwrap_or_else(|| to_rect.center());
                            let from_key = (
                                (from_center.x / cluster_size).floor() as i32,
                                (from_center.y / cluster_size).floor() as i32,
                            );
                            let to_key = (
                                (to_center.x / cluster_size).floor() as i32,
                                (to_center.y / cluster_size).floor() as i32,
                            );
                            let entry = grouped_edges
                                .entry((from_key, to_key, edge_kind))
                                .or_insert((Vec2::ZERO, Vec2::ZERO, 0, from, to));
                            entry.0 += from_center.to_vec2();
                            entry.1 += to_center.to_vec2();
                            entry.2 += 1;
                        }
                        for ((_, _, edge_kind), (from_sum, to_sum, count, from, to)) in
                            grouped_edges
                        {
                            let from_center = from_sum / count as f32;
                            let to_center = to_sum / count as f32;
                            let endpoint_size = Vec2::splat(cluster_size.min(24.0));
                            let width_scale = (1.0 + (count as f32).log2() * 0.15).min(2.0);
                            let from_rect =
                                Rect::from_center_size(from_center.to_pos2(), endpoint_size);
                            let to_rect =
                                Rect::from_center_size(to_center.to_pos2(), endpoint_size);
                            if track_edge_click {
                                if let Some((start, end)) = edge_segment(from_rect, to_rect) {
                                    edge_hit_segments.push((start, end, from, to));
                                }
                            }
                            draw_edge(from_rect, to_rect, edge_kind, width_scale);
                        }
                    } else {
                        for &(from, to) in &edges {
                            let (Some(from_rect), Some(to_rect)) = (node_rect(from), node_rect(to))
                            else {
                                continue;
                            };
                            let edge_kind = graph_edge_kind(label_for(from), label_for(to));
                            if track_edge_click {
                                if let Some((start, end)) = edge_segment(from_rect, to_rect) {
                                    edge_hit_segments.push((start, end, from, to));
                                }
                            }
                            draw_edge(from_rect, to_rect, edge_kind, 1.0);
                        }
                    }
                    for render_node in &render_nodes {
                        let node_rect = render_node.rect;
                        let kind = render_node.kind;
                        let label = &render_node.label;
                        let group_size = render_node.ids.len();
                        let (fill, stroke) = graph_node_colors(kind);
                        paint_graph_node(&painter, node_rect, kind, fill, stroke);
                        // At overview zoom the node shapes still provide useful
                        // structure, but laying out thousands of labels dominates
                        // frame time and gives the GPU very little to do.
                        if zoom >= 0.45 || group_size > 1 {
                            let node_text = if group_size > 1 {
                                format!("{}\n{}", group_size, shorten(label, 24))
                            } else {
                                let max_chars = if zoom < 0.7 { 28 } else { 58 };
                                let display = graph_display_label(label, kind, zoom < 0.7);
                                format!("{}\n{}", kind.label(), shorten(&display, max_chars))
                            };
                            let font_size = (12.0 * zoom).clamp(7.0, 14.0);
                            let text_width = match kind {
                                GraphNodeKind::Class => node_rect.width() * 0.55,
                                GraphNodeKind::String => node_rect.width() * 0.65,
                                _ => node_rect.width() - 14.0 * zoom,
                            };
                            let galley = painter.layout(
                                node_text,
                                FontId::monospace(font_size),
                                Color32::WHITE,
                                text_width.max(24.0),
                            );
                            painter.galley(
                                node_rect.center() - galley.size() / 2.0,
                                galley,
                                Color32::WHITE,
                            );
                        }
                        let node_id = render_node.ids[0];
                        let response = ui.interact(
                            node_rect,
                            ui.make_persistent_id(("graph-node", node_id)),
                            Sense::click(),
                        );
                        let clicked = response.clicked() && !pointer_over_minimap;
                        if group_size > 1 {
                            response.on_hover_text("Clustered nodes — click to zoom in");
                            if clicked {
                                cluster_zoom_requested = true;
                            }
                        } else {
                            response.on_hover_text(label.as_str());
                            if clicked {
                                clicked_node = Some((node_id, label.clone()));
                            }
                        }
                    }
                    if track_edge_click && clicked_node.is_none() && !cluster_zoom_requested {
                        if let Some(pointer) = ui.input(|input| input.pointer.interact_pos()) {
                            let mut best = None;
                            for (start, end, from, to) in edge_hit_segments {
                                let distance = distance_to_segment(pointer, start, end);
                                if distance > 10.0 {
                                    continue;
                                }
                                if best.map_or(true, |(best_distance, _, _, _, _)| {
                                    distance < best_distance
                                }) {
                                    best = Some((distance, from, to, start, end));
                                }
                            }
                            if let Some((_, from, to, start, end)) = best {
                                let from_position = graph_layout
                                    .get(&from)
                                    .map(|position| origin + *position * zoom)
                                    .unwrap_or(start);
                                let to_position = graph_layout
                                    .get(&to)
                                    .map(|position| origin + *position * zoom)
                                    .unwrap_or(end);
                                // Select the endpoint farther from the click. This makes
                                // an edge click move across the relationship instead of
                                // reopening the node immediately beside the pointer.
                                let farther_target = if pointer.distance_sq(from_position)
                                    >= pointer.distance_sq(to_position)
                                {
                                    from
                                } else {
                                    to
                                };
                                let target = if last_edge_click.is_some_and(
                                    |(last_from, last_to, last_target)| {
                                        last_from == from
                                            && last_to == to
                                            && last_target == farther_target
                                    },
                                ) {
                                    if farther_target == from {
                                        to
                                    } else {
                                        from
                                    }
                                } else {
                                    farther_target
                                };
                                next_edge_click = Some((from, to, target));
                                if let Some(label) =
                                    label_for_node(target, graph_node_index, graph_nodes)
                                {
                                    clicked_node = Some((target, label.to_string()));
                                }
                            }
                        }
                    }
                    let minimap_inner = minimap_rect.shrink(8.0);
                    let minimap_span = (max - min).max(Vec2::splat(1.0));
                    let minimap_point = |position: Vec2| {
                        egui::Pos2::new(
                            minimap_inner.left()
                                + ((position.x - min.x) / minimap_span.x).clamp(0.0, 1.0)
                                    * minimap_inner.width(),
                            minimap_inner.top()
                                + ((position.y - min.y) / minimap_span.y).clamp(0.0, 1.0)
                                    * minimap_inner.height(),
                        )
                    };
                    painter.rect_filled(
                        minimap_rect,
                        6.0,
                        Color32::from_rgba_unmultiplied(18, 20, 24, 235),
                    );
                    painter.rect_stroke(
                        minimap_rect,
                        6.0,
                        Stroke::new(1.0, Color32::from_gray(105)),
                        egui::StrokeKind::Outside,
                    );
                    for &(from, to, edge_kind) in graph_minimap_edges {
                        let (color, _) = graph_edge_style(edge_kind);
                        painter.line_segment(
                            [minimap_point(from), minimap_point(to)],
                            Stroke::new(0.7, color),
                        );
                    }
                    for &(_, position, kind) in graph_minimap_nodes {
                        let (fill, _) = graph_node_colors(kind);
                        painter.circle_filled(minimap_point(position), 1.4, fill);
                    }
                    let minimap_view = Rect::from_min_max(
                        minimap_point(logical_clip_min),
                        minimap_point(logical_clip_max),
                    )
                    .intersect(minimap_inner);
                    painter.rect_stroke(
                        minimap_view,
                        1.0,
                        Stroke::new(1.2, Color32::WHITE),
                        egui::StrokeKind::Inside,
                    );
                    let map_response = ui
                        .interact(
                            minimap_rect,
                            ui.make_persistent_id("graph-minimap"),
                            Sense::click_and_drag(),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("Click or drag to navigate the graph");
                    if map_response.clicked() || map_response.dragged() {
                        if let Some(pointer) = map_response.interact_pointer_pos() {
                            minimap_target =
                                Some(minimap_graph_position(pointer, minimap_inner, min, max));
                            clicked_node = None;
                            cluster_zoom_requested = false;
                        }
                    }
                    if graph_layout.is_empty() {
                        painter.text(
                            rect.center(),
                            egui::Align2::CENTER_CENTER,
                            "DOT contained no renderable nodes",
                            FontId::proportional(14.0),
                            theme::MUTED,
                        );
                    }
                });
                let focus_target =
                    focus_node.and_then(|node_id| graph_layout.get(&node_id).copied());
                if let Some(target) = minimap_target.or(focus_target) {
                    output.state.offset = graph_center_offset(
                        target,
                        min,
                        zoom,
                        output.inner_rect.size(),
                        output.content_size,
                    );
                    output.state.store(ui.ctx(), output.id);
                    ui.ctx().request_repaint();
                }
            });
        if let Some(edge_click) = next_edge_click {
            self.graph.last_edge_click = Some(edge_click);
            self.graph.focus_node = Some(edge_click.2);
        } else if clicked_node.is_some() {
            self.graph.last_edge_click = None;
        }
        if cluster_zoom_requested {
            self.graph.zoom = (zoom * 1.6).clamp(0.03, 3.0);
            self.graph.fit_to_view = false;
        }
        if let Some((node_id, label)) = clicked_node {
            self.graph_node_details = Some(GraphNodeDetails {
                node_id,
                kind: graph_node_kind(&label).label().to_string(),
                value: String::new(),
                label: label.clone(),
                targets: Vec::new(),
                loading: true,
            });
            self.request(
                "graph_node_details",
                json!({
                    "op": "graph_node_details",
                    "node_id": node_id,
                    "label": label,
                }),
            );
        }
    }

    fn show_graph_node_details(&mut self, ctx: &egui::Context) {
        let Some(details) = self.graph_node_details.as_ref() else {
            return;
        };
        let snapshot = details.clone();
        let mut close = false;
        let mut navigate = None;
        egui::Window::new(format!("Graph node #{}", snapshot.node_id))
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Type");
                    ui.label(RichText::new(&snapshot.kind).strong().monospace());
                    ui.separator();
                    ui.label(format!("node #{}", snapshot.node_id));
                });
                ui.label(RichText::new("DOT node label").small().color(theme::MUTED));
                ui.add(egui::Label::new(RichText::new(&snapshot.label).monospace()).wrap());
                if !snapshot.value.is_empty() {
                    ui.label(
                        RichText::new("Referenced value")
                            .small()
                            .color(theme::MUTED),
                    );
                    ui.add(egui::Label::new(RichText::new(&snapshot.value).monospace()).wrap());
                }
                ui.separator();
                ui.label(RichText::new("Navigatable references").strong());
                if snapshot.loading {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Resolving Coeus objects…");
                    });
                } else if snapshot.targets.is_empty() {
                    ui.label(
                        RichText::new("No class, method, field, or string reference was resolved.")
                            .small()
                            .color(theme::MUTED),
                    );
                } else {
                    for target in &snapshot.targets {
                        let display_label = self.display_label(&target.kind, &target.label);
                        ui.horizontal(|ui| {
                            if ui
                                .button(format!(
                                    "Go to {}: {}",
                                    target.kind,
                                    shorten(&display_label, 72)
                                ))
                                .clicked()
                            {
                                navigate = Some(target.clone());
                            }
                            self.show_note_chip(ui, &target.kind, &target.note_key, &display_label);
                            if matches!(target.kind.as_str(), "method" | "class")
                                && ui
                                    .small_button(
                                        if self.alias_for(&target.kind, &target.label).is_some() {
                                            "alias"
                                        } else {
                                            "＋ alias"
                                        },
                                    )
                                    .clicked()
                            {
                                self.open_alias_editor_target(target);
                            }
                        });
                    }
                }
                if ui.button("Close").clicked() {
                    close = true;
                }
            });
        if close {
            self.graph_node_details = None;
        }
        if let Some(target) = navigate {
            self.graph_node_details = None;
            self.selected_id = Some(target.id.clone());
            self.tab = Tab::Code;
            self.request("describe", json!({"op": "describe", "id": target.id}));
        }
    }

    fn show_manifest(&mut self, ui: &mut egui::Ui) {
        ui.heading("Android manifest");
        if self.info.is_none() {
            ui.centered_and_justified(|ui| ui.label("Load an APK to inspect its manifest."));
            return;
        }
        ui.label(
            "Edit the decoded AndroidManifest.xml directly, or use the common debugging helpers below.",
        );
        let mut action = None;
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    self.manifest_dirty && !self.busy(),
                    egui::Button::new("Apply XML changes"),
                )
                .clicked()
            {
                action = Some("apply");
            }
            if ui.button("Format XML").clicked() {
                action = Some("format");
            }
            if ui
                .add_enabled(
                    !self.busy(),
                    egui::Button::new(if self.manifest_dirty {
                        "Discard edits & reload"
                    } else {
                        "Reload from APK"
                    }),
                )
                .clicked()
            {
                action = Some("reload");
            }
            let helpers_enabled = !self.manifest_dirty && !self.busy();
            if ui
                .add_enabled(helpers_enabled, egui::Button::new("Enable debuggable"))
                .clicked()
            {
                action = Some("debuggable_on");
            }
            if ui
                .add_enabled(helpers_enabled, egui::Button::new("Disable debuggable"))
                .clicked()
            {
                action = Some("debuggable_off");
            }
            if ui
                .add_enabled(
                    helpers_enabled,
                    egui::Button::new("Allow plaintext + user CAs"),
                )
                .clicked()
            {
                action = Some("plaintext");
            }
        });
        if self.manifest_dirty {
            ui.label(
                RichText::new("Unapplied manifest edits — apply them before using a helper.")
                    .small()
                    .color(theme::WARNING),
            );
        }
        let mut layouter = |ui: &egui::Ui, text: &str, wrap_width: f32| {
            let mut layout = highlight_xml(text);
            layout.wrap.max_width = wrap_width;
            ui.fonts(|fonts| fonts.layout_job(layout))
        };
        let mut xml_changed = false;
        egui::ScrollArea::both()
            .id_salt("manifest-editor")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let xml_size = ui.available_size();
                let response = ui.add_sized(
                    xml_size,
                    egui::TextEdit::multiline(&mut self.manifest_xml)
                        .font(FontId::monospace(12.0))
                        .desired_width(xml_size.x)
                        .code_editor()
                        .layouter(&mut layouter),
                );
                xml_changed = response.changed();
            });
        if xml_changed {
            self.manifest_dirty = true;
        }
        match action {
            Some("format") => match format_xml(&self.manifest_xml) {
                Ok(formatted) => {
                    self.manifest_xml = formatted;
                    self.manifest_dirty = true;
                    self.status =
                        "Formatted manifest XML (review and apply when ready)".to_string();
                }
                Err(error) => {
                    self.status = format!("Could not format XML: {error}");
                }
            },
            Some("apply") => self.request(
                "set_manifest_xml",
                json!({"op": "set_manifest_xml", "xml": self.manifest_xml}),
            ),
            Some("reload") => self.request("manifest", json!({"op": "manifest"})),
            Some("debuggable_on") => self.request(
                "set_debuggable",
                json!({"op": "set_debuggable", "enabled": true}),
            ),
            Some("debuggable_off") => self.request(
                "set_debuggable",
                json!({"op": "set_debuggable", "enabled": false}),
            ),
            Some("plaintext") => self.request(
                "allow_plaintext_and_user_certificates",
                json!({"op": "allow_plaintext_and_user_certificates"}),
            ),
            _ => {}
        }
    }

    fn show_deploy(&mut self, ui: &mut egui::Ui) {
        ui.heading(if self.split_mode {
            "Sign and install split APK set"
        } else {
            "Sign and install APK"
        });
        if self.info.is_none() {
            ui.centered_and_justified(|ui| {
                ui.label("Load an APK before signing or installing it.")
            });
            return;
        }
        if self.split_mode {
            self.show_split_deploy(ui);
            return;
        }
        ui.label(
            "Signing uses the Android SDK apksigner and installation uses adb. Passwords are kept only in this running GUI session.",
        );
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.label("Keystore");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.keystore)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(460.0)
                    .hint_text("debug.keystore or another signing key"),
            );
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.deploy.keystore = path.display().to_string();
                }
            }
            if ui
                .add_enabled(!self.busy(), egui::Button::new("Generate here"))
                .on_hover_text("Create debug.keystore beside the loaded APK or project")
                .clicked()
            {
                self.request_generate_keystore();
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Alias");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.alias)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(220.0),
            );
            ui.label("Store password");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.store_password)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(180.0)
                    .password(true),
            );
            ui.label("Key password");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.key_password)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(180.0)
                    .password(true),
            );
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Output APK");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.output)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(460.0)
                    .hint_text("signed output APK"),
            );
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("signed.apk")
                    .save_file()
                {
                    self.deploy.output = path.display().to_string();
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("apksigner (optional)");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.apksigner)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(360.0)
                    .hint_text("use SDK PATH when empty"),
            );
            ui.label("adb (optional)");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.adb_path)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(260.0)
                    .hint_text("use PATH when empty"),
            );
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Device");
            egui::ComboBox::from_id_salt("deploy-device")
                .selected_text(if self.deploy.serial.is_empty() {
                    "Default adb device"
                } else {
                    self.deploy
                        .devices
                        .iter()
                        .find(|device| device.serial == self.deploy.serial)
                        .map(|device| device.label.as_str())
                        .unwrap_or(self.deploy.serial.as_str())
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.deploy.serial,
                        String::new(),
                        "Default adb device",
                    );
                    for device in self.deploy.devices.clone() {
                        ui.selectable_value(
                            &mut self.deploy.serial,
                            device.serial.clone(),
                            device.label,
                        );
                    }
                });
            let refresh = ui.button("Refresh devices").clicked();
            if refresh {
                self.request(
                    "adb_devices",
                    json!({"op": "adb_devices", "adb_path": self.deploy.adb_path}),
                );
            }
            ui.checkbox(
                &mut self.deploy.replace_existing,
                "Replace existing install",
            );
        });
        ui.separator();
        let mut action = None;
        ui.horizontal_wrapped(|ui| {
            let ready_to_sign = !self.busy()
                && !self.deploy.keystore.trim().is_empty()
                && !self.deploy.alias.trim().is_empty()
                && !self.deploy.store_password.is_empty()
                && !self.deploy.output.trim().is_empty();
            if ui
                .add_enabled(ready_to_sign, egui::Button::new("Sign APK"))
                .clicked()
            {
                action = Some("sign");
            }
            let ready_to_install = !self.busy() && !self.deploy.output.trim().is_empty();
            if ui
                .add_enabled(ready_to_install, egui::Button::new("Install signed APK"))
                .clicked()
            {
                action = Some("install");
            }
            if ui
                .add_enabled(ready_to_sign, egui::Button::new("Sign and install"))
                .clicked()
            {
                action = Some("sign_and_install");
            }
        });
        if let Some(action) = action {
            let request = json!({
                "op": action,
                "output": self.deploy.output,
                "path": self.deploy.output,
                "keystore": self.deploy.keystore,
                "alias": self.deploy.alias,
                "store_password": self.deploy.store_password,
                "key_password": if self.deploy.key_password.is_empty() { Value::Null } else { Value::String(self.deploy.key_password.clone()) },
                "apksigner": if self.deploy.apksigner.is_empty() { Value::Null } else { Value::String(self.deploy.apksigner.clone()) },
                "serial": if self.deploy.serial.is_empty() { Value::Null } else { Value::String(self.deploy.serial.clone()) },
                "adb_path": if self.deploy.adb_path.is_empty() { Value::Null } else { Value::String(self.deploy.adb_path.clone()) },
                "replace_existing": self.deploy.replace_existing,
            });
            self.request_after_session_save(action, request);
        }
    }

    fn show_split_deploy(&mut self, ui: &mut egui::Ui) {
        ui.label(
            "This is a split install set. The base manifest and code are shown in the analysis tabs; deployment writes and installs all members together.",
        );
        ui.label(RichText::new("Members").strong());
        egui::ScrollArea::vertical()
            .id_salt("split-members")
            .max_height(120.0)
            .show(ui, |ui| {
                for member in &self.split_members {
                    ui.label(RichText::new(member).monospace().small());
                }
            });
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.label("Keystore");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.keystore)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(460.0)
                    .hint_text("debug.keystore or another signing key"),
            );
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.deploy.keystore = path.display().to_string();
                }
            }
            if ui
                .add_enabled(!self.busy(), egui::Button::new("Generate here"))
                .on_hover_text("Create debug.keystore beside the loaded APK or project")
                .clicked()
            {
                self.request_generate_keystore();
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Alias");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.alias)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(220.0),
            );
            ui.label("Store password");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.store_password)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(180.0)
                    .password(true),
            );
            ui.label("Key password");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.key_password)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(180.0)
                    .password(true),
            );
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Signed output directory");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.split_output_dir)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(460.0)
                    .hint_text("directory for base.apk and split APKs"),
            );
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.deploy.split_output_dir = path.display().to_string();
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("apksigner (optional)");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.apksigner)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(360.0)
                    .hint_text("use SDK PATH when empty"),
            );
            ui.label("adb (optional)");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.adb_path)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(260.0)
                    .hint_text("use PATH when empty"),
            );
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Device");
            egui::ComboBox::from_id_salt("split-deploy-device")
                .selected_text(if self.deploy.serial.is_empty() {
                    "Default adb device"
                } else {
                    self.deploy
                        .devices
                        .iter()
                        .find(|device| device.serial == self.deploy.serial)
                        .map(|device| device.label.as_str())
                        .unwrap_or(self.deploy.serial.as_str())
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.deploy.serial,
                        String::new(),
                        "Default adb device",
                    );
                    for device in self.deploy.devices.clone() {
                        ui.selectable_value(
                            &mut self.deploy.serial,
                            device.serial.clone(),
                            device.label,
                        );
                    }
                });
            if ui.button("Refresh devices").clicked() {
                self.request(
                    "adb_devices",
                    json!({"op": "adb_devices", "adb_path": self.deploy.adb_path}),
                );
            }
            ui.checkbox(
                &mut self.deploy.replace_existing,
                "Replace existing install",
            );
        });
        ui.separator();
        let ready_to_sign = !self.busy()
            && !self.deploy.keystore.trim().is_empty()
            && !self.deploy.alias.trim().is_empty()
            && !self.deploy.store_password.is_empty()
            && !self.deploy.split_output_dir.trim().is_empty();
        let ready_to_install = !self.busy() && !self.deploy.split_output_dir.trim().is_empty();
        let mut action = None;
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(ready_to_sign, egui::Button::new("Sign all APKs"))
                .clicked()
            {
                action = Some("sign_split");
            }
            if ui
                .add_enabled(ready_to_install, egui::Button::new("Install split set"))
                .clicked()
            {
                action = Some("install_split");
            }
            if ui
                .add_enabled(
                    ready_to_sign,
                    egui::Button::new("Sign and install split set"),
                )
                .clicked()
            {
                action = Some("sign_and_install_split");
            }
        });
        if let Some(action) = action {
            let request = json!({
                "op": action,
                "output_dir": self.deploy.split_output_dir,
                "keystore": self.deploy.keystore,
                "alias": self.deploy.alias,
                "store_password": self.deploy.store_password,
                "key_password": if self.deploy.key_password.is_empty() { Value::Null } else { Value::String(self.deploy.key_password.clone()) },
                "apksigner": if self.deploy.apksigner.is_empty() { Value::Null } else { Value::String(self.deploy.apksigner.clone()) },
                "serial": if self.deploy.serial.is_empty() { Value::Null } else { Value::String(self.deploy.serial.clone()) },
                "adb_path": if self.deploy.adb_path.is_empty() { Value::Null } else { Value::String(self.deploy.adb_path.clone()) },
                "replace_existing": self.deploy.replace_existing,
            });
            self.request_after_session_save(action, request);
        }
    }

    fn show_adb(&mut self, ui: &mut egui::Ui) {
        ui.heading("ADB device");
        ui.label(
            "Browse installed packages on a connected Android device, then pull the base APK and all split APKs into a local directory.",
        );
        let mut refresh_devices = false;
        let mut refresh_packages = false;
        let mut load_selected = false;
        let mut pull_selected = false;
        ui.horizontal_wrapped(|ui| {
            ui.label("adb");
            ui.add(
                egui::TextEdit::singleline(&mut self.adb.adb_path)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(360.0)
                    .hint_text("use adb from PATH when empty"),
            );
            if ui
                .add_enabled(!self.busy(), egui::Button::new("Refresh devices"))
                .clicked()
            {
                refresh_devices = true;
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Device");
            egui::ComboBox::from_id_salt("adb-view-device")
                .selected_text(if self.adb.serial.is_empty() {
                    "Default adb device"
                } else {
                    self.adb
                        .devices
                        .iter()
                        .find(|device| device.serial == self.adb.serial)
                        .map(|device| device.label.as_str())
                        .unwrap_or(self.adb.serial.as_str())
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.adb.serial, String::new(), "Default adb device");
                    for device in self.adb.devices.clone() {
                        ui.selectable_value(
                            &mut self.adb.serial,
                            device.serial.clone(),
                            device.label,
                        );
                    }
                });
            ui.label(format!("{} connected device(s)", self.adb.devices.len()));
        });
        if refresh_devices {
            self.request(
                "adb_devices",
                json!({"op": "adb_devices", "adb_path": self.adb.adb_path}),
            );
        }
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.label("Package filter");
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.adb.package_filter)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(360.0)
                    .hint_text("optional regex, e.g. com.example"),
            );
            if response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
                refresh_packages = true;
            }
            if ui
                .add_enabled(!self.busy(), egui::Button::new("List packages"))
                .clicked()
            {
                refresh_packages = true;
            }
        });
        if refresh_packages {
            self.request(
                "adb_packages",
                json!({
                    "op": "adb_packages",
                    "package_regex": if self.adb.package_filter.trim().is_empty() { Value::Null } else { Value::String(self.adb.package_filter.clone()) },
                    "serial": if self.adb.serial.is_empty() { Value::Null } else { Value::String(self.adb.serial.clone()) },
                    "adb_path": if self.adb.adb_path.is_empty() { Value::Null } else { Value::String(self.adb.adb_path.clone()) },
                }),
            );
        }
        ui.label(
            RichText::new(format!("Installed packages ({})", self.adb.packages.len())).strong(),
        );
        egui::ScrollArea::vertical()
            .id_salt("adb-packages")
            .max_height(360.0)
            .show(ui, |ui| {
                for package in self.adb.packages.clone() {
                    let response = ui.selectable_label(
                        self.adb.selected_package == package,
                        RichText::new(&package).monospace(),
                    );
                    if response.clicked() {
                        self.adb.selected_package = package;
                    }
                }
            });
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.label("Local output directory");
            ui.add(
                egui::TextEdit::singleline(&mut self.adb.output_dir)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(480.0)
                    .hint_text("where pulled APKs should be written"),
            );
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.adb.output_dir = path.display().to_string();
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            let ready = !self.busy()
                && !self.adb.selected_package.trim().is_empty()
                && !self.adb.output_dir.trim().is_empty();
            if ui
                .add_enabled(ready, egui::Button::new("Pull APKs + load split set"))
                .clicked()
            {
                pull_selected = true;
            }
            let load_ready = !self.busy() && !self.adb.selected_package.trim().is_empty();
            if ui
                .add_enabled(
                    load_ready,
                    egui::Button::new("Load split set without saving"),
                )
                .clicked()
            {
                load_selected = true;
            }
        });
        let serial = if self.adb.serial.is_empty() {
            Value::Null
        } else {
            Value::String(self.adb.serial.clone())
        };
        let adb_path = if self.adb.adb_path.is_empty() {
            Value::Null
        } else {
            Value::String(self.adb.adb_path.clone())
        };
        if pull_selected {
            self.request(
                "pull_apks",
                json!({
                    "op": "pull_apks",
                    "package": self.adb.selected_package,
                    "output_dir": self.adb.output_dir,
                    "serial": serial,
                    "adb_path": adb_path,
                }),
            );
        } else if load_selected {
            self.request(
                "load_split_from_adb",
                json!({
                    "op": "load_split_from_adb",
                    "package": self.adb.selected_package,
                    "serial": serial,
                    "adb_path": adb_path,
                }),
            );
        }
    }

    fn show_floating_debugger(&mut self, ctx: &egui::Context) {
        if self.tab == Tab::Debugger || !self.debug.floating_open {
            return;
        }
        let frame = self.debug.frame.clone();
        let values = self.debug.values.clone();
        let connected = self.debug.connected;
        let waiting = self.debug.waiting;
        let busy = self.busy();
        let breakpoint_pending = self.debug_breakpoint_pending();
        let can_control = connected && !waiting && !busy && !breakpoint_pending;
        let can_set_value = connected && frame.is_some() && !waiting && !breakpoint_pending;
        let mut open = self.debug.floating_open;
        let mut resume = false;
        let mut step = false;
        let mut set_value = None;
        let mut edits = self.debug.edits.clone();
        let viewport = ctx.screen_rect();
        let max_width = (viewport.width() - 24.0).max(1.0);
        let max_height = (viewport.height() - 24.0).max(1.0);

        egui::Window::new("Debugger — stopped")
            .id(egui::Id::new("floating-debugger"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .max_size(Vec2::new(max_width, max_height))
            .default_size(Vec2::new(
                440.0_f32.min(max_width),
                520.0_f32.min(max_height),
            ))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("floating-debugger-content")
                    .auto_shrink([false, false])
                    .max_height((max_height - 72.0).max(1.0))
                    .show(ui, |ui| {
                        if let Some(frame) = frame.as_ref() {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!(
                                        "{} → {} @0x{:x}",
                                        value_string(frame, "class"),
                                        value_string(frame, "method"),
                                        value_u64(frame, "code_index")
                                    ))
                                    .strong()
                                    .monospace(),
                                )
                                .wrap(),
                            );
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(can_control, egui::Button::new("Resume (F5)"))
                                    .clicked()
                                {
                                    resume = true;
                                }
                                if ui
                                    .add_enabled(can_control, egui::Button::new("Step (F10)"))
                                    .clicked()
                                {
                                    step = true;
                                }
                                if waiting {
                                    ui.spinner();
                                    ui.label("waiting for the next event…");
                                }
                            });
                            ui.separator();
                            ui.label(RichText::new("Register values").strong());
                            if values.is_empty() {
                                ui.label(
                                    RichText::new(
                                        "No local-variable metadata is available for this frame.",
                                    )
                                    .small()
                                    .color(theme::MUTED),
                                );
                            }
                            for (slot, observed, edit) in values.iter().cloned() {
                                let row_width = ui.available_width().max(1.0);
                                let spacing = ui.spacing().item_spacing.x;
                                let observed_width =
                                    (row_width - 34.0 - 150.0 - 44.0 - spacing * 3.0).max(48.0);
                                ui.horizontal_wrapped(|ui| {
                                    ui.add_sized(
                                        [34.0, 20.0],
                                        egui::Label::new(
                                            RichText::new(format!("v{slot}")).monospace().small(),
                                        ),
                                    );
                                    ui.add_sized(
                                        [observed_width, 20.0],
                                        egui::Label::new(
                                            RichText::new(observed).monospace().small(),
                                        )
                                        .truncate(),
                                    );
                                    let mut edited = edits.get(&slot).cloned().unwrap_or(edit);
                                    ui.add_sized(
                                        [150.0, 20.0],
                                        egui::TextEdit::singleline(&mut edited)
                                            .min_size(Vec2::new(0.0, 30.0))
                                            .margin(Vec2::new(8.0, 6.0)),
                                    );
                                    if ui
                                        .add_enabled(can_set_value, egui::Button::new("Set"))
                                        .clicked()
                                    {
                                        set_value = Some((slot, edited.clone()));
                                    }
                                    edits.insert(slot, edited);
                                });
                            }
                            if let Some(error) = frame.get("values_error").and_then(Value::as_str) {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format!(
                                            "Register values unavailable: {error}"
                                        ))
                                        .color(theme::WARNING),
                                    )
                                    .wrap(),
                                );
                            }
                            ui.label(
                                RichText::new(
                                    "The Code tab highlights the stopped execution index.",
                                )
                                .small()
                                .color(theme::MUTED),
                            );
                        } else if waiting {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label("Waiting for a breakpoint or single-step event…");
                            });
                        } else {
                            ui.label("No stopped stack frame yet.");
                        }
                    });
            });

        self.debug.floating_open = open;
        self.debug.edits = edits;
        if resume {
            self.request_debug_control("debug_resume");
        } else if step {
            self.request_debug_control("debug_step");
        }
        if let Some((slot, value)) = set_value {
            self.queue_debug_value(slot, value);
        }
    }

    fn show_debugger(&mut self, ui: &mut egui::Ui) {
        let debug_request_available = !self.busy() && !self.debug_breakpoint_pending();
        let can_control = self.debug.connected && !self.debug.waiting && debug_request_available;
        let can_set_value = self.debug.connected
            && self.debug.frame.is_some()
            && !self.debug.waiting
            && debug_request_available;
        ui.heading("JDWP debugger");
        ui.label(
            "Discover JDWP-enabled processes through adb, then attach to the selected process. The attach flow manages the JDWP forwarding.",
        );
        ui.horizontal(|ui| {
            ui.label("ADB serial");
            ui.add(
                egui::TextEdit::singleline(&mut self.debug.serial)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(150.0)
                    .hint_text("default device"),
            );
            ui.label("ADB path");
            ui.add(
                egui::TextEdit::singleline(&mut self.debug.adb_path)
                    .min_size(Vec2::new(0.0, 30.0))
                    .margin(Vec2::new(8.0, 6.0))
                    .desired_width(180.0)
                    .hint_text("PATH when empty"),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Forward port");
            ui.add(egui::TextEdit::singleline(&mut self.debug.port).min_size(Vec2::new(0.0, 30.0)).margin(Vec2::new(8.0, 6.0)).desired_width(70.0));
            if ui
                .add_enabled(
                    debug_request_available && !self.debug.apps_loading,
                    egui::Button::new("List JDWP apps"),
                )
                .clicked()
            {
                self.request(
                    "debug_apps",
                    json!({
                        "op":"debug_apps",
                        "serial": if self.debug.serial.is_empty() { Value::Null } else { Value::String(self.debug.serial.clone()) },
                        "adb_path": if self.debug.adb_path.is_empty() { Value::Null } else { Value::String(self.debug.adb_path.clone()) },
                    }),
                );
            }
            if ui
                .add_enabled(
                    debug_request_available && self.debug.connected && !self.debug.waiting,
                    egui::Button::new("Wait"),
                )
                .clicked()
            {
                self.request("debug_wait", json!({"op":"debug_wait"}));
            }
            if ui
                .add_enabled(debug_request_available && self.debug.connected, egui::Button::new("Detach"))
                .clicked()
            {
                self.request("debug_detach", json!({"op":"debug_detach"}));
            }
        });
        if self.debug.connecting {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Attaching/connecting to JDWP…");
            });
        }
        if self.debug.apps_loading {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Listing JDWP processes…");
            });
        }
        let mut attach_pid = None;
        if !self.debug.apps.is_empty() {
            ui.label(RichText::new("JDWP processes").strong());
            for app in self.debug.apps.clone() {
                ui.horizontal(|ui| {
                    let target = if app.package.is_empty() {
                        app.process.clone()
                    } else {
                        format!("{} — {}", app.package, app.process)
                    };
                    ui.label(
                        RichText::new(format!("{} (pid {})", target, app.pid))
                            .monospace()
                            .small(),
                    );
                    if ui
                        .add_enabled(
                            !self.busy() && !self.debug.connecting,
                            egui::Button::new("Attach"),
                        )
                        .clicked()
                    {
                        attach_pid = Some(app.pid);
                    }
                });
            }
        }
        if let Some(pid) = attach_pid {
            let port = self.debug.port.parse::<u16>().unwrap_or(8000);
            self.request(
                "debug_attach",
                json!({
                    "op": "debug_attach",
                    "pid": pid,
                    "port": port,
                    "serial": if self.debug.serial.is_empty() { Value::Null } else { Value::String(self.debug.serial.clone()) },
                    "adb_path": if self.debug.adb_path.is_empty() { Value::Null } else { Value::String(self.debug.adb_path.clone()) },
                }),
            );
        }
        if !self.debug.breakpoints.is_empty() {
            ui.separator();
            ui.label(RichText::new("Breakpoints").strong());
            let mut breakpoint_action: Option<(DebugBreakpoint, &'static str)> = None;
            for breakpoint in self.debug.breakpoints.clone() {
                let display = self.display_label("method", &breakpoint.method_key);
                ui.horizontal_wrapped(|ui| {
                    let state = if breakpoint.enabled {
                        "enabled"
                    } else {
                        "skipped"
                    };
                    ui.label(
                        RichText::new(format!(
                            "{} @0x{:x} · {}",
                            display, breakpoint.offset, state
                        ))
                        .monospace()
                        .small()
                        .color(if breakpoint.enabled {
                            theme::TEXT
                        } else {
                            theme::MUTED
                        }),
                    );
                    if ui
                        .add_enabled(
                            debug_request_available,
                            egui::Button::new(if breakpoint.enabled { "Skip" } else { "Enable" }),
                        )
                        .clicked()
                    {
                        breakpoint_action = Some((
                            breakpoint.clone(),
                            if breakpoint.enabled { "skip" } else { "enable" },
                        ));
                    }
                    if ui.button("Open").clicked() {
                        breakpoint_action = Some((breakpoint.clone(), "open"));
                    }
                    if ui
                        .add_enabled(debug_request_available, egui::Button::new("Remove"))
                        .clicked()
                    {
                        breakpoint_action = Some((breakpoint.clone(), "remove"));
                    }
                });
            }
            if let Some((breakpoint, action)) = breakpoint_action {
                match action {
                    "open" => {
                        self.selected_id = Some(breakpoint.method_id.clone());
                        self.tab = Tab::Code;
                        self.request(
                            "describe",
                            json!({"op":"describe", "id": breakpoint.method_id}),
                        );
                    }
                    "skip" | "enable" => self.request(
                        "debug_breakpoint_skip",
                        json!({
                            "op": "debug_breakpoint_skip",
                            "id": breakpoint.method_id,
                            "offset": breakpoint.offset,
                            "skip": action == "skip",
                        }),
                    ),
                    "remove" => self.request(
                        "debug_breakpoint_remove",
                        json!({
                            "op": "debug_breakpoint_remove",
                            "id": breakpoint.method_id,
                            "offset": breakpoint.offset,
                        }),
                    ),
                    _ => {}
                }
            }
        }
        if let Some(frame) = self.debug.frame.clone() {
            ui.separator();
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{} → {} @0x{:x}",
                        value_string(&frame, "class"),
                        value_string(&frame, "method"),
                        value_u64(&frame, "code_index")
                    ))
                    .strong()
                    .monospace(),
                );
                if ui
                    .add_enabled(can_control, egui::Button::new("Resume (F5)"))
                    .clicked()
                {
                    self.request_debug_control("debug_resume");
                }
                if ui
                    .add_enabled(can_control, egui::Button::new("Step (F10)"))
                    .clicked()
                {
                    self.request_debug_control("debug_step");
                }
                if self.debug.waiting {
                    ui.spinner();
                    ui.label("waiting for the next event…");
                }
            });
            ui.label("Register values");
            let mut set_value = None;
            for (slot, observed, edit) in self.debug.values.clone() {
                let row_width = ui.available_width().max(1.0);
                let spacing = ui.spacing().item_spacing.x;
                let observed_width = (row_width - 34.0 - 180.0 - 44.0 - spacing * 3.0).max(48.0);
                ui.horizontal_wrapped(|ui| {
                    ui.add_sized(
                        [34.0, 20.0],
                        egui::Label::new(RichText::new(format!("v{slot}")).monospace().small()),
                    );
                    ui.add_sized(
                        [observed_width, 20.0],
                        egui::Label::new(RichText::new(&observed).monospace().small()).truncate(),
                    );
                    let mut edited = self.debug.edits.get(&slot).cloned().unwrap_or(edit);
                    ui.add_sized(
                        [180.0, 20.0],
                        egui::TextEdit::singleline(&mut edited)
                            .min_size(Vec2::new(0.0, 30.0))
                            .margin(Vec2::new(8.0, 6.0)),
                    );
                    if ui
                        .add_enabled(can_set_value, egui::Button::new("Set"))
                        .clicked()
                    {
                        set_value = Some((slot, edited.clone()));
                    }
                    self.debug.edits.insert(slot, edited);
                });
            }
            if let Some((slot, value)) = set_value {
                self.queue_debug_value(slot, value);
            }
            if let Some(error) = frame.get("values_error").and_then(Value::as_str) {
                ui.colored_label(
                    theme::WARNING,
                    format!("Register values unavailable: {error}"),
                );
            }
            ui.label(RichText::new("The Code tab highlights the stopped code index. Select an instruction and press B to set or clear a breakpoint.").small().color(theme::MUTED));
        } else {
            ui.add_space(20.0);
            if can_control {
                if ui.button("Resume (F5)").clicked() {
                    self.request_debug_control("debug_resume");
                }
                ui.label(
                    "No frame metadata is available; resume the suspended VM or set Wait again.",
                );
            }
            ui.centered_and_justified(|ui| ui.label("No stopped stack frame yet."));
        }
    }
}

impl eframe::App for CoeusApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if !self.busy() && self.debug.last_poll.elapsed() >= Duration::from_millis(250) {
            self.debug.last_poll = Instant::now();
            if self.debug.connecting {
                self.request("debug_connect_poll", json!({"op":"debug_connect_poll"}));
            } else if self.debug.apps_loading {
                self.request("debug_apps_poll", json!({"op":"debug_apps_poll"}));
            } else if self.debug.waiting {
                self.request("debug_poll", json!({"op":"debug_poll"}));
            }
        }
        let (navigate_back, navigate_forward) = ctx.input(|input| {
            let command_tab = input.modifiers.command && input.key_pressed(Key::Tab);
            (
                command_tab && input.modifiers.shift,
                command_tab && !input.modifiers.shift,
            )
        });
        if navigate_back {
            self.navigate_history(-1);
        } else if navigate_forward {
            self.navigate_history(1);
        }
        let (open, save, find) = ctx.input_mut(|input| {
            (
                input.consume_key(egui::Modifiers::COMMAND, Key::O),
                input.consume_key(egui::Modifiers::COMMAND, Key::S),
                input.consume_key(egui::Modifiers::COMMAND, Key::F),
            )
        });
        if !self.busy() && self.bridge.is_some() {
            if open {
                self.open_apk_dialog();
            }
            if save && self.info.is_some() {
                if self.path.to_ascii_lowercase().ends_with(".coeus") {
                    self.save_project_in_place();
                } else {
                    self.save_project_dialog();
                }
            }
        }
        if find && self.info.is_some() {
            self.sidebar_collapsed = false;
            self.focus_search = true;
        }
        // Breakpoint/event operations share the JDWP packet receiver. Set and
        // clear requests are routed through the wait worker while it is
        // polling, so breakpoints can be changed without racing JDWP reads.
        if !self.busy() && self.debug.connected {
            let b = !ctx.wants_keyboard_input()
                && self.tab == Tab::Code
                && ctx.input(|input| input.modifiers.is_none() && input.key_pressed(Key::B));
            let f5 = ctx.input(|input| input.key_pressed(Key::F5));
            let f10 = ctx.input(|input| input.key_pressed(Key::F10));
            if b && !self.debug_breakpoint_pending() {
                if let (Some(method_id), Some(offset)) = (
                    self.code.selected_method_id.clone(),
                    self.code.selected_offset,
                ) {
                    self.request(
                        "debug_breakpoint",
                        json!({"op":"debug_breakpoint", "id":method_id, "offset":offset}),
                    );
                }
            } else if !self.debug_breakpoint_pending() && !self.debug.waiting && f5 {
                self.request_debug_control("debug_resume");
            } else if !self.debug_breakpoint_pending()
                && !self.debug.waiting
                && f10
                && self.debug.frame.is_some()
            {
                self.request_debug_control("debug_step");
            }
        }
        self.show_tabs(ctx);
        self.show_status(ctx);
        self.show_sidebar(ctx);
        if self.info.is_none() && !matches!(self.tab, Tab::Adb | Tab::Debugger) {
            egui::CentralPanel::default()
                .frame(theme::workspace())
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| self.show_welcome(ui));
                });
        } else if self.tab == Tab::Code {
            self.show_code(ctx);
        } else {
            egui::CentralPanel::default()
                .frame(theme::workspace())
                .show(ctx, |ui| match self.tab {
                    Tab::Search => {
                        egui::ScrollArea::both()
                            .id_salt("search-tab")
                            .auto_shrink([false, false])
                            .show(ui, |ui| self.show_search(ui));
                    }
                    Tab::Notes => {
                        egui::ScrollArea::vertical()
                            .id_salt("notes-tab")
                            .auto_shrink([false, false])
                            .show(ui, |ui| self.show_notes(ui));
                    }
                    Tab::Graph => {
                        egui::ScrollArea::vertical()
                            .id_salt("graph-tab")
                            .auto_shrink([false, false])
                            .show(ui, |ui| self.show_graph(ui));
                    }
                    Tab::Debugger => self.show_debugger(ui),
                    Tab::Manifest => self.show_manifest(ui),
                    Tab::Deploy => {
                        egui::ScrollArea::vertical()
                            .id_salt("deploy-tab")
                            .auto_shrink([false, false])
                            .show(ui, |ui| self.show_deploy(ui));
                    }
                    Tab::Adb => self.show_adb(ui),
                    Tab::Code => unreachable!("Code is rendered with its attached panels"),
                });
        }
        self.show_edit_picker(ctx);
        self.show_note_editor(ctx);
        self.show_note_popup(ctx);
        self.show_alias_editor(ctx);
        self.show_emulation_editor(ctx);
        self.show_emulation_result(ctx);
        self.show_graph_node_details(ctx);
        self.show_floating_debugger(ctx);
        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

fn parse_method_descriptors(signature: &str) -> Vec<String> {
    let Some(arguments) = signature.split_once('(').map(|(_, rest)| rest) else {
        return Vec::new();
    };
    let Some(arguments) = arguments.split_once(')').map(|(args, _)| args) else {
        return Vec::new();
    };
    let bytes = arguments.as_bytes();
    let mut descriptors = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        while index < bytes.len() && bytes[index] == b'[' {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        if bytes[index] == b'L' {
            if let Some(end) = arguments[index..].find(';') {
                index += end + 1;
            } else {
                break;
            }
        } else {
            index += 1;
        }
        descriptors.push(arguments[start..index].to_string());
    }
    descriptors
}

fn emulation_default_value(descriptor: &str) -> String {
    match descriptor {
        "Z" => "false".to_string(),
        "Ljava/lang/String;" => String::new(),
        d if d.starts_with('[') => "[]".to_string(),
        d if d.starts_with('L') => "new".to_string(),
        _ => "0".to_string(),
    }
}

fn result_row(
    ui: &mut egui::Ui,
    result: &ResultRow,
    display_label: &str,
    selected: bool,
    width: f32,
) -> egui::Response {
    let (title, context) = if let Some((class, member)) = display_label.split_once("->") {
        (member.to_string(), class.to_string())
    } else if result.kind == "class" {
        (
            display_label
                .rsplit('/')
                .next()
                .unwrap_or(display_label)
                .trim_end_matches(';')
                .to_string(),
            display_label.to_string(),
        )
    } else {
        (
            display_label.replace(['\n', '\r'], " "),
            result.kind.clone(),
        )
    };
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 46.0), Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            ui.is_enabled(),
            selected,
            display_label,
        )
    });
    if ui.is_rect_visible(rect) {
        let fill = if selected {
            ui.visuals().selection.bg_fill
        } else if response.hovered() || response.has_focus() {
            theme::RAISED
        } else {
            Color32::TRANSPARENT
        };
        ui.painter().rect_filled(rect, 6, fill);
        if selected {
            ui.painter().rect_filled(
                Rect::from_min_size(rect.min + Vec2::new(0.0, 8.0), Vec2::new(3.0, 30.0)),
                2,
                theme::ACCENT,
            );
        }
        if response.has_focus() {
            ui.painter().rect_stroke(
                rect,
                6,
                Stroke::new(1.0, theme::ACCENT),
                egui::StrokeKind::Inside,
            );
        }
        let title_color = if result.is_alias {
            theme::ACCENT
        } else {
            theme::TEXT
        };
        let context = if result.is_alias {
            format!("alias · {context}")
        } else {
            context
        };
        for (text, font, color, y) in [
            (title, FontId::monospace(12.0), title_color, 6.0),
            (context, FontId::proportional(11.0), theme::MUTED, 25.0),
        ] {
            let galley = egui::WidgetText::from(RichText::new(text).font(font).color(color))
                .into_galley(
                    ui,
                    Some(egui::TextWrapMode::Truncate),
                    (width - 20.0).max(1.0),
                    egui::TextStyle::Body,
                );
            ui.painter()
                .galley(rect.min + Vec2::new(10.0, y), galley, color);
        }
    }
    response
}

fn search_validation(query: &str) -> Result<(), String> {
    if query.trim().is_empty() {
        return Err("Enter a search expression, or .* to show all.".to_string());
    }
    regex::Regex::new(query).map(|_| ()).map_err(|error| {
        format!(
            "Invalid expression: {}",
            error
                .to_string()
                .lines()
                .last()
                .unwrap_or("check the syntax")
        )
    })
}

fn value_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn paint_navigation_arrow(
    ui: &egui::Ui,
    response: &egui::Response,
    points_left: bool,
    enabled: bool,
) {
    let rect = response.rect.shrink2(Vec2::new(8.0, 7.0));
    let center = rect.center();
    let tip = if points_left {
        egui::pos2(rect.left(), center.y)
    } else {
        egui::pos2(rect.right(), center.y)
    };
    let tail = if points_left {
        egui::pos2(rect.right(), center.y)
    } else {
        egui::pos2(rect.left(), center.y)
    };
    let head_top = if points_left {
        egui::pos2(rect.left() + 6.0, rect.top())
    } else {
        egui::pos2(rect.right() - 6.0, rect.top())
    };
    let head_bottom = if points_left {
        egui::pos2(rect.left() + 6.0, rect.bottom())
    } else {
        egui::pos2(rect.right() - 6.0, rect.bottom())
    };
    let color = if enabled {
        ui.visuals().text_color()
    } else {
        ui.visuals().weak_text_color()
    };
    let stroke = Stroke::new(2.0, color);
    let painter = ui.painter();
    painter.line_segment([tip, tail], stroke);
    painter.line_segment([tip, head_top], stroke);
    painter.line_segment([tip, head_bottom], stroke);
}

fn value_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or_default()
}

fn optional_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn annotation_key(kind: &str, label: &str) -> String {
    match kind {
        "method" | "class" | "string" if !label.is_empty() => {
            format!("{kind}:{label}")
        }
        _ => String::new(),
    }
}

fn alias_key(kind: &str, label: &str) -> String {
    match kind {
        "method" | "class" if !label.is_empty() => format!("{kind}:{label}"),
        _ => String::new(),
    }
}

fn method_name_for_search(label: &str) -> String {
    label
        .split_once("->")
        .and_then(|(_, method)| method.split_once('(').map(|(name, _)| name))
        .filter(|name| !name.is_empty())
        .unwrap_or(label)
        .to_string()
}

fn parse_note_location(key: &str) -> Option<(String, String, Option<NoteLocation>)> {
    if let Some(rest) = key.strip_prefix("code:class:") {
        let (label, line) = rest.rsplit_once(":line:")?;
        return Some((
            "code".to_string(),
            label.to_string(),
            Some(NoteLocation::Line(line.parse().ok()?)),
        ));
    }
    if let Some(rest) = key.strip_prefix("code:") {
        if let Some((label, offset)) = rest.rsplit_once(":offset:") {
            return Some((
                "code".to_string(),
                label.to_string(),
                Some(NoteLocation::Offset(u64::from_str_radix(offset, 16).ok()?)),
            ));
        }
        if let Some((label, line)) = rest.rsplit_once(":line:") {
            return Some((
                "code".to_string(),
                label.to_string(),
                Some(NoteLocation::Line(line.parse().ok()?)),
            ));
        }
        return None;
    }
    let (kind, label) = key.split_once(':')?;
    matches!(kind, "method" | "class" | "string")
        .then(|| (kind.to_string(), label.to_string(), None))
}

fn notes_map(data: &Value) -> HashMap<String, String> {
    data.get("notes")
        .and_then(Value::as_object)
        .map(|notes| {
            notes
                .iter()
                .filter_map(|(key, value)| {
                    let note = value.as_str()?.to_string();
                    (!key.trim().is_empty() && !note.trim().is_empty())
                        .then_some((key.clone(), note))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn aliases_map(data: &Value) -> HashMap<String, String> {
    data.get("aliases")
        .and_then(Value::as_object)
        .map(|aliases| {
            aliases
                .iter()
                .filter_map(|(key, value)| {
                    let alias = value.as_str()?.to_string();
                    (!key.trim().is_empty() && !alias.trim().is_empty())
                        .then_some((key.clone(), alias))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn edit_picker_kind(value: &Value) -> Option<SearchKind> {
    match value_string(value, "picker").as_str() {
        "methods" => Some(SearchKind::Methods),
        "classes" => Some(SearchKind::Classes),
        "fields" => Some(SearchKind::Fields),
        "strings" => Some(SearchKind::Strings),
        _ => None,
    }
}

fn result_rows(data: &Value) -> Vec<ResultRow> {
    data.get("results")
        .and_then(Value::as_array)
        .map(|results| {
            results
                .iter()
                .map(|result| {
                    let kind = value_string(result, "kind");
                    let label = value_string(result, "label");
                    let note_key = value_string(result, "note_key");
                    ResultRow {
                        id: value_string(result, "id"),
                        note_key: if note_key.is_empty() {
                            annotation_key(&kind, &label)
                        } else {
                            note_key
                        },
                        kind,
                        label,
                        is_alias: result
                            .get("alias")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn picker_result_rows(data: &Value) -> Vec<EditPickerResult> {
    data.get("results")
        .and_then(Value::as_array)
        .map(|results| {
            results
                .iter()
                .map(|result| EditPickerResult {
                    kind: value_string(result, "kind"),
                    label: value_string(result, "label"),
                    index: optional_u64(result, "index"),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_code_offset(line: &str) -> Option<u64> {
    let start = line.find("#0x").or_else(|| line.find("0x"))?;
    let hex = line[start..]
        .strip_prefix("#0x")
        .or_else(|| line[start..].strip_prefix("0x"))?;
    let digits = hex
        .chars()
        .take_while(|character| character.is_ascii_hexdigit())
        .collect::<String>();
    u64::from_str_radix(&digits, 16).ok()
}

fn highlight_smali_with_alias(line: &str, alias_range: Option<(usize, usize)>) -> LayoutJob {
    let font = FontId::monospace(13.0);
    let mut job = LayoutJob::default();
    let comment_at = line.find('#');
    let code = comment_at.map(|index| &line[..index]).unwrap_or(line);
    let comment = comment_at.map(|index| &line[index..]);
    let mut offset = 0;
    for token in code.split_inclusive(|character: char| character.is_whitespace()) {
        let trimmed = token.trim();
        let color = if trimmed.starts_with('.') {
            Color32::from_rgb(110, 205, 215)
        } else if trimmed.starts_with('v') || trimmed.starts_with('p') {
            Color32::from_rgb(235, 190, 105)
        } else if trimmed.starts_with('L') || trimmed.starts_with('[') {
            Color32::from_rgb(180, 155, 235)
        } else if trimmed.starts_with('"') {
            Color32::from_rgb(145, 210, 140)
        } else {
            Color32::from_rgb(215, 220, 225)
        };
        let token_start = offset;
        let token_end = offset + token.len();
        let overlap = alias_range.and_then(|(start, end)| {
            (start < token_end && end > token_start).then_some((start, end))
        });
        if let Some((start, end)) = overlap {
            let relative_start = start.saturating_sub(token_start).min(token.len());
            let relative_end = end.saturating_sub(token_start).min(token.len());
            if relative_start > 0 {
                job.append(
                    &token[..relative_start],
                    0.0,
                    TextFormat {
                        font_id: font.clone(),
                        color,
                        ..Default::default()
                    },
                );
            }
            if relative_end > relative_start {
                job.append(
                    &token[relative_start..relative_end],
                    0.0,
                    TextFormat {
                        font_id: font.clone(),
                        color: theme::ACCENT,
                        background: Color32::from_rgb(34, 74, 96),
                        ..Default::default()
                    },
                );
            }
            if relative_end < token.len() {
                job.append(
                    &token[relative_end..],
                    0.0,
                    TextFormat {
                        font_id: font.clone(),
                        color,
                        ..Default::default()
                    },
                );
            }
        } else {
            job.append(
                token,
                0.0,
                TextFormat {
                    font_id: font.clone(),
                    color,
                    ..Default::default()
                },
            );
        }
        offset = token_end;
    }
    if let Some(comment) = comment {
        job.append(
            comment,
            0.0,
            TextFormat {
                font_id: font,
                color: Color32::from_rgb(115, 125, 135),
                ..Default::default()
            },
        );
    }
    job
}

fn xml_format(font: &FontId, color: Color32) -> TextFormat {
    TextFormat {
        font_id: font.clone(),
        color,
        ..Default::default()
    }
}

fn append_xml_text(job: &mut LayoutJob, text: &str, font: &FontId) {
    let mut cursor = 0;
    while let Some(relative_start) = text[cursor..].find('&') {
        let start = cursor + relative_start;
        let Some(relative_end) = text[start..].find(';') else {
            break;
        };
        let end = start + relative_end + 1;
        if start > cursor {
            job.append(
                &text[cursor..start],
                0.0,
                xml_format(font, Color32::from_rgb(215, 220, 225)),
            );
        }
        job.append(
            &text[start..end],
            0.0,
            xml_format(font, Color32::from_rgb(245, 190, 105)),
        );
        cursor = end;
    }
    if cursor < text.len() {
        job.append(
            &text[cursor..],
            0.0,
            xml_format(font, Color32::from_rgb(215, 220, 225)),
        );
    }
}

fn append_xml_markup(job: &mut LayoutJob, markup: &str, font: &FontId) {
    let special = markup.starts_with("<!--")
        || markup.starts_with("<![CDATA[")
        || markup.starts_with("<?")
        || markup.starts_with("<!DOCTYPE")
        || markup.starts_with("<!doctype");
    if special {
        job.append(
            markup,
            0.0,
            xml_format(font, Color32::from_rgb(115, 125, 135)),
        );
        return;
    }

    let punctuation = Color32::from_rgb(150, 160, 175);
    let tag_name = Color32::from_rgb(105, 190, 240);
    let attribute = Color32::from_rgb(215, 185, 110);
    let value = Color32::from_rgb(145, 210, 140);
    let mut position = 0;

    if markup.starts_with('<') {
        job.append("<", 0.0, xml_format(font, punctuation));
        position = 1;
    }
    if markup[position..].starts_with('/') {
        job.append("/", 0.0, xml_format(font, punctuation));
        position += 1;
    }

    let name_start = position;
    while position < markup.len() {
        let character = markup[position..].chars().next().unwrap_or_default();
        if character.is_whitespace() || matches!(character, '>' | '/' | '?') {
            break;
        }
        position += character.len_utf8();
    }
    if position > name_start {
        job.append(
            &markup[name_start..position],
            0.0,
            xml_format(font, tag_name),
        );
    }

    while position < markup.len() {
        let character = markup[position..].chars().next().unwrap_or_default();
        if character == '"' || character == '\'' {
            let quote = character;
            let value_start = position;
            position += character.len_utf8();
            while position < markup.len() {
                let next = markup[position..].chars().next().unwrap_or_default();
                position += next.len_utf8();
                if next == quote {
                    break;
                }
            }
            job.append(&markup[value_start..position], 0.0, xml_format(font, value));
        } else if character.is_whitespace() {
            let whitespace_start = position;
            position += character.len_utf8();
            while position < markup.len() {
                let next = markup[position..].chars().next().unwrap_or_default();
                if !next.is_whitespace() {
                    break;
                }
                position += next.len_utf8();
            }
            job.append(
                &markup[whitespace_start..position],
                0.0,
                xml_format(font, Color32::from_rgb(215, 220, 225)),
            );
        } else if matches!(character, '>' | '/' | '?' | '=') {
            job.append(
                &markup[position..position + character.len_utf8()],
                0.0,
                xml_format(font, punctuation),
            );
            position += character.len_utf8();
        } else {
            let attribute_start = position;
            position += character.len_utf8();
            while position < markup.len() {
                let next = markup[position..].chars().next().unwrap_or_default();
                if next.is_whitespace() || matches!(next, '>' | '/' | '?' | '=') {
                    break;
                }
                position += next.len_utf8();
            }
            job.append(
                &markup[attribute_start..position],
                0.0,
                xml_format(font, attribute),
            );
        }
    }
}

fn find_xml_markup_end(source: &str, start: usize) -> Option<usize> {
    let rest = &source[start..];
    if rest.starts_with("<!--") {
        return rest.find("-->").map(|end| start + end + 3);
    }
    if rest.starts_with("<![CDATA[") {
        return rest.find("]]>").map(|end| start + end + 3);
    }
    if rest.starts_with("<?") {
        return rest.find("?>").map(|end| start + end + 2);
    }

    let mut quote = None;
    for (offset, character) in rest.char_indices().skip(1) {
        match (quote, character) {
            (Some(expected), character) if character == expected => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (None, '>') => return Some(start + offset + 1),
            _ => {}
        }
    }
    None
}

fn highlight_xml(source: &str) -> LayoutJob {
    let font = FontId::monospace(12.0);
    let mut job = LayoutJob::default();
    let mut cursor = 0;
    while cursor < source.len() {
        let Some(relative_start) = source[cursor..].find('<') else {
            append_xml_text(&mut job, &source[cursor..], &font);
            break;
        };
        let start = cursor + relative_start;
        if start > cursor {
            append_xml_text(&mut job, &source[cursor..start], &font);
        }
        let end = find_xml_markup_end(source, start).unwrap_or(source.len());
        append_xml_markup(&mut job, &source[start..end], &font);
        cursor = end;
    }
    job
}

fn format_xml(source: &str) -> Result<String, String> {
    let mut formatted = String::new();
    let mut cursor = 0;
    let mut indent = 0usize;
    let mut saw_markup = false;

    while cursor < source.len() {
        if source[cursor..].starts_with('<') {
            let end = find_xml_markup_end(source, cursor)
                .ok_or_else(|| "unterminated XML markup".to_string())?;
            let token = source[cursor..end].trim();
            if token.is_empty() {
                cursor = end;
                continue;
            }
            if token.starts_with("</") {
                indent = indent.saturating_sub(1);
            }
            if !formatted.is_empty() {
                formatted.push('\n');
            }
            formatted.push_str(&"  ".repeat(indent));
            formatted.push_str(token);
            saw_markup = true;

            let closing = token.starts_with("</")
                || token.starts_with("<?")
                || token.starts_with("<!--")
                || token.starts_with("<![CDATA[")
                || token.starts_with("<!DOCTYPE")
                || token.starts_with("<!doctype");
            let self_closing = token.ends_with("/>") || token.ends_with("?>");
            if !closing && !self_closing {
                indent += 1;
            }
            cursor = end;
        } else {
            let end = source[cursor..]
                .find('<')
                .map(|offset| cursor + offset)
                .unwrap_or(source.len());
            let text = source[cursor..end]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if !text.is_empty() {
                if !formatted.is_empty() && !formatted.ends_with('\n') {
                    formatted.push(' ');
                }
                formatted.push_str(&text);
            }
            cursor = end;
        }
    }

    if !saw_markup {
        return Err("no XML elements found".to_string());
    }
    Ok(formatted)
}

fn parse_dot(dot: &str) -> (Vec<(usize, String)>, Vec<(usize, usize)>, usize, usize) {
    let mut nodes = Vec::new();
    let mut parsed_edges = Vec::new();
    let mut known = HashSet::new();
    let mut total_nodes = 0;
    let mut total_edges = 0;
    for line in dot.lines() {
        let trimmed = line.trim();
        if let Some((left, right)) = trimmed.split_once("->") {
            if let (Some(from), Some(to)) = (parse_dot_id(left), parse_dot_id(right)) {
                total_edges += 1;
                parsed_edges.push((from, to));
                continue;
            }
        }
        if trimmed.starts_with("digraph") || trimmed == "{" || trimmed == "}" {
            continue;
        }
        let Some(id) = parse_dot_id(trimmed) else {
            continue;
        };
        let Some(label) = parse_dot_label(trimmed) else {
            continue;
        };
        total_nodes += 1;
        if known.insert(id) {
            nodes.push((id, label));
        }
    }
    nodes.sort_by_key(|(id, _)| *id);
    let edges = parsed_edges
        .into_iter()
        .filter(|(from, to)| known.contains(from) && known.contains(to))
        .collect();
    (nodes, edges, total_nodes, total_edges)
}

fn parse_dot_id(value: &str) -> Option<usize> {
    let value = value
        .trim_start()
        .strip_prefix('"')
        .unwrap_or(value.trim_start());
    let digits = value
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn graph_edge_index(edges: &[(usize, usize)]) -> HashMap<usize, Vec<(usize, usize)>> {
    let mut index = HashMap::new();
    for &(from, to) in edges {
        index.entry(from).or_insert_with(Vec::new).push((from, to));
        if from != to {
            index.entry(to).or_insert_with(Vec::new).push((from, to));
        }
    }
    index
}

fn label_for_node<'a>(
    id: usize,
    node_index: &HashMap<usize, usize>,
    nodes: &'a [(usize, String)],
) -> Option<&'a str> {
    node_index
        .get(&id)
        .and_then(|index| nodes.get(*index))
        .map(|(_, label)| label.as_str())
}

const GRAPH_LAYOUT_CELL_SIZE: f32 = 800.0;
const GRAPH_NODE_SIZE: Vec2 = Vec2::new(280.0, 84.0);
const MAX_RENDERED_GRAPH_NODES: usize = 5_000;
const MAX_RENDERED_GRAPH_EDGES: usize = 12_000;

fn graph_layout_index(
    nodes: &[(usize, String)],
    layout: &HashMap<usize, Vec2>,
) -> HashMap<(i32, i32), Vec<usize>> {
    let mut index = HashMap::new();
    for (id, _) in nodes {
        let Some(position) = layout.get(id) else {
            continue;
        };
        let cell = (
            (position.x / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
            (position.y / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
        );
        index.entry(cell).or_insert_with(Vec::new).push(*id);
    }
    index
}

fn graph_layout_edge_index(
    edges: &[(usize, usize)],
    layout: &HashMap<usize, Vec2>,
) -> (
    HashMap<(i32, i32), Vec<(usize, usize)>>,
    Vec<(usize, usize)>,
) {
    const MAX_INDEXED_CELLS_PER_EDGE: i64 = 128;
    let mut index = HashMap::new();
    let mut long_edges = Vec::new();
    for &(from, to) in edges {
        let (Some(from_position), Some(to_position)) = (layout.get(&from), layout.get(&to)) else {
            continue;
        };
        let min_position = from_position.min(*to_position);
        let max_position = from_position.max(*to_position);
        let min_cell = (
            (min_position.x / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
            (min_position.y / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
        );
        let max_cell = (
            (max_position.x / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
            (max_position.y / GRAPH_LAYOUT_CELL_SIZE).floor() as i32,
        );
        let cell_count =
            i64::from(max_cell.0 - min_cell.0 + 1) * i64::from(max_cell.1 - min_cell.1 + 1);
        if cell_count > MAX_INDEXED_CELLS_PER_EDGE {
            long_edges.push((from, to));
            continue;
        }
        for cell_y in min_cell.1..=max_cell.1 {
            for cell_x in min_cell.0..=max_cell.0 {
                index
                    .entry((cell_x, cell_y))
                    .or_insert_with(Vec::new)
                    .push((from, to));
            }
        }
    }
    (index, long_edges)
}

fn parse_dot_label(line: &str) -> Option<String> {
    let label_start = line.find("label")?;
    let attribute = &line[label_start + "label".len()..];
    let equals = attribute.find('=')?;
    let value = attribute[equals + 1..].trim_start();
    let mut characters = value.chars();
    if characters.next()? != '"' {
        return None;
    }
    let mut label = String::new();
    let mut escaped = false;
    for character in characters {
        if escaped {
            label.push(match character {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(label);
        } else {
            label.push(character);
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum GraphNodeKind {
    Method,
    Class,
    Field,
    String,
    Type,
    Static,
    Dynamic,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum GraphEdgeKind {
    Call,
    Argument,
    Return,
    Data,
}

fn all_graph_edge_kinds() -> [GraphEdgeKind; 4] {
    [
        GraphEdgeKind::Call,
        GraphEdgeKind::Argument,
        GraphEdgeKind::Return,
        GraphEdgeKind::Data,
    ]
}

impl GraphEdgeKind {
    fn label(self) -> &'static str {
        match self {
            Self::Call => "function call",
            Self::Argument => "argument",
            Self::Return => "return",
            Self::Data => "data",
        }
    }
}

fn all_graph_node_kinds() -> [GraphNodeKind; 8] {
    [
        GraphNodeKind::Method,
        GraphNodeKind::Class,
        GraphNodeKind::Field,
        GraphNodeKind::String,
        GraphNodeKind::Type,
        GraphNodeKind::Static,
        GraphNodeKind::Dynamic,
        GraphNodeKind::Other,
    ]
}

impl GraphNodeKind {
    fn label(self) -> &'static str {
        match self {
            Self::Method => "method",
            Self::Class => "class",
            Self::Field => "field",
            Self::String => "string",
            Self::Type => "type",
            Self::Static => "static",
            Self::Dynamic => "dynamic",
            Self::Other => "node",
        }
    }
}

fn graph_node_kind(label: &str) -> GraphNodeKind {
    if label.contains("method:") {
        GraphNodeKind::Method
    } else if label.contains("class:") {
        GraphNodeKind::Class
    } else if label.contains("field:") {
        GraphNodeKind::Field
    } else if label.contains("string:") {
        GraphNodeKind::String
    } else if label.contains("type:") {
        GraphNodeKind::Type
    } else if label.contains("static_argument:") {
        GraphNodeKind::Static
    } else if label.contains("dynamic_argument:") || label.contains("dynamic_return:") {
        GraphNodeKind::Dynamic
    } else {
        GraphNodeKind::Other
    }
}

fn graph_info_value(label: &str, key: &str) -> Option<String> {
    let marker = format!("{key}:");
    let start = label.find(&marker)? + marker.len();
    let value = label[start..].trim_start();
    if let Some(value) = value.strip_prefix('"') {
        let mut result = String::new();
        let mut escaped = false;
        for character in value.chars() {
            if escaped {
                result.push(match character {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    other => other,
                });
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                return Some(result);
            } else {
                result.push(character);
            }
        }
        Some(result)
    } else {
        Some(
            value
                .trim_end_matches('}')
                .trim_end_matches(',')
                .trim()
                .to_string(),
        )
    }
}

fn graph_type_display(value: &str, compact: bool) -> String {
    let value = value.trim();
    let (prefix, descriptor) = if let Some(descriptor) = value.strip_prefix("[") {
        ("[]", descriptor)
    } else {
        ("", value)
    };
    let descriptor = descriptor
        .strip_prefix('L')
        .and_then(|value| value.strip_suffix(';'))
        .unwrap_or(descriptor)
        .replace('/', ".");
    let descriptor = if compact {
        descriptor.rsplit('.').next().unwrap_or(&descriptor)
    } else {
        &descriptor
    };
    format!("{prefix}{descriptor}")
}

fn graph_display_label(label: &str, kind: GraphNodeKind, compact: bool) -> String {
    let value = match kind {
        GraphNodeKind::Method => graph_info_value(label, "method"),
        GraphNodeKind::Class => graph_info_value(label, "class"),
        GraphNodeKind::Field => graph_info_value(label, "field"),
        GraphNodeKind::String => graph_info_value(label, "string"),
        GraphNodeKind::Type => graph_info_value(label, "type"),
        GraphNodeKind::Static => graph_info_value(label, "static_argument"),
        GraphNodeKind::Dynamic => graph_info_value(label, "dynamic_argument")
            .or_else(|| graph_info_value(label, "dynamic_return")),
        GraphNodeKind::Other => None,
    };
    let Some(value) = value else {
        return label.to_string();
    };
    match kind {
        GraphNodeKind::Method => {
            if let Some((class, method)) = value.split_once("->") {
                let method = method.split('(').next().unwrap_or(method);
                format!("{}.{}()", graph_type_display(class, compact), method)
            } else {
                value
            }
        }
        GraphNodeKind::Field => {
            if let Some((class, field)) = value.split_once("->") {
                let field = field.split(':').next().unwrap_or(field);
                format!("{}.{}", graph_type_display(class, compact), field)
            } else {
                value
            }
        }
        GraphNodeKind::Class | GraphNodeKind::Type => graph_type_display(&value, compact),
        _ => value,
    }
}

fn graph_search_matches(
    nodes: &[(usize, String)],
    filters: &HashSet<GraphNodeKind>,
    query: &str,
) -> Vec<(usize, String, String)> {
    let query = query.to_ascii_lowercase();
    if query.is_empty() {
        return Vec::new();
    }
    let mut matches = nodes
        .iter()
        .filter_map(|(id, label)| {
            let kind = graph_node_kind(label);
            if !filters.contains(&kind) {
                return None;
            }
            let display = graph_display_label(label, kind, false);
            let compact = graph_display_label(label, kind, true);
            let display_lower = display.to_ascii_lowercase();
            let compact_lower = compact.to_ascii_lowercase();
            let label_lower = label.to_ascii_lowercase();
            let score = if display_lower == query || compact_lower == query {
                0
            } else if display_lower.starts_with(&query) || compact_lower.starts_with(&query) {
                1
            } else if display_lower.contains(&query) || compact_lower.contains(&query) {
                2
            } else if label_lower.contains(&query) {
                3
            } else {
                return None;
            };
            Some((score, *id, display, label.clone()))
        })
        .collect::<Vec<_>>();
    matches.sort_by_key(|(score, id, _, _)| (*score, *id));
    matches
        .into_iter()
        .map(|(_, id, display, label)| (id, display, label))
        .collect()
}

fn is_argument_node(label: &str) -> bool {
    label.contains("static_argument:")
        || label.contains("dynamic_argument:")
        || label.contains("array:")
}

fn is_return_node(label: &str) -> bool {
    label.contains("dynamic_return:")
}

fn graph_edge_kind(from: &str, to: &str) -> GraphEdgeKind {
    if graph_node_kind(from) == GraphNodeKind::Method
        && graph_node_kind(to) == GraphNodeKind::Method
    {
        GraphEdgeKind::Call
    } else if is_argument_node(from) || is_argument_node(to) {
        GraphEdgeKind::Argument
    } else if is_return_node(from) {
        GraphEdgeKind::Return
    } else {
        GraphEdgeKind::Data
    }
}

fn graph_edge_style(kind: GraphEdgeKind) -> (Color32, f32) {
    match kind {
        GraphEdgeKind::Call => (Color32::from_rgb(90, 190, 255), 2.8),
        GraphEdgeKind::Argument => (Color32::from_rgb(245, 170, 75), 2.4),
        GraphEdgeKind::Return => (Color32::from_rgb(105, 220, 155), 2.4),
        GraphEdgeKind::Data => (Color32::from_rgb(145, 155, 170), 1.8),
    }
}

fn graph_node_colors(kind: GraphNodeKind) -> (Color32, Color32) {
    match kind {
        GraphNodeKind::Method => (
            Color32::from_rgb(35, 92, 135),
            Color32::from_rgb(125, 195, 235),
        ),
        GraphNodeKind::Class => (
            Color32::from_rgb(88, 66, 135),
            Color32::from_rgb(190, 155, 245),
        ),
        GraphNodeKind::Field => (
            Color32::from_rgb(125, 87, 35),
            Color32::from_rgb(240, 190, 105),
        ),
        GraphNodeKind::String => (
            Color32::from_rgb(35, 105, 72),
            Color32::from_rgb(125, 220, 165),
        ),
        GraphNodeKind::Type => (
            Color32::from_rgb(35, 105, 105),
            Color32::from_rgb(120, 220, 220),
        ),
        GraphNodeKind::Static => (
            Color32::from_rgb(105, 65, 100),
            Color32::from_rgb(220, 145, 205),
        ),
        GraphNodeKind::Dynamic => (
            Color32::from_rgb(125, 61, 42),
            Color32::from_rgb(240, 145, 110),
        ),
        GraphNodeKind::Other => (
            Color32::from_rgb(60, 70, 80),
            Color32::from_rgb(155, 170, 185),
        ),
    }
}

fn paint_graph_node(
    painter: &egui::Painter,
    rect: Rect,
    kind: GraphNodeKind,
    fill: Color32,
    stroke: Color32,
) {
    let outline = Stroke::new(1.2, stroke);
    let center = rect.center();
    let half = rect.size() / 2.0;
    match kind {
        GraphNodeKind::Class => {
            painter.add(egui::Shape::convex_polygon(
                vec![
                    center + Vec2::new(0.0, -half.y),
                    center + Vec2::new(half.x, 0.0),
                    center + Vec2::new(0.0, half.y),
                    center + Vec2::new(-half.x, 0.0),
                ],
                fill,
                outline,
            ));
        }
        GraphNodeKind::Field => {
            painter.add(egui::Shape::ellipse_filled(center, half, fill));
            painter.add(egui::Shape::ellipse_stroke(center, half, outline));
        }
        GraphNodeKind::String => {
            let diagonal = half.x * 0.25;
            painter.add(egui::Shape::convex_polygon(
                vec![
                    center + Vec2::new(-half.x + diagonal, -half.y),
                    center + Vec2::new(half.x - diagonal, -half.y),
                    center + Vec2::new(half.x, 0.0),
                    center + Vec2::new(half.x - diagonal, half.y),
                    center + Vec2::new(-half.x + diagonal, half.y),
                    center + Vec2::new(-half.x, 0.0),
                ],
                fill,
                outline,
            ));
        }
        GraphNodeKind::Type => {
            painter.add(egui::Shape::ellipse_filled(center, half, fill));
            painter.add(egui::Shape::ellipse_stroke(center, half, outline));
        }
        GraphNodeKind::Static | GraphNodeKind::Dynamic => {
            painter.rect_filled(rect, 14.0, fill);
            painter.rect_stroke(rect, 14.0, outline, egui::StrokeKind::Outside);
        }
        GraphNodeKind::Method | GraphNodeKind::Other => {
            painter.rect_filled(rect, 7.0, fill);
            painter.rect_stroke(rect, 7.0, outline, egui::StrokeKind::Outside);
        }
    }
}

fn layout_bounds(
    node_ids: impl IntoIterator<Item = usize>,
    layout: &HashMap<usize, Vec2>,
    node_size: Vec2,
) -> (Vec2, Vec2) {
    let mut min = Vec2::splat(f32::INFINITY);
    let mut max = Vec2::splat(f32::NEG_INFINITY);
    for id in node_ids {
        let Some(position) = layout.get(&id) else {
            continue;
        };
        let half = node_size / 2.0;
        min.x = min.x.min(position.x - half.x);
        min.y = min.y.min(position.y - half.y);
        max.x = max.x.max(position.x + half.x);
        max.y = max.y.max(position.y + half.y);
    }
    if min.x.is_infinite() {
        (Vec2::ZERO, node_size)
    } else {
        (min, max)
    }
}

fn rect_boundary_point(rect: Rect, direction: Vec2) -> egui::Pos2 {
    let direction = direction.normalized();
    let half = rect.size() / 2.0;
    let horizontal = if direction.x.abs() > f32::EPSILON {
        half.x / direction.x.abs()
    } else {
        f32::INFINITY
    };
    let vertical = if direction.y.abs() > f32::EPSILON {
        half.y / direction.y.abs()
    } else {
        f32::INFINITY
    };
    rect.center() + direction * horizontal.min(vertical)
}

fn distance_to_segment(point: egui::Pos2, start: egui::Pos2, end: egui::Pos2) -> f32 {
    let segment = end - start;
    let length_sq = segment.length_sq();
    if length_sq <= f32::EPSILON {
        return point.distance(start);
    }
    let fraction = ((point - start).dot(segment) / length_sq).clamp(0.0, 1.0);
    point.distance(start + segment * fraction)
}

fn graph_scroll_zoom(input: &mut egui::InputState, viewport: Rect) -> f32 {
    if !input.modifiers.command
        || !input
            .pointer
            .hover_pos()
            .is_some_and(|point| viewport.contains(point))
    {
        return 1.0;
    }
    // Read the wheel directly: egui's zoom_delta also includes pinch gestures
    // and smoothed zoom tails, which are not the Cmd+scroll interaction.
    let delta = input.raw_scroll_delta.y;
    input.raw_scroll_delta = Vec2::ZERO;
    input.smooth_scroll_delta = Vec2::ZERO;
    (delta * 0.005).clamp(-2.0, 2.0).exp()
}

fn minimap_graph_position(pointer: egui::Pos2, inner: Rect, min: Vec2, max: Vec2) -> Vec2 {
    let fraction = ((pointer - inner.min) / inner.size()).clamp(Vec2::ZERO, Vec2::splat(1.0));
    min + fraction * (max - min).max(Vec2::splat(1.0))
}

fn graph_center_offset(target: Vec2, min: Vec2, zoom: f32, viewport: Vec2, content: Vec2) -> Vec2 {
    ((target - min) * zoom + Vec2::splat(40.0) - viewport / 2.0)
        .clamp(Vec2::ZERO, (content - viewport).max(Vec2::ZERO))
}

fn layout_clustered_graph(
    nodes: &[(usize, String)],
    edges: &[(usize, usize)],
) -> HashMap<usize, Vec2> {
    if nodes.is_empty() {
        return HashMap::new();
    }

    // Supergraphs are heterogeneous and cyclic, so a rank-by-edge-direction
    // layout creates very deep, mostly meaningless layers. Build connected
    // components instead, then place each component on concentric BFS rings.
    // This is linear in nodes + edges, deterministic, and keeps related nodes
    // together without making all methods/classes share one coordinate band.
    let mut indices = HashMap::with_capacity(nodes.len());
    for (index, (id, _)) in nodes.iter().enumerate() {
        indices.insert(*id, index);
    }
    let mut adjacency = vec![Vec::new(); nodes.len()];
    for (from, to) in edges {
        let (Some(&from), Some(&to)) = (indices.get(from), indices.get(to)) else {
            continue;
        };
        if from == to {
            continue;
        }
        adjacency[from].push(to);
        adjacency[to].push(from);
    }

    let mut visited = vec![false; nodes.len()];
    let mut components = Vec::new();
    for start in 0..nodes.len() {
        if visited[start] {
            continue;
        }
        let mut component = Vec::new();
        let mut queue = VecDeque::from([start]);
        visited[start] = true;
        while let Some(index) = queue.pop_front() {
            component.push(index);
            for &neighbor in &adjacency[index] {
                if !visited[neighbor] {
                    visited[neighbor] = true;
                    queue.push_back(neighbor);
                }
            }
        }

        let mut anchor = component[0];
        for &candidate in &component[1..] {
            let candidate_key = (
                adjacency[candidate].len(),
                std::cmp::Reverse(nodes[candidate].0),
            );
            let anchor_key = (adjacency[anchor].len(), std::cmp::Reverse(nodes[anchor].0));
            if candidate_key > anchor_key {
                anchor = candidate;
            }
        }

        let mut distances = HashMap::with_capacity(component.len());
        let mut levels = Vec::<Vec<usize>>::new();
        let mut level_queue = VecDeque::from([anchor]);
        distances.insert(anchor, 0);
        while let Some(index) = level_queue.pop_front() {
            let distance = distances[&index];
            if levels.len() <= distance {
                levels.push(Vec::new());
            }
            levels[distance].push(index);
            for &neighbor in &adjacency[index] {
                if !distances.contains_key(&neighbor) {
                    distances.insert(neighbor, distance + 1);
                    level_queue.push_back(neighbor);
                }
            }
        }

        let mut local = HashMap::with_capacity(component.len());
        local.insert(anchor, Vec2::ZERO);
        let pi = std::f32::consts::PI;
        let mut previous_radius = 0.0_f32;
        for (distance, level) in levels.iter().enumerate().skip(1) {
            let count = level.len();
            // Chord distance, rather than arc length, preserves the gap even
            // in small rings. Each ring must also clear the previous ring.
            let required_radius = if count > 1 {
                300.0 / (2.0 * (pi / count as f32).sin())
            } else {
                0.0
            };
            let radius = (previous_radius + 300.0).max(360.0).max(required_radius);
            previous_radius = radius;
            let offset = if distance % 2 == 0 {
                0.0
            } else {
                pi / count.max(1) as f32
            };
            for (position, &index) in level.iter().enumerate() {
                let angle = offset + 2.0 * pi * position as f32 / count.max(1) as f32;
                local.insert(index, Vec2::new(angle.cos() * radius, angle.sin() * radius));
            }
        }

        let mut min = Vec2::splat(f32::INFINITY);
        let mut max = Vec2::splat(f32::NEG_INFINITY);
        for &index in &component {
            let position = local.get(&index).copied().unwrap_or_default();
            min = min.min(position);
            max = max.max(position);
        }
        components.push((
            component.len(),
            component
                .into_iter()
                .map(|index| {
                    (
                        nodes[index].0,
                        local.get(&index).copied().unwrap_or_default(),
                    )
                })
                .collect::<Vec<_>>(),
            min,
            max,
        ));
    }

    // Pack components into rows after laying them out locally. Sorting large
    // components first prevents one giant component from leaving unusable
    // holes in the canvas.
    components.sort_by(|left, right| right.0.cmp(&left.0));
    let mut positions = HashMap::with_capacity(nodes.len());
    let mut cursor = Vec2::ZERO;
    let mut row_height: f32 = 0.0;
    let max_row_width = 6000.0;
    let component_gap = 80.0;
    for (_, component, min, max) in components {
        let size = max - min;
        // `min` and `max` describe node centers. Add exactly one node's
        // extent here so packed components clear one another without the
        // large double-padding that previously made the graph feel sparse.
        let width = size.x + GRAPH_NODE_SIZE.x;
        let height = size.y + GRAPH_NODE_SIZE.y;
        if cursor.x > 0.0 && cursor.x + width > max_row_width {
            cursor.x = 0.0;
            cursor.y += row_height + component_gap;
            row_height = 0.0;
        }
        for (id, position) in component {
            positions.insert(id, cursor + position - min + GRAPH_NODE_SIZE / 2.0);
        }
        cursor.x += width + component_gap;
        row_height = row_height.max(height);
    }
    positions
}

fn layout_graph(nodes: &[(usize, String)], edges: &[(usize, usize)]) -> HashMap<usize, Vec2> {
    let node_count = nodes.len();
    if node_count == 0 {
        return HashMap::new();
    }
    let mut indices = HashMap::new();
    for (index, (id, _)) in nodes.iter().enumerate() {
        indices.insert(*id, index);
    }
    let mut outgoing = vec![Vec::new(); node_count];
    let mut indegree = vec![0usize; node_count];
    for (from, to) in edges {
        let (Some(&from), Some(&to)) = (indices.get(from), indices.get(to)) else {
            continue;
        };
        outgoing[from].push(to);
        indegree[to] += 1;
    }

    // Rank nodes by directed flow. Kahn's algorithm gives a longest-path rank
    // for the acyclic portion of the graph, while the fallback below places
    // cyclic components in layers without letting a cycle grow forever.
    let mut ranks = vec![0usize; node_count];
    let mut queue = VecDeque::new();
    for (index, degree) in indegree.iter().enumerate() {
        if *degree == 0 {
            queue.push_back(index);
        }
    }
    let mut processed = vec![false; node_count];
    while let Some(index) = queue.pop_front() {
        processed[index] = true;
        for &child in &outgoing[index] {
            ranks[child] = ranks[child].max(ranks[index] + 1);
            indegree[child] -= 1;
            if indegree[child] == 0 {
                queue.push_back(child);
            }
        }
    }

    // A call graph can contain recursive calls. Traverse each remaining
    // component once and assign ranks in the direction of its edges; the edge
    // closing the cycle is intentionally allowed to point back upward.
    let mut visited = vec![false; node_count];
    for start in 0..node_count {
        if processed[start] || visited[start] {
            continue;
        }
        let mut component = VecDeque::from([start]);
        visited[start] = true;
        while let Some(index) = component.pop_front() {
            for &child in &outgoing[index] {
                if !processed[child] && !visited[child] {
                    ranks[child] = ranks[child].max(ranks[index] + 1);
                    visited[child] = true;
                    component.push_back(child);
                }
            }
        }
    }

    let max_rank = ranks.iter().copied().max().unwrap_or(0);
    let mut layers = vec![Vec::new(); max_rank + 1];
    for (index, rank) in ranks.into_iter().enumerate() {
        layers[rank].push(index);
    }

    let horizontal_spacing = 320.0;
    let vertical_spacing = 150.0;
    let mut positions = vec![Vec2::ZERO; node_count];
    for (rank, layer) in layers.iter().enumerate() {
        let width = layer.len().saturating_sub(1) as f32 * horizontal_spacing;
        for (column, &index) in layer.iter().enumerate() {
            positions[index] = Vec2::new(
                column as f32 * horizontal_spacing - width / 2.0,
                rank as f32 * vertical_spacing,
            );
        }
    }

    nodes
        .iter()
        .enumerate()
        .map(|(index, (id, _))| (*id, positions[index]))
        .collect()
}

fn shorten(value: &str, max: usize) -> String {
    let value = value.replace("\\n", " ");
    if value.chars().count() <= max {
        return value;
    }
    format!(
        "{}…",
        value
            .chars()
            .take(max.saturating_sub(1))
            .collect::<String>()
    )
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([950.0, 650.0]),
        hardware_acceleration: eframe::HardwareAcceleration::Preferred,
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };
    eframe::run_native(
        "Coeus Explorer",
        options,
        Box::new(|context| Ok(Box::new(CoeusApp::new(context)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimap_click_and_drag_navigate_without_moving_the_overlay() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = CoeusApp::with_bridge(Err("No backend needed for rendering".to_string()));
        app.graph.nodes = (0..12).map(|id| (id, format!("node {id}"))).collect();
        app.graph.node_index = app
            .graph
            .nodes
            .iter()
            .enumerate()
            .map(|(index, (id, _))| (*id, index))
            .collect();
        app.graph.edges = (0..11).map(|id| (id, id + 1)).collect();
        app.graph.kind = "callgraph".to_string();
        app.graph.fit_to_view = false;
        app.graph.zoom = 1.0;
        app.rebuild_graph_layout();
        let mut time = 0.0;
        let mut render = |events: Vec<egui::Event>| {
            time += 0.02;
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(800.0, 600.0),
                    )),
                    time: Some(time),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| app.render_graph_canvas(ui));
                },
            );
            let rects = output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Rect(rect) => Some(rect),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let map = rects
                .iter()
                .find(|rect| rect.fill == Color32::from_rgba_unmultiplied(18, 20, 24, 235))
                .unwrap()
                .rect;
            let visible = rects
                .iter()
                .find(|rect| rect.stroke == Stroke::new(1.2, Color32::WHITE))
                .unwrap()
                .rect;
            (map, visible)
        };
        render(vec![]);
        let (map, initial) = render(vec![]);
        let target = map.min + map.size() * Vec2::new(0.5, 0.75);
        let button = |pos, pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        render(vec![
            egui::Event::PointerMoved(target),
            button(target, true),
        ]);
        render(vec![button(target, false)]);
        let (after_map, after_click) = render(vec![]);
        assert_eq!(
            map, after_map,
            "the minimap must remain anchored while panning"
        );
        assert!(
            after_click.center().y > initial.center().y + 20.0,
            "click should pan toward the selected part of the graph"
        );

        let drag_target = map.min + map.size() * Vec2::new(0.5, 0.25);
        render(vec![
            egui::Event::PointerMoved(target),
            button(target, true),
        ]);
        render(vec![egui::Event::PointerMoved(drag_target)]);
        render(vec![button(drag_target, false)]);
        let (after_map, after_drag) = render(vec![]);
        assert_eq!(map, after_map);
        assert!(after_drag.center().y < after_click.center().y - 20.0);
        assert!(
            app.graph_node_details.is_none(),
            "minimap clicks must not open nodes underneath"
        );
    }

    #[test]
    fn supergraph_rings_clear_large_previous_levels() {
        let nodes = (0..32)
            .map(|id| (id, format!("node {id}")))
            .collect::<Vec<_>>();
        let mut edges = (1..31).map(|id| (0, id)).collect::<Vec<_>>();
        edges.push((1, 31));
        let layout = layout_clustered_graph(&nodes, &edges);
        let center = layout[&0];
        let first_radius = (layout[&1] - center).length();
        let second_radius = (layout[&31] - center).length();
        assert!(second_radius >= first_radius + 299.0);
        for left in 0..32 {
            for right in left + 1..32 {
                assert!((layout[&left] - layout[&right]).length() >= 299.0);
            }
        }
    }

    #[test]
    fn minimap_navigation_maps_and_clamps_canvas_offsets() {
        let inner = Rect::from_min_size(egui::pos2(10.0, 20.0), Vec2::new(200.0, 100.0));
        let min = Vec2::new(-500.0, -200.0);
        let max = Vec2::new(1500.0, 800.0);
        let target = minimap_graph_position(inner.center(), inner, min, max);
        assert_eq!(target, Vec2::new(500.0, 300.0));
        assert_eq!(
            minimap_graph_position(inner.min - Vec2::splat(20.0), inner, min, max),
            min
        );
        let viewport = Vec2::new(500.0, 300.0);
        let content = Vec2::new(2080.0, 1080.0);
        assert_eq!(
            graph_center_offset(target, min, 1.0, viewport, content),
            Vec2::new(790.0, 390.0)
        );
        assert_eq!(
            graph_center_offset(min, min, 1.0, viewport, content),
            Vec2::ZERO
        );
        assert_eq!(
            graph_center_offset(max, min, 1.0, viewport, content),
            content - viewport
        );
        assert_eq!(
            graph_center_offset(target, min, 0.1, viewport, viewport),
            Vec2::ZERO
        );
    }

    #[test]
    fn command_wheel_zooms_only_inside_graph_and_consumes_scroll() {
        let viewport = Rect::from_min_size(egui::pos2(100.0, 100.0), Vec2::splat(300.0));
        for (command, pointer, delta, should_zoom) in [
            (true, viewport.center(), 120.0, true),
            (true, viewport.center(), -120.0, true),
            (false, viewport.center(), 120.0, false),
            (true, egui::pos2(20.0, 20.0), 120.0, false),
        ] {
            let ctx = egui::Context::default();
            let modifiers = egui::Modifiers {
                command,
                ..Default::default()
            };
            let input = egui::RawInput {
                modifiers,
                events: vec![
                    egui::Event::PointerMoved(pointer),
                    egui::Event::MouseWheel {
                        unit: egui::MouseWheelUnit::Point,
                        delta: Vec2::new(0.0, delta),
                        modifiers,
                    },
                ],
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                ctx.input_mut(|input| {
                    let factor = graph_scroll_zoom(input, viewport);
                    if should_zoom {
                        assert!((factor - (delta * 0.005).exp()).abs() < 0.0001);
                        assert_eq!(input.raw_scroll_delta, Vec2::ZERO);
                        assert_eq!(input.smooth_scroll_delta, Vec2::ZERO);
                    } else {
                        assert_eq!(factor, 1.0);
                        assert_eq!(input.raw_scroll_delta.y, delta);
                    }
                })
            });
        }
    }

    #[test]
    fn parses_petgraph_labels_containing_arrows() {
        let dot = r#"digraph {
    0 [ label = "InfoNode { method: \"Lfoo/Bar;->run()V\" }" ]
    1 [ label = "InfoNode { class: \"Lfoo/Bar;\" }" ]
    0 -> 1 [ label = "1" ]
}"#;
        let (nodes, edges, total_nodes, total_edges) = parse_dot(dot);
        assert_eq!(nodes.len(), 2);
        assert_eq!(edges, vec![(0, 1)]);
        assert_eq!(total_nodes, 2);
        assert_eq!(total_edges, 1);
        assert!(nodes[0].1.contains("Lfoo/Bar;->run()V"));
    }

    #[test]
    fn parses_nodes_beyond_the_interactive_render_limit() {
        let mut dot = String::from("digraph {\n");
        for id in 0..601 {
            dot.push_str(&format!("{id} [ label = \"node-{id}\" ]\n"));
        }
        dot.push_str("0 -> 600 [ label = \"1\" ]\n}");

        let (nodes, edges, total_nodes, total_edges) = parse_dot(&dot);
        assert_eq!(nodes.len(), 601);
        assert_eq!(edges, vec![(0, 600)]);
        assert_eq!(total_nodes, 601);
        assert_eq!(total_edges, 1);
    }

    #[test]
    fn graph_edges_are_colored_by_flow_role() {
        let method = r#"InfoNode { method: "Lfoo/Bar;->run()V" }"#;
        let argument = r#"InfoNode { static_argument: "register 0" }"#;
        let return_value = r#"InfoNode { dynamic_return: "result" }"#;

        assert_eq!(graph_edge_kind(method, method), GraphEdgeKind::Call);
        assert_eq!(graph_edge_kind(method, argument), GraphEdgeKind::Argument);
        assert_eq!(graph_edge_kind(return_value, method), GraphEdgeKind::Return);
    }

    #[test]
    fn graph_labels_use_compact_representations() {
        let method =
            r#"InfoNode { method: "Lfoo/bar/Jwt;->getKeyId()Ljava/lang/String; (midx: 192)" }"#;
        let field = r#"InfoNode { field: "Lfoo/bar/Jwt;->keyId:Ljava/lang/String;" }"#;
        assert_eq!(
            graph_display_label(method, GraphNodeKind::Method, true),
            "Jwt.getKeyId()"
        );
        assert_eq!(
            graph_display_label(field, GraphNodeKind::Field, true),
            "Jwt.keyId"
        );
    }

    #[test]
    fn clustered_layout_keeps_all_supergraph_nodes_positioned() {
        let nodes = vec![
            (0, r#"InfoNode { method: "Lfoo/A;->a()V" }"#.to_string()),
            (1, r#"InfoNode { method: "Lfoo/A;->b()V" }"#.to_string()),
            (2, r#"InfoNode { method: "Lfoo/A;->c()V" }"#.to_string()),
            (3, r#"InfoNode { method: "Lfoo/A;->d()V" }"#.to_string()),
        ];
        let layout = layout_clustered_graph(&nodes, &[(0, 1), (0, 2), (0, 3)]);
        assert_eq!(layout.len(), nodes.len());
        let positions = layout
            .values()
            .map(|position| (position.x.to_bits(), position.y.to_bits()))
            .collect::<HashSet<_>>();
        assert_eq!(positions.len(), nodes.len());
    }

    #[test]
    fn layered_layout_returns_every_visible_node_and_follows_flow_downward() {
        let nodes = vec![
            (0, "method".to_string()),
            (1, "class".to_string()),
            (2, "string".to_string()),
        ];
        let layout = layout_graph(&nodes, &[(0, 1), (1, 2)]);
        assert_eq!(layout.len(), nodes.len());
        assert!(layout[&0].y < layout[&1].y);
        assert!(layout[&1].y < layout[&2].y);
    }

    #[test]
    fn xml_highlighter_handles_manifest_syntax() {
        let source = r#"<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.INTERNET" /></manifest>"#;
        let layout = highlight_xml(source);
        assert!(!layout.sections.is_empty());
    }

    #[test]
    fn xml_formatter_indents_nested_elements() {
        let source =
            r#"<?xml version="1.0"?><manifest><application android:label="Coeus" /></manifest>"#;
        let formatted = format_xml(source).expect("valid XML should format");
        assert!(formatted.contains("\n  <application"));
        assert!(formatted.ends_with("</manifest>"));
    }

    #[test]
    fn xml_formatter_reports_incomplete_markup() {
        assert!(format_xml("<manifest").is_err());
    }

    #[test]
    fn annotation_identity_is_stable_for_supported_objects() {
        assert_eq!(
            annotation_key("method", "Lfoo/Bar;->run()V"),
            "method:Lfoo/Bar;->run()V"
        );
        assert_eq!(annotation_key("class", "Lfoo/Bar;"), "class:Lfoo/Bar;");
        assert_eq!(
            annotation_key("string", "shared value"),
            "string:shared value"
        );
        assert!(annotation_key("field", "Lfoo/Bar;->value:I").is_empty());
    }

    #[test]
    fn alias_identity_is_stable_for_classes_and_methods() {
        assert_eq!(alias_key("class", "Lfoo/Bar;"), "class:Lfoo/Bar;");
        assert_eq!(
            alias_key("method", "Lfoo/Bar;->run()V"),
            "method:Lfoo/Bar;->run()V"
        );
        assert!(alias_key("field", "Lfoo/Bar;->value:I").is_empty());
    }

    #[test]
    fn method_note_navigation_searches_the_indexed_name() {
        assert_eq!(
            method_name_for_search("Lfoo/Bar;->run(Ljava/lang/Object;)Ljava/lang/Object;"),
            "run"
        );
        assert_eq!(method_name_for_search("malformed"), "malformed");
    }

    #[test]
    fn notes_are_loaded_only_from_non_empty_string_entries() {
        let data = json!({
            "notes": {
                "method:Lfoo/Bar;->run()V": "inspect this",
                "class:Lfoo/Empty;": "",
                "field:Lfoo/Bar;->value:I": 12
            }
        });
        let notes = notes_map(&data);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes["method:Lfoo/Bar;->run()V"], "inspect this");
    }

    #[test]
    fn aliases_are_loaded_only_from_non_empty_string_entries() {
        let data = json!({
            "aliases": {
                "class:Lfoo/Bar;": "Wallet",
                "method:Lfoo/Bar;->run()V": "start",
                "class:Lfoo/Empty;": "",
                "field:Lfoo/Bar;->value:I": 12
            }
        });
        let aliases = aliases_map(&data);
        assert_eq!(aliases.len(), 2);
        assert_eq!(aliases["class:Lfoo/Bar;"], "Wallet");
    }

    #[test]
    fn note_keys_resolve_to_objects_and_code_locations() {
        let (kind, label, location) =
            parse_note_location("method:Lfoo/Bar;->run()V").expect("method note");
        assert_eq!(kind, "method");
        assert_eq!(label, "Lfoo/Bar;->run()V");
        assert!(location.is_none());

        let (_, label, location) =
            parse_note_location("code:Lfoo/Bar;->run()V:offset:1a").expect("instruction note");
        assert_eq!(label, "Lfoo/Bar;->run()V");
        assert!(matches!(location, Some(NoteLocation::Offset(0x1a))));

        let (_, label, location) =
            parse_note_location("code:class:Lfoo/Bar;:line:12").expect("class line note");
        assert_eq!(label, "Lfoo/Bar;");
        assert!(matches!(location, Some(NoteLocation::Line(12))));
    }
}

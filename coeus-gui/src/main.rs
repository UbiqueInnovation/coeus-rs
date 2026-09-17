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
use serde_json::{json, Value};

mod native_backend;
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
    Xrefs(NavigationTarget),
    EnclosingMethodXrefs,
    ToggleBreakpoint,
    EditNote(NavigationTarget),
}

#[derive(Clone)]
struct CodeInteraction {
    offset: u64,
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
}

struct CodeState {
    method_id: Option<String>,
    kind: String,
    title: String,
    code: String,
    lines: Vec<String>,
    instructions: Vec<InstructionRow>,
    selected_offset: Option<u64>,
    highlighted_offset: Option<u64>,
    highlight_scroll_pending: bool,
    breakpoints: HashSet<u64>,
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
            kind: String::new(),
            title: String::new(),
            code: String::new(),
            lines: Vec::new(),
            instructions: Vec::new(),
            selected_offset: None,
            highlighted_offset: None,
            highlight_scroll_pending: false,
            breakpoints: HashSet::new(),
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
    edges: Vec<(usize, usize)>,
    layout: HashMap<usize, Vec2>,
    total_nodes: usize,
    total_edges: usize,
    zoom: f32,
    fit_to_view: bool,
    node_filters: HashSet<GraphNodeKind>,
}

impl Default for GraphState {
    fn default() -> Self {
        Self {
            kind: String::new(),
            dot: String::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            layout: HashMap::new(),
            total_nodes: 0,
            total_edges: 0,
            zoom: 1.0,
            fit_to_view: true,
            node_filters: all_graph_node_kinds().into_iter().collect(),
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
    last_poll: Instant,
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
    split_package: String,
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
            split_package: String::new(),
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
    note_editor: Option<NoteEditor>,
    note_popup: Option<NotePopup>,
    manifest_xml: String,
    manifest_dirty: bool,
    deploy: DeployState,
    split_mode: bool,
    split_members: Vec<String>,
    adb: AdbState,
}

impl CoeusApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        match Bridge::spawn() {
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
                    note_editor: None,
                    note_popup: None,
                    manifest_xml: String::new(),
                    manifest_dirty: false,
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
                status: error,
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
                note_editor: None,
                note_popup: None,
                manifest_xml: String::new(),
                manifest_dirty: false,
                deploy: DeployState::default(),
                split_mode: false,
                split_members: Vec::new(),
                adb: AdbState::default(),
            },
        }
    }

    fn busy(&self) -> bool {
        !self.pending.is_empty()
    }

    fn can_overlap_request(op: &str) -> bool {
        matches!(
            op,
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
    }

    fn source_directory(&self) -> Option<String> {
        let source = self.path.split(',').next()?.trim();
        if source.is_empty() || source.starts_with("ADB:") {
            return None;
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
            self.request(
                "save_project",
                json!({"op": "save_project", "path": path.display().to_string()}),
            );
        }
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
                        self.info = Some(data);
                        self.results.clear();
                        self.xrefs.clear();
                        self.selected_id = None;
                        self.described_result = None;
                        self.code = CodeState::default();
                        self.graph = GraphState::default();
                        self.string_editor = StringEditorState::default();
                        self.navigation_history.clear();
                        self.navigation_cursor = None;
                        self.navigation_replay = None;
                        self.edit_picker = None;
                        self.graph_node_details = None;
                        self.description_cache.clear();
                        self.note_editor = None;
                        self.note_popup = None;
                        self.manifest_xml = manifest_xml;
                        self.manifest_dirty = false;
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
                        self.status =
                            format!("Saved Coeus project to {}", value_string(&data, "path"));
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
                    "search" => {
                        self.result_count =
                            data.get("count").and_then(Value::as_u64).unwrap_or(0) as usize;
                        self.results = result_rows(&data);
                        self.status = format!("Found {} result(s)", self.result_count);
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
                    }
                    "graph" => {
                        self.graph.kind = value_string(&data, "kind");
                        self.graph.dot = value_string(&data, "dot");
                        let (nodes, edges, total_nodes, total_edges) = parse_dot(&self.graph.dot);
                        self.graph.nodes = nodes;
                        self.graph.edges = edges;
                        self.graph.total_nodes = total_nodes;
                        self.graph.total_edges = total_edges;
                        self.graph.node_filters = all_graph_node_kinds().into_iter().collect();
                        self.rebuild_graph_layout();
                        self.graph_node_details = None;
                        self.graph.zoom = 1.0;
                        self.graph.fit_to_view = true;
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
                            self.debug.frame = None;
                            self.debug.values.clear();
                            self.debug.edits.clear();
                            self.debug.pending_value = None;
                            self.debug.floating_open = false;
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
                        self.code.breakpoints.clear();
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
                    "debug_breakpoint" => {
                        let offset = value_u64(&data, "offset");
                        let enabled = data.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                        if enabled {
                            self.code.breakpoints.insert(offset);
                        } else {
                            self.code.breakpoints.remove(&offset);
                        }
                        self.debug.waiting = data
                            .get("waiting")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        self.debug.last_poll = Instant::now();
                        self.status = if !enabled {
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
                if operation == "debug_apps" || operation == "debug_apps_poll" {
                    self.debug.apps_loading = false;
                }
                if operation == "debug_poll" {
                    self.debug.waiting = false;
                }
                self.status = error;
            }
        }
    }

    fn apply_description(&mut self, data: &Value) {
        let id = value_string(data, "id");
        let kind = value_string(data, "kind");
        let code = value_string(data, "code");
        let result = ResultRow {
            id: id.clone(),
            kind: kind.clone(),
            label: value_string(data, "label"),
            note_key: value_string(data, "note_key"),
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
        self.code.title = value_string(data, "label");
        self.code.code = code.clone();
        self.code.lines = code.lines().map(str::to_string).collect();
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
                    RichText::new("This note follows the same object in search results, cross-references, and code references.")
                        .small()
                        .color(Color32::GRAY),
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
            };
            self.open_note_editor(&target);
        } else if close {
            self.note_popup = None;
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
        self.graph.layout = layout_graph(&nodes, &edges);
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
            .default_width(300.0)
            .max_width(max_sidebar_width)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(
                        RichText::new("COEUS EXPLORER")
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
                ui.label(RichText::new("Structured APK analysis").small().color(Color32::GRAY));
                ui.add_space(10.0);
                ui.label("Selected APK or project path (File menu for actions)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.path)
                        .hint_text("Choose an APK or .coeus project")
                        .desired_width(f32::INFINITY),
                );
                if self.info.is_some() {
                    ui.label("Edited APK output path");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.output_path)
                            .hint_text("edited output APK")
                            .desired_width(f32::INFINITY),
                    );
                }
                if let Some(error) = &self.startup_error {
                    ui.add_space(8.0);
                    ui.colored_label(Color32::from_rgb(255, 150, 140), error);
                }
                if let Some(info) = &self.info {
                    ui.add_space(8.0);
                    ui.label(RichText::new(value_string(info, "package")).strong());
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
                                    .color(Color32::GRAY),
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
                            .color(Color32::GRAY),
                        );
                    });
                }
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Search");
                    egui::ComboBox::from_id_salt("search-kind")
                        .selected_text(self.search_kind.label())
                        .show_ui(ui, |ui| {
                            for kind in [SearchKind::Any, SearchKind::Methods, SearchKind::Classes, SearchKind::Fields, SearchKind::Strings] {
                                ui.selectable_value(&mut self.search_kind, kind, kind.label());
                            }
                        });
                });
                let response = ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("regex, e.g. onCreate|decrypt"));
                if (response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) || ui.button("Find").clicked()) && self.info.is_some() {
                    self.request("search", json!({"op":"search", "kind":self.search_kind.api_name(), "query":self.search}));
                }
                if !self.results.is_empty() {
                    ui.add_space(8.0);
                    ui.label(RichText::new(format!("Results ({} / {})", self.results.len(), self.result_count)).strong());
                    let mut picked = None;
                    let mut action = None;
                    egui::ScrollArea::both()
                        .id_salt("results")
                        .auto_shrink([false, false])
                        .max_height(ui.available_height().max(1.0))
                        .show(ui, |ui| {
                            for result in self.results.clone() {
                                let selected = self.selected_id.as_ref() == Some(&result.id);
                                let response = ui.horizontal(|ui| {
                                    let response = ui.selectable_label(
                                        selected,
                                        RichText::new(format!("[{}] {}", result.kind, result.label))
                                            .monospace()
                                            .size(12.0)
                                            .color(if self.notes.contains_key(&result.note_key) {
                                                Color32::from_rgb(255, 220, 125)
                                            } else {
                                                Color32::WHITE
                                            }),
                                    );
                                    self.show_note_chip(
                                        ui,
                                        &result.kind,
                                        &result.note_key,
                                        &result.label,
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
                        }
                    } else if let Some(result) = picked {
                        self.selected_id = Some(result.id.clone());
                        self.request("describe", json!({"op":"describe", "id":result.id}));
                    }
                }
            });
    }

    fn show_tabs(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
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
                    .on_hover_text("Go to the previously visited class, method, field, or string")
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
                            .color(Color32::GRAY),
                    );
                }
                ui.separator();
                for (tab, label) in [
                    (Tab::Search, "Search"),
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
                        .on_hover_text("Open the debugger window without leaving the current tab")
                        .clicked()
                {
                    self.debug.floating_open = true;
                }
                ui.separator();
                if self.busy() {
                    ui.spinner();
                }
                ui.label(
                    RichText::new(&self.status)
                        .small()
                        .color(Color32::LIGHT_GRAY),
                );
            });
        });
    }

    fn show_search(&mut self, ui: &mut egui::Ui) {
        ui.heading("Search and cross-references");
        ui.label("Select a result to open its decoded source. Cross-references stay as typed Coeus evidence and can be opened the same way.");
        let mut string_replacement = None;
        if let Some(result) = self.selected_result() {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::Label::new(RichText::new(&result.label).strong().monospace()).truncate(),
                );
                self.show_note_chip(ui, &result.kind, &result.note_key, &result.label);
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
            ui.collapsing("References", |ui| {
                for result in self.xrefs.clone() {
                    ui.horizontal(|ui| {
                        if ui
                            .selectable_label(
                                false,
                                RichText::new(&result.label).monospace().color(
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
                        self.show_note_chip(ui, &result.kind, &result.note_key, &result.label);
                    });
                }
            });
            if let Some(result) = picked {
                self.selected_id = Some(result.id.clone());
                self.request("describe", json!({"op":"describe", "id":result.id}));
            }
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
                .min_width(240.0)
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
                    self.show_instruction_nodes(ui, &mut chosen_edit);
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Smali method");
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
                    self.show_note_chip(
                        ui,
                        &target.kind,
                        &target.note_key,
                        &target.label,
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
                }
                if let Some(method_id) = &self.code.method_id {
                    if ui.button("Call graph").clicked() {
                        self.request(
                            "graph",
                            json!({"op":"graph", "kind":"callgraph", "id":method_id, "ignore":""}),
                        );
                        self.tab = Tab::Graph;
                    }
                }
                if ui
                    .button(if self.instruction_pane_collapsed {
                        "Show nodes"
                    } else {
                        "Hide nodes"
                    })
                    .clicked()
                {
                    self.instruction_pane_collapsed = !self.instruction_pane_collapsed;
                }
                if ui.button("Supergraph").clicked() && self.info.is_some() {
                    self.request(
                        "graph",
                        json!({"op":"graph", "kind":"supergraph", "ignore":""}),
                    );
                    self.tab = Tab::Graph;
                }
            });
            ui.label(
                RichText::new(
                    "Inspection is syntax-highlighted. Select an instruction to see typed method-change nodes.",
                )
                .small()
                .color(Color32::GRAY),
            );
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
                            .color(Color32::GRAY),
                    );
                    if let Some(offset) = self.code.highlighted_offset {
                        ui.label(
                            RichText::new(format!("current execution: @0x{offset:x}"))
                                .small()
                                .strong()
                                .color(Color32::YELLOW)
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
                        .color(Color32::GRAY),
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
                ui.allocate_ui_with_layout(
                    ui.available_size(),
                    egui::Layout::top_down(egui::Align::Center),
                    |ui| {
                        ui.centered_and_justified(|ui| {
                            ui.label("Choose a method or class from Search to open its code.")
                        });
                    },
                );
            }
        });

        if let Some(interaction) = code_interaction {
            self.code.selected_offset = Some(interaction.offset);
            match interaction.action {
                Some(CodeAction::Navigate(target)) => {
                    self.selected_id = Some(target.id.clone());
                    self.request("describe", json!({"op":"describe", "id":target.id}));
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
                    if let Some(method_id) = self.code.method_id.clone() {
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
            ui.heading("Instruction nodes");
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
                                .color(Color32::YELLOW),
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
                                        .color(Color32::GRAY),
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
                                                egui::TextEdit::singleline(&mut argument.value)
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
                        .color(Color32::GRAY),
                );
                ui.horizontal(|ui| {
                    ui.label(picker.kind.label());
                    ui.add(
                        egui::TextEdit::singleline(&mut picker.query)
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
                    .color(Color32::GRAY),
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
        let can_change_breakpoint = self.debug.connected && !self.busy();
        let mut interaction = None;
        let mut highlighted_visible = false;
        egui::Frame::dark_canvas(ui.style()).show(ui, |ui| {
            egui::ScrollArea::both()
                .id_salt("smali-code")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        for (index, line) in lines.iter().enumerate() {
                            let offset = parse_code_offset(line);
                            let is_selected = offset.is_some() && offset == selected;
                            let is_highlighted = offset.is_some() && offset == highlighted;
                            let can_toggle_breakpoint = can_change_breakpoint && offset.is_some();
                            let fill = if is_highlighted {
                                Color32::from_rgb(75, 65, 30)
                            } else if is_selected {
                                Color32::from_rgb(30, 58, 82)
                            } else {
                                Color32::TRANSPARENT
                            };
                            let line_response = egui::Frame::NONE
                                .fill(fill)
                                .stroke(if is_highlighted {
                                    Stroke::new(1.0, Color32::YELLOW)
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
                                                        Color32::YELLOW
                                                    } else {
                                                        Color32::DARK_GRAY
                                                    }),
                                            ),
                                        );
                                        if let Some(offset) = offset {
                                            let marker = if breakpoints.contains(&offset) {
                                                "●"
                                            } else {
                                                "○"
                                            };
                                            let marker_response = ui.add_enabled(
                                                can_toggle_breakpoint,
                                                egui::Button::new(RichText::new(marker).color(
                                                    if breakpoints.contains(&offset) {
                                                        Color32::RED
                                                    } else {
                                                        Color32::GRAY
                                                    },
                                                ))
                                                .min_size(Vec2::new(22.0, 20.0)),
                                            );
                                            if marker_response
                                            .on_hover_text(if can_toggle_breakpoint {
                                                if breakpoints.contains(&offset) {
                                                    "Clear breakpoint"
                                                } else {
                                                    "Set breakpoint"
                                                }
                                            } else {
                                                "Connect the debugger before changing breakpoints"
                                            })
                                            .clicked()
                                        {
                                            interaction = Some(CodeInteraction {
                                                offset,
                                                action: Some(CodeAction::ToggleBreakpoint),
                                            });
                                        }
                                            let response = ui.add(
                                                egui::Label::new(highlight_smali(line))
                                                    .sense(Sense::click()),
                                            );
                                            if response.clicked() {
                                                let command_click =
                                                    ui.input(|input| input.modifiers.command);
                                                let action = if command_click {
                                                    self.preferred_navigation_target(offset)
                                                        .map(CodeAction::Navigate)
                                                } else {
                                                    None
                                                };
                                                interaction =
                                                    Some(CodeInteraction { offset, action });
                                            }
                                            let targets = self
                                                .code
                                                .instructions
                                                .iter()
                                                .find(|instruction| instruction.offset == offset)
                                                .map(|instruction| instruction.targets.clone())
                                                .unwrap_or_default();
                                            response.context_menu(|ui| {
                                                if ui
                                                    .button("Find xrefs for enclosing method")
                                                    .clicked()
                                                {
                                                    interaction = Some(CodeInteraction {
                                                        offset,
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
                                                        if ui
                                                            .button(format!(
                                                                "{}: {}",
                                                                target.kind,
                                                                shorten(&target.label, 46)
                                                            ))
                                                            .clicked()
                                                        {
                                                            interaction = Some(CodeInteraction {
                                                                offset,
                                                                action: Some(CodeAction::Navigate(
                                                                    target.clone(),
                                                                )),
                                                            });
                                                            ui.close_menu();
                                                        }
                                                    }
                                                    ui.separator();
                                                    ui.label("Find xrefs to");
                                                    for target in &targets {
                                                        if ui
                                                            .button(format!(
                                                                "{} xrefs: {}",
                                                                target.kind,
                                                                shorten(&target.label, 38)
                                                            ))
                                                            .clicked()
                                                        {
                                                            interaction = Some(CodeInteraction {
                                                                offset,
                                                                action: Some(CodeAction::Xrefs(
                                                                    target.clone(),
                                                                )),
                                                            });
                                                            ui.close_menu();
                                                        }
                                                    }
                                                    for target in &targets {
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
                                                                    shorten(&target.label, 38)
                                                                ))
                                                                .clicked()
                                                        {
                                                            interaction = Some(CodeInteraction {
                                                                offset,
                                                                action: Some(CodeAction::EditNote(
                                                                    target.clone(),
                                                                )),
                                                            });
                                                            ui.close_menu();
                                                        }
                                                    }
                                                }
                                            });
                                            for target in &targets {
                                                self.show_note_chip(
                                                    ui,
                                                    &target.kind,
                                                    &target.note_key,
                                                    &target.label,
                                                );
                                            }
                                        } else {
                                            ui.add(egui::Label::new(highlight_smali(line)));
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
                        }
                    });
                });
        });
        if should_scroll && highlighted_visible {
            self.code.highlight_scroll_pending = false;
        }
        interaction
    }

    fn show_graph(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Graph renderer");
            if ui.button("Call graph from current method").clicked() {
                if let Some(method_id) = self.code.method_id.clone() {
                    self.request(
                        "graph",
                        json!({"op":"graph", "kind":"callgraph", "id":method_id, "ignore":""}),
                    );
                }
            }
            if ui.button("Build supergraph").clicked() && self.info.is_some() {
                self.request(
                    "graph",
                    json!({"op":"graph", "kind":"supergraph", "ignore":""}),
                );
            }
            if ui.button("Fit to view").clicked() {
                self.graph.fit_to_view = true;
            }
            let zoom_response =
                ui.add(egui::Slider::new(&mut self.graph.zoom, 0.1..=3.0).text("zoom"));
            if zoom_response.changed() {
                self.graph.fit_to_view = false;
            }
        });
        let mut filters = self.graph.node_filters.clone();
        let mut filters_changed = false;
        ui.collapsing("Node filters", |ui| {
            ui.horizontal(|ui| {
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
            self.rebuild_graph_layout();
            self.graph.fit_to_view = true;
        }
        if self.graph.dot.is_empty() {
            ui.add_space(20.0);
            ui.centered_and_justified(|ui| {
                ui.label("Build a callgraph from Code or load the complete supergraph.")
            });
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} nodes · {} edges · off-screen nodes are rendered as you scroll",
                    self.graph.nodes.len(),
                    self.graph.edges.len()
                ))
                .small()
                .color(Color32::LIGHT_GRAY),
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
                RichText::new("Cmd + scroll to zoom")
                    .small()
                    .color(Color32::GRAY),
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
        // Keep labels borrowed while painting. A large graph should not clone
        // every label on every frame just because only a small viewport is
        // currently visible.
        let nodes = self
            .graph
            .nodes
            .iter()
            .filter(|(_, label)| self.graph.node_filters.contains(&graph_node_kind(label)))
            .map(|(id, label)| (*id, label.clone()))
            .collect::<Vec<_>>();
        let visible_ids = nodes.iter().map(|(id, _)| *id).collect::<HashSet<_>>();
        let edges = self
            .graph
            .edges
            .iter()
            .filter(|(from, to)| visible_ids.contains(from) && visible_ids.contains(to))
            .cloned()
            .collect::<Vec<_>>();
        let viewport = ui.available_size();
        let base_node_size = Vec2::new(250.0, 72.0);
        let (min, max) = layout_bounds(
            nodes.iter().map(|(id, _)| *id),
            &self.graph.layout,
            base_node_size,
        );
        let logical_size = (max - min).max(Vec2::new(1.0, 1.0)) + Vec2::splat(80.0);
        let fit_zoom = ((viewport.x - 24.0) / logical_size.x)
            .min((viewport.y - 24.0) / logical_size.y)
            .clamp(0.12, 1.5);
        let mut zoom = if self.graph.fit_to_view {
            fit_zoom
        } else {
            self.graph.zoom
        };
        let clip_rect = ui.clip_rect();
        let cmd_zoom_delta = ui.ctx().input(|input| {
            if input.modifiers.command
                && input
                    .pointer
                    .hover_pos()
                    .is_some_and(|pointer| clip_rect.contains(pointer))
            {
                input.zoom_delta()
            } else {
                1.0
            }
        });
        if (cmd_zoom_delta - 1.0).abs() > f32::EPSILON {
            zoom = (zoom * cmd_zoom_delta).clamp(0.1, 3.0);
            self.graph.zoom = zoom;
            self.graph.fit_to_view = false;
        }
        let canvas = Vec2::new(
            (logical_size.x * zoom + 24.0).max(viewport.x),
            (logical_size.y * zoom + 24.0).max(viewport.y).max(320.0),
        );
        let mut clicked_node = None;
        egui::Frame::dark_canvas(ui.style()).show(ui, |ui| {
            egui::ScrollArea::both()
                .id_salt("graph-canvas")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let (rect, _) = ui.allocate_exact_size(canvas, Sense::hover());
                    let painter = ui.painter_at(rect);
                    let origin = rect.left_top() + Vec2::new(40.0, 40.0) - min * zoom;
                    let clip_rect = ui.clip_rect().expand(24.0);
                    let node_rect = |id: usize| {
                        self.graph.layout.get(&id).map(|position| {
                            Rect::from_center_size(origin + *position * zoom, base_node_size * zoom)
                        })
                    };
                    let mut node_rects = HashMap::new();
                    for (id, label) in &nodes {
                        let Some(rect) = node_rect(*id) else {
                            continue;
                        };
                        if rect.intersects(clip_rect) {
                            node_rects.insert(*id, rect);
                        }
                        let _ = label;
                    }
                    let labels = nodes
                        .iter()
                        .map(|(id, label)| (*id, label.as_str()))
                        .collect::<HashMap<_, _>>();
                    for (from, to) in &edges {
                        let (Some(from_rect), Some(to_rect)) = (node_rect(*from), node_rect(*to))
                        else {
                            continue;
                        };
                        if !from_rect.intersects(clip_rect) && !to_rect.intersects(clip_rect) {
                            continue;
                        }
                        let direction = to_rect.center() - from_rect.center();
                        if direction.length_sq() <= f32::EPSILON {
                            continue;
                        }
                        let unit = direction.normalized();
                        let start = rect_boundary_point(from_rect, unit);
                        let end = rect_boundary_point(to_rect, -unit);
                        let edge_kind = graph_edge_kind(
                            labels.get(from).copied().unwrap_or_default(),
                            labels.get(to).copied().unwrap_or_default(),
                        );
                        let (edge_color, edge_width) = graph_edge_style(edge_kind);
                        painter.line_segment([start, end], Stroke::new(edge_width, edge_color));
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
                    }
                    for (id, label) in &nodes {
                        let Some(node_rect) = node_rects.get(id) else {
                            continue;
                        };
                        let kind = graph_node_kind(label);
                        let (fill, stroke) = graph_node_colors(kind);
                        paint_graph_node(&painter, *node_rect, kind, fill, stroke);
                        let node_text = if zoom < 0.45 {
                            format!("#{id}")
                        } else {
                            let max_chars = if zoom < 0.7 { 28 } else { 58 };
                            format!("{}\n{}", kind.label(), shorten(label, max_chars))
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
                        let response = ui.interact(
                            *node_rect,
                            ui.make_persistent_id(("graph-node", *id)),
                            Sense::click(),
                        );
                        let clicked = response.clicked();
                        response.on_hover_text(label.as_str());
                        if clicked {
                            clicked_node = Some((*id, label.clone()));
                        }
                    }
                    if nodes.is_empty() {
                        painter.text(
                            rect.center(),
                            egui::Align2::CENTER_CENTER,
                            "DOT contained no renderable nodes",
                            FontId::proportional(14.0),
                            Color32::GRAY,
                        );
                    }
                });
        });
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
                ui.label(RichText::new("DOT node label").small().color(Color32::GRAY));
                ui.add(egui::Label::new(RichText::new(&snapshot.label).monospace()).wrap());
                if !snapshot.value.is_empty() {
                    ui.label(
                        RichText::new("Referenced value")
                            .small()
                            .color(Color32::GRAY),
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
                            .color(Color32::GRAY),
                    );
                } else {
                    for target in &snapshot.targets {
                        ui.horizontal(|ui| {
                            if ui
                                .button(format!(
                                    "Go to {}: {}",
                                    target.kind,
                                    shorten(&target.label, 72)
                                ))
                                .clicked()
                            {
                                navigate = Some(target.clone());
                            }
                            self.show_note_chip(ui, &target.kind, &target.note_key, &target.label);
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
                .add_enabled(!self.busy(), egui::Button::new("Reload from APK"))
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
                    .color(Color32::YELLOW),
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
        ui.horizontal(|ui| {
            ui.label("Keystore");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.keystore)
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
        ui.horizontal(|ui| {
            ui.label("Alias");
            ui.add(egui::TextEdit::singleline(&mut self.deploy.alias).desired_width(220.0));
            ui.label("Store password");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.store_password)
                    .desired_width(180.0)
                    .password(true),
            );
            ui.label("Key password");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.key_password)
                    .desired_width(180.0)
                    .password(true),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Output APK");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.output)
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
        ui.horizontal(|ui| {
            ui.label("apksigner (optional)");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.apksigner)
                    .desired_width(360.0)
                    .hint_text("use SDK PATH when empty"),
            );
            ui.label("adb (optional)");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.adb_path)
                    .desired_width(260.0)
                    .hint_text("use PATH when empty"),
            );
        });
        ui.horizontal(|ui| {
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
            self.request(action, request);
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
        ui.horizontal(|ui| {
            ui.label("Keystore");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.keystore)
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
        ui.horizontal(|ui| {
            ui.label("Alias");
            ui.add(egui::TextEdit::singleline(&mut self.deploy.alias).desired_width(220.0));
            ui.label("Store password");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.store_password)
                    .desired_width(180.0)
                    .password(true),
            );
            ui.label("Key password");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.key_password)
                    .desired_width(180.0)
                    .password(true),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Signed output directory");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.split_output_dir)
                    .desired_width(460.0)
                    .hint_text("directory for base.apk and split APKs"),
            );
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.deploy.split_output_dir = path.display().to_string();
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("apksigner (optional)");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.apksigner)
                    .desired_width(360.0)
                    .hint_text("use SDK PATH when empty"),
            );
            ui.label("adb (optional)");
            ui.add(
                egui::TextEdit::singleline(&mut self.deploy.adb_path)
                    .desired_width(260.0)
                    .hint_text("use PATH when empty"),
            );
        });
        ui.horizontal(|ui| {
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
            self.request(action, request);
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
        ui.horizontal(|ui| {
            ui.label("adb");
            ui.add(
                egui::TextEdit::singleline(&mut self.adb.adb_path)
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
        ui.horizontal(|ui| {
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
        ui.horizontal(|ui| {
            ui.label("Package filter");
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.adb.package_filter)
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
        ui.horizontal(|ui| {
            ui.label("Local output directory");
            ui.add(
                egui::TextEdit::singleline(&mut self.adb.output_dir)
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
        let can_control = connected && !waiting && !busy;
        let can_set_value = connected && frame.is_some() && !waiting;
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
                                    .color(Color32::GRAY),
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
                                        egui::TextEdit::singleline(&mut edited),
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
                                        .color(Color32::YELLOW),
                                    )
                                    .wrap(),
                                );
                            }
                            ui.label(
                                RichText::new(
                                    "The Code tab highlights the stopped execution index.",
                                )
                                .small()
                                .color(Color32::GRAY),
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
        let can_control = self.debug.connected && !self.debug.waiting && !self.busy();
        let can_set_value =
            self.debug.connected && self.debug.frame.is_some() && !self.debug.waiting;
        ui.heading("JDWP debugger");
        ui.label(
            "Discover JDWP-enabled processes through adb, then attach to the selected process. The attach flow manages the JDWP forwarding.",
        );
        ui.horizontal(|ui| {
            ui.label("ADB serial");
            ui.add(
                egui::TextEdit::singleline(&mut self.debug.serial)
                    .desired_width(150.0)
                    .hint_text("default device"),
            );
            ui.label("ADB path");
            ui.add(
                egui::TextEdit::singleline(&mut self.debug.adb_path)
                    .desired_width(180.0)
                    .hint_text("PATH when empty"),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Forward port");
            ui.add(egui::TextEdit::singleline(&mut self.debug.port).desired_width(70.0));
            if ui
                .add_enabled(
                    !self.busy() && !self.debug.apps_loading,
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
                    !self.busy() && self.debug.connected && !self.debug.waiting,
                    egui::Button::new("Wait"),
                )
                .clicked()
            {
                self.request("debug_wait", json!({"op":"debug_wait"}));
            }
            if ui
                .add_enabled(!self.busy() && self.debug.connected, egui::Button::new("Detach"))
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
                    ui.add_sized([180.0, 20.0], egui::TextEdit::singleline(&mut edited));
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
                    Color32::YELLOW,
                    format!("Register values unavailable: {error}"),
                );
            }
            ui.label(RichText::new("The Code tab highlights the stopped code index. Select an instruction and press B to set or clear a breakpoint.").small().color(Color32::GRAY));
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
        // Breakpoint/event operations share the JDWP packet receiver. Set and
        // clear requests are routed through the wait worker while it is
        // polling, so breakpoints can be changed without racing JDWP reads.
        if !self.busy() && self.debug.connected {
            let b = ctx.input(|input| input.key_pressed(Key::B));
            let f5 = ctx.input(|input| input.key_pressed(Key::F5));
            let f10 = ctx.input(|input| input.key_pressed(Key::F10));
            if b {
                if let (Some(method_id), Some(offset)) =
                    (self.code.method_id.clone(), self.code.selected_offset)
                {
                    self.request(
                        "debug_breakpoint",
                        json!({"op":"debug_breakpoint", "id":method_id, "offset":offset}),
                    );
                }
            } else if !self.debug.waiting && f5 {
                self.request_debug_control("debug_resume");
            } else if !self.debug.waiting && f10 && self.debug.frame.is_some() {
                self.request_debug_control("debug_step");
            }
        }
        self.show_sidebar(ctx);
        self.show_tabs(ctx);
        if self.tab == Tab::Code {
            self.show_code(ctx);
        } else {
            egui::CentralPanel::default().show(ctx, |ui| match self.tab {
                Tab::Search => {
                    egui::ScrollArea::both()
                        .id_salt("search-tab")
                        .auto_shrink([false, false])
                        .show(ui, |ui| self.show_search(ui));
                }
                Tab::Graph => {
                    egui::ScrollArea::vertical()
                        .id_salt("graph-tab")
                        .auto_shrink([false, false])
                        .show(ui, |ui| self.show_graph(ui));
                }
                Tab::Debugger => self.show_debugger(ui),
                Tab::Manifest => self.show_manifest(ui),
                Tab::Deploy => self.show_deploy(ui),
                Tab::Adb => self.show_adb(ui),
                Tab::Code => unreachable!("Code is rendered with its attached panels"),
            });
        }
        self.show_edit_picker(ctx);
        self.show_note_editor(ctx);
        self.show_note_popup(ctx);
        self.show_graph_node_details(ctx);
        self.show_floating_debugger(ctx);
        ctx.request_repaint_after(Duration::from_millis(100));
    }
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

fn highlight_smali(line: &str) -> LayoutJob {
    let font = FontId::monospace(13.0);
    let mut job = LayoutJob::default();
    let comment_at = line.find('#');
    let code = comment_at.map(|index| &line[..index]).unwrap_or(line);
    let comment = comment_at.map(|index| &line[index..]);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    let vertical_spacing = 180.0;
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
}

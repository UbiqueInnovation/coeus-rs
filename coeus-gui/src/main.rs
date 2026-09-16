use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use eframe::egui::text::{LayoutJob, TextFormat};
use eframe::egui::{self, Color32, FontId, Key, Rect, RichText, Sense, Stroke, Vec2};
use serde_json::{json, Value};

const BRIDGE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/bridge.py");
const MAX_RENDER_NODES: usize = 600;

type Response = Result<Value, String>;

struct Bridge {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Bridge {
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Search,
    Code,
    Graph,
    Debugger,
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

struct DebugState {
    host: String,
    port: String,
    connected: bool,
    waiting: bool,
    frame: Option<Value>,
    values: Vec<(u64, String, String)>,
    edits: HashMap<u64, String>,
    apps: Vec<String>,
    last_poll: Instant,
}

struct StringEditorState {
    id: Option<String>,
    original: String,
    replacement: String,
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
            host: "127.0.0.1".to_string(),
            port: "8000".to_string(),
            connected: false,
            waiting: false,
            frame: None,
            values: Vec::new(),
            edits: HashMap::new(),
            apps: Vec::new(),
            last_poll: Instant::now(),
        }
    }
}

struct CoeusApp {
    bridge: Option<Arc<Mutex<Bridge>>>,
    startup_error: Option<String>,
    pending: Option<mpsc::Receiver<Response>>,
    pending_op: Option<String>,
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
}

impl CoeusApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        match Bridge::spawn() {
            Ok(bridge) => Self {
                bridge: Some(Arc::new(Mutex::new(bridge))),
                startup_error: None,
                pending: None,
                pending_op: None,
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
                graph: GraphState::default(),
                code: CodeState::default(),
                debug: DebugState::default(),
                string_editor: StringEditorState::default(),
                status: "Ready — choose an APK to begin".to_string(),
                sidebar_collapsed: false,
                instruction_pane_collapsed: false,
                navigation_kind: NavigationKind::Automatic,
                navigation_history: Vec::new(),
                navigation_cursor: None,
                navigation_replay: None,
                edit_picker: None,
                graph_node_details: None,
            },
            Err(error) => Self {
                bridge: None,
                startup_error: Some(error.clone()),
                pending: None,
                pending_op: None,
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
            },
        }
    }

    fn busy(&self) -> bool {
        self.pending.is_some()
    }

    fn request(&mut self, op: &str, request: Value) {
        if self.busy() {
            self.status = "Waiting for the current Coeus operation…".to_string();
            return;
        }
        let Some(bridge) = self.bridge.as_ref().cloned() else {
            self.status = "Python bridge is unavailable".to_string();
            return;
        };
        let (sender, receiver) = mpsc::channel();
        let name = op.to_string();
        thread::spawn(move || {
            let result = match bridge.lock() {
                Ok(mut bridge) => bridge.call(request),
                Err(_) => Err("Python bridge lock was poisoned".to_string()),
            };
            let _ = sender.send(result);
        });
        self.pending = Some(receiver);
        self.pending_op = Some(name.clone());
        self.status = format!("Running {name}…");
    }

    fn poll(&mut self) {
        let Some(receiver) = self.pending.as_ref() else {
            return;
        };
        match receiver.try_recv() {
            Ok(result) => {
                self.pending = None;
                let operation = self.pending_op.take().unwrap_or_default();
                self.finish(operation, result);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.pending = None;
                self.pending_op = None;
                self.status = "The Python bridge disconnected".to_string();
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
    }

    fn finish(&mut self, operation: String, result: Response) {
        match result {
            Ok(data) => match operation.as_str() {
                "load" => {
                    let package = value_string(&data, "package");
                    if self.output_path.is_empty() {
                        self.output_path =
                            format!("{}.edited.apk", self.path.trim_end_matches(".apk"));
                    }
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
                    self.status = if package.is_empty() {
                        "APK loaded".to_string()
                    } else {
                        format!("Loaded {package}")
                    };
                }
                "write" => {
                    self.status = format!("Wrote edited APK to {}", value_string(&data, "path"));
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
                    self.status = "Replaced the DEX string-pool entry".to_string();
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
                                    width: item.get("width").and_then(Value::as_u64).unwrap_or(0),
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
                                    .map(|target| NavigationTarget {
                                        id: value_string(target, "id"),
                                        kind: value_string(target, "kind"),
                                        label: value_string(target, "label"),
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        details.loading = false;
                    }
                    self.status = "Graph node details loaded".to_string();
                }
                "debug_connect" => {
                    self.debug.connected = true;
                    self.status = "Debugger connected".to_string();
                }
                "debug_apps" => {
                    self.debug.apps = data
                        .get("apps")
                        .and_then(Value::as_array)
                        .map(|apps| {
                            apps.iter()
                                .map(|app| {
                                    format!(
                                        "{} — {} (pid {})",
                                        value_string(app, "package"),
                                        value_string(app, "process"),
                                        app.get("pid").and_then(Value::as_u64).unwrap_or(0)
                                    )
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    self.status = format!("Found {} JDWP process(es)", self.debug.apps.len());
                }
                "debug_breakpoint" => {
                    if let Some(offset) = self.code.selected_offset {
                        self.code.breakpoints.insert(offset);
                    }
                    self.status = format!("Breakpoint set at {}", value_string(&data, "location"));
                }
                "debug_wait" | "debug_resume" | "debug_step" => {
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
                    }
                }
                "debug_set_value" => {
                    self.status = format!("Updated register v{}", value_u64(&data, "slot"));
                }
                _ => {
                    self.status = format!("Completed {operation}");
                }
            },
            Err(error) => {
                if operation == "describe" {
                    self.navigation_replay = None;
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
                                    .map(|target| NavigationTarget {
                                        id: value_string(target, "id"),
                                        kind: value_string(target, "kind"),
                                        label: value_string(target, "label"),
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

    fn filtered_graph_nodes(&self) -> Vec<(usize, String)> {
        self.graph
            .nodes
            .iter()
            .filter(|(_, label)| self.graph.node_filters.contains(&graph_node_kind(label)))
            .take(MAX_RENDER_NODES)
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
        egui::SidePanel::left("project-sidebar")
            .resizable(true)
            .default_width(300.0)
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
                    ui.label("APK path");
                ui.horizontal(|ui| {
                    if ui.button("Browse…").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Android package", &["apk"])
                            .pick_file()
                        {
                            self.path = path.display().to_string();
                            self.output_path.clear();
                        }
                    }
                    if ui.button("Load").clicked() && !self.path.trim().is_empty() {
                        self.request("load", json!({"op":"load", "path":self.path.trim()}));
                    }
                });
                ui.add(
                    egui::TextEdit::singleline(&mut self.path)
                        .hint_text("Choose an APK")
                        .desired_width(f32::INFINITY),
                );
                if self.info.is_some() {
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.output_path)
                                .hint_text("edited output APK")
                                .desired_width(215.0),
                        );
                        if ui.button("Write").clicked() && !self.output_path.trim().is_empty() {
                            self.request("write", json!({"op":"write", "path":self.output_path.trim()}));
                        }
                    });
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
                    egui::ScrollArea::vertical().id_salt("results").show(ui, |ui| {
                        for result in self.results.clone() {
                            let selected = self.selected_id.as_ref() == Some(&result.id);
                            let response = ui
                                .selectable_label(
                                    selected,
                                    RichText::new(format!("[{}] {}", result.kind, result.label))
                                        .monospace()
                                        .size(12.0),
                                );
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
                if ui
                    .add_enabled(
                        can_go_back,
                        egui::Button::new("←").min_size(Vec2::new(28.0, 24.0)),
                    )
                    .on_hover_text("Go to the previously visited class, method, field, or string")
                    .clicked()
                {
                    self.navigate_history(-1);
                }
                if ui
                    .add_enabled(
                        can_go_forward,
                        egui::Button::new("→").min_size(Vec2::new(28.0, 24.0)),
                    )
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
                ] {
                    if ui
                        .selectable_label(self.tab == tab, RichText::new(label).strong())
                        .clicked()
                    {
                        self.tab = tab;
                    }
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
            ui.add(egui::Label::new(RichText::new(&result.label).strong().monospace()).truncate());
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
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for result in self.xrefs.clone() {
                        if ui
                            .selectable_label(false, RichText::new(&result.label).monospace())
                            .clicked()
                        {
                            picked = Some(result);
                        }
                    }
                });
            });
            if let Some(result) = picked {
                self.selected_id = Some(result.id.clone());
                self.request("describe", json!({"op":"describe", "id":result.id}));
            }
        }
    }

    fn show_code(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Smali method");
            if !self.code.title.is_empty() {
                ui.label(
                    RichText::new(&self.code.title)
                        .monospace()
                        .color(Color32::from_rgb(160, 210, 255)),
                );
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
        ui.label(RichText::new("Inspection is syntax-highlighted. Select an instruction to see typed method-change nodes.").small().color(Color32::GRAY));
        ui.add_space(8.0);
        if self.code.method_id.is_none() {
            if self.code.kind == "class" && !self.code.lines.is_empty() {
                ui.label(
                    RichText::new("class source (read-only)")
                        .small()
                        .color(Color32::GRAY),
                );
                egui::Resize::default()
                    .id_salt("class-source-pane")
                    .default_width(900.0)
                    .default_height(600.0)
                    .resizable([true, true])
                    .show(ui, |ui| {
                        let _ = self.render_code_lines(ui);
                    });
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("Choose a method or class from Search to open its code.")
                });
            }
            return;
        }
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
        let mut code_interaction = None;
        let mut chosen_edit: Option<EditRequest> = None;
        let narrow = ui.available_width() < 820.0;
        if narrow {
            ui.vertical(|ui| {
                egui::Resize::default()
                    .id_salt("smali-pane-narrow")
                    .default_width(ui.available_width().max(320.0))
                    .default_height(520.0)
                    .min_width(260.0)
                    .min_height(260.0)
                    .resizable([true, true])
                    .show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new("smali (read-only)")
                                    .small()
                                    .color(Color32::GRAY),
                            );
                            code_interaction = self.render_code_lines(ui);
                        });
                    });
                if !self.instruction_pane_collapsed {
                    ui.collapsing("Method changes", |ui| {
                        self.show_instruction_nodes(ui, &mut chosen_edit);
                    });
                }
            });
        } else {
            ui.horizontal_top(|ui| {
                egui::Resize::default()
                    .id_salt("smali-pane")
                    .default_width(620.0)
                    .min_width(260.0)
                    .resizable([true, false])
                    .show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new("smali (read-only)")
                                    .small()
                                    .color(Color32::GRAY),
                            );
                            code_interaction = self.render_code_lines(ui);
                        });
                    });
                if !self.instruction_pane_collapsed {
                    egui::Resize::default()
                        .id_salt("instruction-node-pane")
                        .default_width(330.0)
                        .min_width(240.0)
                        .resizable([true, false])
                        .show(ui, |ui| {
                            self.show_instruction_nodes(ui, &mut chosen_edit);
                        });
                }
            });
        }
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
                            .max_height(440.0)
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
            ui.label("B — set a breakpoint on the selected instruction");
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
                if self.busy() && self.pending_op.as_deref() == Some("edit_search") {
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

    fn render_code_lines(&self, ui: &mut egui::Ui) -> Option<CodeInteraction> {
        let lines = self.code.lines.clone();
        let breakpoints = self.code.breakpoints.clone();
        let selected = self.code.selected_offset;
        let highlighted = self.code.highlighted_offset;
        let mut interaction = None;
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
                            let fill = if is_highlighted {
                                Color32::from_rgb(75, 65, 30)
                            } else if is_selected {
                                Color32::from_rgb(30, 58, 82)
                            } else {
                                Color32::TRANSPARENT
                            };
                            egui::Frame::NONE.fill(fill).show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.add_sized(
                                        [34.0, 20.0],
                                        egui::Label::new(
                                            RichText::new(format!("{}", index + 1))
                                                .small()
                                                .color(Color32::DARK_GRAY),
                                        ),
                                    );
                                    if let Some(offset) = offset {
                                        let marker = if breakpoints.contains(&offset) {
                                            "●"
                                        } else {
                                            "○"
                                        };
                                        if ui
                                            .add_sized(
                                                [22.0, 20.0],
                                                egui::Button::new(RichText::new(marker).color(
                                                    if breakpoints.contains(&offset) {
                                                        Color32::RED
                                                    } else {
                                                        Color32::GRAY
                                                    },
                                                )),
                                            )
                                            .clicked()
                                        {
                                            interaction = Some(CodeInteraction {
                                                offset,
                                                action: None,
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
                                            interaction = Some(CodeInteraction { offset, action });
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
                                                    action: Some(CodeAction::EnclosingMethodXrefs),
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
                                            }
                                        });
                                    } else {
                                        ui.add(egui::Label::new(highlight_smali(line)));
                                    }
                                });
                            });
                        }
                    });
                });
        });
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
        if self.graph.total_nodes > self.graph.nodes.len() {
            ui.label(RichText::new(format!("Showing the first {} of {} nodes for interactive rendering; raw DOT below is complete.", self.graph.nodes.len(), self.graph.total_nodes)).small().color(Color32::YELLOW));
        }
        egui::Resize::default()
            .id_salt("graph-pane")
            .default_height(520.0)
            .min_height(240.0)
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
        let nodes = self.filtered_graph_nodes();
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
        let (min, max) = layout_bounds(&nodes, &self.graph.layout, base_node_size);
        let logical_size = (max - min).max(Vec2::new(1.0, 1.0)) + Vec2::splat(80.0);
        let fit_zoom = ((viewport.x - 24.0) / logical_size.x)
            .min((viewport.y - 24.0) / logical_size.y)
            .clamp(0.12, 1.5);
        let zoom = if self.graph.fit_to_view {
            fit_zoom
        } else {
            self.graph.zoom
        };
        let canvas = Vec2::new(
            (logical_size.x * zoom + 24.0).max(viewport.x),
            (logical_size.y * zoom + 24.0).max(viewport.y).max(320.0),
        );
        egui::Frame::dark_canvas(ui.style()).show(ui, |ui| {
            egui::ScrollArea::both()
                .id_salt("graph-canvas")
                .show(ui, |ui| {
                    let (rect, _) = ui.allocate_exact_size(canvas, Sense::hover());
                    let painter = ui.painter_at(rect);
                    let origin = rect.left_top() + Vec2::new(40.0, 40.0) - min * zoom;
                    let mut positions = HashMap::new();
                    let mut node_rects = HashMap::new();
                    for (id, label) in &nodes {
                        let Some(position) = self.graph.layout.get(id) else {
                            continue;
                        };
                        let center = origin + *position * zoom;
                        let node_rect = Rect::from_center_size(center, base_node_size * zoom);
                        positions.insert(*id, center);
                        node_rects.insert(*id, node_rect);
                        let _ = label;
                    }
                    for (from, to) in &edges {
                        if let (Some(from_rect), Some(to_rect)) =
                            (node_rects.get(from), node_rects.get(to))
                        {
                            let direction = to_rect.center() - from_rect.center();
                            if direction.length_sq() <= f32::EPSILON {
                                continue;
                            }
                            let unit = direction.normalized();
                            let start = rect_boundary_point(*from_rect, unit);
                            let end = rect_boundary_point(*to_rect, -unit);
                            painter.line_segment(
                                [start, end],
                                Stroke::new(1.0, Color32::from_rgb(80, 100, 120)),
                            );
                            let arrow_size = (6.0 * zoom).clamp(3.0, 8.0);
                            let side = Vec2::new(-unit.y, unit.x);
                            painter.line_segment(
                                [end, end - unit * arrow_size + side * arrow_size * 0.55],
                                Stroke::new(1.0, Color32::from_rgb(110, 135, 155)),
                            );
                            painter.line_segment(
                                [end, end - unit * arrow_size - side * arrow_size * 0.55],
                                Stroke::new(1.0, Color32::from_rgb(110, 135, 155)),
                            );
                        }
                    }
                    let mut clicked_node = None;
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
                        response.on_hover_text(label);
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
                });
        });
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

    fn show_debugger(&mut self, ui: &mut egui::Ui) {
        ui.heading("JDWP debugger");
        ui.label("Forward the Android process with adb, then connect here. The worker waits for events off the UI thread.");
        ui.horizontal(|ui| {
            ui.label("Host");
            ui.add(egui::TextEdit::singleline(&mut self.debug.host).desired_width(130.0));
            ui.label("Port");
            ui.add(egui::TextEdit::singleline(&mut self.debug.port).desired_width(70.0));
            if ui.button("Connect").clicked() {
                let port = self.debug.port.parse::<u16>().unwrap_or(8000);
                self.request(
                    "debug_connect",
                    json!({"op":"debug_connect", "host":self.debug.host, "port":port}),
                );
            }
            if ui.button("List JDWP apps").clicked() {
                self.request("debug_apps", json!({"op":"debug_apps"}));
            }
            if ui.button("Wait").clicked() && self.debug.connected {
                self.request("debug_wait", json!({"op":"debug_wait"}));
            }
        });
        if !self.debug.apps.is_empty() {
            ui.label(RichText::new("JDWP processes").strong());
            for app in &self.debug.apps {
                ui.label(RichText::new(app).monospace().small());
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
                if ui.button("Resume (F5)").clicked() {
                    self.request("debug_resume", json!({"op":"debug_resume"}));
                }
                if ui.button("Step (F10)").clicked() {
                    self.request("debug_step", json!({"op":"debug_step"}));
                }
            });
            ui.label("Register values");
            let mut set_value = None;
            for (slot, observed, edit) in self.debug.values.clone() {
                ui.horizontal(|ui| {
                    ui.label(format!("v{slot}"));
                    ui.label(RichText::new(&observed).monospace().small());
                    let mut edited = edit;
                    ui.add(egui::TextEdit::singleline(&mut edited).desired_width(180.0));
                    if ui.button("Set").clicked() {
                        set_value = Some((slot, edited.clone()));
                    }
                    self.debug.edits.insert(slot, edited);
                });
            }
            if let Some((slot, value)) = set_value {
                self.request(
                    "debug_set_value",
                    json!({"op":"debug_set_value", "slot":slot, "value":value}),
                );
            }
            ui.label(RichText::new("The Code tab highlights the stopped code index. Select an instruction and press B to set a breakpoint.").small().color(Color32::GRAY));
        } else {
            ui.add_space(20.0);
            ui.centered_and_justified(|ui| ui.label("No stopped stack frame yet."));
        }
    }
}

impl eframe::App for CoeusApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.debug.waiting
            && !self.busy()
            && self.debug.last_poll.elapsed() >= Duration::from_millis(250)
        {
            self.debug.last_poll = Instant::now();
            self.request("debug_poll", json!({"op":"debug_poll"}));
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
            } else if f5 && self.debug.frame.is_some() {
                self.request("debug_resume", json!({"op":"debug_resume"}));
            } else if f10 && self.debug.frame.is_some() {
                self.request("debug_step", json!({"op":"debug_step"}));
            }
        }
        self.show_sidebar(ctx);
        self.show_tabs(ctx);
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Search => self.show_search(ui),
            Tab::Code => self.show_code(ui),
            Tab::Graph => self.show_graph(ui),
            Tab::Debugger => self.show_debugger(ui),
        });
        self.show_edit_picker(ctx);
        self.show_graph_node_details(ctx);
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

fn value_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or_default()
}

fn optional_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn edit_picker_kind(value: &Value) -> Option<SearchKind> {
    match value_string(value, "picker").as_str() {
        "methods" => Some(SearchKind::Methods),
        "classes" => Some(SearchKind::Classes),
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
                .map(|result| ResultRow {
                    id: value_string(result, "id"),
                    kind: value_string(result, "kind"),
                    label: value_string(result, "label"),
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

fn parse_dot(dot: &str) -> (Vec<(usize, String)>, Vec<(usize, usize)>, usize, usize) {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut known = HashSet::new();
    let mut total_nodes = 0;
    let mut total_edges = 0;
    for line in dot.lines() {
        let trimmed = line.trim();
        if let Some((left, right)) = trimmed.split_once("->") {
            if let (Some(from), Some(to)) = (parse_dot_id(left), parse_dot_id(right)) {
                total_edges += 1;
                if known.contains(&from) && known.contains(&to) {
                    edges.push((from, to));
                }
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
        if known.len() < MAX_RENDER_NODES && known.insert(id) {
            nodes.push((id, label));
        }
    }
    nodes.sort_by_key(|(id, _)| *id);
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
    nodes: &[(usize, String)],
    layout: &HashMap<usize, Vec2>,
    node_size: Vec2,
) -> (Vec2, Vec2) {
    let mut min = Vec2::splat(f32::INFINITY);
    let mut max = Vec2::splat(f32::NEG_INFINITY);
    for (id, _) in nodes {
        let Some(position) = layout.get(id) else {
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
    let mut positions = Vec::with_capacity(node_count);
    let columns = (node_count as f32).sqrt().ceil() as usize;
    let spacing = 250.0;
    for index in 0..node_count {
        let column = index % columns;
        let row = index / columns;
        positions.push(Vec2::new(
            (column as f32 - columns as f32 / 2.0) * spacing,
            (row as f32 - node_count as f32 / columns as f32 / 2.0) * spacing,
        ));
    }
    let edge_indices = edges
        .iter()
        .filter_map(|(from, to)| Some((*indices.get(from)?, *indices.get(to)?)))
        .collect::<Vec<_>>();
    let ideal_distance = 205.0;
    let iterations = 90;
    for iteration in 0..iterations {
        let mut displacement = vec![Vec2::ZERO; node_count];
        for left in 0..node_count {
            for right in (left + 1)..node_count {
                let delta = positions[left] - positions[right];
                let distance = delta.length().max(1.0);
                let direction = delta / distance;
                let force = ideal_distance * ideal_distance / distance;
                displacement[left] += direction * force;
                displacement[right] -= direction * force;
            }
        }
        for (from, to) in &edge_indices {
            let delta = positions[*from] - positions[*to];
            let distance = delta.length().max(1.0);
            let direction = delta / distance;
            let force = (distance - ideal_distance) * 0.035;
            displacement[*from] -= direction * force;
            displacement[*to] += direction * force;
        }
        let temperature =
            ideal_distance * 0.24 * (1.0 - iteration as f32 / iterations as f32).max(0.05);
        for (index, position) in positions.iter_mut().enumerate() {
            // A small global gravitational pull keeps disconnected components
            // together while the repulsion term preserves readable spacing.
            displacement[index] -= *position * 0.008;
            let distance = displacement[index].length().max(1.0);
            *position += displacement[index] / distance * distance.min(temperature);
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
    fn force_layout_returns_every_visible_node() {
        let nodes = vec![
            (0, "method".to_string()),
            (1, "class".to_string()),
            (2, "string".to_string()),
        ];
        let layout = layout_graph(&nodes, &[(0, 1), (1, 2)]);
        assert_eq!(layout.len(), nodes.len());
    }
}

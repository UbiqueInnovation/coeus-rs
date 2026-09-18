# Coeus GUI

`coeus-gui` is a native `egui` desktop frontend with two interchangeable
analysis backends. Both receive and return the same JSON request/response
objects used by the UI:

- `python` keeps the existing `bridge.py` worker and `coeus-python` wheel.
- `rust` uses the `coeus` crates directly, with no Python process or PyO3
  interop.

## Build and run

The native Rust backend needs only the Rust dependencies:

```text
cd coeus-gui
COEUS_GUI_BACKEND=rust cargo run --release
```

To use the compatibility backend, build the Python extension from
`coeus-python` and install its wheel into the Python environment that will run
the worker:

```text
cd coeus-python
maturin build --release
python3 -m pip install --force-reinstall target/wheels/<wheel>.whl
cd ../coeus-gui
cargo run --release
```

The Python backend remains the default for compatibility. Select either
backend at runtime without rebuilding:

```text
COEUS_GUI_BACKEND=python cargo run --release
COEUS_GUI_BACKEND=rust cargo run --release
```

Use **Open APK…** in the sidebar or welcome screen to choose an APK. The Python
executable can be overridden with `COEUS_PYTHON=/path/to/python` when using
the Python backend. The Rust backend covers the same current GUI feature set:
APK loading, split APK sets, manifest changes, search, inspection, graphing,
DEX string/instruction editing, project archives, ADB operations, signing,
installation, keystore generation, JDWP debugging, and replayable Python
script export. Native inspection commands can run concurrently; state-changing
commands are serialized per loaded analysis.
The project controls can save and reopen a `.coeus` project archive. The
archive is the GUI's portable virtual project boundary: it contains the
current bytes of every APK member, Coeus edit history, and GUI annotations.
Both backends store `gui/session.py`, a generated Python replay script, and
support exporting that script separately. Reopening an archive does not
require the source APKs to remain available.
The project/search sidebar, code pane, instruction pane, graph canvas, and
source panes can be resized; the project and instruction panes can also be
collapsed. The Code / Edit tab gives the smali source and replacement-node
pane the full available work area, with replacement nodes attached to the
left side of the code view.

## Workspace controls

The workspace uses a consistent dark theme, with navigation across the top
and operation status along the bottom. The welcome screen opens APKs, split
sets, saved projects, or the device browser. **Paths & output** in the sidebar
exposes direct path loading and the edited APK destination.

- **Cmd/Ctrl+O** opens an APK; **Cmd/Ctrl+S** saves a project.
- **Cmd/Ctrl+F** expands the sidebar and focuses search. Press Enter to search.
- Search accepts regular expressions, validates syntax before submitting, and
  explains empty results. The Search tab offers entry-point, cryptography, and
  URL searches to get started.
- Results show the member name above its class. Hover for the full identifier;
  click to inspect, or right-click for cross-references and notes.
- Failed backend operations stay visible until dismissed, with a control to
  copy details. Pending manifest edits are visible in the status bar; click
  the indicator to return to the editor.
- The **B** breakpoint shortcut applies in Code / Edit when no text input has
  focus. **F5** resumes and **F10** steps a connected debugger.

Toolbars wrap at smaller window sizes. Signing forms and instruction controls
scroll independently so actions remain reachable in shorter windows.

In Graphs, hold **Cmd** (Ctrl on other platforms) and scroll over the canvas to
zoom around the pointer. Ordinary scrolling pans the graph. Click or drag the
minimap to center the viewport on that part of the graph; **Fit to view** returns
to the overview. Call graph layers and supergraph rings leave space between
nodes, including when a large ring is followed by a smaller one.

The ADB tab lists installed packages on a connected device. Select a package
to pull its base APK and split APKs to a local directory, or load the complete
split set directly for analysis. The Sign / Install tab signs single APKs with
`apksigner` and split sets with `SplitApkSet.sign_all()`, then installs them
with `adb install` or `adb install-multiple`.

The Manifest tab exposes an editable, XML-syntax-highlighted
AndroidManifest.xml, a lightweight formatter, and shortcuts for enabling
debuggable mode and allowing plaintext traffic with user-installed
certificates.

The Sign / Install tab can generate `debug.keystore` beside the loaded APK or
project. It uses `keytool`, fills the generated path into the signing form,
and refuses to overwrite an existing keystore.

When a method is open in Code / Edit, **Emulate** opens an argument form and
runs the method in Coeus's embedded DexVm. Primitive values and strings can be
entered directly; byte arrays accept JSON numbers or a `hex:` value. The result
dialog reports the returned value or the VM failure. The same action is
available from a method's source-line context menu in both class and method
disassemblies. That menu can also open the exact method disassembly, emulate a
referenced method, or ask the static flow analyzer for possible call-site
arguments. Guessed sets can be used individually or run together.
The flow search is bounded per method (256 iterations and 32 branches), with at
most 512 caller methods and 256 returned argument sets; the UI reports when
those limits produce partial results.

## Editing model

The code pane is intentionally not a free-form smali text editor. Coeus
decodes every instruction into an object with an offset and width. The GUI
exposes those instruction objects as nodes and derives typed factory and
insertion actions from the selected node. Applying a node calls the
transactional object-based editing API and reparses the affected DEX, so
branches and payloads can be relaid out and subsequent searches and code views
use the new analysis.

The node pane uses the redesigned transactional method-edit API. The UI keeps
arbitrary text out of the mutation path; textual smali remains a
syntax-highlighted inspection view.

Selecting a string result opens a string-pool editor. Its replacement is sent
to `AnalyzeObject.replace_string`, preserving the string index so existing DEX
references use the new value. Code instructions expose typed method, class,
field, and string targets for command-click and context-menu navigation. The
Back and Forward controls follow completed object navigations, including
cross-reference results; opening a new object from the middle of the stack
starts a new branch. They also accept Command-Tab for forward and
Command-Shift-Tab for backward navigation when the operating system forwards
those shortcuts to the application.

Methods, classes, and DEX strings can be annotated from the Search result menu,
the selected object view, or the Code header/context menu. Notes use canonical
object identities, so a yellow post-it chip appears beside the object wherever
it is referenced in search results, cross-references, graph details, or decoded
code. Click a chip to read the full note; notes are stored in the GUI metadata
when a `.coeus` project is saved.

Instruction nodes with parameters open a typed argument form before applying.
For example, the function replacement node exposes argument register count,
target method index, and first argument register. The catalog includes all
currently exposed `DexInstruction` factories, including conditional branches,
switch, string, literal, move, cast, allocation, and invocation nodes.
DEX-index arguments include a picker that reuses the left-pane regex search,
scopes results to the selected method's DEX, and fills the relative method,
type, or string-pool index after selection.

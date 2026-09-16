# Coeus GUI

`coeus-gui` is a native `egui` desktop frontend for the existing
`coeus-python` API. The Rust process owns the UI and a small Python worker
owns `AnalyzeObject` and `Debugger` instances behind a JSON-lines protocol.

## Build and run

Build the Python extension from `coeus-python` and install its wheel into the
Python environment that will run the worker:

```text
cd coeus-python
maturin build --release
python3 -m pip install --force-reinstall target/wheels/<wheel>.whl
cd ../coeus-gui
cargo run --release
```

Use the Browse button to choose an APK in the application. The Python
executable can be overridden with `COEUS_PYTHON=/path/to/python`.
The project controls can save and reopen a `.coeus` project archive. The
archive is the GUI's portable virtual project boundary: it contains the
current bytes of every APK member, Coeus edit history, GUI annotations, and
`gui/session.py`, a generated Python replay script. `Export script…` writes
that script separately for review or automation. Reopening an archive does
not require the source APKs to remain available.
The project/search sidebar, code pane, instruction pane, graph canvas, and
source panes can be resized; the project and instruction panes can also be
collapsed. The Code / Edit tab gives the smali source and replacement-node
pane the full available work area, with replacement nodes attached to the
left side of the code view.

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

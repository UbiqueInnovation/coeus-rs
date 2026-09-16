# Coeus

## What is Coeus

Coeus is a framework to analyse mobile applications.
Currently its main focuse is on Android APKs, but there are plans to expand native code analysis.

Coeus is composed of various different sub-crates to make it as modular as possible.
Coeus exposes a [rhai](https://rhai.rs/) interface which has quite some abstractions, but is considered deprecated.
Currently the plan is to improve the Python interface, as it offers much more possibilities into further analysis, as, e.g. combining Coeus with the excellent [Capstone](https://www.capstone-engine.org/) disassembler.

## How to use it

The easiest way to play around with Coeus is to use the [coeus-python](./coeus-python) module, and look at the examples.
For build instructions check out the [Readme](./coeus-python/README.md) in the coues-python module.

Next to the `coeus-python` module there is also a Rhai interface, which could be used, though usage is deprecated. To actually build the Rhai interface, use the feature-flag `rhai`.

Coeus can also be used as a crate in another Rust application. Just add it as a dependency to your project and start using it ;).

See the [examples](examples) directory for a simple tutorial and some example usage scenarios of Coeus.

## What can Coeus do?

Coeus offers the following features:

- Extract APKs and other zip-like archives
- Parse all Dex files found
- Parse all Native-Object-Files (thanks to [goblin](https://docs.rs/goblin/0.5.1/goblin/))
- Round-trip APK contents, including binary XML/resources, DEX files, and added native libraries
- Edit manifest XML, add intent filters/resources, and create a network-security config trusting user CAs
- Patch DEX instructions or inject `System.loadLibrary(...)` calls
- Provide methods to search for objects within the dex-file
- Provide a Dex-Emulator for simple Code execution
- Build a Graph of an Application and provide Callgraphs and such (thanks to [petgraph](https://docs.rs/petgraph/latest/petgraph/))
- Provide Information-Flow-Analysis for static function evaluation
- Minimal implementation of the JDWP protocol to allow "smali"-debugging

## Editing and repackaging APKs

The Python interface keeps the original APK entries available and writes an
unsigned edited APK. It can modify the manifest as text, add or replace files
(including `lib/<abi>/*.so`), patch DEX code, and repackage the result:

```python
from pathlib import Path
from coeus_python import AnalyzeObject, DexInstruction

apk = AnalyzeObject("input.apk", False, -1)
apk.set_debuggable(True)
apk.set_package_name("com.example.modified")
apk.allow_plaintext_and_user_certificates()
apk.add_file("lib/arm64-v8a/libfrida-gadget.so",
             Path("libfrida-gadget.so").read_bytes())

# Prefer analysis objects when selecting code to edit. Evidence can be
# downcast to a Method, and the concrete instruction objects retain offsets
# and widths for safe same-size replacements.
method = apk.find_methods("load|onCreate")[0].as_method()
instructions = method.get_instructions()
apk.replace_instruction(method, instructions[0], DexInstruction.nop())
method.inject_load_library(apk, "frida-gadget", register)
# Or select the overload directly from a Class object:
# clazz.inject_load_library(apk, "onCreate", "frida-gadget", register,
#                           "(Landroid/os/Bundle;)V")
apk.write_apk("edited-unsigned.apk")
```

For variable-width edits, use a transactional `MethodEditor`. Branch and
switch targets remain symbolic until the edit is committed:

```python
editor = apk.edit_method(method)
instructions = method.get_instructions()
target = editor.label_before(instructions[-1])
editor.insert_before(instructions[2], [DexInstruction.nop()])
editor.replace(instructions[1], [DexInstruction.nop(), DexInstruction.nop()])
editor.replace(instructions[0], [DexInstruction.if_eqz(0, target)])
method = editor.commit(apk)
```

Switches can be created with
`DexInstruction.switch(register, [(case_value, label), ...], default)`;
payloads and their alignment are generated automatically.

String values can be edited without manually managing string IDs:
`DexInstruction.const_string_value(register, "replacement")`. On commit,
missing values are added to the DEX string pool and the instruction is encoded
as `const-string` or `const-string/jumbo` as required. The existing
`const_string(register, string_index)` constructor remains available for
explicit numeric-index edits.

To change a string-pool entry globally, pass a `DexString` from
`apk.get_strings_as_string()` to `apk.replace_string(string, "replacement")`.
This keeps the string ID stable, so every DEX reference to that entry observes
the replacement.

`allow_plaintext_and_user_certificates()` creates
`res/xml/coeus_network_security_config.xml` and its `resources.arsc` entry if
the input APK does not have one, then wires the typed reference into the
application manifest. `set_manifest_xml()` supports complete textual edits,
including intent filters and other manifest elements; `set_xml_resource()` is
available for existing binary-XML resources.

The output has invalidated `META-INF` signature files removed and is ZIP
aligned, including stored entries, `resources.arsc`, and page-aligned native
libraries. Sign it with a test key before installing it; Android will not
install an unsigned APK. Changing the package name changes the Android install
identity, but does not rename DEX class descriptors or package-qualified
component names. Variable-width DEX editing currently requires a method
without try/catch handlers; switch and fill-array payloads are rebuilt by
`MethodEditor`. Rewritten methods currently omit debug position/local-variable
metadata. Native code recompilation is not included—native libraries can be
added or replaced.

## Split APKs and interactive sessions

`SplitApkSet` keeps every APK from a split install as a live
`AnalyzeObject`, while providing set-wide write, sign, verify, install, and
launch operations. `from_adb()` pulls the base APK and all paths reported by
`pm path`; `get_base_apk()` selects the base member even if the input order is
different:

```python
from coeus_python import SplitApkSet

state = SplitApkSet.from_adb("com.example.app", serial="DEVICE")
base = state.get_base_apk()
base.set_debuggable(True)
base.allow_plaintext_and_user_certificates()
state.save_state("debuggable.coeus")

state.sign_all("signed", "debug.keystore", "androiddebugkey", "android")
state.verify_all("signed")
state.install_all("signed", serial="DEVICE")
state.launch("com.example.app", serial="DEVICE")
```

The state archive stores the current editable, unsigned APK members under
`apks/` and a `state.json` high-level action history. Loading a checkpoint is
the supported way to go back to an earlier state; the history is an audit log,
not an automatic inverse for arbitrary DEX edits.

For a line-oriented workflow, run the repository-provided shell:

```text
python coeus-python/coeus_shell.py
coeus> pull com.example.app DEVICE
coeus> use 0
coeus> debuggable on
coeus> plaintext
coeus> save work.coeus
coeus> sign signed debug.keystore androiddebugkey
coeus> install signed DEVICE
coeus> launch com.example.app DEVICE
coeus> debug list DEVICE
coeus> debug connect 0 DEVICE 8000
coeus> debug wait
```

The shell's `python` command opens a normal Python console with every public
`coeus_python` object preloaded, plus `state`, `apk`, and `shell`; no import
statement is needed for method/class-based DEX analysis and instruction-object
editing. Tab completes shell commands and path arguments; the embedded Python
console also enables identifier and attribute completion when readline is
available.

## Native GUI

The repository also contains a native `egui` frontend in [coeus-gui](./coeus-gui).
It uses a small JSON-line Python worker so the existing `coeus-python` API
remains the source of truth while analysis runs off the UI thread. The GUI
supports regex searches, syntax-highlighted smali inspection, cross-reference
navigation, interactive callgraph/supergraph rendering, JDWP stepping and
stack/register inspection, and structured method editing through typed nodes.
It also includes direct DEX string-pool replacement, resizable and collapsible
panes, typed code-reference navigation, and a force-directed graph canvas with
node-type styling.

The code pane deliberately does not accept arbitrary smali text. It exposes
typed `DexInstruction` factories as instruction nodes and commits anchored
replacements or insertions through `AnalyzeObject.edit_method()`. See
[coeus-gui/README.md](./coeus-gui/README.md) for build instructions.

Installed packages can be filtered before pulling one:

```text
coeus> list heidi DEVICE
```

The expression is matched against the complete package name; omit it to list
everything reported by `pm list packages`.

`debug list` uses `adb jdwp` to find processes with a JDWP agent, resolves
their process/package names, and displays any match against the package name
from the currently loaded manifest. `debug connect` forwards the selected
process over USB and creates a `coeus_python.Debugger` connected to
`127.0.0.1:8000` (or the supplied port). Use `debug resume`, `debug wait`,
`debug step`, and `debug breakpoints` for the common control operations. The
`python` command exposes the live `debugger`, `debug_app`, and `debug_frame`
objects for the rest of the debugger API.

## Contributions

Please feel free to open PRs and contribute to Coeus.

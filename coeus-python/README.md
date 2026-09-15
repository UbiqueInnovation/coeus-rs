# Coeus-Python

Coeus-Python is the Python interface to interact with the `coeus` library.
It uses `pyo3` to expose the `coeus` API.

This is useful for quick prototyping and performing analysis with coeus from Python.

## Build

1. Install [maturin](https://github.com/PyO3/maturin).
2. Build the Rust crate and the Python API into a wheel: `maturin build --release`.
3. Install the wheel: `python3 -m pip install --force-reinstall target/wheels/<wheel-name>.whl`.

## Type Hints

Coeus-Python includes type hints, which should provide enough information for IDEs to provide type checking and auto completion.
These hints are packaged into the wheel.

When you edit the Python API please also update the `coeus_python.pyi` accordingly.

## Using Coeus-Python

The entrypoint for working with Coeus-Python is the `AnalyzeObject`.
This object provides functions to load and parse an APK, as well as search throught the APK.

See the [examples](../examples) directory for a code example.

## APK editing and repackaging

`AnalyzeObject` preserves APK entries and exposes a small editing API. The
writer produces an unsigned APK, so align and sign it before installation:

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
# downcast to a Method, and concrete instruction objects retain offsets and
# widths for safe same-size replacements.
method = apk.find_methods("load|onCreate")[0].as_method()
instructions = method.get_instructions()
apk.replace_instruction(method, instructions[0], DexInstruction.nop())
method.inject_load_library(apk, "frida-gadget", register)
# Or select the overload directly from a Class object:
# clazz.inject_load_library(apk, "onCreate", "frida-gadget", register,
#                           "(Landroid/os/Bundle;)V")
apk.write_apk("edited-unsigned.apk")
```

`set_package_name()` changes the Android install identity in the manifest;
it does not rename DEX descriptors or package-qualified component names.
`set_manifest_xml()` replaces the manifest from text, so intent filters and
other elements can be edited directly. `set_xml_resource()` does the same for
existing binary-XML resources. The network shortcut bundles a minimal
network-security XML resource, creates the missing `resources.arsc` entry when
necessary, enables cleartext traffic, and trusts both the system and user CA
stores. DEX injection emits `const-string` followed by
`System.loadLibrary(String)`; choose an available local register. The writer
produces a ZIP-aligned APK, including page-aligned native libraries, but it
remains unsigned. Methods
with try/catch or switch/array payloads are rejected for safe insertion.

## Split APKs, signing, and save states

`SplitApkSet` holds one `AnalyzeObject` per APK member and has set-wide
operations for repacking, signing with the Android SDK's `apksigner`,
verification, installation, and launching:

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

`AnalyzeObject.sign_apk()` and `SplitApkSet.sign_all()` automatically locate
the newest `apksigner` under `ANDROID_SDK_ROOT`/`ANDROID_HOME`, or use the
`apksigner=` override. The `.coeus` archive contains the current unsigned
repacked APK members and `state.json` with high-level actions. Reloading a
checkpoint with `SplitApkSet.load_state()` is the reliable undo mechanism;
the action history is not an automatic inverse for arbitrary edits.

For a ready-made interactive workflow, run `python coeus_shell.py` from this
directory (or `python coeus-python/coeus_shell.py` from the repository root).
The shell supports `pull`, `load`, `open`, `use`, `manifest`, `debuggable`,
`plaintext`, `add`, `xml`, `save`, `write`, `sign`, `verify`, `install`, and
`launch`. `list [REGEX] [SERIAL]` filters installed package names from adb
before choosing a package to pull. Its `python` command opens a normal Python
console with every public `coeus_python` object preloaded, plus `state`, `apk`,
and `shell`; no import statement is needed for full class/method and
instruction-object editing. Tab completes shell commands and common path
arguments, and the embedded Python console enables Python identifier and
attribute completion when readline is available.

## Native Support

Currently, most of the analysis is done on the dex part of the APK (aka. Java).
There is the possibility to search for imported/exported functions in native libraries.
There is also experimental support to search for strings in the `.rodata` section of the ELF binary.

## Emulation

In order to get and analyse certain static (heap allocated) fields the static constructor of a class needs to be run.
This is demonstrated in the following code sample:

```python
from coeus_python import AnalyzeObject, DexVm;

# Parse and load the APK
ao = AnalyzeObject("test.apk", True, 0);

# Find the interesting field
# in this case we already know what we are looking for:
# Lch/admin/bag/covidcertificate/sdk/android/SdkEnvironment;->PROD

fields = ao.find_fields("^PROD$")
# here we should be more rigorous, but since we basically find references to the field and 
# the fields definition we have to check multiple locations
field = fields[1].as_field()

# We also know in which class the field is defined... 
SdkEnviornment = ao.find_classes("SdkEnvironment")[0].as_class()

# ... and that it is a static class with heap allocated static fields, hence has a <clinit>
class_initializer = field.dex_class["<clinit>"]
# Now we construct a VM based on the resources found in the AnalyzeObject
vm = DexVm(ao)
# The library overides __call__, which means we can conveniently just call the methods
# If there were any arguments we could also supply the arguments. Primitive types should
# be automatically converted. For complex types it is a bit more involved
# as we need to provide a pointer to the object in the VMs HEAP
class_initializer(vm=vm)
print(field.fqdn())
# Now we can just access the static field based on the fully qualified domain name.
# The Value is indexable, and returns fields on the class.
print(vm.get_static_field(field.fqdn()).get_value()["trustListBaseUrl"])
```

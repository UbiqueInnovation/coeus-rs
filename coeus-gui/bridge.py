#!/usr/bin/env python3
"""JSON-line worker used by the native Coeus GUI.

The worker intentionally owns all Coeus Python objects.  The Rust process only
deals in small JSON values, which keeps the GUI responsive while preserving the
existing Python API as the single source of truth for analysis and debugging.
"""

import queue
import re
import shutil
import subprocess
import sys
import json
import tempfile
import threading
import traceback
import os
import zipfile
from pathlib import Path

from coeus_python import (
    AnalyzeObject,
    DexInstruction,
    Debugger,
    StackValue,
    SplitApkSet,
    VmInstance,
    forward_jdwp,
    list_debuggable_apps,
)


# The transactional MethodEditor is the current object-based editing API. Keep
# an environment kill switch for older installed wheels that do not expose it.
ENABLE_EXPERIMENTAL_METHOD_EDITS = os.environ.get(
    "COEUS_GUI_ENABLE_METHOD_EDITS", "1"
).lower() in ("1", "true", "yes")


class Backend:
    def __init__(self):
        self.ao = None
        self.split_set = None
        self.objects = {}
        self.next_object_id = 1
        self.debugger = None
        self.debug_frame = None
        self.debug_method = None
        self.debug_values = []
        self.debug_wait = None
        self.debug_waiting = False
        self.debug_breakpoints = set()
        self.debug_control_queue = queue.Queue()
        self.debug_connect_result = None
        self.debug_connecting = False
        self.debug_apps_result = None
        self.debug_apps_loading = False
        self.session_origin = None
        self.session_events = []
        self.session_script_override = None
        self.notes = {}

    def _refresh_method(self, object_id):
        """Refresh a method wrapper after Coeus reparses an edited DEX."""
        entry = self._entry(object_id)
        signature = entry["object"].signature()
        found = self.ao.find_methods(re.escape(signature))
        for evidence in found:
            try:
                entry["object"] = evidence.as_method()
                entry["evidence"] = evidence
                entry["kind"] = "method"
                return entry["object"]
            except Exception:
                pass
        raise RuntimeError("edited method could not be found after reparsing")

    def _id(self, obj, evidence=None, kind=None):
        object_id = "object-{}".format(self.next_object_id)
        self.next_object_id += 1
        if kind is None:
            kind, obj = self._concrete(evidence if evidence is not None else obj)
        self.objects[object_id] = {
            "object": obj,
            "evidence": evidence,
            "kind": kind,
        }
        return object_id

    @staticmethod
    def _concrete(value):
        for kind, method in (
            ("field_access", "as_field_access"),
            ("method", "as_method"),
            ("class", "as_class"),
            ("field", "as_field"),
            ("string", "as_string"),
            ("native", "as_native_symbol"),
        ):
            try:
                return kind, getattr(value, method)()
            except Exception:
                pass
        return "unknown", value

    @staticmethod
    def _label(kind, obj):
        try:
            if kind == "method":
                return obj.signature()
            if kind == "class":
                return obj.name()
            if kind == "field":
                return obj.fqdn()
            if kind == "string":
                return obj.content()
            if kind == "native":
                return obj.symbol()
            if kind == "field_access":
                return "{} :: {}".format(obj.get_function().signature(), obj.get_instruction())
        except Exception:
            pass
        return str(obj)

    @staticmethod
    def _annotation_key(kind, obj):
        """Return an identity that survives transient GUI object IDs."""
        try:
            if kind == "method":
                return "method:{}".format(obj.signature())
            if kind == "class":
                return "class:{}".format(obj.name())
            if kind == "string":
                return "string:{}:{}".format(obj.get_dex_name(), obj.get_index())
        except Exception:
            pass
        return ""

    def _result(self, obj, evidence=None, kind=None):
        object_id = self._id(obj, evidence, kind)
        actual_kind = self.objects[object_id]["kind"]
        result = {
            "id": object_id,
            "kind": actual_kind,
            "label": self._label(actual_kind, self.objects[object_id]["object"]),
        }
        index = self._relative_index(
            actual_kind, self.objects[object_id]["object"]
        )
        if index is not None:
            result["index"] = int(index)
        dex_name = self._dex_name(actual_kind, self.objects[object_id]["object"])
        if dex_name:
            result["dex"] = dex_name
        annotation_key = self._annotation_key(
            actual_kind, self.objects[object_id]["object"]
        )
        if annotation_key:
            result["note_key"] = annotation_key
        return result

    @staticmethod
    def _relative_index(kind, obj):
        try:
            if kind == "method":
                return obj.get_method_idx()
            if kind == "class":
                return obj.get_type_idx()
            if kind == "string":
                return obj.get_index()
        except Exception:
            pass
        return None

    @staticmethod
    def _dex_name(kind, obj):
        try:
            if kind in {"method", "class", "string"}:
                return obj.get_dex_name()
        except Exception:
            pass
        return ""

    def load(self, path):
        self.ao = AnalyzeObject(path, False, -1)
        self.split_set = None
        self.session_origin = {"kind": "apk", "path": str(path)}
        self.session_events = []
        self.session_script_override = None
        self.notes = {}
        self.debug_breakpoints.clear()
        self.objects.clear()
        self.next_object_id = 1
        manifests = self.ao.get_manifests()
        package = manifests[0].get_package() if manifests else ""
        return {
            "path": path,
            "package": package,
            "dex": self.ao.get_dex_names(),
            "files": len(self.ao.get_file_names()),
            "manifest": self.ao.get_manifest_xml(),
            "split": False,
            "members": [],
            "notes": self.notes,
            "history": self._history(),
        }

    def load_split(self, paths):
        paths = [str(path) for path in paths if str(path).strip()]
        if not paths:
            raise RuntimeError("select at least one APK for the split set")
        self.split_set = SplitApkSet(paths, False, -1)
        self.ao = self.split_set.get_base_apk()
        self.session_origin = {"kind": "split", "paths": paths}
        self.session_events = []
        self.session_script_override = None
        self.notes = {}
        self.debug_breakpoints.clear()
        self.objects.clear()
        self.next_object_id = 1
        manifests = self.ao.get_manifests()
        package = manifests[0].get_package() if manifests else ""
        return {
            "path": ", ".join(paths),
            "package": package,
            "dex": self.ao.get_dex_names(),
            "files": len(self.ao.get_file_names()),
            "manifest": self.ao.get_manifest_xml(),
            "split": True,
            "members": self.split_set.get_names(),
            "notes": self.notes,
            "history": self._history(),
        }

    def load_split_from_adb(self, package, serial=None, adb_path=None):
        package = str(package).strip()
        if not package:
            raise RuntimeError("enter a package name to pull its split APKs")
        self.split_set = SplitApkSet.from_adb(
            package,
            str(serial).strip() if serial else None,
            str(adb_path).strip() if adb_path else None,
            False,
            -1,
        )
        self.ao = self.split_set.get_base_apk()
        self.session_origin = {
            "kind": "adb",
            "package": package,
            "serial": str(serial).strip() if serial else None,
            "adb_path": str(adb_path).strip() if adb_path else None,
        }
        self.session_events = []
        self.session_script_override = None
        self.notes = {}
        self.debug_breakpoints.clear()
        self.objects.clear()
        self.next_object_id = 1
        manifests = self.ao.get_manifests()
        actual_package = manifests[0].get_package() if manifests else package
        return {
            "path": "ADB: {}".format(package),
            "package": actual_package,
            "dex": self.ao.get_dex_names(),
            "files": len(self.ao.get_file_names()),
            "manifest": self.ao.get_manifest_xml(),
            "split": True,
            "members": self.split_set.get_names(),
            "notes": self.notes,
            "history": self._history(),
        }

    def load_project(self, path):
        path = str(path)
        self.split_set = SplitApkSet.load_state(path, False, -1)
        self.ao = self.split_set.get_base_apk()
        self.session_origin = {"kind": "state", "path": path}
        self.session_events = []
        self.session_script_override = None
        self.notes = {}
        try:
            with zipfile.ZipFile(path, "r") as archive:
                metadata = json.loads(archive.read("gui/session.json").decode("utf-8"))
                saved_script = archive.read("gui/session.py").decode("utf-8")
            if saved_script.strip():
                # The archive already contains the script for the edits that
                # produced its embedded APK bytes. Replaying those events on
                # the embedded, already-edited APK would apply them twice.
                self.session_script_override = saved_script
            notes = metadata.get("notes", {})
            if isinstance(notes, dict):
                self.notes = {
                    str(key): str(value)
                    for key, value in notes.items()
                    if str(key).strip() and str(value).strip()
                }
        except (KeyError, OSError, ValueError, UnicodeDecodeError, zipfile.BadZipFile):
            pass
        self.debug_breakpoints.clear()
        self.objects.clear()
        self.next_object_id = 1
        manifests = self.ao.get_manifests()
        package = manifests[0].get_package() if manifests else ""
        return {
            "path": path,
            "package": package,
            "dex": self.ao.get_dex_names(),
            "files": len(self.ao.get_file_names()),
            "manifest": self.ao.get_manifest_xml(),
            "split": len(self.split_set.get_names()) > 1,
            "members": self.split_set.get_names(),
            "notes": self.notes,
            "history": self._history(),
        }

    def manifest_data(self):
        if self.ao is None:
            raise RuntimeError("load an APK first")
        manifests = self.ao.get_manifests()
        return {
            "xml": self.ao.get_manifest_xml(),
            "package": manifests[0].get_package() if manifests else "",
            "history": self._history(),
        }

    def _history(self):
        if self.split_set is not None:
            return self.split_set.get_history()
        if self.ao is not None:
            return self.ao.get_history()
        return []

    def _record_event(self, event):
        self.session_script_override = None
        self.session_events.append(event)

    def history_data(self):
        return {
            "history": self._history(),
            "events": list(self.session_events),
            "script": self.session_script(),
        }

    @staticmethod
    def _script_instruction(factory, arguments):
        arguments = arguments or {}

        def integer(name, default=0):
            value = str(arguments.get(name, default))
            return "int({}, 0)".format(json.dumps(value))

        def text(name, default=""):
            return json.dumps(str(arguments.get(name, default)))

        if factory == "nop":
            return "DexInstruction.nop()"
        if factory == "return_void":
            return "DexInstruction.return_void()"
        if factory == "return_value":
            return "DexInstruction.return_value({})".format(integer("register"))
        if factory == "throw":
            return "DexInstruction.throw({})".format(integer("register"))
        if factory == "const_string_value":
            return "DexInstruction.const_string_value({}, {})".format(
                integer("register"), text("value")
            )
        if factory == "const_string":
            return "DexInstruction.const_string({}, {})".format(
                integer("register"), integer("string_index")
            )
        if factory == "const_string_jumbo":
            return "DexInstruction.const_string_jumbo({}, {})".format(
                integer("register"), integer("string_index")
            )
        if factory == "const_lit32":
            return "DexInstruction.const_lit32({}, {})".format(
                integer("register"), integer("value")
            )
        if factory in {"move_from16", "move_object_from16"}:
            return "DexInstruction.{}({}, {})".format(
                factory, integer("register"), integer("source_register")
            )
        if factory in {"new_instance", "check_cast"}:
            return "DexInstruction.{}({}, {})".format(
                factory, integer("register"), integer("type_index")
            )
        if factory == "invoke_static_range":
            return "DexInstruction.invoke_static_range({}, {}, {})".format(
                integer("register_count", 1),
                integer("method_index"),
                integer("first_register"),
            )
        if factory in {"if_eq", "if_ne", "if_lt", "if_le", "if_gt", "if_ge"}:
            return "DexInstruction.{}({}, {}, after)".format(
                factory, integer("left_register"), integer("right_register")
            )
        if factory in {"if_eqz", "if_nez", "if_ltz", "if_lez", "if_gtz", "if_gez"}:
            return "DexInstruction.{}({}, after)".format(factory, integer("register"))
        if factory == "goto":
            return "DexInstruction.goto(after)"
        if factory == "switch":
            return "DexInstruction.switch({}, [({}, after)])".format(
                integer("register"), integer("case_value")
            )
        return None

    def session_script(self):
        if self.session_script_override is not None and not self.session_events:
            return self.session_script_override
        origin = self.session_origin or {}
        lines = [
            "# Generated by Coeus GUI. Review paths and values before running.",
            "import re",
            "from coeus_python import AnalyzeObject, DexInstruction, SplitApkSet",
            "",
        ]
        kind = origin.get("kind")
        if kind == "state":
            lines.extend([
                "analysis = SplitApkSet.load_state({})".format(
                    json.dumps(origin.get("path", "project.coeus"))
                ),
                "ao = analysis.get_base_apk()",
            ])
        elif kind == "split":
            lines.extend([
                "analysis = SplitApkSet({})".format(
                    json.dumps(origin.get("paths", []))
                ),
                "ao = analysis.get_base_apk()",
            ])
        elif kind == "adb":
            lines.extend([
                "analysis = SplitApkSet.from_adb({}, {}, {})".format(
                    json.dumps(origin.get("package", "")),
                    json.dumps(origin.get("serial")),
                    json.dumps(origin.get("adb_path")),
                ),
                "ao = analysis.get_base_apk()",
            ])
        else:
            lines.append(
                "ao = AnalyzeObject({}, False, -1)".format(
                    json.dumps(origin.get("path", "input.apk"))
                )
            )
        lines.extend([
            "",
            "def find_method(signature):",
            "    name = signature.split('->', 1)[-1].split('(', 1)[0]",
            "    for evidence in ao.find_methods(re.escape(name)):",
            "        try:",
            "            method = evidence.as_method()",
            "            if method.signature() == signature:",
            "                return method",
            "        except Exception:",
            "            pass",
            "    raise RuntimeError('method not found: ' + signature)",
            "",
            "def find_string(dex_name, index):",
            "    for evidence in ao.find_strings('.*'):",
            "        try:",
            "            value = evidence.as_string()",
            "            if value.get_dex_name() == dex_name and value.get_index() == index:",
            "                return value",
            "        except Exception:",
            "            pass",
            "    raise RuntimeError('string not found: {}:{}'.format(dex_name, index))",
            "",
        ])
        for event in self.session_events:
            operation = event.get("operation")
            if operation == "set_manifest_xml":
                lines.extend([
                    "ao.set_manifest_xml({})".format(json.dumps(event.get("xml", ""))),
                    "",
                ])
            elif operation == "set_debuggable":
                lines.extend(["ao.set_debuggable({})".format(bool(event.get("enabled"))), ""])
            elif operation == "allow_plaintext_and_user_certificates":
                lines.extend(["ao.allow_plaintext_and_user_certificates()", ""])
            elif operation == "replace_string":
                lines.extend([
                    "ao.replace_string(find_string({}, {}), {})".format(
                        json.dumps(event.get("dex", "")),
                        int(event.get("index", 0)),
                        json.dumps(event.get("replacement", "")),
                    ),
                    "",
                ])
            elif operation == "apply_edit":
                replacement = self._script_instruction(
                    event.get("factory", ""), event.get("arguments", {})
                )
                if replacement is None:
                    lines.append("# Unsupported recorded edit: {!r}".format(event))
                    lines.append("")
                    continue
                lines.extend([
                    "method = find_method({})".format(
                        json.dumps(event.get("method", ""))
                    ),
                    "target = next(i for i in method.get_instructions() if i.get_offset() == {})".format(
                        int(event.get("offset", 0))
                    ),
                    "editor = ao.edit_method(method)",
                    "after = editor.label_after(target)",
                    "replacement = {}".format(replacement),
                ])
                action = event.get("action", "replace")
                if action == "prepend":
                    lines.append("editor.prepend([replacement])")
                elif action == "insert_before":
                    lines.append("editor.insert_before(target, [replacement])")
                elif action == "insert_after":
                    lines.append("editor.insert_after(target, [replacement])")
                else:
                    lines.append("editor.replace(target, [replacement])")
                lines.extend(["method = editor.commit(ao)", ""])
            elif operation == "write":
                lines.extend([
                    "ao.write_apk({})".format(json.dumps(event.get("path", "edited.apk"))),
                    "",
                ])
        lines.extend([
            "# Example output when no explicit write was recorded:",
            "# ao.write_apk('edited.apk')",
        ])
        return "\n".join(lines) + "\n"

    def _write_project_metadata(self, path):
        metadata = {
            "format_version": 1,
            "origin": self.session_origin,
            "events": self.session_events,
            "history": self._history(),
            "notes": self.notes,
        }
        directory = str(Path(path).expanduser().resolve().parent)
        temporary = tempfile.NamedTemporaryFile(
            prefix=".coeus-project-", suffix=".tmp", dir=directory, delete=False
        )
        temporary_path = temporary.name
        temporary.close()
        try:
            with zipfile.ZipFile(path, "r") as source, zipfile.ZipFile(
                temporary_path, "w", compression=zipfile.ZIP_DEFLATED
            ) as target:
                for entry in source.infolist():
                    if entry.filename in {"gui/session.json", "gui/session.py"}:
                        continue
                    target.writestr(entry, source.read(entry.filename))
                target.writestr(
                    "gui/session.json",
                    json.dumps(metadata, indent=2, sort_keys=True).encode("utf-8"),
                )
                target.writestr("gui/session.py", self.session_script().encode("utf-8"))
            os.replace(temporary_path, path)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)

    def save_project(self, path):
        if self.ao is None:
            raise RuntimeError("load an APK before saving a project")
        path = str(path)
        if self.split_set is not None:
            self.split_set.save_state(path)
        elif hasattr(self.ao, "save_state"):
            self.ao.save_state(path)
        else:
            raise RuntimeError("the installed coeus_python wheel cannot save project state")
        self._write_project_metadata(path)
        return {"path": path, "history": self._history(), "script": self.session_script()}

    def set_note(self, key, note):
        """Create, replace, or remove a GUI annotation."""
        key = str(key).strip()
        if not key:
            raise RuntimeError("note requires an annotated object")
        note = str(note)
        if note.strip():
            self.notes[key] = note
        else:
            self.notes.pop(key, None)
        return {"key": key, "note": self.notes.get(key, "")}

    def export_script(self, path):
        path = str(path)
        Path(path).write_text(self.session_script(), encoding="utf-8")
        return {"path": path}

    def generate_keystore(
        self, directory, alias, store_password, key_password=None, filename="debug.keystore"
    ):
        directory = Path(str(directory)).expanduser()
        if not directory.is_dir():
            raise RuntimeError("keystore folder does not exist: {}".format(directory))
        filename = Path(str(filename)).name
        if not filename or filename in {".", ".."}:
            raise RuntimeError("invalid keystore filename")
        path = directory / filename
        if path.exists():
            raise RuntimeError("keystore already exists: {}".format(path))
        alias = str(alias).strip()
        store_password = str(store_password)
        if not alias:
            raise RuntimeError("keystore alias must not be empty")
        if not store_password:
            raise RuntimeError("keystore password must not be empty")
        key_password = str(key_password) if key_password else store_password
        executable = shutil.which("keytool") or "keytool"
        completed = subprocess.run(
            [
                executable,
                "-genkeypair",
                "-noprompt",
                "-keystore",
                str(path),
                "-alias",
                alias,
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "10000",
                "-storepass",
                store_password,
                "-keypass",
                key_password,
                "-dname",
                "CN=CoEUS Debug,O=CoEUS,C=US",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            if path.exists():
                path.unlink()
            raise RuntimeError(
                "keytool failed: {}".format(
                    (completed.stderr or completed.stdout).strip()
                )
            )
        return {"path": str(path), "alias": alias}

    def set_manifest_xml(self, xml):
        if self.ao is None:
            raise RuntimeError("load an APK first")
        xml = str(xml)
        self.ao.set_manifest_xml(xml)
        self._record_event({"operation": "set_manifest_xml", "xml": xml})
        data = self.manifest_data()
        data["history"] = self._history()
        return data

    def set_debuggable(self, enabled):
        if self.ao is None:
            raise RuntimeError("load an APK first")
        enabled = bool(enabled)
        self.ao.set_debuggable(enabled)
        self._record_event({"operation": "set_debuggable", "enabled": enabled})
        data = self.manifest_data()
        data["history"] = self._history()
        return data

    def allow_plaintext_and_user_certificates(self):
        if self.ao is None:
            raise RuntimeError("load an APK first")
        self.ao.allow_plaintext_and_user_certificates()
        self._record_event(
            {"operation": "allow_plaintext_and_user_certificates"}
        )
        data = self.manifest_data()
        data["history"] = self._history()
        return data

    def write(self, path):
        if self.ao is None:
            raise RuntimeError("load an APK first")
        self.ao.write_apk(path)
        self._record_event({"operation": "write", "path": str(path)})
        return {"path": path, "history": self._history()}

    @staticmethod
    def _adb_executable(adb_path):
        if adb_path and str(adb_path).strip():
            return str(adb_path).strip()
        return shutil.which("adb") or "adb"

    def adb_devices(self, adb_path=None):
        executable = self._adb_executable(adb_path)
        completed = subprocess.run(
            [executable, "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                "adb devices failed: {}".format(
                    (completed.stderr or completed.stdout).strip()
                )
            )
        devices = []
        for line in completed.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, state = parts[:2]
            if state != "device":
                continue
            model = next(
                (part.split(":", 1)[1] for part in parts[2:] if part.startswith("model:")),
                "",
            )
            devices.append({
                "serial": serial,
                "model": model,
                "label": "{}{}".format(serial, " — {}".format(model) if model else ""),
            })
        return {"devices": devices}

    def adb_packages(self, package_regex=None, serial=None, adb_path=None):
        packages = SplitApkSet.list_packages(
            str(package_regex) if package_regex and str(package_regex).strip() else None,
            str(serial).strip() if serial else None,
            str(adb_path).strip() if adb_path else None,
        )
        return {"packages": packages}

    def pull_apks(self, package, output_dir, serial=None, adb_path=None):
        loaded = self.load_split_from_adb(package, serial, adb_path)
        if self.split_set is None:
            raise RuntimeError("ADB did not return an APK set")
        paths = self.split_set.write_all(str(output_dir))
        return {"loaded": loaded, "output_dir": str(output_dir), "paths": paths}

    def install_apk(self, path, serial=None, adb_path=None, replace_existing=True):
        executable = self._adb_executable(adb_path)
        command = [executable]
        if serial and str(serial).strip():
            command.extend(["-s", str(serial).strip()])
        command.append("install")
        if replace_existing:
            command.append("-r")
        command.append(str(path))
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
        )
        output = (completed.stdout or completed.stderr).strip()
        if completed.returncode != 0:
            raise RuntimeError("adb install failed: {}".format(output))
        return {"path": str(path), "serial": serial or "", "output": output}

    def sign_apk(self, output, keystore, alias, store_password, key_password=None, apksigner=None):
        if self.ao is None:
            raise RuntimeError("load an APK first")
        self.ao.sign_apk(
            str(output),
            str(keystore),
            str(alias),
            str(store_password),
            str(key_password) if key_password else None,
            str(apksigner) if apksigner else None,
        )
        return {"path": str(output)}

    def sign_split(self, output_dir, keystore, alias, store_password,
                   key_password=None, apksigner=None):
        if self.split_set is None:
            raise RuntimeError("load a split APK set first")
        paths = self.split_set.sign_all(
            str(output_dir),
            str(keystore),
            str(alias),
            str(store_password),
            str(key_password) if key_password else None,
            str(apksigner) if apksigner else None,
        )
        return {"output_dir": str(output_dir), "paths": paths, "split": True}

    def install_split(self, output_dir, serial=None, adb_path=None, replace_existing=True):
        if self.split_set is None:
            raise RuntimeError("load a split APK set first")
        output = self.split_set.install_all(
            str(output_dir),
            str(serial).strip() if serial else None,
            str(adb_path).strip() if adb_path else None,
            bool(replace_existing),
            False,
        )
        return {
            "output_dir": str(output_dir),
            "serial": serial or "",
            "output": output,
            "split": True,
        }

    def sign_and_install_split(self, output_dir, keystore, alias, store_password,
                               key_password=None, apksigner=None, serial=None,
                               adb_path=None, replace_existing=True):
        self.sign_split(
            output_dir, keystore, alias, store_password, key_password, apksigner
        )
        return self.install_split(output_dir, serial, adb_path, replace_existing)

    def sign_and_install(self, output, keystore, alias, store_password,
                         key_password=None, apksigner=None, serial=None,
                         adb_path=None, replace_existing=True):
        signed = self.sign_apk(
            output, keystore, alias, store_password, key_password, apksigner
        )
        installed = self.install_apk(
            signed["path"], serial, adb_path, replace_existing
        )
        signed.update(installed)
        return signed

    def search(self, kind, query):
        if self.ao is None:
            raise RuntimeError("load an APK first")
        methods = {
            "any": self.ao.find,
            "methods": self.ao.find_methods,
            "classes": self.ao.find_classes,
            "fields": self.ao.find_fields,
            "strings": self.ao.find_strings,
        }
        finder = methods.get(kind)
        if finder is None:
            raise RuntimeError("unknown search kind: {}".format(kind))
        found = finder(query)
        results = []
        for evidence in found[:1000]:
            results.append(self._result(evidence, evidence=evidence))
        return {"results": results, "count": len(found)}

    def edit_search(self, kind, query, dex_name=None):
        """Search for a pool object without replacing the main search list."""
        methods = {
            "methods": self.ao.find_methods,
            "classes": self.ao.find_classes,
            "strings": self.ao.find_strings,
        }
        finder = methods.get(kind)
        if finder is None:
            raise RuntimeError("unknown edit picker search kind: {}".format(kind))
        found = finder(query or ".*")
        results = []
        for evidence in found[:1000]:
            result = self._result(evidence, evidence=evidence)
            if dex_name and result.get("dex") != dex_name:
                # Older installed wheels have get_index() but not the newer
                # DexString.get_dex_name(). Keep those strings usable in the
                # picker; current wheels remain strictly DEX-scoped.
                if result.get("kind") != "string" or "dex" in result:
                    continue
            results.append(result)
        return {
            "results": results,
            "count": len(results),
        }

    def _entry(self, object_id):
        try:
            return self.objects[object_id]
        except KeyError:
            raise RuntimeError("unknown object: {}".format(object_id))

    def _instruction_targets(self, instruction):
        """Resolve typed navigation targets embedded in one smali instruction."""
        text = str(instruction)
        targets = []
        seen = set()

        def add_matches(finder, query, expected=None):
            if not query:
                return
            for evidence in finder(re.escape(query))[:100]:
                result = self._result(evidence, evidence=evidence)
                if expected is not None and result["label"] != expected:
                    continue
                key = (result["kind"], result["label"])
                if key not in seen:
                    seen.add(key)
                    targets.append(result)

        method_references = re.findall(
            r"(L[^\s,{}]+;->[^\s,{}(]+\([^)]*\)[^\s,{}]+)", text
        )
        for reference in method_references:
            method_name = reference.split("->", 1)[1].split("(", 1)[0]
            add_matches(self.ao.find_methods, method_name, reference)

        field_references = re.findall(
            r"(L[^\s,{}]+;->[^\s,{}:]+:[^\s,{}]+)", text
        )
        for reference in field_references:
            field_name = reference.split("->", 1)[1].split(":", 1)[0]
            add_matches(self.ao.find_fields, field_name, reference)

        for reference in re.findall(r"(\[*L[^\s,{};]+;)", text):
            add_matches(self.ao.find_classes, reference, reference)

        if text.lstrip().startswith("const-string"):
            for value in re.findall(r'"((?:\\.|[^"\\])*)"', text):
                value = re.sub(r"\\(.)", r"\1", value)
                add_matches(self.ao.find_strings, value, value)

        return targets

    def _instructions(self, method):
        instructions = []
        for instruction in method.get_instructions():
            instructions.append(
                {
                    "offset": instruction.get_offset(),
                    "size": instruction.get_size(),
                    "mnemonic": instruction.mnemonic(),
                    "text": str(instruction),
                    "targets": self._instruction_targets(instruction),
                }
            )
        return instructions

    def describe(self, object_id):
        entry = self._entry(object_id)
        kind, obj = entry["kind"], entry["object"]
        data = {
            "id": object_id,
            "kind": kind,
            "label": self._label(kind, obj),
        }
        annotation_key = self._annotation_key(kind, obj)
        if annotation_key:
            data["note_key"] = annotation_key
        if kind == "method":
            data.update(
                {
                    "code": obj.code(),
                    "instructions": self._instructions(obj),
                    "class": obj.get_class().name(),
                }
            )
        elif kind == "class":
            data.update({"code": obj.code(self.ao), "class": obj.name()})
        elif kind == "field_access":
            function = obj.get_function()
            method_id = self._id(function, kind="method")
            data.update({"method_id": method_id, "code": function.code()})
        elif kind == "string":
            data.update({"value": obj.content()})
        return data

    def replace_string(self, object_id, replacement):
        if self.ao is None:
            raise RuntimeError("load an APK first")
        entry = self._entry(object_id)
        if entry["kind"] != "string":
            raise RuntimeError("string-pool editing requires a DEX string")
        dex_name = entry["object"].get_dex_name()
        string_index = entry["object"].get_index()
        replacement = str(replacement)
        self.ao.replace_string(entry["object"], replacement)
        refreshed = None
        for evidence in self.ao.find_strings(re.escape(replacement)):
            kind, obj = self._concrete(evidence)
            if kind == "string" and obj.content() == replacement:
                refreshed = (evidence, obj)
                break
        if refreshed is not None:
            evidence, obj = refreshed
            entry["object"] = obj
            entry["evidence"] = evidence
        self._record_event(
            {
                "operation": "replace_string",
                "dex": dex_name,
                "index": int(string_index),
                "replacement": replacement,
            }
        )
        return {"id": object_id, "value": replacement, "history": self._history()}

    @staticmethod
    def _edit_argument(name, label, value, kind="integer", picker=None):
        argument = {
            "name": name,
            "label": label,
            "kind": kind,
            "value": str(value),
        }
        if picker is not None:
            argument["picker"] = picker
        return argument

    @staticmethod
    def _edit_int(arguments, name, default):
        raw = arguments.get(name, default)
        try:
            return int(str(raw).strip(), 0)
        except (TypeError, ValueError):
            raise RuntimeError("{} must be an integer".format(name))

    @staticmethod
    def _edit_group(factory, action):
        if action != "replace" or factory in {"insert_nop", "prepend_nop"}:
            return "Placement"
        if factory in {"return_void", "return_value", "throw"}:
            return "Control flow"
        if factory.startswith("if_") or factory in {"goto", "switch"}:
            return "Control flow"
        if factory.startswith("const_"):
            return "Constants and strings"
        if factory.startswith("move_"):
            return "Register moves"
        if factory in {"new_instance", "check_cast"}:
            return "Objects and types"
        if factory == "invoke_static_range":
            return "Function calls"
        if factory == "nop":
            return "Basic"
        return "Other"

    def _build_edit_instruction(self, factory, arguments, after_selected):
        """Build one typed replacement from GUI argument values."""
        if factory == "nop":
            return DexInstruction.nop()
        if factory == "return_void":
            return DexInstruction.return_void()
        if factory == "return_value":
            return DexInstruction.return_value(self._edit_int(arguments, "register", 0))
        if factory == "throw":
            return DexInstruction.throw(self._edit_int(arguments, "register", 0))
        if factory == "const_string_value":
            return DexInstruction.const_string_value(
                self._edit_int(arguments, "register", 0),
                str(arguments.get("value", "")),
            )
        if factory == "const_string":
            return DexInstruction.const_string(
                self._edit_int(arguments, "register", 0),
                self._edit_int(arguments, "string_index", 0),
            )
        if factory == "const_string_jumbo":
            return DexInstruction.const_string_jumbo(
                self._edit_int(arguments, "register", 0),
                self._edit_int(arguments, "string_index", 0),
            )
        if factory == "const_lit32":
            return DexInstruction.const_lit32(
                self._edit_int(arguments, "register", 0),
                self._edit_int(arguments, "value", 0),
            )
        if factory == "move_from16":
            return DexInstruction.move_from16(
                self._edit_int(arguments, "register", 0),
                self._edit_int(arguments, "source_register", 0),
            )
        if factory == "move_object_from16":
            return DexInstruction.move_object_from16(
                self._edit_int(arguments, "register", 0),
                self._edit_int(arguments, "source_register", 0),
            )
        if factory == "new_instance":
            return DexInstruction.new_instance(
                self._edit_int(arguments, "register", 0),
                self._edit_int(arguments, "type_index", 0),
            )
        if factory == "check_cast":
            return DexInstruction.check_cast(
                self._edit_int(arguments, "register", 0),
                self._edit_int(arguments, "type_index", 0),
            )
        if factory == "invoke_static_range":
            return DexInstruction.invoke_static_range(
                self._edit_int(arguments, "register_count", 1),
                self._edit_int(arguments, "method_index", 0),
                self._edit_int(arguments, "first_register", 0),
            )
        if factory in {
            "if_eq",
            "if_ne",
            "if_lt",
            "if_le",
            "if_gt",
            "if_ge",
        }:
            return getattr(DexInstruction, factory)(
                self._edit_int(arguments, "left_register", 0),
                self._edit_int(arguments, "right_register", 0),
                after_selected,
            )
        if factory in {"if_eqz", "if_nez", "if_ltz", "if_lez", "if_gtz", "if_gez"}:
            return getattr(DexInstruction, factory)(
                self._edit_int(arguments, "register", 0),
                after_selected,
            )
        if factory == "goto":
            return DexInstruction.goto(after_selected)
        if factory == "switch":
            return DexInstruction.switch(
                self._edit_int(arguments, "register", 0),
                [(self._edit_int(arguments, "case_value", 0), after_selected)],
            )
        raise RuntimeError("unknown typed edit factory: {}".format(factory))

    def edit_options(self, object_id, offset):
        """Return typed instruction-node edits and their editable arguments."""
        if not ENABLE_EXPERIMENTAL_METHOD_EDITS:
            return {
                "selected_offset": int(offset),
                "options": [],
                "available": False,
                "reason": "Method editing is waiting for the redesigned Coeus API",
            }
        entry = self._entry(object_id)
        if entry["kind"] != "method":
            raise RuntimeError("instruction edits require a method")
        target = next(
            (instruction for instruction in entry["object"].get_instructions()
             if instruction.get_offset() == int(offset)),
            None,
        )
        if target is None:
            raise RuntimeError("instruction offset is not present in the method")

        editor = self.ao.edit_method(entry["object"])
        after_selected = editor.label_after(target)
        target_text = str(target)
        registers = [int(value) for value in re.findall(r"\bv(\d+)\b", target_text)]
        first_register = registers[0] if registers else 0
        register_count = len(registers) or 1
        if ".." in target_text and len(registers) >= 2:
            register_count = max(1, registers[-1] - registers[0] + 1)

        method_index = 0
        for navigation_target in self._instruction_targets(target):
            if navigation_target["kind"] == "method":
                try:
                    method_index = self._entry(navigation_target["id"])["object"].get_method_idx()
                except Exception:
                    pass
                break

        integer = lambda name, label, value: self._edit_argument(name, label, value)
        candidates = [
            {"factory": "nop", "label": "Replace with NOP", "action": "replace", "arguments": []},
            {"factory": "return_void", "label": "Return void", "action": "replace", "arguments": []},
            {"factory": "return_value", "label": "Return register", "action": "replace", "arguments": [integer("register", "Return register", 0)]},
            {"factory": "throw", "label": "Throw register", "action": "replace", "arguments": [integer("register", "Throw register", 0)]},
            {"factory": "const_string_value", "label": "const-string value", "action": "replace", "arguments": [integer("register", "Destination register", 0), self._edit_argument("value", "String value", "", "text")]},
            {"factory": "const_string", "label": "const-string index", "action": "replace", "arguments": [integer("register", "Destination register", 0), self._edit_argument("string_index", "String pool entry", 0, picker="strings")]},
            {"factory": "const_string_jumbo", "label": "const-string/jumbo index", "action": "replace", "arguments": [integer("register", "Destination register", 0), self._edit_argument("string_index", "String pool entry", 0, picker="strings")]},
            {"factory": "const_lit32", "label": "const literal", "action": "replace", "arguments": [integer("register", "Destination register", 0), integer("value", "Literal value", 0)]},
            {"factory": "move_from16", "label": "move/from16", "action": "replace", "arguments": [integer("register", "Destination register", 0), integer("source_register", "Source register", 0)]},
            {"factory": "move_object_from16", "label": "move-object/from16", "action": "replace", "arguments": [integer("register", "Destination register", 0), integer("source_register", "Source register", 0)]},
            {"factory": "new_instance", "label": "new-instance", "action": "replace", "arguments": [integer("register", "Destination register", 0), self._edit_argument("type_index", "Class/type entry", 0, picker="classes")]},
            {"factory": "check_cast", "label": "check-cast", "action": "replace", "arguments": [integer("register", "Register", 0), self._edit_argument("type_index", "Class/type entry", 0, picker="classes")]},
            {"factory": "invoke_static_range", "label": "invoke-static/range function", "action": "replace", "arguments": [integer("register_count", "Argument register count", register_count), self._edit_argument("method_index", "Target method", method_index, picker="methods"), integer("first_register", "First argument register", first_register)]},
            {"factory": "insert_nop", "label": "Insert NOP before", "action": "insert_before", "arguments": []},
            {"factory": "insert_nop", "label": "Insert NOP after", "action": "insert_after", "arguments": []},
            {"factory": "prepend_nop", "label": "Prepend NOP at method entry", "action": "prepend", "arguments": []},
        ]
        for factory, label in [
            ("if_eq", "Insert if-eq"), ("if_ne", "Insert if-ne"),
            ("if_lt", "Insert if-lt"), ("if_le", "Insert if-le"),
            ("if_gt", "Insert if-gt"), ("if_ge", "Insert if-ge"),
        ]:
            candidates.append({
                "factory": factory,
                "label": label + " → after selected",
                "action": "insert_before",
                "arguments": [integer("left_register", "Left register", 0), integer("right_register", "Right register", 0)],
            })
        for factory, label in [
            ("if_eqz", "Insert if-eqz"), ("if_nez", "Insert if-nez"),
            ("if_ltz", "Insert if-ltz"), ("if_lez", "Insert if-lez"),
            ("if_gtz", "Insert if-gtz"), ("if_gez", "Insert if-gez"),
        ]:
            candidates.append({
                "factory": factory,
                "label": label + " → after selected",
                "action": "insert_before",
                "arguments": [integer("register", "Register", 0)],
            })
        candidates.extend([
            {"factory": "goto", "label": "Insert goto → after selected", "action": "insert_before", "arguments": []},
            {"factory": "switch", "label": "Insert switch case → after selected", "action": "insert_before", "arguments": [integer("register", "Switch register", 0), integer("case_value", "Case value", 0)]},
        ])

        options = []
        for candidate in candidates:
            default_arguments = {
                argument["name"]: argument["value"]
                for argument in candidate["arguments"]
            }
            factory = candidate["factory"]
            if factory == "insert_nop" or factory == "prepend_nop":
                factory = "nop"
            try:
                replacement = self._build_edit_instruction(
                    factory, default_arguments, after_selected
                )
            except Exception:
                continue
            option_id = self._id(replacement, kind="edit")
            self.objects[option_id].update(
                {
                    "label": candidate["label"],
                    "action": candidate["action"],
                    "factory": factory,
                    "argument_specs": candidate["arguments"],
                    "method_id": object_id,
                    "offset": int(offset),
                    "target": target,
                }
            )
            options.append(
                {
                    "group": self._edit_group(candidate["factory"], candidate["action"]),
                    "id": option_id,
                    "label": candidate["label"],
                    "action": candidate["action"],
                    "width": replacement.get_size(),
                    "arguments": candidate["arguments"],
                }
            )
        return {
            "selected_offset": int(offset),
            "width": target.get_size(),
            "options": options,
            "available": True,
            "dex": entry["object"].get_dex_name(),
        }

    def apply_edit(self, option_id, arguments=None):
        if not ENABLE_EXPERIMENTAL_METHOD_EDITS:
            raise RuntimeError(
                "Method editing is waiting for the redesigned Coeus API"
            )
        option = self._entry(option_id)
        if option["kind"] != "edit":
            raise RuntimeError("unknown edit node")
        method_entry = self._entry(option["method_id"])
        method = method_entry["object"]
        editor = self.ao.edit_method(method)
        arguments = arguments or {}
        argument_values = {
            argument["name"]: arguments.get(argument["name"], argument["value"])
            for argument in option.get("argument_specs", [])
        }
        option["object"] = self._build_edit_instruction(
            option["factory"], argument_values, editor.label_after(option["target"])
        )
        if option["action"] == "prepend":
            editor.prepend([option["object"]])
        elif option["action"] == "insert_before":
            editor.insert_before(option["target"], [option["object"]])
        elif option["action"] == "insert_after":
            editor.insert_after(option["target"], [option["object"]])
        else:
            editor.replace(option["target"], [option["object"]])
        method_entry["object"] = editor.commit(self.ao)
        method_entry["evidence"] = None
        self._record_event(
            {
                "operation": "apply_edit",
                "method": method.signature(),
                "offset": int(option["offset"]),
                "action": option["action"],
                "factory": option["factory"],
                "arguments": {
                    str(name): str(value)
                    for name, value in argument_values.items()
                },
            }
        )
        data = self.describe(option["method_id"])
        data["history"] = self._history()
        return data

    def cross_references(self, object_id):
        if self.ao is None:
            raise RuntimeError("load an APK first")
        entry = self._entry(object_id)
        obj = entry["object"]
        if entry["evidence"] is not None:
            found = entry["evidence"].cross_references(self.ao)
        elif hasattr(obj, "cross_references"):
            found = obj.cross_references(self.ao)
        else:
            found = []
        return {
            "results": [self._result(evidence, evidence=evidence) for evidence in found[:1000]],
            "count": len(found),
        }

    def graph(self, object_id, graph_kind, ignore):
        if self.ao is None:
            raise RuntimeError("load an APK first")
        if graph_kind == "supergraph":
            ignore_classes = [
                item.strip() for item in ignore.split(",") if item.strip()
            ]
            self.ao.build_supergraph(ignore_classes)
            dot = self.ao.supergraph_to_dot()
        else:
            entry = self._entry(object_id)
            if entry["kind"] != "method":
                raise RuntimeError("call graphs start from a method result")
            ignore_methods = ["__coeus_gui_never_ignore__"]
            if ignore:
                ignore_methods = [item.strip() for item in ignore.split(",") if item.strip()]
            dot = entry["object"].callgraph(ignore_methods, self.ao).to_dot()
        return {"kind": graph_kind, "dot": dot}

    def graph_node_details(self, label, node_id=None):
        """Resolve a rendered graph label back to navigatable Coeus objects."""
        node_kind = "node"
        value = ""
        match = re.search(
            r'\b(method|class|field|string):\s*"((?:\\.|[^"\\])*)"',
            str(label),
        )
        if match is not None:
            node_kind, value = match.groups()

        finders = {
            "method": self.ao.find_methods,
            "class": self.ao.find_classes,
            "field": self.ao.find_fields,
            "string": self.ao.find_strings,
        }
        targets = []
        finder = finders.get(node_kind)
        if finder is not None and value:
            search_value = value
            expected_label = value
            if node_kind == "method":
                # Information-graph method nodes include a display-only
                # method index suffix, while find_methods searches method
                # names and the GUI method label is the full signature.
                expected_label = re.sub(r"\s+\(midx:\s*\d+\)\s*$", "", value)
                if "->" in expected_label:
                    search_value = expected_label.split("->", 1)[1].split("(", 1)[0]
            elif node_kind == "field" and "->" in value:
                # Field search likewise matches the field name, not its FQDN.
                search_value = value.split("->", 1)[1].split(":", 1)[0]
            try:
                found = finder(re.escape(search_value))
            except Exception:
                found = []
            candidates = [
                self._result(evidence, evidence=evidence)
                for evidence in found[:100]
            ]
            exact = [
                result
                for result in candidates
                if result.get("kind") == node_kind
                and result.get("label") == expected_label
            ]
            targets = (exact or candidates)[:20]

        return {
            "node_id": int(node_id) if node_id is not None else None,
            "kind": node_kind,
            "value": value,
            "label": str(label),
            "targets": targets,
        }

    @staticmethod
    def _debug_connect_worker(result_queue, host, port, forward=None):
        try:
            if forward is not None:
                pid, serial, adb_path = forward
                forward_jdwp(pid, port, serial, adb_path)
            result_queue.put(("ok", Debugger(host, int(port))))
        except Exception as error:
            result_queue.put(("error", str(error)))

    def debug_connect(self, host, port):
        if self.debug_connecting:
            return {"connecting": True, "host": host, "port": int(port)}
        self.debug_connect_result = queue.Queue(maxsize=1)
        self.debug_connecting = True
        threading.Thread(
            target=self._debug_connect_worker,
            args=(self.debug_connect_result, str(host), int(port)),
            daemon=True,
        ).start()
        return {"connecting": True, "host": host, "port": int(port)}

    def debug_attach(self, pid, port, serial=None, adb_path=None):
        if self.debug_connecting:
            return {"connecting": True, "port": int(port)}
        self.debug_connect_result = queue.Queue(maxsize=1)
        self.debug_connecting = True
        threading.Thread(
            target=self._debug_connect_worker,
            args=(
                self.debug_connect_result,
                "127.0.0.1",
                int(port),
                (
                    int(pid),
                    str(serial).strip() if serial else None,
                    str(adb_path).strip() if adb_path else None,
                ),
            ),
            daemon=True,
        ).start()
        return {"connecting": True, "port": int(port), "pid": int(pid)}

    def debug_connect_poll(self):
        if not self.debug_connecting or self.debug_connect_result is None:
            return {"connecting": False, "connected": self.debugger is not None}
        try:
            status, value = self.debug_connect_result.get_nowait()
        except queue.Empty:
            return {"connecting": True}
        self.debug_connecting = False
        self.debug_connect_result = None
        if status == "error":
            raise RuntimeError(value)
        self.debugger = value
        self.debug_frame = None
        self.debug_method = None
        self.debug_values = []
        self.debug_breakpoints.clear()
        return {"connecting": False, "connected": True}

    def debug_detach(self):
        # Let the polling worker release the JDWP object before closing it.
        # This avoids concurrent use of the native client when a detach is
        # requested while the target is being polled for an event.
        if self.debug_waiting:
            result = queue.Queue(maxsize=1)
            self.debug_control_queue.put(("detach", None, None, result))
            try:
                result.get(timeout=1.0)
            except queue.Empty:
                pass
        debugger = self.debugger
        self.debugger = None
        self.debug_waiting = False
        self.debug_wait = None
        self.debug_frame = None
        self.debug_method = None
        self.debug_values = []
        self.debug_breakpoints.clear()
        if debugger is not None:
            debugger.close()
        return {"connected": False, "detached": True}

    @staticmethod
    def _debug_apps_worker(result_queue, serial, adb_path):
        try:
            apps = list_debuggable_apps(serial, adb_path)
            result_queue.put((
                "ok",
                [
                    {
                        "pid": app.pid,
                        "process": app.process_name,
                        "package": app.package_name,
                    }
                    for app in apps
                ],
            ))
        except Exception as error:
            result_queue.put(("error", str(error)))

    def debug_apps(self, serial=None, adb_path=None):
        if self.debug_apps_loading:
            return {"loading": True}
        self.debug_apps_result = queue.Queue(maxsize=1)
        self.debug_apps_loading = True
        threading.Thread(
            target=self._debug_apps_worker,
            args=(
                self.debug_apps_result,
                str(serial).strip() if serial else None,
                str(adb_path).strip() if adb_path else None,
            ),
            daemon=True,
        ).start()
        return {"loading": True}

    def debug_apps_poll(self):
        if not self.debug_apps_loading or self.debug_apps_result is None:
            return {"loading": False, "apps": []}
        try:
            status, value = self.debug_apps_result.get_nowait()
        except queue.Empty:
            return {"loading": True}
        self.debug_apps_loading = False
        self.debug_apps_result = None
        if status == "error":
            raise RuntimeError(value)
        return {"loading": False, "apps": value}

    def debug_breakpoint(self, object_id, offset):
        if self.debugger is None:
            raise RuntimeError("connect a debugger first")
        entry = self._entry(object_id)
        if entry["kind"] != "method":
            raise RuntimeError("breakpoints require a method")
        offset = int(offset)
        key = (entry["object"].signature(), offset)
        enabled = key not in self.debug_breakpoints
        if self.debug_waiting:
            result = queue.Queue(maxsize=1)
            self.debug_control_queue.put(
                ("set" if enabled else "clear", entry["object"], offset, result)
            )
            try:
                status, error = result.get(timeout=5)
            except queue.Empty:
                raise RuntimeError(
                    "timed out while changing the breakpoint from the JDWP wait thread"
                )
            if status != "ok":
                raise RuntimeError(error)
            if enabled:
                self.debug_breakpoints.add(key)
                return {
                    "enabled": True,
                    "offset": offset,
                    "location": "{}@0x{:x}".format(entry["object"].signature(), offset),
                    "waiting": True,
                }
            else:
                self.debug_waiting = False
                self.debug_wait = None
                self.debug_breakpoints.remove(key)
                return {
                    "enabled": False,
                    "offset": offset,
                    "location": "{}@0x{:x}".format(entry["object"].signature(), offset),
                    "waiting": False,
                }

        if not enabled:
            self.debugger.clear_breakpoint(entry["object"], offset)
            self.debug_breakpoints.remove(key)
            return {
                "enabled": False,
                "offset": offset,
                "location": "{}@0x{:x}".format(entry["object"].signature(), offset),
                "waiting": False,
            }
        self.debugger.set_breakpoint(entry["object"], offset)
        self.debug_breakpoints.add(key)
        # A stopped frame means the VM is already suspended and there is no
        # need to start an event waiter yet. Starting one here would make the
        # GUI report ``waiting`` and disable Resume, leaving the user unable
        # to continue after adding a breakpoint to another instruction.
        # Once the user resumes, debug_resume starts the waiter and the new
        # breakpoint remains active for the next event.
        wait = {"waiting": False}
        if self.debug_frame is None:
            # Start listening immediately so a breakpoint remains useful even
            # if the user switches away from the Debugger tab. The worker owns
            # the native JDWP wait, while the JSON bridge stays available for
            # the GUI.
            wait = self.debug_wait_start()
        return {
            "enabled": True,
            "offset": offset,
            "location": "{}@0x{:x}".format(entry["object"].signature(), offset),
            **wait,
        }

    def _handle_debug_control(self, command):
        kind, method, offset, result = command
        try:
            if kind == "detach":
                result.put(("ok", None))
                return True
            if kind == "set":
                self.debugger.set_breakpoint(method, offset)
            elif kind == "clear":
                self.debugger.clear_breakpoint(method, offset)
            else:
                raise RuntimeError("unknown debugger control: {}".format(kind))
        except Exception as error:
            result.put(("error", str(error)))
        else:
            result.put(("ok", None))
        # Clearing cancels the wait worker. Setting leaves it as the owner of
        # the JDWP connection so it can continue polling safely.
        return kind == "clear"

    def _wait_worker(self):
        while True:
            try:
                command = self.debug_control_queue.get_nowait()
            except queue.Empty:
                command = None
            if command is not None and self._handle_debug_control(command):
                return
            try:
                frame = self.debugger.poll_for_package(250)
            except Exception as error:
                self.debug_wait.put(("error", str(error)))
                return
            if frame is None:
                continue
            # Prefer a clear request that arrived while the native poll was
            # resolving the stopped frame. In that case the breakpoint is
            # cleared and the frame is intentionally discarded.
            try:
                command = self.debug_control_queue.get_nowait()
            except queue.Empty:
                command = None
            if command is not None and self._handle_debug_control(command):
                return
            self.debug_wait.put(("frame", frame))
            return

    def debug_wait_start(self):
        if self.debugger is None:
            raise RuntimeError("connect a debugger first")
        if self.debug_waiting:
            return {"waiting": True}
        self.debug_wait = queue.Queue(maxsize=1)
        self.debug_waiting = True
        threading.Thread(target=self._wait_worker, daemon=True).start()
        return {"waiting": True}

    @staticmethod
    def _value_text(value, debugger):
        try:
            actual = value.get_value(debugger)
            if isinstance(actual, VmInstance):
                return actual.to_string(debugger)
            return repr(actual)
        except Exception as error:
            return "<{}>".format(error)

    def _frame_data(self, frame):
        class_name = frame.get_class_name(self.debugger)
        method_name = frame.get_method_name(self.debugger)
        method_signature = frame.get_method_signature(self.debugger)
        classes = self.ao.find_classes(re.escape(class_name))
        if not classes:
            raise RuntimeError("class {} is not present in the loaded APK".format(class_name))
        method = None
        lookup_errors = []
        for evidence in classes:
            try:
                method = evidence.as_class().get_method_by_proto_type(
                    method_name, method_signature
                )
                break
            except Exception as error:
                lookup_errors.append(str(error))
        if method is None:
            for evidence in classes:
                try:
                    method = evidence.as_class().get_method(method_name)
                    break
                except Exception as error:
                    lookup_errors.append(str(error))
        if method is None:
            detail = "; ".join(dict.fromkeys(lookup_errors))
            raise RuntimeError(
                "method {}{} not found in {}{}".format(
                    method_name,
                    method_signature,
                    class_name,
                    ": {}".format(detail) if detail else "",
                )
            )
        method_id = self._id(method, kind="method")
        values_error = None
        try:
            values = frame.get_values_for(self.debugger, method)
        except Exception as error:
            # A valid stopped frame may not have local-variable metadata (for
            # example in optimized code). Keep the frame navigable and
            # resumable even when register inspection is unavailable.
            values = []
            values_error = str(error)
        self.debug_frame = frame
        self.debug_method = method
        self.debug_values = values
        result = {
            "class": class_name,
            "method": method_name,
            "method_id": method_id,
            "code_index": frame.get_code_index(),
            "values": [
                {"slot": index, "value": self._value_text(value, self.debugger)}
                for index, value in enumerate(values)
            ],
        }
        if values_error:
            result["values_error"] = values_error
        return result

    def debug_poll(self):
        if not self.debug_waiting or self.debug_wait is None:
            return {"waiting": False}
        try:
            status, value = self.debug_wait.get_nowait()
        except queue.Empty:
            return {"waiting": True}
        self.debug_waiting = False
        if status == "error":
            raise RuntimeError(value)
        if status == "timeout":
            return {"waiting": False, "timeout": True}
        return {"waiting": False, "frame": self._frame_data(value)}

    def debug_resume(self):
        if self.debugger is None:
            raise RuntimeError("connect a debugger first")
        self.debugger.resume()
        self.debug_frame = None
        self.debug_method = None
        self.debug_values = []
        return self.debug_wait_start()

    def debug_step(self):
        if self.debug_frame is None:
            raise RuntimeError("the debugger is not stopped at a frame")
        self.debug_frame.step(self.debugger)
        self.debugger.resume()
        self.debug_frame = None
        self.debug_method = None
        self.debug_values = []
        return self.debug_wait_start()

    def debug_set_value(self, slot, text):
        if self.debug_frame is None:
            raise RuntimeError("the debugger is not stopped at a frame")
        index = int(slot)
        old_value = self.debug_values[index]
        normalized = text.strip()
        if normalized.lower() in ("true", "false"):
            value = normalized.lower() == "true"
        elif normalized.lower() in ("none", "null", "nil"):
            value = None
        else:
            try:
                value = int(normalized, 0)
            except ValueError:
                try:
                    value = float(normalized)
                except ValueError:
                    value = text
        self.debug_frame.set_value(
            self.debugger,
            index,
            StackValue(self.debugger, value, old_value),
        )
        self.debug_values[index] = StackValue(self.debugger, value, old_value)
        return {"slot": index, "value": self._value_text(self.debug_values[index], self.debugger)}

    def dispatch(self, request):
        op = request.get("op")
        if op == "load":
            return self.load(request["path"])
        if op == "load_split":
            return self.load_split(request.get("paths", []))
        if op == "load_split_from_adb":
            return self.load_split_from_adb(
                request.get("package", ""),
                request.get("serial"),
                request.get("adb_path"),
            )
        if op == "load_project":
            return self.load_project(request["path"])
        if op == "history":
            return self.history_data()
        if op == "manifest":
            return self.manifest_data()
        if op == "set_manifest_xml":
            return self.set_manifest_xml(request.get("xml", ""))
        if op == "set_debuggable":
            return self.set_debuggable(request.get("enabled", False))
        if op == "allow_plaintext_and_user_certificates":
            return self.allow_plaintext_and_user_certificates()
        if op == "write":
            return self.write(request["path"])
        if op == "save_project":
            return self.save_project(request["path"])
        if op == "set_note":
            return self.set_note(request["key"], request.get("note", ""))
        if op == "export_script":
            return self.export_script(request["path"])
        if op == "generate_keystore":
            return self.generate_keystore(
                request["directory"],
                request["alias"],
                request["store_password"],
                request.get("key_password"),
                request.get("filename", "debug.keystore"),
            )
        if op == "adb_devices":
            return self.adb_devices(request.get("adb_path"))
        if op == "adb_packages":
            return self.adb_packages(
                request.get("package_regex"),
                request.get("serial"),
                request.get("adb_path"),
            )
        if op == "pull_apks":
            return self.pull_apks(
                request.get("package", ""),
                request["output_dir"],
                request.get("serial"),
                request.get("adb_path"),
            )
        if op == "sign":
            return self.sign_apk(
                request["output"],
                request["keystore"],
                request["alias"],
                request["store_password"],
                request.get("key_password"),
                request.get("apksigner"),
            )
        if op == "sign_split":
            return self.sign_split(
                request["output_dir"],
                request["keystore"],
                request["alias"],
                request["store_password"],
                request.get("key_password"),
                request.get("apksigner"),
            )
        if op == "install":
            return self.install_apk(
                request["path"],
                request.get("serial"),
                request.get("adb_path"),
                request.get("replace_existing", True),
            )
        if op == "install_split":
            return self.install_split(
                request["output_dir"],
                request.get("serial"),
                request.get("adb_path"),
                request.get("replace_existing", True),
            )
        if op == "sign_and_install":
            return self.sign_and_install(
                request["output"],
                request["keystore"],
                request["alias"],
                request["store_password"],
                request.get("key_password"),
                request.get("apksigner"),
                request.get("serial"),
                request.get("adb_path"),
                request.get("replace_existing", True),
            )
        if op == "sign_and_install_split":
            return self.sign_and_install_split(
                request["output_dir"],
                request["keystore"],
                request["alias"],
                request["store_password"],
                request.get("key_password"),
                request.get("apksigner"),
                request.get("serial"),
                request.get("adb_path"),
                request.get("replace_existing", True),
            )
        if op == "replace_string":
            return self.replace_string(request["id"], request["value"])
        if op == "search":
            return self.search(request.get("kind", "any"), request.get("query", ".*"))
        if op == "edit_search":
            return self.edit_search(
                request.get("kind", "methods"),
                request.get("query", ".*"),
                request.get("dex"),
            )
        if op == "describe":
            return self.describe(request["id"])
        if op == "edit_options":
            return self.edit_options(request["id"], request["offset"])
        if op == "apply_edit":
            return self.apply_edit(request["id"], request.get("arguments", {}))
        if op == "xrefs":
            return self.cross_references(request["id"])
        if op == "graph":
            return self.graph(request.get("id"), request.get("kind", "callgraph"), request.get("ignore", ""))
        if op == "graph_node_details":
            return self.graph_node_details(request.get("label", ""), request.get("node_id"))
        if op == "debug_connect":
            return self.debug_connect(request.get("host", "127.0.0.1"), request.get("port", 8000))
        if op == "debug_attach":
            return self.debug_attach(
                request["pid"],
                request.get("port", 8000),
                request.get("serial"),
                request.get("adb_path"),
            )
        if op == "debug_detach":
            return self.debug_detach()
        if op == "debug_connect_poll":
            return self.debug_connect_poll()
        if op == "debug_apps":
            return self.debug_apps(request.get("serial"), request.get("adb_path"))
        if op == "debug_apps_poll":
            return self.debug_apps_poll()
        if op == "debug_breakpoint":
            return self.debug_breakpoint(request["id"], request["offset"])
        if op == "debug_wait":
            return self.debug_wait_start()
        if op == "debug_poll":
            return self.debug_poll()
        if op == "debug_resume":
            return self.debug_resume()
        if op == "debug_step":
            return self.debug_step()
        if op == "debug_set_value":
            return self.debug_set_value(request["slot"], request["value"])
        raise RuntimeError("unknown operation: {}".format(op))


def main():
    backend = Backend()
    for line in sys.stdin:
        try:
            request = __import__("json").loads(line)
            data = backend.dispatch(request)
            response = {"ok": True, "data": data}
        except Exception as error:
            traceback.print_exc(file=sys.stderr)
            response = {"ok": False, "error": str(error)}
        sys.stdout.write(__import__("json").dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()

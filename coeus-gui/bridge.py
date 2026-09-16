#!/usr/bin/env python3
"""JSON-line worker used by the native Coeus GUI.

The worker intentionally owns all Coeus Python objects.  The Rust process only
deals in small JSON values, which keeps the GUI responsive while preserving the
existing Python API as the single source of truth for analysis and debugging.
"""

import queue
import re
import sys
import threading
import traceback
import os

from coeus_python import (
    AnalyzeObject,
    DexInstruction,
    Debugger,
    StackValue,
    VmInstance,
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
        self.objects = {}
        self.next_object_id = 1
        self.debugger = None
        self.debug_frame = None
        self.debug_method = None
        self.debug_values = []
        self.debug_wait = None
        self.debug_waiting = False

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
        self.objects.clear()
        self.next_object_id = 1
        manifests = self.ao.get_manifests()
        package = manifests[0].get_package() if manifests else ""
        return {
            "path": path,
            "package": package,
            "dex": self.ao.get_dex_names(),
            "files": len(self.ao.get_file_names()),
        }

    def write(self, path):
        if self.ao is None:
            raise RuntimeError("load an APK first")
        self.ao.write_apk(path)
        return {"path": path, "history": self.ao.get_history()}

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
        self.ao.replace_string(entry["object"], str(replacement))
        refreshed = None
        for evidence in self.ao.find_strings(re.escape(str(replacement))):
            kind, obj = self._concrete(evidence)
            if kind == "string" and obj.content() == str(replacement):
                refreshed = (evidence, obj)
                break
        if refreshed is not None:
            evidence, obj = refreshed
            entry["object"] = obj
            entry["evidence"] = evidence
        return {"id": object_id, "value": str(replacement)}

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
        return self.describe(option["method_id"])

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

    def debug_connect(self, host, port):
        self.debugger = Debugger(host, int(port))
        self.debug_frame = None
        self.debug_method = None
        self.debug_values = []
        return {"connected": True, "host": host, "port": int(port)}

    def debug_apps(self, serial=None, adb_path=None):
        apps = list_debuggable_apps(serial, adb_path)
        return {
            "apps": [
                {"pid": app.pid, "process": app.process_name, "package": app.package_name}
                for app in apps
            ]
        }

    def debug_breakpoint(self, object_id, offset):
        if self.debugger is None:
            raise RuntimeError("connect a debugger first")
        entry = self._entry(object_id)
        if entry["kind"] != "method":
            raise RuntimeError("breakpoints require a method")
        self.debugger.set_breakpoint(entry["object"], int(offset))
        return {"location": "{}@0x{:x}".format(entry["object"].signature(), int(offset))}

    def _wait_worker(self):
        try:
            frame = self.debugger.wait_for_package()
            self.debug_wait.put(("frame", frame))
        except Exception as error:
            self.debug_wait.put(("error", str(error)))

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
        classes = self.ao.find_classes(re.escape(class_name))
        if not classes:
            raise RuntimeError("class {} is not present in the loaded APK".format(class_name))
        method = classes[0].as_class()[method_name]
        method_id = self._id(method, kind="method")
        values = frame.get_values_for(self.debugger, method)
        self.debug_frame = frame
        self.debug_method = method
        self.debug_values = values
        return {
            "class": class_name,
            "method": method_name,
            "method_id": method_id,
            "code_index": frame.get_code_index(),
            "values": [
                {"slot": index, "value": self._value_text(value, self.debugger)}
                for index, value in enumerate(values)
            ],
        }

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
        return {"waiting": False, "frame": self._frame_data(value)}

    def debug_resume(self):
        if self.debugger is None:
            raise RuntimeError("connect a debugger first")
        self.debugger.resume()
        return self.debug_wait_start()

    def debug_step(self):
        if self.debug_frame is None:
            raise RuntimeError("the debugger is not stopped at a frame")
        self.debug_frame.step(self.debugger)
        self.debugger.resume()
        return self.debug_wait_start()

    def debug_set_value(self, slot, text):
        if self.debug_frame is None:
            raise RuntimeError("the debugger is not stopped at a frame")
        index = int(slot)
        old_value = self.debug_values[index]
        normalized = text.strip()
        if normalized.lower() in ("true", "false"):
            value = normalized.lower() == "true"
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
        if op == "write":
            return self.write(request["path"])
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
        if op == "debug_apps":
            return self.debug_apps(request.get("serial"), request.get("adb_path"))
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

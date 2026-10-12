"""GUI argument contract tests, independent of the optional Python extension."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


class Instruction:
    def __init__(self, factory="nop", arguments=(), text="nop"):
        self.factory = factory
        self.arguments = arguments
        self.text = text

    def __str__(self):
        return self.text

    def get_offset(self):
        return 0

    def get_size(self):
        return 1


class InstructionFactories:
    def __getattr__(self, factory):
        return lambda *arguments: Instruction(factory, arguments)


extension = types.ModuleType("coeus_python")
for name in (
    "AnalyzeObject", "DexVm", "Debugger", "StackValue", "SplitApkSet",
    "VmInstance", "forward_jdwp", "list_debuggable_apps",
):
    setattr(extension, name, object)
extension.DexInstruction = InstructionFactories()
spec = importlib.util.spec_from_file_location("coeus_gui_bridge_test", Path(__file__).parents[1] / "bridge.py")
bridge = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"coeus_python": extension}):
    spec.loader.exec_module(bridge)


class RegisterArgumentsTest(unittest.TestCase):
    def setUp(self):
        self.backend = bridge.Backend()

    def build(self, factory, **arguments):
        return self.backend._build_edit_instruction(factory, arguments, "after")

    def options(self, text):
        instruction = Instruction(text=text)
        method = types.SimpleNamespace(
            get_instructions=lambda: [instruction], get_dex_name=lambda: "classes.dex",
        )
        self.backend.ao = types.SimpleNamespace(
            edit_method=lambda method: types.SimpleNamespace(label_after=lambda target: "after")
        )
        self.backend._instruction_targets = lambda target: []
        object_id = self.backend._id(method, kind="method")
        return {
            option["label"]: {argument["name"]: argument for argument in option["arguments"]}
            for option in self.backend.edit_options(object_id, 0)["options"]
        }

    def test_plain_and_prefixed_registers(self):
        for value in (7, "7", "007", "v7", " v007 "):
            with self.subTest(value=value):
                self.assertEqual(self.build("const_lit32", register=value, value="-1").arguments, (7, -1))
        self.assertEqual(self.build("move_from16", register="v255", source_register="v65535").arguments, (255, 65535))
        self.assertEqual(self.build("switch", register="v8", case_value="-1").arguments, (8, [(-1, "after")]))

    def test_register_syntax_and_encoding_limits_are_enforced(self):
        for value in ("vv7", "v-1", "v0x7", "v", "v1.5", -1, "256", "v256"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.build("return_value", register=value)
        for factory, arguments in (
            ("move_from16", {"source_register": "v65536"}),
            ("instance_get", {"register": "v16"}),
            ("instance_put", {"object_register": "v16"}),
            ("if_eq", {"left_register": "v16"}),
        ):
            with self.subTest(factory=factory), self.assertRaises(RuntimeError):
                self.build(factory, **arguments)

    def test_invoke_registers_and_range_counts_have_distinct_types(self):
        self.assertEqual(
            self.build("invoke_static", register_count="2", method_index="3", registers="{v1, 02}").arguments,
            (2, 3, [1, 2]),
        )
        self.assertEqual(
            self.build("invoke_virtual_range", register_count="2", method_index="3", first_register="v300").arguments,
            (2, 3, 300),
        )
        for factory, arguments in (
            ("invoke_static", {"register_count": "v2", "registers": "v1 v2"}),
            ("invoke_static", {"register_count": "1", "registers": "v16"}),
            ("invoke_static", {"register_count": "1", "registers": "vv1"}),
            ("invoke_static", {"register_count": "1", "registers": "v1 v2"}),
            ("invoke_static", {"register_count": "0", "method_index": "v3"}),
            ("invoke_static_range", {"register_count": "v2", "first_register": "v3"}),
            ("invoke_static_range", {"register_count": "256", "first_register": "v3"}),
            ("invoke_static_range", {"register_count": "2", "first_register": "v65535"}),
        ):
            with self.subTest(factory=factory, arguments=arguments), self.assertRaises(RuntimeError):
                self.build(factory, **arguments)

    def test_destination_defaults_follow_written_register(self):
        for text in (
            "move/from16 v7, v300", "const/4 v7, 1", 'const-string v7, "v9"',
            "add-int v7, v1, v2", "sub-int/2addr v7, v2", "int-to-long v7, v2",
            "iget v7, v1, LExample;->field:I", "sget v7, LExample;->field:I",
        ):
            with self.subTest(text=text):
                options = self.options(text)
                for label in ("const literal", "const-string value", "move/from16", "iget", "sget"):
                    self.assertEqual(options[label]["register"]["value"], "v7")
                    self.assertEqual(options[label]["register"]["kind"], "register")

    def test_non_destination_operands_are_not_used_as_destination_defaults(self):
        for text in (
            "invoke-static {v7}, LExample;->call(I)V", "return v7",
            "iput v7, v1, LExample;->field:I", "sput v7, LExample;->field:I",
            "aput v7, v1, v2", "if-eqz v7, :label", "throw v7",
        ):
            with self.subTest(text=text):
                self.assertIsNone(bridge.Backend._edit_destination_register(text))
                self.assertEqual(self.options(text)["const literal"]["register"]["value"], "v0")

    def test_option_types_and_large_prefill_remain_editable(self):
        options = self.options("move/from16 v200, v300")
        self.assertEqual(options["iget"]["register"]["value"], "v200")
        self.assertEqual(options["invoke-virtual/range"]["first_register"]["kind"], "register")
        self.assertEqual(options["invoke-virtual/range"]["register_count"]["kind"], "integer")
        self.assertEqual(options["invoke-virtual/range"]["method_index"]["kind"], "integer")

    def test_recorded_scripts_replay_register_notation(self):
        for factory, arguments, expected in (
            ("const_lit32", {"register": "v007", "value": "-1"}, (7, -1)),
            ("move_from16", {"register": "v3", "source_register": "v300"}, (3, 300)),
            ("invoke_static", {"register_count": "2", "registers": "v1, 2", "method_index": "03"}, (2, 3, [1, 2])),
            ("invoke_static_range", {"register_count": "2", "first_register": "v300", "method_index": "3"}, (2, 3, 300)),
        ):
            with self.subTest(factory=factory):
                script = self.backend._script_instruction(factory, arguments)
                replayed = eval(script, {"DexInstruction": extension.DexInstruction})
                self.assertEqual(replayed.arguments, expected)


if __name__ == "__main__":
    unittest.main()

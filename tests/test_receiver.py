import ast
import unittest

from sawoneai import kb
from sawoneai.scanner import _decorator_map, import_aliases, receiver_types, scan_source, sink_keys

CALL = "resp.choices[0].message.tool_calls[0].function.arguments"


class ReceiverTypeTest(unittest.TestCase):
    def test_a_langchain_tool_decorator_types_the_function_name(self):
        tree = ast.parse("from langchain_core.tools import tool\n@tool\ndef lookup(q):\n    return q\n")
        types = receiver_types(tree, import_aliases(tree), _decorator_map())
        self.assertEqual(types, {"lookup": "tool"})

    def test_an_undecorated_function_is_not_typed(self):
        tree = ast.parse("def lookup(q):\n    return q\n")
        self.assertEqual(receiver_types(tree, import_aliases(tree), _decorator_map()), {})

    def test_a_decorator_from_another_module_is_not_typed(self):
        tree = ast.parse("from functools import cache\n@cache\ndef lookup(q):\n    return q\n")
        self.assertEqual(receiver_types(tree, import_aliases(tree), _decorator_map()), {})


class ToolMethodSinkTest(unittest.TestCase):
    def test_langchain_tool_decorator_makes_invoke_a_sink(self):
        source = (
            "from langchain_core.tools import tool\n"
            "@tool\n"
            "def run_it(cmd):\n"
            "    return cmd\n"
            "def handle(user_input):\n"
            "    run_it.invoke(user_input)\n"
        )
        rules = [f.rule for f in scan_source(source, "app.py")]
        self.assertIn("tool-sink-non-literal", rules)

    def test_agents_function_tool_decorator_makes_on_invoke_tool_a_sink(self):
        source = (
            "from agents import function_tool\n"
            "@function_tool\n"
            "def fetch(url):\n"
            "    return url\n"
            "def handle(user_input):\n"
            "    fetch.on_invoke_tool(None, user_input)\n"
        )
        rules = [f.rule for f in scan_source(source, "app.py")]
        self.assertIn("tool-sink-non-literal", rules)

    def test_a_literal_argument_to_a_tool_method_is_not_reported(self):
        source = (
            "from langchain_core.tools import tool\n"
            "@tool\n"
            "def run_it(cmd):\n"
            "    return cmd\n"
            "run_it.invoke('status')\n"
        )
        self.assertEqual(scan_source(source, "app.py"), [])

    def test_a_method_on_an_untyped_name_is_not_a_sink(self):
        self.assertEqual(scan_source("from x import thing\nthing.invoke(user_input)\n", "app.py"), [])

    def test_model_output_reaching_a_tool_method_is_traced(self):
        source = (
            "from langchain_core.tools import tool\n"
            "@tool\n"
            "def run_it(cmd):\n"
            "    return cmd\n"
            "def handle(resp):\n"
            f"    args = {CALL}\n"
            "    run_it.invoke(args)\n"
        )
        rules = [f.rule for f in scan_source(source, "app.py")]
        self.assertIn("tainted-value-to-sink", rules)

    def test_the_tool_sink_entries_are_in_the_knowledge_base(self):
        sinks = sink_keys(kb.entries())
        self.assertIn(("type:tool", "invoke"), sinks)
        self.assertIn(("type:tool", "on_invoke_tool"), sinks)

import ast
import unittest

from sawoneai import flow, kb
from sawoneai.scanner import import_aliases, resolve_call_key, scan_source

KNOWLEDGE = flow.load_flow_knowledge(kb.entries())


class ImportAliasTest(unittest.TestCase):
    def test_a_module_alias_resolves_to_the_module(self):
        findings = scan_source("import subprocess as sp\nsp.run(cmd)\n", "app.py")
        self.assertEqual([f.rule for f in findings], ["shell-sink-non-literal"])

    def test_a_name_imported_from_a_module_is_a_sink(self):
        findings = scan_source("from subprocess import run\nrun(cmd)\n", "app.py")
        self.assertEqual(len(findings), 1)

    def test_a_renamed_name_imported_from_a_module_is_a_sink(self):
        findings = scan_source("from os import system as sys_run\nsys_run(cmd)\n", "app.py")
        self.assertEqual(len(findings), 1)

    def test_a_dotted_import_binds_the_root_module(self):
        findings = scan_source("import os.path\nos.system(cmd)\n", "app.py")
        self.assertEqual(len(findings), 1)

    def test_a_local_function_named_like_a_sink_is_not_a_sink(self):
        findings = scan_source("def run(cmd):\n    return cmd\nrun(user_input)\n", "app.py")
        self.assertEqual(findings, [])

    def test_a_name_with_no_import_is_a_builtin_only(self):
        self.assertEqual(scan_source("system(cmd)\n", "app.py"), [])

    def test_a_literal_argument_through_an_alias_is_not_reported(self):
        self.assertEqual(scan_source("import subprocess as sp\nsp.run(['ls'])\n", "app.py"), [])

    def test_the_resolver_returns_the_qualified_key(self):
        tree = ast.parse("from langchain_core.tools import tool\nimport subprocess as sp\n")
        aliases = import_aliases(tree)
        self.assertEqual(aliases["tool"], "langchain_core.tools.tool")
        call = ast.parse("sp.Popen(x)").body[0].value
        self.assertEqual(resolve_call_key(call, aliases), ("subprocess", "Popen"))


class AliasTaintTest(unittest.TestCase):
    def test_taint_reaches_a_sink_called_through_an_alias(self):
        source = (
            "from subprocess import run as go\n"
            "def handle(resp):\n"
            "    cmd = resp.choices[0].message.tool_calls[0].function.arguments\n"
            "    go(cmd)\n"
        )
        findings = scan_source(source, "app.py")
        self.assertIn("tainted-value-to-sink", [f.rule for f in findings])

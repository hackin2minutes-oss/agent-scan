import tempfile
import unittest
from pathlib import Path

from sawoneai import scanner, tsscan

NEEDS = scanner.NEEDS_REVIEW
UNKNOWN_V = scanner.UNKNOWN


@unittest.skipUnless(tsscan.available(), "tree-sitter TypeScript grammar is not installed")
class TypeScriptSinkTest(unittest.TestCase):
    def scan(self, source, dialect="typescript"):
        return tsscan.scan_source(source, "app.ts", dialect)

    def test_template_with_substitution_into_exec_needs_review(self):
        findings = self.scan('child_process.exec(`ls ${dir}`);\n')
        self.assertEqual([f.verdict for f in findings], [NEEDS])
        self.assertEqual(findings[0].line, 1)
        self.assertIn("child_process.exec", findings[0].reason)

    def test_aliased_import_is_a_known_miss(self):
        # Documented limit: aliases are not followed, so cp.exec is not recognised as child_process.exec.
        self.assertEqual(self.scan('import cp from "child_process";\ncp.exec(`ls ${dir}`);\n'), [])

    def test_identifier_into_eval_needs_review(self):
        findings = self.scan("eval(userText);\n")
        self.assertEqual([f.verdict for f in findings], [NEEDS])

    def test_identifier_into_function_constructor_needs_review(self):
        findings = self.scan("const f = new Function(body);\n")
        self.assertEqual([f.verdict for f in findings], [NEEDS])
        self.assertIn("new Function", findings[0].reason)

    def test_string_literal_into_exec_is_clean(self):
        self.assertEqual(self.scan('child_process.exec("ls -la");\n'), [])

    def test_template_without_substitution_is_clean(self):
        self.assertEqual(self.scan("child_process.execSync(`ls -la`);\n"), [])

    def test_regex_exec_is_not_a_sink(self):
        self.assertEqual(self.scan("const m = pattern.exec(text);\n"), [])

    def test_call_with_no_arguments_is_clean(self):
        self.assertEqual(self.scan("eval();\n"), [])

    def test_unparseable_file_is_unknown_not_clean(self):
        findings = self.scan("function broken( {\n")
        self.assertEqual([f.verdict for f in findings], [UNKNOWN_V])
        self.assertEqual(findings[0].rule, "parse-error")

    def test_tsx_with_jsx_parses(self):
        source = "const view = <div>{title}</div>;\neval(title);\n"
        findings = self.scan(source, dialect="tsx")
        self.assertEqual([f.verdict for f in findings], [NEEDS])

    def test_scan_path_reports_typescript_files_and_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "agent.ts").write_text("eval(input);\n", encoding="utf-8")
            (root / "node_modules" / "pkg").mkdir(parents=True)
            (root / "node_modules" / "pkg" / "index.js").write_text("eval(x);\n", encoding="utf-8")
            result = scanner.scan_path(root)
            paths = [f.path for f in result.findings if f.rule == "ts-non-literal-sink"]
            self.assertEqual(paths, ["src/agent.ts"])


class TypeScriptAvailabilityTest(unittest.TestCase):
    def test_missing_analyser_gives_unknown_not_clean(self):
        original = tsscan.available
        tsscan.available = lambda: False
        try:
            findings = tsscan.scan_source("eval(x);\n", "app.ts")
        finally:
            tsscan.available = original
        self.assertEqual([f.verdict for f in findings], [UNKNOWN_V])
        self.assertEqual(findings[0].rule, "typescript-analyser-unavailable")


if __name__ == "__main__":
    unittest.main()

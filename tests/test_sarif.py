import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_scan import cli, sarif, scanner


def scan_of(source: str) -> scanner.ScanResult:
    root = Path(tempfile.mkdtemp())
    (root / "app.py").write_text(source, encoding="utf-8")
    return scanner.scan_path(root)


class SarifStructureTest(unittest.TestCase):
    def setUp(self):
        self.doc = sarif.to_sarif(scan_of("import os\nos.system(cmd)\n"), "0.0.1")

    def test_version_and_schema_are_sarif_2_1_0(self):
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", self.doc["$schema"])

    def test_one_run_with_the_tool_and_knowledge_base_versions(self):
        run = self.doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "agent-scan")
        self.assertEqual(run["properties"]["knowledgeBaseVersion"], "0.0.1")
        self.assertEqual(run["invocations"][0]["executionSuccessful"], True)

    def test_each_finding_has_a_rule_location_and_message(self):
        result = self.doc["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "shell-sink-non-literal")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app.py")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 2)
        self.assertIn("origin of the value", result["message"]["text"])

    def test_the_rule_is_declared_in_the_driver(self):
        ids = [rule["id"] for rule in self.doc["runs"][0]["tool"]["driver"]["rules"]]
        self.assertIn("shell-sink-non-literal", ids)

    def test_verdict_trace_and_missing_are_kept_in_properties(self):
        properties = self.doc["runs"][0]["results"][0]["properties"]
        self.assertEqual(properties["verdict"], "NEEDS_REVIEW")
        self.assertEqual(properties["trace"], [])
        self.assertTrue(properties["missing"])

    def test_needs_review_is_a_warning_and_unknown_is_a_note(self):
        self.assertEqual(sarif.LEVELS["NEEDS_REVIEW"], "warning")
        self.assertEqual(sarif.LEVELS["UNKNOWN"], "note")

    def test_a_clean_scan_has_no_results(self):
        doc = sarif.to_sarif(scan_of("print('hello')\n"), "0.0.1")
        self.assertEqual(doc["runs"][0]["results"], [])

    def test_the_document_is_valid_json(self):
        json.loads(json.dumps(self.doc))


class SarifCommandTest(unittest.TestCase):
    def test_scan_with_format_sarif_prints_sarif(self):
        root = Path(tempfile.mkdtemp())
        (root / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["scan", str(root), "--format", "sarif"])
        doc = json.loads(out.getvalue())
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), 1)

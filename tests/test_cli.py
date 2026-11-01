import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_scan import cli, kb


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class ScanCommandTest(unittest.TestCase):
    def setUp(self):
        self.project = Path(tempfile.mkdtemp())
        (self.project / "app.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")

    def test_scan_reports_needs_review_and_exits_zero(self):
        code, out, _ = run_cli("scan", str(self.project))
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("1 needs review", out)
        self.assertIn("0 confirmed", out)
        self.assertIn("app.py:2", out)

    def test_json_output_has_the_full_result(self):
        code, out, _ = run_cli("scan", str(self.project), "--json")
        data = json.loads(out)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(data["counts"]["NEEDS_REVIEW"], 1)
        self.assertEqual(data["findings"][0]["rule"], "shell-sink-non-literal")
        self.assertEqual(data["knowledge_base"], "0.0.1")

    def test_a_clean_project_reports_no_findings(self):
        clean = Path(tempfile.mkdtemp())
        (clean / "ok.py").write_text("print('hello')\n", encoding="utf-8")
        code, out, _ = run_cli("scan", str(clean))
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("0 needs review", out)

    def test_skipped_directories_are_not_scanned(self):
        venv = self.project / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "vendored.py").write_text("import os\nos.system(x)\n", encoding="utf-8")
        _, out, _ = run_cli("scan", str(self.project), "--json")
        self.assertEqual(json.loads(out)["files_scanned"], 1)

    def test_scan_refuses_to_run_on_a_tampered_knowledge_base(self):
        original = kb.verify
        try:
            kb.verify = lambda *a, **k: kb.VerifyResult(False, "0.0.1", ["entries.json: hash does not match"])
            code, _, err = run_cli("scan", str(self.project))
        finally:
            kb.verify = original
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("refusing to scan", err)

    def test_scan_of_a_missing_path_exits_two(self):
        code, _, err = run_cli("scan", str(self.project / "does-not-exist"))
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("is not a directory", err)


class KbCommandTest(unittest.TestCase):
    def test_kb_status_says_integrity_only_when_unsigned(self):
        code, out, _ = run_cli("kb", "status")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("verified", out)
        self.assertIn("integrity only", out)

    def test_kb_verify_passes_on_the_shipped_pack(self):
        code, out, _ = run_cli("kb", "verify")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(out.strip(), "verified")

    def test_version_prints_the_package_version(self):
        code, out, _ = run_cli("version")
        self.assertEqual((code, out.strip()), (cli.EXIT_OK, "0.0.1"))


class OutputFileTest(unittest.TestCase):
    def test_output_option_writes_the_result_to_a_file(self):
        project = Path(tempfile.mkdtemp())
        (project / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
        target = Path(tempfile.mkdtemp()) / "result.sarif"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["scan", str(project), "--format", "sarif", "--output", str(target)])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["version"], "2.1.0")


class ActionDefinitionTest(unittest.TestCase):
    def test_action_arguments_match_the_cli_options(self):
        import re
        root = Path(__file__).resolve().parent.parent
        action = (root / "action.yml").read_text(encoding="utf-8")
        for option in ["--format", "--output"]:
            self.assertIn(f'"{option}"', action)
        self.assertIn('"scan"', action)
        self.assertRegex(action, r'image: "Dockerfile"')
        cli.build_parser().parse_args(["scan", ".", "--format", "sarif", "--output", "x.sarif"])

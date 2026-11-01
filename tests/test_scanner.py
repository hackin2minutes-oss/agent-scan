import unittest

from sawoneai.scanner import NEEDS_REVIEW, UNKNOWN, scan_source


class ShellAndEvalSinkTest(unittest.TestCase):
    def test_os_system_with_variable_is_needs_review(self):
        findings = scan_source("import os\ncmd = input()\nos.system(cmd)\n", "app.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "shell-sink-non-literal")
        self.assertEqual(findings[0].verdict, NEEDS_REVIEW)
        self.assertEqual(findings[0].line, 3)

    def test_os_system_with_literal_is_not_reported(self):
        self.assertEqual(scan_source("import os\nos.system('ls -l')\n", "app.py"), [])

    def test_subprocess_with_variable_list_is_needs_review(self):
        findings = scan_source("import subprocess\nsubprocess.run(args)\n", "app.py")
        self.assertEqual([f.rule for f in findings], ["shell-sink-non-literal"])

    def test_subprocess_with_literal_list_is_not_reported(self):
        self.assertEqual(scan_source("import subprocess\nsubprocess.run(['ls', '-l'])\n", "app.py"), [])

    def test_eval_with_variable_is_needs_review(self):
        findings = scan_source("expr = input()\nresult = eval(expr)\n", "app.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "eval-sink-non-literal")
        self.assertEqual(findings[0].verdict, NEEDS_REVIEW)

    def test_eval_with_literal_is_not_reported(self):
        self.assertEqual(scan_source("x = eval('1 + 1')\n", "app.py"), [])

    def test_os_popen_with_variable_is_needs_review(self):
        findings = scan_source("import os\nos.popen(cmd)\n", "app.py")
        self.assertEqual([f.rule for f in findings], ["shell-sink-non-literal"])

    def test_exec_with_variable_is_needs_review(self):
        findings = scan_source("code = get()\nexec(code)\n", "app.py")
        self.assertEqual([f.rule for f in findings], ["eval-sink-non-literal"])

    def test_a_sink_added_to_the_knowledge_base_is_found_without_code_changes(self):
        sinks = {("mylib", "dangerous")}
        findings = scan_source("import mylib\nmylib.dangerous(x)\n", "app.py", sinks)
        self.assertEqual(len(findings), 1)

    def test_every_finding_names_what_is_missing(self):
        findings = scan_source("import os\nos.system(cmd)\n", "app.py")
        self.assertTrue(findings[0].missing)
        self.assertIn("origin of the value", findings[0].missing[0])

    def test_a_file_that_does_not_parse_is_unknown_not_clean(self):
        findings = scan_source("def broken(:\n", "bad.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].verdict, UNKNOWN)
        self.assertEqual(findings[0].rule, "parse-error")

    def test_no_finding_is_ever_confirmed_in_this_version(self):
        verdicts = {f.verdict for f in scan_source("import os\nos.system(x)\neval(y)\n", "app.py")}
        self.assertNotIn("CONFIRMED", verdicts)

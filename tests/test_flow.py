import unittest

from agent_scan import flow, kb
from agent_scan.scanner import NEEDS_REVIEW, scan_source

SINKS = {("subprocess", "run"), ("os", "system"), (None, "eval")}
KNOWLEDGE = flow.load_flow_knowledge(kb.entries())


def flows(source: str):
    import ast
    tree = ast.parse(source)
    return flow.scan_flows(tree, "app.py", SINKS, KNOWLEDGE)


CALL = "resp.choices[0].message.tool_calls[0].function.arguments"


class TaintToSinkTest(unittest.TestCase):
    def test_tool_call_arguments_reach_subprocess_is_needs_review(self):
        source = (
            "import subprocess\n"
            "def handle(resp):\n"
            f"    args = {CALL}\n"
            "    subprocess.run(args, shell=False)\n"
        )
        findings = flows(source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "tainted-value-to-sink")
        self.assertEqual(findings[0].verdict, NEEDS_REVIEW)
        self.assertEqual(findings[0].line, 4)

    def test_the_trace_names_the_source_the_assignment_and_the_sink(self):
        source = (
            "import subprocess\n"
            "def handle(resp):\n"
            f"    raw = {CALL}\n"
            "    cmd = raw\n"
            "    os_cmd = cmd\n"
            "    subprocess.run(os_cmd)\n"
        )
        trace = flows(source)[0].trace
        self.assertTrue(trace[0].startswith("line 3: model output read from .function.arguments"))
        self.assertIn("line 3: assigned to raw", trace)
        self.assertIn("line 4: assigned to cmd", trace)
        self.assertEqual(trace[-1], "line 6: reaches the sink")

    def test_the_finding_lists_what_is_missing(self):
        findings = flows(f"import subprocess\nsubprocess.run({CALL})\n")
        self.assertTrue(any("prompt injection" in item for item in findings[0].missing))
        self.assertTrue(any("across function boundaries" in item for item in findings[0].missing))

    def test_a_reassignment_with_a_constant_clears_the_taint(self):
        source = (
            "import subprocess\n"
            "def handle(resp):\n"
            f"    cmd = {CALL}\n"
            "    cmd = 'ls'\n"
            "    subprocess.run(cmd)\n"
        )
        self.assertEqual(flows(source), [])

    def test_an_untainted_value_reaching_a_sink_is_not_reported_here(self):
        self.assertEqual(flows("import subprocess\ndef f(x):\n    subprocess.run(x)\n"), [])

    def test_taint_does_not_cross_a_function_boundary(self):
        source = (
            "import subprocess\n"
            f"def get(resp):\n    return {CALL}\n"
            "def run(resp):\n    subprocess.run(get(resp))\n"
        )
        self.assertEqual(flows(source), [])

    def test_shlex_quote_around_the_sink_argument_breaks_the_path(self):
        source = (
            "import subprocess, shlex\n"
            "def handle(resp):\n"
            f"    cmd = {CALL}\n"
            "    subprocess.run(shlex.quote(cmd))\n"
        )
        self.assertEqual(flows(source), [])

    def test_scan_source_reports_the_flow_through_the_public_scanner(self):
        source = (
            "import subprocess\n"
            "def handle(resp):\n"
            f"    cmd = {CALL}\n"
            "    subprocess.run(cmd)\n"
        )
        rules = [f.rule for f in scan_source(source, "app.py")]
        self.assertIn("tainted-value-to-sink", rules)

    def test_the_flow_knowledge_comes_from_the_knowledge_base(self):
        self.assertIn(("function", "arguments"), [tuple(p) for p in KNOWLEDGE["sources"]])
        self.assertIn(("shlex", "quote"), KNOWLEDGE["sanitisers"])

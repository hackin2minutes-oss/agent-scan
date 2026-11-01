import unittest

from agent_scan.scanner import scan_source


def rules_of(source: str) -> list[str]:
    return [f.rule for f in scan_source(source, "app.py")]


EXECUTOR = (
    "import subprocess\n"
    "from agents import LocalShellTool\n"
    "def run_cmd(request):\n"
    "    command = request.data.action.command\n"
    "    subprocess.run(command)\n"
    "tool = LocalShellTool(executor=run_cmd)\n"
)


class ExecutorTest(unittest.TestCase):
    def test_executor_request_reaching_a_shell_is_traced(self):
        findings = [f for f in scan_source(EXECUTOR, "app.py") if f.rule == "tainted-value-to-sink"]
        self.assertEqual(len(findings), 1)
        self.assertIn("model-chosen input through LocalShellTool(executor=...)", " ".join(findings[0].trace))

    def test_an_executor_that_ignores_its_request_is_not_traced(self):
        source = (
            "import subprocess\n"
            "from agents import LocalShellTool\n"
            "def run_cmd(request):\n"
            "    subprocess.run(['uptime'])\n"
            "tool = LocalShellTool(executor=run_cmd)\n"
        )
        self.assertNotIn("tainted-value-to-sink", rules_of(source))

    def test_a_shell_quote_wrapper_breaks_the_executor_path(self):
        source = (
            "import subprocess, shlex\n"
            "from agents import LocalShellTool\n"
            "def run_cmd(request):\n"
            "    subprocess.run(shlex.quote(request.data.action.command))\n"
            "tool = LocalShellTool(executor=run_cmd)\n"
        )
        self.assertNotIn("tainted-value-to-sink", rules_of(source))

    def test_a_function_that_is_not_an_executor_is_not_a_source(self):
        source = (
            "import subprocess\n"
            "def run_cmd(request):\n"
            "    subprocess.run(request.data)\n"
        )
        self.assertNotIn("tainted-value-to-sink", rules_of(source))

    def test_an_executor_defined_elsewhere_is_not_traced_here(self):
        source = "from agents import LocalShellTool\ntool = LocalShellTool(executor=imported_run)\n"
        self.assertEqual(scan_source(source, "app.py"), [])

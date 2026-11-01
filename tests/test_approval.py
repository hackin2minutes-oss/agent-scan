import unittest

from sawoneai.scanner import scan_source


def rules_of(source: str) -> list[str]:
    return [f.rule for f in scan_source(source, "app.py")]


class ToolApprovalTest(unittest.TestCase):
    def test_function_tool_reaching_a_sink_without_approval_is_flagged(self):
        source = (
            "import os\n"
            "from agents import function_tool\n"
            "@function_tool\n"
            "def clean(path):\n"
            "    os.system(path)\n"
        )
        self.assertIn("tool-reaches-sink-without-approval", rules_of(source))

    def test_function_tool_with_approval_required_is_not_flagged(self):
        source = (
            "import os\n"
            "from agents import function_tool\n"
            "@function_tool(needs_approval=True)\n"
            "def clean(path):\n"
            "    os.system(path)\n"
        )
        self.assertNotIn("tool-reaches-sink-without-approval", rules_of(source))

    def test_explicit_false_approval_is_flagged(self):
        source = (
            "import os\n"
            "from agents import function_tool\n"
            "@function_tool(needs_approval=False)\n"
            "def clean(path):\n"
            "    os.system(path)\n"
        )
        self.assertIn("tool-reaches-sink-without-approval", rules_of(source))

    def test_a_callable_approval_is_not_judged_statically(self):
        source = (
            "import os\n"
            "from agents import function_tool\n"
            "@function_tool(needs_approval=check)\n"
            "def clean(path):\n"
            "    os.system(path)\n"
        )
        self.assertNotIn("tool-reaches-sink-without-approval", rules_of(source))

    def test_a_tool_without_a_sink_is_not_flagged(self):
        source = (
            "from agents import function_tool\n"
            "@function_tool\n"
            "def add(a, b):\n"
            "    return a + b\n"
        )
        self.assertNotIn("tool-reaches-sink-without-approval", rules_of(source))

    def test_a_literal_command_is_not_a_sink_use(self):
        source = (
            "import os\n"
            "from agents import function_tool\n"
            "@function_tool\n"
            "def status():\n"
            "    os.system('uptime')\n"
        )
        self.assertNotIn("tool-reaches-sink-without-approval", rules_of(source))

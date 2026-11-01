import unittest

from sawoneai import kb
from sawoneai.scanner import loop_rules, scan_source


class AgentLoopTest(unittest.TestCase):
    def test_explicit_none_max_turns_is_flagged(self):
        source = (
            "from agents import Runner\n"
            "Runner.run(agent, 'hello', max_turns=None)\n"
        )
        findings = scan_source(source, "app.py")
        self.assertEqual([f.rule for f in findings], ["unbounded-agent-loop"])
        self.assertEqual(findings[0].line, 2)

    def test_run_sync_with_none_is_flagged_through_an_alias(self):
        source = (
            "from agents import Runner as R\n"
            "R.run_sync(agent, 'hello', max_turns=None)\n"
        )
        self.assertEqual([f.rule for f in scan_source(source, "app.py")], ["unbounded-agent-loop"])

    def test_the_default_is_not_flagged(self):
        self.assertEqual(scan_source("from agents import Runner\nRunner.run(agent, 'hi')\n", "app.py"), [])

    def test_a_numeric_limit_is_not_flagged(self):
        source = "from agents import Runner\nRunner.run(agent, 'hi', max_turns=5)\n"
        self.assertEqual(scan_source(source, "app.py"), [])

    def test_an_unimported_runner_is_not_flagged(self):
        self.assertEqual(scan_source("Runner.run(agent, 'hi', max_turns=None)\n", "app.py"), [])

    def test_the_loop_rule_comes_from_the_knowledge_base(self):
        rules = loop_rules(kb.entries())
        self.assertEqual(rules[("agents.Runner", "run")], ("max_turns", [None]))

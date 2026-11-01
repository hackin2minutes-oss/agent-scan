import tempfile
import unittest
from pathlib import Path

from sawoneai import ghactions, scanner

PINNED = "actions/checkout@" + "a" * 40


def workflow(trigger, steps):
    """Each step is one YAML mapping written as text, so keys such as `with` belong to their step."""
    import yaml
    parsed = [yaml.safe_load(step) for step in steps]
    return yaml.safe_dump({"on": trigger, "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": parsed}}})


class WorkflowCheckTest(unittest.TestCase):
    def rules(self, text):
        return [f.rule for f in ghactions.scan_workflow(text, "ci.yml")]

    def test_checkout_of_pull_request_head_under_pull_request_target_is_flagged(self):
        text = workflow("pull_request_target", [
            f"uses: {PINNED}\nwith:\n  ref: ${{{{ github.event.pull_request.head.sha }}}}",
        ])
        self.assertIn("gha-untrusted-checkout", self.rules(text))

    def test_checkout_of_workflow_run_head_is_flagged(self):
        text = workflow("workflow_run", [
            f"uses: {PINNED}\nwith:\n  ref: ${{{{ github.event.workflow_run.head_sha }}}}",
        ])
        self.assertIn("gha-untrusted-checkout", self.rules(text))

    def test_default_checkout_under_pull_request_target_is_not_flagged(self):
        text = workflow("pull_request_target", [f"uses: {PINNED}"])
        self.assertNotIn("gha-untrusted-checkout", self.rules(text))

    def test_pull_request_head_checkout_under_plain_pull_request_is_not_flagged(self):
        text = workflow("pull_request", [
            f"uses: {PINNED}\nwith:\n  ref: ${{{{ github.event.pull_request.head.sha }}}}",
        ])
        self.assertNotIn("gha-untrusted-checkout", self.rules(text))

    def test_issue_title_in_run_script_is_flagged(self):
        text = workflow("issues", ["run: echo \"${{ github.event.issue.title }}\""])
        self.assertIn("gha-script-injection", self.rules(text))

    def test_safe_env_variable_pattern_is_not_flagged(self):
        text = workflow("issues", ["env:\n  TITLE: ${{ github.event.issue.title }}\nrun: echo \"$TITLE\""])
        self.assertNotIn("gha-script-injection", self.rules(text))

    def test_tag_reference_is_flagged_as_unpinned(self):
        text = workflow("push", ["uses: actions/checkout@v4"])
        self.assertIn("gha-unpinned-action", self.rules(text))

    def test_sha_pinned_action_is_not_flagged_as_unpinned(self):
        text = workflow("push", [f"uses: {PINNED}"])
        self.assertNotIn("gha-unpinned-action", self.rules(text))

    def test_unparseable_workflow_is_unknown(self):
        findings = ghactions.scan_workflow("on: [push\njobs: {", "ci.yml")
        self.assertEqual([f.verdict for f in findings], [scanner.UNKNOWN])

    def test_scan_path_finds_workflows_under_dot_github(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text(
                workflow("issues", ["run: echo \"${{ github.event.issue.title }}\""]), encoding="utf-8")
            result = scanner.scan_path(root)
            paths = [f.path for f in result.findings if f.rule == "gha-script-injection"]
            self.assertEqual(paths, [".github/workflows/ci.yml"])


if __name__ == "__main__":
    unittest.main()

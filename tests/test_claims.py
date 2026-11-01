import json
import unittest

from agent_scan import claims


def line(record) -> str:
    return json.dumps(record)


def assistant_text(text):
    return line({"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}})


def bash_call(call_id, command):
    return line({"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": call_id, "name": "Bash", "input": {"command": command}}]}})


def bash_result(call_id, text):
    return line({"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": call_id, "content": text}]}})


class ClaimCheckTest(unittest.TestCase):
    def test_a_test_claim_backed_by_a_passing_run_is_supported(self):
        transcript = [bash_call("1", "python3 -m unittest discover"), bash_result("1", "Ran 12 tests\n\nOK"),
                      assistant_text("All tests pass now.")]
        result = claims.check(transcript)
        self.assertEqual(result["claims"][0].status, claims.SUPPORTED)

    def test_a_test_claim_contradicted_by_a_failing_run(self):
        transcript = [bash_call("1", "pytest -q"), bash_result("1", "FAILED tests/test_x.py::test_y - AssertionError"),
                      assistant_text("The tests passed.")]
        self.assertEqual(claims.check(transcript)["claims"][0].status, claims.CONTRADICTED)

    def test_a_test_claim_with_no_test_run_is_not_in_logs(self):
        transcript = [assistant_text("I ran the tests and they passed.")]
        result = claims.check(transcript)
        self.assertEqual(result["claims"][0].status, claims.NOT_IN_LOGS)
        self.assertNotIn("false", result["claims"][0].evidence.lower())

    def test_a_test_run_with_an_unclear_result_is_not_in_logs(self):
        transcript = [bash_call("1", "npm test"), bash_result("1", "done"),
                      assistant_text("The test suite passes.")]
        self.assertEqual(claims.check(transcript)["claims"][0].status, claims.NOT_IN_LOGS)

    def test_a_commit_claim_is_supported_by_a_git_commit_call(self):
        transcript = [bash_call("1", "git commit -m 'x'"), bash_result("1", "[main 1a2b3c] x"),
                      assistant_text("I committed the change.")]
        self.assertEqual(claims.check(transcript)["claims"][0].status, claims.SUPPORTED)

    def test_a_push_claim_without_a_push_is_not_in_logs(self):
        transcript = [assistant_text("I pushed the branch.")]
        self.assertEqual(claims.check(transcript)["claims"][0].status, claims.NOT_IN_LOGS)

    def test_a_claim_is_never_reported_as_false(self):
        transcript = [assistant_text("I ran the tests.")]
        for item in claims.check(transcript)["claims"]:
            self.assertIn(item.status, {claims.SUPPORTED, claims.CONTRADICTED, claims.NOT_IN_LOGS})

    def test_unreadable_lines_are_reported_not_guessed(self):
        transcript = ["{not json", assistant_text("hello")]
        result = claims.check(transcript)
        self.assertEqual(result["unreadable_lines"], [1])

    def test_a_result_is_matched_to_its_call_by_id(self):
        transcript = [bash_call("a", "pytest"), bash_call("b", "git status"),
                      bash_result("a", "1 failed"), assistant_text("All tests passed.")]
        self.assertEqual(claims.check(transcript)["claims"][0].status, claims.CONTRADICTED)

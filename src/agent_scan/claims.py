"""Claim checker: what an agent says it did, against the tool calls its session recorded.

Input: a session transcript in JSON Lines, in the format Claude Code writes (assistant messages with text and tool_use
blocks; user messages with tool_result blocks). The format is taken from our understanding of that file and is NOT yet
verified against a real transcript from every version; the parser reports lines it cannot read instead of guessing.

Each claim is marked:
- supported: a tool call in the log backs the claim (and, for test claims, its result shows success);
- contradicted: the log shows the opposite (a test run that failed, for a claim that tests passed);
- not in logs: no matching call was recorded. This does not mean the claim is false: the log may be incomplete.

The checker never says a claim is false. It says what the log shows.
"""

import json
import re
from dataclasses import dataclass, field

SUPPORTED, CONTRADICTED, NOT_IN_LOGS = "supported", "contradicted", "not in logs"

TEST_COMMAND = re.compile(r"\b(pytest|unittest|npm (run )?test|yarn test|go test|dotnet test|mvn test|gradle test|"
                          r"cargo test|jest|vitest)\b")
COMMIT_COMMAND = re.compile(r"\bgit commit\b")
PUSH_COMMAND = re.compile(r"\bgit push\b")
TEST_CLAIM = re.compile(r"\b(tests?|test suite|specs?)\b.{0,40}\b(pass(ed|es|ing)?|green|succeed(ed)?)\b|"
                        r"\b(i|we) (ran|ran the|have run) (the )?tests?\b", re.IGNORECASE)
COMMIT_CLAIM = re.compile(r"\b(i|we) (committed|made a commit|have committed)\b", re.IGNORECASE)
PUSH_CLAIM = re.compile(r"\b(i|we) (pushed|have pushed)\b", re.IGNORECASE)
FAILURE_MARKERS = re.compile(r"\b(FAILED|failures?|errors?|Traceback|exit code [1-9]|failed)\b", re.IGNORECASE)
SUCCESS_MARKERS = re.compile(r"\b(OK|passed|PASSED|all tests pass)\b")


@dataclass
class Claim:
    line: int
    text: str
    kind: str
    status: str
    evidence: str
    missing: list[str] = field(default_factory=list)


@dataclass
class ToolCall:
    line: int
    name: str
    command: str
    result: str = ""
    result_line: int | None = None


def parse_transcript(lines: list[str]):
    """Assistant text claims, tool calls with their results, and the line numbers that could not be read."""
    claims, calls, by_id, unreadable = [], [], {}, []
    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            record = json.loads(raw)
        except ValueError:
            unreadable.append(number)
            continue
        message = record.get("message") or {}
        content = message.get("content")
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if record.get("type") == "assistant" and block.get("type") == "text":
                claims.append((number, block.get("text", "")))
            elif record.get("type") == "assistant" and block.get("type") == "tool_use":
                tool_input = block.get("input") or {}
                command = tool_input.get("command") or tool_input.get("file_path") or ""
                call = ToolCall(number, block.get("name", ""), str(command))
                calls.append(call)
                by_id[block.get("id")] = call
            elif record.get("type") == "user" and block.get("type") == "tool_result":
                call = by_id.get(block.get("tool_use_id"))
                if call is not None:
                    text = block.get("content")
                    call.result = text if isinstance(text, str) else json.dumps(text)
                    call.result_line = number
    return claims, calls, unreadable


def _latest(calls: list[ToolCall], pattern: re.Pattern, before: int) -> ToolCall | None:
    matches = [c for c in calls if c.name == "Bash" and pattern.search(c.command) and c.line <= before]
    return matches[-1] if matches else None


def check(lines: list[str]) -> dict:
    claims, calls, unreadable = parse_transcript(lines)
    results = []
    for number, text in claims:
        if TEST_CLAIM.search(text):
            results.append(_test_claim(number, text, calls))
        elif COMMIT_CLAIM.search(text):
            results.append(_command_claim(number, text, calls, COMMIT_COMMAND, "commit"))
        elif PUSH_CLAIM.search(text):
            results.append(_command_claim(number, text, calls, PUSH_COMMAND, "push"))
    counts = {status: sum(1 for c in results if c.status == status)
              for status in (SUPPORTED, CONTRADICTED, NOT_IN_LOGS)}
    return {"claims": results, "counts": counts, "unreadable_lines": unreadable,
            "tool_calls_read": len(calls)}


def _test_claim(number, text, calls):
    run = _latest(calls, TEST_COMMAND, number)
    if run is None:
        return Claim(number, text.strip(), "tests", NOT_IN_LOGS, "no test command was recorded before this claim",
                     ["the test run itself, in the session log"])
    if run.result and FAILURE_MARKERS.search(run.result) and not SUCCESS_MARKERS.search(run.result):
        return Claim(number, text.strip(), "tests", CONTRADICTED,
                     f"the test command at line {run.line} shows failure in its result (line {run.result_line})", [])
    if run.result and SUCCESS_MARKERS.search(run.result):
        return Claim(number, text.strip(), "tests", SUPPORTED,
                     f"test command at line {run.line} with a success marker in its result (line {run.result_line})", [])
    return Claim(number, text.strip(), "tests", NOT_IN_LOGS,
                 f"a test command ran at line {run.line}, but its result shows neither success nor failure",
                 ["the test output"])


def _command_claim(number, text, calls, pattern, kind):
    call = _latest(calls, pattern, number)
    if call is None:
        return Claim(number, text.strip(), kind, NOT_IN_LOGS, f"no git {kind} was recorded before this claim", [])
    return Claim(number, text.strip(), kind, SUPPORTED, f"git {kind} at line {call.line}", [])

"""Scanner core.

Milestone 0, first check: a value that is not a literal reaching a shell or eval sink in Python code.

Verdicts used here:
- NEEDS_REVIEW: a non-literal argument reaches a sink. The origin of the value is not established, so no
  confirmed path is claimed.
- UNKNOWN: the file could not be analysed. The missing piece is named.

Nothing in this module decides a verdict from a language model. Verdicts follow from the syntax tree and the rules
below, and every finding names what it could not establish.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path

NEEDS_REVIEW = "NEEDS_REVIEW"
UNKNOWN = "UNKNOWN"

# Calls that run a command or evaluate code. Keys are (module or None, function name).
SHELL_SINKS = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "Popen"),
}
EVAL_SINKS = {(None, "eval"), (None, "exec")}

SKIPPED_DIRECTORIES = {".git", ".venv", "venv", "__pycache__", "build", "dist", "node_modules"}


@dataclass
class Finding:
    rule: str
    path: str
    line: int
    verdict: str
    reason: str
    missing: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"rule": self.rule, "path": self.path, "line": self.line, "verdict": self.verdict,
                "reason": self.reason, "missing": list(self.missing)}


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)

    def counts(self) -> dict:
        counts = {NEEDS_REVIEW: 0, UNKNOWN: 0}
        for finding in self.findings:
            counts[finding.verdict] = counts.get(finding.verdict, 0) + 1
        return counts


def _call_key(node: ast.Call):
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return (func.value.id, func.attr)
    if isinstance(func, ast.Name):
        return (None, func.id)
    return None


def _is_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_is_literal(element) for element in node.elts)
    return False


def _sink_label(key) -> str:
    module, name = key
    return f"{module}.{name}" if module else name


def scan_source(source: str, rel_path: str) -> list[Finding]:
    """Findings for one Python source text. A file that does not parse gives one UNKNOWN finding."""
    try:
        tree = ast.parse(source, filename=rel_path)
    except (SyntaxError, ValueError):
        return [Finding("parse-error", rel_path, 1, UNKNOWN, "the file could not be parsed as Python",
                        ["a file that parses as Python"])]
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        key = _call_key(node)
        if key is None or not node.args:
            continue
        if key in SHELL_SINKS:
            rule = "shell-sink-non-literal"
        elif key in EVAL_SINKS:
            rule = "eval-sink-non-literal"
        else:
            continue
        if all(_is_literal(argument) for argument in node.args):
            continue
        findings.append(Finding(
            rule=rule,
            path=rel_path,
            line=node.lineno,
            verdict=NEEDS_REVIEW,
            reason=f"a non-literal argument reaches {_sink_label(key)}; the origin of the value is not established",
            missing=["the origin of the value: user input, model output, retrieved content, or configuration"],
        ))
    return findings


def _python_files(root: Path):
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(part in SKIPPED_DIRECTORIES or part.startswith(".") for part in relative.parts[:-1]):
            continue
        yield path, relative.as_posix()


def scan_path(root: Path) -> ScanResult:
    root = Path(root)
    result = ScanResult(root=str(root))
    for path, relative in _python_files(root):
        result.files_scanned += 1
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            result.findings.append(Finding("unreadable-file", relative, 1, UNKNOWN,
                                           "the file could not be read as UTF-8 text",
                                           ["a readable UTF-8 file"]))
            continue
        result.findings.extend(scan_source(source, relative))
    return result

"""Scanner core.

Milestone 0, first check: a value that is not a literal reaching a sink in Python code. Sinks come from the
knowledge base, so adding a sink is a data change, not a code change.

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

SINK_KIND = "sink"


def sink_keys(entries_list: list[dict]) -> set[tuple]:
    """(module, function) pairs for every sink in the knowledge base. Module is None for builtins."""
    keys = set()
    for entry in entries_list:
        if entry.get("kind") != SINK_KIND:
            continue
        for function in entry.get("functions", []):
            keys.add((entry.get("module"), function))
    return keys


def _load_sinks() -> set[tuple]:
    from agent_scan import kb
    return sink_keys(kb.entries())


SKIPPED_DIRECTORIES = {".git", ".venv", "venv", "__pycache__", "build", "dist", "node_modules"}


@dataclass
class Finding:
    rule: str
    path: str
    line: int
    verdict: str
    reason: str
    missing: list[str] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"rule": self.rule, "path": self.path, "line": self.line, "verdict": self.verdict,
                "reason": self.reason, "missing": list(self.missing), "trace": list(self.trace)}


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


def import_aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> fully qualified name, from the file's import statements.

    `import subprocess as sp` maps sp to subprocess. `from subprocess import run as r` maps r to subprocess.run.
    `import os.path` binds os, so it maps os to os."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    root = alias.name.split(".")[0]
                    aliases[root] = root
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def resolve_call_key(node: ast.Call, aliases: dict[str, str]):
    """(module, function) a call refers to, after resolving import aliases. None when it cannot be named.

    A bare name that is not imported is a builtin (module None), so a local function called run() is not a sink."""
    func = node.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            module = aliases.get(func.value.id, func.value.id)
            return (module, func.attr)
        return None
    if isinstance(func, ast.Name):
        if func.id in aliases:
            qualified = aliases[func.id]
            module, _, name = qualified.rpartition(".")
            return (module or None, name)
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


def scan_source(source: str, rel_path: str, sinks: set[tuple] | None = None) -> list[Finding]:
    """Findings for one Python source text. A file that does not parse gives one UNKNOWN finding.
    Sinks come from the knowledge base unless given."""
    sinks = _load_sinks() if sinks is None else sinks
    try:
        tree = ast.parse(source, filename=rel_path)
    except (SyntaxError, ValueError):
        return [Finding("parse-error", rel_path, 1, UNKNOWN, "the file could not be parsed as Python",
                        ["a file that parses as Python"])]
    findings = []
    from agent_scan import flow, kb
    knowledge = flow.load_flow_knowledge(kb.entries())
    findings.extend(flow.scan_flows(tree, rel_path, sinks, knowledge))
    aliases = import_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        key = resolve_call_key(node, aliases)
        if key is None or not node.args:
            continue
        if key not in sinks:
            continue
        rule = "eval-sink-non-literal" if key[0] is None else "shell-sink-non-literal"
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
    sinks = _load_sinks()
    for path, relative in _python_files(root):
        result.files_scanned += 1
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            result.findings.append(Finding("unreadable-file", relative, 1, UNKNOWN,
                                           "the file could not be read as UTF-8 text",
                                           ["a readable UTF-8 file"]))
            continue
        result.findings.extend(scan_source(source, relative, sinks))
    return result

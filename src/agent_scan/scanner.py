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


def _decorator_map() -> dict[tuple, str]:
    from agent_scan import kb
    mapping = {}
    for entry in kb.entries():
        if entry.get("kind") == "decorator":
            for function in entry.get("functions", []):
                mapping[(entry.get("module"), function)] = entry["produces"]
    return mapping


def loop_rules(entries_list: list[dict]) -> dict[tuple, tuple]:
    """(module, function) -> (keyword, unbounded values) for agent-loop entries in the knowledge base."""
    rules = {}
    for entry in entries_list:
        if entry.get("kind") != "loop":
            continue
        for function in entry.get("functions", []):
            rules[(entry.get("module"), function)] = (entry["keyword"], entry.get("unbounded_values", []))
    return rules


def _loop_findings(tree: ast.AST, rel_path: str, aliases: dict[str, str], types: dict[str, str]) -> list["Finding"]:
    from agent_scan import kb
    rules = loop_rules(kb.entries())
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        key = resolve_call_key(node, aliases, types)
        if key not in rules:
            continue
        keyword, unbounded = rules[key]
        for argument in node.keywords:
            if argument.arg != keyword or not isinstance(argument.value, ast.Constant):
                continue
            if argument.value.value in unbounded:
                findings.append(Finding(
                    rule="unbounded-agent-loop",
                    path=rel_path,
                    line=node.lineno,
                    verdict=NEEDS_REVIEW,
                    reason=f"{keyword}=None removes the turn limit on {key[0]}.{key[1]}; the agent can loop without "
                           "a bound",
                    missing=["whether untrusted content can keep the agent looping",
                             "whether a timeout or outer limit bounds the run"],
                ))
    return findings


def approval_rules(entries_list: list[dict]) -> dict[tuple, str]:
    """(module, function) of a tool decorator -> the keyword that sets its approval requirement."""
    return {(entry.get("module"), function): entry["keyword"]
            for entry in entries_list if entry.get("kind") == "approval"
            for function in entry.get("functions", [])}


def _approval_findings(tree: ast.AST, rel_path: str, aliases: dict[str, str], sinks: set) -> list["Finding"]:
    from agent_scan import kb
    entries_list = kb.entries()
    rules = approval_rules(entries_list)
    missing = {(e.get("module"), f): e.get("missing_values", [False])
               for e in entries_list if e.get("kind") == "approval" for f in e.get("functions", [])}
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            target = decorator.func if call else decorator
            key = _name_key(target, aliases)
            if key not in rules:
                continue
            keyword = rules[key]
            value = None
            present = False
            if call:
                for argument in call.keywords:
                    if argument.arg == keyword:
                        present = True
                        value = argument.value
            if present and not (isinstance(value, ast.Constant) and value.value in missing[key]):
                continue  # approval is set to something other than the unapproved values, or is a callable
            reached = _sink_in_body(node, aliases, sinks)
            if reached:
                findings.append(Finding(
                    rule="tool-reaches-sink-without-approval",
                    path=rel_path,
                    line=node.lineno,
                    verdict=NEEDS_REVIEW,
                    reason=f"tool {node.name} calls {reached} and has no {keyword}=True, so it runs without a "
                           "human approval step",
                    missing=["whether the tool's arguments can be chosen by a model or by untrusted content",
                             "whether an approval callable is used elsewhere"],
                ))
    return findings


def _sink_in_body(function: ast.AST, aliases: dict[str, str], sinks: set):
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            key = resolve_call_key(node, aliases)
            if key in sinks and node.args and not all(_is_literal(a) for a in node.args):
                return f"{key[0] + '.' if key[0] else ''}{key[1]}"
    return None


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


def receiver_types(tree: ast.AST, aliases: dict[str, str], decorators: set[tuple]) -> dict[str, str]:
    """Names this file binds to a known object type, by a decorator in the knowledge base.

    A function decorated with a decorator that produces "tool" makes its name a tool object. Only these bindings are
    known: other constructors are not in the knowledge base yet, so their methods are not sinks."""
    types: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if not isinstance(target, (ast.Name, ast.Attribute)):
                continue
            key = _name_key(target, aliases)
            if key in decorators:
                types[node.name] = decorators[key]
    return types


def _name_key(node, aliases: dict[str, str]):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return (aliases.get(node.value.id, node.value.id), node.attr)
    if isinstance(node, ast.Name):
        if node.id in aliases:
            module, _, name = aliases[node.id].rpartition(".")
            return (module or None, name)
        return (None, node.id)
    return None


def _dotted_name(node: ast.AST) -> list[str] | None:
    """The names of a plain dotted path such as urllib.request, or None when the path has other parts."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        return [node.id] + list(reversed(parts))
    return None


def resolve_call_key(node: ast.Call, aliases: dict[str, str], types: dict[str, str] | None = None):
    """(module, function) a call refers to, after resolving import aliases. None when it cannot be named.

    A bare name that is not imported is a builtin (module None), so a local function called run() is not a sink.
    A method on a name with a known object type is keyed as ("type:<type>", method)."""
    func = node.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            if types and func.value.id in types:
                return (f"type:{types[func.value.id]}", func.attr)
            module = aliases.get(func.value.id, func.value.id)
            return (module, func.attr)
        dotted = _dotted_name(func.value)
        if dotted:
            root, *rest = dotted
            module = ".".join([aliases.get(root, root)] + rest)
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
    types = receiver_types(tree, aliases, _decorator_map())
    findings.extend(_loop_findings(tree, rel_path, aliases, types))
    findings.extend(_approval_findings(tree, rel_path, aliases, sinks))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        key = resolve_call_key(node, aliases, types)
        if key is None or not node.args:
            continue
        if key not in sinks:
            continue
        if key[0] is None:
            rule = "eval-sink-non-literal"
        elif key[0].startswith("type:"):
            rule = "tool-sink-non-literal"
        else:
            rule = "shell-sink-non-literal"
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


def _mcp_config_files(root: Path):
    from agent_scan import mcp
    for path in sorted(root.rglob("*.json")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if any(part in {".git", ".venv", "node_modules"} for part in path.relative_to(root).parts[:-1]):
            continue
        if mcp.is_mcp_config(relative):
            yield path, relative


def _python_files(root: Path):
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(part in SKIPPED_DIRECTORIES or part.startswith(".") for part in relative.parts[:-1]):
            continue
        yield path, relative.as_posix()


def scan_path(root: Path, mcp_tools: dict | None = None, mcp_approved: dict | None = None) -> ScanResult:
    """Scan a directory. mcp_tools is a parsed tools/list document; mcp_approved is {"server": name, "tools": {name:
    hash}}. Both are needed for the tool-description check, and neither is read from the project."""
    root = Path(root)
    result = ScanResult(root=str(root))
    sinks = _load_sinks()
    from agent_scan import kb, mcp, textscan
    text_rules = textscan.text_rules(kb.entries())
    mcp_rules = {entry["rule"]: entry["commands"] for entry in kb.entries() if entry.get("kind") == "mcp_rule"}
    for path, relative in _mcp_config_files(root):
        result.files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            result.findings.append(Finding("unreadable-file", relative, 1, "UNKNOWN",
                                           "the MCP configuration could not be read as UTF-8 text",
                                           ["a readable UTF-8 file"]))
            continue
        result.findings.extend(mcp.check_config(text, relative, mcp_rules))
    if mcp_tools is not None:
        from agent_scan import mcp as mcp_module
        approved = (mcp_approved or {}).get("tools", {})
        server = (mcp_approved or {}).get("server", "mcp-server")
        result.findings.extend(mcp_module.check_tools(mcp_module.tools_from(mcp_tools), approved, text_rules, server))
    for path, relative in textscan.rule_files(root):
        result.files_scanned += 1
        if path.stat().st_size > textscan.MAX_BYTES:
            result.findings.append(Finding("file-too-large", relative, 1, "UNKNOWN",
                                           "the file is larger than the scan limit, so it was not read",
                                           ["a file within the size limit"]))
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            result.findings.append(Finding("unreadable-file", relative, 1, "UNKNOWN",
                                           "the rules file could not be read as UTF-8 text",
                                           ["a readable UTF-8 file"]))
            continue
        result.findings.extend(textscan.scan_text(text, relative, text_rules))
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

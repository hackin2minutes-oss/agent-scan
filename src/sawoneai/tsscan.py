"""TypeScript and JavaScript analyser (milestone 2, first slice).

Uses tree-sitter with the MIT-licensed tree-sitter-typescript grammars. The first check: a value that is not a literal
reaches a known JavaScript sink. The same verdict rules as the Python check apply:

- NEEDS_REVIEW: a non-literal first argument reaches the sink. The origin of the value is not established, so no
  confirmed path is claimed.
- UNKNOWN: the file did not parse, or the analyser is not installed. The missing piece is named.

Limits of this slice, which the report states:
- Only direct calls are recognised: child_process.exec, child_process.execSync, eval, and new Function. An alias
  (for example, const cp = require("child_process")) is not followed.
- The sink list is in this module, not in the signed knowledge base. Moving it there changes the signed pack and needs
  a new release.
"""

from pathlib import Path

from sawoneai.scanner import Finding, NEEDS_REVIEW, UNKNOWN

RULE = "ts-non-literal-sink"

SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
TSX_SUFFIXES = {".tsx", ".jsx"}

CALL_SINKS = {"child_process.exec", "child_process.execSync", "eval"}
CONSTRUCTOR_SINKS = {"Function"}

_parsers: dict = {}


def available() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_typescript  # noqa: F401
    except ImportError:
        return False
    return True


def _parser(dialect: str):
    if dialect not in _parsers:
        from tree_sitter import Language, Parser
        import tree_sitter_typescript as grammars
        language = grammars.language_tsx() if dialect == "tsx" else grammars.language_typescript()
        _parsers[dialect] = Parser(Language(language))
    return _parsers[dialect]


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _is_literal(node) -> bool:
    if node.type == "string":
        return True
    if node.type == "template_string":
        return not any(child.type == "template_substitution" for child in node.children)
    return False


def _first_argument_is_non_literal(arguments) -> bool:
    if arguments is None:
        return False
    named = [child for child in arguments.named_children if child.type != "comment"]
    if not named:
        return False
    return not _is_literal(named[0])


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def scan_source(source: str, rel_path: str, dialect: str = "typescript") -> list[Finding]:
    """Findings for one TypeScript or JavaScript source text."""
    if not available():
        return [Finding("typescript-analyser-unavailable", rel_path, 1, UNKNOWN,
                        "the TypeScript analyser is not installed, so this file was not analysed",
                        ["tree-sitter and tree-sitter-typescript installed"])]
    tree = _parser(dialect).parse(source.encode("utf-8"))
    if tree.root_node.has_error:
        return [Finding("parse-error", rel_path, 1, UNKNOWN,
                        "the file could not be parsed as TypeScript or JavaScript",
                        ["a file that parses as TypeScript or JavaScript"])]
    findings = []
    for node in _walk(tree.root_node):
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if callee is None or _text(callee) not in CALL_SINKS:
                continue
            name = _text(callee)
        elif node.type == "new_expression":
            callee = node.child_by_field_name("constructor")
            if callee is None or _text(callee) not in CONSTRUCTOR_SINKS:
                continue
            name = f"new {_text(callee)}"
        else:
            continue
        if _first_argument_is_non_literal(node.child_by_field_name("arguments")):
            findings.append(Finding(
                RULE, rel_path, node.start_point[0] + 1, NEEDS_REVIEW,
                f"a value that is not a literal reaches {name}, so its origin is not established",
                ["the origin of the value passed to " + name],
                [f"{rel_path}:{node.start_point[0] + 1} {name}(...)"]))
    return findings


def scan_file(path: Path, rel_path: str) -> list[Finding]:
    dialect = "tsx" if path.suffix in TSX_SUFFIXES else "typescript"
    source = path.read_text(encoding="utf-8")
    return scan_source(source, rel_path, dialect)

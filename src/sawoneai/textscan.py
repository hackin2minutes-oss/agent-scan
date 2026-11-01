"""Instruction and rules files: CLAUDE.md, AGENTS.md, Cursor rules, and similar files that agents read with trust.

Patterns come from the knowledge base (kind "text_rule"). Each match is a NEEDS_REVIEW finding. A credential value is
never printed: the report shows only its first two and last two characters.
"""

import re
from pathlib import Path

from sawoneai.scanner import NEEDS_REVIEW, Finding

RULE_FILE_NAMES = {"CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", "copilot-instructions.md",
                   ".github/copilot-instructions.md"}
RULE_DIRECTORIES = {".cursor/rules"}
RULE_SUFFIXES = {".mdc"}
MAX_BYTES = 1_000_000


def is_rule_file(relative: str) -> bool:
    name = relative.rsplit("/", 1)[-1]
    if relative in RULE_FILE_NAMES or name in RULE_FILE_NAMES:
        return True
    if any(relative.startswith(directory + "/") for directory in RULE_DIRECTORIES):
        return Path(name).suffix in RULE_SUFFIXES
    return False


def redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return f"{value[:2]}…{value[-2:]}"


def text_rules(entries: list[dict]) -> list[tuple[str, re.Pattern, str]]:
    rules = []
    for entry in entries:
        if entry.get("kind") == "text_rule":
            rules.append((entry["rule"], re.compile(entry["pattern"]), entry["message"]))
    return rules


def scan_text(text: str, relative: str, rules: list) -> list[Finding]:
    findings = []
    for rule, pattern, message in rules:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            shown = match.group(0)
            if rule == "credential-in-rules":
                shown = redact(shown)
            elif rule == "hidden-text-in-rules":
                shown = f"U+{ord(match.group(0)):04X}"
            elif len(shown) > 80:
                shown = shown[:77] + "..."
            findings.append(Finding(
                rule=rule,
                path=relative,
                line=line,
                verdict=NEEDS_REVIEW,
                reason=f"{message}: {shown}",
                missing=["whether the file's author intended this text", "whether the agent loads this file in every run"],
            ))
    return findings


def rule_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if any(part in {".git", ".venv", "node_modules"} for part in path.relative_to(root).parts[:-1]):
            continue
        if is_rule_file(relative):
            yield path, relative

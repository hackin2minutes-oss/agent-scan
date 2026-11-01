"""Model Context Protocol (MCP) configuration and tool descriptions.

Two kinds of check, both reported as NEEDS_REVIEW:

1. Configuration files (.mcp.json, mcp.json, .cursor/mcp.json, claude_desktop_config.json): remote servers over plain
   HTTP, servers launched through a shell, servers launched from unpinned packages, and credentials written as literal
   values in the environment. The rules that name commands come from the knowledge base.

2. Tool descriptions: the scanner never runs a server. The user saves the output of tools/list. Each tool's description
   and input schema are hashed. A tool that is new, or whose hash differs from the approved record, is reported, and
   the description text is checked with the instruction-file rules (hidden text, tool-poisoning phrases).
"""

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from agent_scan import textscan
from agent_scan.scanner import NEEDS_REVIEW, Finding

CONFIG_NAMES = {".mcp.json", "mcp.json", ".cursor/mcp.json", "claude_desktop_config.json"}
CREDENTIAL_KEY = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|credential|auth)")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
PINNED = re.compile(r"@\d+\.\d+|==|@\d|:latest$")


def is_mcp_config(relative: str) -> bool:
    return relative in CONFIG_NAMES or relative.rsplit("/", 1)[-1] in CONFIG_NAMES


def _servers(document) -> dict:
    if not isinstance(document, dict):
        return {}
    servers = document.get("mcpServers")
    return servers if isinstance(servers, dict) else {}


def _finding(rule, relative, reason, missing):
    return Finding(rule=rule, path=relative, line=1, verdict=NEEDS_REVIEW, reason=reason, missing=missing)


def check_config(text: str, relative: str, rules: dict) -> list[Finding]:
    """Findings for one MCP configuration file. rules maps a rule id to the commands it names."""
    try:
        document = json.loads(text)
    except ValueError:
        return [Finding("unreadable-file", relative, 1, "UNKNOWN", "the MCP configuration is not valid JSON",
                        ["a valid JSON configuration"])]
    findings = []
    for name, server in _servers(document).items():
        if not isinstance(server, dict):
            continue
        url = server.get("url")
        if isinstance(url, str):
            parsed = urlparse(url)
            if parsed.scheme == "http" and parsed.hostname not in LOCAL_HOSTS:
                findings.append(_finding("remote-mcp-over-plain-http", relative,
                                         f"server {name} connects to {parsed.hostname} over plain HTTP",
                                         ["whether the traffic is protected by another layer"]))
        command = server.get("command")
        args = [str(a) for a in server.get("args", []) if isinstance(a, (str, int))]
        if isinstance(command, str):
            base = command.rsplit("/", 1)[-1].lower()
            if base in rules.get("shell-capable-mcp-server", []):
                findings.append(_finding("shell-capable-mcp-server", relative,
                                         f"server {name} is launched through a shell ({base}), so any command the "
                                         "model asks it to run can run",
                                         ["whether the server limits the commands it runs"]))
            if base in rules.get("unpinned-mcp-package", []):
                package = next((a for a in args if not a.startswith("-")), "")
                if package and not PINNED.search(package):
                    findings.append(_finding("unpinned-mcp-package", relative,
                                             f"server {name} runs {package} without a version pin",
                                             ["the version the server will run, and whether it has changed"]))
        env = server.get("env", {})
        if isinstance(env, dict):
            for key, value in env.items():
                if isinstance(value, str) and CREDENTIAL_KEY.search(key) and not value.startswith("${"):
                    findings.append(_finding("credential-in-mcp-config", relative,
                                             f"server {name} sets {key} to a literal value "
                                             f"({textscan.redact(value)})",
                                             ["whether the value is a real credential"]))
    return findings


def tool_hash(tool: dict) -> str:
    """SHA-256 over the description and the input schema, in canonical form."""
    material = json.dumps({"description": tool.get("description", ""),
                           "inputSchema": tool.get("inputSchema", {})}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def tools_from(document) -> list[dict]:
    tools = document.get("tools") if isinstance(document, dict) else None
    if not isinstance(tools, list):
        raise ValueError("the tool list has no tools array")
    return [tool for tool in tools if isinstance(tool, dict) and isinstance(tool.get("name"), str)]


def check_tools(tools: list[dict], approved: dict[str, str], text_rules: list, server: str = "server") -> list[Finding]:
    """Findings for tools that are new or changed since approval, and for hidden instructions in their descriptions."""
    findings = []
    for tool in tools:
        name = tool["name"]
        description = tool.get("description", "") if isinstance(tool.get("description"), str) else ""
        digest = tool_hash(tool)
        if name not in approved:
            findings.append(_finding("unapproved-mcp-tool", f"{server}/{name}",
                                     f"tool {name} is not in the approved list",
                                     ["a review of the tool's description and schema"]))
        elif approved[name] != digest:
            findings.append(_finding("changed-mcp-tool", f"{server}/{name}",
                                     f"tool {name} changed since approval: its description or schema differs",
                                     ["the reason for the change, and a new approval"]))
        for finding in textscan.scan_text(description, f"{server}/{name}", text_rules):
            findings.append(finding)
    return findings

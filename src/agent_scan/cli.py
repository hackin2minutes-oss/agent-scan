"""Command line: agent-scan scan PATH | kb status | kb verify | version."""

import argparse
import json
import sys
from pathlib import Path

from agent_scan import __version__, kb, sarif, scanner

EXIT_OK = 0
EXIT_CONFIRMED = 1
EXIT_ERROR = 2


def _print_summary(result: scanner.ScanResult, pack_version: str) -> None:
    counts = result.counts()
    print(f"Agent Scan {__version__} · knowledge base {pack_version} · files scanned: {result.files_scanned}")
    print(f"Findings: {counts[scanner.NEEDS_REVIEW]} needs review, {counts[scanner.UNKNOWN]} unknown, "
          "0 confirmed")
    print("Confirmed paths need a traced source; this version does not trace sources yet.")
    for finding in result.findings:
        print(f"  [{finding.verdict}] {finding.path}:{finding.line} {finding.rule}")
        print(f"      {finding.reason}")
        for item in finding.missing:
            print(f"      missing: {item}")


def _emit(args, text: str) -> None:
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def _cmd_scan(args) -> int:
    check = kb.verify()
    if not check.ok:
        print("knowledge base failed verification; refusing to scan:", file=sys.stderr)
        for problem in check.problems:
            print(f"  {problem}", file=sys.stderr)
        return EXIT_ERROR
    if not Path(args.path).is_dir():
        print(f"scan could not complete: {args.path} is not a directory", file=sys.stderr)
        return EXIT_ERROR
    try:
        mcp_tools = _load_json(args.mcp_tools) if args.mcp_tools else None
        mcp_approved = _load_json(args.mcp_approved) if args.mcp_approved else None
        result = scanner.scan_path(args.path, mcp_tools=mcp_tools, mcp_approved=mcp_approved)
    except (OSError, ValueError) as exc:
        print(f"scan could not complete: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.format == "sarif":
        _emit(args, json.dumps(sarif.to_sarif(result, check.version), indent=2))
    elif args.format == "json" or args.json:
        _emit(args, json.dumps({"agent_scan": __version__, "knowledge_base": check.version,
                          "root": result.root, "files_scanned": result.files_scanned,
                          "counts": result.counts(),
                          "findings": [finding.to_dict() for finding in result.findings]}, indent=2))
    else:
        _print_summary(result, check.version)
    return EXIT_CONFIRMED if result.counts().get("CONFIRMED", 0) else EXIT_OK


def _cmd_kb_status(_args) -> int:
    check = kb.verify()
    print(f"knowledge base {check.version}: {'verified' if check.ok else 'NOT verified'}; "
          f"signed: {'yes' if check.signed else 'no (integrity only)'}; "
          f"entries: {len(kb.entries())}")
    for problem in check.problems:
        print(f"  {problem}")
    return EXIT_OK if check.ok else EXIT_ERROR


def _cmd_kb_verify(_args) -> int:
    check = kb.verify()
    print("verified" if check.ok else "failed")
    for problem in check.problems:
        print(f"  {problem}")
    return EXIT_OK if check.ok else EXIT_ERROR


def _load_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _cmd_mcp_hash(args) -> int:
    from agent_scan import mcp
    try:
        tools = mcp.tools_from(_load_json(args.file))
    except (OSError, ValueError) as exc:
        print(f"could not read the tool list: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(json.dumps({"server": args.server, "tools": {t["name"]: mcp.tool_hash(t) for t in tools}}, indent=2))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-scan", description="Security scanner for AI and agent code.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a directory of Python code")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text",
                      help="output format: text (default), json, or sarif 2.1.0")
    scan.add_argument("--json", action="store_true", help="same as --format json")
    scan.add_argument("--output", help="write the result to this file instead of standard output")
    scan.add_argument("--mcp-tools", help="saved tools/list output of an MCP server, to check its tool descriptions")
    scan.add_argument("--mcp-approved", help="approved hashes for those tools, as written by 'mcp hash'")
    scan.set_defaults(handler=_cmd_scan)
    kb_parser = commands.add_parser("kb", help="knowledge base commands")
    kb_commands = kb_parser.add_subparsers(dest="kb_command", required=True)
    kb_commands.add_parser("status", help="show the knowledge base version and integrity").set_defaults(
        handler=_cmd_kb_status)
    kb_commands.add_parser("verify", help="verify the knowledge base files against the manifest").set_defaults(
        handler=_cmd_kb_verify)
    mcp_parser = commands.add_parser("mcp", help="MCP tool-description commands")
    mcp_commands = mcp_parser.add_subparsers(dest="mcp_command", required=True)
    mcp_hash = mcp_commands.add_parser("hash", help="hash each tool of a saved tools/list output, for approval")
    mcp_hash.add_argument("file")
    mcp_hash.add_argument("--server", default="mcp-server")
    mcp_hash.set_defaults(handler=_cmd_mcp_hash)
    commands.add_parser("version", help="print the version").set_defaults(
        handler=lambda _args: print(__version__) or EXIT_OK)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)

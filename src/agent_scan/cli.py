"""Command line: agent-scan scan PATH | kb status | kb verify | version."""

import argparse
import json
import sys
from pathlib import Path

from agent_scan import __version__, kb, scanner

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
        result = scanner.scan_path(args.path)
    except OSError as exc:
        print(f"scan could not complete: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.json:
        print(json.dumps({"agent_scan": __version__, "knowledge_base": check.version,
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-scan", description="Security scanner for AI and agent code.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a directory of Python code")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--json", action="store_true", help="print the full result as JSON")
    scan.set_defaults(handler=_cmd_scan)
    kb_parser = commands.add_parser("kb", help="knowledge base commands")
    kb_commands = kb_parser.add_subparsers(dest="kb_command", required=True)
    kb_commands.add_parser("status", help="show the knowledge base version and integrity").set_defaults(
        handler=_cmd_kb_status)
    kb_commands.add_parser("verify", help="verify the knowledge base files against the manifest").set_defaults(
        handler=_cmd_kb_verify)
    commands.add_parser("version", help="print the version").set_defaults(
        handler=lambda _args: print(__version__) or EXIT_OK)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)

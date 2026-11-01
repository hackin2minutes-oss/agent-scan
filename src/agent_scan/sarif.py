"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers.

Verdicts map to SARIF levels so that a reviewer sees the same thing in both places:
- NEEDS_REVIEW -> "warning"
- UNKNOWN -> "note"

Every result carries the verdict, the trace (if any) and what is missing, in its properties, so nothing that is
stated in the terminal output is lost in SARIF.
"""

from agent_scan import __version__
from agent_scan.scanner import NEEDS_REVIEW, ScanResult

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {NEEDS_REVIEW: "warning", "UNKNOWN": "note", "CONFIRMED": "error"}


def _result(finding) -> dict:
    level = LEVELS.get(finding.verdict, "note")
    return {
        "ruleId": finding.rule,
        "level": level,
        "message": {"text": finding.reason},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.path},
                "region": {"startLine": max(1, finding.line)},
            }
        }],
        "properties": {
            "verdict": finding.verdict,
            "trace": list(finding.trace),
            "missing": list(finding.missing),
        },
    }


def to_sarif(result: ScanResult, knowledge_base_version: str) -> dict:
    rule_ids = sorted({finding.rule for finding in result.findings})
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "agent-scan",
                "version": __version__,
                "informationUri": "https://github.com/hackin2minutes-oss/agent-scan",
                "rules": [{"id": rule_id, "shortDescription": {"text": rule_id}} for rule_id in rule_ids],
            }},
            "invocations": [{"executionSuccessful": True}],
            "properties": {"knowledgeBaseVersion": knowledge_base_version,
                           "filesScanned": result.files_scanned},
            "results": [_result(finding) for finding in result.findings],
        }],
    }

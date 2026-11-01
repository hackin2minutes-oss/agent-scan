"""Compare the scanner with Semgrep (community Python rules) and Bandit on the labelled Python cases in tests/corpus.

Scope: only Python files are compared, because the baseline tools read Python. JSON and rules files are reported as not
applicable to them. Matching is by file and line: a labelled line counts as found if the tool reports anything on it.

Caveats, stated with the results:
- The labels were written for this scanner's rules, so they favour it. A baseline tool is not penalised for a rule it
  was never meant to have.
- Semgrep runs the public "p/python" ruleset, which needs the registry. Bandit runs with its default checks.
- Line-level matching is coarse: a tool that reports a different rule on the same line counts as a hit.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate_corpus  # noqa: E402
from agent_scan.scanner import scan_path  # noqa: E402

CORPUS = ROOT / "tests" / "corpus"
RESULTS = ROOT / "results" / "baseline-comparison.json"
# Tool locations can be set with environment variables. Defaults are the names on PATH.
SEMGREP = os.environ.get("SEMGREP_BIN", "semgrep")
BANDIT = os.environ.get("BANDIT_BIN", "bandit")


def python_labels() -> dict[str, set[tuple[str, int]]]:
    by_case = {}
    for case in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
        by_case[case.name] = {(f, n) for f, n, _ in evaluate_corpus.labels_for(case) if f.endswith(".py")}
    return by_case


class Blocked(Exception):
    pass


def _run(command: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=600)
    except FileNotFoundError as exc:
        raise Blocked(f"{command[0]} is not installed or not on PATH") from exc


def run_semgrep(case: Path) -> set[tuple[str, int]]:
    completed = _run([SEMGREP, "scan", "--config", "p/python", "--metrics=off", "--json", "-q", str(case)])
    if not completed.stdout:
        raise Blocked("semgrep produced no output")
    document = json.loads(completed.stdout)
    if not document.get("rules"):
        # Without rules the tool reports nothing. That is not a result, so the baseline is recorded as blocked.
        raise Blocked("the p/python ruleset loaded zero rules, so semgrep could not run its checks")
    out = set()
    for item in document.get("results", []):
        out.add((Path(item["path"]).relative_to(case).as_posix(), item["start"]["line"]))
    return out


def run_bandit(case: Path) -> set[tuple[str, int]]:
    completed = _run([BANDIT, "-q", "-f", "json", "-r", str(case)])
    out = set()
    if completed.stdout:
        for item in json.loads(completed.stdout).get("results", []):
            out.add((Path(item["filename"]).relative_to(case).as_posix(), item["line_number"]))
    return out


def run_scanner(case: Path) -> set[tuple[str, int]]:
    return {(f.path, f.line) for f in scan_path(case).findings if f.verdict == "NEEDS_REVIEW" and f.path.endswith(".py")}


def compare() -> dict:
    labels = python_labels()
    tools = {"agent-scan": run_scanner, "semgrep-p-python": run_semgrep, "bandit": run_bandit}
    results = {}
    for name, runner in tools.items():
        hits = misses = unlabelled = 0
        negative_cases_flagged = 0
        try:
            for case in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
                expected = labels[case.name]
                reported = runner(case)
                for item in expected:
                    if item in reported:
                        hits += 1
                    else:
                        misses += 1
                unlabelled += len(reported - expected)
                if not expected and reported:
                    negative_cases_flagged += 1
        except Blocked as exc:
            results[name] = {"status": "BLOCKED_WITH_EXACT_REASON", "reason": str(exc)}
            continue
        results[name] = {"status": "RAN", "labelled_lines_found": hits, "labelled_lines_missed": misses,
                         "findings_on_unlabelled_lines": unlabelled,
                         "negative_cases_with_findings": negative_cases_flagged}
    total = sum(len(v) for v in labels.values())
    return {
        "labelled_python_lines": total,
        "labelling": "author-labelled for agent-scan's rules; favours agent-scan (see scripts/compare_baselines.py)",
        "tools": results,
    }


if __name__ == "__main__":
    result = compare()
    RESULTS.parent.mkdir(exist_ok=True)
    RESULTS.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"labelled Python lines: {result['labelled_python_lines']}")
    for name, r in result["tools"].items():
        if r["status"] != "RAN":
            print(f"  {name:18s} BLOCKED: {r['reason']}")
            continue
        print(f"  {name:18s} found={r['labelled_lines_found']} missed={r['labelled_lines_missed']} "
              f"unlabelled={r['findings_on_unlabelled_lines']} negatives_flagged={r['negative_cases_with_findings']}")

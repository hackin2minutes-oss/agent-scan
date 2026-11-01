"""Evaluate the scanner on the labelled corpus in tests/corpus.

Labels are written in the corpus files as `# expect: <rule>` (or `<!-- expect -->`-free plain text for rule files).
A label on a line says the scanner should report that rule on that line. The evaluator compares labels with the
scanner's findings, per rule, and writes the counts to results/corpus-results.json.

What this measures: agreement between the labels and the implementation. The labels were written by the author of the
rules, not by an independent reviewer, so these numbers are not an estimate of accuracy on other code.
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sawoneai.scanner import scan_path  # noqa: E402

CORPUS = ROOT / "tests" / "corpus"
RESULTS = ROOT / "results" / "corpus-results.json"
LABEL = re.compile(r"expect:\s*([a-z0-9-]+)")


def labels_for(case: Path) -> set[tuple[str, int, str]]:
    found = set()
    sidecar = case / "expect.json"
    if sidecar.is_file():
        for item in json.loads(sidecar.read_text(encoding="utf-8"))["labels"]:
            found.add((item["file"], item["line"], item["rule"]))
    for path in sorted(case.rglob("*")):
        if not path.is_file() or path.name == "expect.json":
            continue
        relative = path.relative_to(case).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for match in LABEL.finditer(line):
                found.add((relative, number, match.group(1)))
    return found


def reported_for(case: Path) -> set[tuple[str, int, str]]:
    return {(f.path, f.line, f.rule) for f in scan_path(case).findings if f.verdict == "NEEDS_REVIEW"}


def evaluate() -> dict:
    per_rule = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    cases = []
    for case in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
        expected, reported = labels_for(case), reported_for(case)
        for item in expected & reported:
            per_rule[item[2]]["tp"] += 1
        for item in reported - expected:
            per_rule[item[2]]["fp"] += 1
        for item in expected - reported:
            per_rule[item[2]]["fn"] += 1
        cases.append({"case": case.name, "expected": len(expected), "reported": len(reported),
                      "agree": expected == reported})
    rules = {}
    for rule, c in sorted(per_rule.items()):
        precision = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else None
        recall = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else None
        rules[rule] = {**c, "precision": precision, "recall": recall}
    totals = {k: sum(v[k] for v in per_rule.values()) for k in ("tp", "fp", "fn")}
    return {
        "labelling": "author-labelled; no independent second labeller; inter-rater agreement not measured",
        "cases": len(cases),
        "cases_agreeing": sum(1 for c in cases if c["agree"]),
        "totals": totals,
        "per_rule": rules,
        "case_results": cases,
    }


if __name__ == "__main__":
    result = evaluate()
    RESULTS.parent.mkdir(exist_ok=True)
    RESULTS.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"cases: {result['cases']}, agreeing: {result['cases_agreeing']}, totals: {result['totals']}")
    for rule, c in result["per_rule"].items():
        print(f"  {rule:40s} tp={c['tp']} fp={c['fp']} fn={c['fn']} precision={c['precision']} recall={c['recall']}")

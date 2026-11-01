"""Labelling kit for an independent second labeller, and the agreement calculation.

  python3 scripts/labelling_kit.py blind OUTDIR   writes blinded copies of the corpus and an items.csv sheet
  python3 scripts/labelling_kit.py agree SHEET.csv compares the returned sheet with the author's labels (Cohen's kappa)

Each item is one line of one file in one corpus case. The labeller writes the rule that applies to that line, or
"none". Author labels are removed from the blinded copies (the "# expect" markers and expect.json files).
"""

import csv
import json
import re
import shutil
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate_corpus  # noqa: E402

CORPUS = ROOT / "tests" / "corpus"
MARKER = re.compile(r"\s*#\s*expect:.*$")
FIELDS = ["case", "file", "line", "rule"]


def items() -> list[tuple[str, str, int]]:
    found = []
    for case in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
        for path in sorted(case.rglob("*")):
            if not path.is_file() or path.name == "expect.json":
                continue
            relative = path.relative_to(case).as_posix()
            for number, _ in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                found.append((case.name, relative, number))
    return found


def blind(out: Path) -> dict:
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(CORPUS, out)
    for path in out.rglob("*"):
        if path.is_file() and path.name == "expect.json":
            path.unlink()
        elif path.is_file():
            text = path.read_text(encoding="utf-8")
            if "expect:" in text:
                cleaned = "\n".join(MARKER.sub("", line) for line in text.splitlines())
                path.write_text(cleaned + "\n", encoding="utf-8")
    sheet = out.parent / "items.csv"
    with sheet.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(FIELDS)
        for case, relative, number in items():
            writer.writerow([case, relative, number, ""])
    return {"blinded_corpus": str(out), "sheet": str(sheet), "items": len(items())}


def author_rules() -> dict[tuple[str, str, int], str]:
    labels = {}
    for case in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
        for relative, number, rule in evaluate_corpus.labels_for(case):
            labels[(case.name, relative, number)] = rule
    return labels


def kappa(a: dict, b: dict, keys: list) -> float:
    n = len(keys)
    if n == 0:
        return float("nan")
    observed = sum(1 for k in keys if a[k] == b[k]) / n
    count_a, count_b = Counter(a[k] for k in keys), Counter(b[k] for k in keys)
    expected = sum((count_a[c] / n) * (count_b[c] / n) for c in set(count_a) | set(count_b))
    if expected == 1:
        return 1.0
    return (observed - expected) / (1 - expected)


def agree(sheet: Path) -> dict:
    author = author_rules()
    keys = items()
    given = {}
    with sheet.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            key = (row["case"], row["file"], int(row["line"]))
            given[key] = (row["rule"] or "").strip() or "none"
    missing = [k for k in keys if k not in given]
    if missing:
        raise SystemExit(f"the sheet is missing {len(missing)} items; every item needs a rule or 'none'")
    a = {k: author.get(k, "none") for k in keys}
    b = {k: given[k] for k in keys}
    result = {"items": len(keys), "cohen_kappa": round(kappa(a, b, keys), 4),
              "agreeing_items": sum(1 for k in keys if a[k] == b[k]),
              "rule_disagreements": sorted({f"{a[k]} vs {b[k]}" for k in keys if a[k] != b[k]})}
    out = ROOT / "results" / "labelling-agreement.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "blind":
        print(blind(Path(sys.argv[2])))
    elif len(sys.argv) == 3 and sys.argv[1] == "agree":
        print(agree(Path(sys.argv[2])))
    else:
        raise SystemExit(__doc__)

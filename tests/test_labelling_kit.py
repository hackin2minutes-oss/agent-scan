import csv
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import labelling_kit  # noqa: E402


class LabellingKitTest(unittest.TestCase):
    def test_the_blinded_corpus_has_no_author_labels(self):
        out = Path(tempfile.mkdtemp()) / "blind"
        labelling_kit.blind(out)
        for path in out.rglob("*"):
            if path.is_file():
                self.assertNotIn("expect:", path.read_text(encoding="utf-8"), path)
                self.assertNotEqual(path.name, "expect.json")

    def test_the_sheet_lists_every_line_once(self):
        out = Path(tempfile.mkdtemp()) / "blind"
        result = labelling_kit.blind(out)
        with Path(result["sheet"]).open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), result["items"])
        self.assertEqual(len({(r["case"], r["file"], r["line"]) for r in rows}), len(rows))

    def test_an_independent_sheet_that_matches_the_author_has_kappa_one(self):
        out = Path(tempfile.mkdtemp()) / "blind"
        result = labelling_kit.blind(out)
        author = labelling_kit.author_rules()
        with Path(result["sheet"]).open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        with Path(result["sheet"]).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(labelling_kit.FIELDS)
            for row in rows:
                key = (row["case"], row["file"], int(row["line"]))
                writer.writerow([row["case"], row["file"], row["line"], author.get(key, "")])
        self.assertEqual(labelling_kit.agree(Path(result["sheet"]))["cohen_kappa"], 1.0)

    def test_an_incomplete_sheet_is_refused(self):
        out = Path(tempfile.mkdtemp()) / "blind"
        result = labelling_kit.blind(out)
        with Path(result["sheet"]).open("w", newline="", encoding="utf-8") as handle:
            csv.writer(handle).writerow(labelling_kit.FIELDS)
        with self.assertRaises(SystemExit):
            labelling_kit.agree(Path(result["sheet"]))

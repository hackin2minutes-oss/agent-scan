"""Regression gate for the labelled corpus in tests/corpus.

This test checks that the scanner still agrees with the labels. It does not measure accuracy on other code: the labels
were written by the author of the rules, and some were corrected after a first run (see scripts/evaluate_corpus.py).
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate_corpus  # noqa: E402


class CorpusRegressionTest(unittest.TestCase):
    def test_every_corpus_case_agrees_with_its_labels(self):
        result = evaluate_corpus.evaluate()
        disagreeing = [c["case"] for c in result["case_results"] if not c["agree"]]
        self.assertEqual(disagreeing, [])

    def test_there_are_no_false_positives_or_misses_against_the_labels(self):
        totals = evaluate_corpus.evaluate()["totals"]
        self.assertEqual((totals["fp"], totals["fn"]), (0, 0))

    def test_the_corpus_has_positive_and_negative_cases(self):
        names = [p.name for p in evaluate_corpus.CORPUS.iterdir() if p.is_dir()]
        self.assertGreaterEqual(sum("negative" in n for n in names), 5)
        self.assertGreaterEqual(sum("positive" in n for n in names), 10)

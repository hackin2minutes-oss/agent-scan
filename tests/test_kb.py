import json
import shutil
import tempfile
import unittest
from pathlib import Path

from agent_scan import kb

PACK = kb.PACK_DIR


class KnowledgeBaseIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.pack = self.tmp / "kb"
        shutil.copytree(PACK, self.pack)

    def test_the_shipped_pack_verifies(self):
        result = kb.verify(self.pack)
        self.assertTrue(result.ok, result.problems)
        self.assertEqual(result.version, "0.0.1")
        self.assertFalse(result.signed)

    def test_a_changed_file_fails_verification(self):
        (self.pack / "entries.json").write_text("{}", encoding="utf-8")
        result = kb.verify(self.pack)
        self.assertFalse(result.ok)
        self.assertTrue(any("hash does not match" in p for p in result.problems))

    def test_a_missing_listed_file_fails_verification(self):
        (self.pack / "entries.json").unlink()
        result = kb.verify(self.pack)
        self.assertFalse(result.ok)
        self.assertTrue(any("missing" in p for p in result.problems))

    def test_an_unlisted_file_fails_verification(self):
        (self.pack / "extra.json").write_text("{}", encoding="utf-8")
        result = kb.verify(self.pack)
        self.assertFalse(result.ok)
        self.assertTrue(any("not listed" in p for p in result.problems))

    def test_an_unreadable_manifest_fails_verification(self):
        (self.pack / "manifest.json").write_text("not json", encoding="utf-8")
        self.assertFalse(kb.verify(self.pack).ok)


class EntryTestLinkTest(unittest.TestCase):
    """Every entry must name a test, and that test must exist. This is the first gate of the coverage rules."""

    def test_every_entry_names_a_reference_and_an_existing_test(self):
        root = Path(__file__).resolve().parent.parent
        for entry in kb.entries():
            self.assertTrue(entry["reference"].startswith("https://"), entry["id"])
            path, _, name = entry["test"].partition("::")
            source = (root / path).read_text(encoding="utf-8")
            self.assertIn(f"def {name}(", source, entry["id"])

    def test_the_entries_file_is_valid_json_with_the_expected_format(self):
        data = json.loads((PACK / "entries.json").read_text(encoding="utf-8"))
        self.assertEqual(data["format"], "agent-scan-kb-entries/1")

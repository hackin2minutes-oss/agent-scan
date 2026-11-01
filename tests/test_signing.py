import json
import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_scan import kb


def signed_copy(private_key, trust_key=None):
    pack = Path(tempfile.mkdtemp()) / "kb"
    shutil.copytree(kb.PACK_DIR, pack)
    manifest = kb.load_manifest(pack)
    (pack / kb.MANIFEST_NAME).write_text(json.dumps(kb.sign_manifest(manifest, private_key), indent=2),
                                         encoding="utf-8")
    trust = pack.parent / "trust"
    trust.mkdir(exist_ok=True)
    key_to_trust = (trust_key or private_key).public_key()
    (trust / "release.pem").write_bytes(key_to_trust.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return pack, trust


class SignedPackTest(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()

    def test_a_pack_signed_by_a_trusted_key_verifies(self):
        pack, trust = signed_copy(self.key)
        result = kb.verify(pack, trust_dir=trust)
        self.assertTrue(result.ok, result.problems)
        self.assertTrue(result.signed)

    def test_a_pack_signed_by_an_untrusted_key_is_refused(self):
        other = Ed25519PrivateKey.generate()
        pack, trust = signed_copy(self.key, trust_key=other)
        result = kb.verify(pack, trust_dir=trust)
        self.assertFalse(result.ok)
        self.assertTrue(any("does not verify" in p for p in result.problems))

    def test_a_signed_pack_with_no_trusted_key_is_refused(self):
        pack, trust = signed_copy(self.key)
        (trust / "release.pem").unlink()
        result = kb.verify(pack, trust_dir=trust)
        self.assertFalse(result.ok)
        self.assertTrue(any("no trusted public key" in p for p in result.problems))

    def test_a_tampered_manifest_fails_the_signature(self):
        pack, trust = signed_copy(self.key)
        data = json.loads((pack / kb.MANIFEST_NAME).read_text(encoding="utf-8"))
        data["version"] = "9.9.9"
        (pack / kb.MANIFEST_NAME).write_text(json.dumps(data), encoding="utf-8")
        result = kb.verify(pack, trust_dir=trust)
        self.assertFalse(result.ok)
        self.assertTrue(any("does not verify" in p for p in result.problems))

    def test_a_changed_file_fails_even_when_the_signature_is_valid(self):
        pack, trust = signed_copy(self.key)
        (pack / "entries.json").write_text("{}", encoding="utf-8")
        result = kb.verify(pack, trust_dir=trust)
        self.assertFalse(result.ok)

    def test_an_unsigned_pack_verifies_for_integrity_only(self):
        result = kb.verify(kb.PACK_DIR)
        self.assertTrue(result.ok)
        self.assertFalse(result.signed)

    def test_a_malformed_signature_is_refused(self):
        pack, trust = signed_copy(self.key)
        data = json.loads((pack / kb.MANIFEST_NAME).read_text(encoding="utf-8"))
        data["signature"] = {"algorithm": "rsa", "value": "x"}
        (pack / kb.MANIFEST_NAME).write_text(json.dumps(data), encoding="utf-8")
        result = kb.verify(pack, trust_dir=trust)
        self.assertFalse(result.ok)
        self.assertTrue(any("unsupported" in p for p in result.problems))

    def test_signing_does_not_change_the_signed_content(self):
        manifest = kb.load_manifest(kb.PACK_DIR)
        signed = kb.sign_manifest(manifest, self.key)
        self.assertEqual(kb.canonical_manifest(signed), kb.canonical_manifest(manifest))

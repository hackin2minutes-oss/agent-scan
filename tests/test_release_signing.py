import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import sign_release  # noqa: E402
from sawoneai import kb  # noqa: E402


class ReleaseSigningTest(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.outside = Path(tempfile.mkdtemp())
        self.key_path = self.outside / "release.pem"
        self.key_path.write_bytes(self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.pack = Path(tempfile.mkdtemp()) / "kb"
        shutil.copytree(kb.PACK_DIR, self.pack)

    def test_a_key_outside_the_repository_signs_the_pack(self):
        signed = sign_release.sign(self.pack, self.key_path)
        self.assertEqual(signed["signature"]["algorithm"], "ed25519")
        self.assertIsNotNone(json_signature(self.pack))

    def test_a_key_inside_the_repository_is_refused(self):
        inside = ROOT / "tests" / "release-test-key.pem"
        inside.write_bytes(self.key_path.read_bytes())
        try:
            with self.assertRaises(SystemExit) as raised:
                sign_release.sign(self.pack, inside)
            self.assertIn("inside the repository", str(raised.exception))
        finally:
            inside.unlink()

    def test_a_non_ed25519_key_is_refused(self):
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
        ec_path = self.outside / "ec.pem"
        ec_path.write_bytes(generate_private_key(SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with self.assertRaises(SystemExit):
            sign_release.sign(self.pack, ec_path)


def json_signature(pack: Path):
    import json
    return json.loads((pack / kb.MANIFEST_NAME).read_text(encoding="utf-8")).get("signature")

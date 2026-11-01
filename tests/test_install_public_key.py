import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import install_public_key  # noqa: E402


class InstallPublicKeyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.trust = self.tmp / "trust"
        install_public_key.TRUST = self.trust
        self.key = Ed25519PrivateKey.generate()

    def write(self, name, data):
        path = self.tmp / name
        path.write_bytes(data)
        return path

    def test_a_public_key_is_installed(self):
        pub = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        target = install_public_key.install(self.write("pub.pem", pub), "release-2026")
        self.assertEqual(target.name, "release-2026.pem")
        self.assertTrue(target.is_file())

    def test_a_private_key_is_refused(self):
        private = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())
        with self.assertRaises(SystemExit) as raised:
            install_public_key.install(self.write("priv.pem", private), "x")
        self.assertIn("private key", str(raised.exception))
        self.assertFalse(self.trust.exists())

    def test_a_non_ed25519_public_key_is_refused(self):
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
        ec_pub = generate_private_key(SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(SystemExit):
            install_public_key.install(self.write("ec.pem", ec_pub), "x")

    def test_a_name_with_a_path_separator_is_refused(self):
        pub = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(SystemExit):
            install_public_key.install(self.write("pub.pem", pub), "../escape")

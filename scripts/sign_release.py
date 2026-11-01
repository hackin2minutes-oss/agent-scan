"""Sign a knowledge-base pack for release. Run by the maintainer, never in CI on untrusted input.

The private key must be a file outside this repository. The script refuses a key inside the repository, so a key cannot
be committed by accident. The public key that verifies the pack must be shipped in src/sawoneai/data/kb/trust/.

Usage: python3 scripts/sign_release.py PACK_DIR KEY_PEM
"""

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sawoneai import kb  # noqa: E402


def refuse_key_inside_repository(key_path: Path) -> None:
    if key_path.resolve().is_relative_to(ROOT):
        raise SystemExit("refused: the private key is inside the repository; keep it outside")


def sign(pack: Path, key_path: Path) -> dict:
    refuse_key_inside_repository(key_path)
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("refused: the key is not an Ed25519 private key")
    manifest = json.loads((pack / kb.MANIFEST_NAME).read_text(encoding="utf-8"))
    signed = kb.sign_manifest(manifest, key)
    (pack / kb.MANIFEST_NAME).write_text(json.dumps(signed, indent=2) + "\n", encoding="utf-8")
    return signed


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    signed = sign(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"signed pack version {signed['version']} with algorithm {signed['signature']['algorithm']}")

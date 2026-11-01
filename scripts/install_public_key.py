"""Install a release's PUBLIC key into the package's trusted-keys folder.

Only the public key is accepted. A private key is refused, so one cannot be committed by mistake.

Usage: python3 scripts/install_public_key.py PUBLIC_KEY_PEM NAME
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent
TRUST = ROOT / "src" / "sawoneai" / "data" / "kb" / "trust"


def install(source: Path, name: str) -> Path:
    data = source.read_bytes()
    if b"PRIVATE KEY" in data:
        raise SystemExit("refused: this is a private key; only the public key is installed")
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise SystemExit(f"refused: not a PEM public key ({exc})")
    if not isinstance(key, Ed25519PublicKey):
        raise SystemExit("refused: the public key is not Ed25519")
    if not name.replace("-", "").replace("_", "").isalnum():
        raise SystemExit("refused: the name may contain only letters, digits, - and _")
    TRUST.mkdir(parents=True, exist_ok=True)
    target = TRUST / f"{name}.pem"
    target.write_bytes(key.public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo))
    return target


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(f"installed {install(Path(sys.argv[1]), sys.argv[2])}")

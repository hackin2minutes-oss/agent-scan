"""Knowledge base: a versioned pack shipped inside the package, verified before use.

A pack is a manifest plus the files it lists. The manifest records the SHA-256 of every file. Verification fails if
any file is missing, changed, or not listed.

The manifest may also carry an Ed25519 signature made by the maintainer's key. A signature is checked against a public
key shipped in the package (data/kb/trust/). A signed pack that does not verify against a trusted key is refused. An
unsigned pack is accepted for integrity only, and the status output says so.
"""

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PACK_DIR = Path(__file__).parent / "data" / "kb"
TRUST_DIR = PACK_DIR / "trust"
MANIFEST_NAME = "manifest.json"
SIGNATURE_ALGORITHM = "ed25519"


@dataclass
class VerifyResult:
    ok: bool
    version: str
    problems: list[str] = field(default_factory=list)
    signed: bool = False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(pack_dir: Path = PACK_DIR) -> dict:
    return json.loads((pack_dir / MANIFEST_NAME).read_text(encoding="utf-8"))


def canonical_manifest(manifest: dict) -> bytes:
    """The bytes that are signed: the manifest without its signature, as canonical JSON."""
    body = {key: value for key, value in manifest.items() if key != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def trusted_public_keys(trust_dir: Path = TRUST_DIR) -> list[Ed25519PublicKey]:
    keys = []
    if trust_dir.is_dir():
        for path in sorted(trust_dir.glob("*.pem")):
            key = serialization.load_pem_public_key(path.read_bytes())
            if isinstance(key, Ed25519PublicKey):
                keys.append(key)
    return keys


def signature_problems(manifest: dict, keys: list[Ed25519PublicKey]) -> list[str]:
    signature = manifest.get("signature")
    if signature is None:
        return []
    if not isinstance(signature, dict) or signature.get("algorithm") != SIGNATURE_ALGORITHM:
        return ["manifest signature has an unsupported form"]
    if not keys:
        return ["manifest is signed, but no trusted public key is shipped with this package"]
    try:
        value = base64.b64decode(signature["value"], validate=True)
    except (KeyError, ValueError, TypeError):
        return ["manifest signature is not valid base64"]
    for key in keys:
        try:
            key.verify(value, canonical_manifest(manifest))
            return []
        except InvalidSignature:
            continue
    return ["manifest signature does not verify against any trusted key"]


def sign_manifest(manifest: dict, private_key: Ed25519PrivateKey) -> dict:
    """Return the manifest with a signature. The maintainers' release build calls this with the release key."""
    signed = dict(manifest)
    signed["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "value": base64.b64encode(private_key.sign(canonical_manifest(manifest))).decode("ascii"),
    }
    return signed


def verify(pack_dir: Path = PACK_DIR, trust_dir: Path | None = None) -> VerifyResult:
    try:
        manifest = load_manifest(pack_dir)
    except (OSError, ValueError) as exc:
        return VerifyResult(False, "unknown", [f"manifest could not be read: {type(exc).__name__}"])
    # Trusted keys come only from the installed package, never from the pack being checked.
    problems = list(signature_problems(manifest, trusted_public_keys(trust_dir or TRUST_DIR)))
    listed = manifest.get("files", {})
    for name, expected in sorted(listed.items()):
        path = pack_dir / name
        if not path.is_file():
            problems.append(f"{name}: listed in the manifest but missing")
        elif _sha256(path) != expected:
            problems.append(f"{name}: hash does not match the manifest")
    for path in sorted(pack_dir.iterdir()):
        if path.name != MANIFEST_NAME and path.is_file() and path.name not in listed:
            problems.append(f"{path.name}: present but not listed in the manifest")
    return VerifyResult(not problems, str(manifest.get("version", "unknown")), problems,
                        signed=manifest.get("signature") is not None)


_cache: dict = {}


def _stamp(directory: Path) -> tuple:
    """Changes when the manifest or the entries file changes, so cached results are not stale."""
    parts = []
    for name in (MANIFEST_NAME, "entries.json"):
        try:
            stat = (directory / name).stat()
            parts.append((stat.st_mtime_ns, stat.st_size))
        except OSError:
            parts.append(None)
    return tuple(parts)


def current_pack_dir() -> Path:
    """The pack in use: an activated update if it verifies, otherwise the pack shipped with the package.

    The verification result is cached per pack and is recomputed when the pack's files change, so a scan of many files
    verifies the pack once rather than once per file."""
    try:
        from agent_scan import update
        active = update.active_root() / "current"
    except Exception:
        return PACK_DIR
    if not active.is_dir():
        return PACK_DIR
    key = ("current", str(active), str(TRUST_DIR), _stamp(active))
    if key not in _cache:
        _cache[key] = verify(active).ok
    return active if _cache[key] else PACK_DIR


def entries(pack_dir: Path | None = None) -> list[dict]:
    directory = pack_dir or current_pack_dir()
    key = ("entries", str(directory), _stamp(directory))
    if key not in _cache:
        _cache[key] = json.loads((directory / "entries.json").read_text(encoding="utf-8"))["entries"]
    return _cache[key]


def write_manifest(pack_dir: Path = PACK_DIR, version: str = "0.0.1") -> dict:
    """Rebuild the manifest from the files in the pack. Used by the maintainers' build, not by scans."""
    files = {path.name: _sha256(path) for path in sorted(pack_dir.iterdir())
             if path.is_file() and path.name != MANIFEST_NAME}
    manifest = {"pack": "agent-scan-kb", "version": version, "files": files, "signature": None}
    (pack_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest

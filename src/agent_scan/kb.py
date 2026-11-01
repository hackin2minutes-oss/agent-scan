"""Knowledge base: a versioned pack shipped inside the package, verified by hash before use.

A pack is a manifest plus the files it lists. The manifest records the SHA-256 of every file. Verification fails if
any file is missing, changed, or not listed. Signing of the manifest is planned for a later milestone; until then,
verification checks integrity, not origin, and the status output says so.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

PACK_DIR = Path(__file__).parent / "data" / "kb"
MANIFEST_NAME = "manifest.json"


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


def verify(pack_dir: Path = PACK_DIR) -> VerifyResult:
    try:
        manifest = load_manifest(pack_dir)
    except (OSError, ValueError) as exc:
        return VerifyResult(False, "unknown", [f"manifest could not be read: {type(exc).__name__}"])
    problems = []
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
                        signed=bool(manifest.get("signature")))


def entries(pack_dir: Path = PACK_DIR) -> list[dict]:
    return json.loads((pack_dir / "entries.json").read_text(encoding="utf-8"))["entries"]


def write_manifest(pack_dir: Path = PACK_DIR, version: str = "0.0.1") -> dict:
    """Rebuild the manifest from the files in the pack. Used by the maintainers' build, not by scans."""
    files = {path.name: _sha256(path) for path in sorted(pack_dir.iterdir())
             if path.is_file() and path.name != MANIFEST_NAME}
    manifest = {"pack": "agent-scan-kb", "version": version, "files": files, "signature": None}
    (pack_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest

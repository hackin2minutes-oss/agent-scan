"""Knowledge-base updates from allowlisted sources only.

Nothing is fetched unless the configuration lists the source. A source is an https address, or a plain-http address on
localhost that is listed exactly (used for tests and for an internal mirror on the same machine).

An update is staged and fully verified before it is used:
1. The manifest and every listed file are downloaded into a staging folder, with a size limit on each.
2. The manifest must carry a signature that verifies against a trusted public key shipped in the package.
3. Every file must match its hash in the manifest.
4. The version must be newer than the one in use. Downgrades are refused unless the user asks for a rollback.

Only then is the staged pack moved into place. The previous active pack is kept, so `kb rollback` can restore it. A failed
update leaves the active pack untouched.
"""

import json
import os
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from sawoneai import kb

MAX_FILE_BYTES = 20_000_000
MAX_MANIFEST_BYTES = 1_000_000
TIMEOUT_SECONDS = 30
LOCAL_HOSTS = {"127.0.0.1", "localhost"}


def default_config_path() -> Path:
    return Path(os.environ.get("SAWONEAI_CONFIG", Path.home() / ".config" / "sawoneai" / "config.json"))


@dataclass
class UpdateConfig:
    sources: list[str] = field(default_factory=list)


class UpdateError(Exception):
    pass


def load_config(path: Path) -> UpdateConfig:
    if not path.is_file():
        return UpdateConfig()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise UpdateError(f"the update configuration is not valid JSON: {exc}") from exc
    sources = data.get("knowledge_base_sources", [])
    if not isinstance(sources, list) or not all(isinstance(s, str) for s in sources):
        raise UpdateError("knowledge_base_sources must be a list of addresses")
    return UpdateConfig(sources=sources)


def check_source(source: str, config: UpdateConfig) -> str:
    """The source, with a trailing slash, if it is allowed. Raises UpdateError otherwise."""
    if source not in config.sources:
        raise UpdateError(f"{source} is not in the allowlist")
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme == "https":
        pass
    elif parsed.scheme == "http" and parsed.hostname in LOCAL_HOSTS:
        pass
    else:
        raise UpdateError(f"{source} must use https (plain http is accepted only for localhost)")
    return source if source.endswith("/") else source + "/"


def _fetch(url: str, limit: int) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
            data = response.read(limit + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise UpdateError(f"could not fetch {url}: {type(exc).__name__}") from exc
    if len(data) > limit:
        raise UpdateError(f"{url} is larger than the {limit}-byte limit")
    return data


def parse_version(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError as exc:
        raise UpdateError(f"version {version!r} is not a dotted number") from exc


def active_root() -> Path:
    home = Path(os.environ.get("SAWONEAI_HOME", Path.home() / ".local" / "share" / "sawoneai"))
    return home / "kb"


def download(source: str, config: UpdateConfig, staging: Path) -> dict:
    base = check_source(source, config)
    manifest_bytes = _fetch(base + kb.MANIFEST_NAME, MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except ValueError as exc:
        raise UpdateError("the downloaded manifest is not valid JSON") from exc
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise UpdateError("the downloaded manifest lists no files")
    staging.mkdir(parents=True, exist_ok=True)
    (staging / kb.MANIFEST_NAME).write_bytes(manifest_bytes)
    for name in files:
        if "/" in name or name.startswith(".") or name == kb.MANIFEST_NAME:
            raise UpdateError(f"the manifest lists an unsafe file name: {name}")
        (staging / name).write_bytes(_fetch(base + name, MAX_FILE_BYTES))
    return manifest


def stage_and_verify(source: str, config: UpdateConfig, *, current_version: str,
                     allow_downgrade: bool = False) -> tuple[Path, str]:
    """Download, verify and return the staging folder and the new version. Raises UpdateError on any failure."""
    staging = Path(tempfile.mkdtemp(prefix="agent-scan-kb-"))
    try:
        manifest = download(source, config, staging)
        result = kb.verify(staging, trust_dir=kb.TRUST_DIR)
        if not result.ok:
            raise UpdateError("the downloaded pack failed verification: " + "; ".join(result.problems))
        if not result.signed:
            raise UpdateError("the downloaded pack is not signed, so it is not accepted")
        new_version = str(manifest.get("version", ""))
        if not allow_downgrade and parse_version(new_version) <= parse_version(current_version):
            raise UpdateError(f"version {new_version} is not newer than {current_version}; downgrades are refused")
        return staging, new_version
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def activate(staging: Path) -> None:
    """Move a verified staging pack into place, keeping the previous active pack for rollback."""
    root = active_root()
    root.mkdir(parents=True, exist_ok=True)
    current = root / "current"
    previous = root / "previous"
    incoming = root / "incoming"
    if incoming.exists():
        shutil.rmtree(incoming)
    shutil.move(str(staging), str(incoming))
    if previous.exists():
        shutil.rmtree(previous)
    if current.exists():
        current.rename(previous)
    incoming.rename(current)


def rollback() -> None:
    root = active_root()
    previous = root / "previous"
    current = root / "current"
    if not previous.is_dir():
        raise UpdateError("there is no previous knowledge-base pack to roll back to")
    if current.exists():
        swap = root / "swap"
        if swap.exists():
            shutil.rmtree(swap)
        current.rename(swap)
        previous.rename(current)
        swap.rename(previous)
    else:
        previous.rename(current)

import functools
import http.server
import json
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sawoneai import kb, update


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def make_release(directory: Path, key, version: str, *, sign=True, tamper=False):
    """A pack folder that is served as an update: the shipped files at the given version, signed with key."""
    if directory.exists():
        shutil.rmtree(directory)
    shutil.copytree(kb.PACK_DIR, directory, ignore=shutil.ignore_patterns("trust", "manifest.json"))
    manifest = json.loads((kb.PACK_DIR / "manifest.json").read_text(encoding="utf-8"))
    manifest["version"] = version
    body = {"pack": manifest["pack"], "version": version, "files": {}, "signature": None}
    for path in sorted(directory.iterdir()):
        body["files"][path.name] = kb._sha256(path)
    if sign:
        body = kb.sign_manifest(body, key)
    (directory / "manifest.json").write_text(json.dumps(body), encoding="utf-8")
    if tamper:
        (directory / "entries.json").write_text('{"format": "x", "entries": []}', encoding="utf-8")
    return directory


class ServedRelease:
    def __init__(self, directory: Path):
        handler = functools.partial(QuietHandler, directory=str(directory))
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class UpdateTest(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.home = Path(tempfile.mkdtemp())
        self.trust = Path(tempfile.mkdtemp())
        (self.trust / "release.pem").write_bytes(self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.served = Path(tempfile.mkdtemp())
        patches = [
            mock.patch.object(kb, "TRUST_DIR", self.trust),
            mock.patch.dict(os.environ, {"SAWONEAI_HOME": str(self.home)}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def config_for(self, *sources):
        config = self.home / "config.json"
        config.write_text(json.dumps({"knowledge_base_sources": list(sources)}), encoding="utf-8")
        return config

    def active_version(self):
        return kb.verify(kb.current_pack_dir()).version

    def test_an_allowlisted_signed_update_is_activated(self):
        make_release(self.served / "r", self.key, "0.0.2")
        with ServedRelease(self.served / "r") as server:
            config = self.config_for(server.url)
            self.assertEqual(update.load_config(config).sources, [server.url])
            staging, version = update.stage_and_verify(server.url, update.load_config(config),
                                                       current_version="0.0.1")
            update.activate(staging)
        self.assertEqual(version, "0.0.2")
        self.assertEqual(self.active_version(), "0.0.2")
        self.assertTrue(kb.entries())

    def test_a_source_that_is_not_allowlisted_is_refused(self):
        make_release(self.served / "r", self.key, "0.0.2")
        with ServedRelease(self.served / "r") as server:
            config = update.load_config(self.config_for("http://127.0.0.1:1/"))
            with self.assertRaisesRegex(update.UpdateError, "not in the allowlist"):
                update.stage_and_verify(server.url, config, current_version="0.0.1")

    def test_no_configured_source_means_no_update(self):
        self.assertEqual(update.load_config(self.home / "missing.json").sources, [])

    def test_plain_http_to_a_remote_host_is_refused(self):
        config = update.UpdateConfig(sources=["http://updates.example.com/"])
        with self.assertRaisesRegex(update.UpdateError, "must use https"):
            update.check_source("http://updates.example.com/", config)

    def test_https_source_is_accepted(self):
        config = update.UpdateConfig(sources=["https://updates.example.com/kb"])
        self.assertEqual(update.check_source("https://updates.example.com/kb", config),
                         "https://updates.example.com/kb/")

    def test_an_unsigned_release_is_refused_and_nothing_changes(self):
        make_release(self.served / "r", self.key, "0.0.2", sign=False)
        with ServedRelease(self.served / "r") as server:
            config = update.UpdateConfig(sources=[server.url])
            with self.assertRaisesRegex(update.UpdateError, "not signed"):
                update.stage_and_verify(server.url, config, current_version="0.0.1")
        self.assertFalse((update.active_root() / "current").exists())

    def test_a_release_signed_by_an_untrusted_key_is_refused(self):
        make_release(self.served / "r", Ed25519PrivateKey.generate(), "0.0.2")
        with ServedRelease(self.served / "r") as server:
            config = update.UpdateConfig(sources=[server.url])
            with self.assertRaisesRegex(update.UpdateError, "does not verify"):
                update.stage_and_verify(server.url, config, current_version="0.0.1")

    def test_a_tampered_file_is_refused(self):
        make_release(self.served / "r", self.key, "0.0.2", tamper=True)
        with ServedRelease(self.served / "r") as server:
            config = update.UpdateConfig(sources=[server.url])
            with self.assertRaisesRegex(update.UpdateError, "failed verification"):
                update.stage_and_verify(server.url, config, current_version="0.0.1")

    def test_a_downgrade_or_same_version_is_refused(self):
        make_release(self.served / "r", self.key, "0.0.1")
        with ServedRelease(self.served / "r") as server:
            config = update.UpdateConfig(sources=[server.url])
            with self.assertRaisesRegex(update.UpdateError, "not newer"):
                update.stage_and_verify(server.url, config, current_version="0.0.1")

    def test_an_oversized_file_is_refused(self):
        make_release(self.served / "r", self.key, "0.0.2")
        with ServedRelease(self.served / "r") as server, mock.patch.object(update, "MAX_FILE_BYTES", 10):
            config = update.UpdateConfig(sources=[server.url])
            with self.assertRaisesRegex(update.UpdateError, "larger than"):
                update.stage_and_verify(server.url, config, current_version="0.0.1")

    def test_a_manifest_with_an_unsafe_file_name_is_refused(self):
        make_release(self.served / "r", self.key, "0.0.2")
        manifest = json.loads((self.served / "r" / "manifest.json").read_text(encoding="utf-8"))
        manifest["files"]["../escape.json"] = "0" * 64
        manifest = kb.sign_manifest({k: v for k, v in manifest.items() if k != "signature"}, self.key)
        (self.served / "r" / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with ServedRelease(self.served / "r") as server:
            config = update.UpdateConfig(sources=[server.url])
            with self.assertRaisesRegex(update.UpdateError, "unsafe file name"):
                update.stage_and_verify(server.url, config, current_version="0.0.1")

    def test_rollback_restores_the_previous_pack(self):
        make_release(self.served / "a", self.key, "0.0.2")
        make_release(self.served / "b", self.key, "0.0.3")
        with ServedRelease(self.served / "a") as first:
            staging, _ = update.stage_and_verify(first.url, update.UpdateConfig(sources=[first.url]),
                                                 current_version="0.0.1")
            update.activate(staging)
        with ServedRelease(self.served / "b") as second:
            staging, _ = update.stage_and_verify(second.url, update.UpdateConfig(sources=[second.url]),
                                                 current_version="0.0.2")
            update.activate(staging)
        self.assertEqual(self.active_version(), "0.0.3")
        update.rollback()
        self.assertEqual(self.active_version(), "0.0.2")

    def test_rollback_without_a_previous_pack_is_an_error(self):
        with self.assertRaisesRegex(update.UpdateError, "no previous"):
            update.rollback()

    def test_the_cli_refuses_when_no_source_is_allowlisted(self):
        import contextlib
        import io
        from sawoneai import cli
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main(["kb", "update", "--config", str(self.home / "none.json")])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("no update source is allowlisted", err.getvalue())

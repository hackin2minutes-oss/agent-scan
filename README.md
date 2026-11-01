# Agent Scan

Security scanner for AI and agentic AI applications. It finds weaknesses that ordinary scanners miss, such as model
output reaching a shell or an eval, and it says how sure it is.

**Status: version 0.0.1, first slice.** One check (Python: a non-literal value reaching a shell or eval sink) and a
verified knowledge-base pack. Verdicts are only *needs review* or *unknown* in this version. Confirmed paths need
source tracing, which is not built yet.

## Try it

```
pip install -e .
agent-scan scan path/to/project
agent-scan scan path/to/project --json
agent-scan kb status
```

## Knowledge-base updates

Updates come only from sources listed in a configuration file, over https (plain http only for localhost):

```
{ "knowledge_base_sources": ["https://updates.example.org/agent-scan/"] }
```

```
agent-scan kb update --config ~/.config/agent-scan/config.json
agent-scan kb rollback
```

An update is downloaded, checked against the hashes in its manifest, checked for an Ed25519 signature from a key
shipped with the package, and refused if it is not newer. A failed update leaves the pack in use unchanged. The release
signing key is not in this repository; the release process holds it.

## Container

```
docker build -t agent-scan:0.0.1 .
docker run --rm --network none --read-only --tmpfs /tmp --user 1001:1001 \
  -v "$PWD:/work:ro" agent-scan:0.0.1 scan /work
```

The image runs as a non-root user, needs no network to scan, and the base image is pinned by digest. Verified locally
with networking off and a read-only root filesystem.

## Principles

- Honest verdicts: a finding is never reported as confirmed without a traced path.
- No language model decides a verdict.
- Works offline. The knowledge base ships inside the package and is verified by hash before every scan.
- Scanned code is parsed, never executed.

## Layout

- `src/agent_scan/scanner.py`: the checks.
- `src/agent_scan/kb.py`: knowledge-base pack, integrity verification.
- `src/agent_scan/data/kb/`: the pack (`entries.json`, `manifest.json`).
- `src/agent_scan/cli.py`: command line.
- `tests/`: unit tests. Run with `PYTHONPATH=src python3 -m unittest discover -s tests -t .`
- `docs/plan/`: the plan, the licence position, and the OWASP coverage specification.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`. Third-party components: `THIRD_PARTY_NOTICES.md`.

## Not yet

Source tracing, the framework knowledge base (LangChain, OpenAI SDK, MCP), OWASP coverage rows, signed updates,
container image, GitHub, GitLab and Azure DevOps delivery, and TypeScript. See `docs/plan/`.

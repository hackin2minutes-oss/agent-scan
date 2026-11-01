"""GitHub Actions workflow checker (first slice).

This checks pipeline files, not AI code. It reads .github/workflows/*.yml and *.yaml with PyYAML (MIT licence) and
checks three things. Each finding is NEEDS_REVIEW: it names the pattern and what it could not establish. A workflow
that does not parse is UNKNOWN.

Rules:
- gha-untrusted-checkout: a workflow triggered by pull_request_target or workflow_run checks out a ref taken from
  the pull request or the triggering run. That code can run with the repository's secrets.
- gha-script-injection: a run step interpolates an event field that a contributor can set (issue or pull request
  title or body, comment body, branch name, commit message) directly into the shell script.
- gha-unpinned-action: an action is referenced by a tag or branch, not a full 40-character commit SHA.

Limits: this reads the workflow text only. It does not know which secrets a job can reach, which branch protections
apply, or what the runner does. It does not run the pipeline.
"""

import re
from pathlib import Path

from sawoneai.scanner import Finding, NEEDS_REVIEW, UNKNOWN

PRIVILEGED_TRIGGERS = {"pull_request_target", "workflow_run"}

UNTRUSTED_REF = re.compile(
    r"github\.event\.(pull_request\.head|workflow_run\.head_sha|workflow_run\.head_branch|"
    r"pull_request\.head\.ref|pull_request\.head\.sha)"
)

UNTRUSTED_TEXT = re.compile(
    r"\$\{\{\s*github\.event\.(issue\.title|issue\.body|pull_request\.title|pull_request\.body|"
    r"comment\.body|review\.body|review_comment\.body|pull_request\.head\.ref|head_commit\.message|"
    r"head_commit\.author\.name|workflow_run\.head_branch|workflow_run\.display_title)\s*\}\}"
)

PINNED_SHA = re.compile(r"@[0-9a-f]{40}$")
SUFFIXES = {".yml", ".yaml"}


def _triggers(document: dict) -> set[str]:
    # PyYAML reads the bare key `on` as the boolean True, so both forms are checked.
    on = document.get("on", document.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on)
    return set()


def _steps(document: dict):
    for job_name, job in (document.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for index, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict):
                yield job_name, index, step


def scan_workflow(text: str, rel_path: str) -> list[Finding]:
    import yaml
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        return [Finding("workflow-parse-error", rel_path, 1, UNKNOWN,
                        "the workflow file could not be parsed as YAML",
                        ["a file that parses as YAML"])]
    if not isinstance(document, dict):
        return [Finding("workflow-parse-error", rel_path, 1, UNKNOWN,
                        "the workflow file is not a mapping, so it was not checked",
                        ["a workflow mapping with jobs"])]
    findings = []
    triggers = _triggers(document)
    privileged = triggers & PRIVILEGED_TRIGGERS
    for job_name, index, step in _steps(document):
        uses = step.get("uses")
        where = f"job {job_name}, step {index + 1}"
        if isinstance(uses, str):
            if not uses.startswith("./") and not uses.startswith("docker://") and not PINNED_SHA.search(uses):
                findings.append(Finding(
                    "gha-unpinned-action", rel_path, 1, NEEDS_REVIEW,
                    f"{where} uses {uses}, which is not pinned to a full commit SHA",
                    ["a commit SHA for the action"], [f"{where}: uses {uses}"]))
            with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
            ref = with_block.get("ref")
            if privileged and uses.startswith("actions/checkout") and isinstance(ref, str) and UNTRUSTED_REF.search(ref):
                findings.append(Finding(
                    "gha-untrusted-checkout", rel_path, 1, NEEDS_REVIEW,
                    f"a {', '.join(sorted(privileged))} workflow checks out {ref}, which comes from the pull request "
                    "or the triggering run, and runs with repository secrets",
                    ["the trust decision for that code: a same-repository check or a review step"],
                    [f"{where}: checkout ref {ref}"]))
        run = step.get("run")
        if isinstance(run, str):
            match = UNTRUSTED_TEXT.search(run)
            if match:
                findings.append(Finding(
                    "gha-script-injection", rel_path, 1, NEEDS_REVIEW,
                    f"{where} puts {match.group(0)} into a shell script, so a contributor-set value can run commands",
                    ["the value passed through an environment variable instead of the script text"],
                    [f"{where}: {match.group(0)}"]))
    return findings


def workflow_files(root: Path):
    directory = root / ".github" / "workflows"
    if not directory.is_dir():
        return
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix in SUFFIXES:
            yield path, path.relative_to(root).as_posix()


def scan_file(path: Path, rel_path: str) -> list[Finding]:
    return scan_workflow(path.read_text(encoding="utf-8"), rel_path)

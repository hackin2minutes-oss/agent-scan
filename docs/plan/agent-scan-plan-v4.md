# Agent Scan plan v4: AI and agentic-AI security scanner

Working name: **Agent Scan** (to be replaced after the name check, section 17).
This plan supersedes v1 to v3. It is standalone. Facts that are not confirmed are marked **VERIFY**.

---

## 1. What it is, in one paragraph

A command-line tool and CI integration that scans the code, prompts, rules files, and tool configuration of AI and agent
applications. It finds the weaknesses specific to agents: model output or retrieved content reaching a dangerous tool,
prompt injection paths, excessive tool permissions, unbounded agent loops, and secrets in prompts and configuration. It
explains each finding, gives a confidence level and a fix, and says what it could not check. It carries its own
knowledge base, so it runs in restricted networks, and it receives signed updates from an allowlist.

**Scope is AI and agentic AI only.** It does not replace general SAST, dependency scanning, or secret scanning. It
complements them, and it can read their output (SARIF) as additional input.

---

## 2. Decisions to make first

| # | Decision | Recommendation | Reason |
|---|---|---|---|
| D1 | Licence of our code | **Apache-2.0** | Permissive, patent grant, clear for enterprise use. |
| D2 | Open-core split | Open: the CLI, engine, knowledge-base format, rules, container and CI integrations. Paid (later): team dashboard, hosted update mirror with SLA, support. | Free distribution fits the adoption goal. Paid layer funds maintenance. |
| D3 | Name | Shortlist of 3, then trademark and package-name search | "Agent Scan" is generic. |
| D4 | Engine language | Python for the engine (matches the existing code and the agent ecosystem) | Fastest route to M0. |
| D5 | First frameworks | LangChain, LangGraph, OpenAI Agents SDK and OpenAI Python SDK, MCP Python SDK | Most used. Coverage checked before M0 (section 7). |
| D6 | Team | 3 people in M0: engine engineer, CLI and CI engineer, security reviewer at 50 percent | Realistic minimum. |
| D7 | Timeline | M0 in 14 weeks. M1 in 8 weeks. | Includes knowledge-base labelling, user testing, and release engineering. |

---

## 3. Who it's for

1. **Agent builders** who need a fast answer before they ship an agent or an agent-enabled feature.
2. **Security reviewers and architects** who approve agents and need evidence they can check, offline if necessary.
3. **Platform and DevOps teams** who run agents in regulated or restricted networks and need a scanner that works
   without internet access.
4. **Developers using coding agents**, who want to check the code and rules files an agent produced or changed.

---

## 4. Principles

1. **Works offline by default.** The knowledge base ships inside the tool. A scan needs no network.
2. **Five-minute first result.** One command, no account, no configuration file.
3. **Honest verdicts.** Every finding is *confirmed path*, *needs review*, or *unknown with the missing piece named*. The tool never says "safe"
   without proof, and never reports more confidence than its evidence supports.
4. **No language model decides a verdict.** Verdicts come from fixed rules and recorded evidence. A model may write a
   human-readable summary, opt-in, labelled as generated.
5. **Scanned content is hostile.** Code, prompts, and rules files are never executed or treated as instructions to the tool.
6. **Updates are explicit and verifiable.** Nothing changes the knowledge base unless the user has allowed the source, and
   every update is signature-checked before use.
7. **Say what was not checked.** Every report lists the knowledge-base version and age, frameworks covered, files skipped, and what the verdicts cannot see.

---

## 5. Functionality

### 5.1 Checks (by milestone)

**M0: agent code (Python)**
- **Model output to dangerous tool:** a value that comes from a model response or retrieved content reaches a
  shell, SQL, file-write, outbound request, email, or payment tool.
- **Retrieved and untrusted content to tool:** the same, for content from web pages, documents, email, or tool results.
- **Tool permissions:** destructive tools with no approval step; tools whose arguments accept free-form paths,
  commands, or URLs without a restriction.
- **Agent loops:** loops with no maximum step count or no time limit.
- **Secrets:** credentials in code, prompts, and configuration, reported with the value redacted.

**M1: configuration and prompts**
- **Rules files and system prompts** (for example CLAUDE.md, AGENTS.md, Cursor rules): unsafe instructions, credentials, and
  hidden text (zero-width characters, bidirectional controls, HTML comments).
- **MCP configuration and servers:** declared tools and permissions checked against rules. A hash of each approved tool
  description is stored, and changes are reported.
- **Agent configuration files** that enable broad autonomous actions with no approval.

**M2: TypeScript and JavaScript agent code**
- The same M0 checks, for LangChain.js, the OpenAI and Anthropic JavaScript SDKs, and MCP TypeScript SDK code.

**M3: evidence from runs**
- **Claim checker:** compares what an agent states it did (for example "tests passed") against its recorded tool calls, marking
  each claim *supported*, *contradicted*, or *not in the logs*.
- **Log import:** reads agent audit logs (JSONL) to add runtime evidence to a verdict.

**Out of scope (for now):** general web vulnerabilities, cloud permissions, non-AI code, and multi-agent
orchestration analysis beyond the M0 checks.

### 5.2 Verdicts

| Verdict | Meaning | Fails a build by default? |
|---|---|---|
| Confirmed path | The code shows a source reaching a sink with no sanitiser on that path, and the source is attacker-influenced by the rule's definition | Yes, if the gate is set to fail on it |
| Needs review | A path exists, but depends on model behaviour or an unverified classification | No |
| Unknown | The evidence is insufficient. The missing piece is named. | No |
| Not found | No path found in the scanned code. Says what was scanned. | No |

Unverified classifications can never produce a confirmed path. A finding's confidence is shown next to its verdict.

### 5.3 Outputs
- **Terminal:** counts, top findings, and the first action to take.
- **HTML:** one page for non-specialists, with a glossary and path diagrams. Accessible (WCAG 2.2 AA target, tested).
- **SARIF 2.1.0:** GitHub code scanning, Azure DevOps and other SARIF consumers.
- **JSON:** the full evidence record for every finding.
- **Markdown:** a pull-request comment and the job summary (GitHub step summary, GitLab and Azure DevOps equivalents).
- **GitLab SAST report** (`gl-sast-report.json`) **VERIFY** the current schema version before building it.
- Every report states the tool version, knowledge-base version and build date, scanned commit, frameworks covered, and skipped files.

### 5.4 Commands
- `agent-scan scan <path>`: the one command most people need.
- `agent-scan explain <finding-id>`: rule, source-to-sink path, evidence, fix, reference, and confidence with its reason.
- `agent-scan baseline`: accepts today's findings, so only new problems are reported afterwards.
- `agent-scan ignore <id> --reason "..."`: expires after 90 days unless renewed.
- `agent-scan kb status`: knowledge-base version, age, and source.
- `agent-scan kb update`: applies an allowed update (section 7).
- `agent-scan kb import <bundle>`: imports a signed offline bundle (section 7).
- `agent-scan doctor`: checks the environment and reports what can and cannot be scanned.

**Exit codes:** 0 clean or only needs-review and unknown findings; 1 confirmed paths found; 2 the scan could not complete.
Unknown never fails a build unless the user sets that explicitly.

---

## 6. Delivery: how people run it

The same engine, four ways. Each is built and tested in CI on every release.

| Target | What is delivered | Notes |
|---|---|---|
| **Command line** | Python package (`pip install`), and a single-file archive for machines without Python | Works offline once installed. |
| **Container image** | Small Linux image, non-root user, read-only file system supported, knowledge base inside | For restricted networks and any CI that runs containers. Image signed and published with an SBOM. |
| **GitHub Actions** | Composite action that runs the image, writes SARIF, the job summary, and optional PR comment | Least-privilege permissions documented. Pinned by digest in examples. |
| **GitLab CI** | CI/CD component (reusable template) that runs the image and produces a SAST-format report | Uses the container image. **VERIFY** the GitLab component packaging requirements before release. |
| **Azure DevOps** | Pipeline task that runs the container image as a container job, with SARIF output and a summary | **VERIFY** the current task packaging option (container job versus an extension) before release. |

**Restricted networks.** Everything runs with no network access. The image contains the knowledge base. The only network
action is the optional update (section 7), and it is off by default in restricted mode.

**Scanning a pipeline's own output.** Scanners that already run in a pipeline can write SARIF, and this tool can read it
as additional input, so existing tools and this tool can be used together.

---

## 7. Knowledge base: bundled, versioned, and updated with control

### 7.1 What is in it
- **Sources and sinks** for each supported framework and SDK: the functions that take model output or external content,
  and the functions that act on the world (shell, SQL, files, requests, email, payments).
- **Sanitisers and guards** that break a path, recorded per function, with the conditions under which they count.
- **Permission rules:** approval steps, argument restrictions, and destructive-tool markers.
- **Agent loop rules:** the functions that start loops, and the limits that count as a guard.
- **Prompt and configuration rules:** credential patterns, hidden-text patterns, and unsafe-instruction patterns.
- **Weakness references:** CWE numbers with our own short names, and NVD CVE identifiers for framework advisories.
- **Test programs:** each entry is backed by a test program with a known answer. The test programs ship with the tool too,
  so a user can check the tool on their own machine.

### 7.2 Format and packaging
- A **versioned data pack**: an SQLite database (public-domain licence, **VERIFY** the current SQLite licence statement
  before release) plus a JSON manifest.
- The manifest lists each entry's ID, framework, version range, role, arguments, weakness, reference, test ID,
  date verified, and the knowledge-base version that added it.
- The data pack is **signed**, and the manifest records a hash of every file in it.
- The image and the package each include a copy, so the tool always has a working knowledge base.

### 7.3 How it is kept current

**Maintainers (our side)**
- **Daily:** check framework releases and the NVD CVE feed for the frameworks we cover. Each change opens a task.
- **Weekly:** rerun every test program against the latest framework releases. A failing test marks its entry *stale*. Stale entries are never changed silently.
- **Monthly:** publish a stable knowledge-base release, signed, with a change list.
- **Within 72 hours:** publish an emergency release for a critical framework advisory.
- **Stale SLA:** a stale entry is fixed or marked *not covered* within 14 days.

**Users (their side)**
- **Update channels:** `stable` (monthly, default), `fast` (weekly), `pinned` (no updates until changed by the user).
- **Allowlist:** the user lists the update sources they accept. Default: our public update host only. Enterprise users
  can list an internal mirror instead (for example an artifact repository they already run). Any other address is refused.
- **Update steps:** fetch the manifest; check the signature against the public key the tool ships with; check the hashes;
  refuse any version older than the installed one (no downgrades) unless the user pins; stage the new pack; run the
  built-in test programs against it; only then activate it. The previous pack is kept for rollback.
- **Offline import:** a signed bundle can be carried in on removable media or through an approved transfer, and
  `agent-scan kb import` checks it the same way. This is the path for fully air-gapped networks.
- **Freshness:** the report and `kb status` show the knowledge-base age. If it is older than a set limit (default 45 days),
  the report says so, and results are marked as possibly out of date for newer framework versions.
- **Key rotation:** the public key can be rotated by a new release, with the old key accepted for one overlap period.

**Mirror option for restricted networks.** An organisation can run a mirror of our update host behind its own
allowlist, mirror the signed packs, and point the tool at it. The mirror cannot alter a signed pack without the check failing.

---

## 8. Architecture

```
 code, prompts, rules, MCP config
            |
   [1] Parsers ........ Python (tree-sitter); later TypeScript; YAML/JSON/Markdown for config
            |
   [2] Knowledge base . bundled data pack, signed, versioned
            |
   [3] Router ......... verified class | inferred class | category fallback | generic investigation
            |
   [4] Flow analyser .. source-to-sink through calls, arguments, returns; sanitisers on the path
            |
   [5] Verdict rules .. fixed, readable rules; no model in this step
            |
   [6] Evidence store . every fact with source and confidence; traceable from any verdict
            |
   [7] Reporters ...... terminal, HTML, SARIF, JSON, Markdown, GitLab format
```

**The brain is stages 3 to 5.** It is deterministic: the same inputs and knowledge-base version give the same verdicts.

**What already exists in our engine code:** the router, the verdict rules, the evidence graph with provenance, the SARIF,
JSON and Markdown reporters, the commit-match check, the weakness classes, and the test harness. New work is the
knowledge base, the agent flow analyser, the delivery packaging, and the update system.

---

## 9. Security of the tool itself

- **Threat model:** scanned content may contain crafted code, rules, or prompts that try to make the scanner misreport,
  fail, or leak data. Defences: no execution of scanned code; parsing without evaluation; text from scanned files is data,
  never instructions to the tool; fixed verdict rules.
- **Evasion testing:** a red-team corpus of deliberately evasive programs, run on every release. Misses are reported, not hidden.
- **Secret redaction:** a detected secret appears only as its first and last characters, in every output. An automated
  test fails the build if a full secret appears anywhere.
- **Update security:** signed manifests, hash checks, no downgrades, allowlisted sources, staged activation with tests,
  and rollback (section 7).
- **Supply chain:** pinned dependencies; an SBOM and a `NOTICE` file generated per release; **VERIFY** the signing tool
  for images and packages (for example Sigstore) and the release platform it integrates with.
- **Container hardening:** non-root user, minimal base image, read-only file system supported, no shell needed at runtime.
- **CI least privilege:** each integration documents the minimum permissions needed. The GitHub Action asks for read
  access, plus write access to code scanning only if the user opts in.
- **Network:** no network calls during a scan. Updates are the only network action, and only to allowlisted sources.

---

## 10. Privacy and data

- **No telemetry by default.** An opt-in telemetry setting sends anonymous counts only (commands, error types), with a published schema.
- **No source code, file names, findings, or secrets leave the machine,** with or without telemetry.
- **Update requests** send only the installed knowledge-base version. The request is shown in full before the first update.
- **Hosted features (paid, later):** a privacy notice before launch, reviewed by counsel.

---

## 11. Licences

**Our code:** Apache-2.0, with a `NOTICE` file generated per release from the SBOM.

**Components we use (permissive only, per the earlier checks):**
- tree-sitter core and the Python and C# grammars: MIT (per package metadata). **VERIFY** each repository's LICENSE file.
- Python standard library: PSF licence.
- LangChain packages: MIT per PyPI metadata. **VERIFY** each package used (core and community packages can differ).
- OpenAI Python SDK: Apache-2.0 for recent releases. **VERIFY** the version pinned.
- SQLite: public domain. **VERIFY** the current statement before release.
- Anthropic Python and JavaScript SDKs: **VERIFY** before use. Until verified, they are not included.

**Excluded:** Semgrep's engine (LGPL-2.1, which carries distribution obligations) and Semgrep's rules (restricted use);
CodeQL (limited to open-source projects); GitHub Advisory Database text (CC BY 4.0, attribution required in every use);
OWASP LLM Top 10 text (CC BY-SA 4.0, share-alike); MITRE ATLAS (licence not found).

**Knowledge-base text:** written by us from primary API documentation, and checked by tests. Identifiers (CWE numbers, CVE
IDs) are cited, and our own wording is used. No text is copied from another rule set, advisory, or framework guidance.

**Obligation accepted:** keep the notices and generate the `NOTICE` file each release. No other obligation.

**Using Semgrep for comparison only:** running it in our test harness to produce a baseline is not distribution of its
code or rules. This is kept out of the shipped tool.

---

## 12. Testing and evaluation

- **Labelled corpus:** about 60 small agent programs in M0, each labelled by the security reviewer and checked by a second
  labeller. Agreement measured (Cohen's kappa). Below 0.6 means relabel.
- **Held-out split:** part of the corpus is not used while rules are written, to avoid overfitting.
- **Baseline:** the same corpus run through Semgrep (our own rules only, for comparison) and Bandit. Our tool must do better on
  agent-specific checks, or the report says where it does not.
- **Red-team corpus:** evasive programs, rerun on every release.
- **Delivery tests:** the container image, the GitHub Action, the GitLab component, and the Azure DevOps task each run the
  same corpus in CI, and produce the same verdicts.
- **Offline tests:** the full scan is run with networking disabled, and the update path is tested against a tampered
  pack, an expired manifest, a downgrade attempt, and an unlisted source. Each must be refused.
- **Redaction test:** every release runs the secret-leak check across all output formats.
- **Performance:** median scan time on three reference projects (small, medium, large), on a stated machine, published per release.

---

## 13. Usability and accessibility

- **First result:** under five minutes, measured with real users (section 14).
- **Plain language first:** each finding's first sentence explains the risk without jargon. Technical detail is underneath.
- **Quiet by default:** top findings and a count of the rest. `--all` shows everything.
- **HTML report:** WCAG 2.2 AA target, tested with a keyboard-only pass and a screen reader. Dark mode.
- **Messages when a scan cannot finish:** what failed, which file, and what to do next.
- **Localisation:** strings kept in separate files from day one. English at launch.

---

## 14. User research

- **Before M0:** five interviews with people who build or approve agents, including two who are not security specialists.
- **In the last week of M0:** five usability sessions with a real project. Time to first result, where people get stuck, and what they misread.
- **Changes:** anything more than two people misread is changed before release.

---

## 15. Milestones and timing

**Assumption:** the 3-person team in section 2. Estimates are unvalidated until the first sprint is complete.

**M0 (14 weeks): first working release**
- Weeks 1-2: coverage check of the first frameworks; interviews; name shortlist; licence confirmations (section 11).
- Weeks 3-7: parser and router on the existing engine; knowledge base for the first frameworks (about 40 entries);
  corpus of about 60 labelled programs.
- Weeks 8-10: CLI commands; terminal, HTML, SARIF, JSON and Markdown outputs; knowledge-base bundling and signing;
  update system with allowlist and offline import.
- Weeks 11-12: container image; GitHub Action; redaction and offline tests; red-team corpus; security review of the scanner.
- Weeks 13-14: GitLab component and Azure DevOps task (VERIFY packaging first); user testing; release candidate.

**M1 (8 weeks): configuration and prompts.** Rules-file and system-prompt checks, hidden-text detection, MCP configuration
and description hashes, pre-commit hook.

**M2 (8 weeks): TypeScript.** Same knowledge-base format, TypeScript grammar (VERIFY its licence), JavaScript and
TypeScript SDK entries.

**M3 (later): run evidence.** Claim checker and log import.

**Not planned:** non-AI code analysis, cloud permissions, multi-agent orchestration beyond M0 checks.

---

## 16. Risks

| Risk | Mitigation |
|---|---|
| Framework APIs change faster than entries | Weekly test job; stale SLA; emergency releases |
| Labelling is slow or inconsistent | Two labellers; kappa tracked; relabel rule |
| Knowledge base grows too large for the image | Measured size budget per release; split packs by framework, loaded on demand from the bundle |
| Update channel is compromised | Signed manifests, allowlist, no downgrades, staged activation, rollback |
| Restricted users cannot update | Offline import of signed bundles; internal mirror option |
| Non-specialists cannot use it | Interviews; first-result target; plain language |
| Scanner is attacked through scanned content | Section 9 controls; red-team corpus |
| Commercial tools add the same feature | Open core; evidence-based honest verdicts; offline and restricted use |
| Scope creep | Milestone gates; out-of-scope list in section 5.1 |
| Licence of a dependency changes | Pinned versions; SBOM; licence check in CI |

---

## 17. Open items to verify or decide

**Decide:** name (D3), open-core split details (D2), timeline and budget (D6, D7), who owns each framework entry.

**Verify before release:**
1. tree-sitter repository LICENSE files (core, Python, C#, TypeScript).
2. LangChain packages used, and their licences.
3. OpenAI Python SDK version pinned, and its licence.
4. Anthropic SDKs: licence, before inclusion.
5. SQLite public-domain statement.
6. NVD terms for CVE identifiers.
7. MITRE CWE terms for names (numbers alone are cited).
8. GitLab CI component packaging requirements.
9. Azure DevOps task packaging option (container job versus extension).
10. GitLab SAST report schema version.
11. Signing tool for images and packages, and its release-platform integration.
12. A PyInstaller or similar single-file build, and its licence terms, if used.

---

## 18. First ten actions

1. Confirm D1 (Apache-2.0), D2 (open core), D4 (Python), D5 (frameworks).
2. Run the name shortlist through a trademark and package-name check.
3. Book five interviews with agent builders and approvers.
4. Do the coverage check: list the public functions in the chosen frameworks that run a tool or receive model output.
5. Verify items 1 to 5 in section 17.
6. Write the first 20 knowledge-base entries, each with a test program.
7. Build the knowledge-base pack format and signing, with a test that refuses a tampered pack.
8. Build `scan` and the terminal and SARIF outputs on the existing engine.
9. Build the container image and run the corpus inside it with networking disabled.
10. Run the GitHub Action on three real agent projects and record every wrong finding.

---

## 19. Definition of done for M0

- `agent-scan scan .` gives a readable result in under five minutes for a new user (measured).
- The same scan runs in a container with networking disabled, from the GitHub Action, and from the GitLab and Azure DevOps
  integrations, with identical verdicts.
- The knowledge base is bundled, signed, and versioned; updates are refused unless signed, from an allowed source, and not a downgrade.
- An offline bundle can be imported and checked on a machine with no network.
- Every finding has an explanation, a fix, a confidence level, and a reference.
- The corpus numbers, kappa, the baseline comparison, the red-team results, and the speed figures are published.
- The redaction test and the offline tests pass.
- Every licence in section 11 is confirmed, and the `NOTICE` file is generated.
- The scanner's own security review is complete, with findings fixed or accepted in writing.

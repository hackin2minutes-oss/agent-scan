# OWASP AI Exchange: control and threat mapping

Source: OWASP AI Exchange, owaspai.org (content licensed CC0 1.0). Names and identifiers below are the AI Exchange's
control and threat names, with our own wording for the status. The status values are defined in
`docs/coverage/owasp-ai-coverage.md` (COVERED, PARTIAL, PLANNED, GUIDANCE, OUT OF SCOPE).

**Read status:** the table of contents was read to the end of the controls list and to the threat list up to
"Agentic AI threats". The rest of the deep-dive pages (per-control text) was not read. Each row must be checked against
its control page before the M0 release gate, and rows may be added.

## 1. Controls

### Manage

| Control | Our check | Status |
|---|---|---|
| AI program | Organisational policy | GUIDANCE |
| Dev program | Organisational policy | GUIDANCE |
| Check compliance | Organisational process | GUIDANCE |
| Security education | Organisational process | GUIDANCE |
| Supply chain management | Unpinned tools and MCP servers (ASI04 rows) | PARTIAL |
| Security program | Organisational process | GUIDANCE |
| Secure development program | Organisational process | GUIDANCE |
| Development security | Development environment hardening | GUIDANCE |
| Segregate data | Training and dev data separation | GUIDANCE |
| Discrete (development-time) | Development environment | GUIDANCE |
| Model access control | Approval gates on tool calls only; model endpoint auth is not seen | PARTIAL |
| Runtime model integrity | Model file integrity at run time | OUT OF SCOPE (runtime infrastructure) |
| Runtime model IO integrity | Model input and output integrity at run time | OUT OF SCOPE (runtime infrastructure) |
| Runtime model confidentiality | Model access at run time | OUT OF SCOPE (runtime infrastructure) |
| Model input confidentiality | Sensitive data sent to model | PARTIAL (credential and personal-data patterns in prompts) |
| Encode model output | Output reaching shell, SQL, HTML, URL and eval sinks | PARTIAL (listed sinks) |
| Limit resources | Agent loops with no step limit (LLM10 rows) | PARTIAL |
| Augmentation data confidentiality | Retrieval data exposure | PARTIAL (credential patterns only) |
| Augmentation data integrity | Retrieved content checked before use | GUIDANCE |
| Confidential compute | Hardware and cloud configuration | OUT OF SCOPE (infrastructure) |
| Model obfuscation | Model protection | GUIDANCE |

### Have resilient models

All controls in this group concern training and model construction (alignment, federated learning, adversarial training,
ensembles, data quality, bias testing, validation). SawoneAI reads application code and configuration, not training
pipelines. Each is GUIDANCE, except where a training script is in the scanned code: then "training code loads data from
unverified URLs" is covered by LLM04 (PARTIAL, M2).

| Control | Status |
|---|---|
| Model alignment | GUIDANCE |
| Federated learning | GUIDANCE |
| Continuous validation | GUIDANCE |
| Unwanted bias testing | GUIDANCE |
| Evasion robust model | GUIDANCE |
| Poison robust model | GUIDANCE |
| Train adversarial | GUIDANCE |
| Train data distortion | GUIDANCE |
| Adversarial robust distillation | GUIDANCE |
| Model ensemble | GUIDANCE |
| More train data | GUIDANCE |
| Small model | GUIDANCE |
| Data quality control | GUIDANCE |

### Watch

| Control | Our check | Status |
|---|---|---|
| Anomalous input handling | Runtime input monitoring | GUIDANCE |
| Evasion input handling | Runtime input monitoring | GUIDANCE |
| Unwanted input series handling | Runtime input monitoring | GUIDANCE |
| Prompt injection I/O handling | Untrusted content reaching model input (flow analysis, LLM01) | PARTIAL |
| DoS input validation | Input size and rate validation | GUIDANCE |
| Input distortion | Model-side input processing | OUT OF SCOPE |
| Sensitive output handling | Secrets in outputs and logs (LLM02) | PARTIAL |
| Obscure confidence | Confidence exposure in outputs | GUIDANCE |
| Rate limit | Rate limits on endpoints | GUIDANCE |
| Monitor use | Audit logs and claim checker (M3) | PLANNED (M3) |

### Limit

| Control | Our check | Status |
|---|---|---|
| Data minimise | Personal data in prompts (M1 patterns) | PARTIAL |
| Allowed data | Data policy | GUIDANCE |
| Short retain | Retention policy | GUIDANCE |
| Obfuscate training data | Training data handling | GUIDANCE |
| Oversight | Human approval before destructive tools (LLM06, ASI09) | PARTIAL |
| Least model privilege | Broad tools and unrestricted arguments (ASI02, ASI03) | PARTIAL |
| AI transparency | Disclosure to users | GUIDANCE |
| Explainability | Model explanations | GUIDANCE |

### Other controls named on the page

| Control | Status |
|---|---|
| Governance controls | GUIDANCE |
| Data limit | GUIDANCE |
| Limit unwanted behaviour | PARTIAL (approval and tool-scope checks) |
| Input segregation | GUIDANCE |
| Agent sandboxing | PARTIAL (shell, exec and code-interpreter sink detection, ASI05) |
| Conventional runtime security controls | GUIDANCE (out of AI scope; see the general scanners) |
| Conventional development security and supply chain controls | GUIDANCE (general scanners) |

## 2. Threats

| Threat | Our check | Status |
|---|---|---|
| Direct prompt injection | Model output or user text reaching tool sinks (LLM01, flow) | PARTIAL |
| Indirect prompt injection | Retrieved and fetched content reaching model input (LLM01, flow) | PARTIAL |
| Evasion | Adversarial inputs at use time | GUIDANCE |
| Direct runtime model poisoning | Runtime model changes | OUT OF SCOPE |
| Augmentation data manipulation | Retrieval store writes from untrusted sources (LLM08, M2) | PLANNED (M2) |
| Direct development-time model poisoning | Training pipeline | GUIDANCE |
| Data poisoning of train or fine-tune data | Training data source (LLM04, M2) | PARTIAL |
| Supply-chain model poisoning | Model download without pinning (LLM03) | PARTIAL |
| Supply-chain data poisoning | Dataset download without pinning (LLM03) | PARTIAL |
| Disclosure in output | Secrets and personal data in outputs (LLM02) | PARTIAL |
| Direct augmentation data leak | Retrieval store exposure (LLM08) | PARTIAL |
| Model inversion and membership inference | Model property | GUIDANCE |
| Development-time data leak | Training data exposure in code | PARTIAL (credential patterns) |
| Model exfiltration | Model file access | OUT OF SCOPE |
| Direct runtime model leak | Runtime model access | OUT OF SCOPE |
| Direct development-time model leak | Model files in the repository | PARTIAL (credential and model-file patterns, M1) |
| AI resource exhaustion | Unbounded loops and calls (LLM10) | PARTIAL |
| Input data leak | Sensitive data in model input (LLM02) | PARTIAL |
| Output contains conventional injection | Output to shell, SQL, HTML sinks (LLM05) | COVERED (listed sinks) |
| Generic runtime security threats | General scanners | OUT OF SCOPE (covered by existing tools) |
| Generic development-environment and supply-chain threats | General scanners | OUT OF SCOPE (covered by existing tools) |
| Agent escape | Tool and sandbox boundaries (ASI02, ASI05) | PARTIAL |
| Agent message structure manipulation | Agent-to-agent messages (ASI07) | PLANNED (M3) |

## 3. Gaps before the release gate

1. Read the per-control pages and the remaining threat list (the truncated part of the table of contents).
2. Confirm each status above against the control text, and change rows that the text contradicts.
3. Add a CI gate: every control and threat named in this file has a row and a status.

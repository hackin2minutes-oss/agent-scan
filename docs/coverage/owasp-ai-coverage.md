# OWASP AI coverage

Every item of the OWASP AI sources below has a row, with the check that covers it, its status, and how its name was
verified. No item is left without a status. Item names are the OWASP identifiers with our short names. No OWASP text is
copied.

Status key: COVERED (check and test in the release), PARTIAL (named sub-cases only), PLANNED (milestone given),
GUIDANCE (not detectable from code or configuration; the report points to guidance), OUT OF SCOPE (reason given).

Verification key: VERIFIED (name read from the official page in this check), UNVERIFIED (not read from the official
document; taken from a secondary summary or from memory).

## 1. OWASP Top 10 for LLM Applications (2025 names; 2026 edition not yet read)

| ID | Name (short) | Check | Status | Verification |
|---|---|---|---|---|
| LLM01 | Prompt injection | Model output and fetched content reaching sinks and model input; instruction-file checks | PARTIAL | UNVERIFIED |
| LLM02 | Sensitive information disclosure | Credential patterns in prompts and rules; redaction in all outputs | PARTIAL | UNVERIFIED |
| LLM03 | Supply chain | Unpinned MCP launcher packages | PARTIAL | UNVERIFIED |
| LLM04 | Data and model poisoning | None | GUIDANCE | UNVERIFIED |
| LLM05 | Improper output handling | Model output to shell and eval sinks | COVERED | UNVERIFIED |
| LLM06 | Excessive agency | Tools reaching sinks without approval; tool-method sinks | COVERED (listed patterns) | UNVERIFIED |
| LLM07 | System prompt leakage | Credentials in prompts | PARTIAL | UNVERIFIED |
| LLM08 | Vector and embedding weaknesses | None yet | PLANNED (M2) | UNVERIFIED |
| LLM09 | Misinformation | Missing human review is not detectable | GUIDANCE | UNVERIFIED |
| LLM10 | Unbounded consumption | Explicit unlimited turn limit | PARTIAL | UNVERIFIED |

## 2. OWASP Top 10 for Agentic Applications (ASI01 to ASI10)

| ID | Name | Check | Status | Verification |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | Fetched content and instruction files reaching the model | PARTIAL | VERIFIED |
| ASI02 | Tool Misuse | Tool sinks with model-chosen arguments | COVERED (listed patterns) | VERIFIED |
| ASI03 | Identity & Privilege Abuse | Credentials in MCP config; tool permissions | PARTIAL | VERIFIED |
| ASI04 | Agentic Supply Chain Vulnerabilities | Unpinned MCP packages; changed MCP tool descriptions | PARTIAL | VERIFIED |
| ASI05 | Unexpected Code Execution | Model output to shell and eval sinks | COVERED | VERIFIED |
| ASI06 | Memory & Context Poisoning | None yet | PLANNED (M3) | VERIFIED |
| ASI07 | Insecure Inter-Agent Communication | None; no multi-agent model | PLANNED (M3) | VERIFIED |
| ASI08 | Cascading Failures | Unlimited turn limit only | PARTIAL | VERIFIED |
| ASI09 | Human-Agent Trust Exploitation | Missing approval steps; the trust itself is not detectable | GUIDANCE | VERIFIED |
| ASI10 | Rogue Agents | Run-time behaviour; needs run evidence | PLANNED (M3) | VERIFIED |

## 3. OWASP Agentic Skills Top 10 (AST01 to AST10)

| ID | Name | Check | Status | Verification |
|---|---|---|---|---|
| AST01 | Malicious Skills | Skill files are not yet read | PLANNED (M1) | VERIFIED |
| AST02 | Supply Chain Compromise | Unpinned launcher packages in MCP config | PARTIAL | VERIFIED |
| AST03 | Over-Privileged Skills | Tool permission checks apply to tools; not to skills | PLANNED (M1) | VERIFIED |
| AST04 | Insecure Metadata | Tool-description checks apply to MCP tools; not to skill metadata | PLANNED (M1) | VERIFIED |
| AST05 | Untrusted External Instructions | Fetched content into the model; instruction-file checks | PARTIAL | VERIFIED |
| AST06 | Weak Isolation | Run-time isolation is not visible in code | GUIDANCE | VERIFIED |
| AST07 | Update Drift | Changed MCP tool descriptions against approved hashes | PARTIAL | VERIFIED |
| AST08 | Poor Scanning | This tool is the scanning; its limits are stated in every report | GUIDANCE | VERIFIED |
| AST09 | No Governance | Organisational process | GUIDANCE | VERIFIED |
| AST10 | Cross-Platform Reuse | Skills shared across platforms are not yet read | PLANNED (M2) | VERIFIED |

## 4. OWASP GenAI guide for third-party MCP servers (v1.0, October 2025)

The official document was not read in this check. The themes below come from a secondary summary, so every row is
UNVERIFIED until the document is read at genai.owasp.org.

| Theme | Check | Status | Verification |
|---|---|---|---|
| Discovery and origin verification | MCP config: remote servers over plain HTTP | PARTIAL | UNVERIFIED |
| Connection mode and isolation | Shell-launched servers | PARTIAL | UNVERIFIED |
| Authentication and authorisation | Literal credentials in MCP environment | PARTIAL | UNVERIFIED |
| Human approval of unknown tools | Unapproved tool hashes | PARTIAL | UNVERIFIED |
| Version pinning and hashing | Unpinned launcher packages; changed tool hashes | PARTIAL | UNVERIFIED |
| Governance | Organisational process | GUIDANCE | UNVERIFIED |

## 5. OWASP AI Exchange

The AI Exchange has many controls. This check read only its top-level categories. The control-level mapping is not done.

| Category | Check | Status |
|---|---|---|
| Manage (governance, supply chain, conventional security) | Supply-chain checks on MCP packages; the rest is GUIDANCE | PARTIAL (category level) |
| Have resilient models (input attacks) | Prompt injection flows | PARTIAL (category level) |
| Watch (model I/O and monitoring) | Model output to sinks; fetched content into the model | PARTIAL (category level) |
| Limit (sensitive data, model behaviour) | Credentials in prompts and config; unlimited turns | PARTIAL (category level) |

Control-level mapping: PLANNED before the M0 gate can close.

## 6. Gaps this table makes visible

- The LLM Top 10 names are from 2025. The 2026 edition is not yet read.
- The MCP guide rows rest on a secondary summary.
- The AI Exchange has only category-level coverage.
- AST01, AST03 and AST04 need skill-file support, which is not built.
- ASI06, ASI07, ASI10 and LLM08 need features planned for M2 and M3.

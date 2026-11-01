# OWASP AI coverage

Every item of the OWASP AI sources below has a row, with the check that covers it, its status, and how its name was
verified. No item is left without a status. Item names are the OWASP identifiers with our short names. No OWASP text is
copied.

Status key: COVERED (check and test in the release), PARTIAL (named sub-cases only), PLANNED (milestone given),
GUIDANCE (not detectable from code or configuration; the report points to guidance), OUT OF SCOPE (reason given).

Verification key: VERIFIED (name read from the official page in this check), UNVERIFIED (not read from the official
document; taken from a secondary summary or from memory).

## 1. OWASP Top 10 for LLM Applications, 2026 edition (names VERIFIED from the official PDF, August 2026)

| ID | Name | Check | Status |
|---|---|---|---|
| LLM01 | Prompt Injection | Fetched content and model output reaching model input or sinks; instruction-file checks | PARTIAL |
| LLM02 | Sensitive Information Disclosure | Credential patterns in prompts, rules and MCP config; redaction in every output | PARTIAL |
| LLM03 | Excessive Agency | Tools reaching sinks without approval; tool-method sinks; unlimited turns | COVERED (listed patterns) |
| LLM04 | Supply Chain | Unpinned MCP launcher packages; changed MCP tool descriptions | PARTIAL |
| LLM05 | Data and Model Poisoning | None | GUIDANCE |
| LLM06 | Unbounded Consumption | Explicit unlimited turn limit | PARTIAL |
| LLM07 | Misinformation | Missing human review is not detectable | GUIDANCE |
| LLM08 | Hidden Context Exposure | Credentials in prompts and rules; hidden text in instruction files | PARTIAL |
| LLM09 | Vector and Embedding Weaknesses | None yet | PLANNED (M2) |
| LLM10 | Improper Output Handling | Model output to shell and eval sinks | COVERED |

The 2025 names are retired in this table: "System Prompt Leakage" is not in the 2026 list, and the 2026 edition adds
"Hidden Context Exposure". Rows above follow the 2026 list only.

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

The official cheatsheet page was read. Its seven section topics are VERIFIED. Its individual recommendations are not on
the page, so each topic's check is a PARTIAL mapping, and no recommendation is claimed as covered.

| Topic (VERIFIED) | Check | Status |
|---|---|---|
| Secure server discovery | MCP config: remote servers over plain HTTP | PARTIAL |
| Client sandboxing | Shell-launched servers | PARTIAL |
| Authentication | Literal credentials in MCP environment | PARTIAL |
| Authorization | Unapproved tool hashes | PARTIAL |
| Least-privilege access | Unpinned launcher packages; tool permission checks | PARTIAL |
| Human-in-the-loop oversight | Missing approval on tools that reach sinks | PARTIAL |
| Governance workflows | Organisational process | GUIDANCE |

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

- The MCP guide's individual recommendations are not on the official page, so the MCP rows are topic-level only.
- The AI Exchange has only category-level coverage.
- AST01, AST03 and AST04 need skill-file support, which is not built.
- ASI06, ASI07, ASI10 and LLM08 need features planned for M2 and M3.

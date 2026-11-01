# Agent Scan: OWASP AI coverage specification (addendum to plan v4)

Purpose: every item in the OWASP AI and GenAI body of work that can affect an AI or agent application is listed here,
with the check that covers it, the milestone, and a status. No item is skipped. An item that cannot be checked
statically is listed as such, with the guidance we give instead.

## 1. Rules for this specification

1. **Every item has a row.** A CI gate fails the build if an OWASP item from the sources in section 2 is missing a row,
   or has no status.
2. **Status values:**
   - **COVERED:** a check exists, has a test program, and is in the release.
   - **PARTIAL:** a check covers named sub-cases. The report states which sub-cases are not covered.
   - **PLANNED:** a check is scheduled for the milestone shown.
   - **GUIDANCE:** not detectable from code or configuration. The report prints the guidance for that item.
   - **OUT OF SCOPE:** stated with the reason.
3. **No text is copied from OWASP.** Each row uses our own wording and the OWASP identifier. Where OWASP text is
   reproduced in future, the licence check in plan v4 section 11 applies first.
4. **Names are verified before release.** Item names below marked **VERIFY** were not read from the official page in
   this session and must be checked against it before the first release.

## 2. Sources covered

| Source | Owner | What it is | Status of this spec |
|---|---|---|---|
| OWASP Top 10 for LLM Applications | OWASP GenAI Security Project | Ten risk categories for LLM applications. A 2026 edition exists. | 2025 names below. 2026 differences: **VERIFY**. |
| OWASP Top 10 for Agentic Applications (Dec 2025) | OWASP GenAI Security Project | Ten risk categories for autonomous and agentic systems, ASI01 to ASI10. | Names below **VERIFY**. ASI04 confirmed from the project announcement. |
| OWASP Agentic Skills Top 10 (AST10) | OWASP | Risks in agent skills across major agent platforms. | Items **not yet read**. Must be added before M1. |
| Practical guide for securely using third-party MCP servers | OWASP GenAI Security Project | Guidance for MCP server use. | **Not yet read.** Must be added before M1. |
| OWASP AI Exchange (formerly AI Security and Privacy Guide) | OWASP Flagship project | Controls and threats across AI systems, including privacy. | **Not yet read.** Controls must be mapped before M0 closes. |
| OWASP GenAI Security Project resources and exploit roundups | OWASP | Current exploit trends and guidance. | Reviewed in the daily maintenance task (plan v4 section 7.3). |
| OWASP ML Security Top 10 | OWASP | Machine-learning system risks. | **Existence not confirmed.** VERIFY. Added if it exists. |

## 3. OWASP Top 10 for LLM Applications (2025 names, VERIFY against 2026 edition)

| ID | Risk (our short name) | Agent Scan coverage | Milestone | Status | Notes |
|---|---|---|---|---|---|
| LLM01 | Prompt injection | Model output and retrieved content reaching tool sinks (flow analysis); hidden-text checks in prompts and rules files | M0 (flow), M1 (prompt and rules files) | PARTIAL | Direct and indirect injection are reported as flows. Whether a model can be steered is not decided statically, so those paths are *needs review*. |
| LLM02 | Sensitive information disclosure | Credentials and personal-data patterns in prompts, logs, and output paths; redaction of secrets in every output | M0 (secrets, redaction), M1 (personal-data patterns) | PARTIAL | Runtime data leaks are not seen. |
| LLM03 | Supply chain | Unpinned model and tool downloads; remote code loading; untrusted model sources in code | M1 | PARTIAL | Checks on the code and config side only. Registry and model provenance is GUIDANCE. |
| LLM04 | Data and model poisoning | Training or fine-tuning code that loads data from unverified URLs; retrieval sources with no integrity check | M2 | PARTIAL | Poisoned content itself is not detectable statically: GUIDANCE. |
| LLM05 | Improper output handling | Model output to shell, SQL, file, HTML, URL, and eval sinks | M0 | COVERED (for listed sinks) | Core check. Sink list is in the knowledge base and can be extended. |
| LLM06 | Excessive agency | Tools with no approval step; destructive tools; broad argument schemas; agents with more tools than their task | M0 | COVERED (for the listed patterns) | Approval-step detection depends on recognised approval patterns, stated in the report. |
| LLM07 | System prompt leakage | Secrets and sensitive rules embedded in system prompts; endpoints that return prompt text | M1 | PARTIAL | Endpoint behaviour at run time is not seen. |
| LLM08 | Vector and embedding weaknesses | Retrieval code that stores untrusted documents without source checks or access filters; missing tenant separation in stores | M2 | PARTIAL | Store configuration in the cloud is out of scope. |
| LLM09 | Misinformation | High-stakes model output used with no human review step | M1 | GUIDANCE | Correctness of content cannot be checked statically. The check finds missing review steps only. |
| LLM10 | Unbounded consumption | Agent loops with no step limit; model calls with no token or time limit; endpoints with no rate limit | M0 (loops), M1 (limits) | PARTIAL | Cost and load at run time not seen. |

## 4. OWASP Top 10 for Agentic Applications (ASI01 to ASI10, VERIFY names)

| ID | Risk (our short name) | Agent Scan coverage | Milestone | Status | Notes |
|---|---|---|---|---|---|
| ASI01 | Agent goal hijack | Untrusted content reaching the planner or system prompt; instruction text in retrieved content | M0 (flow), M1 (rules and prompts) | PARTIAL | As LLM01. |
| ASI02 | Tool misuse and exploitation | Tool arguments that accept unrestricted values; tools used with model-chosen arguments and no validation | M0 | COVERED (listed patterns) | Core check. |
| ASI03 | Identity and privilege abuse | Tools using broad or shared credentials; missing per-user scoping in tool calls | M0 (code), M1 (config) | PARTIAL | Identity provider state is out of scope. |
| ASI04 | Agentic supply chain vulnerabilities | Unpinned tools, MCP servers, and skills; tool descriptions that changed since approval (hash check) | M1 | PARTIAL | Hash check covers changes we were told about. |
| ASI05 | Unexpected code execution | Model output to exec, eval, shell, or code-interpreter sinks | M0 | COVERED | Same sink family as LLM05. |
| ASI06 | Memory and context poisoning | Memory or context stores written from untrusted content and read back into prompts | M2 | PARTIAL | Store contents at run time not seen. |
| ASI07 | Insecure inter-agent communication | Agent-to-agent calls with no authentication or message validation in code | M3 | PLANNED | Needs multi-agent flow model. |
| ASI08 | Cascading failures | Retries and fan-out with no limit; one agent's output feeding others without checks | M2 | PARTIAL | Run-time cascades not seen. |
| ASI09 | Human-agent trust exploitation | Missing confirmation before high-impact actions | M1 | GUIDANCE | Whether users trust the output is a human factor. The check finds missing confirmation steps. |
| ASI10 | Rogue agents | Agents with no kill switch, no logging of actions, or unbounded autonomy | M1 (code), M3 (run evidence) | PARTIAL | Behaviour at run time needs the claim checker and logs. |

## 5. OWASP Agentic Skills Top 10 (AST10)

**Status: not yet read.** Rows are added in M1 from the official list. Each item gets a row with the same columns as above,
before the M1 release gate. The build fails until every AST item has a row.

## 6. Third-party MCP server guidance

**Status: not yet read.** Each recommendation in the guide gets a row. Recommendations that concern the operator's
process (for example, review before approval) are GUIDANCE. Recommendations about configuration and code are COVERED or
PARTIAL, as for ASI04 and ASI03.

## 7. OWASP AI Exchange controls

**Status: not yet read.** The AI Exchange organises controls and threats. Each control is mapped to one of:
- a check in Agent Scan (COVERED or PARTIAL),
- a GUIDANCE item (printed in the report), or
- OUT OF SCOPE, with the reason (for example, data governance and model training processes).

The mapping is written before M0 closes. Controls are not dropped because they are hard to check.

## 8. Coverage summary (to be filled from sections 3 to 7)

| Source | Items | COVERED | PARTIAL | PLANNED | GUIDANCE | OUT OF SCOPE |
|---|---|---|---|---|---|---|
| LLM Top 10 | 10 | 2 | 7 | 0 | 1 | 0 |
| Agentic Top 10 | 10 | 2 | 6 | 1 | 1 | 0 |
| Agentic Skills Top 10 | pending | | | | | |
| MCP third-party guide | pending | | | | | |
| AI Exchange | pending | | | | | |

Counts for the first two rows follow from the tables above. Rows marked pending are filled before the release gate.

## 9. Rules that keep it complete

- **Gate:** the release build fails if a source in section 2 has an item without a row, or a row without a status.
- **Change watch:** the daily maintenance check (plan v4, section 7.3) compares each source's current item list against this file, and opens a task for any new, renamed, or removed item.
- **Test per COVERED row:** each COVERED row has at least one test program that the tool must flag, and one that it must not flag.
- **Honest reporting:** a report for an AI application lists the rows that apply to it, with each row's status, so a reader can see what was and was not checked.

## 10. Open items before the release gate

1. Read the 2026 LLM Top 10 edition and update section 3.
2. Read the Agentic Top 10 official page and confirm the names in section 4.
3. Read the AST10 list, the MCP third-party guide, and the AI Exchange controls, and add rows (sections 5 to 7).
4. Confirm whether an OWASP ML Security Top 10 exists. Add it if so.
5. Confirm the licence position for each source before any text or long reference is reproduced (plan v4, section 11).

# Agent Scan plan v3: licence-clean addendum

This replaces section 4 (building blocks), the licence parts of section 5, and the licence notes in section 12 of plan v2.
Everything else in v2 still applies.

## 1. The rule

**Use only components that are free to use and distribute, with no licence that adds obligations beyond keeping notices.**

Be precise about what "no obligations" means. Under the permissive licences we'd use (MIT, Apache-2.0, BSD, PSF), the
only obligation is to keep the copyright and licence notice in the distributed code. That is one `NOTICE` file, generated
from the SBOM. Nothing else is required. Components that need more than that are excluded:

| Excluded | Why |
|---|---|
| LGPL (Semgrep engine) | Obligations when distributing a modified library. Excluded. |
| Semgrep Registry rules | Restrict use in competing products. Excluded. We write our own rules. |
| CC BY 4.0 (GitHub Advisory Database) | Attribution required in every use. Excluded from the knowledge base. |
| CC BY-SA 4.0 (OWASP LLM Top 10) | Share-alike on derived text. Excluded: we don't copy or adapt its text. |
| MITRE ATLAS, CWE text | Licence not confirmed. Excluded until confirmed. We use CWE numbers only, which are identifiers. |
| CodeQL | Licence limited to open-source projects. Excluded. |

## 2. Components

| Component | Licence (source checked) | Status |
|---|---|---|
| tree-sitter core library | MIT (package metadata) | **Use.** Confirm against the repo LICENSE file before release. |
| tree-sitter-python grammar | MIT (package metadata, upstream repo link) | **Use.** Confirm the LICENSE file in the repo. |
| tree-sitter-c-sharp grammar | MIT (package metadata, upstream repo link) | **Use.** Confirm the LICENSE file. |
| tree-sitter-typescript grammar | To verify, per repo | **Hold** until checked (M2). |
| Python standard library | PSF licence (permissive) | **Use.** |
| LangChain (langchain, langchain-core) | MIT (PyPI metadata). Sub-packages may differ. | **Use** the packages we depend on, after checking each. |
| OpenAI Python SDK | Apache-2.0 for recent releases; some older releases listed as MIT (third-party packaging indexes) | **Use**, pinned to a release we have checked. |
| Anthropic Python SDK | Not confirmed in our checks | **Hold** until the LICENSE file is read. |
| SARIF output format | Specification and schema licence not confirmed | **Hold.** We write the output ourselves from the public format description, and do not copy schema files until the licence is checked. |
| Our own code | Chosen by us | **Recommend Apache-2.0** (permissive, with a patent grant), with a `NOTICE` file. |

Every dependency is pinned, and each release generates an SBOM and a `NOTICE` file from it.

## 3. Knowledge-base sources (no obligations)

| Source | How we use it | Obligation |
|---|---|---|
| Framework documentation and source code | Read to find function names and signatures. Facts about the API, not copied prose. | None beyond the framework's own licence, which we check per package (section 2). |
| CVE identifiers from NVD | Use the IDs and our own description | To verify: NVD terms before use. Most US government data is public domain; confirm. |
| CWE numbers | Use the number and our own short name | Identifiers only. Confirm MITRE terms before publishing names. |
| Our labelled test programs | Written by us, from scratch | None. Licensed as the repository. |
| Our own descriptions of weaknesses | Written by us | None. |

**Rule for entries:** every entry is written by us from primary API documentation, and checked by a test. No text is
copied from any rule set, advisory, or framework guidance. Source links are kept as references in the entry.

## 4. Consequences for the plan

- **Rules:** write our own rules. The rule format and the rules are ours, under Apache-2.0.
- **Advisory data:** use CVE IDs and NVD references only. No GitHub Advisory Database text.
- **Weakness references:** use CWE numbers and our own wording. No OWASP or ATLAS text, and no ATLAS IDs until confirmed.
- **Competitor analysis (section 12 of v2):** we read public product pages to compare features. We copy no text, rules,
  or code from them.
- **Obligations we accept:** one `NOTICE` file in each release, generated from the SBOM, and the licence text of each
  dependency included as the licence requires.

## 5. Still to verify before the first release

1. The LICENSE file in each repository listed as "use" in section 2 (tree-sitter core and grammars, LangChain packages, OpenAI SDK).
2. The Anthropic SDK licence, before it is used.
3. NVD terms for the CVE data we reference.
4. MITRE CWE terms for any use beyond the number.
5. The SARIF specification and schema licence, before any schema file is copied into the repository.

Until item 1 and item 2 are checked, the build should not include those dependencies. This is recorded as a release gate.

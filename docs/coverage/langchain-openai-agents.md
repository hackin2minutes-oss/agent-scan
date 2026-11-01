# Coverage check: LangChain, OpenAI SDK, OpenAI Agents SDK

Inventory taken from the installed packages on 2026-11-01:
- langchain-core 1.7.3
- openai 3.42.0
- openai-agents 0.24.0

Status key (from the OWASP coverage specification):
- **COVERED:** a knowledge-base entry and a test exist, and the scanner detects it.
- **PLANNED:** a milestone is named.
- **NOT DETECTABLE YET:** needs type information or taint tracking that the scanner does not have yet. The reason is given.
- **OUT OF SCOPE:** stated with the reason.

**Current result (version 0.0.1, after the executor and editor rules):** 7 framework items are COVERED. Added: the local
shell executor and the apply-patch editor, where model-chosen input reaches the tool's own code. Earlier: the Agents SDK runner's
unlimited turn limit (`max_turns=None`) and the approval step on `function_tool` tools that reach a sink. Also covered: the LangChain `tool` decorator, the
LangChain tool methods (`invoke`, `run`, `ainvoke`, `arun`), and the Agents SDK `function_tool` decorator with its
`on_invoke_tool` method. Each is backed by a knowledge-base entry and a test. Other framework items are still open, as marked below.

## 1. Tool execution: where model-chosen arguments run

| Surface | Role | Status | Reason / milestone |
|---|---|---|---|
| `langchain_core.tools.BaseTool.invoke` / `run` / `_run` (`ChildTool`) | Sink: runs a tool with arguments that may come from a model | NOT DETECTABLE YET | Method call on an object. Needs type inference to know the receiver is a tool. M0 follow-up. |
| `langchain_core.tools.tool` (decorator) | Definition: declares the tool and its argument schema | COVERED (typing only) | Makes the decorated name a tool, so its methods are sinks. Argument schemas are not read yet. |
| `langchain_core.tools.BaseToolkit` | Definition: groups tools | PLANNED (M1) | Counts the tools an agent receives (excessive agency). |
| `agents.tool.function_tool` | Definition: wraps a Python function as an agent tool | COVERED (typing only) | Same as the LangChain decorator. |
| `agents.tool.FunctionTool.on_invoke_tool` | Sink: runs the user function with model-chosen arguments | COVERED (for tools made with `function_tool`) | Same as the LangChain row. |
| `agents.tool.LocalShellTool` | Sink: model-chosen shell commands on the local machine | COVERED (for an executor function or method passed by name) | The executor's parameters are model output; a flow into a shell or eval sink is traced. An executor defined elsewhere is not followed. |
| `agents.tool.ShellToolLocalSkill`, `ShellToolInlineSkill` | Definition: shell skills and their sources | PLANNED (M1) | Skills are a supply-chain surface (ASI04). |
| `agents.tool.ComputerTool` | Permission: controls the screen and input | PLANNED (M1) | Safety-check hooks are recognised as guards. |
| `agents.tool.ApplyPatchTool` | Sink: applies model-written patches to files | COVERED (for an editor class passed as an instance, and a function passed by name) | The editor's methods receive model-chosen operations; a flow into a shell or eval sink is traced. File writes that use no sink are not reported. |
| `agents.tool.HostedMCPTool` | Permission: remote MCP server reachable from the agent | PLANNED (M1) | Tool descriptions are checked against approved hashes. |
| `agents.tool.FileSearchTool`, `WebSearchTool` | Source: retrieved content entering the context | PLANNED (M2) | Source for prompt injection (LLM01, ASI01). |
| `agents.tool.CodeInterpreterTool` | Hosted execution: runs code in the provider's sandbox | OUT OF SCOPE for local code execution | Execution is remote. Reported as a permission. |

## 2. Agent loops and guards

| Surface | Role | Status | Reason / milestone |
|---|---|---|---|
| `agents.run.Runner.run` / `run_sync` | Loop: runs an agent until it stops | COVERED (for an explicit `max_turns=None`) | A missing `max_turns` is not reported: the SDK's default is 10 turns. |
| `agents.guardrail` (input, output, and tool guardrails) | Guard: checks content before or after a model call | OUT OF SCOPE as a sanitiser | Decision: a guardrail is never credited as a sanitiser. Most guardrails are themselves model-based and can be steered, and the SDK does not state what a guardrail guarantees. A path through a guardrail is still reported. |
| `needs_approval` on `agents.tool.function_tool` | Guard: requires confirmation before a tool runs | COVERED (for tools whose body reaches a sink) | A tool reaching a sink with no approval, or with it set to False, is reported. A callable approval is not judged statically. |

## 3. Model output and content sources

| Surface | Role | Status | Reason / milestone |
|---|---|---|---|
| `openai` chat completions `tool_calls[].function.arguments` | Source: model-chosen arguments | NOT DETECTABLE YET | Needs taint tracking from the response into a sink. M0 flow analysis. |
| `openai` Responses API `function_call` items and their output | Source: model-chosen arguments | NOT DETECTABLE YET | Same as above. |
| Retrieved content (vector stores, web and file search results) | Source: untrusted content | PLANNED (M2) | LLM01, LLM08, ASI01. |

## 4. What the scanner needs to close the gaps

1. **Type information** for method calls on tool objects (NOT DETECTABLE YET rows). Without it, the scanner can only match
   module-level functions, which is why the framework rows stay open.
2. **Taint tracking** from a source (model response, retrieved content) to a sink. This is the M0 flow analysis.
3. **Entries** for each PLANNED row above, each with a reference and a passing test.

## 5. Known limits of the current checks

- Guardrails are never credited as sanitisers (see section 2). A flow through a guardrail is still reported.

- Receivers are typed per file, not per function: a name reused for something else in the same file may be wrongly typed.
- Only the two decorators above create typed tools. `StructuredTool.from_function` and similar constructors are not typed.
- Sink names come from the framework source as read at the time of the check. They have not yet been tested against the installed versions' behaviour.

## 6. Gate for M0

M0 does not close until every row in this document is COVERED, PLANNED with a milestone inside M0, or OUT OF SCOPE with a
stated reason. No row is left without a status.

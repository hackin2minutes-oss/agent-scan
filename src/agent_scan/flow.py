"""Intra-function taint tracking: a value from model output, or from untrusted content, reaching a sink.

Sources, sinks, sanitisers and parameter sources come from the knowledge base. The analysis is conservative and limited
on purpose:

- Scope: one function body at a time (module level is one scope). Values passed into or returned from another
  function are not followed, and the report says so.
- Propagation: an assignment whose right-hand side contains a tainted value makes the target tainted. Any reassignment
  with an untainted value clears the taint. Loops are read in source order once.
- A sanitiser call wrapping a sink argument directly breaks the path for that argument.
- Sources are: model output (the tool-call arguments of a model response), untrusted content fetched by a call in the
  knowledge base (for example an HTTP response body), and the parameters of functions the framework calls with
  model-chosen input.
- Sinks are: shell and eval sinks (rule tainted-value-to-sink), and model input (rule untrusted-content-to-model-input,
  for content that is fetched from outside and passed to a model, which is indirect prompt injection).
- The result is NEEDS_REVIEW, never a confirmed path: nothing in the code shows that an attacker controls the content.
"""

import ast

from agent_scan.scanner import NEEDS_REVIEW, Finding, _decorator_map, import_aliases, receiver_types, resolve_call_key

RULE = "tainted-value-to-sink"
RULE_MODEL_INPUT = "untrusted-content-to-model-input"
SOURCE_KIND = "source"
SANITISER_KIND = "sanitiser"


def _tokens(node: ast.AST) -> list[str] | None:
    """Dotted tokens of an attribute chain such as response.choices[].function.arguments, or None."""
    parts: list[str] = []
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Subscript):
            parts.append("[]")
            node = node.value
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            return list(reversed(parts))
        else:
            return None


def load_flow_knowledge(entries: list[dict]) -> dict:
    """Source suffixes, sanitiser keys, parameter sources, untrusted-content calls and model-input sinks."""
    sources, sanitisers, parameter_sources = [], set(), {}
    untrusted, prompt_sinks = set(), set()
    for entry in entries:
        kind = entry.get("kind")
        if kind == SOURCE_KIND:
            sources.append(tuple(entry["pattern"].split(".")))
        elif kind == SANITISER_KIND:
            for function in entry.get("functions", []):
                sanitisers.add((entry.get("module"), function))
        elif kind == "parameter_source":
            for function in entry.get("functions", []):
                parameter_sources[(entry.get("module"), function)] = entry["keyword"]
        elif kind == "untrusted_call":
            for function in entry.get("functions", []):
                untrusted.add((entry.get("module"), function))
        elif kind == "prompt_sink":
            for function in entry.get("functions", []):
                prompt_sinks.add((entry.get("module"), function))
    return {"sources": sources, "sanitisers": sanitisers, "parameter_sources": parameter_sources,
            "untrusted": untrusted, "prompt_sinks": prompt_sinks}


def _executor_functions(tree: ast.Module, aliases: dict, parameter_sources: dict) -> dict[int, str]:
    """Functions whose parameters receive model-chosen input, keyed by the function node's identity.

    A function passed by name is one. An editor class passed as an instance (editor=Editor()) contributes each of its
    methods except __init__. The description names the framework call that receives them."""
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    functions = {node.name: node for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    found: dict[int, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        key = resolve_call_key(node, aliases)
        if key not in parameter_sources:
            continue
        keyword = parameter_sources[key]
        for argument in node.keywords:
            if argument.arg != keyword:
                continue
            description = f"{key[1]}({keyword}=...)"
            value = argument.value
            if isinstance(value, ast.Name) and value.id in functions:
                found[id(functions[value.id])] = description
            elif isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in classes:
                for method in classes[value.func.id].body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name != "__init__":
                        found[id(method)] = description
    return found


def _source_trace(expr: ast.AST, sources) -> list[str] | None:
    for node in ast.walk(expr):
        if isinstance(node, ast.Attribute):
            tokens = _tokens(node)
            if tokens and any(tuple(tokens[-len(s):]) == s for s in sources if len(tokens) >= len(s)):
                return [f"line {node.lineno}: model output read from .{'.'.join(tokens[-2:])}"]
    return None


def _untrusted_trace(expr: ast.AST, aliases: dict, types: dict, untrusted: set) -> list[str] | None:
    for node in ast.walk(expr):
        if isinstance(node, ast.Call):
            key = resolve_call_key(node, aliases, types)
            if key in untrusted:
                return [f"line {node.lineno}: untrusted content fetched by {key[0] + '.' if key[0] else ''}{key[1]}()"]
    return None


def _taint_of(expr: ast.AST, tainted: dict, sources, knowledge: dict, aliases: dict, types: dict):
    source = _source_trace(expr, sources)
    if source:
        return source
    fetched = _untrusted_trace(expr, aliases, types, knowledge["untrusted"])
    if fetched:
        return fetched
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in tainted:
            return tainted[node.id]
    return None


def _scopes(tree: ast.Module):
    yield tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _scope_events(scope):
    """Assignments and calls of one scope, in source order, without descending into nested functions."""
    events = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.Assign, ast.Call)):
            events.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return sorted(events, key=lambda n: (n.lineno, n.col_offset, 0 if isinstance(n, ast.Assign) else 1))


def _label(key) -> str:
    return key[1] if key[0] is None else f"{key[0]}.{key[1]}"


def scan_flows(tree: ast.Module, rel_path: str, sinks: set, knowledge: dict) -> list[Finding]:
    sources = knowledge["sources"]
    sanitisers = knowledge["sanitisers"]
    prompt_sinks = knowledge.get("prompt_sinks", set())
    findings: list[Finding] = []
    if not sources and not knowledge.get("untrusted") and not prompt_sinks:
        return findings
    aliases = import_aliases(tree)
    types = receiver_types(tree, aliases, _decorator_map())
    executors = _executor_functions(tree, aliases, knowledge.get("parameter_sources", {}))
    for scope in _scopes(tree):
        tainted: dict[str, list[str]] = {}
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(scope) in executors:
            for argument in scope.args.args:
                if argument.arg != "self":
                    tainted[argument.arg] = [
                        f"line {scope.lineno}: parameter {argument.arg} of {scope.name}, which receives "
                        f"model-chosen input through {executors[id(scope)]}"]
        for event in _scope_events(scope):
            if isinstance(event, ast.Assign):
                trace = _taint_of(event.value, tainted, sources, knowledge, aliases, types)
                for target in event.targets:
                    if isinstance(target, ast.Name):
                        if trace:
                            tainted[target.id] = trace + [f"line {event.lineno}: assigned to {target.id}"]
                        else:
                            tainted.pop(target.id, None)
                continue
            key = resolve_call_key(event, aliases, types)
            if key is None:
                continue
            if key in prompt_sinks:
                rule, reason = RULE_MODEL_INPUT, (
                    f"content fetched from outside reaches the model through {_label(key)}; a page or file can "
                    "carry instructions the model follows (indirect prompt injection)")
                missing = ["whether the fetched content is trusted by the application's design",
                           "whether the model's tools can act on what the content asks",
                           "data flow across function boundaries (not followed)"]
            elif key in sinks:
                rule, reason = RULE, (
                    f"model output reaches {_label(key)} in the same function; whether an attacker can influence "
                    "the model output is not established")
                missing = ["whether untrusted content can reach the model input (prompt injection)",
                           "validation or sanitisation between the source and the sink, if any",
                           "data flow across function boundaries (not followed)"]
            else:
                continue
            for argument in event.args:
                if isinstance(argument, ast.Call) and resolve_call_key(argument, aliases, types) in sanitisers:
                    continue
                trace = _taint_of(argument, tainted, sources, knowledge, aliases, types)
                if trace:
                    findings.append(Finding(
                        rule=rule,
                        path=rel_path,
                        line=event.lineno,
                        verdict=NEEDS_REVIEW,
                        reason=reason,
                        missing=list(missing),
                        trace=trace + [f"line {event.lineno}: reaches the sink"],
                    ))
                    break
    return findings

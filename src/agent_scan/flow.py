"""Intra-function taint tracking: a value from model output reaching a sink in the same function.

Sources, sinks and sanitisers come from the knowledge base. The analysis is conservative and limited on purpose:

- Scope: one function body at a time (module level is one scope). Values passed into or returned from another
  function are not followed, and the report says so.
- Propagation: an assignment whose right-hand side contains a tainted value makes the target tainted. Any
  reassignment with an untainted value clears the taint. Loops are read in source order once.
- A sanitiser call wrapping a sink argument directly breaks the path for that argument.
- The result is NEEDS_REVIEW, never a confirmed path: the knowledge base says model output is a source, but nothing
  in the code shows that an attacker controls it. The trace is reported so a reviewer can follow it.
"""

import ast
from pathlib import Path

from agent_scan.scanner import NEEDS_REVIEW, Finding, _decorator_map, import_aliases, receiver_types, resolve_call_key

RULE = "tainted-value-to-sink"
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
    """Source suffixes, sanitiser keys and parameter sources, from knowledge-base entries.

    A parameter source is a call that hands a function to the framework, which then calls it with model-chosen input.
    The keyword names the argument that receives the function, so the function's parameters are tainted."""
    sources = []
    sanitisers = set()
    parameter_sources = {}
    for entry in entries:
        if entry.get("kind") == SOURCE_KIND:
            sources.append(tuple(entry["pattern"].split(".")))
        elif entry.get("kind") == SANITISER_KIND:
            for function in entry.get("functions", []):
                sanitisers.add((entry.get("module"), function))
        elif entry.get("kind") == "parameter_source":
            for function in entry.get("functions", []):
                parameter_sources[(entry.get("module"), function)] = entry["keyword"]
    return {"sources": sources, "sanitisers": sanitisers, "parameter_sources": parameter_sources}


def _executor_functions(tree: ast.Module, aliases: dict, parameter_sources: dict) -> dict[str, str]:
    """Names of functions handed to a parameter source, mapped to the framework call that receives them."""
    names = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        key = resolve_call_key(node, aliases)
        if key not in parameter_sources:
            continue
        keyword = parameter_sources[key]
        for argument in node.keywords:
            if argument.arg == keyword and isinstance(argument.value, ast.Name):
                names[argument.value.id] = f"{key[1]}({keyword}=...)"
    return names


def _source_trace(expr: ast.AST, sources) -> list[str] | None:
    for node in ast.walk(expr):
        if isinstance(node, ast.Attribute):
            tokens = _tokens(node)
            if tokens and any(tuple(tokens[-len(s):]) == s for s in sources if len(tokens) >= len(s)):
                return [f"line {node.lineno}: model output read from .{'.'.join(tokens[-2:])}"]
    return None


def _taint_of(expr: ast.AST, tainted: dict, sources) -> list[str] | None:
    source = _source_trace(expr, sources)
    if source:
        return source
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


def scan_flows(tree: ast.Module, rel_path: str, sinks: set, knowledge: dict) -> list[Finding]:
    sources = knowledge["sources"]
    sanitisers = knowledge["sanitisers"]
    findings: list[Finding] = []
    if not sources:
        return findings
    aliases = import_aliases(tree)
    types = receiver_types(tree, aliases, _decorator_map())
    executors = _executor_functions(tree, aliases, knowledge.get("parameter_sources", {}))
    for scope in _scopes(tree):
        tainted: dict[str, list[str]] = {}
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and scope.name in executors:
            for argument in scope.args.args:
                if argument.arg != "self":
                    tainted[argument.arg] = [
                        f"line {scope.lineno}: parameter {argument.arg} of {scope.name}, which receives "
                        f"model-chosen input through {executors[scope.name]}"]
        for event in _scope_events(scope):
            if isinstance(event, ast.Assign):
                trace = _taint_of(event.value, tainted, sources)
                for target in event.targets:
                    if isinstance(target, ast.Name):
                        if trace:
                            tainted[target.id] = trace + [f"line {event.lineno}: assigned to {target.id}"]
                        else:
                            tainted.pop(target.id, None)
                continue
            key = resolve_call_key(event, aliases, types)
            if key is None or key not in sinks:
                continue
            for argument in event.args:
                if isinstance(argument, ast.Call) and resolve_call_key(argument, aliases, types) in sanitisers:
                    continue
                trace = _taint_of(argument, tainted, sources)
                if trace:
                    findings.append(Finding(
                        rule=RULE,
                        path=rel_path,
                        line=event.lineno,
                        verdict=NEEDS_REVIEW,
                        reason=(f"model output reaches {key[1] if key[0] is None else key[0] + '.' + key[1]} "
                                "in the same function; whether an attacker can influence the model output is not "
                                "established"),
                        missing=["whether untrusted content can reach the model input (prompt injection)",
                                 "validation or sanitisation between the source and the sink, if any",
                                 "data flow across function boundaries (not followed)"],
                        trace=trace + [f"line {event.lineno}: reaches the sink"],
                    ))
                    break
    return findings

#!/usr/bin/env python3
"""Fail when the reviewed guest-facing host-transition inventory drifts.

The scanner is deliberately token based. Rust ``use`` declarations are lexical
items, so a file-global regular-expression match both misses multiline imports
and leaks block-local aliases into later code. This module performs the small
amount of Rust parsing needed by the inventory: comments/literals, balanced
token trees, cfg predicates, brace scopes, use trees, and call paths.
"""

from __future__ import annotations

import itertools
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, NamedTuple


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "scripts/migrate/host-authority-transition-inventory.json"
SOURCE_ROOTS = (
    Path("crates/carrick-runtime/src"),
    Path("crates/carrick-vmm-hvf/src"),
)


def _operation_table() -> dict[tuple[str, ...], tuple[str, str]]:
    operations: dict[tuple[str, ...], tuple[str, str]] = {}

    def add(kind: str, prefix: tuple[str, ...], names: tuple[str, ...]) -> None:
        for name in names:
            path = (*prefix, name)
            operations[path] = (kind, "::".join(path))

    add("host_identity", ("std", "process"), ("id",))
    add(
        "host_identity",
        ("libc",),
        (
            "getpid",
            "getppid",
            "getpgrp",
            "getsid",
            "getuid",
            "geteuid",
            "getgid",
            "getegid",
            "getgroups",
            "getrlimit",
            "setrlimit",
        ),
    )
    add(
        "host_process_control",
        ("libc",),
        ("fork", "wait4", "waitid", "kill", "killpg", "pthread_kill"),
    )
    add(
        "host_namespace_view",
        ("libc",),
        ("getifaddrs", "gethostname", "getaddrinfo"),
    )
    add(
        "ambient_filesystem",
        ("std", "fs"),
        (
            "canonicalize",
            "copy",
            "create_dir",
            "create_dir_all",
            "exists",
            "hard_link",
            "metadata",
            "read",
            "read_dir",
            "read_link",
            "read_to_string",
            "remove_dir",
            "remove_dir_all",
            "remove_file",
            "rename",
            "set_permissions",
            "soft_link",
            "symlink_metadata",
            "write",
        ),
    )
    add(
        "ambient_filesystem",
        ("std", "fs", "File"),
        ("open", "create", "create_new"),
    )
    add("ambient_filesystem", ("std", "fs", "OpenOptions"), ("new",))
    add(
        "ambient_network",
        ("std", "net", "TcpStream"),
        ("connect", "connect_timeout"),
    )
    add("ambient_network", ("std", "net", "TcpListener"), ("bind",))
    add("ambient_network", ("std", "net", "UdpSocket"), ("bind", "connect"))
    add(
        "carrier_substrate",
        ("std", "thread"),
        ("spawn", "sleep", "yield_now"),
    )
    add("carrier_substrate", ("std", "thread", "Builder"), ("new",))
    operations[("applevisor_sys", "hv_vcpus_exit")] = (
        "carrier_substrate",
        "applevisor_sys::hv_vcpus_exit",
    )
    # Some call sites receive this FFI symbol from a generated/prelude import.
    # It still inventories only when it is syntactically called.
    operations[("hv_vcpus_exit",)] = ("carrier_substrate", "hv_vcpus_exit")
    return operations


OPERATIONS = _operation_table()
CLASSIFICATIONS = {
    "forbidden_semantic",
    "declared_substrate",
    "declared_backing",
    "legacy_unreachable",
}
AUTHORITIES = {
    "forbidden_semantic": {"guest_answer", "host_target"},
    "declared_substrate": {"authenticated_carrier"},
    "declared_backing": {"authorized_backing"},
    "legacy_unreachable": {
        "compile_time_exclusion",
        "standalone_target_exclusion",
    },
}
BANNED_REVIEW_FRAGMENTS = (
    "concrete operation form:",
    "guest-visible process state",
    "carrick created that resource",
    "pre-authorized backing object",
    "performs a carrier-side",
)
GENERIC_RESOURCES = {
    "authenticated carrier",
    "authorized backing",
    "backing object",
    "carrier resource",
    "compile time exclusion",
    "filesystem operation",
    "guest answer",
    "host resource",
    "host target",
    "network operation",
    "process state",
    "runtime resource",
    "standalone target exclusion",
}
DISJUNCTION = re.compile(r"\b(?:or|versus)\b", re.IGNORECASE)
REVIEW_FIELDS = {"classification", "evidence", "rationale"}


class InventoryError(Exception):
    """The source inventory and its review state do not agree."""


class Token(NamedTuple):
    value: str
    start: int
    end: int
    line: int
    kind: str


def _raw_string_end(source: str, index: int) -> int | None:
    for prefix in ("br", "cr", "r"):
        if not source.startswith(prefix, index):
            continue
        cursor = index + len(prefix)
        while cursor < len(source) and source[cursor] == "#":
            cursor += 1
        if cursor >= len(source) or source[cursor] != '"':
            continue
        hashes = cursor - index - len(prefix)
        delimiter = '"' + ("#" * hashes)
        end = source.find(delimiter, cursor + 1)
        return len(source) if end == -1 else end + len(delimiter)
    return None


def _quoted_literal_end(source: str, index: int) -> int | None:
    quote_index = index
    if source.startswith(('b"', 'c"'), index):
        quote_index += 1
    if quote_index >= len(source) or source[quote_index] != '"':
        return None
    cursor = quote_index + 1
    while cursor < len(source):
        if source[cursor] == "\\":
            cursor += 2
        elif source[cursor] == '"':
            return cursor + 1
        else:
            cursor += 1
    return len(source)


def _character_literal_end(source: str, index: int) -> int | None:
    quote_index = index + 1 if source.startswith("b'", index) else index
    if quote_index >= len(source) or source[quote_index] != "'":
        return None
    cursor = quote_index + 1
    if cursor >= len(source):
        return None
    if source[cursor] == "\\":
        cursor += 2
        while cursor < len(source) and source[cursor] != "'":
            cursor += 1
    else:
        cursor += 1
    return cursor + 1 if cursor < len(source) and source[cursor] == "'" else None


def rust_tokens(source: str) -> list[Token]:
    """Tokenize the Rust surface needed for balanced scope and call analysis."""
    tokens: list[Token] = []
    index = 0
    line = 1
    while index < len(source):
        char = source[index]
        if char.isspace():
            if char == "\n":
                line += 1
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline == -1 else newline
            continue
        if source.startswith("/*", index):
            cursor = index + 2
            depth = 1
            while cursor < len(source) and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            line += source.count("\n", index, cursor)
            index = cursor
            continue
        literal_end = (
            _raw_string_end(source, index)
            or _quoted_literal_end(source, index)
            or _character_literal_end(source, index)
        )
        if literal_end is not None:
            tokens.append(Token(source[index:literal_end], index, literal_end, line, "literal"))
            line += source.count("\n", index, literal_end)
            index = literal_end
            continue
        if source.startswith("r#", index) and index + 2 < len(source):
            cursor = index + 2
            if source[cursor].isalpha() or source[cursor] == "_":
                cursor += 1
                while cursor < len(source) and (
                    source[cursor].isalnum() or source[cursor] == "_"
                ):
                    cursor += 1
                tokens.append(Token(source[index + 2 : cursor], index, cursor, line, "ident"))
                index = cursor
                continue
        if char.isalpha() or char == "_":
            cursor = index + 1
            while cursor < len(source) and (
                source[cursor].isalnum() or source[cursor] == "_"
            ):
                cursor += 1
            tokens.append(Token(source[index:cursor], index, cursor, line, "ident"))
            index = cursor
            continue
        if source.startswith("::", index):
            tokens.append(Token("::", index, index + 2, line, "punct"))
            index += 2
            continue
        tokens.append(Token(char, index, index + 1, line, "punct"))
        index += 1
    return tokens


def _matching_delimiter(tokens: list[Token], start: int) -> int | None:
    pairs = {"(": ")", "[": "]", "{": "}"}
    opening = tokens[start].value
    closing = pairs.get(opening)
    if closing is None:
        return None
    stack = [closing]
    for index in range(start + 1, len(tokens)):
        value = tokens[index].value
        if value in pairs:
            stack.append(pairs[value])
        elif stack and value == stack[-1]:
            stack.pop()
            if not stack:
                return index
    return None


CfgNode = tuple[str, object]


def _parse_cfg_expression(
    tokens: list[Token], index: int, end: int
) -> tuple[CfgNode, int] | None:
    if index >= end or tokens[index].kind != "ident":
        return None
    name = tokens[index].value
    index += 1
    if index < end and tokens[index].value == "=":
        if index + 1 >= end:
            return None
        value = tokens[index + 1].value
        return ("atom", f"{name}={value}"), index + 2
    if index >= end or tokens[index].value != "(":
        return ("atom", name), index
    close = _matching_delimiter(tokens, index)
    if close is None or close >= end:
        return None
    cursor = index + 1
    children: list[CfgNode] = []
    while cursor < close:
        parsed = _parse_cfg_expression(tokens, cursor, close)
        if parsed is None:
            return None
        child, cursor = parsed
        children.append(child)
        if cursor < close:
            if tokens[cursor].value != ",":
                return None
            cursor += 1
    if name not in {"all", "any", "not"}:
        rendered = "".join(token.value for token in tokens[index - 1 : close + 1])
        return ("atom", rendered), close + 1
    if name == "not" and len(children) != 1:
        return None
    return (name, tuple(children)), close + 1


def _cfg_eval(node: CfgNode, values: dict[str, bool]) -> bool:
    operator, payload = node
    if operator == "atom":
        return values.get(str(payload), False)
    children = payload
    assert isinstance(children, tuple)
    if operator == "all":
        return all(_cfg_eval(child, values) for child in children)
    if operator == "any":
        return any(_cfg_eval(child, values) for child in children)
    if operator == "not":
        return not _cfg_eval(children[0], values)
    raise AssertionError(f"unknown cfg operator: {operator}")


def _cfg_atoms(node: CfgNode) -> set[str]:
    operator, payload = node
    if operator == "atom":
        return {str(payload)}
    children = payload
    assert isinstance(children, tuple)
    return set().union(*(_cfg_atoms(child) for child in children)) if children else set()


def _cfg_attribute_implies_test(tokens: list[Token]) -> bool:
    if len(tokens) < 3 or tokens[0].value != "cfg" or tokens[1].value != "(":
        return False
    close = _matching_delimiter(tokens, 1)
    if close is None or close != len(tokens) - 1:
        return False
    parsed = _parse_cfg_expression(tokens, 2, close)
    if parsed is None or parsed[1] != close:
        return False
    expression = parsed[0]
    atoms = sorted(_cfg_atoms(expression) - {"test"})
    # Exact enumeration preserves repeated atom correlation, for example
    # ``all(any(test, x), not(x))``.
    for assignment in itertools.product((False, True), repeat=len(atoms)):
        values = dict(zip(atoms, assignment, strict=True))
        values["test"] = False
        if _cfg_eval(expression, values):
            return False
    return True


def _attribute(
    tokens: list[Token], index: int
) -> tuple[int, bool, list[Token]] | None:
    if index >= len(tokens) or tokens[index].value != "#":
        return None
    cursor = index + 1
    inner = cursor < len(tokens) and tokens[cursor].value == "!"
    if inner:
        cursor += 1
    if cursor >= len(tokens) or tokens[cursor].value != "[":
        return None
    close = _matching_delimiter(tokens, cursor)
    if close is None:
        return None
    return close + 1, inner, tokens[cursor + 1 : close]


def _skip_visibility(tokens: list[Token], index: int) -> int:
    if index >= len(tokens) or tokens[index].value != "pub":
        return index
    index += 1
    if index < len(tokens) and tokens[index].value == "(":
        close = _matching_delimiter(tokens, index)
        return len(tokens) if close is None else close + 1
    return index


def _attributed_items(
    tokens: list[Token],
) -> list[tuple[int, list[tuple[bool, list[Token]]]]]:
    """Return each attributed item's token index and its complete attributes."""
    items: list[tuple[int, list[tuple[bool, list[Token]]]]] = []
    index = 0
    while index < len(tokens):
        if _attribute(tokens, index) is None:
            index += 1
            continue
        cursor = index
        attributes: list[tuple[bool, list[Token]]] = []
        while True:
            parsed = _attribute(tokens, cursor)
            if parsed is None:
                break
            cursor, inner, body = parsed
            attributes.append((inner, body))
        items.append((_skip_visibility(tokens, cursor), attributes))
        index = max(cursor, index + 1)
    return items


def _attributes_imply_test(attributes: list[tuple[bool, list[Token]]]) -> bool:
    return any(
        not inner and _cfg_attribute_implies_test(body)
        for inner, body in attributes
    )


def _cfg_predicate_text(attributes: list[tuple[bool, list[Token]]]) -> str | None:
    for inner, body in attributes:
        if inner or len(body) < 3 or body[0].value != "cfg" or body[1].value != "(":
            continue
        close = _matching_delimiter(body, 1)
        if close == len(body) - 1:
            return "".join(token.value for token in body[2:close])
    return None


def test_only_module_ranges(tokens: list[Token]) -> list[tuple[int, int]]:
    """Return token-index ranges for inline modules whose cfg requires test."""
    ranges: list[tuple[int, int]] = []
    for item, attributes in _attributed_items(tokens):
        if not _attributes_imply_test(attributes):
            continue
        if item < len(tokens) and tokens[item].value == "mod":
            item += 1
            if item < len(tokens) and tokens[item].kind == "ident":
                item += 1
                if item < len(tokens) and tokens[item].value == "{":
                    close = _matching_delimiter(tokens, item)
                    if close is not None:
                        ranges.append((item, close))
    return ranges


def _item_end(tokens: list[Token], start: int) -> int | None:
    stack: list[str] = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    for index in range(start, len(tokens)):
        value = tokens[index].value
        if value in pairs:
            stack.append(pairs[value])
        elif stack and value == stack[-1]:
            stack.pop()
            if not stack and value == "}":
                return index
        elif value == ";" and not stack:
            return index
    return None


def test_only_item_ranges(tokens: list[Token]) -> list[tuple[int, int]]:
    """Return complete attributed items/statements unavailable in production."""
    ranges: list[tuple[int, int]] = []
    index = 0
    while index < len(tokens):
        if _attribute(tokens, index) is None:
            index += 1
            continue
        cursor = index
        attributes: list[tuple[bool, list[Token]]] = []
        while True:
            parsed = _attribute(tokens, cursor)
            if parsed is None:
                break
            cursor, inner, body = parsed
            attributes.append((inner, body))
        item = _skip_visibility(tokens, cursor)
        if _attributes_imply_test(attributes):
            end = _item_end(tokens, item)
            if end is not None:
                ranges.append((index, end))
        index = max(cursor, index + 1)
    return ranges


def _without_ranges(tokens: list[Token], ranges: list[tuple[int, int]]) -> list[Token]:
    if not ranges:
        return tokens
    ranges = sorted(ranges)
    result: list[Token] = []
    range_index = 0
    for index, token in enumerate(tokens):
        while range_index < len(ranges) and index > ranges[range_index][1]:
            range_index += 1
        if range_index < len(ranges):
            start, end = ranges[range_index]
            if start <= index <= end:
                continue
        result.append(token)
    return result


def _scope_map(tokens: list[Token]) -> tuple[list[int], list[dict[str, object]]]:
    scopes: list[dict[str, object]] = [
        {"parent": None, "aliases": {}, "globs": [], "value_bindings": {}}
    ]
    stack = [0]
    scope_for_token: list[int] = []
    for token in tokens:
        scope_for_token.append(stack[-1])
        if token.value == "{":
            scopes.append(
                {
                    "parent": stack[-1],
                    "aliases": {},
                    "globs": [],
                    "value_bindings": {},
                }
            )
            stack.append(len(scopes) - 1)
        elif token.value == "}" and len(stack) > 1:
            stack.pop()
    return scope_for_token, scopes


def _parse_use_tree(
    tokens: list[Token],
) -> tuple[dict[str, set[tuple[str, ...]]], list[tuple[str, ...]]]:
    aliases: dict[str, set[tuple[str, ...]]] = {}
    globs: list[tuple[str, ...]] = []

    def group(index: int, end: int, prefix: tuple[str, ...]) -> int:
        while index < end and tokens[index].value != "}":
            before = index
            index = branch(index, end, prefix)
            if index == before:
                return end
            if index < end and tokens[index].value == ",":
                index += 1
            elif index < end and tokens[index].value != "}":
                return end
        return index + 1 if index < end and tokens[index].value == "}" else index

    def branch(index: int, end: int, prefix: tuple[str, ...]) -> int:
        if index < end and tokens[index].value == "::":
            index += 1
        if index < end and tokens[index].value == "{":
            return group(index + 1, end, prefix)
        if index < end and tokens[index].value == "*":
            globs.append(prefix)
            return index + 1
        segments: list[str] = []
        while index < end and tokens[index].kind == "ident":
            segments.append(tokens[index].value)
            index += 1
            if index >= end or tokens[index].value != "::":
                break
            index += 1
            if index < end and tokens[index].value == "{":
                return group(index + 1, end, (*prefix, *segments))
            if index < end and tokens[index].value == "*":
                globs.append((*prefix, *segments))
                return index + 1
        if not segments:
            return index
        if segments == ["self"]:
            canonical = prefix
            default_alias = prefix[-1] if prefix else "self"
        else:
            canonical = (*prefix, *segments)
            default_alias = segments[-1]
        alias = default_alias
        if index < end and tokens[index].value == "as":
            index += 1
            if index >= end or tokens[index].kind != "ident":
                return end
            alias = tokens[index].value
            index += 1
        if alias != "_" and canonical:
            aliases.setdefault(alias, set()).add(canonical)
        return index

    group(0, len(tokens), ())
    return aliases, globs


def _use_end(tokens: list[Token], start: int) -> int | None:
    stack: list[str] = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    for index in range(start, len(tokens)):
        value = tokens[index].value
        if value in pairs:
            stack.append(pairs[value])
        elif stack and value == stack[-1]:
            stack.pop()
        elif value == ";" and not stack:
            return index
    return None


def _collect_imports(
    tokens: list[Token], scope_for_token: list[int], scopes: list[dict[str, object]]
) -> None:
    for index, token in enumerate(tokens):
        if token.value != "use" or token.kind != "ident":
            continue
        end = _use_end(tokens, index + 1)
        if end is None:
            continue
        aliases, globs = _parse_use_tree(tokens[index + 1 : end])
        scope = scopes[scope_for_token[index]]
        scope_aliases = scope["aliases"]
        scope_globs = scope["globs"]
        assert isinstance(scope_aliases, dict)
        assert isinstance(scope_globs, list)
        for alias, paths in aliases.items():
            existing = scope_aliases.setdefault(alias, set())
            assert isinstance(existing, set)
            existing.update(paths)
        scope_globs.extend(globs)


def _collect_value_bindings(
    tokens: list[Token], scope_for_token: list[int], scopes: list[dict[str, object]]
) -> None:
    """Record lexical let bindings that shadow imported function values."""
    ignored = {"mut", "ref", "self", "Self", "crate", "super"}
    for index, token in enumerate(tokens):
        if token.value != "let" or token.kind != "ident":
            continue
        end = _use_end(tokens, index + 1)
        if end is None:
            continue
        pattern_end = end
        stack: list[str] = []
        pairs = {"(": ")", "[": "]", "{": "}"}
        for cursor in range(index + 1, end):
            value = tokens[cursor].value
            if value in pairs:
                stack.append(pairs[value])
            elif stack and value == stack[-1]:
                stack.pop()
            elif not stack and value in {"=", ":"}:
                pattern_end = cursor
                break
        names: set[str] = set()
        for cursor in range(index + 1, pattern_end):
            candidate = tokens[cursor]
            if candidate.kind != "ident" or candidate.value in ignored:
                continue
            if candidate.value == "_" or not candidate.value[0].islower():
                continue
            if cursor > index + 1 and tokens[cursor - 1].value == "::":
                continue
            if cursor + 1 < pattern_end and tokens[cursor + 1].value == "::":
                continue
            names.add(candidate.value)
        bindings = scopes[scope_for_token[index]]["value_bindings"]
        assert isinstance(bindings, dict)
        for name in names:
            activations = bindings.setdefault(name, [])
            assert isinstance(activations, list)
            activations.append(end)


def _scope_chain(scope_id: int, scopes: list[dict[str, object]]) -> list[int]:
    chain: list[int] = []
    current: int | None = scope_id
    while current is not None:
        chain.append(current)
        parent = scopes[current]["parent"]
        assert parent is None or isinstance(parent, int)
        current = parent
    return chain


def _canonical_paths(
    path: tuple[str, ...],
    scope_id: int,
    scopes: list[dict[str, object]],
    call_index: int,
) -> set[tuple[str, ...]]:
    results: set[tuple[str, ...]] = set()

    def expand(candidate: tuple[str, ...], seen: frozenset[str]) -> None:
        if not candidate:
            return
        first = candidate[0]
        if first == "self" and len(candidate) > 1:
            expand(candidate[1:], seen | {"self"})
            return
        if first in seen:
            results.add(candidate)
            return
        for current in _scope_chain(scope_id, scopes):
            if len(candidate) == 1:
                bindings = scopes[current]["value_bindings"]
                assert isinstance(bindings, dict)
                activations = bindings.get(first, [])
                assert isinstance(activations, list)
                if any(activation < call_index for activation in activations):
                    return
            aliases = scopes[current]["aliases"]
            assert isinstance(aliases, dict)
            replacements = aliases.get(first)
            if isinstance(replacements, set):
                for replacement in replacements:
                    expand((*replacement, *candidate[1:]), seen | {first})
                return
        results.add(candidate)
        for current in _scope_chain(scope_id, scopes):
            globs = scopes[current]["globs"]
            assert isinstance(globs, list)
            for prefix in globs:
                assert isinstance(prefix, tuple)
                expand((*prefix, *candidate), seen | {first})

    expand(path, frozenset())
    return results


def _matching_open(tokens: list[Token], close: int) -> int | None:
    pairs = {")": "(", "]": "[", "}": "{"}
    closing = tokens[close].value
    opening = pairs.get(closing)
    if opening is None:
        return None
    stack = [opening]
    for index in range(close - 1, -1, -1):
        value = tokens[index].value
        if value in pairs:
            stack.append(pairs[value])
        elif stack and value == stack[-1]:
            stack.pop()
            if not stack:
                return index
    return None


def _path_range(
    tokens: list[Token], start: int, end: int
) -> tuple[tuple[str, ...], int] | None:
    while start < end and tokens[start].value == "(" and tokens[end - 1].value == ")":
        close = _matching_delimiter(tokens, start)
        if close != end - 1:
            break
        start += 1
        end -= 1
    if start >= end or tokens[start].kind != "ident":
        return None
    parts = [tokens[start].value]
    cursor = start + 1
    while cursor < end:
        if (
            cursor + 1 >= end
            or tokens[cursor].value != "::"
            or tokens[cursor + 1].kind != "ident"
        ):
            return None
        parts.append(tokens[cursor + 1].value)
        cursor += 2
    return tuple(parts), start


def _call_path(
    tokens: list[Token], call_index: int
) -> tuple[tuple[str, ...], int] | None:
    index = call_index - 1
    if index >= 0 and tokens[index].value == ")":
        opening = _matching_open(tokens, index)
        if opening is None:
            return None
        return _path_range(tokens, opening + 1, index)
    if index >= 0 and tokens[index].value == ">":
        depth = 1
        index -= 1
        while index >= 0 and depth:
            if tokens[index].value == ">":
                depth += 1
            elif tokens[index].value == "<":
                depth -= 1
            index -= 1
        if depth or index < 0 or tokens[index].value != "::":
            return None
        index -= 1
    if index < 0 or tokens[index].kind != "ident":
        return None
    parts = [tokens[index].value]
    start = index
    while (
        start >= 2
        and tokens[start - 1].value == "::"
        and tokens[start - 2].kind == "ident"
    ):
        start -= 2
        parts.insert(0, tokens[start].value)
    return tuple(parts), start


def scan_source(source: str) -> list[tuple[int, str, str]]:
    """Return ``(line, kind, operation)`` for executable watched calls."""
    all_tokens = rust_tokens(source)
    tokens = _without_ranges(all_tokens, test_only_item_ranges(all_tokens))
    scope_for_token, scopes = _scope_map(tokens)
    _collect_imports(tokens, scope_for_token, scopes)
    _collect_value_bindings(tokens, scope_for_token, scopes)
    found: set[tuple[int, str, str]] = set()
    for index, token in enumerate(tokens):
        if token.value != "(":
            continue
        parsed = _call_path(tokens, index)
        if parsed is None:
            continue
        path, start = parsed
        for canonical in _canonical_paths(
            path, scope_for_token[start], scopes, call_index=index
        ):
            operation = OPERATIONS.get(canonical)
            if operation is None:
                continue
            kind, name = operation
            found.add((tokens[start].line, kind, name))
    return sorted(found)


def _rust_string_value(token: Token) -> str | None:
    if token.kind != "literal":
        return None
    value = token.value
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, str) else None
    match = re.fullmatch(r'r(?P<hashes>#+)?"(?P<body>.*)"(?P=hashes)', value, re.DOTALL)
    return None if match is None else match.group("body")


def _path_attribute(attributes: list[tuple[bool, list[Token]]]) -> str | None:
    for inner, body in attributes:
        if inner or len(body) != 3:
            continue
        if body[0].value == "path" and body[1].value == "=":
            return _rust_string_value(body[2])
    return None


def _module_source_candidates(
    declaring: Path,
    module: str,
    path_attribute: str | None,
    *,
    crate_root: bool = False,
) -> tuple[Path, ...]:
    if path_attribute is not None:
        return (declaring.parent / path_attribute,)
    if crate_root or declaring.name in {"lib.rs", "main.rs", "mod.rs"}:
        base = declaring.parent
    else:
        base = declaring.parent / declaring.stem
    return (base / f"{module}.rs", base / module / "mod.rs")


def _external_cfg_exclusions(
    root: Path, sources: list[Path]
) -> dict[str, dict[str, object]]:
    references: dict[Path, list[tuple[bool, dict[str, object]]]] = {}
    for declaring in sources:
        tokens = rust_tokens(declaring.read_text(encoding="utf-8"))
        for item, attributes in _attributed_items(tokens):
            if (
                item + 2 >= len(tokens)
                or tokens[item].value != "mod"
                or tokens[item + 1].kind != "ident"
                or tokens[item + 2].value != ";"
            ):
                continue
            module = tokens[item + 1].value
            candidates = _module_source_candidates(
                declaring, module, _path_attribute(attributes)
            )
            target = next((candidate for candidate in candidates if candidate.exists()), None)
            if target is None:
                continue
            predicate = _cfg_predicate_text(attributes)
            metadata: dict[str, object] = {
                "kind": "cfg_path_module",
                "declaration_file": str(declaring.relative_to(root)),
                "module": module,
                "predicate": predicate or "<unconditional>",
            }
            references.setdefault(target.resolve(), []).append(
                (_attributes_imply_test(attributes), metadata)
            )
    exclusions: dict[str, dict[str, object]] = {}
    for target, declarations in references.items():
        if not declarations or not all(excluded for excluded, _ in declarations):
            continue
        metadata = {json.dumps(item, sort_keys=True): item for _, item in declarations}
        if len(metadata) != 1:
            raise InventoryError(f"ambiguous cfg exclusion for {target}")
        path = Path(target)
        try:
            relative = str(path.relative_to(root.resolve()))
        except ValueError:
            continue
        exclusions[relative] = next(iter(metadata.values()))
    return exclusions


def _manifest_bin_roots(
    root: Path, source_root: Path
) -> tuple[str, dict[Path, str]] | None:
    manifest = source_root.parent / "Cargo.toml"
    if not manifest.exists():
        return None
    try:
        document = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InventoryError(f"cannot parse {manifest}: {error}") from error
    roots: dict[Path, str] = {}
    for entry in document.get("bin", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        path = entry.get("path")
        if isinstance(name, str) and isinstance(path, str):
            roots[(manifest.parent / path).resolve()] = name
    package = document.get("package", {})
    autobins = not isinstance(package, dict) or package.get("autobins", True) is not False
    if autobins:
        for path in (source_root / "bin").glob("*.rs"):
            roots.setdefault(path.resolve(), path.stem)
        for path in (source_root / "bin").glob("*/main.rs"):
            roots.setdefault(path.resolve(), path.parent.name)
    return str(manifest.relative_to(root)), roots


def _production_module_references(path: Path, *, crate_root: bool) -> list[Path]:
    tokens = rust_tokens(path.read_text(encoding="utf-8"))
    attributed = {item: attributes for item, attributes in _attributed_items(tokens)}
    references: list[Path] = []
    for index, token in enumerate(tokens):
        if token.value != "mod" or index + 2 >= len(tokens):
            continue
        if tokens[index + 1].kind != "ident" or tokens[index + 2].value != ";":
            continue
        attributes = attributed.get(index, [])
        if _attributes_imply_test(attributes):
            continue
        references.extend(
            candidate
            for candidate in _module_source_candidates(
                path,
                tokens[index + 1].value,
                _path_attribute(attributes),
                crate_root=crate_root,
            )
            if candidate.exists()
        )
    return references


def _standalone_target_exclusions(
    root: Path,
) -> dict[str, dict[str, object]]:
    ownership: dict[Path, tuple[str, set[str]]] = {}
    for source_root_relative in SOURCE_ROOTS:
        source_root = root / source_root_relative
        manifest_roots = _manifest_bin_roots(root, source_root)
        if manifest_roots is None:
            continue
        manifest, bin_roots = manifest_roots
        for bin_root, target in bin_roots.items():
            if not bin_root.exists():
                continue
            queue = [(bin_root, True)]
            visited: set[Path] = set()
            while queue:
                path, crate_root = queue.pop()
                path = path.resolve()
                if path in visited:
                    continue
                visited.add(path)
                current_manifest, targets = ownership.setdefault(path, (manifest, set()))
                if current_manifest != manifest:
                    raise InventoryError(f"standalone source has multiple manifests: {path}")
                targets.add(target)
                queue.extend(
                    (referenced, False)
                    for referenced in _production_module_references(
                        path, crate_root=crate_root
                    )
                )
    exclusions: dict[str, dict[str, object]] = {}
    for path, (manifest, targets) in ownership.items():
        exclusions[str(path.relative_to(root.resolve()))] = {
            "kind": "standalone_cargo_target",
            "manifest": manifest,
            "targets": sorted(targets),
        }
    return exclusions


def product_exclusions(root: Path, sources: list[Path]) -> dict[str, dict[str, object]]:
    exclusions = _external_cfg_exclusions(root, sources)
    for path, exclusion in _standalone_target_exclusions(root).items():
        prior = exclusions.get(path)
        if prior is not None and prior != exclusion:
            raise InventoryError(f"source has ambiguous product exclusions: {path}")
        exclusions[path] = exclusion
    return exclusions


def production_source(root: Path) -> list[Path]:
    paths: list[Path] = []
    for source_root in SOURCE_ROOTS:
        path = root / source_root
        if not path.exists():
            continue
        paths.extend(
            candidate
            for candidate in path.rglob("*.rs")
            if "tests" not in candidate.relative_to(root).parts
        )
    return sorted(paths)


def generate(root: Path) -> list[dict[str, object]]:
    """Return sorted source rows for all declared guest-facing transitions."""
    entries: list[dict[str, object]] = []
    sources = production_source(root)
    exclusions = product_exclusions(root, sources)
    for path in sources:
        source = path.read_text(encoding="utf-8")
        relative = str(path.relative_to(root))
        source_lines = source.splitlines()
        grouped: dict[tuple[int, str], set[str]] = {}
        for line, kind, operation in scan_source(source):
            grouped.setdefault((line, kind), set()).add(operation)
        for (line, kind), operations in grouped.items():
            row: dict[str, object] = {
                "file": relative,
                "line": line,
                "kind": kind,
                "text": source_lines[line - 1].strip(),
                "operations": sorted(operations),
            }
            if relative in exclusions:
                row["product_exclusion"] = exclusions[relative]
            entries.append(row)
    return sorted(entries, key=lambda row: (row["file"], row["line"], row["kind"]))


def source_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {key: value for key, value in row.items() if key not in REVIEW_FIELDS}
        for row in rows
    ]


def row_identity(row: dict[str, object]) -> str:
    """Return the collision-free identity of every generated source field."""
    return json.dumps(
        {key: value for key, value in row.items() if key not in REVIEW_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
    )


def _unique_rows(
    rows: list[dict[str, object]], label: str
) -> dict[str, dict[str, object]]:
    indexed: dict[str, dict[str, object]] = {}
    for row in rows:
        identity = row_identity(row)
        if identity in indexed:
            raise InventoryError(f"duplicate {label} inventory identity: {identity}")
        indexed[identity] = row
    return indexed


def _normalized_claim(value: str) -> str:
    return re.sub(r"[^a-z0-9/_-]+", " ", value.casefold()).strip()


def _validate_review_text(value: object, label: str, row: dict[str, object]) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InventoryError(f"empty inventory {label}: {row}")
    normalized = _normalized_claim(value)
    if len(normalized) < 8 or normalized in GENERIC_RESOURCES:
        raise InventoryError(f"generic inventory {label}: {row}")
    folded = value.casefold()
    if any(fragment in folded for fragment in BANNED_REVIEW_FRAGMENTS):
        raise InventoryError(f"generic inventory {label}: {row}")
    if DISJUNCTION.search(value):
        raise InventoryError(f"disjunctive inventory {label}: {row}")
    return value


def _validate_evidence(row: dict[str, object]) -> None:
    classification = row["classification"]
    evidence = row.get("evidence")
    if not isinstance(evidence, dict):
        raise InventoryError(f"missing structured inventory evidence: {row}")
    authority = evidence.get("authority")
    if authority not in AUTHORITIES[classification]:
        raise InventoryError(f"invalid structured inventory authority: {row}")
    _validate_review_text(evidence.get("resource"), "evidence resource", row)
    exclusion = row.get("product_exclusion")
    if classification == "legacy_unreachable":
        if not isinstance(exclusion, dict):
            raise InventoryError(f"legacy row has no recognized product exclusion: {row}")
        expected_authority = {
            "cfg_path_module": "compile_time_exclusion",
            "standalone_cargo_target": "standalone_target_exclusion",
        }.get(exclusion.get("kind"))
        if authority != expected_authority or evidence.get("exclusion") != exclusion:
            raise InventoryError(f"legacy evidence does not bind its source exclusion: {row}")
        if set(evidence) != {"authority", "resource", "exclusion"}:
            raise InventoryError(f"invalid legacy evidence schema: {row}")
    else:
        if exclusion is not None:
            raise InventoryError(f"excluded product source is not classified legacy: {row}")
        if set(evidence) != {"authority", "resource"}:
            raise InventoryError(f"invalid authority evidence schema: {row}")


def validate(actual: list[dict[str, object]], expected: list[dict[str, object]]) -> None:
    """Require exact source rows and a complete concrete classification review."""
    _unique_rows(actual, "generated")
    _unique_rows(expected, "reviewed")
    if source_rows(actual) != source_rows(expected):
        raise InventoryError("guest-facing host-transition inventory drifted")
    for row in expected:
        classification = row.get("classification")
        rationale = row.get("rationale")
        if classification == "unreviewed":
            raise InventoryError(f"unreviewed inventory row: {row}")
        if classification not in CLASSIFICATIONS:
            raise InventoryError(f"invalid inventory classification: {row}")
        _validate_review_text(rationale, "rationale", row)
        _validate_evidence(row)


def reviewed_rows(
    actual: list[dict[str, object]], expected: list[dict[str, object]]
) -> list[dict[str, object]]:
    _unique_rows(actual, "generated")
    previous = _unique_rows(expected, "reviewed")
    rows: list[dict[str, object]] = []
    for row in actual:
        prior = previous.get(row_identity(row))
        if prior is None:
            rows.append(
                {
                    **row,
                    "classification": "unreviewed",
                    "evidence": {},
                    "rationale": "",
                }
            )
        else:
            rows.append(
                {
                    **row,
                    "classification": prior.get("classification", "unreviewed"),
                    "evidence": prior.get("evidence", {}),
                    "rationale": prior.get("rationale", ""),
                }
            )
    return rows


def load_inventory() -> list[dict[str, object]]:
    try:
        data: Any = json.loads(INVENTORY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InventoryError(f"cannot read host-transition inventory: {error}") from error
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        raise InventoryError("host-transition inventory must be a JSON list of rows")
    return data


def main(argv: list[str]) -> int:
    if argv not in ([], ["--write"]):
        print(f"usage: {Path(sys.argv[0]).name} [--write]", file=sys.stderr)
        return 2
    actual = generate(ROOT)
    try:
        expected = load_inventory()
    except InventoryError as error:
        expected = []
        if argv != ["--write"]:
            print(error, file=sys.stderr)
            return 1
    if argv == ["--write"]:
        try:
            rewritten = reviewed_rows(actual, expected)
        except InventoryError as error:
            print(error, file=sys.stderr)
            return 1
        INVENTORY.write_text(json.dumps(rewritten, indent=2) + "\n", encoding="utf-8")
        return 0
    try:
        validate(actual, expected)
    except InventoryError as error:
        print(error, file=sys.stderr)
        print(
            "Regenerate with --write only after classifying every changed site.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

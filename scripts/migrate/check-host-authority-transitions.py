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
from pathlib import Path
from typing import Any, NamedTuple


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "scripts/migrate/host-authority-transition-inventory.json"
SOURCE_ROOTS = (
    Path("crates/carrick-runtime/src/dispatch"),
    Path("crates/carrick-runtime/src/vfs"),
    Path("crates/carrick-runtime/src/namespace"),
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
RATIONALE_PREFIXES = {
    "forbidden_semantic": ("guest answer: ", "host target: "),
    "declared_substrate": ("authenticated carrier: ",),
    "declared_backing": ("authorized backing: ",),
    "legacy_unreachable": (
        "compile-time exclusion: ",
        "standalone target exclusion: ",
    ),
}
BANNED_RATIONALE_FRAGMENTS = (
    "Concrete operation form:",
    "guest-visible process state",
    "Carrick created that resource",
    "pre-authorized backing object",
    "performs a carrier-side",
)
REVIEW_FIELDS = {"classification", "rationale"}


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


def test_only_module_ranges(tokens: list[Token]) -> list[tuple[int, int]]:
    """Return token-index ranges for inline modules whose cfg requires test."""
    ranges: list[tuple[int, int]] = []
    index = 0
    while index < len(tokens):
        first = _attribute(tokens, index)
        if first is None:
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
        implies_test = any(
            not inner and _cfg_attribute_implies_test(body)
            for inner, body in attributes
        )
        if implies_test:
            item = _skip_visibility(tokens, cursor)
            if item < len(tokens) and tokens[item].value == "mod":
                item += 1
                if item < len(tokens) and tokens[item].kind == "ident":
                    item += 1
                    if item < len(tokens) and tokens[item].value == "{":
                        close = _matching_delimiter(tokens, item)
                        if close is not None:
                            ranges.append((item, close))
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
    scopes: list[dict[str, object]] = [{"parent": None, "aliases": {}, "globs": []}]
    stack = [0]
    scope_for_token: list[int] = []
    for token in tokens:
        scope_for_token.append(stack[-1])
        if token.value == "{":
            scopes.append({"parent": stack[-1], "aliases": {}, "globs": []})
            stack.append(len(scopes) - 1)
        elif token.value == "}" and len(stack) > 1:
            stack.pop()
    return scope_for_token, scopes


def _parse_use_tree(
    tokens: list[Token],
) -> tuple[dict[str, tuple[str, ...]], list[tuple[str, ...]]]:
    aliases: dict[str, tuple[str, ...]] = {}
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
            aliases[alias] = canonical
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
        scope_aliases.update(aliases)
        scope_globs.extend(globs)


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
    path: tuple[str, ...], scope_id: int, scopes: list[dict[str, object]]
) -> set[tuple[str, ...]]:
    results: set[tuple[str, ...]] = set()

    def expand(candidate: tuple[str, ...], seen: frozenset[str]) -> None:
        if not candidate:
            return
        first = candidate[0]
        if first in seen:
            results.add(candidate)
            return
        for current in _scope_chain(scope_id, scopes):
            aliases = scopes[current]["aliases"]
            assert isinstance(aliases, dict)
            replacement = aliases.get(first)
            if isinstance(replacement, tuple):
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


def _call_path(
    tokens: list[Token], call_index: int
) -> tuple[tuple[str, ...], int] | None:
    index = call_index - 1
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
    tokens = _without_ranges(all_tokens, test_only_module_ranges(all_tokens))
    scope_for_token, scopes = _scope_map(tokens)
    _collect_imports(tokens, scope_for_token, scopes)
    found: set[tuple[int, str, str]] = set()
    for index, token in enumerate(tokens):
        if token.value != "(":
            continue
        parsed = _call_path(tokens, index)
        if parsed is None:
            continue
        path, start = parsed
        for canonical in _canonical_paths(path, scope_for_token[start], scopes):
            operation = OPERATIONS.get(canonical)
            if operation is None:
                continue
            kind, name = operation
            found.add((tokens[start].line, kind, name))
    return sorted(found)


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
    for path in production_source(root):
        source = path.read_text(encoding="utf-8")
        relative = str(path.relative_to(root))
        source_lines = source.splitlines()
        grouped: dict[tuple[int, str], set[str]] = {}
        for line, kind, operation in scan_source(source):
            grouped.setdefault((line, kind), set()).add(operation)
        for (line, kind), operations in grouped.items():
            entries.append(
                {
                    "file": relative,
                    "line": line,
                    "kind": kind,
                    "text": source_lines[line - 1].strip(),
                    "operations": sorted(operations),
                }
            )
    return sorted(entries, key=lambda row: (row["file"], row["line"], row["kind"]))


def source_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {key: value for key, value in row.items() if key not in REVIEW_FIELDS}
        for row in rows
    ]


def validate(actual: list[dict[str, object]], expected: list[dict[str, object]]) -> None:
    """Require exact source rows and a complete concrete classification review."""
    if source_rows(actual) != source_rows(expected):
        raise InventoryError("guest-facing host-transition inventory drifted")
    for row in expected:
        classification = row.get("classification")
        rationale = row.get("rationale")
        if classification == "unreviewed":
            raise InventoryError(f"unreviewed inventory row: {row}")
        if classification not in CLASSIFICATIONS:
            raise InventoryError(f"invalid inventory classification: {row}")
        if not isinstance(rationale, str) or not rationale.strip():
            raise InventoryError(f"empty inventory rationale: {row}")
        prefixes = RATIONALE_PREFIXES[classification]
        if not rationale.startswith(prefixes):
            raise InventoryError(
                f"rationale does not name its concrete authority role: {row}"
            )
        if any(fragment in rationale for fragment in BANNED_RATIONALE_FRAGMENTS):
            raise InventoryError(f"generic inventory rationale: {row}")
        if classification != "legacy_unreachable" and re.search(
            r"\b(?:or|versus)\b", rationale
        ):
            raise InventoryError(f"disjunctive inventory rationale: {row}")


def reviewed_rows(
    actual: list[dict[str, object]], expected: list[dict[str, object]]
) -> list[dict[str, object]]:
    previous = {
        (row.get("file"), row.get("kind"), row.get("text")): row for row in expected
    }
    rows: list[dict[str, object]] = []
    for row in actual:
        prior = previous.get((row["file"], row["kind"], row["text"]))
        if prior is None:
            rows.append({**row, "classification": "unreviewed", "rationale": ""})
        else:
            rows.append(
                {
                    **row,
                    "classification": prior.get("classification", "unreviewed"),
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
        INVENTORY.write_text(
            json.dumps(reviewed_rows(actual, expected), indent=2) + "\n",
            encoding="utf-8",
        )
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

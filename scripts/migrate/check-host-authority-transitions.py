#!/usr/bin/env python3
"""Fail when the reviewed guest-facing host-transition inventory drifts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "scripts/migrate/host-authority-transition-inventory.json"
SOURCE_ROOTS = (
    Path("crates/carrick-runtime/src/dispatch"),
    Path("crates/carrick-runtime/src/vfs"),
    Path("crates/carrick-runtime/src/namespace"),
    Path("crates/carrick-vmm-hvf/src"),
)
PATTERNS = {
    "host_identity": re.compile(
        r"\b(?:std::process::id|libc::(?:getpid|getppid|getpgrp|getsid|"
        r"getuid|geteuid|getgid|getegid|getgroups|getrlimit|setrlimit))\s*\("
    ),
    "host_process_control": re.compile(
        r"\blibc::(?:fork|wait4|waitid|kill|killpg|pthread_kill)\s*\("
    ),
    "host_namespace_view": re.compile(
        r"\blibc::(?:getifaddrs|gethostname|getaddrinfo)\s*\("
    ),
    "ambient_filesystem": re.compile(
        r"\bstd::fs::(?:read|read_to_string|write|metadata|symlink_metadata|"
        r"read_link|read_dir|create_dir|create_dir_all|set_permissions|"
        r"remove_file|remove_dir|remove_dir_all|rename|hard_link|"
        r"File::(?:open|create)|OpenOptions::new)\s*\("
    ),
    "ambient_network": re.compile(
        r"\bstd::net::(?:TcpStream::(?:connect|connect_timeout)|"
        r"TcpListener::bind|UdpSocket::(?:bind|connect))\s*\("
    ),
    "carrier_substrate": re.compile(
        r"\b(?:std::thread::(?:spawn|sleep|yield_now)|"
        r"std::thread::Builder::new|hv_vcpus_exit)\b"
    ),
}
NETWORK_IMPORT = re.compile(r"^\s*use\s+std::net::(?P<items>[^;]+);")
NETWORK_ITEM = re.compile(
    r"^\s*(?P<type>TcpStream|TcpListener|UdpSocket)"
    r"(?:\s+as\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*))?\s*$"
)
NETWORK_METHODS = {
    "TcpStream": ("connect", "connect_timeout"),
    "TcpListener": ("bind",),
    "UdpSocket": ("bind", "connect"),
}
CLASSIFICATIONS = {
    "forbidden_semantic",
    "declared_substrate",
    "declared_backing",
    "legacy_unreachable",
}


class InventoryError(Exception):
    """The source inventory and its review state do not agree."""


def string_literal_end(source: str, index: int) -> int | None:
    """Return the exclusive end of a Rust string literal starting at index."""
    raw_end = index
    if source[index] == "r":
        while raw_end + 1 < len(source) and source[raw_end + 1] == "#":
            raw_end += 1
        if raw_end + 1 < len(source) and source[raw_end + 1] == '"':
            hashes = raw_end - index
            end = source.find('"' + ('#' * hashes), raw_end + 2)
            return None if end == -1 else end + hashes + 1
    if source[index] != '"':
        return None
    end = index + 1
    while end < len(source):
        if source[end] == "\\":
            end += 2
            continue
        if source[end] == '"':
            return end + 1
        end += 1
    return len(source)


def mask_comments(source: str) -> str:
    """Replace Rust comments with spaces while retaining every newline."""
    result = list(source)
    index = 0
    depth = 0
    line_comment = False
    while index < len(source):
        if line_comment:
            if source[index] == "\n":
                line_comment = False
            else:
                result[index] = " "
            index += 1
            continue
        if depth:
            if source.startswith("/*", index):
                result[index : index + 2] = "  "
                depth += 1
                index += 2
            elif source.startswith("*/", index):
                result[index : index + 2] = "  "
                depth -= 1
                index += 2
            else:
                if source[index] != "\n":
                    result[index] = " "
            index += 1
            continue
        literal_end = string_literal_end(source, index)
        if literal_end is not None:
            index = literal_end
            continue
        if source.startswith("//", index):
            result[index : index + 2] = "  "
            line_comment = True
            index += 2
        elif source.startswith("/*", index):
            result[index : index + 2] = "  "
            depth = 1
            index += 2
        else:
            index += 1
    return "".join(result)


def mask_string_literals(source: str) -> str:
    """Replace Rust string and character literals so their braces do not count."""
    result = list(source)
    index = 0
    while index < len(source):
        literal_end = string_literal_end(source, index)
        if literal_end is not None:
            for literal_index in range(index, literal_end):
                if result[literal_index] != "\n":
                    result[literal_index] = " "
            index = literal_end
            continue
        if source[index] == "'":
            end = index + 1
            if end < len(source) and source[end] == "\\":
                end += 2
            else:
                end += 1
            if end < len(source) and source[end] == "'":
                end += 1
                for literal_index in range(index, end):
                    result[literal_index] = " "
                index = end
                continue
        index += 1
    return "".join(result)


def mask_cfg_test_modules(source: str) -> str:
    """Mask brace-balanced bodies of modules compiled only for Rust tests."""
    masked = list(source)
    attribute = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    module = re.compile(
        r"\s*\b(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{"
    )
    for match in attribute.finditer(source):
        module_match = module.match(source, match.end())
        if module_match is None:
            continue
        opening = module_match.end() - 1
        depth = 0
        index = opening
        while index < len(source):
            char = source[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    index += 1
                    break
            index += 1
        if depth != 0:
            continue
        for body_index in range(opening, index):
            if masked[body_index] != "\n":
                masked[body_index] = " "
    return "".join(masked)


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


def imported_network_types(line: str) -> dict[str, tuple[str, ...]]:
    """Extract direct and braced std::net socket type imports from one line."""
    match = NETWORK_IMPORT.match(line)
    if match is None:
        return {}
    items = match.group("items").strip()
    if items.startswith("{") and items.endswith("}"):
        candidates = items[1:-1].split(",")
    else:
        candidates = [items]
    imports: dict[str, tuple[str, ...]] = {}
    for candidate in candidates:
        item = NETWORK_ITEM.match(candidate)
        if item is not None:
            imports[item.group("alias") or item.group("type")] = NETWORK_METHODS[item.group("type")]
    return imports


def imported_network_operation(line: str, imports: dict[str, tuple[str, ...]]) -> bool:
    """True when an imported std::net socket type invokes a socket operation."""
    return any(
        re.search(rf"\b{re.escape(name)}::(?:{'|'.join(methods)})\s*\(", line)
        for name, methods in imports.items()
    )


def generate(root: Path) -> list[dict[str, object]]:
    """Return sorted source rows for all declared guest-facing transitions."""
    entries: list[dict[str, object]] = []
    for path in production_source(root):
        source = path.read_text(encoding="utf-8")
        visible = mask_cfg_test_modules(mask_string_literals(mask_comments(source)))
        relative = str(path.relative_to(root))
        source_lines = source.splitlines()
        imports: dict[str, tuple[str, ...]] = {}
        for number, line in enumerate(visible.splitlines(), 1):
            text = source_lines[number - 1].strip()
            imports.update(imported_network_types(line))
            for kind, pattern in PATTERNS.items():
                if pattern.search(line) or (
                    kind == "ambient_network" and imported_network_operation(line, imports)
                ):
                    entries.append(
                        {"file": relative, "line": number, "kind": kind, "text": text}
                    )
    return sorted(entries, key=lambda row: (row["file"], row["line"], row["kind"]))


def source_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {key: value for key, value in row.items() if key not in {"classification", "rationale"}}
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


def reviewed_rows(actual: list[dict[str, object]], expected: list[dict[str, object]]) -> list[dict[str, object]]:
    previous = {
        (row.get("file"), row.get("kind"), row.get("text")): row
        for row in expected
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
            json.dumps(reviewed_rows(actual, expected), indent=2) + "\n", encoding="utf-8"
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

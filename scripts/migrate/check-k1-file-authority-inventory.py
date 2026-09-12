#!/usr/bin/env python3
"""Fail when the checked K1 FileAuthority operation inventory drifts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crates/carrick-runtime/src"
INVENTORY = ROOT / "scripts/migrate/k1-file-authority-operation-inventory.json"
FILE_AUTHORITY_MODULE = SOURCE / "file_authority"
PATTERNS = {
    "table_guard": re.compile(
        r"\b(read_open_files|write_open_files|lock_next_fd|lock_stdio_cloexec|"
        r"lock_closed_stdio|read_fd_open_paths|write_fd_open_paths|"
        r"lock_splice_pushback|read_epoll_fds|write_epoll_fds|"
        r"epoll_wake_registry|nofile_soft|set_nofile_soft)\b"
    ),
    "description_guard": re.compile(r"\.description\.(read|write|try_read)\("),
    "description_backing": re.compile(
        r"\b(open_description\(\)|concrete_backing::<|OpenDescriptionRef\b)"
    ),
    "epoll": re.compile(r"\b(epoll|Epoll|EPOLL)\b"),
    "stream": re.compile(
        r"\b(splice|Splice|tee|vmsplice|sendfile|PipeStream|pushback)\b"
    ),
    "mapping": re.compile(
        r"\b(mmap|Mmap|mapping|Mapping|io_uring|IoUring|ioring)\b"
    ),
    "lifecycle": re.compile(
        r"\b(host_fork_file_authority_rejection|for_fork_copy|for_exec|"
        r"native_reexec_fd|restore_native_reexec_fd|copy_file_table_for_host_fork)\b"
    ),
}

# Text that matches a category word but is not a file-authority operation.
# `Vec::splice` on the semantic VMA vector (`VmaMap`) is std vector surgery,
# not a pipe/stream transfer; the "stream" word match would otherwise record
# it as a K1 stream site and force a false classification at every landing.
NON_AUTHORITY_TEXT = (
    re.compile(r"\bself\.vmas\.splice\("),
    re.compile(r"\bmod\s+mmap;"),
    re.compile(r'include_str!\("mmap\.rs"\)'),
)


def brace_deltas(source: str) -> list[int]:
    """Per-line `{`/`}` balance of `source`, skipping braces inside line and
    (nested) block comments, string literals, raw strings and char literals,
    so a `'}'`, a multi-line `r#"…"#` fixture or a brace in a comment cannot
    unbalance the test-module walk."""
    deltas: list[int] = []
    delta = 0
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char == "\n":
            deltas.append(delta)
            delta = 0
            index += 1
        elif source.startswith("//", index):
            newline = source.find("\n", index)
            index = length if newline < 0 else newline
        elif source.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    if source[index] == "\n":
                        deltas.append(delta)
                        delta = 0
                    index += 1
        elif raw := re.compile(r"b?r(#*)\"").match(source, index):
            terminator = '"' + raw.group(1)
            close = source.find(terminator, raw.end())
            close = length if close < 0 else close + len(terminator)
            newlines = source.count("\n", index, close)
            if newlines:
                deltas.extend([delta] + [0] * (newlines - 1))
                delta = 0
            index = close
        elif char == '"' or source.startswith('b"', index):
            index += 2 if char == "b" else 1
            while index < length and source[index] != '"':
                if source[index] == "\\":
                    index += 1
                if index < length and source[index] == "\n":
                    deltas.append(delta)
                    delta = 0
                index += 1
            index += 1
        elif char == "'" and (match := re.compile(r"'(?:\\.[^']*|[^'\\\n])'").match(source, index)):
            index = match.end()
        else:
            if char == "{":
                delta += 1
            elif char == "}":
                delta -= 1
            index += 1
    deltas.append(delta)
    return deltas


def cfg_test_module_lines(lines: list[str]) -> set[int]:
    """1-based line numbers inside every `#[cfg(test)] mod … { … }` block.

    A unit test that takes a table or description lock is not an authority
    escape the burndown has to migrate; only the line-text `#[cfg(test)]`
    check existed before, so such a site inside a test module counted as a
    production callsite.
    """
    deltas = brace_deltas("\n".join(lines))
    inside: set[int] = set()
    index = 0
    while index < len(lines):
        if lines[index].strip() == "#[cfg(test)]":
            probe = index + 1
            while probe < len(lines) and lines[probe].strip().startswith("#["):
                probe += 1
            if probe < len(lines) and re.match(r"\s*(pub(\([^)]*\))?\s+)?mod\s+\w+\s*\{", lines[probe]):
                depth = 0
                for number in range(probe, len(lines)):
                    depth += deltas[number]
                    inside.add(number + 1)
                    if depth <= 0:
                        index = number
                        break
        index += 1
    return inside


def is_out_of_line_test_module(path: Path) -> bool:
    """`path` is a whole-file test module: its parent declares it as
    `#[cfg(test)] mod <stem>;` (`dispatch/fs.rs` → `dispatch/fs/tests.rs`),
    `#[cfg(test)] #[path = "…"] mod <stem>;` or `#[cfg(test)]
    include!("<stem>.rs")`.

    `cfg_test_module_lines` only sees inline `mod … { … }` blocks, so every
    line of such a file counted as a production callsite and the burndown
    ceiling refused new unit tests of the very guards it tracks.
    """
    parents = [path.parent.with_suffix(".rs"), path.parent / "mod.rs"]
    declaration = re.compile(
        r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:"
        r"(?:pub(?:\([^)]*\))?\s+)?mod\s+" + re.escape(path.stem) + r"\s*;"
        r"|include!\(\"(?:[^\"]*/)?" + re.escape(path.name) + r"\"\))"
    )
    return any(
        parent.is_file() and declaration.search(parent.read_text())
        for parent in parents
    )


def generate() -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for path in sorted(SOURCE.rglob("*.rs")):
        if path.is_relative_to(FILE_AUTHORITY_MODULE):
            # Inventory the legacy authority escapes that production cutover
            # must delete, not the replacement authority's closed internal
            # implementation. The replacement is production-visible now, so a
            # cfg(test)-string sentinel can no longer define this boundary.
            continue
        relative = str(path.relative_to(ROOT))
        lines = path.read_text().splitlines()
        test_lines = cfg_test_module_lines(lines)
        whole_file_test = is_out_of_line_test_module(path)
        for number, line in enumerate(lines, 1):
            if any(pattern.search(line) for pattern in NON_AUTHORITY_TEXT):
                continue
            categories = [name for name, pattern in PATTERNS.items() if pattern.search(line)]
            if categories:
                text = line.strip()
                entries.append(
                    {
                        "file": relative,
                        "line": number,
                        "categories": categories,
                        "text": text,
                        "scope_kind": (
                            "test_or_definition"
                            if "#[cfg(test)]" in text
                            or number in test_lines
                            or whole_file_test
                            or relative.endswith("/kernel/objects.rs")
                            or relative.endswith("/dispatch/fd_table.rs")
                            else "production_callsite"
                        ),
                    }
                )
    counts = {
        name: sum(name in entry["categories"] for entry in entries)
        for name in PATTERNS
    }
    return {
        "schema": 1,
        "scope": "production Rust sources under crates/carrick-runtime/src",
        "counts": counts,
        "production_counts": {
            name: sum(
                name in entry["categories"]
                and entry["scope_kind"] == "production_callsite"
                for entry in entries
            )
            for name in PATTERNS
        },
        "files": {
            name: len(
                {
                    entry["file"]
                    for entry in entries
                    if name in entry["categories"]
                }
            )
            for name in PATTERNS
        },
        "entries": entries,
    }


def main(argv: list[str]) -> int:
    actual = generate()
    if argv == ["--write"]:
        INVENTORY.write_text(json.dumps(actual, indent=2) + "\n")
        return 0
    if argv:
        print(
            f"usage: {Path(sys.argv[0]).name} [--write]",
            file=sys.stderr,
        )
        return 2

    try:
        expected = json.loads(INVENTORY.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"cannot read K1 FileAuthority inventory: {error}", file=sys.stderr)
        return 1
    if actual == expected:
        return 0
    print("K1 FileAuthority operation inventory drifted", file=sys.stderr)
    print(f"expected counts: {expected['counts']}", file=sys.stderr)
    print(f"actual counts:   {actual['counts']}", file=sys.stderr)
    print(
        "Regenerate with --write only after classifying and migrating every changed site.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

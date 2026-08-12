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
FILE_AUTHORITY_GATE = "#[cfg(test)]\npub(crate) mod file_authority;"
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


def generate() -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    authority_is_test_only = FILE_AUTHORITY_GATE in (SOURCE / "lib.rs").read_text()
    for path in sorted(SOURCE.rglob("*.rs")):
        if authority_is_test_only and path.is_relative_to(FILE_AUTHORITY_MODULE):
            # The disconnected replacement model is intentionally outside the
            # production-escape inventory until its cfg(test) gate is deleted
            # by the atomic cutover. Once enabled, it is scanned automatically.
            continue
        relative = str(path.relative_to(ROOT))
        for number, line in enumerate(path.read_text().splitlines(), 1):
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

    expected = json.loads(INVENTORY.read_text())
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

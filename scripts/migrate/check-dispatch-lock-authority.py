#!/usr/bin/env python3
"""Check and enforce dispatch lock authority across production runtime sources.

This gate inventories raw lock acquisitions in `crates/carrick-runtime/src`:
- `proc` dispatcher state
- `pty_table` state
- `sysv_process` and `sysv_namespace` state
- `file_table_internals`

It enforces that:
1. No unclassified or newly added raw lock acquisitions can appear (fail-closed, shrink-only).
2. Paired SysV mutations use the typed `SysvProcessGuard` -> `SysvNamespacePermit` -> `lock_paired` authority.
3. Standalone SysV operations use the encapsulated `with_state` / `with_sysv_process` closures.
4. Test scopes, comments, and string literals are ignored.
5. Exact agreement between code and checked-in inventory is required.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
SCAN_PATHS = [
    REPO_ROOT / "crates" / "carrick-runtime" / "src" / "dispatch",
    REPO_ROOT / "crates" / "carrick-runtime" / "src" / "kernel" / "objects.rs",
]
DEFAULT_INVENTORY_PATH = REPO_ROOT / "scripts" / "migrate" / "dispatch-lock-authority.json"

CATEGORIES = {
    "proc": "raw acquisition of dispatcher `proc` lock",
    "pty_table": "raw acquisition of `pty_table` lock",
    "sysv_process": "raw acquisition of per-process `sysv_process` lock",
    "sysv_namespace": "raw acquisition of shared SysV `state` lock",
    "file_table_internals": "direct acquisition of FileTable internal mutex/rwlock",
}

FILE_TABLE_INTERNAL_FIELDS = frozenset(
    {
        "open_files",
        "next_fd",
        "stdio_cloexec",
        "closed_stdio",
        "fd_open_paths",
        "splice_pushback",
        "epoll_fds",
    }
)

LOCK_METHODS = frozenset(
    {
        "lock",
        "try_lock",
        "read",
        "write",
        "try_read",
        "try_write",
        "try_read_until",
        "try_write_until",
    }
)


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int
    pos: int


@dataclass(frozen=True)
class RawLockSite:
    id: str
    file: str
    line: int
    item: str
    category: str
    expression: str
    ordinal: int


def lex_rust(source: str) -> list[Token]:
    """Tokenize Rust source while ignoring comments and tracking string/char literals."""
    tokens: list[Token] = []
    i = 0
    line = 1
    length = len(source)

    while i < length:
        char = source[i]
        if char.isspace():
            if char == "\n":
                line += 1
            i += 1
            continue

        if source[i : i + 2] == "//":
            i += 2
            while i < length and source[i] != "\n":
                i += 1
            continue

        if source[i : i + 2] == "/*":
            i += 2
            depth = 1
            while i < length and depth:
                if source[i] == "\n":
                    line += 1
                    i += 1
                elif source[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif source[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue

        raw_prefix = None
        if char == "r":
            raw_prefix = 1
        elif char in {"b", "c"} and i + 1 < length and source[i + 1] == "r":
            raw_prefix = 2
        if raw_prefix is not None:
            cursor = i + raw_prefix
            hashes = 0
            while cursor < length and source[cursor] == "#":
                hashes += 1
                cursor += 1
            if cursor < length and source[cursor] == '"':
                closing = '"' + ("#" * hashes)
                end = source.find(closing, cursor + 1)
                if end < 0:
                    end = length - len(closing)
                end += len(closing)
                text = source[i:end]
                tokens.append(Token("string", text, line, i))
                line += text.count("\n")
                i = end
                continue

        if char == '"' or (
            char in {"b", "c"} and i + 1 < length and source[i + 1] == '"'
        ):
            start = i
            if char in {"b", "c"}:
                i += 1
            i += 1
            while i < length:
                if source[i] == "\n":
                    line += 1
                if source[i] == "\\":
                    i += 2
                elif source[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            tokens.append(Token("string", source[start:i], line, start))
            continue

        if char == "'" or (
            char == "b" and i + 1 < length and source[i + 1] == "'"
        ):
            start = i
            byte_char = char == "b"
            if byte_char:
                i += 1
            i += 1
            if not byte_char and i < length and (
                source[i].isalpha() or source[i] == "_"
            ):
                while i < length and (source[i].isalnum() or source[i] == "_"):
                    i += 1
                if i >= length or source[i] != "'":
                    tokens.append(Token("lifetime", source[start:i], line, start))
                    continue
            while i < length:
                if source[i] == "\\":
                    i += 2
                elif source[i] == "'":
                    i += 1
                    break
                else:
                    i += 1
            tokens.append(Token("char", source[start:i], line, start))
            continue

        if char.isalpha() or char == "_":
            start = i
            i += 1
            while i < length and (source[i].isalnum() or source[i] == "_"):
                i += 1
            tokens.append(Token("ident", source[start:i], line, start))
            continue

        if char.isdigit():
            start = i
            i += 1
            while i < length and (source[i].isalnum() or source[i] in "._"):
                if source[i] == "." and i + 1 < length and source[i + 1] == ".":
                    break
                i += 1
            tokens.append(Token("number", source[start:i], line, start))
            continue

        two = source[i : i + 2]
        if two in {"::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", "..", "+=", "-="}:
            tokens.append(Token("punct", two, line, i))
            i += 2
            continue
        tokens.append(Token("punct", char, line, i))
        i += 1

    return tokens


def _matching_delimiter(tokens: Sequence[Token], start: int, opening: str, closing: str) -> int:
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index].text == opening:
            depth += 1
        elif tokens[index].text == closing:
            depth -= 1
            if depth == 0:
                return index
    return len(tokens) - 1


def production_mask(tokens: Sequence[Token]) -> list[bool]:
    """Return True for tokens that can compile when cfg(test) is disabled."""
    production = [True] * len(tokens)
    test_scope_stack = [False]
    pending_test_attribute = False
    pending_test_item = False

    index = 0
    while index < len(tokens):
        token = tokens[index]
        current_test = test_scope_stack[-1]

        if token.text == "#" and index + 1 < len(tokens) and tokens[index + 1].text == "[":
            end = _matching_delimiter(tokens, index + 1, "[", "]")
            attribute = [item.text for item in tokens[index + 2 : end]]
            exact_test = attribute == ["test"]
            exact_cfg_test = (
                attribute == ["cfg", "(", "test", ")"]
                or ("cfg" in attribute and "test" in attribute)
            )
            if exact_test or exact_cfg_test:
                pending_test_attribute = True
            for attr_index in range(index, min(end + 1, len(tokens))):
                production[attr_index] = not current_test
            index = end + 1
            continue

        if pending_test_attribute and token.text in {
            "fn",
            "mod",
            "impl",
            "trait",
            "struct",
            "enum",
            "const",
            "static",
        }:
            pending_test_item = True
            pending_test_attribute = False

        if token.text == "{":
            test_scope_stack.append(current_test or pending_test_item)
            production[index] = not test_scope_stack[-1]
            pending_test_item = False
        elif token.text == "}":
            production[index] = not current_test
            if len(test_scope_stack) > 1:
                test_scope_stack.pop()
        else:
            production[index] = not current_test and not pending_test_item
            if token.text == ";":
                pending_test_attribute = False
                pending_test_item = False
        index += 1

    return production


def find_enclosing_item(tokens: Sequence[Token], target_idx: int) -> str:
    """Find enclosing type/trait/fn item path."""
    current_impl = None
    current_fn = None

    # Scan backward for nearest fn or impl
    for i in range(target_idx, -1, -1):
        if current_fn is None and tokens[i].text == "fn" and i + 1 < len(tokens) and tokens[i + 1].kind == "ident":
            current_fn = tokens[i + 1].text
        if current_impl is None and tokens[i].text == "impl" and i + 1 < len(tokens):
            ident_candidates = []
            for j in range(i + 1, min(i + 30, len(tokens))):
                if tokens[j].text in {"{", "where", ";"}:
                    break
                if tokens[j].kind == "ident" and tokens[j].text not in {"for", "dyn", "mut", "const"}:
                    ident_candidates.append(tokens[j].text)
            if ident_candidates:
                current_impl = ident_candidates[-1]
        if current_fn and current_impl:
            break

    if current_impl and current_fn:
        return f"{current_impl}::{current_fn}"
    if current_fn:
        return current_fn
    if current_impl:
        return current_impl
    return "<top_level>"


def scan_tokens(tokens: Sequence[Token], relative_path: str) -> list[RawLockSite]:
    """Scan a tokenized Rust file for raw lock acquisition sites."""
    prod_mask = production_mask(tokens)
    raw_occurrences: list[tuple[int, str, str, str]] = []  # (line, item, category, expression)

    for i in range(len(tokens) - 3):
        if not prod_mask[i] or tokens[i].kind == "string":
            continue

        # Category: `proc` -> `.proc.lock()`, `.proc.read()`, `.proc.write()`
        if (
            tokens[i].text == "."
            and tokens[i + 1].text == "proc"
            and tokens[i + 2].text == "."
            and tokens[i + 3].text in LOCK_METHODS
            and i + 4 < len(tokens)
            and tokens[i + 4].text == "("
        ):
            enclosing = find_enclosing_item(tokens, i)
            expr = f".proc.{tokens[i + 3].text}()"
            raw_occurrences.append((tokens[i + 1].line, enclosing, "proc", expr))

        # Category: `pty_table` -> `.pty_table.lock()`, `.pty_table().lock()`
        elif (
            tokens[i].text == "."
            and tokens[i + 1].text == "pty_table"
        ):
            cursor = i + 2
            if cursor < len(tokens) and tokens[cursor].text == "(":
                if cursor + 1 < len(tokens) and tokens[cursor + 1].text == ")":
                    cursor += 2
            if (
                cursor + 1 < len(tokens)
                and tokens[cursor].text == "."
                and tokens[cursor + 1].text in LOCK_METHODS
                and cursor + 2 < len(tokens)
                and tokens[cursor + 2].text == "("
            ):
                enclosing = find_enclosing_item(tokens, i)
                expr = f".pty_table.{tokens[cursor + 1].text}()"
                raw_occurrences.append((tokens[i + 1].line, enclosing, "pty_table", expr))

        # Category: `sysv_process` -> `.sysv_process.lock()`
        elif (
            tokens[i].text == "."
            and tokens[i + 1].text == "sysv_process"
            and tokens[i + 2].text == "."
            and tokens[i + 3].text in LOCK_METHODS
            and i + 4 < len(tokens)
            and tokens[i + 4].text == "("
        ):
            enclosing = find_enclosing_item(tokens, i)
            expr = f".sysv_process.{tokens[i + 3].text}()"
            raw_occurrences.append((tokens[i + 1].line, enclosing, "sysv_process", expr))

        # Category: `sysv_namespace` -> `.sysv.state.lock()` or `.state.lock()`
        elif (
            tokens[i].text == "."
            and tokens[i + 1].text == "sysv"
            and tokens[i + 2].text == "."
            and tokens[i + 3].text == "state"
            and i + 5 < len(tokens)
            and tokens[i + 4].text == "."
            and tokens[i + 5].text in LOCK_METHODS
            and i + 6 < len(tokens)
            and tokens[i + 6].text == "("
        ):
            enclosing = find_enclosing_item(tokens, i)
            expr = f".sysv.state.{tokens[i + 5].text}()"
            raw_occurrences.append((tokens[i + 3].line, enclosing, "sysv_namespace", expr))

        elif (
            tokens[i].text == "."
            and tokens[i + 1].text == "state"
            and tokens[i + 2].text == "."
            and tokens[i + 3].text in LOCK_METHODS
            and i + 4 < len(tokens)
            and tokens[i + 4].text == "("
        ):
            enclosing = find_enclosing_item(tokens, i)
            if relative_path.endswith("dispatch/sysv.rs") or relative_path.endswith("dispatch/sysv/lock_authority.rs"):
                expr = f".state.{tokens[i + 3].text}()"
                raw_occurrences.append((tokens[i + 1].line, enclosing, "sysv_namespace", expr))

        # Category: `file_table_internals`
        elif (
            tokens[i].text == "."
            and tokens[i + 1].text in FILE_TABLE_INTERNAL_FIELDS
            and tokens[i + 2].text == "."
            and tokens[i + 3].text in LOCK_METHODS
            and i + 4 < len(tokens)
            and tokens[i + 4].text == "("
        ):
            enclosing = find_enclosing_item(tokens, i)
            expr = f".{tokens[i + 1].text}.{tokens[i + 3].text}()"
            raw_occurrences.append((tokens[i + 1].line, enclosing, "file_table_internals", expr))

    # Assign stable ordinals and unique IDs per (file, item, category)
    ordinal_counters: dict[tuple[str, str], int] = {}
    sites: list[RawLockSite] = []
    for line, item, category, expr in raw_occurrences:
        key = (item, category)
        ordinal = ordinal_counters.get(key, 0) + 1
        ordinal_counters[key] = ordinal
        site_id = f"{relative_path}::{item}::{category}#{ordinal}"
        sites.append(
            RawLockSite(
                id=site_id,
                file=relative_path,
                line=line,
                item=item,
                category=category,
                expression=expr,
                ordinal=ordinal,
            )
        )

    return sites


def scan_sources(repo_root: Path) -> list[RawLockSite]:
    """Scan all configured production sources under carrick-runtime."""
    all_sites: list[RawLockSite] = []
    for target in SCAN_PATHS:
        if target.is_file():
            files = [target]
        elif target.is_dir():
            files = sorted(target.rglob("*.rs"))
        else:
            continue

        for rs_file in files:
            relative = str(rs_file.relative_to(repo_root))
            source = rs_file.read_text(encoding="utf-8")
            tokens = lex_rust(source)
            file_sites = scan_tokens(tokens, relative)
            all_sites.extend(file_sites)

    # Validate that every site ID is globally unique
    seen_ids: set[str] = set()
    for site in all_sites:
        if site.id in seen_ids:
            raise ValueError(f"Duplicate site ID generated: {site.id}")
        seen_ids.add(site.id)

    return sorted(all_sites, key=lambda s: (s.file, s.line, s.id))


def build_inventory_dict(sites: Sequence[RawLockSite]) -> dict[str, Any]:
    counts = {cat: 0 for cat in CATEGORIES}
    entries = []
    for site in sites:
        counts[site.category] = counts.get(site.category, 0) + 1
        entry: dict[str, Any] = {
            "id": site.id,
            "file": site.file,
            "line": site.line,
            "item": site.item,
            "category": site.category,
            "expression": site.expression,
            "ordinal": site.ordinal,
        }
        if site.item.endswith("lock_sysv_process"):
            entry["classification"] = "trusted_minting_boundary"
            entry["rationale"] = "Sole trusted minting boundary for SysvProcessGuard capturing exact namespace reference."
        elif site.item.endswith("lock_paired"):
            entry["classification"] = "trusted_paired_boundary"
            entry["rationale"] = "Sole trusted paired acquisition boundary consuming linearly minted SysvNamespacePermit."
        entries.append(entry)

    return {
        "schema_version": 1,
        "description": "Reviewed inventory of classified production raw lock acquisitions (fail-closed, shrink-only)",
        "total_count": len(entries),
        "category_counts": counts,
        "entries": entries,
    }


ALLOWED_ENTRY_FIELDS = frozenset(
    {"id", "file", "line", "item", "category", "expression", "ordinal", "classification", "rationale"}
)
REQUIRED_ENTRY_FIELDS = frozenset(
    {"id", "file", "line", "item", "category", "expression", "ordinal"}
)


def validate_inventory(
    current_sites: Sequence[RawLockSite], inventory_data: dict[str, Any]
) -> list[str]:
    """Compare current scanned sites against checked-in inventory data."""
    errors: list[str] = []

    if inventory_data.get("schema_version") != 1:
        errors.append(f"Invalid or missing inventory schema_version: {inventory_data.get('schema_version')}")
        return errors

    entries = inventory_data.get("entries")
    if not isinstance(entries, list):
        errors.append("Inventory 'entries' is not a list")
        return errors

    # Check for duplicate IDs and validate entry fields in inventory
    inv_ids: set[str] = set()
    inv_entries_by_id: dict[str, dict[str, Any]] = {}
    for idx, item in enumerate(entries):
        if not isinstance(item, dict):
            errors.append(f"Entry #{idx} is not a dictionary")
            continue

        entry_keys = set(item.keys())
        missing_keys = REQUIRED_ENTRY_FIELDS - entry_keys
        if missing_keys:
            errors.append(f"Entry #{idx} is missing required field(s): {sorted(missing_keys)}")

        extra_keys = entry_keys - ALLOWED_ENTRY_FIELDS
        if extra_keys:
            errors.append(f"Entry #{idx} has disallowed extra field(s): {sorted(extra_keys)}")

        entry_id = item.get("id")
        if not entry_id:
            continue
        if entry_id in inv_ids:
            errors.append(f"Duplicate inventory entry ID: {entry_id}")
            continue
        inv_ids.add(entry_id)
        inv_entries_by_id[entry_id] = item

    # Check header counts
    expected_total = len(entries)
    if inventory_data.get("total_count") != expected_total:
        errors.append(
            f"Header total_count mismatch: declared {inventory_data.get('total_count')}, but entries list has {expected_total}"
        )

    category_counts = inventory_data.get("category_counts")
    if not isinstance(category_counts, dict):
        errors.append("Header category_counts is missing or not a dictionary")
    else:
        actual_counts = {cat: 0 for cat in CATEGORIES}
        for item in entries:
            cat = item.get("category")
            if cat in actual_counts:
                actual_counts[cat] += 1
            else:
                errors.append(f"Entry {item.get('id')} has unknown category: {cat}")
        for cat in CATEGORIES:
            declared = category_counts.get(cat, 0)
            actual = actual_counts.get(cat, 0)
            if declared != actual:
                errors.append(
                    f"Category count mismatch for '{cat}': declared {declared}, actual entries count {actual}"
                )

    curr_sites_by_id = {site.id: site for site in current_sites}
    curr_ids = set(curr_sites_by_id.keys())

    # 1. Unclassified additions (in source, but not in inventory) -> FAIL
    unclassified_ids = curr_ids - inv_ids
    for uid in sorted(unclassified_ids):
        site = curr_sites_by_id[uid]
        errors.append(
            f"Unclassified raw lock acquisition [{site.category}] at {site.file}:{site.line} "
            f"in item `{site.item}`: `{site.expression}` (ID: {site.id}). "
            f"Raw lock additions are forbidden; use encapsulated subsystem authority."
        )

    # 2. Stale or expanded inventory entries (in inventory, but not in source) -> FAIL
    stale_ids = inv_ids - curr_ids
    for sid in sorted(stale_ids):
        entry = inv_entries_by_id[sid]
        errors.append(
            f"Inventory entry not found in production source: {sid} "
            f"({entry.get('file')}:{entry.get('line')}). "
            f"If this site was intentionally migrated/removed, update {DEFAULT_INVENTORY_PATH.name} to record the shrink."
        )

    # 3. Exact metadata agreement for shared IDs
    for common_id in sorted(curr_ids & inv_ids):
        site = curr_sites_by_id[common_id]
        entry = inv_entries_by_id[common_id]
        if site.category != entry.get("category"):
            errors.append(
                f"Metadata mismatch for {common_id}: category in source is '{site.category}', in inventory is '{entry.get('category')}'"
            )
        if site.file != entry.get("file"):
            errors.append(
                f"Metadata mismatch for {common_id}: file in source is '{site.file}', in inventory is '{entry.get('file')}'"
            )
        if site.line != entry.get("line"):
            errors.append(
                f"Metadata mismatch for {common_id}: line in source is {site.line}, in inventory is {entry.get('line')}"
            )
        if site.item != entry.get("item"):
            errors.append(
                f"Metadata mismatch for {common_id}: item in source is '{site.item}', in inventory is '{entry.get('item')}'"
            )
        if site.expression != entry.get("expression"):
            errors.append(
                f"Metadata mismatch for {common_id}: expression in source is '{site.expression}', in inventory is '{entry.get('expression')}'"
            )
        if site.ordinal != entry.get("ordinal"):
            errors.append(
                f"Metadata mismatch for {common_id}: ordinal in source is {site.ordinal}, in inventory is {entry.get('ordinal')}"
            )

    return errors


def run_self_tests() -> bool:
    """Run comprehensive self-tests verifying red-first fail-closed behavior."""
    print("Running check-dispatch-lock-authority self-tests...")

    # Test 1: Comments and strings containing lock patterns must be ignored
    comment_source = """
    // this.proc.lock() in a comment must be ignored
    /* dispatcher.sysv_process.lock() */
    fn safe_fn() {
        let msg = "parent.proc.lock() in string";
        let _ = r#".pty_table.lock()"#;
    }
    """
    tokens = lex_rust(comment_source)
    sites = scan_tokens(tokens, "crates/carrick-runtime/src/test.rs")
    assert len(sites) == 0, f"Comments/strings produced false positives: {sites}"

    # Test 2: Test scopes (#[test] and #[cfg(test)]) must be ignored
    test_scope_source = """
    #[test]
    fn unit_test() {
        parent.proc.lock().do_something();
    }
    #[cfg(test)]
    mod tests {
        fn helper() {
            dispatcher.sysv_process.lock();
        }
    }
    """
    tokens = lex_rust(test_scope_source)
    sites = scan_tokens(tokens, "crates/carrick-runtime/src/test.rs")
    assert len(sites) == 0, f"Test scopes produced false positives: {sites}"

    # Test 3: Raw proc acquisition in production must be detected
    raw_proc_source = """
    impl SyscallDispatcher {
        fn handle_syscall(&self) {
            let mut proc = self.proc.lock();
        }
    }
    """
    tokens = lex_rust(raw_proc_source)
    sites = scan_tokens(tokens, "crates/carrick-runtime/src/dispatch/syscall.rs")
    assert len(sites) == 1, f"Expected 1 raw proc site, got {len(sites)}"
    assert sites[0].category == "proc"
    assert sites[0].ordinal == 1
    assert sites[0].id == "crates/carrick-runtime/src/dispatch/syscall.rs::SyscallDispatcher::handle_syscall::proc#1"

    # Test 4: Raw sysv_process boundary is detected
    sysv_proc_source = """
    impl SyscallDispatcher {
        pub fn lock_sysv_process(&self) {
            let guard = self.sysv_process.lock();
        }
    }
    """
    tokens = lex_rust(sysv_proc_source)
    sites = scan_tokens(tokens, "crates/carrick-runtime/src/dispatch/sysv.rs")
    assert len(sites) == 1, f"Expected 1 sysv_process site, got {len(sites)}"
    assert sites[0].category == "sysv_process"
    assert sites[0].ordinal == 1

    # Test 5: Raw sysv_namespace boundary in lock_authority.rs is detected
    sysv_ns_source = """
    impl SysvNamespacePermit {
        pub fn lock_paired(&self) {
            let state = self.namespace.state.lock();
        }
    }
    """
    tokens = lex_rust(sysv_ns_source)
    sites = scan_tokens(tokens, "crates/carrick-runtime/src/dispatch/sysv/lock_authority.rs")
    assert len(sites) == 1, f"Expected 1 sysv_namespace site, got {len(sites)}"
    assert sites[0].category == "sysv_namespace"
    assert sites[0].ordinal == 1

    # Test 6: Multiple identical acquisitions in one function get distinct ordinals
    multi_source = """
    impl SyscallDispatcher {
        fn complex_fn(&self) {
            let _a = self.proc.lock();
            let _b = self.proc.lock();
        }
    }
    """
    tokens = lex_rust(multi_source)
    sites = scan_tokens(tokens, "crates/carrick-runtime/src/dispatch/mod.rs")
    assert len(sites) == 2, f"Expected 2 sites, got {len(sites)}"
    assert sites[0].ordinal == 1
    assert sites[1].ordinal == 2
    assert sites[0].id != sites[1].id

    # Test 7: FileTable internals in kernel/objects.rs are detected
    file_table_source = """
    impl FileTable {
        fn read_next(&self) {
            let _ = self.next_fd.lock();
        }
    }
    """
    tokens = lex_rust(file_table_source)
    sites = scan_tokens(tokens, "crates/carrick-runtime/src/kernel/objects.rs")
    assert len(sites) == 1, f"Expected 1 file_table_internals site, got {len(sites)}"
    assert sites[0].category == "file_table_internals"

    # Test 8: Validation against valid inventory passes
    inv = build_inventory_dict(sites)
    errors = validate_inventory(sites, inv)
    assert len(errors) == 0, f"Valid inventory failed: {errors}"

    # Test 9: Unclassified raw lock addition must FAIL validation
    extra_sites = list(sites) + [
        RawLockSite(
            id="crates/carrick-runtime/src/dispatch/mod.rs::SyscallDispatcher::new_leak::proc#1",
            file="crates/carrick-runtime/src/dispatch/mod.rs",
            line=100,
            item="SyscallDispatcher::new_leak",
            category="proc",
            expression=".proc.lock()",
            ordinal=1,
        )
    ]
    errors = validate_inventory(extra_sites, inv)
    assert any("Unclassified raw lock acquisition" in e for e in errors), f"Addition did not fail: {errors}"

    # Test 10: Stale/expanded inventory entry must FAIL validation
    expanded_inv = dict(inv)
    expanded_entries = list(inv["entries"]) + [
        {
            "id": "crates/carrick-runtime/src/dispatch/mod.rs::SyscallDispatcher::stale::proc#1",
            "file": "crates/carrick-runtime/src/dispatch/mod.rs",
            "line": 999,
            "item": "SyscallDispatcher::stale",
            "category": "proc",
            "expression": ".proc.lock()",
            "ordinal": 1,
        }
    ]
    expanded_inv["entries"] = expanded_entries
    expanded_inv["total_count"] = len(expanded_entries)
    expanded_inv["category_counts"]["proc"] = expanded_inv["category_counts"].get("proc", 0) + 1
    errors = validate_inventory(sites, expanded_inv)
    assert any("Inventory entry not found in production source" in e for e in errors), f"Stale inventory did not fail: {errors}"

    # Test 11: Duplicate ID in inventory must FAIL validation
    dup_inv = dict(inv)
    dup_entries = list(inv["entries"]) + [inv["entries"][0]]
    dup_inv["entries"] = dup_entries
    dup_inv["total_count"] = len(dup_entries)
    errors = validate_inventory(sites, dup_inv)
    assert any("Duplicate inventory entry ID" in e for e in errors), f"Duplicate ID did not fail: {errors}"

    # Test 12: Header count mismatch must FAIL validation
    mismatch_inv = dict(inv)
    mismatch_inv["total_count"] = 999
    errors = validate_inventory(sites, mismatch_inv)
    assert any("Header total_count mismatch" in e for e in errors), f"Count mismatch did not fail: {errors}"

    # Test 13: Extra disallowed field in inventory entry must FAIL validation
    extra_field_inv = dict(inv)
    extra_field_entries = [dict(inv["entries"][0], unreviewed_extra="illegal")]
    extra_field_inv["entries"] = extra_field_entries
    errors = validate_inventory(sites, extra_field_inv)
    assert any("disallowed extra field" in e for e in errors), f"Extra field did not fail: {errors}"

    # Test 14: Metadata mismatch (e.g. line drift or expression) must FAIL validation
    line_drift_inv = dict(inv)
    line_drift_entries = [dict(inv["entries"][0], line=inv["entries"][0]["line"] + 10)]
    line_drift_inv["entries"] = line_drift_entries
    errors = validate_inventory(sites, line_drift_inv)
    assert any("Metadata mismatch" in e for e in errors), f"Line drift did not fail: {errors}"

    print("All check-dispatch-lock-authority self-tests PASSED.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Validate production source matches inventory")
    parser.add_argument("--candidate", type=Path, help="Write scanned candidate inventory to specified path")
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY_PATH, help="Path to inventory JSON")
    parser.add_argument("--self-test", action="store_true", help="Run comprehensive unit tests")

    args = parser.parse_args()

    if args.self_test:
        return 0 if run_self_tests() else 1

    current_sites = scan_sources(REPO_ROOT)

    if args.candidate:
        candidate_data = build_inventory_dict(current_sites)
        args.candidate.write_text(json.dumps(candidate_data, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote candidate inventory ({len(current_sites)} sites) to {args.candidate}")
        return 0

    if not args.inventory.exists():
        print(f"Error: Inventory file {args.inventory} not found.", file=sys.stderr)
        return 1

    try:
        inventory_data = json.loads(args.inventory.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Error reading inventory JSON {args.inventory}: {e}", file=sys.stderr)
        return 1

    errors = validate_inventory(current_sites, inventory_data)
    if errors:
        print(f"FAIL: Found {len(errors)} dispatch lock authority inventory violation(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"OK: Verified exact match of {len(current_sites)} production raw lock sites against {args.inventory.name}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())


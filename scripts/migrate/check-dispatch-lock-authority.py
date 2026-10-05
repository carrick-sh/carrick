#!/usr/bin/env python3
"""Check and enforce dispatch lock authority across production runtime sources.

This gate inventories raw lock acquisitions in `crates/carrick-kernel/src`:
- `proc` dispatcher state
- `pty_table` state
- `sysv_process` and `sysv_namespace` state
- `file_table_internals`

It enforces that:
1. No unclassified or newly added raw lock acquisitions can appear (fail-closed, shrink-only).
2. Paired SysV mutations use the typed `SysvProcessGuard` -> `SysvNamespacePermit` -> `lock_paired` authority.
3. Standalone SysV operations use the encapsulated `with_state` / `with_sysv_process` closures.
4. Monotone category and total count ceilings cannot be exceeded.
5. Exact trusted boundaries and their classifications are validated.
6. Test scopes, comments, and string literals are ignored.
7. Findings are consumed ephemerally by the position-free authority-debt gate.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
SCAN_PATHS = [REPO_ROOT / "crates" / "carrick-kernel" / "src"]

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
        "epoll_fds",
    }
)

LOCK_METHODS = frozenset(
    {
        "lock",
        "try_lock",
        "try_lock_for",
        "try_lock_until",
        "lock_arc",
        "read",
        "try_read",
        "try_read_for",
        "try_read_until",
        "read_arc",
        "write",
        "try_write",
        "try_write_for",
        "try_write_until",
        "write_arc",
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


# `feature = "test-support"` is test scope, exactly like `test`. Splitting the
# runtime into carrick-kernel + carrick-runtime moved test fixtures out of the
# crate whose tests consume them, and `cfg(test)` is per-crate-compilation, so
# those fixtures are gated `cfg(any(test, feature = "test-support"))`. No
# product target enables `test-support`, so the gate still means "test code" in
# every shipped build. Matching the exact feature NAME keeps this narrow: any
# other `feature = "..."` term is still production.
_TEST_SUPPORT_TERMS = ("feature", "=", '"test-support"')


def _is_test_only_attribute(tokens: Sequence[Token], start: int, end: int) -> bool:
    """Return True only if the attribute is strictly test-only (e.g. #[test], #[cfg(test)])."""
    attr_texts = [item.text for item in tokens[start:end]]
    if attr_texts == ["test"]:
        return True
    if attr_texts == ["cfg", "(", "test", ")"]:
        return True
    if "any" in attr_texts:
        # `any(test, feature = "test-support")` (alone or nested inside an
        # `all(...)`) is still test-only: every disjunct is a test term.
        stripped = [t for t in attr_texts if t not in ("cfg", "any", "all", "(", ")", ",")]
        residual = list(stripped)
        for term in _TEST_SUPPORT_TERMS:
            if term in residual:
                residual.remove(term)
            else:
                return False
        return bool(residual) and all(
            t == "test" or t.startswith('"') or t in ("target_os", "target_arch", "=")
            for t in residual
        ) and "test" in residual
    if "not" in attr_texts and "test" in attr_texts:
        return False
    if attr_texts and attr_texts[0] == "cfg" and "test" in attr_texts:
        return True
    return False


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
            if _is_test_only_attribute(tokens, index + 2, end):
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

    # Track local variable bindings inside functions for local lock alias detection
    fn_aliases: dict[str, str] = {}

    i = 0
    while i < len(tokens):
        if not prod_mask[i] or tokens[i].kind == "string":
            i += 1
            continue

        # Check for let binding alias: `let [mut] var_name = ...`
        if tokens[i].text == "let" and i + 1 < len(tokens):
            idx = i + 1
            if idx < len(tokens) and tokens[idx].text == "mut":
                idx += 1
            if idx < len(tokens) and tokens[idx].kind == "ident":
                var_name = tokens[idx].text
                eq_idx = -1
                semi_idx = -1
                for j in range(idx + 1, min(idx + 30, len(tokens))):
                    if tokens[j].text == "=":
                        eq_idx = j
                    elif tokens[j].text in {";", "{"}:
                        semi_idx = j
                        break
                if eq_idx != -1 and semi_idx != -1:
                    rhs_tokens = [t.text for t in tokens[eq_idx + 1 : semi_idx] if t.text not in {"&", "mut", "*", "(", ")"}]
                    if rhs_tokens and rhs_tokens[-1] == "proc":
                        fn_aliases[var_name] = "proc"
                    elif rhs_tokens and rhs_tokens[-1] == "pty_table":
                        fn_aliases[var_name] = "pty_table"
                    elif rhs_tokens and rhs_tokens[-1] == "sysv_process":
                        fn_aliases[var_name] = "sysv_process"
                    elif rhs_tokens and rhs_tokens[-1] == "state" and (
                        "sysv" in rhs_tokens
                        or relative_path.endswith("dispatch/sysv.rs")
                        or relative_path.endswith("dispatch/sysv/lock_authority.rs")
                    ):
                        fn_aliases[var_name] = "sysv_namespace"
                    elif rhs_tokens and rhs_tokens[-1] in FILE_TABLE_INTERNAL_FIELDS:
                        fn_aliases[var_name] = "file_table_internals"

        # Check for lock method invocation: `.<lock_method>(`
        if (
            tokens[i].text == "."
            and i + 1 < len(tokens)
            and tokens[i + 1].text in LOCK_METHODS
            and i + 2 < len(tokens)
            and tokens[i + 2].text == "("
        ):
            lock_method = tokens[i + 1].text
            enclosing = find_enclosing_item(tokens, i)
            category = None
            expr = None

            # Look backwards from `.` at `i`
            # Case 1: Immediately preceded by `)` -> parenthesized or method call
            if i > 0 and tokens[i - 1].text == ")":
                open_idx = -1
                paren_depth = 0
                for k in range(i - 1, -1, -1):
                    if tokens[k].text == ")":
                        paren_depth += 1
                    elif tokens[k].text == "(":
                        paren_depth -= 1
                        if paren_depth == 0:
                            open_idx = k
                            break
                if open_idx != -1:
                    if open_idx > 0 and tokens[open_idx - 1].text == "pty_table":
                        category = "pty_table"
                        expr = f".pty_table.{lock_method}()"
                    else:
                        inner_tokens = [
                            t.text for t in tokens[open_idx + 1 : i - 1] if t.text not in {"(", ")"}
                        ]
                        if inner_tokens:
                            if inner_tokens[-1] == "proc":
                                category = "proc"
                                expr = f".proc.{lock_method}()"
                            elif inner_tokens[-1] == "sysv_process":
                                category = "sysv_process"
                                expr = f".sysv_process.{lock_method}()"
                            elif inner_tokens[-1] == "state" and (
                                "sysv" in inner_tokens
                                or relative_path.endswith("dispatch/sysv.rs")
                                or relative_path.endswith("dispatch/sysv/lock_authority.rs")
                            ):
                                category = "sysv_namespace"
                                expr = f".sysv.state.{lock_method}()" if "sysv" in inner_tokens else f".state.{lock_method}()"
                            elif inner_tokens[-1] == "pty_table":
                                category = "pty_table"
                                expr = f".pty_table.{lock_method}()"
                            elif inner_tokens[-1] in FILE_TABLE_INTERNAL_FIELDS:
                                category = "file_table_internals"
                                expr = f".{inner_tokens[-1]}.{lock_method}()"
                            elif len(inner_tokens) == 1 and inner_tokens[0] in fn_aliases:
                                category = fn_aliases[inner_tokens[0]]
                                expr = f"{inner_tokens[0]}.{lock_method}()"

            # Case 2: Immediately preceded by an ident
            elif i > 0 and tokens[i - 1].kind == "ident":
                prev_ident = tokens[i - 1].text
                if i > 1 and tokens[i - 2].text == ".":
                    if prev_ident == "proc":
                        category = "proc"
                        expr = f".proc.{lock_method}()"
                    elif prev_ident == "pty_table":
                        category = "pty_table"
                        expr = f".pty_table.{lock_method}()"
                    elif prev_ident == "sysv_process":
                        category = "sysv_process"
                        expr = f".sysv_process.{lock_method}()"
                    elif prev_ident == "state":
                        if i > 3 and tokens[i - 3].text == "sysv" and tokens[i - 4].text == ".":
                            category = "sysv_namespace"
                            expr = f".sysv.state.{lock_method}()"
                        elif relative_path.endswith("dispatch/sysv.rs") or relative_path.endswith("dispatch/sysv/lock_authority.rs"):
                            category = "sysv_namespace"
                            expr = f".state.{lock_method}()"
                    elif prev_ident in FILE_TABLE_INTERNAL_FIELDS:
                        category = "file_table_internals"
                        expr = f".{prev_ident}.{lock_method}()"
                elif prev_ident in fn_aliases:
                    category = fn_aliases[prev_ident]
                    expr = f"{prev_ident}.{lock_method}()"

            if category is not None and expr is not None:
                raw_occurrences.append((tokens[i].line, enclosing, category, expr))

        i += 1

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
    for old_target in SCAN_PATHS:
        target = repo_root / old_target.relative_to(REPO_ROOT)
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


def validate_sysv_lock_authority_rules(
    repo_root: Path,
    override_sources: dict[str, str] | None = None,
) -> list[str]:
    """Validate exact visibility tokens and strict caller boundaries for SysV lock authority APIs."""
    errors: list[str] = []

    def get_source(rel_path: str) -> str:
        if override_sources and rel_path in override_sources:
            return override_sources[rel_path]
        full_path = repo_root / rel_path
        return full_path.read_text(encoding="utf-8") if full_path.exists() else ""

    # 1. Check exact visibility tokens in crates/carrick-kernel/src/dispatch/sysv.rs
    sysv_source = get_source("crates/carrick-kernel/src/dispatch/sysv.rs")
    expected_restricted_fns = {"with_state", "with_state_mut", "lock_sysv_process", "with_sysv_process", "with_sysv_process_mut"}
    seen_helpers = set()
    if sysv_source:
        sysv_tokens = lex_rust(sysv_source)
        expected_restricted_fns = {
            "with_state",
            "with_state_mut",
            "lock_sysv_process",
            "with_sysv_process",
            "with_sysv_process_mut",
        }
        for idx, token in enumerate(sysv_tokens):
            if token.text == "fn" and idx + 1 < len(sysv_tokens) and sysv_tokens[idx + 1].text in expected_restricted_fns:
                fn_name = sysv_tokens[idx + 1].text
                seen_helpers.add(fn_name)
                # Look backward from `fn` for visibility starting at `pub`
                vis_tokens = []
                k = idx - 1
                found_pub = False
                while k >= 0 and sysv_tokens[k].text not in {"}", ";", "{"}:
                    if sysv_tokens[k].text == "pub":
                        found_pub = True
                        vis_tokens = [t.text for t in sysv_tokens[k:idx]]
                        break
                    k -= 1
                expected_vis = ["pub", "(", "in", "crate", "::", "dispatch", "::", "sysv", ")"]
                if not found_pub or vis_tokens != expected_vis:
                    vis_str = "".join(vis_tokens) if vis_tokens else "private"
                    errors.append(
                        f"crates/carrick-kernel/src/dispatch/sysv.rs: helper '{fn_name}' has unauthorized visibility '{vis_str}' (must be exact 'pub(in crate::dispatch::sysv)')"
                    )

    missing = expected_restricted_fns - seen_helpers
    if missing:
        errors.append(f"missing SysV rule owner/helper discovery: {sorted(missing)}")
    paired_source = get_source("crates/carrick-kernel/src/dispatch/sysv/lock_authority.rs")
    paired_tokens = lex_rust(paired_source)
    if not any(t.text == "fn" and i + 1 < len(paired_tokens) and paired_tokens[i + 1].text == "lock_paired" for i, t in enumerate(paired_tokens)):
        errors.append("missing SysvNamespacePermit::lock_paired rule owner discovery")

    # 2. Check strict cross-module caller boundary
    runtime_src = repo_root / "crates/carrick-kernel/src"
    if runtime_src.exists() or override_sources:
        restricted_identifiers = {
            "lock_sysv_process",
            "with_sysv_process",
            "with_sysv_process_mut",
            "SysvProcessGuard",
            "SysvNamespacePermit",
            "SysvPairedNamespaceGuard",
            "lock_paired",
        }
        files_to_check: list[tuple[str, str]] = []
        if override_sources:
            for rpath, src in override_sources.items():
                if (
                    rpath.startswith("crates/carrick-kernel/src/")
                    and not rpath.startswith("crates/carrick-kernel/src/dispatch/sysv")
                    and not rpath.endswith("dispatch/sysv.rs")
                ):
                    files_to_check.append((rpath, src))
        else:
            for path in sorted(runtime_src.rglob("*.rs")):
                rpath = str(path.relative_to(repo_root))
                if not rpath.startswith("crates/carrick-kernel/src/dispatch/sysv") and not rpath.endswith("dispatch/sysv.rs"):
                    files_to_check.append((rpath, path.read_text(encoding="utf-8")))

        for rpath, src in files_to_check:
            tokens = lex_rust(src)
            prod_mask = production_mask(tokens)
            for idx, token in enumerate(tokens):
                if not prod_mask[idx]:
                    continue
                if token.text in restricted_identifiers:
                    errors.append(
                        f"{rpath}:{token.line}: unauthorized cross-module reference to SysV lock authority identifier '{token.text}' outside dispatch::sysv"
                    )
                elif token.text in {"with_state", "with_state_mut"}:
                    # Check if called on sysv namespace
                    if idx > 0 and tokens[idx - 1].text == ".":
                        if idx > 1 and tokens[idx - 2].kind == "ident" and tokens[idx - 2].text in {"sysv", "namespace", "ipc"}:
                            errors.append(
                                f"{rpath}:{token.line}: unauthorized cross-module call to '{token.text}' outside dispatch::sysv"
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
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/syscall.rs")
    assert len(sites) == 1, f"Expected 1 raw proc site, got {len(sites)}"
    assert sites[0].category == "proc"
    assert sites[0].ordinal == 1
    assert sites[0].id == "crates/carrick-kernel/src/dispatch/syscall.rs::SyscallDispatcher::handle_syscall::proc#1"

    # Test 4: Raw sysv_process boundary is detected
    sysv_proc_source = """
    impl SyscallDispatcher {
        pub fn lock_sysv_process(&self) {
            let guard = self.sysv_process.lock();
        }
    }
    """
    tokens = lex_rust(sysv_proc_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/sysv.rs")
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
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/sysv/lock_authority.rs")
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
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/mod.rs")
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
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/kernel/objects.rs")
    assert len(sites) == 1, f"Expected 1 file_table_internals site, got {len(sites)}"
    assert sites[0].category == "file_table_internals"

    # Adversarial Bypass Test 8: Parenthesized compound field `(x.sysv.state).lock()`
    paren_compound_source = """
    fn bypass_paren(d: &SyscallDispatcher) {
        let _g = (d.sysv.state).lock();
    }
    """
    tokens = lex_rust(paren_compound_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/sysv.rs")
    assert len(sites) == 1, f"Parenthesized compound bypass was not caught: {sites}"
    assert sites[0].category == "sysv_namespace"

    # Adversarial Bypass Test 9: Parenthesized proc field `(self.proc).read()`
    paren_proc_source = """
    impl SyscallDispatcher {
        fn bypass_proc_paren(&self) {
            let _g = (self.proc).read();
        }
    }
    """
    tokens = lex_rust(paren_proc_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/proc.rs")
    assert len(sites) == 1, f"Parenthesized proc bypass was not caught: {sites}"
    assert sites[0].category == "proc"

    # Adversarial Bypass Test 10: Local lock alias `let p = &self.proc; p.lock();`
    alias_proc_source = """
    impl SyscallDispatcher {
        fn bypass_alias(&self) {
            let p = &self.proc;
            let _g = p.lock();
        }
    }
    """
    tokens = lex_rust(alias_proc_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/mod.rs")
    assert len(sites) == 1, f"Local alias bypass was not caught: {sites}"
    assert sites[0].category == "proc"

    # Adversarial Bypass Test 11: Timed / alternative lock methods `try_lock_for`, `try_write_until`
    timed_methods_source = """
    impl SyscallDispatcher {
        fn bypass_timed(&self, d: Duration, t: Instant) {
            let _a = self.proc.try_lock_for(d);
            let _b = self.sysv_process.try_write_until(t);
        }
    }
    """
    tokens = lex_rust(timed_methods_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/mod.rs")
    assert len(sites) == 2, f"Timed methods were not caught: {sites}"
    assert sites[0].category == "proc"
    assert sites[1].category == "sysv_process"

    # Adversarial Bypass Test 12: Production code under `#[cfg(any(test, target_os = "macos"))]` must NOT be ignored
    cfg_any_source = """
    #[cfg(any(test, target_os = "macos"))]
    fn macos_prod_path(d: &SyscallDispatcher) {
        let _g = d.proc.lock();
    }
    """
    tokens = lex_rust(cfg_any_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/mod.rs")
    assert len(sites) == 1, f"cfg(any(...)) production code was falsely ignored: {sites}"
    assert sites[0].category == "proc"

    # Test 18: Negative visibility test - pub(crate) on with_state must FAIL
    widened_vis_source = """
    impl SysvIpcNamespace {
        pub(crate) fn with_state<F, R>(&self, f: F) -> R { f(&self.state) }
    }
    """
    errs = validate_sysv_lock_authority_rules(
        REPO_ROOT,
        override_sources={"crates/carrick-kernel/src/dispatch/sysv.rs": widened_vis_source},
    )
    assert any("helper 'with_state' has unauthorized visibility 'pub(crate)'" in e for e in errs), f"Widened visibility did not fail: {errs}"

    # Test 19: Negative visibility test - pub on lock_sysv_process must FAIL
    pub_vis_source = """
    impl SyscallDispatcher {
        pub fn lock_sysv_process(&self) {}
    }
    """
    errs = validate_sysv_lock_authority_rules(
        REPO_ROOT,
        override_sources={"crates/carrick-kernel/src/dispatch/sysv.rs": pub_vis_source},
    )
    assert any("helper 'lock_sysv_process' has unauthorized visibility 'pub'" in e for e in errs), f"Public visibility did not fail: {errs}"

    # Test 20: Negative caller test - sibling module calling lock_sysv_process must FAIL
    sibling_caller_source = """
    impl SyscallDispatcher {
        fn leak_sysv(&self) {
            let _g = self.lock_sysv_process();
        }
    }
    """
    errs = validate_sysv_lock_authority_rules(
        REPO_ROOT,
        override_sources={
            "crates/carrick-kernel/src/dispatch/sysv.rs": "",
            "crates/carrick-kernel/src/dispatch/fs.rs": sibling_caller_source,
        },
    )
    assert any("unauthorized cross-module reference to SysV lock authority identifier 'lock_sysv_process'" in e for e in errs), f"Sibling caller did not fail: {errs}"

    # Test 21: Negative caller test - sibling module calling namespace.with_state must FAIL
    sibling_ns_caller_source = """
    fn leak_ns(d: &SyscallDispatcher) {
        d.sysv.with_state(|_| ());
    }
    """
    errs = validate_sysv_lock_authority_rules(
        REPO_ROOT,
        override_sources={
            "crates/carrick-kernel/src/dispatch/sysv.rs": "",
            "crates/carrick-kernel/src/dispatch/net.rs": sibling_ns_caller_source,
        },
    )
    assert any("unauthorized cross-module call to 'with_state'" in e for e in errs), f"Sibling namespace caller did not fail: {errs}"

    # Test 22: Negative caller test - sibling module referencing SysvNamespacePermit must FAIL
    sibling_permit_source = """
    fn leak_permit(_p: &SysvNamespacePermit) {}
    """
    errs = validate_sysv_lock_authority_rules(
        REPO_ROOT,
        override_sources={
            "crates/carrick-kernel/src/dispatch/sysv.rs": "",
            "crates/carrick-kernel/src/dispatch/mod.rs": sibling_permit_source,
        },
    )
    assert any("unauthorized cross-module reference to SysV lock authority identifier 'SysvNamespacePermit'" in e for e in errs), f"Sibling permit reference did not fail: {errs}"

    print("All check-dispatch-lock-authority self-tests PASSED (16 fixtures).")
    return True


def main():
    parser = argparse.ArgumentParser(description="Discover raw locks and check structural SysV authority")
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--discover", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return 0 if run_self_tests() else 1
    errors = validate_sysv_lock_authority_rules(args.root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    sites = scan_sources(args.root)
    print(json.dumps([{"file": s.file, "line": s.line, "category": s.category} for s in sites]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

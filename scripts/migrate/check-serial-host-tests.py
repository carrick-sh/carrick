#!/usr/bin/env python3
"""Enforce serial_host isolation for tests with process-wide / host-wide effects.

Every #[test] or test helper in carrick-kernel and carrick-vfs that:
- forks (libc::fork)
- spawns subprocesses (std::process::Command::new / .spawn())
- mutates process environment (std::env::set_var / remove_var)
- alters process resource limits (libc::setrlimit)
- alters process file-creation mask (libc::umask)
- reads/resets host-syscall budgets (test_host_openat_count, test_host_stat_count)
- reads/mutates process-wide resolve cache generations (fs_resolve_cache::*, HOST_XATTR_READS)
must live inside a `mod serial_host` module so that the parallel test runner
(`cargo test -- --skip serial_host`) runs only fork-free, process-isolated tests,
while the serial runner (`RUST_TEST_THREADS=1 cargo test serial_host`) runs the rest.

Transitive calls from tests or helpers outside `mod serial_host` to helpers
that perform these operations are also detected and reported.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
import re
import sys
from typing import Sequence


@dataclass(frozen=True)
class Token:
    kind: str  # 'ident', 'punct', 'string', 'char', 'number'
    text: str
    line: int
    col: int


def lex_rust(source: str) -> list[Token]:
    """Tokenize Rust source while stripping comments and preserving string/char literals with line info."""
    tokens: list[Token] = []
    i = 0
    line = 1
    col = 1
    length = len(source)

    while i < length:
        char = source[i]

        # Whitespace
        if char.isspace():
            if char == "\n":
                line += 1
                col = 1
            else:
                col += 1
            i += 1
            continue

        # Line comment //
        if source[i : i + 2] == "//":
            i += 2
            col += 2
            while i < length and source[i] != "\n":
                i += 1
                col += 1
            continue

        # Block comment /* ... */ (nested)
        if source[i : i + 2] == "/*":
            i += 2
            col += 2
            depth = 1
            while i < length and depth > 0:
                if source[i] == "\n":
                    line += 1
                    col = 1
                    i += 1
                elif source[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                    col += 2
                elif source[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                    col += 2
                else:
                    i += 1
                    col += 1
            continue

        # Raw string literals: r"...", r#"..."#, br"...", br#"...", cr"...", cr#"..."
        raw_prefix = 0
        if char == "r" and i + 1 < length and (source[i + 1] in ('"', "#")):
            raw_prefix = 1
        elif (
            char in ("b", "c")
            and i + 2 < length
            and source[i + 1] == "r"
            and (source[i + 2] in ('"', "#"))
        ):
            raw_prefix = 2

        if raw_prefix > 0:
            start_i = i
            start_line = line
            start_col = col
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
                raw_text = source[start_i:end]
                tokens.append(Token("string", raw_text, start_line, start_col))
                lines_in_str = raw_text.count("\n")
                if lines_in_str > 0:
                    line += lines_in_str
                    col = len(raw_text.rsplit("\n", 1)[-1]) + 1
                else:
                    col += len(raw_text)
                i = end
                continue

        # Regular string literals: "...", b"...", c"..."
        if char == '"' or (
            char in ("b", "c") and i + 1 < length and source[i + 1] == '"'
        ):
            start_i = i
            start_line = line
            start_col = col
            if char in ("b", "c"):
                i += 1
                col += 1
            i += 1
            col += 1
            while i < length:
                c = source[i]
                if c == "\n":
                    line += 1
                    col = 1
                    i += 1
                elif c == "\\":
                    i += 2
                    col += 2
                elif c == '"':
                    i += 1
                    col += 1
                    break
                else:
                    i += 1
                    col += 1
            tokens.append(Token("string", source[start_i:i], start_line, start_col))
            continue

        # Char literals / Lifetimes: '...', b'...'
        if char == "'" or (char == "b" and i + 1 < length and source[i + 1] == "'"):
            start_i = i
            start_line = line
            start_col = col
            byte_char = char == "b"
            if byte_char:
                i += 1
                col += 1
            i += 1
            col += 1

            # Check if lifetime e.g. 'a, 'static, 'de
            if not byte_char and i < length and (source[i].isalpha() or source[i] == "_"):
                scan = i
                while scan < length and (source[scan].isalnum() or source[scan] == "_"):
                    scan += 1
                if scan >= length or source[scan] != "'":
                    lifetime_text = source[start_i:scan]
                    tokens.append(Token("ident", lifetime_text, start_line, start_col))
                    col += scan - start_i
                    i = scan
                    continue

            # Char literal
            while i < length:
                c = source[i]
                if c == "\n":
                    line += 1
                    col = 1
                    i += 1
                elif c == "\\":
                    i += 2
                    col += 2
                elif c == "'":
                    i += 1
                    col += 1
                    break
                else:
                    i += 1
                    col += 1
            tokens.append(Token("char", source[start_i:i], start_line, start_col))
            continue

        # Identifiers
        if char.isalpha() or char == "_":
            start_i = i
            start_line = line
            start_col = col
            while i < length and (source[i].isalnum() or source[i] == "_"):
                i += 1
            ident_text = source[start_i:i]
            tokens.append(Token("ident", ident_text, start_line, start_col))
            col += len(ident_text)
            continue

        # Numbers
        if char.isdigit():
            start_i = i
            start_line = line
            start_col = col
            while i < length and (source[i].isalnum() or source[i] in "._"):
                if source[i] == "." and i + 1 < length and source[i + 1] == ".":
                    break
                i += 1
            num_text = source[start_i:i]
            tokens.append(Token("number", num_text, start_line, start_col))
            col += len(num_text)
            continue

        # Multi-character punctuation
        two = source[i : i + 2]
        if two in (
            "::",
            "->",
            "=>",
            "==",
            "!=",
            "<=",
            ">=",
            "&&",
            "||",
            "..",
            "+=",
            "-=",
            "<<",
            ">>",
        ):
            tokens.append(Token("punct", two, line, col))
            i += 2
            col += 2
            continue

        # Single-character punctuation
        tokens.append(Token("punct", char, line, col))
        i += 1
        col += 1

    return tokens


@dataclass
class FunctionInfo:
    name: str
    type_name: str | None
    line: int
    is_test: bool
    is_test_context: bool
    in_serial_host: bool
    direct_violations: list[tuple[str, int, str]] = field(default_factory=list)
    callees: set[str] = field(default_factory=set)

    @property
    def full_name(self) -> str:
        if self.type_name:
            return f"{self.type_name}::{self.name}"
        return self.name


@dataclass
class ModuleScope:
    name: str
    in_serial_host: bool
    is_test: bool
    brace_depth: int


@dataclass
class ImplScope:
    type_name: str
    in_serial_host: bool
    is_test: bool
    brace_depth: int


def _is_test_path(path_str: str) -> bool:
    p = Path(path_str)
    return (
        p.name == "tests.rs"
        or p.name.endswith("_tests.rs")
        or "/tests/" in path_str
        or path_str.endswith("/tests")
    )


def _scan_function_body(
    body_tokens: Sequence[Token],
    is_test_context: bool,
) -> tuple[list[tuple[str, int, str]], set[str]]:
    """Scan tokens in a function body for direct serial operations and callees."""
    direct_violations: list[tuple[str, int, str]] = []
    callees: set[str] = set()

    n = len(body_tokens)
    idx = 0

    while idx < n:
        tok = body_tokens[idx]
        prev_tok = body_tokens[idx - 1] if idx > 0 else None

        # Check callees:
        # 1. <Type> :: <ident> ( -> callee is "<Type>::<ident>", "<Type>"
        # 2. serial_host :: <ident> ( -> callee is "<ident>"
        # 3. serial_host :: <Type> :: <ident> ( -> callee is "<Type>::<ident>", "<Type>"
        # 4. <ident> ( -> callee is "<ident>" (only if not preceded by '::' or '.')
        # 5. <Type> { -> callee is "<Type>" (struct construction)
        if tok.kind == "ident":
            # Check for <ident1> :: <ident2>
            if idx + 2 < n and body_tokens[idx + 1].text == "::" and body_tokens[idx + 2].kind == "ident":
                ident1 = tok.text
                ident2 = body_tokens[idx + 2].text
                if ident1 == "serial_host":
                    if idx + 4 < n and body_tokens[idx + 3].text == "::" and body_tokens[idx + 4].kind == "ident":
                        ident3 = body_tokens[idx + 4].text
                        callees.add(f"{ident2}::{ident3}")
                        callees.add(ident2)
                    else:
                        callees.add(ident2)
                else:
                    callees.add(f"{ident1}::{ident2}")
                    callees.add(ident1)

            # Check for bare <ident> (
            elif idx + 1 < n and body_tokens[idx + 1].text == "(":
                if prev_tok is None or prev_tok.text not in ("::", "."):
                    callees.add(tok.text)

            # Check for struct init <Type> {
            elif idx + 1 < n and body_tokens[idx + 1].text == "{":
                if prev_tok is None or prev_tok.text not in ("::", "."):
                    callees.add(tok.text)

        # Check direct serial operations (only in test context)
        if is_test_context:
            # 1. libc::fork
            if (
                tok.text == "libc"
                and idx + 2 < n
                and body_tokens[idx + 1].text == "::"
                and body_tokens[idx + 2].text == "fork"
            ):
                direct_violations.append(("libc::fork", tok.line, "calls libc::fork"))

            # 2. Command::new / process::Command::new / std::process::Command::new / Command::spawn
            elif (
                tok.text == "Command"
                and idx + 2 < n
                and body_tokens[idx + 1].text == "::"
                and body_tokens[idx + 2].text in ("new", "spawn")
            ):
                direct_violations.append(("Command::new", tok.line, f"calls Command::{body_tokens[idx + 2].text}"))

            # 3. std::env::set_var / remove_var / env::set_var / set_var(
            elif tok.text in ("set_var", "remove_var") and idx + 1 < n and body_tokens[idx + 1].text == "(":
                if prev_tok is None or prev_tok.text != ".":
                    direct_violations.append((f"std::env::{tok.text}", tok.line, f"calls std::env::{tok.text}"))

            # 4. libc::setrlimit / setrlimit(
            elif (
                tok.text == "libc"
                and idx + 2 < n
                and body_tokens[idx + 1].text == "::"
                and body_tokens[idx + 2].text == "setrlimit"
            ):
                direct_violations.append(("libc::setrlimit", tok.line, "calls libc::setrlimit"))
            elif tok.text == "setrlimit" and idx + 1 < n and body_tokens[idx + 1].text == "(":
                if prev_tok is None or prev_tok.text != ".":
                    direct_violations.append(("libc::setrlimit", tok.line, "calls libc::setrlimit"))

            # 5. libc::umask / umask(
            elif (
                tok.text == "libc"
                and idx + 2 < n
                and body_tokens[idx + 1].text == "::"
                and body_tokens[idx + 2].text == "umask"
            ):
                direct_violations.append(("libc::umask", tok.line, "calls libc::umask"))
            elif tok.text == "umask" and idx + 1 < n and body_tokens[idx + 1].text == "(":
                if prev_tok is None or prev_tok.text != ".":
                    direct_violations.append(("libc::umask", tok.line, "calls libc::umask"))

            # 6. Host metric & openat/stat counters
            elif tok.text in (
                "test_host_openat_count",
                "reset_test_host_openat_count",
                "test_host_stat_count",
                "reset_test_host_stat_count",
                "HOST_XATTR_READS",
            ):
                if prev_tok is None or prev_tok.text != ".":
                    direct_violations.append(("host_metric_counter", tok.line, f"accesses exact host metric counter {tok.text}"))

            # 7. Process-wide resolve cache generations
            elif (
                tok.text == "fs_resolve_cache"
                and idx + 2 < n
                and body_tokens[idx + 1].text == "::"
            ):
                member = body_tokens[idx + 2].text
                direct_violations.append(("fs_resolve_cache", tok.line, f"accesses process-wide cache generation fs_resolve_cache::{member}"))
            elif tok.text in (
                "bump_generation",
                "bump_dir_generation",
                "bump_meta_generation",
                "bump_marker_generation",
            ):
                if prev_tok is None or prev_tok.text != ".":
                    direct_violations.append(("fs_resolve_cache", tok.line, f"accesses process-wide cache generation {tok.text}"))

        idx += 1

    return direct_violations, callees


def parse_rust_file(source: str, file_path: str) -> list[FunctionInfo]:
    """Parse a Rust file into structural functions and their serial properties."""
    tokens = lex_rust(source)
    file_is_test = _is_test_path(file_path)

    functions: list[FunctionInfo] = []
    module_stack: list[ModuleScope] = []
    impl_stack: list[ImplScope] = []
    brace_depth = 0

    idx = 0
    n = len(tokens)

    # Check top-level inner attributes e.g. #![cfg(test)]
    while idx < n and tokens[idx].text == "#" and idx + 1 < n and tokens[idx + 1].text == "!":
        idx += 2
        if idx < n and tokens[idx].text == "[":
            idx += 1
            attr_tokens: list[str] = []
            bracket_depth = 1
            while idx < n and bracket_depth > 0:
                if tokens[idx].text == "[":
                    bracket_depth += 1
                elif tokens[idx].text == "]":
                    bracket_depth -= 1
                if bracket_depth > 0:
                    attr_tokens.append(tokens[idx].text)
                idx += 1
            attr_str = "".join(attr_tokens)
            if "cfg(test)" in attr_str:
                file_is_test = True

    pending_attributes: list[str] = []
    attr_start_line = 0

    while idx < n:
        tok = tokens[idx]

        # Manage brace depth and pop completed scopes
        if tok.text == "{":
            brace_depth += 1
            idx += 1
            continue
        elif tok.text == "}":
            brace_depth -= 1
            while module_stack and brace_depth < module_stack[-1].brace_depth:
                module_stack.pop()
            while impl_stack and brace_depth < impl_stack[-1].brace_depth:
                impl_stack.pop()
            idx += 1
            continue

        # Parse outer attributes: #[...]
        if tok.text == "#" and idx + 1 < n and tokens[idx + 1].text == "[":
            if not pending_attributes:
                attr_start_line = tok.line
            idx += 2
            attr_tokens = []
            bracket_depth = 1
            while idx < n and bracket_depth > 0:
                if tokens[idx].text == "[":
                    bracket_depth += 1
                elif tokens[idx].text == "]":
                    bracket_depth -= 1
                if bracket_depth > 0:
                    attr_tokens.append(tokens[idx].text)
                idx += 1
            pending_attributes.append("".join(attr_tokens))
            continue

        # Check module declaration: mod <name> { ... }
        if tok.text == "mod" and idx + 1 < n and tokens[idx + 1].kind == "ident":
            mod_name = tokens[idx + 1].text
            has_cfg_test = any("cfg(test)" in a for a in pending_attributes)
            is_serial_host = (
                mod_name == "serial_host"
                or (len(module_stack) > 0 and module_stack[-1].in_serial_host)
            )
            is_test_mod = (
                has_cfg_test
                or mod_name == "serial_host"
                or mod_name in ("tests", "test")
                or mod_name.endswith("_tests")
                or mod_name.startswith("test_")
                or (len(module_stack) > 0 and module_stack[-1].is_test)
                or file_is_test
            )

            # Advance past mod <name>
            idx += 2
            # Look ahead for ; or {
            while idx < n and tokens[idx].text not in (";", "{"):
                idx += 1

            if idx < n and tokens[idx].text == "{":
                brace_depth += 1
                module_stack.append(
                    ModuleScope(
                        name=mod_name,
                        in_serial_host=is_serial_host,
                        is_test=is_test_mod,
                        brace_depth=brace_depth,
                    )
                )
                idx += 1

            pending_attributes = []
            continue

        # Check impl block: impl ... Type { ... }
        if tok.text == "impl":
            # Find the type name before {
            idx += 1
            type_tokens: list[str] = []
            while idx < n and tokens[idx].text != "{":
                if tokens[idx].text == ";":
                    break
                type_tokens.append(tokens[idx].text)
                idx += 1

            if idx < n and tokens[idx].text == "{":
                brace_depth += 1
                type_str = "".join(type_tokens)
                if "for" in type_tokens:
                    for_idx = type_tokens.index("for")
                    impl_type = type_tokens[for_idx + 1] if for_idx + 1 < len(type_tokens) else "Anonymous"
                elif type_tokens:
                    idents = [t for t in type_tokens if re.match(r"^[A-Za-z_]\w*$", t)]
                    impl_type = idents[-1] if idents else "Anonymous"
                else:
                    impl_type = "Anonymous"

                impl_in_serial = len(module_stack) > 0 and module_stack[-1].in_serial_host
                impl_is_test = file_is_test or (len(module_stack) > 0 and module_stack[-1].is_test)
                impl_stack.append(
                    ImplScope(
                        type_name=impl_type,
                        in_serial_host=impl_in_serial,
                        is_test=impl_is_test,
                        brace_depth=brace_depth,
                    )
                )
                idx += 1

            pending_attributes = []
            continue

        # Check function declaration: [pub] [async] [unsafe] [extern ...] fn <name>
        if tok.text == "fn" and idx + 1 < n and tokens[idx + 1].kind == "ident":
            fn_name = tokens[idx + 1].text
            fn_line = attr_start_line if pending_attributes else tok.line

            has_test_attr = any(
                a == "test"
                or a.startswith("test(")
                or a.startswith("tokio::test")
                or a == "tokio::test"
                or a.startswith("test_case")
                for a in pending_attributes
            )
            has_cfg_test_attr = any("cfg(test)" in a for a in pending_attributes)

            in_serial = (
                (len(module_stack) > 0 and module_stack[-1].in_serial_host)
                or (len(impl_stack) > 0 and impl_stack[-1].in_serial_host)
            )
            is_test_ctx = (
                file_is_test
                or in_serial
                or has_test_attr
                or has_cfg_test_attr
                or (len(module_stack) > 0 and module_stack[-1].is_test)
                or (len(impl_stack) > 0 and impl_stack[-1].is_test)
            )
            current_type = impl_stack[-1].type_name if impl_stack else None

            # Scan ahead to opening { of function body (or ; if signature only)
            idx += 2
            while idx < n and tokens[idx].text not in ("{", ";"):
                idx += 1

            if idx < n and tokens[idx].text == "{":
                # Capture body tokens until matching }
                body_start_idx = idx + 1
                fn_brace_balance = 1
                scan_idx = idx + 1
                while scan_idx < n and fn_brace_balance > 0:
                    if tokens[scan_idx].text == "{":
                        fn_brace_balance += 1
                    elif tokens[scan_idx].text == "}":
                        fn_brace_balance -= 1
                    scan_idx += 1

                body_tokens = tokens[body_start_idx : scan_idx - 1]
                direct_violations, callees = _scan_function_body(body_tokens, is_test_ctx)

                functions.append(
                    FunctionInfo(
                        name=fn_name,
                        type_name=current_type,
                        line=fn_line,
                        is_test=has_test_attr,
                        is_test_context=is_test_ctx,
                        in_serial_host=in_serial,
                        direct_violations=direct_violations,
                        callees=callees,
                    )
                )

                idx = scan_idx
                pending_attributes = []
                continue

            pending_attributes = []
            continue

        # If any other keyword/ident is reached, clear pending attributes
        if tok.kind in ("ident", "punct") and tok.text not in ("pub", "async", "unsafe", "extern", "const"):
            pending_attributes = []

        idx += 1

    return functions


def offenders(source: str, file_path: str) -> list[str]:
    """Find all functions in test scope that escape serial_host protection."""
    functions = parse_rust_file(source, file_path)
    if not functions:
        return []

    # Map of function names to FunctionInfo
    func_map: dict[str, FunctionInfo] = {}
    for f in functions:
        if f.type_name:
            func_map[f.full_name] = f
        else:
            func_map[f.name] = f
            func_map[f.full_name] = f

    # Serial entities: functions/types known to perform serial operations -> reason summary
    serial_entities: dict[str, str] = {}

    # Seed with direct violations from test-context functions
    for f in functions:
        if f.is_test_context and f.direct_violations:
            first_v = f.direct_violations[0]
            summary = first_v[2]
            if f.type_name:
                serial_entities[f.full_name] = summary
                serial_entities[f.type_name] = f"instantiates {f.type_name} ({summary})"
            else:
                serial_entities[f.name] = summary
                serial_entities[f.full_name] = summary

    # Transitive closure across helpers
    changed = True
    while changed:
        changed = False
        for f in functions:
            if f.is_test_context:
                target_key = f.full_name if f.type_name else f.name
                if target_key not in serial_entities:
                    for callee in f.callees:
                        if callee in serial_entities:
                            reason = f"calls serial helper {callee} (which {serial_entities[callee]})"
                            if f.type_name:
                                serial_entities[f.full_name] = reason
                                serial_entities[f.type_name] = f"instantiates {f.type_name} ({reason})"
                            else:
                                serial_entities[f.name] = reason
                                serial_entities[f.full_name] = reason
                            changed = True
                            break

    # Identify offenders: functions in test context outside serial_host that perform or call serial ops
    reported_violations: list[str] = []
    seen_lines: set[int] = set()

    for f in functions:
        if f.is_test_context and not f.in_serial_host:
            target_key = f.full_name if f.type_name else f.name
            if f.direct_violations:
                for v in f.direct_violations:
                    v_line = v[1]
                    if v_line not in seen_lines:
                        reported_violations.append(
                            f"{file_path}:{v_line}: {f.full_name} {v[2]} outside mod serial_host"
                        )
                        seen_lines.add(v_line)
            elif target_key in serial_entities:
                if f.line not in seen_lines:
                    reason = serial_entities[target_key]
                    reported_violations.append(
                        f"{file_path}:{f.line}: {f.full_name} {reason} outside mod serial_host"
                    )
                    seen_lines.add(f.line)

    return reported_violations


def run_self_tests() -> bool:
    """Run built-in test fixtures for check-serial-host-tests."""
    fixtures_passed = 0
    total_fixtures = 0

    def check(name: str, code: str, path: str, expect_offenders: bool, expected_contains: str | None = None) -> bool:
        nonlocal fixtures_passed, total_fixtures
        total_fixtures += 1
        res = offenders(code, path)
        if expect_offenders and not res:
            print(f"FAIL self-test '{name}': expected offenders, got none")
            return False
        if not expect_offenders and res:
            print(f"FAIL self-test '{name}': expected no offenders, got {res}")
            return False
        if expected_contains and not any(expected_contains in r for r in res):
            print(f"FAIL self-test '{name}': expected output containing '{expected_contains}', got {res}")
            return False
        fixtures_passed += 1
        return True

    # 1. Basic test with unguarded libc::fork
    t1_bad = "#[test]\nfn t() { let p = unsafe { libc::fork() }; }\n"
    t1_good = "mod serial_host {\nuse super::*;\n#[test]\nfn t() { let p = unsafe { libc::fork() }; }\n}\n"
    assert check("1a_unguarded_fork", t1_bad, "src/lib.rs", True, "calls libc::fork")
    assert check("1b_serial_fork", t1_good, "src/lib.rs", False)

    # 2. Multiline functions with attributes and comments
    t2_bad = """
    #[test]
    #[ignore = "needs setup"]
    fn my_multiline_test(
        // parameter comments
    ) {
        let cmd = std::process::Command::new("cargo");
        let _ = cmd;
    }
    """
    t2_good = """
    mod serial_host {
        use super::*;
        #[test]
        fn my_multiline_test() {
            let cmd = std::process::Command::new("cargo");
            let _ = cmd;
        }
    }
    """
    assert check("2a_multiline_command_new", t2_bad, "src/lib.rs", True, "Command::new")
    assert check("2b_multiline_serial", t2_good, "src/lib.rs", False)

    # 3. Nested modules
    t3_bad = """
    mod outer {
        mod inner {
            #[test]
            fn t() {
                unsafe { std::env::set_var("FOO", "BAR") };
            }
        }
    }
    """
    t3_good = """
    mod outer {
        mod serial_host {
            mod inner {
                #[test]
                fn t() {
                    unsafe { std::env::set_var("FOO", "BAR") };
                }
            }
        }
    }
    """
    assert check("3a_nested_mod_bad", t3_bad, "src/lib.rs", True, "set_var")
    assert check("3b_nested_mod_good", t3_good, "src/lib.rs", False)

    # 4. Strings and comments with braces and call names
    t4_clean = """
    #[test]
    fn string_braces_and_comments() {
        // libc::fork() in line comment { { {
        /*
           Command::new("x") in block comment {
           /* nested block { } */
        */
        let s = "libc::fork() { } } \" \\" ";
        let raw = r#" libc::setrlimit { } "#;
        let c = '{';
        let b = b'{';
        assert_eq!(s.len(), 20);
    }
    """
    assert check("4_string_comment_braces", t4_clean, "src/lib.rs", False)

    # 5. Test helpers inside #[cfg(test)] module
    t5_helper = """
    #[cfg(test)]
    mod tests {
        fn setup_fork_child() {
            unsafe { libc::fork() };
        }

        #[test]
        fn calls_helper() {
            setup_fork_child();
        }
    }
    """
    assert check("5_test_helper_bad", t5_helper, "src/lib.rs", True, "calls libc::fork")

    # 6. File-level test file (tests.rs)
    t6_file = """
    fn helper_shut() {
        let limit: libc::rlimit = unsafe { std::mem::zeroed() };
        unsafe { libc::setrlimit(0, &limit) };
    }

    #[test]
    fn file_level_test() {
        helper_shut();
    }
    """
    assert check("6_file_level_tests_rs", t6_file, "crates/carrick-vfs/src/fs_backend/tests.rs", True, "setrlimit")

    # 7. Caller of serial helper in parallel test (helper in serial_host, caller outside)
    t7_escape = """
    mod serial_host {
        pub fn fork_helper() {
            unsafe { libc::fork() };
        }
    }

    #[test]
    fn parallel_caller() {
        serial_host::fork_helper();
    }
    """
    assert check("7_caller_escapes_serial_host", t7_escape, "src/lib.rs", True, "calls serial helper")

    # 8. Host metric counters and resolve cache generations
    t8_metrics_bad = """
    #[test]
    fn budget_test() {
        reset_test_host_openat_count();
        let opens = test_host_openat_count();
        crate::fs_resolve_cache::bump_generation();
        assert_eq!(opens, 0);
    }
    """
    t8_metrics_good = """
    mod serial_host {
        use super::*;
        #[test]
        fn budget_test() {
            reset_test_host_openat_count();
            let opens = test_host_openat_count();
            crate::fs_resolve_cache::bump_generation();
            assert_eq!(opens, 0);
        }
    }
    """
    assert check("8a_metric_counters_bad", t8_metrics_bad, "crates/carrick-vfs/src/fs_backend/tests.rs", True, "host metric counter")
    assert check("8b_metric_counters_good", t8_metrics_good, "crates/carrick-vfs/src/fs_backend/tests.rs", False)

    # 9. Struct helper constructor (DescriptorTableShut / UmaskGuard style)
    t9_struct_bad = """
    struct Shut;
    impl Shut {
        fn new() -> Self {
            unsafe { libc::umask(0o022) };
            Self
        }
    }

    #[test]
    fn uses_struct() {
        let _guard = Shut::new();
    }
    """
    t9_struct_good = """
    mod serial_host {
        use super::*;
        struct Shut;
        impl Shut {
            fn new() -> Self {
                unsafe { libc::umask(0o022) };
                Self
            }
        }

        #[test]
        fn uses_struct() {
            let _guard = Shut::new();
        }
    }
    """
    assert check("9a_struct_helper_bad", t9_struct_bad, "crates/carrick-vfs/src/fs_backend/tests.rs", True, "calls libc::umask")
    assert check("9b_struct_helper_good", t9_struct_good, "crates/carrick-vfs/src/fs_backend/tests.rs", False)

    # 10. Production code with Command / umask is NOT flagged
    t10_prod = """
    struct Runner;
    impl Runner {
        pub fn run(&self) {
            let _cmd = std::process::Command::new("sudo");
            let _old = unsafe { libc::umask(0) };
        }
    }
    """
    assert check("10_production_code_not_flagged", t10_prod, "crates/carrick-kernel/src/wedge_capture.rs", False)

    # 11. Multi-hop transitive helper calls (A -> B -> C -> libc::fork)
    t11_multihop = """
    #[cfg(test)]
    mod tests {
        fn c_forks() {
            unsafe { libc::fork() };
        }
        fn b_calls_c() {
            c_forks();
        }
        #[test]
        fn a_calls_b() {
            b_calls_c();
        }
    }
    """
    assert check("11_multihop_transitive", t11_multihop, "src/lib.rs", True, "calls serial helper")

    print(f"check-serial-host-tests: self-test ok ({fixtures_passed}/{total_fixtures} passed)")
    return fixtures_passed == total_fixtures


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Check that tests with host/process mutations live in mod serial_host."
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run self-test fixtures and exit.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print verbose diagnostics and summary.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Specific files or directories to scan (defaults to carrick-kernel and carrick-vfs).",
    )

    args = parser.parse_args(argv)

    if args.self_test:
        return 0 if run_self_tests() else 1

    repo_root = Path(__file__).resolve().parents[2]

    if args.paths:
        search_paths = [Path(p).resolve() for p in args.paths]
    else:
        search_paths = [
            repo_root / "crates" / "carrick-kernel" / "src",
            repo_root / "crates" / "carrick-vfs" / "src",
        ]

    files_to_scan: list[Path] = []
    for sp in search_paths:
        if sp.is_file() and sp.suffix == ".rs":
            files_to_scan.append(sp)
        elif sp.is_dir():
            files_to_scan.extend(sorted(sp.rglob("*.rs")))

    all_offenders: list[str] = []

    for file_path in files_to_scan:
        try:
            source = file_path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"Error reading {file_path}: {e}", file=sys.stderr)
            continue

        rel_path = (
            file_path.relative_to(repo_root)
            if file_path.is_relative_to(repo_root)
            else file_path
        )
        found = offenders(source, str(rel_path))
        all_offenders.extend(found)

    for item in all_offenders:
        print(item)

    if args.verbose:
        print(f"\nTotal offenders found: {len(all_offenders)}")

    return 1 if all_offenders else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

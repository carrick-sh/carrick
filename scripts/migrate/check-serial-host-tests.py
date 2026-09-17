#!/usr/bin/env python3
"""Ratchet: Enforce serial execution for tests that fork, mutate host state, or read exact metrics.

Every #[test] in carrick-kernel / carrick-vfs that forks host processes,
spawns subprocesses, mutates environment variables/rlimits/umask, or asserts
on process-wide counters and directory cache invariants must live inside a
`mod serial_host`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import importlib.util
from pathlib import Path
import sys
from typing import Sequence

# Dynamically import the canonical Rust lexer from check-mm-authority.py
_MM_PATH = Path(__file__).resolve().parent / "check-mm-authority.py"
_SPEC = importlib.util.spec_from_file_location("check_mm_authority", _MM_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"Cannot load lexer from {_MM_PATH}")
_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MOD
_SPEC.loader.exec_module(_MOD)
lex_rust = _MOD.lex_rust
Token = _MOD.Token

ROOTS = ("crates/carrick-kernel/src", "crates/carrick-vfs/src")

DIRECT_PATTERNS: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...] = (
    # A closed descriptor number can be reused by any concurrently opening test.
    ("closed host fd probe", (("F_GETFD", ")", "}", ",", "-", "1"),)),
    ("take_abort_request", (("take_abort_request",),)),
    ("reset_for_tests", (("reset_for_tests",),)),
    ("libc::fork", (("libc", "::", "fork"),)),
    ("Command::new", (("Command", "::", "new"), ("process", "::", "Command", "::", "new"))),
    ("Command::spawn", (("Command", "::", "spawn"),)),
    ("std::env::set_var", (("env", "::", "set_var"), ("std", "::", "env", "::", "set_var"))),
    ("std::env::remove_var", (("env", "::", "remove_var"), ("std", "::", "env", "::", "remove_var"))),
    ("libc::setrlimit", (("libc", "::", "setrlimit"),)),
    ("libc::umask", (("libc", "::", "umask"),)),
    ("test_host_openat_count", (("test_host_openat_count",),)),
    ("reset_test_host_openat_count", (("reset_test_host_openat_count",),)),
    ("test_host_stat_count", (("test_host_stat_count",),)),
    ("reset_test_host_stat_count", (("reset_test_host_stat_count",),)),
    ("HOST_XATTR_READS", (("HOST_XATTR_READS",),)),
    ("host_xattr_read_count", (("host_xattr_read_count",),)),
    ("reset_host_xattr_read_count", (("reset_host_xattr_read_count",),)),
    ("path_walk_host_opens", (("path_walk_host_opens",),)),
    ("reset_path_walk_host_opens", (("reset_path_walk_host_opens",),)),
    ("cache_eviction_visited_keys", (("cache_eviction_visited_keys",),)),
    ("reset_cache_eviction_visited_keys", (("reset_cache_eviction_visited_keys",),)),
    ("dir_fd_for", (("dir_fd_for",),)),
    ("drop_dir_cache", (("drop_dir_cache",),)),
    ("open_immutable_lower_readonly", (("open_immutable_lower_readonly",),)),
    ("open_immutable_file_readonly", (("open_immutable_file_readonly",),)),
    ("enable_sparse_upper_fast_miss", (("enable_sparse_upper_fast_miss",),)),
    ("fs_resolve_cache::bump_generation", (("fs_resolve_cache", "::", "bump_generation"),)),
    ("fs_resolve_cache::bump_dir_generation", (("fs_resolve_cache", "::", "bump_dir_generation"),)),
    ("fs_resolve_cache::bump_meta_generation", (("fs_resolve_cache", "::", "bump_meta_generation"),)),
    ("fs_resolve_cache::bump_marker_generation", (("fs_resolve_cache", "::", "bump_marker_generation"),)),
)

TRAIT_METHODS = frozenset({"drop", "deref", "clone", "default", "from", "into", "as_ref", "as_mut"})


@dataclass
class FnItem:
    name: str
    qual_name: str
    line: int
    is_test: bool
    is_serial_host: bool
    is_test_mod: bool
    direct_violations: list[tuple[int, str]] = field(default_factory=list)
    calls: set[str] = field(default_factory=set)


@dataclass
class Scope:
    kind: str  # "root", "mod", "impl", "struct", "block"
    name: str
    is_serial_host: bool
    is_test_mod: bool


def scan_source(path_str: str, source: str) -> list[str]:
    """Scan a single Rust source file for serial host violations."""
    tokens = lex_rust(source)
    is_test_file = (
        path_str.endswith("tests.rs")
        or "/tests/" in path_str
        or path_str.endswith("_test.rs")
        or path_str.endswith("test.rs")
    )
    scope_stack = [Scope("root", "", False, is_test_file)]
    fns: list[FnItem] = []

    pending_test = False
    pending_cfg_test = False

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        # Attributes #[...] or #![...]
        if tok.text == "#" and i + 1 < n and tokens[i + 1].text in ("[", "!"):
            bracket_idx = i + 1 if tokens[i + 1].text == "[" else i + 2
            if bracket_idx < n and tokens[bracket_idx].text == "[":
                depth = 1
                j = bracket_idx + 1
                attr_toks: list[str] = []
                while j < n and depth > 0:
                    if tokens[j].text == "[":
                        depth += 1
                    elif tokens[j].text == "]":
                        depth -= 1
                    if depth > 0:
                        attr_toks.append(tokens[j].text)
                    j += 1
                attr_text = "".join(attr_toks)
                if attr_text in ("test", "tokio::test"):
                    pending_test = True
                elif "cfg(test)" in attr_text:
                    pending_cfg_test = True
                i = j
                continue

        # mod <name>
        if tok.text == "mod" and i + 1 < n and tokens[i + 1].kind == "ident":
            mod_name = tokens[i + 1].text
            j = i + 2
            if j < n and tokens[j].text == "{":
                cur = scope_stack[-1]
                is_serial = (mod_name == "serial_host") or cur.is_serial_host
                is_test_m = pending_cfg_test or (mod_name == "tests") or cur.is_test_mod
                scope_stack.append(Scope("mod", mod_name, is_serial, is_test_m))
                pending_test = False
                pending_cfg_test = False
                i = j + 1
                continue
            elif j < n and tokens[j].text == ";":
                pending_test = False
                pending_cfg_test = False
                i = j + 1
                continue

        # impl <Type> { ... }
        if tok.text == "impl":
            j = i + 1
            type_tokens: list[str] = []
            while j < n and tokens[j].text != "{":
                if tokens[j].kind == "ident":
                    type_tokens.append(tokens[j].text)
                j += 1
            if j < n and tokens[j].text == "{":
                impl_name = type_tokens[-1] if type_tokens else "impl"
                cur = scope_stack[-1]
                scope_stack.append(Scope("impl", impl_name, cur.is_serial_host, cur.is_test_mod))
                pending_test = False
                pending_cfg_test = False
                i = j + 1
                continue

        # fn <name> or async fn <name>
        if tok.text in ("fn", "async"):
            fn_idx = i if tok.text == "fn" else (i + 1 if i + 1 < n and tokens[i + 1].text == "fn" else -1)
            if fn_idx != -1 and fn_idx + 1 < n and tokens[fn_idx + 1].kind == "ident":
                fn_name = tokens[fn_idx + 1].text
                cur = scope_stack[-1]
                qual_name = f"{cur.name}::{fn_name}" if cur.kind == "impl" else fn_name
                j = fn_idx + 2
                while j < n and tokens[j].text not in ("{", ";"):
                    j += 1
                if j < n and tokens[j].text == "{":
                    depth = 1
                    j += 1
                    body_tokens: list[Token] = []
                    while j < n and depth > 0:
                        if tokens[j].text == "{":
                            depth += 1
                        elif tokens[j].text == "}":
                            depth -= 1
                        if depth > 0:
                            body_tokens.append(tokens[j])
                        j += 1

                    fn_item = FnItem(
                        name=fn_name,
                        qual_name=qual_name,
                        line=tok.line,
                        is_test=pending_test,
                        is_serial_host=cur.is_serial_host,
                        is_test_mod=cur.is_test_mod,
                    )

                    b_len = len(body_tokens)
                    for b_i, b_tok in enumerate(body_tokens):
                        # check direct patterns
                        for pat_name, sequences in DIRECT_PATTERNS:
                            for seq in sequences:
                                seq_len = len(seq)
                                if b_i + seq_len <= b_len:
                                    match = True
                                    for k in range(seq_len):
                                        if body_tokens[b_i + k].text != seq[k]:
                                            match = False
                                            break
                                    if match and pat_name == "closed host fd probe":
                                        # The same token suffix occurs in assert_ne! on a live fd.
                                        assertion = next((t.text for t in reversed(body_tokens[:b_i])
                                                          if t.text in ("assert_eq", "assert_ne")), None)
                                        match = assertion == "assert_eq"
                                    if match:
                                        fn_item.direct_violations.append((b_tok.line, pat_name))

                        # collect call targets and struct instantiations
                        if b_tok.kind == "ident":
                            if b_i + 2 < b_len and body_tokens[b_i + 1].text == "::" and body_tokens[b_i + 2].kind == "ident":
                                full = f"{b_tok.text}::{body_tokens[b_i + 2].text}"
                                fn_item.calls.add(full)
                                fn_item.calls.add(b_tok.text)
                            elif b_i + 1 < b_len and body_tokens[b_i + 1].text == "{" and b_tok.text[0].isupper():
                                fn_item.calls.add(b_tok.text)
                            elif b_i + 1 < b_len and body_tokens[b_i + 1].text == "(":
                                if b_i == 0 or (body_tokens[b_i - 1].text not in (".", "::")):
                                    fn_item.calls.add(b_tok.text)

                    fns.append(fn_item)
                    pending_test = False
                    pending_cfg_test = False
                    i = j
                    continue

        if tok.text == "{":
            cur = scope_stack[-1]
            scope_stack.append(Scope("block", "", cur.is_serial_host, cur.is_test_mod))
        elif tok.text == "}":
            if len(scope_stack) > 1:
                scope_stack.pop()

        i += 1

    # Transitive helper propagation fixpoint
    serial_helpers: dict[str, str] = {}
    for f in fns:
        if (f.is_test_mod or f.is_test or f.is_serial_host) and f.direct_violations:
            reason = f.direct_violations[0][1]
            if f.name not in TRAIT_METHODS:
                serial_helpers[f.name] = reason
            serial_helpers[f.qual_name] = reason
            if "::" in f.qual_name:
                struct_name = f.qual_name.split("::")[0]
                serial_helpers[struct_name] = f"instantiates {struct_name} (which calls {reason})"

    changed = True
    while changed:
        changed = False
        for f in fns:
            if f.qual_name not in serial_helpers and (f.is_test_mod or f.is_test or f.is_serial_host):
                for call in f.calls:
                    if call in serial_helpers:
                        sub_reason = serial_helpers[call]
                        desc = f"calls serial helper {call} ({sub_reason})"
                        if f.name not in TRAIT_METHODS:
                            serial_helpers[f.name] = desc
                        serial_helpers[f.qual_name] = desc
                        if "::" in f.qual_name:
                            struct_name = f.qual_name.split("::")[0]
                            if struct_name not in serial_helpers:
                                serial_helpers[struct_name] = f"instantiates {struct_name} (which {desc})"
                        changed = True
                        break

    # Emit diagnostics for tests or test-only helpers outside serial_host
    diagnostics: list[str] = []
    for f in fns:
        if (f.is_test or f.is_test_mod) and not f.is_serial_host:
            if f.direct_violations:
                line, pat = f.direct_violations[0]
                diagnostics.append(f"{path_str}:{line}: {f.name} calls {pat} outside mod serial_host")
            elif f.is_test and f.name in serial_helpers:
                diagnostics.append(f"{path_str}:{f.line}: {f.name} {serial_helpers[f.name]} outside mod serial_host")
            else:
                for call in f.calls:
                    if call in serial_helpers:
                        diagnostics.append(
                            f"{path_str}:{f.line}: {f.name} calls serial helper {call} "
                            f"({serial_helpers[call]}) outside mod serial_host"
                        )
                        break

    return diagnostics


def run_self_tests() -> int:
    """Validate scanner against comprehensive test fixtures."""
    fixtures = [
        ("fail_closed_fd_probe", "#[test]\nfn t() { assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1); }\n", True),
        ("pass_live_fd_probe", "#[test]\nfn t() { assert_ne!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1); }\n", False),
        ("pass_clean_test", "#[test]\nfn t() { assert_eq!(1, 1); }\n", False),
        ("fail_unguarded_fork", "#[test]\nfn t() { unsafe { libc::fork() }; }\n", True),
        ("pass_serial_fork", "mod serial_host {\n#[test]\nfn t() { unsafe { libc::fork() }; }\n}\n", False),
        (
            "fail_helper_transitive",
            "#[cfg(test)]\nmod tests {\nfn helper() { libc::fork(); }\n#[test]\nfn t() { helper(); }\n}\n",
            True,
        ),
        (
            "fail_struct_constructor",
            "#[cfg(test)]\nmod tests {\nstruct Shut;\nimpl Shut {\nfn new() { libc::setrlimit(0, 0); }\n}\n#[test]\nfn t() { let _s = Shut::new(); }\n}\n",
            True,
        ),
        (
            "fail_struct_instantiation",
            "#[cfg(test)]\nmod tests {\nstruct Shut;\nimpl Shut {\nfn new() { libc::setrlimit(0, 0); }\n}\n#[test]\nfn t() { let _s = Shut {}; }\n}\n",
            True,
        ),
        (
            "pass_multiline_fn",
            "#[test]\nfn multiline(\n    x: u32,\n    y: u32,\n) {\n    assert_eq!(x, y);\n}\n",
            False,
        ),
        (
            "pass_braces_in_strings_and_comments",
            "#[test]\nfn tricky() {\n    let s = \"libc::fork() { \";\n    // libc::fork() { }\n    /* libc::fork() { */\n    let _r = r#\" libc::fork() { \"#;\n}\n",
            False,
        ),
        (
            "fail_metric_openat_budget",
            "#[test]\nfn t() { reset_test_host_openat_count(); assert_eq!(test_host_openat_count(), 0); }\n",
            True,
        ),
        (
            "fail_metric_path_walk_opens",
            "#[test]\nfn t() { b.reset_path_walk_host_opens(); assert_eq!(b.path_walk_host_opens(), 0); }\n",
            True,
        ),
        (
            "fail_metric_cache_eviction_visited",
            "#[test]\nfn t() { b.reset_cache_eviction_visited_keys(); assert_eq!(b.cache_eviction_visited_keys(), 0); }\n",
            True,
        ),
        (
            "fail_dir_cache_storm_fixture",
            "#[test]\nfn dir_cache_survives_a_file_create_and_unlink_storm() {\n    let before = b.dir_fd_for(Path::new(\"pkg\")).unwrap();\n}\n",
            True,
        ),
        (
            "fail_fast_readonly_open_fixture",
            "#[test]\nfn fast_readonly_open_uses_the_immutable_lower_when_the_sparse_upper_is_absent() {\n    let res = vfs.open_immutable_lower_readonly(\"/usr/lib/cache\");\n}\n",
            True,
        ),
        (
            "fail_env_mutation",
            "#[test]\nfn t() { std::env::set_var(\"KEY\", \"VAL\"); }\n",
            True,
        ),
        (
            "fail_command_spawn",
            "#[test]\nfn t() { Command::new(\"echo\").spawn().unwrap(); }\n",
            True,
        ),
        (
            "fail_multi_hop_helper",
            "#[cfg(test)]\nmod tests {\nfn leaf() { libc::fork(); }\nfn mid() { leaf(); }\n#[test]\nfn t() { mid(); }\n}\n",
            True,
        ),
        (
            "fail_drop_calls_fork_helper",
            "#[cfg(test)]\nmod tests {\nstruct DropFork;\nimpl Drop for DropFork {\nfn drop(&mut self) { fork_helper(); }\n}\nfn fork_helper() { unsafe { libc::fork() }; }\n#[test]\nfn t() { let _d = DropFork {}; }\n}\n",
            True,
        ),
    ]

    for name, src, should_fail in fixtures:
        diags = scan_source("test.rs", src)
        failed = len(diags) > 0
        if failed != should_fail:
            print(f"SELF-TEST FAILED on {name}: expected failed={should_fail}, got {failed} (diags: {diags})")
            return 1

    print(f"check-serial-host-tests: self-test ok ({len(fixtures)}/{len(fixtures)} passed)")
    return 0


def main(argv: Sequence[str]) -> int:
    if "--self-test" in argv:
        return run_self_tests()

    all_diags: list[str] = []
    for root in ROOTS:
        root_path = Path(root)
        if not root_path.exists():
            continue
        for p in sorted(root_path.rglob("*.rs")):
            all_diags.extend(scan_source(str(p), p.read_text()))

    for d in all_diags:
        print(d)

    return 1 if all_diags else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

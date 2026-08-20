#!/usr/bin/env python3

"""Deny unmistakable syntax that can bypass the compiler authority catalog.

Clippy remains the semantic authority. This checker deliberately does not
resolve Rust names, cfgs, modules, or product reachability; it only sees raw
escape syntax that Semgrep 1.166 cannot reliably inspect inside macro token
trees or preserve ABI/link-name context for.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


REPLACEMENT = (
    "add a named operation to the compiler host-authority catalog or route it "
    "through the typed host-capability facade"
)

RAW_SYSCALL_BOUNDARIES = frozenset(
    {
        PurePosixPath("crates/carrick-portable/src/lib.rs"),
        PurePosixPath("crates/carrick-vmm-kvm/src/kvm_aarch64_engine.rs"),
        PurePosixPath("crates/carrick-aarch64/src/engine.rs"),
        PurePosixPath("crates/carrick-host/src/netbsd_futex.rs"),
        PurePosixPath("crates/carrick-host-linux/src/epoll_mux.rs"),
        PurePosixPath("crates/carrick-host/src/shared_word.rs"),
        PurePosixPath("crates/carrick-vmm-nvmm/src/nvmm.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-asyncsig/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-fork-raw/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-vfork-exec/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-vfork-exit/src/main.rs"),
    }
)

ASSEMBLY_BOUNDARIES = frozenset(
    {
        PurePosixPath("crates/carrick-dsr-aarch64/src/counter.rs"),
        PurePosixPath("crates/carrick-dsr-aarch64/src/emit.rs"),
        PurePosixPath("crates/carrick-dsr-x86/src/gateway.rs"),
        PurePosixPath("crates/carrick-dsr-x86/tests/fixtures/computeloop.rs"),
        PurePosixPath("crates/carrick-dsr-x86/tests/fixtures/tinyguest.rs"),
        PurePosixPath("crates/carrick-native-darwin/src/direct.rs"),
        PurePosixPath("crates/carrick-runtime/tools/vdso_getrandom_blob.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-fpsignal/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-sigfpe/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-sigill/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-sigsegv-default/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-sigsegv-gp/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-sigsegv/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-hvf/src/trap/sysreg.rs"),
        PurePosixPath("crates/carrick-vmm-kvm/src/guest_setup.rs"),
        PurePosixPath("crates/carrick-vmm-kvm/src/kvm.rs"),
    }
)

WATCHED_EXTERN_NAMES = frozenset(
    {
        "waitpid",
        "wait4",
        "waitid",
        "kill",
        "killpg",
        "pthread_kill",
        "fork",
        "vfork",
        "execve",
        "posix_spawn",
        "open",
        "openat",
        "close",
        "unlink",
        "unlinkat",
        "rename",
        "renameat",
        "mkdir",
        "mkdirat",
        "rmdir",
        "chdir",
        "fchdir",
        "chroot",
    }
)

RAW_CALL_RE = re.compile(r"\blibc\s*::\s*(syscall|dlopen|dlsym)\s*\(")
ASM_CALL_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:(?:core|std)\s*::\s*arch\s*::\s*)?"
    r"(asm|global_asm)\s*!\s*[({\[]"
)
ARCH_USE_RE = re.compile(
    r"\buse\s+(?:core|std)\s*::\s*arch\s*::(?P<body>[^;]*);",
    re.DOTALL,
)
EXTERN_BLOCK_RE = re.compile(r"\bextern\b\s*\{")
FUNCTION_DECL_RE = re.compile(r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
LINK_NAME_PREFIX_RE = re.compile(r"#\s*\[\s*link_name\s*=\s*$", re.DOTALL)


class ScanError(RuntimeError):
    pass


@dataclass(frozen=True)
class StringToken:
    start: int
    end: int
    value: str | None


@dataclass(frozen=True)
class Finding:
    offset: int
    message: str


def _mask(chars: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if chars[index] != "\n":
            chars[index] = " "


def _is_token_boundary(text: str, index: int) -> bool:
    return index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_")


def _raw_string_start(text: str, index: int) -> tuple[int, int] | None:
    if not _is_token_boundary(text, index):
        return None
    for prefix in ("br", "cr", "r"):
        if not text.startswith(prefix, index):
            continue
        cursor = index + len(prefix)
        while cursor < len(text) and text[cursor] == "#":
            cursor += 1
        if cursor < len(text) and text[cursor] == '"':
            return cursor + 1, cursor - index - len(prefix)
    return None


def _decode_normal_string(source: str) -> str | None:
    quote = source.find('"')
    if quote < 0:
        return None
    try:
        value = ast.literal_eval(source[quote:])
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def mask_comments_and_literals(text: str) -> tuple[str, list[StringToken]]:
    masked = list(text)
    strings: list[StringToken] = []
    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = len(text)
            _mask(masked, index, end)
            index = end
            continue

        if text.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < len(text) and depth:
                if text.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif text.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                raise ScanError("unterminated Rust block comment")
            _mask(masked, index, cursor)
            index = cursor
            continue

        raw = _raw_string_start(text, index)
        if raw is not None:
            content_start, hashes = raw
            terminator = '"' + ("#" * hashes)
            terminator_start = text.find(terminator, content_start)
            if terminator_start < 0:
                raise ScanError("unterminated Rust raw string")
            end = terminator_start + len(terminator)
            strings.append(
                StringToken(index, end, text[content_start:terminator_start])
            )
            _mask(masked, index, end)
            index = end
            continue

        prefix_length = 0
        if (
            _is_token_boundary(text, index)
            and index + 1 < len(text)
            and text[index] in ("b", "c")
            and text[index + 1] == '"'
        ):
            prefix_length = 1
        if text[index] == '"' or prefix_length:
            start = index
            cursor = index + prefix_length + 1
            escaped = False
            while cursor < len(text):
                char = text[cursor]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    cursor += 1
                    break
                cursor += 1
            else:
                raise ScanError("unterminated Rust string")
            strings.append(
                StringToken(start, cursor, _decode_normal_string(text[start:cursor]))
            )
            _mask(masked, start, cursor)
            index = cursor
            continue

        char_start = index
        if (
            _is_token_boundary(text, index)
            and text.startswith("b'", index)
        ):
            index += 1
        if text[index] == "'":
            cursor = index + 1
            escaped = False
            while cursor < len(text) and text[cursor] != "\n":
                char = text[cursor]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "'":
                    cursor += 1
                    _mask(masked, char_start, cursor)
                    index = cursor
                    break
                cursor += 1
            else:
                index = char_start + 1
            if index != char_start:
                continue

        index += 1

    return "".join(masked), strings


def _matching_brace(code: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ScanError("unterminated extern block")


def _extern_findings(
    code: str, strings: list[StringToken]
) -> list[Finding]:
    findings: list[Finding] = []
    for block in EXTERN_BLOCK_RE.finditer(code):
        opening = code.find("{", block.start(), block.end())
        closing = _matching_brace(code, opening)
        body = code[opening + 1 : closing]
        for declaration in FUNCTION_DECL_RE.finditer(body):
            name = declaration.group("name")
            if name in WATCHED_EXTERN_NAMES:
                findings.append(
                    Finding(
                        opening + 1 + declaration.start(),
                        f"local extern declaration of {name} bypasses resolved review",
                    )
                )
        for token in strings:
            if not (opening < token.start < closing):
                continue
            prefix = code[max(opening, token.start - 160) : token.start]
            if not LINK_NAME_PREFIX_RE.search(prefix):
                continue
            if token.value is None or token.value in WATCHED_EXTERN_NAMES:
                target = token.value if token.value is not None else "undecodable symbol"
                findings.append(
                    Finding(
                        token.start,
                        f"local extern link_name {target} bypasses resolved review",
                    )
                )
    return findings


def scan_source(relative: PurePosixPath, text: str) -> list[Finding]:
    code, strings = mask_comments_and_literals(text)
    findings: list[Finding] = []

    if relative not in RAW_SYSCALL_BOUNDARIES:
        for match in RAW_CALL_RE.finditer(code):
            findings.append(
                Finding(match.start(), f"raw libc::{match.group(1)} bypasses review")
            )

    if relative not in ASSEMBLY_BOUNDARIES:
        for match in ASM_CALL_RE.finditer(code):
            findings.append(
                Finding(match.start(), f"{match.group(1)}! bypasses review")
            )
        for match in ARCH_USE_RE.finditer(code):
            imported = match.group("body")
            if re.search(r"\b(?:asm|global_asm)\b|\*", imported):
                findings.append(
                    Finding(match.start(), "assembly macro import bypasses review")
                )

    findings.extend(_extern_findings(code, strings))
    return sorted(set(findings), key=lambda finding: (finding.offset, finding.message))


def scan_tree(root: Path) -> list[str]:
    crates = root / "crates"
    if not crates.is_dir():
        raise ScanError(f"missing Rust scan root: {crates}")
    rendered: list[str] = []
    for path in sorted(crates.rglob("*.rs")):
        try:
            relative = PurePosixPath(path.relative_to(root).as_posix())
            text = path.read_text(encoding="utf-8")
            findings = scan_source(relative, text)
        except (OSError, UnicodeError) as error:
            raise ScanError(f"cannot read {path}: {error}") from error
        except ScanError as error:
            raise ScanError(f"{relative}: {error}") from error
        for finding in findings:
            line = text.count("\n", 0, finding.offset) + 1
            rendered.append(
                f"{relative}:{line}: error: {finding.message}; {REPLACEMENT}"
            )
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        findings = scan_tree(root)
    except ScanError as error:
        print(f"error: host-authority escape scan failed closed: {error}", file=sys.stderr)
        return 2
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

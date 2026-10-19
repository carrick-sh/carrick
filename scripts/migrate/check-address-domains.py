#!/usr/bin/env python3
"""Reject new struct GuestVa, HostVa, or Gpa definitions outside carrick-guest-arch owner.

Enforces issue #682: one guest/host address-domain vocabulary with private fields,
owned solely by carrick-guest-arch (crates/carrick-guest-arch/src/lib.rs).
Other crates must import or re-export the owner's types instead of redefining them.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys
import tempfile
from typing import Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCAN_ROOTS = (
    REPO_ROOT / "crates",
)
OWNER_PATHS = frozenset(
    {
        "crates/carrick-guest-arch/src/lib.rs",
    }
)
FORBIDDEN_STRUCT_NAMES = frozenset(
    {
        "GuestVa",
        "HostVa",
        "Gpa",
    }
)


@dataclass(frozen=True, order=True)
class Finding:
    category: str
    path: str
    line: int
    detail: str


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int


def lex_rust(source: str) -> list[Token]:
    """Tokenize Rust source, stripping comments, strings, and char literals."""
    tokens: list[Token] = []
    index = 0
    line = 1
    length = len(source)

    while index < length:
        char = source[index]
        if char.isspace():
            if char == "\n":
                line += 1
            index += 1
            continue

        # Line comment
        if source[index : index + 2] == "//":
            end = source.find("\n", index)
            if end < 0:
                break
            index = end
            continue

        # Block comment (handling nesting)
        if source[index : index + 2] == "/*":
            depth = 1
            index += 2
            while index < length and depth > 0:
                if source[index : index + 2] == "/*":
                    depth += 1
                    index += 2
                elif source[index : index + 2] == "*/":
                    depth -= 1
                    index += 2
                else:
                    if source[index] == "\n":
                        line += 1
                    index += 1
            continue

        # Raw string literal r"..." or r#"..."#
        if char == "r" and index + 1 < length and (source[index + 1] == '"' or source[index + 1] == '#'):
            cursor = index + 1
            hashes = 0
            while cursor < length and source[cursor] == "#":
                hashes += 1
                cursor += 1
            if cursor < length and source[cursor] == '"':
                delim = '"' + ("#" * hashes)
                end = source.find(delim, cursor + 1)
                if end < 0:
                    end = length
                else:
                    end += len(delim)
                line += source[index:end].count("\n")
                index = end
                continue

        # String or byte string literal
        if char in {'"', "'"} or (
            char in {"b", "c"}
            and index + 1 < length
            and source[index + 1] in {'"', "'"}
        ):
            quote = source[index + (char in {"b", "c"})]
            # Handle lifetime like 'a or 'static
            if quote == "'" and index + 1 < length and (source[index + 1].isalpha() or source[index + 1] == "_"):
                cursor = index + 1
                while cursor < length and (source[cursor].isalnum() or source[cursor] == "_"):
                    cursor += 1
                if cursor < length and source[cursor] == "'":
                    # Character literal 'x'
                    cursor += 1
                tokens.append(Token("lifetime", source[index:cursor], line))
                index = cursor
                continue

            index += 1 + (char in {"b", "c"})
            while index < length:
                if source[index] == "\n":
                    line += 1
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            continue

        # Identifiers and keywords
        if char.isalpha() or char == "_":
            end = index + 1
            while end < length and (source[end].isalnum() or source[end] == "_"):
                end += 1
            ident = source[index:end]
            tokens.append(Token("ident", ident, line))
            index = end
            continue

        # Punctuation / symbols
        tokens.append(Token("punct", char, line))
        index += 1

    return tokens


def scan_source(source: str, relative_path: str) -> list[Finding]:
    """Scan tokenized Rust for forbidden struct definitions outside owner."""
    if relative_path in OWNER_PATHS:
        return []

    findings: list[Finding] = []
    tokens = lex_rust(source)

    for i in range(len(tokens) - 1):
        if tokens[i].text == "struct" and tokens[i + 1].text in FORBIDDEN_STRUCT_NAMES:
            struct_name = tokens[i + 1].text
            findings.append(
                Finding(
                    category="forbidden-address-domain-definition",
                    path=relative_path,
                    line=tokens[i + 1].line,
                    detail=f"struct {struct_name} defined outside carrick-guest-arch owner",
                )
            )

    return findings


def _relative(path: Path, root: Path = REPO_ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def scan_paths(paths: Iterable[Path], root: Path = REPO_ROOT) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(paths):
        if path.suffix == ".rs":
            findings.extend(scan_source(path.read_text(encoding="utf-8"), _relative(path, root)))
    return sorted(findings)


def requested_paths(raw_paths: Sequence[str], root_dir: Path = REPO_ROOT) -> list[Path]:
    if not raw_paths:
        return [path for r in DEFAULT_SCAN_ROOTS for path in r.rglob("*.rs")]
    paths: list[Path] = []
    repo = root_dir.resolve()
    for raw_path in raw_paths:
        candidate = (root_dir / raw_path).resolve()
        try:
            candidate.relative_to(repo)
        except ValueError as error:
            raise ValueError(f"path escapes repository: {raw_path}") from error
        if not candidate.exists():
            raise ValueError(f"path does not exist: {raw_path}")
        paths.extend(candidate.rglob("*.rs") if candidate.is_dir() else [candidate])
    return paths


def self_test() -> None:
    negative = {
        "crates/carrick-core/src/mm/transfer.rs": (
            "forbidden-address-domain-definition",
            "pub struct GuestVa(pub u64);",
        ),
        "crates/carrick-guest-mem/src/lib.rs": (
            "forbidden-address-domain-definition",
            "#[derive(Debug)]\npub struct HostVa(pub usize);",
        ),
        "crates/carrick-softmmu/src/domains.rs": (
            "forbidden-address-domain-definition",
            "struct Gpa(u64);",
        ),
        "crates/carrick-kernel/src/other.rs": (
            "forbidden-address-domain-definition",
            "pub(crate) struct GuestVa { addr: u64 }",
        ),
    }
    positive = {
        "crates/carrick-guest-arch/src/lib.rs": (
            "pub struct GuestVa(u64);\n"
            "pub struct HostVa(usize);\n"
            "pub struct Gpa(u64);\n"
        ),
        "crates/carrick-guest-mem/src/reexport.rs": (
            "pub use carrick_guest_arch::{Gpa, GuestVa, HostVa};\n"
            "pub struct GuestVaRange { start: GuestVa, end: GuestVa }\n"
            "pub struct Stage1Gpa(u64);\n"
            "pub struct AuthenticatedGpa(Gpa);\n"
        ),
        "crates/carrick-runtime/src/comment_and_string.rs": (
            "// struct GuestVa(u64);\n"
            "/* pub struct HostVa(usize); */\n"
            'const MSG: &str = "struct Gpa(u64);";\n'
            'const RAW: &str = r#"struct GuestVa(u64);"#;\n'
            "let va = GuestVa::new(0x1000);\n"
        ),
    }

    with tempfile.TemporaryDirectory(prefix="carrick-address-domains-") as directory:
        root = Path(directory)
        for name, (_, source) in negative.items():
            file_path = root / name
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(source + "\n", encoding="utf-8")
        for name, source in positive.items():
            file_path = root / name
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(source + "\n", encoding="utf-8")

        for name, (category, _) in negative.items():
            file_path = root / name
            findings = scan_paths([file_path], root=root)
            if not findings:
                raise AssertionError(f"{name}: expected finding {category}, got nothing")
            if findings[0].category != category:
                raise AssertionError(f"{name}: expected category {category}, got {findings[0].category}")
        for name in positive:
            file_path = root / name
            findings = scan_paths([file_path], root=root)
            if findings:
                raise AssertionError(f"{name}: unexpected findings {findings!r}")

    print(
        f"address domains self-test: {len(negative)} negative and {len(positive)} positive fixtures passed"
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--self-test", action="store_true", help="Run self-test fixtures")
    mode.add_argument("--check", action="store_true", help="Check workspace for forbidden address domain structs")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="Repository root directory")
    parser.add_argument("--path", action="append", default=[], help="Specific paths to scan")
    args = parser.parse_args(argv)
    if not args.self_test and not args.check and not args.path:
        parser.error("one of --self-test, --check, or --path is required")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        self_test()
        return 0
    try:
        paths = requested_paths(args.path, root_dir=args.root)
    except ValueError as error:
        print(f"address domains gate: {error}", file=sys.stderr)
        return 2
    findings = scan_paths(paths, root=args.root)
    if findings:
        for finding in findings:
            print(
                f"{finding.path}:{finding.line}: {finding.category}: {finding.detail}",
                file=sys.stderr,
            )
        print(f"address domains gate: {len(findings)} forbidden struct definition(s)", file=sys.stderr)
        return 1
    print(f"address domains gate: ok ({len(paths)} Rust files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

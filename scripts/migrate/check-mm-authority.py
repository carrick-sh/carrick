#!/usr/bin/env python3
"""Reject untyped MM authority and debug-only structural lock order."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys
import tempfile
from typing import Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCAN_ROOTS = (
    REPO_ROOT / "crates" / "carrick-runtime",
    REPO_ROOT / "crates" / "carrick-hal",
    REPO_ROOT / "crates" / "carrick-guest-mem",
    REPO_ROOT / "crates" / "carrick-vmm-hvf",
)

FORBIDDEN = {
    "foreign-current-memory": "current GuestMemory access in a foreign target arm",
    "raw-mm-authority": "raw pid/mm/ttbr/va tuple crosses an MM access API",
    "untyped-current-bound": "production dispatch generic uses GuestMemory without CurrentMmMemory",
    "unpermitted-host-alias": "host-alias acquisition lacks HostAliasPermit",
    "legacy-lock-order": "debug-only LockLevel authority remains",
    "public-mm-token-construction": "opaque MM authority is externally constructible",
    "blanket-current-impl": "CurrentMmMemory has a blanket implementation",
}


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
    """Tokenize the Rust constructs needed for source-shape enforcement."""
    tokens: list[Token] = []
    index = 0
    line = 1
    while index < len(source):
        char = source[index]
        if char.isspace():
            line += char == "\n"
            index += 1
            continue
        if source[index : index + 2] == "//":
            index = source.find("\n", index)
            if index < 0:
                break
            continue
        if source[index : index + 2] == "/*":
            depth = 1
            index += 2
            while index < len(source) and depth:
                if source[index : index + 2] == "/*":
                    depth += 1
                    index += 2
                elif source[index : index + 2] == "*/":
                    depth -= 1
                    index += 2
                else:
                    line += source[index] == "\n"
                    index += 1
            continue
        if char in {'"', "'"} or (
            char in {"b", "c"}
            and index + 1 < len(source)
            and source[index + 1] in {'"', "'"}
        ):
            quote = source[index + (char in {"b", "c"})]
            start_line = line
            if quote == "'" and index + 1 < len(source) and source[index + 1].isalpha():
                end = index + 1
                while end < len(source) and (source[end].isalnum() or source[end] == "_"):
                    end += 1
                if end == len(source) or source[end] != "'":
                    tokens.append(Token("lifetime", source[index:end], start_line))
                    index = end
                    continue
            index += 1 + (char in {"b", "c"})
            while index < len(source):
                line += source[index] == "\n"
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            tokens.append(Token("literal", quote, start_line))
            continue
        if char == "r":
            cursor = index + 1
            while cursor < len(source) and source[cursor] == "#":
                cursor += 1
            if cursor < len(source) and source[cursor] == '"':
                closing = '"' + source[index + 1 : cursor]
                end = source.find(closing, cursor + 1)
                end = len(source) if end < 0 else end + len(closing)
                line += source[index:end].count("\n")
                tokens.append(Token("literal", "r", line,))
                index = end
                continue
        if char.isalpha() or char == "_":
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] == "_"):
                end += 1
            tokens.append(Token("ident", source[index:end], line))
            index = end
            continue
        if char.isdigit():
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] in "._"):
                end += 1
            tokens.append(Token("number", source[index:end], line))
            index = end
            continue
        punctuation = source[index : index + 2]
        if punctuation in {"::", "->", "=>", "..", "==", "!=", "<=", ">=", "&&", "||"}:
            tokens.append(Token("punct", punctuation, line))
            index += 2
        else:
            tokens.append(Token("punct", char, line))
            index += 1
    return tokens


def matching(tokens: Sequence[Token], start: int, opening: str, closing: str) -> int:
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
    """Ignore exact #[test] and #[cfg(test)] items, like the sibling gates."""
    production = [True] * len(tokens)
    stack = [False]
    pending_test_item = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        current_test = stack[-1]
        if token.text == "#" and index + 1 < len(tokens) and tokens[index + 1].text == "[":
            end = matching(tokens, index + 1, "[", "]")
            attribute = [item.text for item in tokens[index + 2 : end]]
            pending_test_item |= attribute in (["test"], ["cfg", "(", "test", ")"])
            for attribute_index in range(index, end + 1):
                production[attribute_index] = not current_test
            index = end + 1
            continue
        if pending_test_item and token.text in {
            "fn",
            "mod",
            "impl",
            "trait",
            "struct",
            "enum",
            "type",
            "use",
            "const",
            "static",
        }:
            pending_test_item = False
            cursor = index
            while cursor < len(tokens) and tokens[cursor].text not in {"{", ";"}:
                production[cursor] = False
                cursor += 1
            if cursor < len(tokens) and tokens[cursor].text == "{":
                end = matching(tokens, cursor, "{", "}")
                for body_index in range(cursor, end + 1):
                    production[body_index] = False
                index = end + 1
                continue
            if cursor < len(tokens):
                production[cursor] = False
                index = cursor + 1
                continue
        if token.text == "{":
            stack.append(current_test or pending_test_item)
            production[index] = not stack[-1]
            pending_test_item = False
        elif token.text == "}":
            production[index] = not current_test
            if len(stack) > 1:
                stack.pop()
        else:
            production[index] = not current_test
        index += 1
    return production


def sequence_at(tokens: Sequence[Token], index: int, values: Sequence[str]) -> bool:
    return [token.text for token in tokens[index : index + len(values)]] == list(values)


def function_signature_end(tokens: Sequence[Token], start: int) -> int:
    for index in range(start, len(tokens)):
        if tokens[index].text in {"{", ";"}:
            return index
    return len(tokens)


def _has_host_alias_context(tokens: Sequence[Token], index: int) -> bool:
    return any(token.text == "HostAliasTransactions" for token in tokens) or any(
        token.text == "host_alias_transactions" for token in tokens[max(0, index - 8) : index]
    )


def scan_source(source: str, relative_path: str) -> list[Finding]:
    """Return forbidden production authority shapes in one Rust leaf."""
    tokens = lex_rust(source)
    production = production_mask(tokens)
    findings: set[Finding] = set()

    is_guest_mem_crate = relative_path.startswith("crates/carrick-guest-mem/")

    def add(index: int, category: str, detail: str) -> None:
        if production[index]:
            findings.add(Finding(category, relative_path, tokens[index].line, detail))

    def add_once(category: str, index: int, detail: str) -> None:
        if not any(finding.category == category for finding in findings):
            add(index, category, detail)

    for index, token in enumerate(tokens):
        if not production[index] or token.kind == "literal":
            continue

        if token.text == "OtherGuest":
            arrow = next(
                (
                    cursor
                    for cursor in range(index + 1, min(index + 24, len(tokens)))
                    if tokens[cursor].text == "=>"
                ),
                None,
            )
            if arrow is not None:
                body_start = arrow + 1
                body_end = matching(tokens, body_start, "{", "}") if body_start < len(tokens) and tokens[body_start].text == "{" else body_start
                direct_current_access = False
                for cursor in range(body_start, body_end + 1):
                    forbidden_memory = tokens[cursor].text == "process_vm_copy_self" or sequence_at(tokens, cursor, [".", "read_bytes", "("])
                    if forbidden_memory:
                        direct_current_access = True
                        add(cursor, "foreign-current-memory", tokens[cursor].text)
                if not direct_current_access:
                    function = next(
                        (cursor for cursor in range(index - 1, -1, -1) if tokens[cursor].text == "fn"),
                        None,
                    )
                    if function is not None:
                        signature_end = function_signature_end(tokens, function)
                        sig_tokens = [item.text for item in tokens[function:signature_end]]
                        if "GuestMemory" in sig_tokens or "CurrentMmMemory" in sig_tokens:
                            add(index, "foreign-current-memory", "OtherGuest arm remains inside current GuestMemory dispatch")

        if token.text == "fn" and index > 0 and tokens[index - 1].text == "pub":
            end = function_signature_end(tokens, index)
            signature = [item.text for item in tokens[index:end]]
            raw_coordinates = {"pid", "target_pid", "mm", "ttbr", "va"}
            if (
                len(raw_coordinates.intersection(signature)) >= 2
                or (index + 1 < len(tokens) and tokens[index + 1].text == "is_range_mapped" and "u64" in signature)
            ):
                add(index, "raw-mm-authority", "public ForeignMmAccess API accepts raw MM coordinates")
            if token.text == "fn" and index + 1 < len(tokens) and tokens[index + 1].text == "for_task":
                if "ForeignMmAccess" in signature or relative_path.endswith("kernel/foreign_mm.rs"):
                    add(index + 1, "public-mm-token-construction", "ForeignMmAccess::for_task is public")

        if not is_guest_mem_crate:
            if token.text == "fn":
                end = function_signature_end(tokens, index)
                signature = [item.text for item in tokens[index:end]]
                if "GuestMemory" in signature and "CurrentMmMemory" not in signature:
                    add(index, "untyped-current-bound", "GuestMemory generic lacks CurrentMmMemory")

            if token.text in {"struct", "enum", "trait", "type"}:
                end = function_signature_end(tokens, index)
                header = [item.text for item in tokens[index:end]]
                if "GuestMemory" in header and "CurrentMmMemory" not in header and "<" in header:
                    add(index, "untyped-current-bound", "GuestMemory generic lacks CurrentMmMemory")

            if token.text == "impl":
                end = function_signature_end(tokens, index)
                header = [item.text for item in tokens[index:end]]
                if "GuestMemory" in header and "CurrentMmMemory" not in header:
                    if "for" in header:
                        for_idx = header.index("for")
                        trait_part = header[1:for_idx]
                        if "<" in trait_part or trait_part not in (["GuestMemory"], ["carrick_guest_mem", "::", "GuestMemory"]):
                            add(index, "untyped-current-bound", "GuestMemory generic lacks CurrentMmMemory")
                    elif "<" in header:
                        add(index, "untyped-current-bound", "GuestMemory generic lacks CurrentMmMemory")

        if sequence_at(tokens, index, [".", "begin_dispatch", "(", ")"]):
            if _has_host_alias_context(tokens, index):
                add(index + 1, "unpermitted-host-alias", "HostAliasTransactions::begin_dispatch()")

        if token.text in {"LockLevel", "LockOrderGuard"}:
            add_once("legacy-lock-order", index, token.text)

        if token.text == "impl":
            end = function_signature_end(tokens, index)
            header = [item.text for item in tokens[index:end]]
            if "CurrentMmMemory" in header and "for" in header:
                target = header[header.index("for") + 1] if header.index("for") + 1 < len(header) else ""
                if target and target in header[1 : header.index("CurrentMmMemory")]:
                    add(index, "blanket-current-impl", "CurrentMmMemory blanket implementation")

    return sorted(findings)


def _relative(path: Path, root: Path = REPO_ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def scan_paths(paths: Iterable[Path], root: Path = REPO_ROOT) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(paths):
        if path.suffix == ".rs" and "tests" not in path.parts and path.name != "tests.rs":
            findings.extend(scan_source(path.read_text(encoding="utf-8"), _relative(path, root)))
    return sorted(findings)


def requested_paths(raw_paths: Sequence[str]) -> list[Path]:
    if not raw_paths:
        return [path for root in DEFAULT_SCAN_ROOTS for path in root.rglob("*.rs")]
    repo = REPO_ROOT.resolve()
    paths: list[Path] = []
    for raw_path in raw_paths:
        candidate = (REPO_ROOT / raw_path).resolve()
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
        "foreign-copy.rs": (
            "foreign-current-memory",
            "match target { MmRelation::OtherGuest => { process_vm_copy_self(memory); } }",
        ),
        "foreign-read.rs": (
            "foreign-current-memory",
            "match target { MmRelation::OtherGuest => { memory.read_bytes(0, 1); } }",
        ),
        "foreign-current-mm.rs": (
            "foreign-current-memory",
            "fn f<M: CurrentMmMemory>(m: &M) { match target { MmRelation::OtherGuest => { todo!() } } }",
        ),
        "raw-tuple.rs": (
            "raw-mm-authority",
            "pub fn access(pid: u64, mm: u64, ttbr: u64, va: u64) {}",
        ),
        "generic-current.rs": (
            "untyped-current-bound",
            "fn dispatch<M: GuestMemory>(memory: &M) {}",
        ),
        "impl-param-current.rs": (
            "untyped-current-bound",
            "fn dispatch(memory: &impl GuestMemory) {}",
        ),
        "dyn-param-current.rs": (
            "untyped-current-bound",
            "fn dispatch(memory: &dyn GuestMemory) {}",
        ),
        "crates/carrick-runtime/src/fake_guest_mem.rs": (
            "untyped-current-bound",
            "fn dispatch(memory: &impl GuestMemory) {}",
        ),
        "type-generic-current.rs": (
            "untyped-current-bound",
            "struct SyscallCtx<'a, M: GuestMemory> { memory: &'a M }",
        ),
        "impl-generic-current.rs": (
            "untyped-current-bound",
            "impl<M: GuestMemory> Dispatcher<M> {}",
        ),
        "host-alias.rs": (
            "unpermitted-host-alias",
            "fn f(t: &HostAliasTransactions) { t.begin_dispatch(); }",
        ),
        "legacy-lock.rs": (
            "legacy-lock-order",
            "fn f() { LockOrderGuard::acquire(LockLevel::Proc); }",
        ),
        "public-token.rs": (
            "public-mm-token-construction",
            "pub fn for_task(kernel: &Kernel, pid: TaskId) -> ForeignMmAccess { todo!() }",
        ),
        "blanket-current.rs": (
            "blanket-current-impl",
            "impl<T: GuestMemory> CurrentMmMemory for T {}",
        ),
        "implicit-blanket-current.rs": (
            "blanket-current-impl",
            "impl<T> CurrentMmMemory for T where T: GuestMemory {}",
        ),
    }
    positive = {
        "comment.rs": "// LockOrderGuard::acquire(LockLevel::Proc)",
        "string.rs": 'const EXAMPLE: &str = "memory.read_bytes(0, 1)";',
        "test.rs": "#[cfg(test)] fn f<M: GuestMemory>(memory: &M) { memory.read_bytes(0, 1); }",
        "test-impl.rs": "#[cfg(test)] impl<T: GuestMemory> CurrentMmMemory for T {}",
        "test-use.rs": "#[cfg(test)] use crate::dispatch::lock_order::LockLevel;",
        "test-const.rs": "#[cfg(test)] const LEVEL: LockLevel = LockLevel::Proc;",
        "test-static.rs": "#[cfg(test)] static LEVEL: Option<LockLevel> = None;",
        "current-bound.rs": "fn dispatch<M: GuestMemory + CurrentMmMemory>(memory: &M) {}",
        "current-type-bound.rs": "struct SyscallCtx<M: GuestMemory + CurrentMmMemory> { memory: M }",
        "current-impl-bound.rs": "impl<M: GuestMemory + CurrentMmMemory> Dispatcher<M> {}",
        "current-relation.rs": "match target { MmRelation::Current => memory.read_bytes(0, 1) }",
        "foreign-facade.rs": "fn f(access: ForeignMmAccess) { access.read_foreign(0, 1); }",
        "permitted-host-alias.rs": "fn f(t: &HostAliasTransactions, permit: &HostAliasPermit) { t.begin_dispatch(&permit); }",
        "crates/carrick-guest-mem/src/guard.rs": "pub struct HostWriteGuard<'a, M: GuestMemory + ?Sized> { memory: &'a mut M }",
        "crates/carrick-guest-mem/src/zero.rs": "pub fn zero_range(memory: &mut impl GuestMemory) {}",
    }

    with tempfile.TemporaryDirectory(prefix="carrick-mm-authority-") as directory:
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
            expected = [(category, name, 1)]
            actual = [(finding.category, finding.path, finding.line) for finding in findings]
            if actual != expected:
                raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")
        for name in positive:
            file_path = root / name
            findings = scan_paths([file_path], root=root)
            if findings:
                raise AssertionError(f"{name}: unexpected findings {findings!r}")

    print(
        "mm authority self-test: "
        f"{len(negative)} negative and {len(positive)} positive fixtures passed"
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--path", action="append", default=[])
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
        paths = requested_paths(args.path)
    except ValueError as error:
        print(f"mm authority gate: {error}", file=sys.stderr)
        return 2
    findings = scan_paths(paths)
    if findings:
        for finding in findings:
            print(
                f"{finding.path}:{finding.line}: {finding.category}: "
                f"{FORBIDDEN[finding.category]} ({finding.detail})",
                file=sys.stderr,
            )
        print(f"mm authority gate: {len(findings)} production finding(s)", file=sys.stderr)
        return 1
    print(f"mm authority gate: ok ({len(paths)} Rust leaves)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

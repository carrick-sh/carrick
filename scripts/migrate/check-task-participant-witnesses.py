#!/usr/bin/env python3

"""Reject scalar or generic thread-population authority in production Rust.

Carrick has several distinct thread populations: durable Task membership,
active/admitting guest executors, crash responders, and current vCPU leases.
This gate rejects the source shapes that erase those distinctions. It tokenizes
Rust so comments, literals, and exact test-only scopes cannot satisfy or trip
the production contract.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys
import tempfile
from typing import Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCAN_ROOT = REPO_ROOT / "crates" / "carrick-runtime" / "src"

RAW_TASK_MEMBERSHIP = "raw task membership arithmetic"
RAW_TASK_PROJECTION = "generic task membership projection"
RAW_TASK_CARDINALITY = "raw task cardinality"
SCALAR_CENSUS_STORAGE = "scalar executor census storage"
SCALAR_CENSUS_API = "scalar executor census API"
RAW_CRASH_PARTICIPATION = "raw crash-safe-point mutation"

CRASH_MUTATION_OWNERS = frozenset(
    {
        "crates/carrick-runtime/src/kernel/guest_execution.rs",
        "crates/carrick-runtime/src/kernel/objects.rs",
    }
)


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int
    pos: int


@dataclass(frozen=True, order=True)
class Finding:
    category: str
    path: str
    line: int
    detail: str


def lex_rust(source: str) -> list[Token]:
    """Tokenize enough Rust to recognize authority shapes and test scopes."""
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

        three = source[i : i + 3]
        if three in {"...", "..="}:
            tokens.append(Token("punct", three, line, i))
            i += 3
            continue
        two = source[i : i + 2]
        if two in {
            "::",
            "->",
            "=>",
            "==",
            "!=",
            "<=",
            ">=",
            "&&",
            "||",
            "+=",
            "-=",
            "*=",
            "/=",
            "<<",
            ">>",
            "..",
        }:
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
    """Return True for tokens that can compile with cfg(test) disabled."""
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
            exact_cfg_test = attribute == ["cfg", "(", "test", ")"]
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


def _sequence_at(tokens: Sequence[Token], index: int, texts: Sequence[str]) -> bool:
    return [token.text for token in tokens[index : index + len(texts)]] == list(texts)


def _find_block(tokens: Sequence[Token], start: int) -> tuple[int, int] | None:
    for index in range(start, len(tokens)):
        if tokens[index].text == "{":
            return index, _matching_delimiter(tokens, index, "{", "}")
        if tokens[index].text == ";":
            return None
    return None


def scan_source(source: str, relative_path: str) -> list[Finding]:
    tokens = lex_rust(source)
    is_production = production_mask(tokens)
    findings: set[Finding] = set()

    def add(index: int, category: str, detail: str) -> None:
        if index < len(tokens) and is_production[index]:
            findings.add(Finding(category, relative_path, tokens[index].line, detail))

    for index, token in enumerate(tokens):
        if not is_production[index] or token.kind in {"string", "char"}:
            continue

        if _sequence_at(tokens, index, [".", "threads", "(", ")", ".", "len", "(", ")"]):
            add(index, RAW_TASK_MEMBERSHIP, "threads().len()")
        if _sequence_at(
            tokens,
            index,
            [".", "threads", "(", ")", ".", "iter", "(", ")", ".", "count", "(", ")"],
        ):
            add(index, RAW_TASK_MEMBERSHIP, "threads().iter().count()")
        if (
            relative_path == "crates/carrick-runtime/src/kernel/crash_capture.rs"
            and _sequence_at(tokens, index, [".", "threads", "(", ")"])
        ):
            add(index, RAW_TASK_PROJECTION, "CrashQuorum generic Task::threads()")
        if token.kind == "ident" and token.text == "live_thread_count":
            add(index, RAW_TASK_CARDINALITY, "live_thread_count")
        if (
            relative_path == "crates/carrick-runtime/src/vcpu_loop/quiesce.rs"
            and _sequence_at(tokens, index, [".", "live", "(", ")"])
        ):
            add(index, SCALAR_CENSUS_API, "GuestExecutorCensus::live() call")

        if (
            token.kind == "ident"
            and token.text
            in {
                "enter_crash_safe_point_participation",
                "leave_crash_safe_point_participation",
            }
            and relative_path not in CRASH_MUTATION_OWNERS
        ):
            add(index, RAW_CRASH_PARTICIPATION, token.text)

        if _sequence_at(tokens, index, ["struct", "GuestExecutorCensus"]):
            block = _find_block(tokens, index + 2)
            if block is not None:
                start, end = block
                for member_index in range(start + 1, end):
                    if (
                        is_production[member_index]
                        and tokens[member_index].text == "AtomicUsize"
                    ):
                        add(member_index, SCALAR_CENSUS_STORAGE, "GuestExecutorCensus AtomicUsize")

        if _sequence_at(tokens, index, ["impl", "GuestExecutorCensus"]):
            block = _find_block(tokens, index + 2)
            if block is not None:
                start, end = block
                cursor = start + 1
                while cursor < end:
                    if _sequence_at(tokens, cursor, ["fn", "live"]):
                        fn_block = _find_block(tokens, cursor + 2)
                        signature_end = fn_block[0] if fn_block is not None else end
                        signature = [item.text for item in tokens[cursor:signature_end]]
                        if "->" in signature and "usize" in signature:
                            add(cursor, SCALAR_CENSUS_API, "GuestExecutorCensus::live() -> usize")
                    cursor += 1

    return sorted(findings)


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return path.name


def scan_paths(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(paths):
        if path.suffix != ".rs":
            continue
        findings.extend(scan_source(path.read_text(encoding="utf-8"), _relative(path)))
    return sorted(findings)


def self_test() -> None:
    negative = {
        "raw_len.rs": (RAW_TASK_MEMBERSHIP, "fn f(task: &Task) { if task.threads().len() > 1 {} }"),
        "raw_iter_count.rs": (
            RAW_TASK_MEMBERSHIP,
            "fn f(task: &Task) { if task.threads().iter().count() > 1 {} }",
        ),
        "raw_task_count.rs": (
            RAW_TASK_CARDINALITY,
            "fn f(task: &Task) { let _ = task.live_thread_count(); }",
        ),
        "scalar_census.rs": (
            SCALAR_CENSUS_STORAGE,
            "struct GuestExecutorCensus { live: AtomicUsize }",
        ),
        "scalar_census_api.rs": (
            SCALAR_CENSUS_API,
            "impl GuestExecutorCensus { pub fn live(&self) -> usize { 1 } }",
        ),
        "raw_crash.rs": (
            RAW_CRASH_PARTICIPATION,
            "fn f(thread: &Thread) { thread.enter_crash_safe_point_participation(); }",
        ),
    }
    positive = {
        "comment.rs": "fn f() { /* task.threads().len() */ let _ = 1; }",
        "string.rs": 'fn f() { let _ = "task.threads().len()"; }',
        "test_mod.rs": "#[cfg(test)] mod tests { fn f(task: &Task) { let _ = task.live_thread_count(); } }",
        "test_fn.rs": "#[test] fn scalar_fixture() { let _ = census.live(); }",
        "fork.rs": "fn f(w: &ForkBarrierParticipants) { if w.requires_quiesce() {} }",
        "crash.rs": "fn f(w: &CrashBarrierParticipants) { if w.requires_quiesce() {} }",
        "exit.rs": "fn f(w: &ThreadExitParticipants) { if w.permits_nonfinal_exit() {} }",
        "roster.rs": "fn f(w: CrashCaptureParticipants) { for t in w.into_threads() {} }",
        "probe.rs": "fn f(w: &CoreNoteParticipants) { probe(w.required_note_count_for_probe()); }",
        "census_probe.rs": "fn f(c: &GuestExecutorCensus) { probe(c.participant_count_for_probe()); }",
    }

    with tempfile.TemporaryDirectory(prefix="carrick-participant-gate-") as directory:
        root = Path(directory)
        for name, (_, source) in negative.items():
            (root / name).write_text(source + "\n", encoding="utf-8")
        for name, source in positive.items():
            (root / name).write_text(source + "\n", encoding="utf-8")

        for name, (expected_category, _) in negative.items():
            findings = scan_paths([root / name])
            categories = [finding.category for finding in findings]
            if categories != [expected_category]:
                raise AssertionError(f"{name}: expected {[expected_category]!r}, got {categories!r}")
        for name in positive:
            findings = scan_paths([root / name])
            if findings:
                raise AssertionError(f"{name}: unexpected findings {findings!r}")

        crash_projection = scan_source(
            "fn poll(&self) { for thread in self.task.threads() {} }\n",
            "crates/carrick-runtime/src/kernel/crash_capture.rs",
        )
        if [finding.category for finding in crash_projection] != [RAW_TASK_PROJECTION]:
            raise AssertionError(
                "crash projection: expected generic task membership finding, "
                f"got {crash_projection!r}"
            )

        census_call = scan_source(
            "fn pause(census: &GuestExecutorCensus) { probe(census.live()); }\n",
            "crates/carrick-runtime/src/vcpu_loop/quiesce.rs",
        )
        if [finding.category for finding in census_call] != [SCALAR_CENSUS_API]:
            raise AssertionError(
                "census call: expected scalar executor census finding, "
                f"got {census_call!r}"
            )

    print(
        "task participant witness self-test: "
        f"{len(negative) + 2} negative and {len(positive)} positive fixtures passed"
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        help="scan one repository-relative Rust file or directory (repeatable)",
    )
    return parser.parse_args(argv)


def requested_paths(raw_paths: Sequence[str]) -> list[Path]:
    if not raw_paths:
        return list(DEFAULT_SCAN_ROOT.rglob("*.rs"))
    paths: list[Path] = []
    repo = REPO_ROOT.resolve()
    for raw in raw_paths:
        candidate = (REPO_ROOT / raw).resolve()
        try:
            candidate.relative_to(repo)
        except ValueError as error:
            raise ValueError(f"path escapes repository: {raw}") from error
        if not candidate.exists():
            raise ValueError(f"path does not exist: {raw}")
        if candidate.is_dir():
            paths.extend(candidate.rglob("*.rs"))
        else:
            paths.append(candidate)
    return paths


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        self_test()
        return 0
    try:
        paths = requested_paths(args.path)
    except ValueError as error:
        print(f"task participant witness gate: {error}", file=sys.stderr)
        return 2
    findings = scan_paths(paths)
    if findings:
        for finding in findings:
            print(
                f"{finding.path}:{finding.line}: {finding.category}: {finding.detail}",
                file=sys.stderr,
            )
        print(
            f"task participant witness gate: {len(findings)} production finding(s)",
            file=sys.stderr,
        )
        return 1
    print(f"task participant witness gate: ok ({len(paths)} Rust leaves)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

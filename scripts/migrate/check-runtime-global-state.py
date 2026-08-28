#!/usr/bin/env python3

"""Gate process-global state with a stable monotone ledger.

Discovers process-global statics, thread-local cells, and environment variable
reads across the runtime crates. Compares against the checked ledger
`runtime-global-state.json` to ensure no new unreviewed process-global state is
introduced and source modifications are explicitly reviewed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
LEDGER_PATH = REPO_ROOT / "scripts" / "migrate" / "runtime-global-state.json"

DEFAULT_SCAN_ROOTS = (
    "crates/carrick-runtime/src",
    "crates/carrick-kernel/src",
    "crates/carrick-vmm-hvf/src",
)

ALLOWED_CLASSIFICATIONS = frozenset(
    {
        "container_debt",
        "carrier_infra",
        "host_kernel_object",
        "monotonic_allocator",
        "config_debug",
        "test_only",
    }
)


class LedgerError(Exception):
    """The source state violates the reviewed global-state ledger contract."""


@dataclass(frozen=True, order=True)
class Finding:
    kind: str  # static | thread_local | env_var | env_var_os
    file: str
    symbol: str
    fingerprint: str  # sha256(normalized tokens), never a line number


@dataclass(frozen=True)
class Token:
    kind: str  # IDENT, LIFETIME, STRING, CHAR, NUMBER, PUNCT
    text: str
    pos: int


def _tokenize(source: str) -> list[Token]:
    """Tokenize Rust source code into lexical tokens, skipping comments and whitespace."""
    tokens: list[Token] = []
    i = 0
    n = len(source)

    while i < n:
        c = source[i]

        # 1. Whitespace
        if c.isspace():
            i += 1
            continue

        # 2. Line comment
        if c == "/" and i + 1 < n and source[i + 1] == "/":
            i += 2
            while i < n and source[i] != "\n":
                i += 1
            continue

        # 3. Block comment (with nesting)
        if c == "/" and i + 1 < n and source[i + 1] == "*":
            i += 2
            depth = 1
            while i < n and depth > 0:
                if source[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif source[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue

        # 4. Raw string literals: r"...", r#"..."#, br"...", br#"..."#
        is_raw_byte = source[i : i + 3].startswith("br\"") or source[
            i : i + 3
        ].startswith("br#")
        is_raw = (
            c == "r" and i + 1 < n and (source[i + 1] == '"' or source[i + 1] == "#")
        )
        if is_raw or is_raw_byte:
            start_pos = i
            if is_raw_byte:
                i += 2  # skip 'br'
            else:
                i += 1  # skip 'r'
            hash_count = 0
            while i < n and source[i] == "#":
                hash_count += 1
                i += 1
            if i < n and source[i] == '"':
                i += 1  # skip opening quote
                end_marker = '"' + ("#" * hash_count)
                end_idx = source.find(end_marker, i)
                if end_idx != -1:
                    i = end_idx + len(end_marker)
                    tokens.append(Token("STRING", source[start_pos:i], start_pos))
                    continue
                else:
                    i = n
                    tokens.append(Token("STRING", source[start_pos:i], start_pos))
                    continue
            else:
                i = start_pos

        # 5. Normal strings / byte strings: "...", b"..."
        if c == '"' or (c == "b" and i + 1 < n and source[i + 1] == '"'):
            start_pos = i
            if c == "b":
                i += 2
            else:
                i += 1
            while i < n:
                if source[i] == "\\":
                    i += 2
                elif source[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            tokens.append(Token("STRING", source[start_pos:i], start_pos))
            continue

        # 6. Chars / Byte chars / Lifetimes: '...
        if c == "'" or (c == "b" and i + 1 < n and source[i + 1] == "'"):
            start_pos = i
            is_byte = c == "b"
            if is_byte:
                i += 2
            else:
                i += 1

            if i < n:
                # Check for lifetime: 'ident where not followed by '
                if not is_byte and (source[i].isalpha() or source[i] == "_"):
                    ident_start = i
                    while i < n and (source[i].isalnum() or source[i] == "_"):
                        i += 1
                    if i < n and source[i] == "'":
                        i += 1
                        tokens.append(Token("CHAR", source[start_pos:i], start_pos))
                    else:
                        tokens.append(
                            Token("LIFETIME", source[start_pos:i], start_pos)
                        )
                    continue
                elif source[i] == "\\":
                    i += 1
                    while i < n and source[i] != "'":
                        if source[i] == "\\":
                            i += 2
                        else:
                            i += 1
                    if i < n and source[i] == "'":
                        i += 1
                    tokens.append(Token("CHAR", source[start_pos:i], start_pos))
                    continue
                else:
                    i += 1
                    if i < n and source[i] == "'":
                        i += 1
                    tokens.append(Token("CHAR", source[start_pos:i], start_pos))
                    continue

        # 7. Identifiers / keywords: [a-zA-Z_][a-zA-Z0-9_]* (and r#ident)
        if c == "r" and i + 1 < n and source[i + 1] == "#":
            start_pos = i
            i += 2
            while i < n and (source[i].isalnum() or source[i] == "_"):
                i += 1
            tokens.append(Token("IDENT", source[start_pos:i], start_pos))
            continue

        if c.isalpha() or c == "_":
            start_pos = i
            while i < n and (source[i].isalnum() or source[i] == "_"):
                i += 1
            tokens.append(Token("IDENT", source[start_pos:i], start_pos))
            continue

        # 8. Numbers: 0x..., 0b..., 0o..., 123...
        if c.isdigit():
            start_pos = i
            while i < n and (source[i].isalnum() or source[i] in "._"):
                if source[i] == "." and i + 1 < n and source[i + 1] == ".":
                    break
                i += 1
            tokens.append(Token("NUMBER", source[start_pos:i], start_pos))
            continue

        # 9. Punctuation / Multi-character symbols
        start_pos = i
        two = source[i : i + 2]
        three = source[i : i + 3]

        if three in ("...", "..="):
            tokens.append(Token("PUNCT", three, start_pos))
            i += 3
            continue

        if two in (
            "::",
            "->",
            "=>",
            "==",
            "!=",
            "<=",
            ">=",
            "+=",
            "-=",
            "*=",
            "/=",
            "&&",
            "||",
            "<<",
            ">>",
            "..",
        ):
            tokens.append(Token("PUNCT", two, start_pos))
            i += 2
            continue

        tokens.append(Token("PUNCT", c, start_pos))
        i += 1

    return tokens


def _strip_string_quotes(raw: str) -> str:
    """Extract string contents from string / raw-string literal tokens."""
    if raw.startswith('r#"') and raw.endswith('"#'):
        return raw[3:-2]
    if raw.startswith('r##"') and raw.endswith('"##'):
        return raw[4:-3]
    if raw.startswith('r"') and raw.endswith('"'):
        return raw[2:-1]
    if raw.startswith('b"') and raw.endswith('"'):
        return raw[2:-1]
    if raw.startswith('br#"') and raw.endswith('"#'):
        return raw[4:-2]
    if raw.startswith('br"') and raw.endswith('"'):
        return raw[3:-1]
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    return raw


def _format_env_arg(tokens: Sequence[Token]) -> str:
    """Format the argument of an env::var call into a symbol component."""
    if len(tokens) == 1 and tokens[0].kind == "STRING":
        return _strip_string_quotes(tokens[0].text)

    parts: list[str] = []
    for tok in tokens:
        if (
            parts
            and parts[-1] not in ("::", ".", "&", "(", "[")
            and tok.text not in ("::", ".", "&", ")", "]", ",")
        ):
            parts.append(" ")
        parts.append(tok.text)
    return "".join(parts)


def _is_cfg_attr(attr_tokens: Sequence[Token]) -> bool:
    """Check if an attribute token list is a #[cfg(...)] attribute."""
    return (
        len(attr_tokens) >= 4
        and attr_tokens[0].text == "#"
        and attr_tokens[1].text == "["
        and attr_tokens[2].text == "cfg"
        and attr_tokens[3].text == "("
    )


@dataclass
class _Scope:
    name: str
    kind: str  # "fn" | "mod"
    cfgs: list[list[Token]]
    brace_depth: int


def scan_source(path: Path | str, source: str) -> tuple[Finding, ...]:
    """Discover all statics, thread-locals, and env::var reads in source text."""
    posix_path = (
        path.as_posix() if isinstance(path, (Path, PurePosixPath)) else str(path)
    )
    tokens = _tokenize(source)
    findings: list[Finding] = []

    scope_stack: list[_Scope] = []
    pending_attributes: list[list[Token]] = []

    pending_item_kind: str | None = None
    pending_item_name: str | None = None
    pending_item_cfgs: list[list[Token]] = []
    in_item_header: bool = False

    # Track thread_local! macro blocks and their attributes/cfgs
    thread_local_depths: list[int] = []
    thread_local_attrs: list[list[Token]] = []

    symbol_counts: dict[tuple[str, str], int] = {}
    brace_depth = 0
    paren_depth = 0
    bracket_depth = 0

    idx = 0
    num_tokens = len(tokens)

    while idx < num_tokens:
        tok = tokens[idx]

        # 1. Attributes: #[...] or #![...]
        if tok.text == "#":
            attr_start = idx
            idx += 1
            is_inner = False
            if idx < num_tokens and tokens[idx].text == "!":
                is_inner = True
                idx += 1
            if idx < num_tokens and tokens[idx].text == "[":
                attr_bracket = 1
                idx += 1
                while idx < num_tokens and attr_bracket > 0:
                    if tokens[idx].text == "[":
                        attr_bracket += 1
                    elif tokens[idx].text == "]":
                        attr_bracket -= 1
                    idx += 1
                attr_tokens = tokens[attr_start:idx]
                if is_inner and _is_cfg_attr(attr_tokens):
                    if scope_stack:
                        scope_stack[-1].cfgs.append(attr_tokens)
                elif not is_inner:
                    pending_attributes.append(attr_tokens)
                continue
            else:
                idx = attr_start + 1
                continue

        # 2. Track delimiters
        if tok.text == "{":
            brace_depth += 1
            if in_item_header and pending_item_name is not None and pending_item_kind is not None:
                scope_stack.append(
                    _Scope(
                        name=pending_item_name,
                        kind=pending_item_kind,
                        cfgs=pending_item_cfgs,
                        brace_depth=1,
                    )
                )
                pending_item_name = None
                pending_item_kind = None
                pending_item_cfgs = []
                in_item_header = False
            elif scope_stack:
                scope_stack[-1].brace_depth += 1
            pending_attributes = []
        elif tok.text == "}":
            brace_depth -= 1
            if scope_stack:
                scope_stack[-1].brace_depth -= 1
                if scope_stack[-1].brace_depth == 0:
                    scope_stack.pop()
            if thread_local_depths and brace_depth < thread_local_depths[-1]:
                thread_local_depths.pop()
                if thread_local_attrs:
                    thread_local_attrs.pop()
            pending_attributes = []
        elif tok.text == "(":
            paren_depth += 1
        elif tok.text == ")":
            paren_depth -= 1
        elif tok.text == "[":
            bracket_depth += 1
        elif tok.text == "]":
            bracket_depth -= 1
        elif tok.text == ";":
            if in_item_header and paren_depth == 0 and bracket_depth == 0:
                pending_item_name = None
                pending_item_kind = None
                pending_item_cfgs = []
                in_item_header = False
            if paren_depth == 0 and bracket_depth == 0:
                pending_attributes = []

        # 3. Track mod declarations for scope & enclosing cfg
        if tok.kind == "IDENT" and tok.text == "mod":
            if idx + 1 < num_tokens and tokens[idx + 1].kind == "IDENT":
                pending_item_kind = "mod"
                pending_item_name = tokens[idx + 1].text
                pending_item_cfgs = [
                    attr for attr in pending_attributes if _is_cfg_attr(attr)
                ]
                in_item_header = True
                pending_attributes = []

        # 4. Track fn declarations for scope & enclosing cfg
        if tok.kind == "IDENT" and tok.text == "fn":
            if idx + 1 < num_tokens and tokens[idx + 1].kind == "IDENT":
                pending_item_kind = "fn"
                pending_item_name = tokens[idx + 1].text
                pending_item_cfgs = [
                    attr for attr in pending_attributes if _is_cfg_attr(attr)
                ]
                in_item_header = True
                pending_attributes = []

        # 5. Track thread_local! macro invocations
        if (
            tok.kind == "IDENT"
            and tok.text == "thread_local"
            and idx + 1 < num_tokens
            and tokens[idx + 1].text == "!"
        ):
            macro_direct_attrs = list(pending_attributes)
            pending_attributes = []
            if idx + 2 < num_tokens and tokens[idx + 2].text == "{":
                thread_local_depths.append(brace_depth + 1)
                thread_local_attrs.append(
                    [tok for attr in macro_direct_attrs for tok in attr]
                )

        # 6. Check for std::env::var and std::env::var_os calls
        if (
            tok.kind == "IDENT"
            and tok.text == "std"
            and idx + 4 < num_tokens
            and tokens[idx + 1].text == "::"
            and tokens[idx + 2].kind == "IDENT"
            and tokens[idx + 2].text == "env"
            and tokens[idx + 3].text == "::"
            and tokens[idx + 4].kind == "IDENT"
            and tokens[idx + 4].text in ("var", "var_os")
            and idx + 5 < num_tokens
            and tokens[idx + 5].text == "("
        ):
            op_kind = (
                "env_var" if tokens[idx + 4].text == "var" else "env_var_os"
            )
            call_start = idx
            idx += 5  # at '('
            call_paren_depth = 1
            arg_tokens: list[Token] = []
            call_tokens: list[Token] = list(tokens[call_start : idx + 1])
            idx += 1

            while idx < num_tokens and call_paren_depth > 0:
                t = tokens[idx]
                call_tokens.append(t)
                if t.text == "(":
                    call_paren_depth += 1
                    arg_tokens.append(t)
                elif t.text == ")":
                    call_paren_depth -= 1
                    if call_paren_depth > 0:
                        arg_tokens.append(t)
                else:
                    arg_tokens.append(t)
                idx += 1

            arg_name = _format_env_arg(arg_tokens)
            if scope_stack:
                base_symbol = f"{'::'.join(s.name for s in scope_stack)}::{arg_name}"
            else:
                base_symbol = arg_name

            count = symbol_counts.get((op_kind, base_symbol), 0) + 1
            symbol_counts[(op_kind, base_symbol)] = count
            symbol = base_symbol if count == 1 else f"{base_symbol}#{count}"

            enclosing_cfg_tokens = [
                t for s in scope_stack for attr in s.cfgs for t in attr
            ]
            direct_stmt_attr_tokens = [
                t for attr in pending_attributes for t in attr
            ]
            fingerprint_tokens = (
                enclosing_cfg_tokens + direct_stmt_attr_tokens + call_tokens
            )
            fingerprint_text = " ".join(t.text for t in fingerprint_tokens)
            fingerprint = hashlib.sha256(
                fingerprint_text.encode("utf-8")
            ).hexdigest()
            findings.append(Finding(op_kind, posix_path, symbol, fingerprint))
            continue

        # 7. Check for static declarations
        if tok.kind == "IDENT" and tok.text == "static":
            next_idx = idx + 1
            if (
                next_idx < num_tokens
                and tokens[next_idx].kind == "IDENT"
                and tokens[next_idx].text == "mut"
            ):
                next_idx += 1

            if next_idx < num_tokens and tokens[next_idx].kind == "IDENT":
                static_name = tokens[next_idx].text
                colon_idx = next_idx + 1
                if colon_idx < num_tokens and tokens[colon_idx].text == ":":
                    start_static_idx = idx
                    cur_idx = colon_idx + 1
                    cur_brace = 0
                    cur_paren = 0
                    cur_bracket = 0
                    item_tokens: list[Token] = list(
                        tokens[start_static_idx:cur_idx]
                    )

                    while cur_idx < num_tokens:
                        t = tokens[cur_idx]
                        item_tokens.append(t)
                        if t.text == "{":
                            cur_brace += 1
                        elif t.text == "}":
                            cur_brace -= 1
                        elif t.text == "(":
                            cur_paren += 1
                        elif t.text == ")":
                            cur_paren -= 1
                        elif t.text == "[":
                            cur_bracket += 1
                        elif t.text == "]":
                            cur_bracket -= 1
                        elif (
                            t.text == ";"
                            and cur_brace == 0
                            and cur_paren == 0
                            and cur_bracket == 0
                        ):
                            cur_idx += 1
                            break
                        cur_idx += 1

                    is_thread_local = bool(thread_local_depths)
                    finding_kind = (
                        "thread_local" if is_thread_local else "static"
                    )

                    if scope_stack:
                        base_symbol = f"{'::'.join(s.name for s in scope_stack)}::{static_name}"
                    else:
                        base_symbol = static_name

                    count = symbol_counts.get((finding_kind, base_symbol), 0) + 1
                    symbol_counts[(finding_kind, base_symbol)] = count
                    symbol = base_symbol if count == 1 else f"{base_symbol}#{count}"

                    direct_attr_tokens = [
                        t for attr in pending_attributes for t in attr
                    ]
                    macro_attr_tokens = (
                        thread_local_attrs[-1] if is_thread_local and thread_local_attrs else []
                    )
                    enclosing_cfg_tokens = [
                        t for s in scope_stack for attr in s.cfgs for t in attr
                    ]

                    fingerprint_tokens = (
                        enclosing_cfg_tokens
                        + macro_attr_tokens
                        + direct_attr_tokens
                        + item_tokens
                    )
                    fingerprint_text = " ".join(t.text for t in fingerprint_tokens)
                    fingerprint = hashlib.sha256(
                        fingerprint_text.encode("utf-8")
                    ).hexdigest()
                    findings.append(
                        Finding(finding_kind, posix_path, symbol, fingerprint)
                    )
                    pending_attributes = []
                    idx = cur_idx
                    continue

        idx += 1

    return tuple(findings)


def discover(
    root: Path, scan_roots: Sequence[str] = DEFAULT_SCAN_ROOTS
) -> tuple[Finding, ...]:
    """Discover all findings across the configured crate roots."""
    all_findings: list[Finding] = []
    workspace_root = root.resolve()

    for rel_root in scan_roots:
        target_dir = workspace_root / rel_root
        if not target_dir.is_dir():
            continue
        for file_path in sorted(target_dir.rglob("*.rs")):
            if not file_path.is_file():
                continue
            rel_path = file_path.relative_to(workspace_root).as_posix()
            source = file_path.read_text(encoding="utf-8")
            findings = scan_source(rel_path, source)
            all_findings.extend(findings)

    return tuple(sorted(all_findings))


def load_ledger(path: Path) -> list[dict[str, Any]]:
    """Load and validate JSON ledger structure."""
    if not path.is_file():
        raise LedgerError(f"ledger file does not exist: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise LedgerError(f"malformed ledger JSON at {path}: {error}") from error

    if not isinstance(data, dict):
        raise LedgerError("ledger root must be a JSON object")
    if data.get("schema") != 1:
        raise LedgerError(f"unsupported ledger schema version: {data.get('schema')}")
    rows = data.get("rows")
    if not isinstance(rows, list):
        raise LedgerError("ledger 'rows' must be a list")

    return rows


def compare(
    actual: Sequence[Finding], reviewed: Sequence[dict[str, Any]]
) -> None:
    """Compare discovered findings against reviewed rows, failing on any drift or violations."""
    actual_keys: set[tuple[str, str, str]] = set()
    actual_map: dict[tuple[str, str, str], Finding] = {}
    for idx, f in enumerate(actual, 1):
        key = (f.kind, f.file, f.symbol)
        if key in actual_keys:
            raise LedgerError(
                f"duplicate discovered finding identity: kind={key[0]} file={key[1]} symbol={key[2]}"
            )
        actual_keys.add(key)
        actual_map[key] = f

    reviewed_keys: set[tuple[str, str, str]] = set()
    reviewed_map: dict[tuple[str, str, str], dict[str, Any]] = {}

    for idx, row in enumerate(reviewed, 1):
        if not isinstance(row, dict):
            raise LedgerError(f"reviewed row {idx} is not an object")
        for req_field in (
            "kind",
            "file",
            "symbol",
            "fingerprint",
            "classification",
            "rationale",
        ):
            if not row.get(req_field):
                raise LedgerError(
                    f"reviewed row {idx} missing required non-empty field {req_field!r}"
                )

        classification = row["classification"]
        if classification not in ALLOWED_CLASSIFICATIONS:
            raise LedgerError(
                f"reviewed row {idx} has invalid classification: {classification!r}"
            )

        if classification == "container_debt" and not row.get("destination"):
            raise LedgerError(
                f"reviewed row {idx} with classification 'container_debt' missing 'destination'"
            )

        key = (row["kind"], row["file"], row["symbol"])
        if key in reviewed_keys:
            raise LedgerError(
                f"duplicate reviewed row in ledger: kind={key[0]} file={key[1]} symbol={key[2]}"
            )
        reviewed_keys.add(key)
        reviewed_map[key] = row

    # Check additions
    additions = sorted(set(actual_map) - set(reviewed_map))
    if additions:
        details = [
            f"  + [{k}] {f} :: {s}"
            for k, f, s in additions
        ]
        raise LedgerError(
            f"new unreviewed global state findings ({len(additions)} additions):\n"
            + "\n".join(details)
        )

    # Check removals / stale entries
    removals = sorted(set(reviewed_map) - set(actual_map))
    if removals:
        details = [
            f"  - [{k}] {f} :: {s}"
            for k, f, s in removals
        ]
        raise LedgerError(
            f"stale reviewed global state entries ({len(removals)} removals):\n"
            + "\n".join(details)
        )

    # Check source fingerprint drift
    drifted: list[str] = []
    for key in sorted(actual_map):
        act = actual_map[key]
        rev = reviewed_map[key]
        if act.fingerprint != rev["fingerprint"]:
            drifted.append(
                f"  ~ [{key[0]}] {key[1]} :: {key[2]} "
                f"(expected fingerprint {rev['fingerprint'][:16]}..., actual {act.fingerprint[:16]}...)"
            )

    if drifted:
        raise LedgerError(
            f"source drift in global state findings ({len(drifted)} drifted):\n"
            + "\n".join(drifted)
        )


def _bootstrap(root: Path) -> int:
    """Discover findings from source and print initial unreviewed ledger JSON to stdout."""
    findings = discover(root)
    rows: list[dict[str, Any]] = []

    for f in findings:
        rows.append(
            {
                "kind": f.kind,
                "file": f.file,
                "symbol": f.symbol,
                "fingerprint": f.fingerprint,
                "classification": "unreviewed",
                "rationale": "UNREVIEWED: classify scope and state rationale.",
            }
        )

    ledger = {"schema": 1, "rows": rows}
    print(json.dumps(ledger, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Workspace root path",
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        default=LEDGER_PATH,
        help="Path to reviewed global state ledger",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--check",
        action="store_true",
        help="Check current source against reviewed global state ledger",
    )
    group.add_argument(
        "--bootstrap",
        action="store_true",
        help="Print discovered rows as JSON to stdout (does not write file)",
    )

    args = parser.parse_args(argv)

    if args.bootstrap:
        return _bootstrap(args.root)

    if args.check:
        try:
            findings = discover(args.root)
            reviewed = load_ledger(args.ledger)
            compare(findings, reviewed)
        except (LedgerError, OSError) as error:
            print(f"error: check-runtime-global-state: {error}", file=sys.stderr)
            return 1
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

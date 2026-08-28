#!/usr/bin/env python3

"""Token-aware scanner and validator for runtime std::process::abort() calls."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Sequence

SHARD_NAMES = ("runtime.json", "hvf.json", "vcpu-loop.json")


@dataclass(frozen=True)
class AbortFinding:
    file: str
    function: str
    ordinal_in_function: int
    fingerprint: str


class LedgerError(Exception):
    """Raised when ledger validation fails."""


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int
    pos: int


@dataclass
class Scope:
    kind: str  # "root", "mod", "impl", "trait", "fn", "block"
    name: str
    is_test: bool
    brace_depth: int
    fn_start_token_idx: int = 0
    body_brace_token_idx: int = 0
    is_if_then: bool = False


def lex_rust(source: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(source)
    line = 1

    while i < n:
        c = source[i]

        if c.isspace():
            if c == "\n":
                line += 1
            i += 1
            continue

        if c == "/" and i + 1 < n:
            if source[i + 1] == "/":
                i += 2
                while i < n and source[i] != "\n":
                    i += 1
                continue
            if source[i + 1] == "*":
                i += 2
                depth = 1
                while i < n and depth > 0:
                    if source[i] == "\n":
                        line += 1
                    if i + 1 < n and source[i : i + 2] == "/*":
                        depth += 1
                        i += 2
                    elif i + 1 < n and source[i : i + 2] == "*/":
                        depth -= 1
                        i += 2
                    else:
                        i += 1
                continue

        if c == "r" or (c in ("b", "c") and i + 1 < n and source[i + 1] == "r"):
            prefix_len = 1 if c == "r" else 2
            if i + prefix_len < n and (
                source[i + prefix_len] == "\"" or source[i + prefix_len] == "#"
            ):
                p = i + prefix_len
                num_hashes = 0
                while p < n and source[p] == "#":
                    num_hashes += 1
                    p += 1
                if p < n and source[p] == "\"":
                    p += 1
                    closing = "\"" + ("#" * num_hashes)
                    end_idx = source.find(closing, p)
                    if end_idx != -1:
                        end_pos = end_idx + len(closing)
                        raw_text = source[i:end_pos]
                        line += raw_text.count("\n")
                        tokens.append(Token("string", raw_text, line, i))
                        i = end_pos
                        continue

        if c == "\"" or (c in ("b", "c") and i + 1 < n and source[i + 1] == "\""):
            start_pos = i
            if c in ("b", "c"):
                i += 1
            i += 1
            while i < n:
                if source[i] == "\n":
                    line += 1
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == "\"":
                    i += 1
                    break
                i += 1
            raw_text = source[start_pos:i]
            tokens.append(Token("string", raw_text, line, start_pos))
            continue

        if c == "\x27" or (c == "b" and i + 1 < n and source[i + 1] == "\x27"):
            start_pos = i
            is_byte = c == "b"
            if is_byte:
                i += 1
            i += 1
            if i < n and source[i] == "\\":
                i += 1
                while i < n and source[i] != "\x27":
                    if source[i] == "\n":
                        line += 1
                    i += 1
                if i < n and source[i] == "\x27":
                    i += 1
                raw_text = source[start_pos:i]
                tokens.append(Token("char", raw_text, line, start_pos))
                continue
            if i < n and source[i] != "\x27" and i + 1 < n and source[i + 1] == "\x27":
                i += 2
                raw_text = source[start_pos:i]
                tokens.append(Token("char", raw_text, line, start_pos))
                continue
            if not is_byte and i < n and (source[i].isalpha() or source[i] == "_"):
                while i < n and (source[i].isalnum() or source[i] == "_"):
                    i += 1
                if i < n and source[i] == "\x27":
                    i += 1
                    tokens.append(Token("char", source[start_pos:i], line, start_pos))
                else:
                    tokens.append(Token("lifetime", source[start_pos:i], line, start_pos))
                continue
            tokens.append(Token("punct", source[start_pos:i], line, start_pos))
            continue

        if c.isdigit():
            start_pos = i
            while i < n and (source[i].isalnum() or source[i] in "._"):
                if source[i] == "." and i + 1 < n and (source[i + 1] == "." or source[i + 1].isalpha()):
                    break
                i += 1
            tokens.append(Token("number", source[start_pos:i], line, start_pos))
            continue

        if c.isalpha() or c == "_":
            start_pos = i
            while i < n and (source[i].isalnum() or source[i] == "_"):
                i += 1
            tokens.append(Token("ident", source[start_pos:i], line, start_pos))
            continue

        three = source[i : i + 3]
        if three in ("...", "..="):
            tokens.append(Token("punct", three, line, i))
            i += 3
            continue
        two = source[i : i + 2]
        if two in (
            "::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||",
            "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>", "..",
        ):
            tokens.append(Token("punct", two, line, i))
            i += 2
            continue

        tokens.append(Token("punct", c, line, i))
        i += 1

    return tokens


def cfg_possible_values(tokens: list[Token]) -> set[bool]:
    """Evaluate a cfg predicate with `test = false` and other atoms unknown."""

    def parse_expr(index: int) -> tuple[set[bool], int]:
        if index >= len(tokens) or tokens[index].kind != "ident":
            return {False, True}, index + 1

        name = tokens[index].text
        index += 1
        if index < len(tokens) and tokens[index].text == "=":
            return {False, True}, min(index + 2, len(tokens))
        if index >= len(tokens) or tokens[index].text != "(":
            return ({False} if name == "test" else {False, True}), index

        index += 1
        children: list[set[bool]] = []
        while index < len(tokens) and tokens[index].text != ")":
            child, index = parse_expr(index)
            children.append(child)
            if index < len(tokens) and tokens[index].text == ",":
                index += 1
            elif index < len(tokens) and tokens[index].text != ")":
                return {False, True}, index
        if index < len(tokens) and tokens[index].text == ")":
            index += 1

        if name == "all":
            can_be_true = all(True in child for child in children)
            can_be_false = any(False in child for child in children)
            values = ({True} if can_be_true else set()) | (
                {False} if can_be_false else set()
            )
            return values or {True}, index
        if name == "any":
            can_be_true = any(True in child for child in children)
            can_be_false = all(False in child for child in children)
            values = ({True} if can_be_true else set()) | (
                {False} if can_be_false else set()
            )
            return values or {False}, index
        if name == "not" and len(children) == 1:
            return {not value for value in children[0]}, index
        return {False, True}, index

    values, end = parse_expr(0)
    return values if end == len(tokens) else {False, True}


def is_test_only_attribute(tokens: list[Token]) -> bool:
    if len(tokens) == 1 and tokens[0].text == "test":
        return True
    if len(tokens) >= 3 and tokens[-1].text == "test" and tokens[-2].text == "::":
        return True
    if (
        len(tokens) >= 4
        and tokens[0].text == "cfg"
        and tokens[1].text == "("
        and tokens[-1].text == ")"
    ):
        return True not in cfg_possible_values(tokens[2:-1])
    if (
        len(tokens) >= 4
        and tokens[0].text == "cfg_attr"
        and tokens[1].text == "("
        and tokens[-1].text == ")"
    ):
        inner = tokens[2:-1]
        comma_idx = None
        paren_depth = 0
        bracket_depth = 0
        for idx, tok in enumerate(inner):
            if tok.text == "(":
                paren_depth += 1
            elif tok.text == ")":
                paren_depth -= 1
            elif tok.text == "[":
                bracket_depth += 1
            elif tok.text == "]":
                bracket_depth -= 1
            elif tok.text == "," and paren_depth == 0 and bracket_depth == 0:
                comma_idx = idx
                break
        if comma_idx is not None:
            pred_tokens = inner[:comma_idx]
            attr_tokens = inner[comma_idx + 1:]
            if cfg_possible_values(pred_tokens) == {True}:
                sub_attrs: list[list[Token]] = []
                curr: list[Token] = []
                p_d = 0
                b_d = 0
                for t in attr_tokens:
                    if t.text == "(":
                        p_d += 1
                        curr.append(t)
                    elif t.text == ")":
                        p_d -= 1
                        curr.append(t)
                    elif t.text == "[":
                        b_d += 1
                        curr.append(t)
                    elif t.text == "]":
                        b_d -= 1
                        curr.append(t)
                    elif t.text == "," and p_d == 0 and b_d == 0:
                        if curr:
                            sub_attrs.append(curr)
                            curr = []
                    else:
                        curr.append(t)
                if curr:
                    sub_attrs.append(curr)

                for sub_attr in sub_attrs:
                    if is_test_only_attribute(sub_attr):
                        return True
    return False


def normalize_type_tokens(tokens: list[Token]) -> str:
    parts: list[str] = []
    previous: Token | None = None
    word_kinds = {"ident", "lifetime", "number"}
    for token in tokens:
        if (
            previous is not None
            and previous.kind in word_kinds
            and token.kind in word_kinds
        ):
            parts.append(" ")
        parts.append(token.text)
        previous = token
    return "".join(parts).strip()


def angle_delta(token: Token) -> int:
    if token.text == "<":
        return 1
    if token.text == "<<":
        return 2
    if token.text == ">":
        return -1
    if token.text == ">>":
        return -2
    return 0


def matching_angle_close(tokens: list[Token], start_idx: int) -> int | None:
    depth = 0
    for idx in range(start_idx, len(tokens)):
        depth += angle_delta(tokens[idx])
        if depth <= 0:
            return idx
    return None


def looks_like_angle_open(tokens: list[Token], start_idx: int) -> bool:
    if angle_delta(tokens[start_idx]) <= 0:
        return False
    angle_depth = 0
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    for idx in range(start_idx, len(tokens)):
        token = tokens[idx]
        if (
            idx > start_idx
            and token.text in ("=>", ";")
            and paren_depth == 0
            and bracket_depth == 0
            and brace_depth == 0
        ):
            return False
        if token.text == "(":
            paren_depth += 1
        elif token.text == ")":
            if paren_depth == 0:
                return False
            paren_depth -= 1
        elif token.text == "[":
            bracket_depth += 1
        elif token.text == "]":
            if bracket_depth == 0:
                return False
            bracket_depth -= 1
        elif token.text == "{":
            brace_depth += 1
        elif token.text == "}":
            if brace_depth == 0:
                return False
            brace_depth -= 1
        elif brace_depth == 0:
            angle_depth += angle_delta(token)
            if angle_depth <= 0:
                return True
    return False


def extract_impl_name(tokens: list[Token], start_idx: int) -> str:
    i = start_idx + 1
    n = len(tokens)
    impl_toks: list[Token] = []
    angle_depth = 0
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    while i < n:
        token = tokens[i]
        if (
            token.text in ("{", "where")
            and angle_depth == 0
            and paren_depth == 0
            and bracket_depth == 0
            and brace_depth == 0
        ):
            break
        impl_toks.append(token)
        if token.text == "(":
            paren_depth += 1
        elif token.text == ")":
            paren_depth = max(0, paren_depth - 1)
        elif token.text == "[":
            bracket_depth += 1
        elif token.text == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif token.text == "{":
            brace_depth += 1
        elif token.text == "}":
            brace_depth = max(0, brace_depth - 1)
        elif brace_depth == 0:
            angle_depth = max(0, angle_depth + angle_delta(token))
        i += 1

    toks = impl_toks
    if toks and toks[0].text == "<":
        close_idx = matching_angle_close(toks, 0)
        if close_idx is not None and (
            close_idx + 1 >= len(toks) or toks[close_idx + 1].text != "::"
        ):
            toks = toks[close_idx + 1:]

    for_idx = None
    depth = 0
    brace_depth = 0
    paren_depth = 0
    bracket_depth = 0
    for idx, t in enumerate(toks):
        if t.text == "(":
            paren_depth += 1
        elif t.text == ")":
            paren_depth = max(0, paren_depth - 1)
        elif t.text == "[":
            bracket_depth += 1
        elif t.text == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif t.text == "{":
            brace_depth += 1
        elif t.text == "}":
            brace_depth = max(0, brace_depth - 1)
        elif brace_depth == 0:
            depth = max(0, depth + angle_delta(t))
        followed_by_hrtb_binder = False
        if idx + 1 < len(toks) and toks[idx + 1].text == "<":
            close_idx = matching_angle_close(toks, idx + 1)
            followed_by_hrtb_binder = close_idx is not None and (
                close_idx + 1 >= len(toks) or toks[close_idx + 1].text != "::"
            )
        if (
            t.text == "for"
            and depth == 0
            and brace_depth == 0
            and paren_depth == 0
            and bracket_depth == 0
            and not followed_by_hrtb_binder
            and for_idx is None
        ):
            for_idx = idx

    if for_idx is not None:
        trait_toks = toks[:for_idx]
        type_toks = toks[for_idx + 1:]
        trait_name = normalize_type_tokens(trait_toks)
        type_name = normalize_type_tokens(type_toks)
        return f"<{type_name} as {trait_name}>"
    return normalize_type_tokens(toks)


def normalize_context(tokens: list[Token]) -> str:
    parts: list[str] = []
    for t in tokens:
        if parts and (t.text.isalnum() or t.text == "_") and (parts[-1].isalnum() or parts[-1] == "_"):
            parts.append(" ")
        parts.append(t.text)
    return "".join(parts).strip()


def compute_fingerprint(context_tokens: list[Token]) -> str:
    norm = normalize_context(context_tokens)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def extract_statement_context(tokens: list[Token], abort_idx: int, fn_body_brace_idx: int) -> list[Token]:
    # Scan from fn_body_brace_idx + 1 to abort_idx to find the start of the enclosing statement at fn depth
    depth = 0
    stmt_start = fn_body_brace_idx + 1

    for idx in range(fn_body_brace_idx + 1, abort_idx):
        t = tokens[idx]
        if t.text == "{":
            depth += 1
        elif t.text == "}":
            depth -= 1
            if depth == 0:
                stmt_start = idx + 1
        elif t.text == ";" and depth == 0:
            stmt_start = idx + 1

    # Check for immediately preceding log statement at fn depth
    start = stmt_start
    if start > fn_body_brace_idx + 1:
        prev_idx = start - 1
        while prev_idx > fn_body_brace_idx and tokens[prev_idx].text in (";", "}"):
            prev_idx -= 1
        p_start = fn_body_brace_idx + 1
        p_depth = 0
        for idx in range(fn_body_brace_idx + 1, prev_idx + 1):
            if tokens[idx].text == "{":
                p_depth += 1
            elif tokens[idx].text == "}":
                p_depth -= 1
                if p_depth == 0:
                    p_start = idx + 1
            elif tokens[idx].text == ";" and p_depth == 0:
                p_start = idx + 1
        prev_stmt_text = "".join(t.text for t in tokens[p_start:start])
        if any(k in prev_stmt_text for k in ("tracing::", "eprintln!", "log::", "error!")):
            start = p_start

    # Scan forward from abort_idx to find the end of the enclosing statement at fn depth
    depth = 0
    for idx in range(fn_body_brace_idx + 1, abort_idx):
        if tokens[idx].text == "{":
            depth += 1
        elif tokens[idx].text == "}":
            depth -= 1

    end = abort_idx + 7
    while end < len(tokens):
        t = tokens[end]
        if t.text == "{":
            depth += 1
        elif t.text == "}":
            if depth == 0:
                break
            depth -= 1
            if depth == 0:
                end += 1
                break
        elif t.text == ";" and depth == 0:
            end += 1
            break
        end += 1

    return tokens[start:end]


def scan_abort_source(
    path: Path | str, source: str
) -> Sequence[AbortFinding]:
    posix_path = PurePosixPath(Path(path).as_posix()).as_posix()
    tokens = lex_rust(source)

    scopes: list[Scope] = [Scope("root", "<root>", False, 0, 0, 0)]
    pending_test = False
    pending_if = False
    pending_fn: str | None = None
    pending_fn_tok_idx: int = 0
    pending_fn_is_test = False
    pending_impl: str | None = None
    pending_impl_is_test = False
    pending_trait: str | None = None
    pending_trait_is_test = False
    pending_mod: str | None = None
    pending_mod_is_test = False
    pending_test_delimiters: tuple[int, int, int] | None = None
    pending_test_angle_depth = 0
    current_brace_depth = 0
    current_paren_depth = 0
    current_bracket_depth = 0
    declaration_angle_depth = 0
    declaration_paren_depth = 0
    declaration_bracket_depth = 0
    non_scope_brace_depth = 0

    findings: list[AbortFinding] = []
    fn_ordinals: dict[str, int] = {}

    i = 0
    n = len(tokens)

    while i < n:
        tok = tokens[i]

        if tok.text == "#" and i + 1 < n:
            is_inner = tokens[i + 1].text == "!"
            attr_start = i + (2 if is_inner else 1)
            if attr_start < n and tokens[attr_start].text == "[":
                depth = 1
                attr_idx = attr_start + 1
                attr_toks: list[Token] = []
                while attr_idx < n and depth > 0:
                    if tokens[attr_idx].text == "[":
                        depth += 1
                    elif tokens[attr_idx].text == "]":
                        depth -= 1
                    if depth > 0:
                        attr_toks.append(tokens[attr_idx])
                    attr_idx += 1

                is_test = is_test_only_attribute(attr_toks)
                if is_inner:
                    if is_test:
                        scopes[-1].is_test = True
                else:
                    if is_test:
                        pending_test = True
                        pending_test_delimiters = (
                            current_brace_depth,
                            current_paren_depth,
                            current_bracket_depth,
                        )
                        pending_test_angle_depth = 0
                i = attr_idx
                continue

        if (
            tok.kind == "ident"
            and declaration_paren_depth == 0
            and declaration_bracket_depth == 0
            and declaration_angle_depth == 0
            and non_scope_brace_depth == 0
        ):
            if tok.text == "if":
                pending_if = True
            elif tok.text == "fn" and pending_fn is None and i + 1 < n and tokens[i + 1].kind == "ident":
                pending_fn = tokens[i + 1].text
                pending_fn_tok_idx = i
                pending_fn_is_test = pending_test
                pending_test = False
                pending_test_delimiters = None
                pending_test_angle_depth = 0
                declaration_angle_depth = 0
                declaration_paren_depth = 0
                declaration_bracket_depth = 0
            elif tok.text == "impl" and pending_fn is None and scopes[-1].kind in ("root", "mod"):
                pending_impl = extract_impl_name(tokens, i)
                pending_impl_is_test = pending_test
                pending_test = False
                pending_test_delimiters = None
                pending_test_angle_depth = 0
                declaration_angle_depth = 0
                declaration_paren_depth = 0
                declaration_bracket_depth = 0
            elif tok.text == "trait" and pending_fn is None and scopes[-1].kind in ("root", "mod") and i + 1 < n and tokens[i + 1].kind == "ident":
                pending_trait = tokens[i + 1].text
                pending_trait_is_test = pending_test
                pending_test = False
                pending_test_delimiters = None
                pending_test_angle_depth = 0
                declaration_angle_depth = 0
                declaration_paren_depth = 0
                declaration_bracket_depth = 0
            elif tok.text == "mod" and pending_fn is None and scopes[-1].kind in ("root", "mod") and i + 1 < n and tokens[i + 1].kind == "ident":
                pending_mod = tokens[i + 1].text
                pending_mod_is_test = pending_test
                pending_test = False
                pending_test_delimiters = None
                pending_test_angle_depth = 0

        if tok.text == "}" and non_scope_brace_depth > 0:
            non_scope_brace_depth -= 1
            i += 1
            continue

        if non_scope_brace_depth > 0:
            if tok.text == "{":
                non_scope_brace_depth += 1
            i += 1
            continue

        if non_scope_brace_depth == 0:
            if tok.text == "(":
                current_paren_depth += 1
            elif tok.text == ")":
                current_paren_depth = max(0, current_paren_depth - 1)
                if pending_test_delimiters and pending_test_delimiters[1] > current_paren_depth:
                    pending_test = False
                    pending_test_delimiters = None
                    pending_test_angle_depth = 0
            elif tok.text == "[":
                current_bracket_depth += 1
            elif tok.text == "]":
                current_bracket_depth = max(0, current_bracket_depth - 1)
                if pending_test_delimiters and pending_test_delimiters[2] > current_bracket_depth:
                    pending_test = False
                    pending_test_delimiters = None
                    pending_test_angle_depth = 0

            if pending_fn is not None or pending_impl is not None or pending_trait is not None:
                if tok.text == "(":
                    declaration_paren_depth += 1
                elif tok.text == ")":
                    declaration_paren_depth = max(0, declaration_paren_depth - 1)
                elif tok.text == "[":
                    declaration_bracket_depth += 1
                elif tok.text == "]":
                    declaration_bracket_depth = max(0, declaration_bracket_depth - 1)
                else:
                    declaration_angle_depth = max(
                        0, declaration_angle_depth + angle_delta(tok)
                    )

            if pending_test:
                delta = angle_delta(tok)
                if pending_test_angle_depth > 0:
                    pending_test_angle_depth = max(
                        0, pending_test_angle_depth + delta
                    )
                elif delta > 0 and looks_like_angle_open(tokens, i):
                    pending_test_angle_depth = delta

        if tok.text == "{" and (
            declaration_angle_depth > 0
            or declaration_paren_depth > 0
            or declaration_bracket_depth > 0
            or pending_test_angle_depth > 0
        ):
            non_scope_brace_depth += 1
            i += 1
            continue

        if tok.text == ";" and (
            declaration_angle_depth == 0
            and declaration_paren_depth == 0
            and declaration_bracket_depth == 0
            and non_scope_brace_depth == 0
            and (
                pending_test_delimiters is None
                or (
                    current_paren_depth <= pending_test_delimiters[1]
                    and current_bracket_depth <= pending_test_delimiters[2]
                )
            )
        ):
            pending_test = False
            pending_test_delimiters = None
            pending_test_angle_depth = 0
            pending_fn = None
            pending_fn_is_test = False
            pending_impl = None
            pending_impl_is_test = False
            pending_trait = None
            pending_trait_is_test = False
            pending_mod = None
            pending_mod_is_test = False
            declaration_angle_depth = 0
            declaration_paren_depth = 0
            declaration_bracket_depth = 0
            i += 1
            continue

        if (
            tok.text == ","
            and pending_test
            and pending_test_angle_depth == 0
            and pending_test_delimiters
            == (current_brace_depth, current_paren_depth, current_bracket_depth)
        ):
            pending_test = False
            pending_test_delimiters = None
            pending_test_angle_depth = 0
            i += 1
            continue

        if tok.text == "{":
            current_brace_depth += 1
            if pending_fn:
                is_test_scope = pending_fn_is_test or any(s.is_test for s in scopes)
                scopes.append(Scope("fn", pending_fn, is_test_scope, current_brace_depth, pending_fn_tok_idx, i))
                pending_fn = None
                pending_fn_is_test = False
            elif pending_impl:
                is_test_scope = pending_impl_is_test or any(s.is_test for s in scopes)
                scopes.append(Scope("impl", pending_impl, is_test_scope, current_brace_depth))
                pending_impl = None
                pending_impl_is_test = False
            elif pending_trait:
                is_test_scope = pending_trait_is_test or any(s.is_test for s in scopes)
                scopes.append(Scope("trait", pending_trait, is_test_scope, current_brace_depth))
                pending_trait = None
                pending_trait_is_test = False
            elif pending_mod:
                is_test_scope = pending_mod_is_test or any(s.is_test for s in scopes)
                scopes.append(Scope("mod", pending_mod, is_test_scope, current_brace_depth))
                pending_mod = None
                pending_mod_is_test = False
            else:
                is_test_scope = pending_test or any(s.is_test for s in scopes)
                is_if_block = pending_if
                scopes.append(Scope("block", "", is_test_scope, current_brace_depth, is_if_then=is_if_block))
            pending_if = False
            pending_test = False
            pending_test_delimiters = None
            pending_test_angle_depth = 0
            declaration_angle_depth = 0
            declaration_paren_depth = 0
            declaration_bracket_depth = 0
            i += 1
            continue

        if tok.text == "}":
            is_test_branch = False
            if len(scopes) > 1 and scopes[-1].brace_depth == current_brace_depth:
                is_test_branch = scopes[-1].is_test and scopes[-1].is_if_then
                scopes.pop()
            current_brace_depth = max(0, current_brace_depth - 1)

            # If this was an if/else if test branch and next token is else, continue test scope
            if is_test_branch and i + 1 < n and tokens[i + 1].text == "else":
                pending_test = True
                pending_test_delimiters = (
                    current_brace_depth,
                    current_paren_depth,
                    current_bracket_depth,
                )
            else:
                pending_test = False
                pending_test_delimiters = None
            pending_test_angle_depth = 0
            i += 1
            continue

        if (
            tok.text == "std"
            and i + 6 < n
            and tokens[i + 1].text == "::"
            and tokens[i + 2].text == "process"
            and tokens[i + 3].text == "::"
            and tokens[i + 4].text == "abort"
            and tokens[i + 5].text == "("
            and tokens[i + 6].text == ")"
        ):
            is_in_test = pending_test or any(s.is_test for s in scopes)
            if not is_in_test:
                fn_name = "<module>"
                fn_body_brace_idx = 0
                for s in reversed(scopes):
                    if s.kind == "fn":
                        fn_name = s.name
                        fn_body_brace_idx = s.body_brace_token_idx
                        break

                container_parts = [
                    s.name for s in scopes if s.kind in ("mod", "impl", "trait")
                ]
                if container_parts:
                    qualified_fn = "::".join(container_parts + [fn_name])
                else:
                    qualified_fn = fn_name

                ord_val = fn_ordinals.get(qualified_fn, 0) + 1
                fn_ordinals[qualified_fn] = ord_val

                context_tokens = extract_statement_context(tokens, i, fn_body_brace_idx)
                fp = compute_fingerprint(context_tokens)

                findings.append(
                    AbortFinding(
                        file=posix_path,
                        function=qualified_fn,
                        ordinal_in_function=ord_val,
                        fingerprint=fp,
                    )
                )

            i += 7
            continue

        i += 1

    return tuple(findings)


def discover_runtime_aborts(root: Path) -> Sequence[AbortFinding]:
    findings: list[AbortFinding] = []
    search_dirs = [
        root / "crates/carrick-runtime/src",
        root / "crates/carrick-vmm-hvf/src",
    ]
    for d in search_dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.rs")):
            source = p.read_text(encoding="utf-8")
            rel = p.relative_to(root).as_posix()
            findings.extend(scan_abort_source(rel, source))
    return tuple(findings)


def route_shard(file_path: str) -> str:
    p = PurePosixPath(file_path)
    if "crates/carrick-runtime/src/vcpu_loop" in p.as_posix():
        return "vcpu-loop.json"
    if "crates/carrick-runtime/src" in p.as_posix():
        return "runtime.json"
    if "crates/carrick-vmm-hvf/src" in p.as_posix():
        return "hvf.json"
    raise LedgerError(f"unknown shard for file: {file_path}")


def load_shard(path: Path) -> dict:
    if not path.is_file():
        raise LedgerError(f"shard file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise LedgerError(f"malformed JSON in {path}: {e}") from e
    return data


def validate_shards(
    findings: Sequence[AbortFinding], ledgers: dict[str, dict]
) -> None:
    # Explicitly check for duplicate actual identities before constructing index
    seen_finding_keys: set[tuple[str, str, int]] = set()
    for f in findings:
        key = (f.file, f.function, f.ordinal_in_function)
        if key in seen_finding_keys:
            raise LedgerError(f"duplicate finding identity: {key}")
        seen_finding_keys.add(key)

    findings_by_shard: dict[str, list[AbortFinding]] = {s: [] for s in SHARD_NAMES}
    for f in findings:
        shard = route_shard(f.file)
        if shard not in findings_by_shard:
            raise LedgerError(f"invalid shard route {shard} for {f.file}")
        findings_by_shard[shard].append(f)

    for shard_name, shard_data in ledgers.items():
        if shard_name not in SHARD_NAMES:
            raise LedgerError(f"unknown shard name: {shard_name}")

        if shard_data.get("schema") != 1:
            raise LedgerError(f"{shard_name}: expected schema 1")
        if shard_data.get("shard") != shard_name:
            raise LedgerError(f"{shard_name}: mismatched shard field {shard_data.get('shard')}")

        rows = shard_data.get("rows")
        if not isinstance(rows, list):
            raise LedgerError(f"{shard_name}: rows must be a list")

        debt_ceiling = shard_data.get("typed_error_debt_ceiling")
        if not isinstance(debt_ceiling, int) or debt_ceiling < 0:
            raise LedgerError(f"{shard_name}: typed_error_debt_ceiling must be non-negative integer")

        # Validate rows
        seen_row_keys: set[tuple[str, str, int]] = set()
        debt_count = 0
        rows_by_key: dict[tuple[str, str, int], dict] = {}

        for row in rows:
            if not isinstance(row, dict):
                raise LedgerError(f"{shard_name}: row must be a dict")
            file_p = row.get("file")
            func = row.get("function")
            ord_val = row.get("ordinal_in_function")
            fp = row.get("fingerprint")
            verdict = row.get("verdict")
            rationale = row.get("rationale")
            failure_domain = row.get("failure_domain")
            typed_error = row.get("typed_error")

            if not file_p or not isinstance(file_p, str):
                raise LedgerError(f"{shard_name}: invalid file in row")
            if not func or not isinstance(func, str):
                raise LedgerError(f"{shard_name}: invalid function in row")
            if not isinstance(ord_val, int) or ord_val < 1:
                raise LedgerError(f"{shard_name}: invalid ordinal_in_function")
            if not fp or not isinstance(fp, str):
                raise LedgerError(f"{shard_name}: invalid fingerprint")

            if route_shard(file_p) != shard_name:
                raise LedgerError(f"{shard_name}: row {file_p} belongs in {route_shard(file_p)}")

            if verdict not in ("carrier_fault", "typed_error_debt"):
                raise LedgerError(f"{shard_name}: invalid verdict {verdict}")

            if not rationale or not isinstance(rationale, str) or not rationale.strip():
                raise LedgerError(f"{shard_name}: missing rationale for {file_p} {func} #{ord_val}")

            if not failure_domain or not isinstance(failure_domain, str) or not failure_domain.strip():
                raise LedgerError(f"{shard_name}: missing failure_domain for {file_p} {func} #{ord_val}")

            if verdict == "typed_error_debt":
                debt_count += 1
                if not typed_error or not isinstance(typed_error, str) or not typed_error.strip():
                    raise LedgerError(f"{shard_name}: typed_error_debt requires typed_error")
            elif typed_error is not None:
                raise LedgerError(f"{shard_name}: carrier_fault must not have typed_error")

            key = (file_p, func, ord_val)
            if key in seen_row_keys:
                raise LedgerError(f"{shard_name}: duplicate row for {key}")
            seen_row_keys.add(key)
            rows_by_key[key] = row

        if debt_count != debt_ceiling:
            raise LedgerError(
                f"{shard_name}: typed_error_debt_ceiling ({debt_ceiling}) does not match exact debt count ({debt_count})"
            )

        # Compare findings for this shard
        actual_findings = findings_by_shard[shard_name]
        actual_keys = {(f.file, f.function, f.ordinal_in_function) for f in actual_findings}

        missing = actual_keys - seen_row_keys
        if missing:
            raise LedgerError(f"{shard_name}: missing classifications for {len(missing)} calls: {sorted(missing)[:3]}")

        stale = seen_row_keys - actual_keys
        if stale:
            raise LedgerError(f"{shard_name}: stale rows present for {len(stale)} calls: {sorted(stale)[:3]}")

        # Check fingerprints match
        for f in actual_findings:
            key = (f.file, f.function, f.ordinal_in_function)
            row = rows_by_key[key]
            if row["fingerprint"] != f.fingerprint:
                raise LedgerError(
                    f"{shard_name}: fingerprint drift for {f.file} {f.function} #{f.ordinal_in_function}"
                )


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    shards_dir = root / "scripts/migrate/runtime-aborts"

    args = sys.argv[1:]
    check_shard: str | None = None
    if "--check-shard" in args:
        idx = args.index("--check-shard")
        if idx + 1 < len(args):
            check_shard = args[idx + 1]
            if not check_shard.endswith(".json"):
                check_shard += ".json"
        else:
            print("ERROR: --check-shard requires shard name", file=sys.stderr)
            return 2

    only_shard: str | None = None
    if "--only" in args:
        idx = args.index("--only")
        if idx + 1 < len(args):
            only_shard = args[idx + 1]
            if not only_shard.endswith(".json"):
                only_shard += ".json"
        else:
            print("ERROR: --only requires shard name", file=sys.stderr)
            return 2

    target_shard = check_shard or only_shard
    all_findings = discover_runtime_aborts(root)

    if target_shard and not ("--check" in args and only_shard):
        shard_path = shards_dir / target_shard
        if not shard_path.is_file():
            print(f"ERROR: Shard file {shard_path} does not exist", file=sys.stderr)
            return 1
        ledger = load_shard(shard_path)
        shard_findings = [f for f in all_findings if route_shard(f.file) == target_shard]
        try:
            validate_shards(shard_findings, {target_shard: ledger})
        except LedgerError as e:
            print(f"FAIL: {e}", file=sys.stderr)
            return 1
        cf_count = sum(1 for r in ledger["rows"] if r["verdict"] == "carrier_fault")
        td_count = sum(1 for r in ledger["rows"] if r["verdict"] == "typed_error_debt")
        print(f"OK: shard {target_shard} valid ({len(ledger['rows'])} aborts: {cf_count} carrier_fault, {td_count} typed_error_debt)")
        return 0

    # Validate all existing shards (or filtered by --only)
    ledgers: dict[str, dict] = {}
    pending_shards: list[str] = []
    shards_to_inspect = [only_shard] if only_shard else list(SHARD_NAMES)

    for s in shards_to_inspect:
        p = shards_dir / s
        if p.is_file():
            ledgers[s] = load_shard(p)
        else:
            pending_shards.append(s)

    if "--check" in args:
        if pending_shards:
            for p_shard in pending_shards:
                p_findings = [f for f in all_findings if route_shard(f.file) == p_shard]
                print(f"[pending] {p_shard}: {len(p_findings)} abort calls unclassified (pending Task 5)")

        if not ledgers:
            print("ERROR: No shards available to validate", file=sys.stderr)
            return 1

        active_findings = [f for f in all_findings if route_shard(f.file) in ledgers]
        try:
            validate_shards(active_findings, ledgers)
        except LedgerError as e:
            print(f"FAIL: {e}", file=sys.stderr)
            return 1

        for s, l in ledgers.items():
            cf = sum(1 for r in l["rows"] if r["verdict"] == "carrier_fault")
            td = sum(1 for r in l["rows"] if r["verdict"] == "typed_error_debt")
            print(f"OK: shard {s} valid ({len(l['rows'])} aborts: {cf} carrier_fault, {td} typed_error_debt)")
        return 0

    print("Usage: check-runtime-aborts.py [--check [--only <shard>] | --check-shard <shard>]")
    return 1


if __name__ == "__main__":
    sys.exit(main())

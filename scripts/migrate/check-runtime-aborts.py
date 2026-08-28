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
REQUIRED_SHARDS = frozenset(SHARD_NAMES)


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
    is_if_condition: bool = False
    restore_pending_test: bool = False
    restore_test_delimiters: tuple[int, int, int] | None = None
    restore_pending_if: bool = False
    restore_pending_if_is_let: bool = False
    restore_pending_if_let_has_equal: bool = False
    restore_pending_if_is_for: bool = False
    restore_pending_if_for_has_in: bool = False
    restore_pending_if_paren_depth: int = 0
    restore_pending_if_bracket_depth: int = 0
    restore_pending_if_expression_brace: bool = False
    is_macro_tokens: bool = False
    identity_salt: str = ""


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


def is_match_guard_if(tokens: list[Token], if_idx: int) -> bool:
    """Distinguish `pattern if guard =>` from an `if` expression."""

    paren_depth = 0
    bracket_depth = 0
    idx = if_idx + 1
    expression_prefix = {
        "if", "=", "&&", "||", "!", "+", "-", "*", "/", "%", "&", "|",
        "^", "<", ">", "<=", ">=", "==", "!=", "(", "[", ",", "=>",
        "unsafe", "const",
    }
    while idx < len(tokens):
        text = tokens[idx].text
        if text == "(":
            paren_depth += 1
        elif text == ")":
            paren_depth = max(0, paren_depth - 1)
        elif text == "[":
            bracket_depth += 1
        elif text == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif paren_depth == 0 and bracket_depth == 0:
            if text == "=>":
                return True
            if text in (";", ","):
                return False
            if text == "{":
                previous = tokens[idx - 1].text if idx > if_idx + 1 else "if"
                if previous not in expression_prefix:
                    return False
                depth = 1
                idx += 1
                while idx < len(tokens) and depth > 0:
                    if tokens[idx].text == "{":
                        depth += 1
                    elif tokens[idx].text == "}":
                        depth -= 1
                    idx += 1
                continue
        idx += 1
    return False


def matching_brace_index(tokens: list[Token], open_idx: int) -> int | None:
    depth = 0
    for idx in range(open_idx, len(tokens)):
        if tokens[idx].text == "{":
            depth += 1
        elif tokens[idx].text == "}":
            depth -= 1
            if depth == 0:
                return idx
    return None


def definition_identity(
    tokens: list[Token],
    name: str,
    start_idx: int,
    body_open_idx: int,
    scope_salts: Sequence[str] = (),
) -> str:
    close_idx = matching_brace_index(tokens, body_open_idx)
    if close_idx is None:
        return name
    definition = "|".join(scope_salts) + "|" + "".join(
        token.text for token in tokens[start_idx:close_idx + 1]
    )
    definition_id = hashlib.sha256(definition.encode("utf-8")).hexdigest()[:12]
    return f"{name}@{definition_id}"


def lexical_salt(tokens: list[Token], start_idx: int | None, end_idx: int) -> str:
    if start_idx is None:
        return ""
    text = "".join(token.text for token in tokens[start_idx:end_idx])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def is_cfg_match_pattern_brace(tokens: list[Token], open_idx: int) -> bool:
    """Whether an attributed brace belongs to a match pattern before `=>`."""

    close_idx = matching_brace_index(tokens, open_idx)
    if close_idx is None:
        return False
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    idx = close_idx + 1
    while idx < len(tokens):
        text = tokens[idx].text
        if text == "(":
            paren_depth += 1
        elif text == ")":
            paren_depth = max(0, paren_depth - 1)
        elif text == "[":
            bracket_depth += 1
        elif text == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif text == "{":
            brace_depth += 1
        elif text == "}":
            if brace_depth == 0:
                return False
            brace_depth -= 1
        elif paren_depth == 0 and bracket_depth == 0 and brace_depth == 0:
            if text == "=>":
                return True
            if text in (",", ";"):
                return False
        idx += 1
    return False


def scan_abort_source(
    path: Path | str, source: str
) -> Sequence[AbortFinding]:
    posix_path = PurePosixPath(Path(path).as_posix()).as_posix()
    tokens = lex_rust(source)

    scopes: list[Scope] = [Scope("root", "<root>", False, 0, 0, 0)]
    pending_test = False
    pending_if = False
    pending_if_is_let = False
    pending_if_let_has_equal = False
    pending_if_is_for = False
    pending_if_for_has_in = False
    pending_if_paren_depth = 0
    pending_if_bracket_depth = 0
    pending_if_expression_brace = False
    pending_fn: str | None = None
    pending_fn_tok_idx: int = 0
    pending_fn_is_test = False
    pending_impl: str | None = None
    pending_impl_tok_idx = 0
    pending_impl_is_test = False
    pending_trait: str | None = None
    pending_trait_tok_idx = 0
    pending_trait_is_test = False
    pending_mod: str | None = None
    pending_mod_tok_idx = 0
    pending_mod_is_test = False
    pending_item_start_idx: int | None = None
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
    fn_ordinals: dict[tuple[str, int], int] = {}
    finding_identities: set[AbortFinding] = set()

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
                    if pending_item_start_idx is None:
                        pending_item_start_idx = i
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
            if (
                tok.text in ("if", "while", "for")
                and not any((pending_fn, pending_impl, pending_trait, pending_mod))
                and (
                    i == 0
                    or (pending_test and i > 0 and tokens[i - 1].text == "]")
                    or tokens[i - 1].text in {
                        "{", "}", ";", "=", "=>", "(", "[", ",", "else",
                        "return", "break", "yield", "&&", "||", "!", "if",
                        ":",
                    }
                )
                and (tok.text != "if" or not is_match_guard_if(tokens, i))
            ):
                pending_item_start_idx = None
                pending_if = True
                pending_if_is_let = False
                pending_if_let_has_equal = False
                pending_if_is_for = tok.text == "for"
                pending_if_for_has_in = False
                pending_if_paren_depth = current_paren_depth
                pending_if_bracket_depth = current_bracket_depth
                pending_if_expression_brace = False
            elif pending_if and tok.text == "let":
                pending_if_is_let = True
                pending_if_let_has_equal = False
            elif (
                pending_if
                and pending_if_is_for
                and tok.text == "in"
                and current_paren_depth == pending_if_paren_depth
                and current_bracket_depth == pending_if_bracket_depth
            ):
                pending_if_for_has_in = True
            elif pending_if and tok.text in ("match", "async", "loop"):
                pending_if_expression_brace = True
            elif (
                current_paren_depth == 0
                and current_bracket_depth == 0
                and tok.text == "fn"
                and pending_fn is None
                and i + 1 < n
                and tokens[i + 1].kind == "ident"
            ):
                pending_fn = tokens[i + 1].text
                pending_fn_tok_idx = pending_item_start_idx if pending_item_start_idx is not None else i
                pending_fn_is_test = pending_test
                pending_item_start_idx = None
                pending_test = False
                pending_test_delimiters = None
                pending_test_angle_depth = 0
                declaration_angle_depth = 0
                declaration_paren_depth = 0
                declaration_bracket_depth = 0
            elif (
                current_paren_depth == 0
                and current_bracket_depth == 0
                and tok.text == "impl"
                and pending_fn is None
            ):
                pending_impl = extract_impl_name(tokens, i)
                pending_impl_tok_idx = pending_item_start_idx if pending_item_start_idx is not None else i
                pending_impl_is_test = pending_test
                pending_item_start_idx = None
                pending_test = False
                pending_test_delimiters = None
                pending_test_angle_depth = 0
                declaration_angle_depth = 0
                declaration_paren_depth = 0
                declaration_bracket_depth = 0
            elif (
                current_paren_depth == 0
                and current_bracket_depth == 0
                and tok.text == "trait"
                and pending_fn is None
                and i + 1 < n
                and tokens[i + 1].kind == "ident"
            ):
                pending_trait = tokens[i + 1].text
                pending_trait_tok_idx = pending_item_start_idx if pending_item_start_idx is not None else i
                pending_trait_is_test = pending_test
                pending_item_start_idx = None
                pending_test = False
                pending_test_delimiters = None
                pending_test_angle_depth = 0
                declaration_angle_depth = 0
                declaration_paren_depth = 0
                declaration_bracket_depth = 0
            elif (
                current_paren_depth == 0
                and current_bracket_depth == 0
                and tok.text == "mod"
                and pending_fn is None
                and i + 1 < n
                and tokens[i + 1].kind == "ident"
            ):
                pending_mod = tokens[i + 1].text
                pending_mod_tok_idx = pending_item_start_idx if pending_item_start_idx is not None else i
                pending_mod_is_test = pending_test
                pending_item_start_idx = None
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

        if (
            pending_if
            and pending_if_is_let
            and tok.text == "="
            and current_paren_depth == pending_if_paren_depth
            and current_bracket_depth == pending_if_bracket_depth
        ):
            pending_if_let_has_equal = True

        brace_starts_macro_tokens = (
            tok.text == "{"
            and i > 1
            and tokens[i - 1].text == "!"
            and tokens[i - 2].kind == "ident"
        )
        brace_is_macro_delimiter = brace_starts_macro_tokens and any(
            (pending_fn, pending_impl, pending_trait, pending_mod)
        )
        brace_is_cfg_match_pattern = (
            tok.text == "{"
            and pending_test
            and is_cfg_match_pattern_brace(tokens, i)
        )
        brace_is_if_condition_group = False
        if tok.text == "{" and pending_if:
            nested_delimiter = (
                current_paren_depth > pending_if_paren_depth
                or current_bracket_depth > pending_if_bracket_depth
            )
            pattern_before_equal = (
                (pending_if_is_let and not pending_if_let_has_equal)
                or (pending_if_is_for and not pending_if_for_has_in)
            )
            previous_requires_expression = i > 0 and tokens[i - 1].text in {
                "if", "=", "&&", "||", "!", "+", "-", "*", "/", "%",
                "&", "|", "^", "<", ">", "<=", ">=", "==", "!=", "(",
                "[", ",", "=>", "unsafe", "const", ":", "while", "for", "in",
                "..", "..=",
            }
            brace_is_if_condition_group = (
                any(scope.is_if_condition for scope in scopes)
                or brace_starts_macro_tokens
                or pending_if_expression_brace
                or nested_delimiter
                or pattern_before_equal
                or previous_requires_expression
            )

        if tok.text == "{" and brace_is_if_condition_group:
            is_macro_tokens = (
                brace_starts_macro_tokens
                or any(scope.is_macro_tokens for scope in scopes)
            )
            consume_expression_brace = (
                pending_if_expression_brace
                and not nested_delimiter
                and not pattern_before_equal
                and not brace_starts_macro_tokens
            )
            current_brace_depth += 1
            scopes.append(
                Scope(
                    "block",
                    "",
                    pending_test or any(scope.is_test for scope in scopes),
                    current_brace_depth,
                    is_if_condition=True,
                    restore_pending_test=pending_test,
                    restore_test_delimiters=pending_test_delimiters,
                    restore_pending_if=pending_if,
                    restore_pending_if_is_let=pending_if_is_let,
                    restore_pending_if_let_has_equal=pending_if_let_has_equal,
                    restore_pending_if_is_for=pending_if_is_for,
                    restore_pending_if_for_has_in=pending_if_for_has_in,
                    restore_pending_if_paren_depth=pending_if_paren_depth,
                    restore_pending_if_bracket_depth=pending_if_bracket_depth,
                    restore_pending_if_expression_brace=(
                        False if consume_expression_brace else pending_if_expression_brace
                    ),
                    is_macro_tokens=is_macro_tokens,
                )
            )
            pending_test = False
            pending_test_delimiters = None
            pending_test_angle_depth = 0
            i += 1
            continue

        if tok.text == "{" and brace_starts_macro_tokens and not brace_is_macro_delimiter:
            macro_identity_salt = lexical_salt(tokens, pending_item_start_idx, i)
            pending_item_start_idx = None
            current_brace_depth += 1
            scopes.append(
                Scope(
                    "block",
                    "",
                    pending_test or any(scope.is_test for scope in scopes),
                    current_brace_depth,
                    is_macro_tokens=True,
                    identity_salt=macro_identity_salt,
                )
            )
            pending_test = False
            pending_test_delimiters = None
            pending_test_angle_depth = 0
            i += 1
            continue

        if tok.text == "{" and (
            declaration_angle_depth > 0
            or declaration_paren_depth > 0
            or declaration_bracket_depth > 0
            or pending_test_angle_depth > 0
            or brace_is_macro_delimiter
            or brace_is_cfg_match_pattern
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
            pending_item_start_idx = None
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
            pending_if = False
            pending_if_is_let = False
            pending_if_let_has_equal = False
            pending_if_is_for = False
            pending_if_for_has_in = False
            pending_if_expression_brace = False
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
            pending_item_start_idx = None
            pending_test = False
            pending_test_delimiters = None
            pending_test_angle_depth = 0
            i += 1
            continue

        if tok.text == "{":
            scope_salts = tuple(
                scope.identity_salt for scope in scopes if scope.identity_salt
            )
            block_identity_salt = ""
            if not any((pending_fn, pending_impl, pending_trait, pending_mod)):
                block_identity_salt = lexical_salt(tokens, pending_item_start_idx, i)
            pending_item_start_idx = None
            current_brace_depth += 1
            if pending_fn:
                is_test_scope = pending_fn_is_test or any(s.is_test for s in scopes)
                function_name = pending_fn
                outer_fn_indices = [
                    scope_idx for scope_idx, scope in enumerate(scopes) if scope.kind == "fn"
                ]
                if outer_fn_indices:
                    outer_fn_idx = outer_fn_indices[-1]
                    has_named_item_container = any(
                        scope.kind in ("impl", "trait", "mod")
                        for scope in scopes[outer_fn_idx + 1:]
                    )
                    if not has_named_item_container or scope_salts:
                        function_name = definition_identity(
                            tokens,
                            pending_fn,
                            pending_fn_tok_idx,
                            i,
                            scope_salts,
                        )
                scopes.append(Scope("fn", function_name, is_test_scope, current_brace_depth, pending_fn_tok_idx, i))
                pending_fn = None
                pending_fn_is_test = False
            elif pending_impl:
                is_test_scope = pending_impl_is_test or any(s.is_test for s in scopes)
                impl_name = pending_impl
                if any(scope.kind == "fn" for scope in scopes) or scope_salts:
                    impl_name = definition_identity(
                        tokens, pending_impl, pending_impl_tok_idx, i, scope_salts
                    )
                scopes.append(Scope("impl", impl_name, is_test_scope, current_brace_depth))
                pending_impl = None
                pending_impl_is_test = False
            elif pending_trait:
                is_test_scope = pending_trait_is_test or any(s.is_test for s in scopes)
                trait_name = pending_trait
                if any(scope.kind == "fn" for scope in scopes) or scope_salts:
                    trait_name = definition_identity(
                        tokens, pending_trait, pending_trait_tok_idx, i, scope_salts
                    )
                scopes.append(Scope("trait", trait_name, is_test_scope, current_brace_depth))
                pending_trait = None
                pending_trait_is_test = False
            elif pending_mod:
                is_test_scope = pending_mod_is_test or any(s.is_test for s in scopes)
                mod_name = pending_mod
                if any(scope.kind == "fn" for scope in scopes) or scope_salts:
                    mod_name = definition_identity(
                        tokens, pending_mod, pending_mod_tok_idx, i, scope_salts
                    )
                scopes.append(Scope("mod", mod_name, is_test_scope, current_brace_depth))
                pending_mod = None
                pending_mod_is_test = False
            else:
                is_test_scope = pending_test or any(s.is_test for s in scopes)
                is_if_block = pending_if
                scopes.append(
                    Scope(
                        "block",
                        "",
                        is_test_scope,
                        current_brace_depth,
                        is_if_then=is_if_block,
                        identity_salt=block_identity_salt,
                    )
                )
            pending_if = False
            pending_if_is_let = False
            pending_if_let_has_equal = False
            pending_if_is_for = False
            pending_if_for_has_in = False
            pending_if_expression_brace = False
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
            closed_if_condition = False
            closed_macro_tokens = False
            restore_pending_test = False
            restore_test_delimiters: tuple[int, int, int] | None = None
            restore_pending_if = False
            restore_pending_if_is_let = False
            restore_pending_if_let_has_equal = False
            restore_pending_if_is_for = False
            restore_pending_if_for_has_in = False
            restore_pending_if_paren_depth = 0
            restore_pending_if_bracket_depth = 0
            restore_pending_if_expression_brace = False
            if len(scopes) > 1 and scopes[-1].brace_depth == current_brace_depth:
                is_test_branch = scopes[-1].is_test and scopes[-1].is_if_then
                closed_if_condition = scopes[-1].is_if_condition
                closed_macro_tokens = scopes[-1].is_macro_tokens
                restore_pending_test = scopes[-1].restore_pending_test
                restore_test_delimiters = scopes[-1].restore_test_delimiters
                restore_pending_if = scopes[-1].restore_pending_if
                restore_pending_if_is_let = scopes[-1].restore_pending_if_is_let
                restore_pending_if_let_has_equal = scopes[-1].restore_pending_if_let_has_equal
                restore_pending_if_is_for = scopes[-1].restore_pending_if_is_for
                restore_pending_if_for_has_in = scopes[-1].restore_pending_if_for_has_in
                restore_pending_if_paren_depth = scopes[-1].restore_pending_if_paren_depth
                restore_pending_if_bracket_depth = scopes[-1].restore_pending_if_bracket_depth
                restore_pending_if_expression_brace = scopes[-1].restore_pending_if_expression_brace
                scopes.pop()
            current_brace_depth = max(0, current_brace_depth - 1)

            # Curly macro arguments are ambiguous before expansion: some are
            # item-generating token lists (`define_syscall! { fn ... }`), while
            # others merely contain tokens that resemble an incomplete item
            # (`discard! { fn fake }`). Parse complete item bodies so generated
            # source retains its lexical identity, but never let an unfinished
            # declaration escape the macro argument and capture the following
            # production block.
            if closed_macro_tokens:
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

            if closed_if_condition:
                pending_test = restore_pending_test
                pending_test_delimiters = restore_test_delimiters
                pending_test_angle_depth = 0
                pending_if = restore_pending_if
                pending_if_is_let = restore_pending_if_is_let
                pending_if_let_has_equal = restore_pending_if_let_has_equal
                pending_if_is_for = restore_pending_if_is_for
                pending_if_for_has_in = restore_pending_if_for_has_in
                pending_if_paren_depth = restore_pending_if_paren_depth
                pending_if_bracket_depth = restore_pending_if_bracket_depth
                pending_if_expression_brace = restore_pending_if_expression_brace
                i += 1
                continue

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
                fn_scope_idx: int | None = None
                for scope_idx in range(len(scopes) - 1, -1, -1):
                    s = scopes[scope_idx]
                    if s.kind == "fn":
                        fn_name = s.name
                        fn_body_brace_idx = s.body_brace_token_idx
                        fn_scope_idx = scope_idx
                        break

                container_parts = [
                    s.name
                    for scope_idx, s in enumerate(scopes)
                    if s.kind in ("mod", "impl", "trait")
                    or (s.kind == "fn" and fn_scope_idx is not None and scope_idx < fn_scope_idx)
                ]
                if container_parts:
                    qualified_fn = "::".join(container_parts + [fn_name])
                else:
                    qualified_fn = fn_name

                ordinal_key = (qualified_fn, fn_body_brace_idx)
                ord_val = fn_ordinals.get(ordinal_key, 0) + 1
                fn_ordinals[ordinal_key] = ord_val

                context_tokens = extract_statement_context(tokens, i, fn_body_brace_idx)
                fp = compute_fingerprint(context_tokens)

                finding = AbortFinding(
                    file=posix_path,
                    function=qualified_fn,
                    ordinal_in_function=ord_val,
                    fingerprint=fp,
                )
                if finding in finding_identities:
                    raise LedgerError(
                        f"{posix_path}: ambiguous duplicate abort identity in "
                        f"{qualified_fn}; add distinguishing lexical structure"
                    )
                finding_identities.add(finding)
                findings.append(finding)

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


def validate_required_shards(ledgers: dict[str, dict]) -> None:
    actual = set(ledgers)
    if actual != REQUIRED_SHARDS:
        missing = sorted(REQUIRED_SHARDS - actual)
        unexpected = sorted(actual - REQUIRED_SHARDS)
        raise LedgerError(
            f"required abort shards mismatch: missing={missing}, "
            f"unexpected={unexpected}"
        )


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

    # Validate the exact required shard set, or one explicitly focused shard.
    ledgers: dict[str, dict] = {}
    shards_to_inspect = [only_shard] if only_shard else list(SHARD_NAMES)

    for s in shards_to_inspect:
        p = shards_dir / s
        if not p.is_file():
            print(f"FAIL: required shard file not found: {p}", file=sys.stderr)
            return 1
        ledgers[s] = load_shard(p)

    if "--check" in args:
        active_findings = [f for f in all_findings if route_shard(f.file) in ledgers]
        try:
            if only_shard is None:
                validate_required_shards(ledgers)
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

#!/usr/bin/env python3

"""Token-aware scanner and validator for runtime std::process::abort() calls."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Sequence

EXCLUDED_CRATE_PREFIXES = (
    "crates/carrick-conformance",
    "crates/carrick-fatal",  # the sink itself: the one legitimate raw abort
    "crates/carrick-dsr",
    "crates/carrick-native-darwin",
)


@dataclass(frozen=True)
class AbortFinding:
    file: str
    function: str
    ordinal_in_function: int
    fingerprint: str
    sink: str = "raw"
    domain: str | None = None
    line: int = field(default=0, compare=False)
    column: int = field(default=0, compare=False)


class LedgerError(Exception):
    """Raised when production termination violates the boundary."""


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int
    pos: int


def opaque_macro_inputs(tokens: Sequence[Token]) -> list[bool]:
    """Attributes inside arbitrary macro inputs cannot establish test scope."""
    opaque: list[bool] = []
    delimiters: list[bool] = []
    for index, token in enumerate(tokens):
        inherited = bool(delimiters and delimiters[-1])
        if token.text in {"(", "[", "{"}:
            invocation = (
                index >= 2
                and tokens[index - 1].text == "!"
                and tokens[index - 2].kind.lower() == "ident"
            )
            definition = (
                index >= 3
                and tokens[index - 2].text == "!"
                and tokens[index - 3].text == "macro_rules"
            )
            inherited = inherited or invocation or definition
            delimiters.append(inherited)
        opaque.append(inherited)
        if token.text in {")", "]", "}"} and delimiters:
            delimiters.pop()
    return opaque


def validate_test_dialect(tokens: Sequence[Token], path: str) -> None:
    """Only built-in attributes outside opaque inputs establish test scope.

    A cfg(test) ancestor proves exclusion independently of imports in its
    discarded body. Attribute names alone never establish that proof.
    """
    tokens = [Token(t.kind.lower(), t.text, getattr(t, "line", 0), t.pos) for t in tokens]
    opaque = opaque_macro_inputs(tokens)
    proof = [False] * len(tokens)
    attrs = []
    scopes = [False]
    pending = False
    i = 0
    while i < len(tokens):
        proof[i] = scopes[-1]
        if tokens[i].text == "#":
            start = i + 1
            inner = start < len(tokens) and tokens[start].text == "!"
            start += int(inner)
            if start < len(tokens) and tokens[start].text == "[":
                end = start + 1
                depth = 1
                while end < len(tokens) and depth:
                    depth += (tokens[end].text == "[") - (tokens[end].text == "]")
                    end += 1
                if depth:
                    raise LedgerError(f"{path}: restricted census dialect: unresolved attribute")
                attr = tokens[start + 1:end - 1]
                attrs.append((i, attr, scopes[-1] or pending))
                cfg_proof = (attr and attr[0].text == "cfg" and
                             is_test_only_attribute(attr) and not opaque[i])
                if inner and cfg_proof:
                    scopes[-1] = True
                elif cfg_proof:
                    pending = True
                for j in range(i, end):
                    proof[j] = scopes[-1]
                i = end
                continue
        if tokens[i].text == "{":
            scopes.append(scopes[-1] or pending)
            pending = False
        elif tokens[i].text == "}" and len(scopes) > 1:
            scopes.pop()
        elif tokens[i].text == ";":
            pending = False
        i += 1
    globs = []
    for i, token in enumerate(tokens):
        if token.text != "use" or proof[i]:
            continue
        end = i + 1
        while end < len(tokens) and tokens[end].text != ";":
            end += 1
        imported = tokens[i + 1:end]
        if any(t.text == "*" for t in imported):
            globs.append(i)
        for j, t in enumerate(imported):
            if t.text == "test" and (j + 1 == len(imported) or imported[j + 1].text != "::"):
                raise LedgerError(f"{path}:{getattr(t, 'line', 0)}: restricted census dialect: import may rebind built-in test")
    for i, attr, proven in attrs:
        if proven or not attr:
            continue
        texts = [t.text for t in attr]
        head = texts[:texts.index("(")] if "(" in texts else texts
        if head[-1:] == ["test"]:
            if head != ["test"]:
                raise LedgerError(f"{path}:{getattr(tokens[i], 'line', 0)}: restricted census dialect: qualified test attribute is unsupported")
            if globs:
                raise LedgerError(f"{path}:{getattr(tokens[i], 'line', 0)}: restricted census dialect: glob import makes test exclusion ambiguous")
        if texts[0] == "cfg_attr":
            # Skip the predicate and examine the selected attributes only.
            depth = 0
            comma = None
            for j, text in enumerate(texts[2:-1], 2):
                depth += (text == "(") - (text == ")")
                if text == "," and depth == 0:
                    comma = j
                    break
            if comma is None:
                raise LedgerError(f"{path}: restricted census dialect: unresolved conditional attribute")
            if "test" in texts[comma + 1:]:
                raise LedgerError(f"{path}:{getattr(tokens[i], 'line', 0)}: restricted census dialect: conditional test attribute is unsupported")
        if opaque[i] and is_test_only_attribute(attr):
            raise LedgerError(f"{path}:{getattr(tokens[i], 'line', 0)}: restricted census dialect: test exclusion in macro input is unsupported")


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

        # Raw identifiers name the same operation as their ordinary spelling.
        if source.startswith("r#", i) and i + 2 < n and (source[i + 2].isalpha() or source[i + 2] == "_"):
            start_pos = i
            i += 2
            while i < n and (source[i].isalnum() or source[i] == "_"):
                i += 1
            tokens.append(Token("ident", source[start_pos + 2:i], line, start_pos))
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
            # `feature = "test-support"` is test scope, exactly like `test`.
            # Splitting the runtime into carrick-kernel + carrick-runtime moved
            # test fixtures out of the crate whose tests consume them, and
            # `cfg(test)` is per-crate-compilation, so those fixtures are gated
            # `cfg(any(test, feature = "test-support"))`. No product target
            # enables `test-support`, so the gate still means "test code" in
            # every shipped build. Matching the exact feature NAME keeps this
            # narrow: every other `feature = "..."` stays unknown, which is
            # what makes a debug-feature abort still inventoried.
            value = (
                tokens[index + 1].text if index + 1 < len(tokens) else ""
            )
            if name == "feature" and value == '"test-support"':
                return {False}, min(index + 2, len(tokens))
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
    if (
        len(tokens) >= 4
        and tokens[0].text == "cfg"
        and tokens[1].text == "("
        and tokens[-1].text == ")"
    ):
        return True not in cfg_possible_values(tokens[2:-1])
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


def parse_string_literal(text: str) -> str:
    if text.startswith("r"):
        p = 1
        num_hashes = 0
        while p < len(text) and text[p] == "#":
            num_hashes += 1
            p += 1
        if p < len(text) and text[p] == '"':
            p += 1
            end = len(text) - 1 - num_hashes
            return text[p:end]
    elif text.startswith('"') and text.endswith('"') and len(text) >= 2:
        import ast
        try:
            val = ast.literal_eval(text)
            if isinstance(val, str):
                return val
        except Exception:
            return text[1:-1]
    return text


def extract_statement_context(
    tokens: list[Token],
    abort_idx: int,
    fn_body_brace_idx: int,
    site_end_idx: int | None = None,
) -> list[Token]:
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

    end = site_end_idx if site_end_idx is not None else abort_idx + 7
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
    validate_test_dialect(tokens, posix_path)
    opaque = opaque_macro_inputs(tokens)

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

                is_test = not opaque[i] and is_test_only_attribute(attr_toks)
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

        is_raw_abort = (
            tok.text == "std"
            and i + 6 < n
            and tokens[i + 1].text == "::"
            and tokens[i + 2].text == "process"
            and tokens[i + 3].text == "::"
            and tokens[i + 4].text == "abort"
            and tokens[i + 5].text == "("
            and tokens[i + 6].text == ")"
        )
        is_carrick_fatal = (
            tok.text == "carrick_fatal"
            and i + 1 < n
            and tokens[i + 1].text == "!"
            and i + 2 < n
            and tokens[i + 2].text in ("(", "[", "{")
        )

        site_sink: str | None = None
        site_domain: str | None = None
        site_end_idx: int | None = None
        next_i: int | None = None

        if is_raw_abort:
            site_sink = "raw"
            site_domain = None
            site_end_idx = i + 7
            next_i = i + 7
        elif is_carrick_fatal:
            open_idx = i + 2
            open_delim = tokens[open_idx].text
            close_delim = {"(": ")", "[": "]", "{": "}"}[open_delim]
            if open_idx + 1 >= n:
                raise LedgerError(f"{posix_path}: empty carrick_fatal! invocation")
            first_arg_tok = tokens[open_idx + 1]
            if first_arg_tok.kind != "string":
                raise LedgerError(f"{posix_path}: carrick_fatal! domain must be a string literal")
            domain_str = parse_string_literal(first_arg_tok.text)

            depth = 1
            k = open_idx + 1
            while k < n and depth > 0:
                if tokens[k].text == open_delim:
                    depth += 1
                elif tokens[k].text == close_delim:
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            if depth != 0:
                raise LedgerError(f"{posix_path}: unclosed carrick_fatal! macro invocation")
            macro_close_idx = k
            site_sink = "fatal"
            site_domain = domain_str
            site_end_idx = macro_close_idx + 1
            next_i = macro_close_idx + 1

        if site_sink is not None and next_i is not None:
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

                context_tokens = extract_statement_context(tokens, i, fn_body_brace_idx, site_end_idx)
                fp = compute_fingerprint(context_tokens)

                finding = AbortFinding(
                    file=posix_path,
                    function=qualified_fn,
                    ordinal_in_function=ord_val,
                    fingerprint=fp,
                    sink=site_sink,
                    domain=site_domain,
                    line=tokens[i].line,
                    column=tokens[i].pos - source.rfind("\n", 0, tokens[i].pos) - 1,
                )
                if finding in finding_identities:
                    raise LedgerError(
                        f"{posix_path}: ambiguous duplicate abort identity in "
                        f"{qualified_fn}; add distinguishing lexical structure"
                    )
                finding_identities.add(finding)
                findings.append(finding)

            i = next_i
            continue

        i += 1

    return tuple(findings)


def discover_runtime_aborts(root: Path, *, test_files: Sequence[str] = ()) -> Sequence[AbortFinding]:
    findings: list[AbortFinding] = []
    crates_dir = root / "crates"
    # The strict Rust census rejects production references outside */src.
    # Integration-test targets and build scripts are not product source inputs.
    for p in sorted(crates_dir.glob("*/src/**/*.rs")):
        rel = p.relative_to(root).as_posix()
        if rel in test_files or any(rel.startswith(ex) for ex in EXCLUDED_CRATE_PREFIXES):
            continue
        source = p.read_text(encoding="utf-8")
        findings.extend(scan_abort_source(rel, source))
    return tuple(findings)


def route_shard(file_path: str) -> str:
    p = PurePosixPath(file_path)
    posix_str = p.as_posix()
    if any(posix_str.startswith(ex) for ex in EXCLUDED_CRATE_PREFIXES):
        raise LedgerError(f"file is in excluded crate: {file_path}")
    if "crates/carrick-runtime/src/vcpu_loop" in posix_str:
        return "vcpu-loop.json"
    # The kernel graph, dispatch and the in-zone subsystems moved to
    # crates/carrick-kernel (plan
    # 2026-09-13-extract-carrick-vfs-and-carrick-kernel). Their reviewed abort
    # rows stay in the shard that already holds them: the shards partition a
    # review ledger, and re-sharding every row would turn a pure code move into
    # an unreviewable rewrite of `runtime.json` and `other.json`.
    if "crates/carrick-kernel/src" in posix_str:
        return "runtime.json"
    if "crates/carrick-runtime/src" in posix_str:
        return "runtime.json"
    if "crates/carrick-vmm-hvf/src" in posix_str:
        return "hvf.json"
    if posix_str.startswith("crates/"):
        return "other.json"
    raise LedgerError(f"unknown shard for file: {file_path}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Discover fatal symbols and unconditionally deny raw termination")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--discover", action="store_true")
    args = parser.parse_args()
    findings = discover_runtime_aborts(args.root)
    raw = [f for f in findings if f.sink == "raw"]
    if raw:
        print(f"raw termination forbidden: {raw[0].file}::{raw[0].function}", file=sys.stderr)
        return 1
    print(json.dumps([{"file": f.file, "function": f.function, "domain": f.domain, "line": f.line, "column": f.column} for f in findings]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

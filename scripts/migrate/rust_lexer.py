"""Shared lexical engine for the three authority discovery checkers.

These are checker dialects, not a Rust parser. Keep their historical literal,
number and punctuation boundaries (including malformed input) unchanged.
"""

import re

# The common path consumes whole runs in C rather than visiting each character
# in Python. Nested comments and hash-delimited strings need a bounded detour.
_MASTER = re.compile(
    r'(?P<space>\s+)|(?P<comment>//[^\n]*|/\*)'
    r'|(?P<raw>(?:br|cr|r)\#*")'
    r'|(?P<string>[bc]?"(?:[^"\\]|\\[\s\S])*?(?:"|\\?\Z))'
    r"|(?P<quote>b?')"
    r'|(?P<word>\w+)|(?P<punct>[^\w\s])'
)
_WORD = re.compile(r'\w*')
_NUMBER = re.compile(r'(?:\w|\.(?!\.))*')
_ABORT_NUMBER = re.compile(r'(?:\w|\.(?!\.|[^\W\d_]))*')
_COMMENT_EDGE = re.compile(r'/\*|\*/')
_ESCAPES = re.compile(r'\\[\s\S]')
_QUOTED_CHAR = re.compile(r"(?:[^'\\]|\\[\s\S])*(?:'|\\?\Z)")
_ESCAPE_CHAR = re.compile(r"[^']*(?:'|\Z)")
_GLOBAL_PUNCT = frozenset(':: -> => == != <= >= += -= *= /= && || << >> ..'.split())
_DISPATCH_PUNCT = frozenset(':: -> => == != <= >= && || .. += -='.split())
_ABORT_PUNCT = _GLOBAL_PUNCT | frozenset('%= &= |= ^='.split())


def lex(source, dialect):
    """Yield (kind, text, line, position) in the requested historical dialect."""
    global_state = dialect == 'global'
    aborts = dialect == 'aborts'
    punctuation = (_GLOBAL_PUNCT if global_state else
                   _ABORT_PUNCT if aborts else _DISPATCH_PUNCT)
    number = _ABORT_NUMBER if aborts else _NUMBER
    length = len(source)
    line = 1
    pos = 0
    while pos < length:
        match = _MASTER.match(source, pos)
        group = match.lastgroup
        end = match.end()
        text = match.group()
        token_line = line
        if group == 'space':
            line += text.count('\n')
            pos = end
            continue
        if group == 'comment':
            if text == '/*':
                depth = 1
                for edge in _COMMENT_EDGE.finditer(source, end):
                    depth += 1 if edge.group() == '/*' else -1
                    if not depth:
                        end = edge.end()
                        break
                else:
                    end = length
                line += source.count('\n', pos, end)
            pos = end
            continue
        if group == 'raw':
            if global_state and text.startswith('cr'):
                group, text, end = 'word', 'cr', pos + 2
            else:
                closing = '"' + '#' * text.count('#')
                closing_pos = source.find(closing, end)
                if closing_pos < 0 and aborts:
                    # This checker historically falls through to an identifier
                    # and a normal string for an unterminated raw literal.
                    end = pos + (2 if text.startswith(('br', 'cr')) else 1)
                    group, text = 'word', source[pos:end]
                else:
                    end = length if closing_pos < 0 else closing_pos + len(closing)
                    text = source[pos:end]
                    line += text.count('\n')
                    kind = 'string'
                    if aborts:
                        token_line = line
                    yield kind.upper() if global_state else kind, text, token_line, pos
                    pos = end
                    continue
        if group == 'string':
            if global_state and text.startswith('c'):
                group, text, end = 'word', 'c', pos + 1
            else:
                # The old loops skipped a newline immediately after a backslash.
                line += text.count('\n') - sum(e.group().endswith('\n') for e in _ESCAPES.finditer(text)) if '\n' in text else 0
                kind = 'string'
                token_line = line
        if group == 'quote':
            byte = text.startswith('b')
            cursor = end
            if global_state and cursor == length:
                yield ('IDENT' if byte else 'PUNCT'), ('' if byte else "'"), line, cursor
                pos = cursor
                continue
            if cursor < length and not byte and (source[cursor].isalpha() or source[cursor] == '_'):
                end = _WORD.match(source, cursor).end()
                if end < length and source[end] == "'":
                    end += 1
                    kind = 'char'
                else:
                    kind = 'lifetime'
            elif not global_state and not aborts:
                end = _QUOTED_CHAR.match(source, cursor).end()
                kind = 'char'
            elif cursor < length and source[cursor] == '\\':
                if aborts:
                    end = _ESCAPE_CHAR.match(source, cursor + 1).end()
                    line += source.count('\n', cursor + 1, end)
                    token_line = line
                else:
                    end = _QUOTED_CHAR.match(source, cursor + 1).end()
                kind = 'char'
            elif aborts:
                if cursor + 1 < length and source[cursor] != "'" and source[cursor + 1] == "'":
                    end = cursor + 2
                    kind = 'char'
                else:
                    kind = 'punct'
            elif cursor < length:
                end = cursor + 1
                if end < length and source[end] == "'":
                    end += 1
                kind = 'char'
            else:
                # Global's trailing quote falls through after advancing once.
                kind = 'punct'
            text = source[pos:end]
        if group == 'word':
            char = text[0]
            if char.isdigit():
                end = number.match(source, pos).end()
                text = source[pos:end]
                kind = 'number'
            elif char.isalpha() or char == '_':
                kind = 'ident'
                if text == 'r' and end < length and source[end] == '#':
                    cursor = end + 1
                    if global_state or (cursor < length and (source[cursor].isalpha() or source[cursor] == '_')):
                        end = _WORD.match(source, cursor).end()
                        text = source[cursor:end]
            else:
                # Python's Unicode alnum set includes non-letter, non-digit
                # characters; the old scanners emitted those as punctuation.
                text, end, kind = char, pos + 1, 'punct'
        if group == 'punct':
            three = source[pos:pos + 3]
            two = source[pos:pos + 2]
            if dialect != 'dispatch' and three in ('...', '..='):
                text, end = three, pos + 3
            elif two in punctuation:
                text, end = two, pos + 2
            kind = 'punct'
        yield kind.upper() if global_state else kind, text, token_line, pos
        pos = end

#!/usr/bin/env python3
"""Fixed lexical contracts for the authority checkers' three dialects."""

import unittest

from rust_lexer import lex


class RustLexerTests(unittest.TestCase):
    def check_tokens(self, source, expected, dialects=('global', 'dispatch', 'aborts')):
        for dialect in dialects:
            with self.subTest(source=source, dialect=dialect):
                actual = list(lex(source, dialect))
                # Global tokens have no line field in their checker adapter.
                if dialect == 'global':
                    actual = [(kind.lower(), text, 1, pos) for kind, text, _, pos in actual]
                self.assertEqual(actual, expected)

    def test_raw_literals(self):
        self.check_tokens('r#"a"# br##"b"#c"##', [
            ('string', 'r#"a"#', 1, 0), ('string', 'br##"b"#c"##', 1, 7),
        ])
        self.check_tokens('cr#"c"#', [('string', 'cr#"c"#', 1, 0)], ('dispatch', 'aborts'))
        self.check_tokens('cr#"c"#', [
            ('ident', 'cr', 1, 0), ('punct', '#', 1, 2),
            ('string', '"c"', 1, 3), ('punct', '#', 1, 6),
        ], ('global',))

    def test_comments(self):
        source = '/** doc /* nested */ end */\n/// doc\n//! inner\n/*! doc */ fn'
        self.check_tokens(source, [('ident', 'fn', 4, 57)], ('dispatch', 'aborts'))
        self.check_tokens(source, [('ident', 'fn', 1, 57)], ('global',))
        self.check_tokens('fn /* unterminated\n /* nested */', [('ident', 'fn', 1, 0)])

    def test_byte_and_c_literals(self):
        self.check_tokens('b"x" b\'x\'', [('string', 'b"x"', 1, 0), ('char', "b'x'", 1, 5)])
        self.check_tokens('c"x"', [('string', 'c"x"', 1, 0)], ('dispatch', 'aborts'))
        self.check_tokens('c"x"', [('ident', 'c', 1, 0), ('string', '"x"', 1, 1)], ('global',))

    def test_lifetimes_and_chars(self):
        self.check_tokens("'a", [('lifetime', "'a", 1, 0)])
        self.check_tokens("'a'", [('char', "'a'", 1, 0)])
        self.check_tokens(r"'\u{1F600}'", [('char', r"'\u{1F600}'", 1, 0)])
        self.check_tokens(r"'\''", [('char', r"'\''", 1, 0)], ('dispatch',))
        # Preserve the old scanners' early quote termination, including the
        # global scanner's advanced position for a final unmatched quote.
        self.check_tokens(r"'\''", [('char', "'\\'", 1, 0), ('punct', "'", 1, 4)], ('global',))
        self.check_tokens(r"'\''", [('char', "'\\'", 1, 0), ('punct', "'", 1, 3)], ('aborts',))
        self.check_tokens("'", [('punct', "'", 1, 1)], ('global',))

    def test_numbers(self):
        self.check_tokens('123_456u64 0xff_u8 1.25f32 1..2', [
            ('number', '123_456u64', 1, 0), ('number', '0xff_u8', 1, 11),
            ('number', '1.25f32', 1, 19), ('number', '1', 1, 27),
            ('punct', '..', 1, 28), ('number', '2', 1, 30),
        ])
        self.check_tokens('1.foo', [('number', '1.foo', 1, 0)], ('global', 'dispatch'))
        self.check_tokens('1.foo', [
            ('number', '1', 1, 0), ('punct', '.', 1, 1), ('ident', 'foo', 1, 2),
        ], ('aborts',))

    def test_punctuation(self):
        self.check_tokens(':: -> => && || += -=', [
            ('punct', '::', 1, 0), ('punct', '->', 1, 3), ('punct', '=>', 1, 6),
            ('punct', '&&', 1, 9), ('punct', '||', 1, 12),
            ('punct', '+=', 1, 15), ('punct', '-=', 1, 18),
        ])
        self.check_tokens('== != <= >=', [
            ('punct', '==', 1, 0), ('punct', '!=', 1, 3),
            ('punct', '<=', 1, 6), ('punct', '>=', 1, 9),
        ])
        self.check_tokens('... ..= *= /= << >>', [
            ('punct', '...', 1, 0), ('punct', '..=', 1, 4),
            ('punct', '*=', 1, 8), ('punct', '/=', 1, 11),
            ('punct', '<<', 1, 14), ('punct', '>>', 1, 17),
        ], ('global',))
        source = '... ..= *= /= << >> %= &= |= ^='
        self.check_tokens(source, [
            ('punct', '...', 1, 0), ('punct', '..=', 1, 4),
            ('punct', '*=', 1, 8), ('punct', '/=', 1, 11),
            ('punct', '<<', 1, 14), ('punct', '>>', 1, 17),
            ('punct', '%=', 1, 20), ('punct', '&=', 1, 23),
            ('punct', '|=', 1, 26), ('punct', '^=', 1, 29),
        ], ('aborts',))
        self.check_tokens('... ..= *=', [
            ('punct', '..', 1, 0), ('punct', '.', 1, 2), ('punct', '..', 1, 4),
            ('punct', '=', 1, 6), ('punct', '*', 1, 8), ('punct', '=', 1, 9),
        ], ('dispatch',))
        self.check_tokens('%= &= |= ^=', [
            ('punct', '%', 1, 0), ('punct', '=', 1, 1),
            ('punct', '&', 1, 3), ('punct', '=', 1, 4),
            ('punct', '|', 1, 6), ('punct', '=', 1, 7),
            ('punct', '^', 1, 9), ('punct', '=', 1, 10),
        ], ('global',))

    def test_unterminated_literals(self):
        self.check_tokens('"open\\', [('string', '"open\\', 1, 0)])
        self.check_tokens('r##"open', [('string', 'r##"open', 1, 0)], ('global', 'dispatch'))
        self.check_tokens('r##"open', [
            ('ident', 'r', 1, 0), ('punct', '#', 1, 1), ('punct', '#', 1, 2),
            ('string', '"open', 1, 3),
        ], ('aborts',))

    def test_lines_and_raw_identifiers(self):
        self.check_tokens('r#type', [('ident', 'type', 1, 0)])
        self.check_tokens('"a\nb" next', [('string', '"a\nb"', 2, 0), ('ident', 'next', 2, 6)], ('dispatch', 'aborts'))
        self.check_tokens('r"a\nb" next', [('string', 'r"a\nb"', 1, 0), ('ident', 'next', 2, 7)], ('dispatch',))
        self.check_tokens('r"a\nb" next', [('string', 'r"a\nb"', 2, 0), ('ident', 'next', 2, 7)], ('aborts',))


if __name__ == '__main__':
    unittest.main()

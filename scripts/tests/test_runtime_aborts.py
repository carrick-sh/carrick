#!/usr/bin/env python3

"""Tests for runtime abort discovery and monotone sharded ledger validation."""

import dataclasses
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/migrate/check-runtime-aborts.py"
SPEC = importlib.util.spec_from_file_location("check_runtime_aborts", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

AbortFinding = CHECKER.AbortFinding
LedgerError = CHECKER.LedgerError
scan_abort_source = CHECKER.scan_abort_source
validate_shards = CHECKER.validate_shards


def abort_row(
    finding: AbortFinding,
    verdict: str = "carrier_fault",
    typed_error: str | None = None,
    failure_domain: str = "test_domain",
    rationale: str = "test rationale",
) -> dict:
    row = {
        "file": finding.file,
        "function": finding.function,
        "ordinal_in_function": finding.ordinal_in_function,
        "fingerprint": finding.fingerprint,
        "verdict": verdict,
        "failure_domain": failure_domain,
        "rationale": rationale,
    }
    if typed_error is not None:
        row["typed_error"] = typed_error
    return row


def ledger_set(
    rows: list[dict],
    shard: str = "vcpu-loop.json",
    debt_ceiling: int | None = None,
) -> dict[str, dict]:
    if debt_ceiling is None:
        debt_ceiling = sum(1 for r in rows if r.get("verdict") == "typed_error_debt")
    return {
        shard: {
            "schema": 1,
            "shard": shard,
            "typed_error_debt_ceiling": debt_ceiling,
            "rows": list(rows),
        }
    }


class RuntimeAbortLedgerTests(unittest.TestCase):
    def test_discovers_multiline_calls_and_distinguishes_ordinals(self):
        source = r'''fn publish() {
    if first_failed() { std::process::abort(); }
    if second_failed() { std::process::
        abort(); }
}'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual([(row.function, row.ordinal_in_function) for row in rows],
                         [("publish", 1), ("publish", 2)])
        self.assertNotEqual(rows[0].fingerprint, rows[1].fingerprint)

    def test_ignores_comments_strings_and_cfg_test_items(self):
        source = r'''// std::process::abort();
const TEXT: &str = "std::process::abort()";
#[cfg(test)] fn test_only() { std::process::abort(); }
#[test] fn another_test() { std::process::abort(); }
#[cfg(test)]
mod tests {
    fn helper() { std::process::abort(); }
}
mod inner_tests {
    #![cfg(test)]
    fn helper() { std::process::abort(); }
}
'''
        self.assertEqual(
            scan_abort_source(Path("crates/carrick-runtime/src/lib.rs"), source), ())

    def test_parameter_level_cfg_test_does_not_make_function_test_only(self):
        source = r'''
fn production(#[cfg(test)] x: u8) {
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("production", 1)],
        )

    def test_aggregate_final_member_cfg_test_does_not_leak_to_next_item(self):
        cases = [
            ("struct", r'''
struct X {
    #[cfg(test)]
    field: u8
}
fn production() { std::process::abort(); }
'''),
            ("union", r'''
union U {
    #[cfg(test)]
    field: u8
}
fn production() { std::process::abort(); }
'''),
            ("enum", r'''
enum E {
    #[cfg(test)]
    Variant
}
fn production() { std::process::abort(); }
'''),
        ]
        for kind, source in cases:
            with self.subTest(kind=kind):
                rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
                self.assertEqual(
                    [(r.function, r.ordinal_in_function) for r in rows],
                    [("production", 1)],
                )

    def test_array_types_and_nested_semicolons_preserve_function_identity(self):
        cases = [
            ("array_param", r'''
fn production(x: [u8; 1]) {
    std::process::abort();
}
''', [("production", 1)]),
            ("array_return", r'''
fn production() -> [u8; 1] {
    std::process::abort();
}
''', [("production", 1)]),
            ("impl_method", r'''
impl X {
    fn production(&self, x: [u8; 1]) -> [u8; 2] {
        std::process::abort();
    }
}
''', [("X::production", 1)]),
            ("cfg_test_array_param", r'''
fn production(#[cfg(test)] x: [u8; 1]) {
    std::process::abort();
}
''', [("production", 1)]),
        ]
        for name, source, expected in cases:
            with self.subTest(case=name):
                rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
                self.assertEqual(
                    [(r.function, r.ordinal_in_function) for r in rows],
                    expected,
                )

    def test_trait_default_methods_and_insertion_stability(self):
        source = r'''
trait A {
    fn reset() { std::process::abort(); }
}
trait B {
    fn reset() { std::process::abort(); }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("A::reset", 1), ("B::reset", 1)],
        )

        source_with_insertion = r'''
trait A {
    fn unrelated() {}
    fn reset() { std::process::abort(); }
}
trait B {
    fn reset() { std::process::abort(); }
    fn other() {}
}
'''
        rows_inserted = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source_with_insertion)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows_inserted],
            [("A::reset", 1), ("B::reset", 1)],
        )

    def test_complete_lexical_module_ancestry(self):
        source = r'''
mod a {
    mod shared {
        fn run() { std::process::abort(); }
    }
}
mod b {
    mod shared {
        fn run() { std::process::abort(); }
    }
}
mod c {
    impl X {
        fn run() { std::process::abort(); }
    }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("a::shared::run", 1), ("b::shared::run", 1), ("c::X::run", 1)],
        )

    def test_attributed_if_else_chain_covers_all_branches(self):
        source = r'''
fn f(c: bool) {
    #[cfg(test)]
    if c {
        std::process::abort();
    } else if false {
        std::process::abort();
    } else {
        std::process::abort();
    }
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("f", 1)],
        )

    def test_always_applied_cfg_attr_test_exclusion(self):
        source = r'''
#[cfg_attr(all(), cfg(test))]
fn hidden_all() { std::process::abort(); }

#[cfg_attr(not(test), cfg(test))]
fn hidden_not_test() { std::process::abort(); }

#[cfg_attr(feature = "unknown", cfg(test))]
fn shown_feature() { std::process::abort(); }

#[cfg_attr(test, allow(dead_code))]
fn shown_cfg_attr_test_allow() { std::process::abort(); }
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("shown_feature", 1), ("shown_cfg_attr_test_allow", 1)],
        )

    def test_fingerprints_start_at_function_body_brace_excluding_declaration_const_blocks(self):
        source1 = r'''
fn f() where [(); { 1 }]: Sized {
    std::process::abort();
}
'''
        source2 = r'''
fn f() where [(); { 2 }]: Sized {
    std::process::abort();
}
'''
        r1 = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source1)
        r2 = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source2)
        self.assertEqual(len(r1), 1)
        self.assertEqual(len(r2), 1)
        self.assertEqual(r1[0].fingerprint, r2[0].fingerprint)

    def test_macro_argument_tokens_do_not_overwrite_declaration_identity(self):
        source = r'''
macro_rules! ty { ($($t:tt)*) => { () }; }
fn outer(_: ty!(fn fake), _: ty![impl fake2], _: ty!{trait fake3}) -> ty!(fn fake4) {
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("outer", 1)],
        )

    def test_curly_type_macro_does_not_open_function_body(self):
        source = r'''
macro_rules! ty { ($($t:tt)*) => { () }; }
fn outer() -> ty!{fn fake} {
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("outer", 1)],
        )

    def test_attributed_if_let_braced_pattern_keeps_whole_chain_test_only(self):
        source = r'''
struct S { f: u8 }
fn outer(x: Option<S>) {
    #[cfg(test)]
    if let Some(S { f: _ }) = x {
        std::process::abort();
    } else {
        std::process::abort();
    }
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("outer", 1)],
        )

    def test_match_guard_if_is_not_parsed_as_an_if_expression(self):
        source = r'''
struct S { value: u8 }
fn outer(x: S) {
    match x {
        S { value } if value > 0 => { consume(value); }
        _ => { std::process::abort(); }
    }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("outer", 1)],
        )

    def test_if_body_followed_by_standalone_block_keeps_both_aborts(self):
        source = r'''
fn outer(result: Result<(), ()>) {
    if let Err(_error) = result {
        std::process::abort();
    }
    {
        cleanup().unwrap_or_else(|_error| { std::process::abort(); });
    }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("outer", 1), ("outer", 2)],
        )

    def test_production_if_condition_blocks_are_scanned(self):
        source = r'''
fn outer() {
    if { std::process::abort(); true } { consume(); }
    if let Some(value) = { std::process::abort(); Some(1) } { consume(value); }
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("outer", 1), ("outer", 2), ("outer", 3)],
        )

    def test_nested_if_inside_attributed_condition_preserves_outer_else_scope(self):
        source = r'''
fn outer(flag: bool) {
    #[cfg(test)]
    if { if flag { consume(); } true } {
        std::process::abort();
    } else {
        std::process::abort();
    }
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("outer", 1)],
        )

    def test_attributed_let_chain_resets_pattern_state_per_let(self):
        source = r'''
struct S { value: u8 }
fn outer(first: Option<u8>, second: S) {
    #[cfg(test)]
    if let Some(_) = first && let S { value: _ } = second {
        std::process::abort();
    } else {
        std::process::abort();
    }
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("outer", 1)],
        )

    def test_curly_condition_macro_tokens_do_not_create_fake_items(self):
        source = r'''
macro_rules! boolify { ($($tokens:tt)*) => { true }; }
fn outer() {
    if boolify!{fn fake} { std::process::abort(); }
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("outer", 1), ("outer", 2)],
        )

    def test_curly_body_macro_tokens_do_not_create_fake_items(self):
        source = r'''
macro_rules! discard { ($($tokens:tt)*) => {}; }
fn outer() {
    discard!{fn fake}
    { std::process::abort(); }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("outer", 1)],
        )

    def test_curly_item_macro_tokens_preserve_complete_function_definitions(self):
        source = r'''
macro_rules! define { ($($tokens:tt)*) => { $($tokens)* }; }
define! {
    fn generated() {
        std::process::abort();
    }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("generated", 1)],
        )

    def test_attributed_expression_leading_condition_blocks_keep_else_test_only(self):
        cases = [
            ("match", r'''
fn outer(value: bool) {
    #[cfg(test)]
    if match value { true => true, false => false } {
        std::process::abort();
    } else { std::process::abort(); }
    std::process::abort();
}
'''),
            ("async", r'''
async fn outer() {
    #[cfg(test)]
    if async { true }.await {
        std::process::abort();
    } else { std::process::abort(); }
    std::process::abort();
}
'''),
            ("loop", r'''
fn outer() {
    #[cfg(test)]
    if loop { break true } {
        std::process::abort();
    } else { std::process::abort(); }
    std::process::abort();
}
'''),
            ("label", r'''
fn outer() {
    #[cfg(test)]
    if 'condition: { break 'condition true } {
        std::process::abort();
    } else { std::process::abort(); }
    std::process::abort();
}
'''),
        ]
        for name, source in cases:
            with self.subTest(case=name):
                rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
                self.assertEqual(
                    [(r.function, r.ordinal_in_function) for r in rows],
                    [("outer", 1)],
                )

    def test_attributed_loop_header_expression_blocks_keep_body_test_only(self):
        cases = [
            ("while-match", r'''
fn outer(value: bool) {
    #[cfg(test)]
    while match value { true => true, false => false } {
        std::process::abort();
    }
    std::process::abort();
}
'''),
            ("while-async", r'''
async fn outer() {
    #[cfg(test)]
    while async { false }.await {
        std::process::abort();
    }
    std::process::abort();
}
'''),
            ("for-match", r'''
fn outer(value: bool) {
    #[cfg(test)]
    for item in match value { true => [1], false => [2] } {
        let _ = item;
        std::process::abort();
    }
    std::process::abort();
}
'''),
            ("for-braced-pattern-and-iterator", r'''
struct S { value: u8 }
fn outer(values: [S; 1]) {
    #[cfg(test)]
    for S { value: _ } in { values } {
        std::process::abort();
    }
    std::process::abort();
}
'''),
            ("for-range-endpoint-block", r'''
fn outer() {
    #[cfg(test)]
    for item in 0..{ std::process::abort(); 3 } {
        let _ = item;
        std::process::abort();
    }
    std::process::abort();
}
'''),
            ("labeled-while-match", r'''
fn outer(value: bool) {
    #[cfg(test)]
    'again: while match value { true => true, false => false } {
        std::process::abort();
        break 'again;
    }
    std::process::abort();
}
'''),
        ]
        for name, source in cases:
            with self.subTest(case=name):
                rows = scan_abort_source(
                    Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source
                )
                self.assertEqual(
                    [(r.function, r.ordinal_in_function) for r in rows],
                    [("outer", 1)],
                )

    def test_distinct_block_local_functions_have_insertion_stable_identities(self):
        before = r'''
fn outer() {
    { fn local() { if first() { std::process::abort(); } } local(); }
    { fn local() { if second() { std::process::abort(); } } local(); }
}
'''
        after = r'''
fn outer() {
    { fn unrelated() { std::process::abort(); } unrelated(); }
    { fn local() { if first() { std::process::abort(); } } local(); }
    { fn local() { if second() { std::process::abort(); } } local(); }
}
'''
        before_rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), before)
        after_rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), after)
        self.assertEqual(len({row.function for row in before_rows}), 2)
        before_by_fingerprint = {row.fingerprint: row.function for row in before_rows}
        after_by_fingerprint = {row.fingerprint: row.function for row in after_rows}
        for fingerprint, function in before_by_fingerprint.items():
            self.assertEqual(after_by_fingerprint[fingerprint], function)

    def test_distinct_block_local_item_containers_have_stable_identities(self):
        before = r'''
fn outer() {
    { trait A { fn reset() { if first() { std::process::abort(); } } } }
    { trait A { fn reset() { if second() { std::process::abort(); } } } }
    { struct S; impl S { fn reset() { if third() { std::process::abort(); } } } }
    { struct S; impl S { fn reset() { if fourth() { std::process::abort(); } } } }
}
'''
        after = r'''
fn outer() {
    { trait Unrelated { fn reset() { std::process::abort(); } } }
    { trait A { fn reset() { if first() { std::process::abort(); } } } }
    { trait A { fn reset() { if second() { std::process::abort(); } } } }
    { struct S; impl S { fn reset() { if third() { std::process::abort(); } } } }
    { struct S; impl S { fn reset() { if fourth() { std::process::abort(); } } } }
}
'''
        before_rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), before)
        after_rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), after)
        self.assertEqual(len({row.function for row in before_rows}), 4)
        before_by_fingerprint = {row.fingerprint: row.function for row in before_rows}
        after_by_fingerprint = {row.fingerprint: row.function for row in after_rows}
        for fingerprint, function in before_by_fingerprint.items():
            self.assertEqual(after_by_fingerprint[fingerprint], function)

    def test_byte_identical_local_definitions_are_rejected_as_ambiguous(self):
        cases = [
            r'''
fn outer() {
    { fn local() { std::process::abort(); } }
    { fn local() { std::process::abort(); } }
}
''',
            r'''
fn outer() {
    { trait A { fn reset() { std::process::abort(); } } }
    { trait A { fn reset() { std::process::abort(); } } }
}
''',
            r'''
fn outer() {
    { struct S; impl S { fn reset() { std::process::abort(); } } }
    { struct S; impl S { fn reset() { std::process::abort(); } } }
}
''',
        ]
        for source in cases:
            with self.subTest(source=source), self.assertRaises(LedgerError):
                scan_abort_source(
                    Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source
                )

    def test_irrelevant_or_test_only_duplicate_local_definitions_are_allowed(self):
        source = r'''
fn outer() {
    { fn local() { consume(); } }
    { fn local() { consume(); } }
    #[cfg(test)]
    fn selected() { std::process::abort(); }
    #[cfg(not(test))]
    fn selected() { std::process::abort(); }
}
'''
        rows = scan_abort_source(
            Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source
        )
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].function.startswith("outer::selected@"))
        self.assertEqual(rows[0].ordinal_in_function, 1)

    def test_mutually_exclusive_production_cfg_is_part_of_local_identity(self):
        source = r'''
fn outer() {
    #[cfg(feature = "a")]
    fn local() { std::process::abort(); }
    #[cfg(not(feature = "a"))]
    fn local() { std::process::abort(); }
}
'''
        rows = scan_abort_source(
            Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row.function for row in rows}), 2)
        self.assertTrue(all(row.function.startswith("outer::local@") for row in rows))
        self.assertEqual([row.ordinal_in_function for row in rows], [1, 1])

    def test_mutually_exclusive_cfg_block_is_part_of_nested_local_identity(self):
        source = r'''
fn outer() {
    #[cfg(feature = "a")]
    { fn local() { std::process::abort(); } }
    #[cfg(not(feature = "a"))]
    { fn local() { std::process::abort(); } }
}
'''
        rows = scan_abort_source(
            Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row.function for row in rows}), 2)

    def test_cfg_item_macro_is_part_of_generated_local_identity(self):
        source = r'''
macro_rules! items { ($($tokens:tt)*) => { $($tokens)* }; }
fn outer() {
    #[cfg(feature = "a")]
    items! { fn local() { std::process::abort(); } }
    #[cfg(not(feature = "a"))]
    items! { fn local() { std::process::abort(); } }
}
'''
        rows = scan_abort_source(
            Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row.function for row in rows}), 2)

    def test_hrtb_for_does_not_replace_pending_function_identity(self):
        source = r'''
fn outer<F>(_value: F)
where
    F: for<'a> Fn(&'a u8),
{
    std::process::abort();
}
'''
        rows = scan_abort_source(
            Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source
        )
        self.assertEqual(
            [(row.function, row.ordinal_in_function) for row in rows],
            [("outer", 1)],
        )

    def test_cfg_test_braced_match_pattern_covers_the_arm_body(self):
        source = r'''
struct S { value: u8 }
fn outer(x: S) {
    match x {
        #[cfg(test)]
        S { value } if value > 0 => { std::process::abort(); }
        _ => {}
    }
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("outer", 1)],
        )

    def test_local_item_identity_includes_enclosing_function(self):
        source = r'''
fn outer() {
    trait A { fn reset() { std::process::abort(); } }
    trait B { fn reset() { std::process::abort(); } }
    struct S;
    impl S { fn reset() { std::process::abort(); } }
}
fn sibling() {
    trait A { fn reset() { std::process::abort(); } }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        identities = [(r.function, r.ordinal_in_function) for r in rows]
        self.assertEqual(len(identities), 4)
        self.assertEqual([ordinal for _, ordinal in identities], [1, 1, 1, 1])
        self.assertTrue(identities[0][0].startswith("outer::A@"))
        self.assertTrue(identities[1][0].startswith("outer::B@"))
        self.assertTrue(identities[2][0].startswith("outer::S@"))
        self.assertTrue(identities[3][0].startswith("sibling::A@"))
        self.assertTrue(all(function.endswith("::reset") for function, _ in identities))

    def test_production_capable_attributes_are_discovered(self):
        source = r'''
#[cfg(not(test))]
fn not_test_fn() {
    std::process::abort();
}

#[cfg_attr(test, allow(dead_code))]
fn cfg_attr_fn() {
    std::process::abort();
}

#[cfg(any(test, feature = "ship"))]
fn any_feature_fn() {
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [
                ("not_test_fn", 1),
                ("cfg_attr_fn", 1),
                ("any_feature_fn", 1),
            ],
        )

    def test_stable_function_identity_includes_enclosing_type(self):
        source = r'''
impl TypeA {
    fn drop(&mut self) {
        std::process::abort();
    }
}

impl TypeB {
    fn drop(&mut self) {
        std::process::abort();
    }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("TypeA::drop", 1), ("TypeB::drop", 1)],
        )

    def test_generic_specializations_and_qualified_paths_are_distinguished(self):
        source = r'''
impl Trait<i32> for Type { fn reset(&self) { std::process::abort(); } }
impl Trait<u32> for Type { fn reset(&self) { std::process::abort(); } }
impl Other for Box<i32> { fn reset(&self) { std::process::abort(); } }
impl Other for Box<u32> { fn reset(&self) { std::process::abort(); } }
impl<T> ns::Trait<T> for ns::Box<T> { fn run(&self) { std::process::abort(); } }
impl<T> ns::Inherent<T> { fn run(&self) { std::process::abort(); } }
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [
                ("<Type as Trait<i32>>::reset", 1),
                ("<Type as Trait<u32>>::reset", 1),
                ("<Box<i32> as Other>::reset", 1),
                ("<Box<u32> as Other>::reset", 1),
                ("<ns::Box<T> as ns::Trait<T>>::run", 1),
                ("ns::Inherent<T>::run", 1),
            ],
        )

    def test_generic_specialization_insertion_does_not_renumber_sibling(self):
        before = r'''
impl Trait<i32> for Type { fn reset(&self) { std::process::abort(); } }
impl Trait<u32> for Type { fn reset(&self) { std::process::abort(); } }
'''
        after = r'''
impl Trait<i32> for Type {
    fn reset(&self) {
        std::process::abort();
        std::process::abort();
    }
}
impl Trait<u32> for Type { fn reset(&self) { std::process::abort(); } }
'''
        rows_before = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), before)
        rows_after = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), after)

        self.assertEqual(rows_before[1].function, "<Type as Trait<u32>>::reset")
        self.assertEqual(rows_before[1].ordinal_in_function, 1)

        self.assertEqual(rows_after[2].function, "<Type as Trait<u32>>::reset")
        self.assertEqual(rows_after[2].ordinal_in_function, 1)
        self.assertEqual(rows_before[1], rows_after[2])

    def test_nested_generics_and_qualified_trait_paths_keep_impl_identity(self):
        source = r'''
impl Trait<Vec<i32>> for Type {
    fn reset(&self) { std::process::abort(); }
}
impl <T as Meta>::Trait for Type {
    fn reset(&self) { std::process::abort(); }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [
                ("<Type as Trait<Vec<i32>>>::reset", 1),
                ("<Type as <T as Meta>::Trait>::reset", 1),
            ],
        )

    def test_reference_self_types_do_not_share_impl_identity(self):
        source = r'''
impl Trait for Type {
    fn reset(&self) { std::process::abort(); }
}
impl Trait for &Type {
    fn reset(&self) { std::process::abort(); }
}
impl Trait for &mut Type {
    fn reset(&self) { std::process::abort(); }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [
                ("<Type as Trait>::reset", 1),
                ("<&Type as Trait>::reset", 1),
                ("<&mut Type as Trait>::reset", 1),
            ],
        )

    def test_higher_ranked_for_does_not_replace_impl_separator(self):
        source = r'''
impl for<'a> Trait<'a> for Type {
    fn run(&self) { std::process::abort(); }
}
impl Trait for for<'a> fn(&'a str) {
    fn run(&self) { std::process::abort(); }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [
                ("<Type as for<'a>Trait<'a>>::run", 1),
                ("<for<'a>fn(&'a str) as Trait>::run", 1),
            ],
        )

    def test_qualified_self_type_after_impl_separator_is_preserved(self):
        source = r'''
impl Trait for <T as Meta>::Assoc {
    fn run(&self) { std::process::abort(); }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("<<T as Meta>::Assoc as Trait>::run", 1)],
        )

    def test_const_generic_braces_do_not_open_declaration_body(self):
        source = r'''
impl<const N: usize> Trait<{ N + 1 }> for Type<N> {
    fn run(&self) { std::process::abort(); }
}

fn standalone<const N: usize>() -> Array<{ N + 1 }> {
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [
                ("<Type<N> as Trait<{N+1}>>::run", 1),
                ("standalone", 1),
            ],
        )

    def test_const_generic_block_tokens_do_not_end_declaration(self):
        source = r'''
impl Trait<{ let n = 1; n + 1 }> for Type {
    fn run(&self) { std::process::abort(); }
}

fn standalone() -> Array<{ let n = 1; n + 1 }> {
    std::process::abort();
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [
                ("<Type as Trait<{let n=1;n+1}>>::run", 1),
                ("standalone", 1),
            ],
        )

    def test_cfg_test_scope_survives_commas_in_generic_arguments(self):
        source = r'''
#[cfg(test)]
const TEST_VALUE: Pair<A, B> = make(|| { std::process::abort(); });

fn production(x: Kind) {
    match x {
        #[cfg(test)]
        Kind::A => foo::<X, Y>(std::process::abort()),
        Kind::B => std::process::abort(),
    }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("production", 1)],
        )

    def test_cfg_angle_probe_does_not_cross_match_arm_boundary(self):
        source = r'''
fn production(kind: Kind, x: i32, y: i32, z: i32, q: i32) -> bool {
    match kind {
        #[cfg(test)]
        Kind::A => x < y,
        Kind::B => { std::process::abort(); z } > q,
        Kind::C => { std::process::abort(); true },
    }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("production", 1), ("production", 2)],
        )

    def test_cfg_all_requires_test_and_match_arm_scope_ends_at_comma(self):
        source = r'''
#[cfg(all(test, feature = "x"))]
fn test_only() { std::process::abort(); }

fn production(x: Kind) {
    match x {
        #[cfg(test)]
        Kind::A => std::process::abort(),
        Kind::B => std::process::abort(),
    }
}
'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual(
            [(r.function, r.ordinal_in_function) for r in rows],
            [("production", 1)],
        )

    def test_unrelated_method_insertion_does_not_renumber_sibling_type(self):
        before = r'''
impl TypeA {
    fn drop(&mut self) {
        std::process::abort();
    }
}

impl TypeB {
    fn drop(&mut self) {
        std::process::abort();
    }
}
'''
        after = r'''
impl TypeA {
    fn drop(&mut self) {
        std::process::abort();
        std::process::abort();
    }
}

impl TypeB {
    fn drop(&mut self) {
        std::process::abort();
    }
}
'''
        rows_before = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), before)
        rows_after = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), after)

        self.assertEqual(rows_before[1].function, "TypeB::drop")
        self.assertEqual(rows_before[1].ordinal_in_function, 1)

        self.assertEqual(rows_after[2].function, "TypeB::drop")
        self.assertEqual(rows_after[2].ordinal_in_function, 1)
        self.assertEqual(rows_before[1], rows_after[2])

    def test_duplicate_actual_identities_are_rejected(self):
        finding = AbortFinding("crates/carrick-runtime/src/vcpu_loop/mod.rs",
                               "publish", 1, "a" * 64)
        row = abort_row(finding, verdict="carrier_fault", typed_error=None)
        with self.assertRaises(LedgerError):
            validate_shards((finding, finding), ledger_set([row], debt_ceiling=0))

    def test_exact_shards_reject_add_remove_drift_and_bad_metadata(self):
        finding = AbortFinding("crates/carrick-runtime/src/vcpu_loop/mod.rs",
                               "publish", 1, "a" * 64)
        good = abort_row(finding, verdict="typed_error_debt",
                         typed_error="PublishError")
        validate_shards((finding,), ledger_set([good], debt_ceiling=1))
        bad_cases = [
            ledger_set([], debt_ceiling=0),
            ledger_set([good, good], debt_ceiling=2),
            ledger_set([dict(good, verdict="unknown")], debt_ceiling=0),
            ledger_set([good], debt_ceiling=2),
            ledger_set([dict(good, fingerprint="b" * 64)], debt_ceiling=1),
            ledger_set([dict(good, rationale="")], debt_ceiling=1),
            ledger_set([dict(good, failure_domain="")], debt_ceiling=1),
            ledger_set([dict(good, typed_error=None)], debt_ceiling=1),
        ]
        for ledgers in bad_cases:
            with self.subTest(ledgers=ledgers), self.assertRaises(LedgerError):
                validate_shards((finding,), ledgers)

    def test_wrong_shard_is_rejected(self):
        finding = AbortFinding("crates/carrick-vmm-hvf/src/trap.rs",
                               "run", 1, "c" * 64)
        row = abort_row(finding, verdict="carrier_fault", typed_error=None)
        with self.assertRaises(LedgerError):
            validate_shards((finding,), ledger_set([row], shard="runtime.json",
                                                   debt_ceiling=0))

    def test_full_gate_requires_exactly_all_named_shards(self):
        complete = {name: {} for name in CHECKER.REQUIRED_SHARDS}
        CHECKER.validate_required_shards(complete)
        for missing in CHECKER.REQUIRED_SHARDS:
            with self.subTest(missing=missing), self.assertRaises(LedgerError):
                CHECKER.validate_required_shards(
                    {name: {} for name in CHECKER.REQUIRED_SHARDS if name != missing}
                )
        with self.assertRaises(LedgerError):
            CHECKER.validate_required_shards({**complete, "surprise.json": {}})

    def test_carrier_fault_with_typed_error_is_rejected(self):
        finding = AbortFinding("crates/carrick-runtime/src/vcpu_loop/mod.rs",
                               "publish", 1, "a" * 64)
        bad_row = abort_row(finding, verdict="carrier_fault", typed_error="UnexpectedError")
        with self.assertRaises(LedgerError):
            validate_shards((finding,), ledger_set([bad_row], debt_ceiling=0))

    def test_line_only_move_keeps_identity(self):
        one = scan_abort_source(
            Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"),
            "fn publish() {\n    std::process::abort();\n}",
        )
        two = scan_abort_source(
            Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"),
            "\n\n\nfn publish() {\n\n    std::process::abort();\n\n}",
        )
        self.assertEqual(one, two)

    def test_preceding_log_statement_is_captured_in_fingerprint(self):
        with_log = scan_abort_source(
            Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"),
            'fn publish() {\n    tracing::error!("failed");\n    std::process::abort();\n}',
        )
        without_log = scan_abort_source(
            Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"),
            'fn publish() {\n    std::process::abort();\n}',
        )
        self.assertEqual(len(with_log), 1)
        self.assertEqual(len(without_log), 1)
        self.assertNotEqual(with_log[0].fingerprint, without_log[0].fingerprint)


if __name__ == "__main__":
    unittest.main()

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

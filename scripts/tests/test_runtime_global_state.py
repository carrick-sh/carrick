#!/usr/bin/env python3

from __future__ import annotations

import dataclasses
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/migrate/check-runtime-global-state.py"
SPEC = importlib.util.spec_from_file_location(
    "check_runtime_global_state", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)

Finding = GATE.Finding
LedgerError = GATE.LedgerError
scan_source = GATE.scan_source
compare = GATE.compare


def reviewed_row(finding: GATE.Finding, **kwargs) -> dict:
    row = {
        "kind": finding.kind,
        "file": finding.file,
        "symbol": finding.symbol,
        "fingerprint": finding.fingerprint,
        "classification": kwargs.get("classification", "carrier_infra"),
        "rationale": kwargs.get("rationale", "Test rationale."),
    }
    if "destination" in kwargs:
        row["destination"] = kwargs["destination"]
    elif row["classification"] == "container_debt":
        row["destination"] = "Container.test_field"
    return row


class RuntimeGlobalStateTests(unittest.TestCase):
    def test_discovers_multiline_static_and_env_sources(self):
        source = r'''static mut RAW: u64 = 0;
static CELL: OnceLock<u64> = OnceLock::new();
thread_local! { static TLS: Cell<u8> = const { Cell::new(0) }; }
fn config() { let _ = std::env::var("CARRICK_RUN_ID"); }
'''
        findings = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual(
            [(row.kind, row.symbol) for row in findings],
            [
                ("static", "RAW"),
                ("static", "CELL"),
                ("thread_local", "TLS"),
                ("env_var", "config::CARRICK_RUN_ID"),
            ],
        )

    def test_ignores_comments_strings_and_lifetimes(self):
        source = r'''// static FAKE: u8 = 0;
const TEXT: &str = "std::env::var(\"FAKE\")";
fn borrow(value: &'static str) -> &'static str { value }
'''
        self.assertEqual(scan_source(Path("crates/x/src/lib.rs"), source), ())

    def test_cfg_test_policy_is_deterministic(self):
        source = "#[cfg(test)] static TEST_CELL: AtomicU64 = AtomicU64::new(0);"
        rows = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual(
            [(row.kind, row.symbol) for row in rows], [("static", "TEST_CELL")]
        )

    def test_exact_ledger_rejects_add_remove_drift_and_bad_rows(self):
        finding = Finding("static", "crates/x/src/lib.rs", "CELL", "a" * 64)
        reviewed = reviewed_row(finding, classification="carrier_infra")
        compare((finding,), (reviewed,))
        for actual, rows in [((finding,), ()), ((), (reviewed,))]:
            with self.assertRaises(LedgerError):
                compare(actual, rows)
        with self.assertRaises(LedgerError):
            compare(
                (dataclasses.replace(finding, fingerprint="b" * 64),),
                (reviewed,),
            )
        with self.assertRaises(LedgerError):
            compare((finding,), (reviewed, reviewed))
        with self.assertRaises(LedgerError):
            compare(
                (finding,), (reviewed_row(finding, classification="unknown"),)
            )

    def test_line_only_move_keeps_identity(self):
        one = scan_source(
            Path("crates/x/src/lib.rs"),
            "#[cfg(test)]\nstatic CELL: AtomicU64 = AtomicU64::new(0);",
        )
        two = scan_source(
            Path("crates/x/src/lib.rs"),
            "\n\n#[cfg(test)]\n\nstatic CELL: AtomicU64 = AtomicU64::new(0);",
        )
        self.assertEqual(one, two)

    def test_direct_cfg_test_attribute_change_causes_drift(self):
        with_cfg = scan_source(
            Path("crates/x/src/lib.rs"),
            "#[cfg(test)]\nstatic CELL: AtomicU64 = AtomicU64::new(0);",
        )
        without_cfg = scan_source(
            Path("crates/x/src/lib.rs"),
            "static CELL: AtomicU64 = AtomicU64::new(0);",
        )
        self.assertEqual(len(with_cfg), 1)
        self.assertEqual(len(without_cfg), 1)
        self.assertEqual(with_cfg[0].symbol, without_cfg[0].symbol)
        self.assertNotEqual(with_cfg[0].fingerprint, without_cfg[0].fingerprint)

        # Confirm compare rejects with_cfg against without_cfg review
        with self.assertRaises(LedgerError):
            compare(with_cfg, (reviewed_row(without_cfg[0]),))

    def test_enclosing_module_cfg_test_change_causes_drift(self):
        with_mod_cfg = scan_source(
            Path("crates/x/src/lib.rs"),
            "#[cfg(test)]\nmod tests {\n    static CELL: AtomicU64 = AtomicU64::new(0);\n}",
        )
        without_mod_cfg = scan_source(
            Path("crates/x/src/lib.rs"),
            "mod tests {\n    static CELL: AtomicU64 = AtomicU64::new(0);\n}",
        )
        self.assertEqual(len(with_mod_cfg), 1)
        self.assertEqual(len(without_mod_cfg), 1)
        self.assertEqual(with_mod_cfg[0].symbol, without_mod_cfg[0].symbol)
        self.assertNotEqual(
            with_mod_cfg[0].fingerprint, without_mod_cfg[0].fingerprint
        )

        with self.assertRaises(LedgerError):
            compare(with_mod_cfg, (reviewed_row(without_mod_cfg[0]),))

    def test_statement_cfg_test_attribute_on_env_read_causes_drift(self):
        with_cfg = scan_source(
            Path("crates/x/src/lib.rs"),
            'fn f() { #[cfg(test)] let _ = std::env::var("X"); }',
        )
        without_cfg = scan_source(
            Path("crates/x/src/lib.rs"),
            'fn f() { let _ = std::env::var("X"); }',
        )
        self.assertEqual(len(with_cfg), 1)
        self.assertEqual(len(without_cfg), 1)
        self.assertEqual(with_cfg[0].symbol, without_cfg[0].symbol)
        self.assertNotEqual(with_cfg[0].fingerprint, without_cfg[0].fingerprint)

        # Confirm compare rejects with_cfg against without_cfg review
        with self.assertRaises(LedgerError):
            compare(with_cfg, (reviewed_row(without_cfg[0]),))

    def test_statement_cfg_attribute_does_not_leak_to_subsequent_findings(self):
        source = r'''
fn f() {
    #[cfg(test)]
    let _ = std::env::var("X");
    let _ = std::env::var("Y");
}
'''
        findings = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual(len(findings), 2)
        plain_y = scan_source(
            Path("crates/x/src/lib.rs"),
            'fn f() { let _ = std::env::var("Y"); }',
        )
        self.assertEqual(findings[1].fingerprint, plain_y[0].fingerprint)

    def test_statement_cfg_line_only_move_remains_stable(self):
        one = scan_source(
            Path("crates/x/src/lib.rs"),
            'fn f() {\n    #[cfg(test)]\n    let _ = std::env::var("X");\n}',
        )
        two = scan_source(
            Path("crates/x/src/lib.rs"),
            'fn f() {\n\n    #[cfg(test)]\n\n    let _ = std::env::var("X");\n}',
        )
        self.assertEqual(one, two)


    def test_non_test_attributes_included_in_fingerprint_without_automatic_classification(self):
        source = "#[allow(dead_code)]\npub static FOO: u32 = 42;"
        findings = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].symbol, "FOO")
        # Ensure that non-test attribute differs from plain declaration
        plain = scan_source(Path("crates/x/src/lib.rs"), "pub static FOO: u32 = 42;")
        self.assertNotEqual(findings[0].fingerprint, plain[0].fingerprint)

    def test_discovers_env_var_os_and_identifiers(self):
        source = r'''
fn get_home() {
    let _ = std::env::var_os("CARRICK_HOME");
}
fn get_base() {
    let _ = std::env::var_os(BASE_DIR_ENV);
}
'''
        findings = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual(
            [(row.kind, row.symbol) for row in findings],
            [
                ("env_var_os", "get_home::CARRICK_HOME"),
                ("env_var_os", "get_base::BASE_DIR_ENV"),
            ],
        )

    def test_discovers_function_local_static(self):
        source = r'''
pub(crate) fn root_net_ns() -> &'static Arc<NetNs> {
    static ROOT: OnceLock<Arc<NetNs>> = OnceLock::new();
    ROOT.get_or_init(|| Arc::new(NetNs::new()))
}
'''
        findings = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual(
            [(row.kind, row.symbol) for row in findings],
            [("static", "root_net_ns::ROOT")],
        )

    def test_discovers_nested_and_multiline_initializers(self):
        source = r'''
static COMPLEX: LazyLock<Mutex<HashMap<u32, (i32, String)>>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert(0, (1, "init".to_string()));
    Mutex::new(map)
});
'''
        findings = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "static")
        self.assertEqual(findings[0].symbol, "COMPLEX")

    def test_nested_block_comments_and_raw_strings(self):
        source = r'''
/* comment /* nested comment */ static IGNORED: u8 = 0; */
const RAW: &str = r#" static RAW_IGNORED: u8 = 0; std::env::var("IGNORED"); "#;
const RAW_HASH: &str = r##" std::env::var_os("IGNORED"); "##;
'''
        findings = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual(findings, ())

    def test_requires_destination_for_container_debt(self):
        finding = Finding("static", "crates/x/src/lib.rs", "DEBT", "a" * 64)
        bad_debt = {
            "kind": "static",
            "file": "crates/x/src/lib.rs",
            "symbol": "DEBT",
            "fingerprint": "a" * 64,
            "classification": "container_debt",
            "rationale": "Must move to container.",
        }
        with self.assertRaises(LedgerError):
            compare((finding,), (bad_debt,))
        good_debt = dict(bad_debt, destination="Container.debt_field")
        compare((finding,), (good_debt,))

    def test_concurrent_mode_rejects_even_destination_backed_container_debt(self):
        finding = Finding("static", "crates/x/src/lib.rs", "DEBT", "a" * 64)
        debt = reviewed_row(finding, classification="container_debt")
        with self.assertRaises(LedgerError):
            compare((finding,), (debt,), require_concurrent_embed_clean=True)

    def test_concurrent_source_policy_rejects_ambient_runtime_accessors(self):
        source = "fn current_thread_registry() -> &'static Registry { todo!() }"
        with self.assertRaises(LedgerError):
            GATE.validate_concurrent_source(
                Path("crates/carrick-thread/src/thread.rs"), source
            )

    def test_concurrent_source_policy_rejects_run_id_env_below_launch_boundary(self):
        source = 'fn helper() { let _ = std::env::var("CARRICK_RUN_ID"); }'
        with self.assertRaises(LedgerError):
            GATE.validate_concurrent_source(
                Path("crates/carrick-runtime/src/dispatch/proctitle.rs"), source
            )
        GATE.validate_concurrent_source(
            Path("crates/carrick-runtime/src/kernel/container.rs"), source
        )

    def test_concurrent_source_policy_allows_container_keyed_endpoint_map(self):
        source = "static RUNTIME_ENDPOINTS: LazyLock<Map<ContainerId, Endpoint>> = init();"
        GATE.validate_concurrent_source(
            Path("crates/carrick-thread/src/thread.rs"), source
        )

    def test_requires_rationale_for_all_rows(self):
        finding = Finding("static", "crates/x/src/lib.rs", "INFRA", "a" * 64)
        bad_infra = {
            "kind": "static",
            "file": "crates/x/src/lib.rs",
            "symbol": "INFRA",
            "fingerprint": "a" * 64,
            "classification": "carrier_infra",
            "rationale": "",
        }
        with self.assertRaises(LedgerError):
            compare((finding,), (bad_infra,))
        good_infra = dict(bad_infra, rationale="Host process wide state.")
        compare((finding,), (good_infra,))

    def test_thread_local_multiple_and_visibility(self):
        source = r'''
thread_local! {
    pub static TLS1: Cell<u32> = const { Cell::new(1) };
    pub(crate) static TLS2: Cell<u64> = const { Cell::new(2) };
}
'''
        findings = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual(
            [(row.kind, row.symbol) for row in findings],
            [("thread_local", "TLS1"), ("thread_local", "TLS2")],
        )

    def test_load_ledger_validates_schema_and_path(self):
        with self.assertRaises(LedgerError):
            GATE.load_ledger(Path("nonexistent_file.json"))

    def test_compare_rejects_duplicate_actual_identities(self):
        f1 = Finding("static", "crates/x/src/lib.rs", "DUP", "a" * 64)
        f2 = Finding("static", "crates/x/src/lib.rs", "DUP", "a" * 64)
        reviewed = reviewed_row(f1)
        with self.assertRaises(LedgerError) as ctx:
            compare((f1, f2), (reviewed,))
        self.assertIn("duplicate discovered finding identity", str(ctx.exception))

    def test_bootstrap_emits_unreviewed_and_fails_compare(self):
        finding = Finding("static", "crates/x/src/lib.rs", "RAW", "a" * 64)
        unreviewed = {
            "kind": finding.kind,
            "file": finding.file,
            "symbol": finding.symbol,
            "fingerprint": finding.fingerprint,
            "classification": "unreviewed",
            "rationale": "UNREVIEWED: classify scope and state rationale.",
        }
        with self.assertRaises(LedgerError) as ctx:
            compare((finding,), (unreviewed,))
        self.assertIn("invalid classification: 'unreviewed'", str(ctx.exception))

    def test_cli_ledger_option_with_temporary_ledger(self):
        import contextlib
        import io

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            tf.write(json.dumps({"schema": 1, "rows": []}))
            temp_path = Path(tf.name)
        try:
            # Running --check against empty ledger on current repo should exit 1 (additions present)
            stderr_buf = io.StringIO()
            with contextlib.redirect_stderr(stderr_buf):
                exit_code = GATE.main(["--check", "--ledger", str(temp_path)])
            self.assertEqual(exit_code, 1)
            self.assertIn("error: check-runtime-global-state:", stderr_buf.getvalue())
        finally:
            temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

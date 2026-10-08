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
from scripts.tests.authority_census_support import scan_source as census_scan, source_verdict, census_tree

def scan_source(path, source):
    return census_scan(GATE.scan_source, path, source)




def validate_concurrent_source(path, source):
    return GATE.validate_concurrent_source(path, source, verdict=source_verdict(str(path), source))


class RuntimeGlobalStateTests(unittest.TestCase):
    def test_moved_neutral_counters_remain_in_the_default_census(self):
        sources = {
            f"crates/{crate}/src/lib.rs": "static COUNTER: AtomicU64 = AtomicU64::new(1);\n"
            for crate in ("carrick-core", "carrick-core-abi")
        }
        with census_tree(sources) as (root, verdict):
            self.assertEqual(
                {row.file for row in GATE.discover(root, verdict=verdict)},
                set(sources),
            )


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
            [(row.kind, row.symbol) for row in rows], []
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




    def test_statement_cfg_attribute_does_not_leak_to_subsequent_findings(self):
        source = r'''
fn f() {
    #[cfg(test)]
    let _ = std::env::var("X");
    let _ = std::env::var("Y");
}
'''
        findings = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual(len(findings), 1)
        plain_y = scan_source(
            Path("crates/x/src/lib.rs"),
            'fn f() { let _ = std::env::var("Y"); }',
        )
        self.assertEqual(findings[0].fingerprint, plain_y[0].fingerprint)

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



    def test_concurrent_source_policy_rejects_ambient_runtime_accessors(self):
        source = "fn current_thread_registry() -> &'static Registry { todo!() }"
        with self.assertRaises(LedgerError):
            validate_concurrent_source(
                Path("crates/carrick-thread/src/thread.rs"), source
            )

    def test_concurrent_source_policy_rejects_run_id_env_below_launch_boundary(self):
        source = 'fn helper() { let _ = std::env::var("CARRICK_RUN_ID"); }'
        with self.assertRaises(LedgerError):
            validate_concurrent_source(
                Path("crates/carrick-kernel/src/dispatch/proctitle.rs"), source
            )
        validate_concurrent_source(
            Path("crates/carrick-kernel/src/kernel/container.rs"), source
        )

    def test_concurrent_source_policy_allows_container_keyed_endpoint_map(self):
        source = "static RUNTIME_ENDPOINTS: LazyLock<Map<ContainerId, Endpoint>> = init();"
        validate_concurrent_source(
            Path("crates/carrick-thread/src/thread.rs"), source
        )


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






if __name__ == "__main__":
    unittest.main()

"""Retained raw-lock fixtures, classified exclusively by Rust."""

import importlib.util
from pathlib import Path
import sys
import unittest
from scripts.tests.authority_census_support import census_tree, scan_locks

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "dispatch_lock_fixtures", ROOT / "scripts/migrate/check-dispatch-lock-authority.py"
)
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)
REPO_ROOT = ROOT
lex_rust = gate.lex_rust


def scan_tokens(tokens, path):
    return scan_locks(gate, path, " ".join(token.text for token in tokens))


def validate_sysv_lock_authority_rules(_, override_sources):
    sources = {
        "crates/carrick-kernel/src/dispatch/sysv.rs": "impl IpcView {"
        + "".join(
            "pub(in crate::dispatch::sysv) fn " + name + "() {}"
            for name in [
                "with_state",
                "with_state_mut",
                "lock_sysv_process",
                "with_sysv_process",
                "with_sysv_process_mut",
            ]
        )
        + "}",
        "crates/carrick-kernel/src/dispatch/sysv/lock_authority.rs": "impl SysvNamespacePermit { fn lock_paired() {} }",
    }
    sources.update(override_sources)
    with census_tree(sources) as (root, verdict):
        return gate.validate_sysv_lock_authority_rules(root, verdict=verdict)


def run_self_tests() -> bool:
    """Run comprehensive self-tests verifying red-first fail-closed behavior."""
    print("Running check-dispatch-lock-authority self-tests...")

    # Test 1: Comments and strings containing lock patterns must be ignored
    comment_source = """
    // this.proc.lock() in a comment must be ignored
    /* dispatcher.sysv_process.lock() */
    fn safe_fn() {
        let msg = "parent.proc.lock() in string";
        let _ = r#".pty_table.lock()"#;
    }
    """
    tokens = lex_rust(comment_source)
    sites = scan_tokens(tokens, "crates/carrick-runtime/src/test.rs")
    assert len(sites) == 0, f"Comments/strings produced false positives: {sites}"

    # Test 2: Test scopes (#[test] and #[cfg(test)]) must be ignored
    test_scope_source = """
    #[test]
    fn unit_test() {
        parent.proc.lock().do_something();
    }
    #[cfg(test)]
    mod tests {
        fn helper() {
            dispatcher.sysv_process.lock();
        }
    }
    """
    tokens = lex_rust(test_scope_source)
    sites = scan_tokens(tokens, "crates/carrick-runtime/src/test.rs")
    assert len(sites) == 0, f"Test scopes produced false positives: {sites}"

    # Test 3: Raw proc acquisition in production must be detected
    raw_proc_source = """
    impl SyscallDispatcher {
        fn handle_syscall(&self) {
            let mut proc = self.proc.lock();
        }
    }
    """
    tokens = lex_rust(raw_proc_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/syscall.rs")
    assert len(sites) == 1, f"Expected 1 raw proc site, got {len(sites)}"
    assert sites[0].category == "proc"
    assert sites[0].ordinal == 1
    assert (
        sites[0].id
        == "crates/carrick-kernel/src/dispatch/syscall.rs::SyscallDispatcher::handle_syscall::proc#1"
    )

    # Test 4: Raw sysv_process boundary is detected
    sysv_proc_source = """
    impl SyscallDispatcher {
        pub fn lock_sysv_process(&self) {
            let guard = self.sysv_process.lock();
        }
    }
    """
    tokens = lex_rust(sysv_proc_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/sysv.rs")
    assert len(sites) == 1, f"Expected 1 sysv_process site, got {len(sites)}"
    assert sites[0].category == "sysv_process"
    assert sites[0].ordinal == 1

    # Test 5: Raw sysv_namespace boundary in lock_authority.rs is detected
    sysv_ns_source = """
    impl SysvNamespacePermit {
        pub fn lock_paired(&self) {
            let state = self.namespace.state.lock();
        }
    }
    """
    tokens = lex_rust(sysv_ns_source)
    sites = scan_tokens(
        tokens, "crates/carrick-kernel/src/dispatch/sysv/lock_authority.rs"
    )
    assert len(sites) == 1, f"Expected 1 sysv_namespace site, got {len(sites)}"
    assert sites[0].category == "sysv_namespace"
    assert sites[0].ordinal == 1

    # Test 6: Multiple identical acquisitions in one function get distinct ordinals
    multi_source = """
    impl SyscallDispatcher {
        fn complex_fn(&self) {
            let _a = self.proc.lock();
            let _b = self.proc.lock();
        }
    }
    """
    tokens = lex_rust(multi_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/mod.rs")
    assert len(sites) == 2, f"Expected 2 sites, got {len(sites)}"
    assert sites[0].ordinal == 1
    assert sites[1].ordinal == 2
    assert sites[0].id != sites[1].id

    # Test 7: FileTable internals in kernel/objects.rs are detected
    file_table_source = """
    impl FileTable {
        fn read_next(&self) {
            let _ = self.next_fd.lock();
        }
    }
    """
    tokens = lex_rust(file_table_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/kernel/objects.rs")
    assert len(sites) == 1, f"Expected 1 file_table_internals site, got {len(sites)}"
    assert sites[0].category == "file_table_internals"

    # Adversarial Bypass Test 8: Parenthesized compound field `(x.sysv.state).lock()`
    paren_compound_source = """
    fn bypass_paren(d: &SyscallDispatcher) {
        let _g = (d.sysv.state).lock();
    }
    """
    tokens = lex_rust(paren_compound_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/sysv.rs")
    assert len(sites) == 1, f"Parenthesized compound bypass was not caught: {sites}"
    assert sites[0].category == "sysv_namespace"

    # Adversarial Bypass Test 9: Parenthesized proc field `(self.proc).read()`
    paren_proc_source = """
    impl SyscallDispatcher {
        fn bypass_proc_paren(&self) {
            let _g = (self.proc).read();
        }
    }
    """
    tokens = lex_rust(paren_proc_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/proc.rs")
    assert len(sites) == 1, f"Parenthesized proc bypass was not caught: {sites}"
    assert sites[0].category == "proc"

    # Adversarial Bypass Test 10: Local lock alias `let p = &self.proc; p.lock();`
    alias_proc_source = """
    impl SyscallDispatcher {
        fn bypass_alias(&self) {
            let p = &self.proc;
            let _g = p.lock();
        }
    }
    """
    tokens = lex_rust(alias_proc_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/mod.rs")
    assert len(sites) == 1, f"Local alias bypass was not caught: {sites}"
    assert sites[0].category == "proc"

    # Adversarial Bypass Test 11: Timed / alternative lock methods `try_lock_for`, `try_write_until`
    timed_methods_source = """
    impl SyscallDispatcher {
        fn bypass_timed(&self, d: Duration, t: Instant) {
            let _a = self.proc.try_lock_for(d);
            let _b = self.sysv_process.try_write_until(t);
        }
    }
    """
    tokens = lex_rust(timed_methods_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/mod.rs")
    assert len(sites) == 2, f"Timed methods were not caught: {sites}"
    assert sites[0].category == "proc"
    assert sites[1].category == "sysv_process"

    # Adversarial Bypass Test 12: Production code under `#[cfg(any(test, target_os = "macos"))]` must NOT be ignored
    cfg_any_source = """
    #[cfg(any(test, target_os = "macos"))]
    fn macos_prod_path(d: &SyscallDispatcher) {
        let _g = d.proc.lock();
    }
    """
    tokens = lex_rust(cfg_any_source)
    sites = scan_tokens(tokens, "crates/carrick-kernel/src/dispatch/mod.rs")
    assert len(sites) == 1, (
        f"cfg(any(...)) production code was falsely ignored: {sites}"
    )
    assert sites[0].category == "proc"

    # Test 18: Negative visibility test - pub(crate) on with_state must FAIL
    widened_vis_source = """
    impl SysvIpcNamespace {
        pub(crate) fn with_state<F, R>(&self, f: F) -> R { f(&self.state) }
    }
    """
    errs = validate_sysv_lock_authority_rules(
        REPO_ROOT,
        override_sources={
            "crates/carrick-kernel/src/dispatch/sysv.rs": widened_vis_source
        },
    )
    assert any(
        "helper 'with_state' has unauthorized visibility 'pub(crate)'" in e
        for e in errs
    ), f"Widened visibility did not fail: {errs}"

    # Test 19: Negative visibility test - pub on lock_sysv_process must FAIL
    pub_vis_source = """
    impl SyscallDispatcher {
        pub fn lock_sysv_process(&self) {}
    }
    """
    errs = validate_sysv_lock_authority_rules(
        REPO_ROOT,
        override_sources={"crates/carrick-kernel/src/dispatch/sysv.rs": pub_vis_source},
    )
    assert any(
        "helper 'lock_sysv_process' has unauthorized visibility 'pub'" in e
        for e in errs
    ), f"Public visibility did not fail: {errs}"

    # Test 20: Negative caller test - sibling module calling lock_sysv_process must FAIL
    sibling_caller_source = """
    impl SyscallDispatcher {
        fn leak_sysv(&self) {
            let _g = self.lock_sysv_process();
        }
    }
    """
    errs = validate_sysv_lock_authority_rules(
        REPO_ROOT,
        override_sources={
            "crates/carrick-kernel/src/dispatch/sysv.rs": "",
            "crates/carrick-kernel/src/dispatch/fs.rs": sibling_caller_source,
        },
    )
    assert any(
        "unauthorized cross-module reference to SysV lock authority identifier 'lock_sysv_process'"
        in e
        for e in errs
    ), f"Sibling caller did not fail: {errs}"

    # Test 21: Negative caller test - sibling module calling namespace.with_state must FAIL
    sibling_ns_caller_source = """
    fn leak_ns(d: &SyscallDispatcher) {
        d.sysv.with_state(|_| ());
    }
    """
    errs = validate_sysv_lock_authority_rules(
        REPO_ROOT,
        override_sources={
            "crates/carrick-kernel/src/dispatch/sysv.rs": "",
            "crates/carrick-kernel/src/dispatch/net.rs": sibling_ns_caller_source,
        },
    )
    assert any("unauthorized cross-module call to 'with_state'" in e for e in errs), (
        f"Sibling namespace caller did not fail: {errs}"
    )

    # Test 22: Negative caller test - sibling module referencing SysvNamespacePermit must FAIL
    sibling_permit_source = """
    fn leak_permit(_p: &SysvNamespacePermit) {}
    """
    errs = validate_sysv_lock_authority_rules(
        REPO_ROOT,
        override_sources={
            "crates/carrick-kernel/src/dispatch/sysv.rs": "",
            "crates/carrick-kernel/src/dispatch/mod.rs": sibling_permit_source,
        },
    )
    assert any(
        "unauthorized cross-module reference to SysV lock authority identifier 'SysvNamespacePermit'"
        in e
        for e in errs
    ), f"Sibling permit reference did not fail: {errs}"

    return True


class DispatchLockFixtures(unittest.TestCase):
    def test_retained_lock_fixtures(self):
        self.assertTrue(run_self_tests())


class ProductionSysvOwners(unittest.TestCase):
    def source(self, test_only=False):
        return 'impl IpcView {' + ''.join(
            ('#[cfg(test)] ' if test_only and name == 'with_sysv_process_mut' else '')
            + 'pub(in crate::dispatch::sysv) fn ' + name + '() {}'
            for name in ['with_state', 'with_state_mut', 'lock_sysv_process', 'with_sysv_process', 'with_sysv_process_mut']
        ) + '}'

    def check(self, source):
        return validate_sysv_lock_authority_rules(REPO_ROOT, {
            'crates/carrick-kernel/src/dispatch/sysv.rs': source,
        })

    def test_rust_excluded_test_helper_is_not_a_required_production_owner(self):
        self.assertEqual(self.check(self.source(test_only=True)), [])

    def test_production_helper_discovery_remains_required(self):
        source = self.source(test_only=True).replace(
            'pub(in crate::dispatch::sysv) fn with_sysv_process() {}', ''
        )
        self.assertTrue(any('missing SysV rule owner/helper discovery' in error for error in self.check(source)))

    def test_mutating_helper_if_production_keeps_its_visibility_rule(self):
        source = self.source().replace(
            'pub(in crate::dispatch::sysv) fn with_sysv_process_mut()',
            'pub(crate) fn with_sysv_process_mut()'
        )
        self.assertTrue(any('with_sysv_process_mut' in error and 'unauthorized visibility' in error for error in self.check(source)))

"""Retained scanners must reject ambiguous test scope before discarding sites."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts/migrate' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

ABORT = load('check-runtime-aborts')
GLOBAL = load('check-runtime-global-state')
LOCK = load('check-dispatch-lock-authority')

class RestrictedTestScope(unittest.TestCase):
    def scanners(self):
        path = 'crates/carrick-kernel/src/dispatch/poll.rs'
        return (
            lambda source: ABORT.scan_abort_source(path, source),
            lambda source: GLOBAL.scan_source(path, source),
            lambda source: LOCK.scan_tokens(LOCK.lex_rust(source), path),
        )

    def test_rebound_test_rejected_by_every_retained_scanner(self):
        self.reject('use tracing::instrument as test; #[test] fn hidden() { std::process::abort(); this.proc.lock(); std::env::var("X"); }', 'import may rebind built-in test')

    def test_glob_test_rejected_by_every_retained_scanner(self):
        self.reject('use tracing::*; #[test] fn hidden() { std::process::abort(); this.proc.lock(); }', 'glob import makes test exclusion ambiguous')

    def test_qualified_test_rejected_by_every_retained_scanner(self):
        self.reject('#[tracing::test] fn hidden() { std::process::abort(); this.proc.lock(); }', 'qualified test attribute is unsupported')

    def test_conditional_test_rejected_by_every_retained_scanner(self):
        self.reject('#[cfg_attr(all(), test)] fn hidden() { std::process::abort(); this.proc.lock(); }', 'conditional test attribute is unsupported')

    def test_opaque_test_rejected_by_every_retained_scanner(self):
        self.reject('pass! { @ #[cfg(test)] fn hidden() { std::process::abort(); this.proc.lock(); } }', 'test exclusion in macro input is unsupported')

    def reject(self, source, message):
        for scanner in self.scanners():
            with self.subTest(scanner=scanner):
                with self.assertRaisesRegex(Exception, message):
                    scanner(source)

    def test_builtin_scope_remains_valid_with_local_test_glob(self):
        for scanner in self.scanners():
            scanner('#[cfg(test)] mod tests { use super::*; #[test] fn hidden() { std::process::abort(); this.proc.lock(); } }')

    def test_diverging_function_body_is_parsed_scope(self):
        for scanner in self.scanners():
            scanner('fn finish() -> ! { #[cfg(test)] std::panic::resume_unwind(Box::new("test")); #[cfg(not(test))] carrick_fatal!("runtime", "fail"); }')

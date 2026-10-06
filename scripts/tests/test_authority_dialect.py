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
from scripts.tests.authority_census_support import scan_source, scan_locks

class RestrictedTestScope(unittest.TestCase):
    def scanners(self):
        path = 'crates/carrick-kernel/src/dispatch/poll.rs'
        return (
            lambda source: scan_source(ABORT.scan_abort_source, path, source),
            lambda source: scan_source(GLOBAL.scan_source, path, source),
            lambda source: scan_locks(LOCK, path, source),
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

class RustVerdictContract(unittest.TestCase):
    path = 'crates/carrick-kernel/src/dispatch/poll.rs'

    def test_every_scanner_rejects_missing_verdict(self):
        source = 'fn hidden() { std::process::abort(); this.proc.lock(); std::env::var("CARRICK_RUN_ID"); }'
        for scanner in (
            lambda: ABORT.scan_abort_source(self.path, source),
            lambda: GLOBAL.scan_source(self.path, source),
            lambda: LOCK.scan_tokens(LOCK.lex_rust(source), self.path),
            lambda: GLOBAL.validate_concurrent_source(Path(self.path), source),
        ):
            with self.subTest(scanner=scanner):
                with self.assertRaisesRegex(Exception, 'missing Rust census verdict'):
                    scanner()

    def test_all_retained_cli_entries_consume_every_dialect_rejection(self):
        import json, subprocess, tempfile
        from scripts.tests.authority_census_support import census_json
        cases = [
            ('#[cfg_attr(all(), path="selected.rs")] mod hidden;', 'conditional module path'),
            ('#[macro_use(test)] extern crate custom_test; #[test] fn hidden() { std::process::abort(); this.proc.lock(); }', 'macro_use import is unresolved'),
            ('#[tracing::instrument(fields(value = std::env::var("CARRICK_RUN_ID")))] fn hidden() {}', 'unaudited attribute'),
            ('use std::process::abort as finish; fn hidden() { finish(); }', 'renamed protected import'),
            ('use std::process::{self}; fn hidden() { process::abort(); }', 'canonical path'),
            ('use std::env::*; fn hidden() { var("CARRICK_RUN_ID"); }', 'canonical path'),
            ('#[derive(::clap::Parser)] struct Data { #[arg(env="CARRICK_RUN_ID")] run: String }', 'generated environment read'),
            ('use custom_derive::Clone; #[derive(Clone)] struct Data;', 'compiler derive'),
            ('pass! { mod hidden; }', 'module selection in macro input'),
        ]
        for source, message in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                file = root / self.path
                file.parent.mkdir(parents=True)
                file.write_text(source)
                (file.parent / 'selected.rs').write_text('fn hidden() {}')
                proof = root / 'verdict.json'
                proof.write_text(json.dumps(census_json(root)))
                for checker in [ABORT, GLOBAL, LOCK]:
                    result = subprocess.run([sys.executable, checker.__file__, '--root', str(root), '--census-verdict', str(proof)], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, checker.__file__)
                    self.assertIn(message, result.stderr, checker.__file__)

    def test_changed_source_missing_file_and_changed_file_set_fail_closed(self):
        from scripts.tests.authority_census_support import census_tree
        source = 'fn shown() { this.proc.lock(); }'
        with census_tree({self.path: source}) as (root, verdict):
            for scanner in (
                lambda text: ABORT.scan_abort_source(self.path, text, verdict=verdict),
                lambda text: GLOBAL.scan_source(self.path, text, verdict=verdict),
                lambda text: LOCK.scan_tokens(LOCK.lex_rust(text), self.path, source=text, verdict=verdict),
            ):
                with self.assertRaisesRegex(Exception, 'stale Rust census source'):
                    scanner(source + ' fn changed() {}')
            with self.assertRaisesRegex(Exception, 'missing Rust census file verdict'):
                ABORT.scan_abort_source('crates/absent/src/lib.rs', source, verdict=verdict)
            (root / self.path).with_name('added.rs').write_text('fn added() {}')
            for scanner in (ABORT.discover_runtime_aborts, GLOBAL.discover, GLOBAL.validate_concurrent_tree, LOCK.scan_sources, LOCK.validate_sysv_lock_authority_rules):
                with self.assertRaisesRegex(Exception, 'source file set changed'):
                    scanner(root, verdict=verdict)

    def test_non_ascii_positions_and_item_scope_come_from_rust(self):
        from scripts.tests.authority_census_support import source_verdict
        source = 'const TEXT: &str = "é🌳"; #[cfg(test)] fn hidden() { std::process::abort(); this.proc.lock(); } fn shown() { std::process::abort(); this.proc.lock(); }'
        verdict = source_verdict(self.path, source)
        production = verdict.production_source(self.path, source)
        self.assertEqual(len(production), len(source))
        self.assertEqual(production.index('fn shown'), source.index('fn shown'))
        self.assertEqual(len(ABORT.scan_abort_source(self.path, source, verdict=verdict)), 1)
        self.assertEqual(len(LOCK.scan_tokens(LOCK.lex_rust(source), self.path, source=source, verdict=verdict)), 1)

    def test_changed_policy_invalidates_verdict(self):
        import copy, tempfile
        from scripts.tests.authority_census_support import source_verdict
        data = copy.deepcopy(source_verdict(self.path, 'fn shown() {}').data)
        with tempfile.TemporaryDirectory() as directory:
            data['tool_root'] = directory
            with self.assertRaisesRegex(Exception, 'stale Rust census policy'):
                ABORT.census_verdict.CensusVerdict(data)

    def test_historical_verdict_cannot_exempt_working_source(self):
        import copy
        from scripts.tests.authority_census_support import source_verdict
        data = copy.deepcopy(source_verdict(self.path, 'fn shown() {}').data)
        data['dialect'] = 'historical_base'
        with self.assertRaisesRegex(Exception, 'strict Rust dialect verdict required'):
            ABORT.census_verdict.CensusVerdict(data)

    def test_changed_parent_invalidates_unchanged_scanned_child(self):
        from scripts.tests.authority_census_support import census_tree
        parent = 'crates/carrick-kernel/src/lib.rs'
        source = 'fn hidden() { std::process::abort(); this.proc.lock(); }'
        with census_tree({parent: '#[cfg(test)] #[path="dispatch/poll.rs"] mod tests;', self.path: source}) as (root, verdict):
            self.assertEqual(ABORT.scan_abort_source(self.path, source, verdict=verdict), ())
            (root / parent).write_text('#[path="dispatch/poll.rs"] mod production;')
            for scanner in (
                lambda: ABORT.scan_abort_source(self.path, source, verdict=verdict),
                lambda: GLOBAL.scan_source(self.path, source, verdict=verdict),
                lambda: LOCK.scan_tokens(LOCK.lex_rust(source), self.path, source=source, verdict=verdict),
            ):
                with self.assertRaisesRegex(Exception, 'stale Rust census source'):
                    scanner()

    def test_standalone_probe_scope_is_not_a_test_exemption(self):
        from scripts.tests.authority_census_support import census_tree
        path = 'crates/carrick-vmm-kvm/src/bin/probe.rs'
        source = 'fn probe() { std::process::abort(); }'
        with census_tree({path: source}) as (root, verdict):
            self.assertFalse(verdict.data['files'][path]['product_profile'])
            self.assertTrue(verdict.data['files'][path]['production'])
            self.assertEqual(len(ABORT.discover_runtime_aborts(root, verdict=verdict)), 1)

    def test_struct_field_exclusion_does_not_hide_production_sibling(self):
        from scripts.tests.authority_census_support import source_verdict
        source = '\n'.join([
            'struct State { #[cfg(test)] hidden: String, trace: bool }',
            'impl State { fn new() -> Self { Self {',
            '#[cfg(test)] hidden: std::env::var("HIDDEN").unwrap_or_default(),',
            'trace: std::env::var_os("CARRICK_TRACE_TRAPS").is_some(),',
            '} } }',
        ])
        verdict = source_verdict(self.path, source)
        findings = GLOBAL.scan_source(self.path, source, verdict=verdict)
        self.assertEqual([(f.kind, f.argument) for f in findings], [('env_var_os', 'CARRICK_TRACE_TRAPS')])

    def test_policy_changed_after_verdict_load_is_rejected_at_scanner_entry(self):
        import copy, shutil, tempfile
        from scripts.tests.authority_census_support import source_verdict
        source = 'fn shown() {}'
        data = copy.deepcopy(source_verdict(self.path, source).data)
        with tempfile.TemporaryDirectory() as directory:
            for file in data['inputs']:
                target = Path(directory) / file
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(Path(data['tool_root']) / file, target)
            data['tool_root'] = directory
            verdict = ABORT.census_verdict.CensusVerdict(data)
            (Path(directory) / 'scripts/migrate/authority-attribute-allowlist.json').write_text('[]')
            with self.assertRaisesRegex(Exception, 'stale Rust census policy'):
                ABORT.scan_abort_source(self.path, source, verdict=verdict)

    def test_tree_changed_during_scanning_fails_closed(self):
        from unittest.mock import patch
        from scripts.tests.authority_census_support import census_tree
        source = 'fn shown() { this.proc.lock(); }'
        for checker, entry, pattern in (
            (ABORT, ABORT.discover_runtime_aborts, '_scan_production_aborts'),
            (GLOBAL, GLOBAL.discover, '_scan_production_globals'),
            (LOCK, LOCK.scan_sources, '_scan_production_tokens'),
        ):
            with self.subTest(checker=checker.__name__), census_tree({self.path: source}) as (root, verdict):
                original = getattr(checker, pattern)
                def change_tree(*args, **kwargs):
                    (root / self.path).with_name('added.rs').write_text('fn added() {}')
                    return original(*args, **kwargs)
                with patch.object(checker, pattern, side_effect=change_tree):
                    with self.assertRaisesRegex(Exception, 'source file set changed'):
                        entry(root, verdict=verdict)

    def test_round8_classes_rejected_at_every_retained_cli(self):
        import json, subprocess, tempfile
        from scripts.tests.authority_census_support import census_json
        cases = [
            (self.path, 'use custom_macros::serde::{self}; #[derive(serde::Serialize)] struct Data;', 'audited macro binding'),
            (self.path, 'use custom_macros::clap::{self}; #[derive(clap::Parser)] struct Data;', 'audited macro binding'),
            (self.path, 'fn hidden() { let _ = (std::env::var)("CARRICK_RUN_ID"); }', 'protected operation shape'),
            (self.path, 'fn hidden() { (std::process::abort)(); }', 'protected operation shape'),
            (self.path, 'fn hidden() { let read = std::env::var::<&str>; let _ = read("CARRICK_RUN_ID"); }', 'protected operation shape'),
            (self.path, 'fn hidden() { let acquire = FileTable::read_open_files; }', 'protected operation shape'),
            (self.path, 'fn hidden() { let callbacks = Callbacks { read: std::env::var::<&str> }; }', 'protected operation shape'),
            (self.path, 'use std::env::var; fn hidden() { for var in [] {} let read = var; }', 'protected operation shape'),
            (self.path, 'mod core { mod mem {} } fn hidden() { core::mem::offset_of!(Data, args); }', 'protected operation shape'),
            (self.path, 'fn hidden() { wrap!(std::env::var("CARRICK_RUN_ID")); }', 'protected operation shape'),
            (self.path, 'fn hidden() { ::std::vec![std::env::var]; }', 'protected operation shape'),
            (self.path, 'pass! { OpenDescriptionRef::clone }', 'protected operation shape'),
            (self.path, '#[derive(::serde::Deserialize)] struct Data { #[serde(skip, default = "std::env::vars")] hidden: std::env::Vars }', 'protected callback'),
            (self.path, 'use custom_macros::Clone::{self}; #[derive(Clone)] struct Data;', 'compiler derive'),
            ('crates/carrick-cli/src/args.rs', 'mod extra { #[derive(::clap::Parser)] struct RunArgs { #[arg(env="CARRICK_EXEC_BACKEND")] backend: String } }', 'generated environment read'),
            ('crates/carrick-cli/src/args.rs', 'fn hidden() { #[derive(::clap::Parser)] struct RunArgs { #[arg(env="CARRICK_EXEC_BACKEND")] backend: String } }', 'generated environment read'),
        ]
        for path, source, message in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                file = root / path
                file.parent.mkdir(parents=True)
                file.write_text(source)
                if '/carrick-cli/' in path:
                    (file.parent / 'main.rs').write_text('mod args;')
                proof = root / 'verdict.json'
                proof.write_text(json.dumps(census_json(root)))
                for checker in [ABORT, GLOBAL, LOCK]:
                    result = subprocess.run([sys.executable, checker.__file__, '--root', str(root), '--census-verdict', str(proof)], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, checker.__file__)
                    self.assertIn(message, result.stderr, checker.__file__)


class CanonicalCallPatterns(unittest.TestCase):
    def test_plain_exact_item_imports_reach_the_unique_patterns(self):
        aborts = scan_source(ABORT.scan_abort_source, 'crates/carrick-runtime/src/lib.rs', 'use std::process::abort; fn finish() { abort(); }')
        self.assertEqual(len(aborts), 1)
        globals = scan_source(GLOBAL.scan_source, 'crates/carrick-kernel/src/lib.rs', 'use std::env::var; fn read_run() { var("CARRICK_RUN_ID"); }')
        self.assertEqual([(g.kind, g.argument) for g in globals], [('env_var', 'CARRICK_RUN_ID')])

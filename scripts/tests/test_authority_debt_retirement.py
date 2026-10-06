"""Witnesses for the landing identity before and after inventory retirement."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
from scripts.tests.authority_census_support import scan_locks, source_verdict, census_tree, census_json


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/migrate' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class RetirementWitnesses(unittest.TestCase):
    def test_blank_lines_do_not_change_lock_admission(self):
        gate = load('check-dispatch-lock-authority')
        path = 'crates/carrick-kernel/src/dispatch/proc.rs'
        source = 'fn operation() { this.proc.lock(); }'
        sites = scan_locks(gate, path, source)
        moved = scan_locks(gate, path, '\n\n' + source)
        if hasattr(gate, 'validate_inventory'):
            # The old landing identity rejects precisely this harmless move.
            self.assertEqual(gate.validate_inventory(moved, gate.build_inventory_dict(sites)), [])
        else:
            self.assertEqual([(s.item, s.category) for s in sites], [(s.item, s.category) for s in moved])

    def test_missing_sysv_owner_fails_closed(self):
        gate = load('check-dispatch-lock-authority')
        source = {'crates/carrick-kernel/src/dispatch/sysv.rs':
                  'impl IpcView { fn renamed_owner() {} }'}
        with census_tree(source) as (root, verdict):
            self.assertTrue(gate.validate_sysv_lock_authority_rules(root, verdict=verdict))

    def test_landing_has_no_position_writers(self):
        justfile = (ROOT / 'justfile').read_text()
        self.assertNotIn('\nreconcile-inventories ', justfile)
        self.assertNotIn('\nremote-recapture ', justfile)
        self.assertNotIn('\ntest-reconcile-exit-status:', justfile)

    def test_ambient_global_zero_rule_is_unconditional(self):
        gate = load('check-runtime-global-state')
        with self.assertRaises(gate.LedgerError):
            gate.validate_concurrent_source(Path('crates/carrick-kernel/src/dispatch/test.rs'),
                                           'static CURRENT_FUTEX_REGISTRY: usize = 0;', verdict=source_verdict('crates/carrick-kernel/src/dispatch/test.rs', 'static CURRENT_FUTEX_REGISTRY: usize = 0;'))

    def test_raw_abort_is_denied_unconditionally(self):
        import subprocess, tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'crates/carrick-kernel/src'
            source.mkdir(parents=True)
            (source / 'lib.rs').write_text('pub fn operation() { std::process::abort(); }')
            proof = root / "verdict.json"
            proof.write_text(json.dumps(census_json(root)))
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/migrate/check-runtime-aborts.py'),
                                     '--root', str(root), '--discover', '--census-verdict', str(proof)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('raw termination forbidden', result.stderr)



if __name__ == '__main__':
    unittest.main()

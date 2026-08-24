#!/usr/bin/env python3

import importlib.util
import sys
import unittest
from unittest import mock
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/migrate/check-carrier-only-process-invariant.py"
SPEC = importlib.util.spec_from_file_location("carrier_only_process_invariant", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


def finding(path: str, item: str, kind: str):
    return GATE.Finding(PurePosixPath(path), 1, 1, kind, kind, item)


class CarrierOnlyProcessInvariantTest(unittest.TestCase):
    def test_exact_carrier_birth_is_separate_from_other_lifecycle_calls(self):
        self.assertEqual(
            GATE.classify(
                finding(
                    "crates/carrick-cli/src/lifecycle.rs", "launch", "posix_spawn"
                )
            ),
            "carrier_birth",
        )
        self.assertEqual(
            GATE.classify(
                finding("crates/carrick-cli/src/lifecycle.rs", "stop_one", "fork")
            ),
            "forbidden_product_process_creation",
        )

    def test_runtime_and_vmm_process_creation_are_always_forbidden(self):
        cases = (
            ("crates/carrick-runtime/src/apfs.rs", "snapshot", "process_command"),
            ("crates/carrick-aarch64/src/engine.rs", "fork", "fork"),
            ("crates/carrick-vmm-kvm/src/run_elf.rs", "run", "posix_spawn"),
        )
        for path, item, kind in cases:
            with self.subTest(path=path, kind=kind):
                self.assertEqual(
                    GATE.classify(finding(path, item, kind)),
                    "forbidden_product_process_creation",
                )

    def test_guest_process_control_and_pid_liveness_probes_are_forbidden(self):
        self.assertEqual(
            GATE.classify(
                finding(
                    "crates/carrick-runtime/src/dispatch/signal.rs",
                    "bootstrap_signal_send_as",
                    "kill",
                )
            ),
            "forbidden_guest_to_host_process_control",
        )
        self.assertEqual(
            GATE.classify(
                finding(
                    "crates/carrick-runtime/src/kernel/control/endpoint.rs",
                    "process_is_alive",
                    "kill_probe",
                )
            ),
            "forbidden_guest_to_host_process_control",
        )
        self.assertEqual(
            GATE.classify(
                finding(
                    "crates/carrick-runtime/src/kernel/control/endpoint.rs",
                    "process_is_alive",
                    "kill",
                )
            ),
            "forbidden_guest_to_host_process_control",
        )

    def test_operator_and_probe_code_never_becomes_product_allowlist(self):
        self.assertEqual(
            GATE.classify(
                finding(
                    "crates/carrick-cli/src/debug.rs",
                    "run_lldb_deadline",
                    "process_command",
                )
            ),
            "operator_tool",
        )
        self.assertEqual(
            GATE.classify(
                finding(
                    "crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs",
                    "live_fork",
                    "fork",
                )
            ),
            "probe_tool",
        )
        self.assertEqual(
            GATE.classify(
                finding("crates/carrick-cli/src/debug.rs", "new_unreviewed_helper", "fork")
            ),
            "forbidden_product_process_creation",
        )
        self.assertEqual(
            GATE.classify(
                finding(
                    "crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs",
                    "new_unreviewed_helper",
                    "fork",
                )
            ),
            "forbidden_product_process_creation",
        )

    def test_every_workspace_library_source_defaults_to_product_scope(self):
        for path in (
            "crates/carrick-kernel/src/lib.rs",
            "crates/carrick-image/src/lib.rs",
            "crates/carrick-portable/src/lib.rs",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    GATE.classify(finding(path, "hidden_birth", "fork")),
                    "forbidden_product_process_creation",
                )

    def test_renamed_non_product_dependency_cannot_escape_reachability_proof(self):
        workspace = {
            "harness_alias": {
                "package": "carrick-test-support",
                "path": "crates/carrick-test-support",
            }
        }
        self.assertEqual(
            GATE.dependency_package_names(
                {"harness_alias": {"workspace": True}}, workspace
            ),
            {"carrick-test-support"},
        )
        self.assertEqual(
            GATE.dependency_package_names(
                {
                    "renamed": {
                        "package": "carrick-conformance",
                        "path": "../carrick-conformance",
                    }
                },
                {},
            ),
            {"carrick-conformance"},
        )

    def test_test_source_reachability_requires_an_exact_cfg_test_guard(self):
        self.assertTrue(
            GATE.cfg_test_includes(
                '#[cfg(test)]\n#[path = "fs/tests.rs"]\nmod tests;\n',
                "fs/tests.rs",
            )
        )
        self.assertTrue(
            GATE.cfg_test_includes('#[cfg(test)]\ninclude!("tests.rs");\n', "tests.rs")
        )
        self.assertFalse(GATE.cfg_test_includes('include!("tests.rs");\n', "tests.rs"))
        self.assertFalse(
            GATE.cfg_test_includes('#[path = "fs/tests.rs"]\nmod tests;\n', "fs/tests.rs")
        )

    def test_test_and_fixture_paths_are_classified_before_product_scope(self):
        for path in (
            "crates/carrick-runtime/src/dispatch/tests.rs",
            "crates/carrick-runtime/tests/runtime_loop.rs",
            "crates/carrick-vmm-bhyve/fixtures/bhyve-fork/src/main.rs",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    GATE.classify(finding(path, "fixture", "fork")),
                    "test_or_probe",
                )

    def test_an_unlisted_product_binary_is_not_misclassified_as_a_probe(self):
        self.assertEqual(
            GATE.classify(
                finding(
                    "crates/carrick-runtime/src/bin/carrick-kvm.rs",
                    "main",
                    "fork",
                )
            ),
            "forbidden_product_process_creation",
        )

    def test_reviewed_carrier_birth_count_cannot_expand(self):
        birth = finding(
            "crates/carrick-cli/src/lifecycle.rs", "launch", "posix_spawn"
        )
        with mock.patch.object(GATE, "scan", return_value=[birth, birth]):
            failures = GATE.failures(Path("."))
        expansions = [
            line for line in failures if "forbidden_exception_expansion" in line
        ]
        self.assertEqual(len(expansions), 1)

    def test_removed_or_renamed_exception_fails_stale_exception_audit(self):
        reviewed = []
        limits = (
            GATE.CARRIER_BIRTH_LIMITS
            | GATE.CARRIER_SUBSTRATE_LIMITS
            | GATE.REVIEWED_OPERATOR_LIMITS
            | GATE.REVIEWED_PROBE_LIMITS
        )
        omitted = next(iter(GATE.CARRIER_BIRTH_LIMITS))
        for identity, limit in limits.items():
            if identity == omitted:
                continue
            path, item, kind = identity
            reviewed.extend(finding(str(path), item, kind) for _ in range(limit))

        for replacement in (
            [],
            [finding(str(omitted[0]), f"{omitted[1]}_renamed", omitted[2])],
        ):
            with self.subTest(replacement=replacement):
                with mock.patch.object(GATE, "scan", return_value=reviewed + replacement):
                    failures = GATE.failures(Path("."))
                stale = [line for line in failures if "stale_exception" in line]
                self.assertEqual(stale, [mock.ANY])
                self.assertIn(str(omitted[0]), stale[0])
                self.assertIn(omitted[1], stale[0])


if __name__ == "__main__":
    unittest.main()

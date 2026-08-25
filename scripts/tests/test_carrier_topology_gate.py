#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "scripts/conformance/carrier-topology-gate.py"
SPEC = importlib.util.spec_from_file_location("carrier_topology_gate", PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


VALID_REPARENTED = """
CTOP1|BEGIN|target=100
CTOP1|CREATE|parent=100|child=101|time_ns=10
CTOP1|EXEC|pid=101|name=carrick|time_ns=11
CTOP1|EXIT|pid=100|time_ns=12
CTOP1|CREATE|parent=101|child=102|time_ns=13
CTOP1|EXEC|pid=102|name=carrick|time_ns=14
CTOP1|EXIT|pid=102|time_ns=15
CTOP1|EXIT|pid=101|time_ns=16
CTOP1|SUMMARY|target=100|births=2|exits=3|live=0|complete=1|errors=0
"""


class CarrierTopologyGateTests(unittest.TestCase):
    def test_lineage_survives_target_exit_and_reparenting(self):
        ledger = MODULE.parse_lineage(VALID_REPARENTED)
        self.assertEqual(ledger.target, 100)
        self.assertEqual(ledger.births, [(100, 101), (101, 102)])
        self.assertEqual(ledger.exited, {100, 101, 102})
        self.assertEqual(ledger.exec_names, {101: "carrick", 102: "carrick"})

    def test_lineage_fails_closed_on_missing_summary_error_or_unclosed_pid(self):
        with self.assertRaisesRegex(MODULE.TopologyError, "summary"):
            MODULE.parse_lineage("CTOP1|BEGIN|target=1\nCTOP1|EXIT|pid=1|time_ns=2\n")
        with self.assertRaisesRegex(MODULE.TopologyError, "DTrace error"):
            MODULE.parse_lineage(
                "CTOP1|BEGIN|target=1\n"
                "CTOP1|ERROR|cpu=0|epid=7\n"
                "CTOP1|SUMMARY|target=1|births=0|exits=0|live=1|complete=0|errors=1\n"
            )

    def test_lineage_rejects_duplicate_summary_and_out_of_order_timestamps(self):
        with self.assertRaisesRegex(MODULE.TopologyError, "one summary"):
            MODULE.parse_lineage(
                "CTOP1|BEGIN|target=1\n"
                "CTOP1|EXIT|pid=1|time_ns=2\n"
                "CTOP1|SUMMARY|target=1|births=0|exits=1|live=0|complete=1|errors=0\n"
                "CTOP1|SUMMARY|target=1|births=0|exits=1|live=0|complete=1|errors=0\n"
            )
        reordered = (
            "CTOP1|BEGIN|target=1\n"
            "CTOP1|EXIT|pid=2|time_ns=21\n"
            "CTOP1|EXIT|pid=1|time_ns=22\n"
            "CTOP1|CREATE|parent=1|child=2|time_ns=19\n"
            "CTOP1|EXEC|pid=2|name=carrick|time_ns=20\n"
            "CTOP1|SUMMARY|target=1|births=1|exits=2|live=0|complete=1|errors=0\n"
        )
        self.assertEqual(MODULE.parse_lineage(reordered).births, [(1, 2)])
        with self.assertRaisesRegex(MODULE.TopologyError, "timestamp"):
            MODULE.parse_lineage(reordered.replace("time_ns=20", "time_ns=0"))
        with self.assertRaisesRegex(MODULE.TopologyError, "duplicate child"):
            MODULE.parse_lineage(
                reordered.replace(
                    "CTOP1|EXEC|pid=2|name=carrick|time_ns=20\n",
                    "CTOP1|CREATE|parent=1|child=2|time_ns=20\n",
                )
            )
        with self.assertRaisesRegex(MODULE.TopologyError, "did not exit"):
            MODULE.parse_lineage(
                "CTOP1|BEGIN|target=1\n"
                "CTOP1|CREATE|parent=1|child=2|time_ns=1\n"
                "CTOP1|EXIT|pid=1|time_ns=2\n"
                "CTOP1|SUMMARY|target=1|births=1|exits=1|live=1|complete=0|errors=0\n"
            )

    def test_exact_birth_policy_rejects_extra_or_noncarrier_child(self):
        ledger = MODULE.parse_lineage(VALID_REPARENTED)
        MODULE.validate_birth_policy(ledger, expected_births=2, carrier_exec_name="carrick")
        with self.assertRaisesRegex(MODULE.TopologyError, "expected 1 birth"):
            MODULE.validate_birth_policy(ledger, expected_births=1, carrier_exec_name="carrick")
        ledger.exec_names[102] = "helper"
        with self.assertRaisesRegex(MODULE.TopologyError, "non-carrier"):
            MODULE.validate_birth_policy(ledger, expected_births=2, carrier_exec_name="carrick")

    def test_state_census_rejects_stopped_and_zombie_rows(self):
        rows = MODULE.parse_ps_states("10 S\n11 T\n12 Z+\n")
        with self.assertRaisesRegex(MODULE.TopologyError, "T/Z"):
            MODULE.reject_stopped_or_zombie(rows, {10, 11, 12})
        MODULE.reject_stopped_or_zombie({10: "S", 11: "R+"}, {10, 11})

    def test_live_state_census_graces_terminal_publication_race_but_is_bounded(self):
        pending = MODULE.advance_live_state_census(
            {10: "S", 11: "Z"}, {10, 11}, {}, 5.0, zombie_grace=1.0
        )
        self.assertEqual(pending, {11: 5.0})
        pending = MODULE.advance_live_state_census(
            {10: "S", 11: "Z"}, {10, 11}, pending, 5.999, zombie_grace=1.0
        )
        self.assertEqual(pending, {11: 5.0})
        with self.assertRaisesRegex(MODULE.TopologyError, "retained Z state"):
            MODULE.advance_live_state_census(
                {10: "S", 11: "Z"}, {10, 11}, pending, 6.0, zombie_grace=1.0
            )

        # Once proc:::exit is visible, the PID leaves the DTrace-live set and
        # its pending publication-race row is pruned.
        self.assertEqual(
            MODULE.advance_live_state_census(
                {10: "S", 11: "Z"}, {10}, pending, 5.5, zombie_grace=1.0
            ),
            {},
        )
        with self.assertRaisesRegex(MODULE.TopologyError, "forbidden T state"):
            MODULE.advance_live_state_census(
                {10: "T"}, {10}, {}, 5.0, zombie_grace=1.0
            )

    def test_terminal_census_allows_only_dtrace_proven_exited_zombies(self):
        self.assertEqual(
            MODULE.classify_terminal_states(
                {10: "Z", 11: "R"}, {10, 11}, {10}
            ),
            {10},
        )
        with self.assertRaisesRegex(MODULE.TopologyError, "unproven-zombie"):
            MODULE.classify_terminal_states({10: "Z"}, {10}, set())
        with self.assertRaisesRegex(MODULE.TopologyError, "stopped"):
            MODULE.classify_terminal_states({10: "T"}, {10}, {10})

    def test_partial_lineage_cleanup_targets_unexited_owned_pids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "partial.raw"
            path.write_text(
                "CTOP1|BEGIN|target=10\n"
                "CTOP1|CREATE|parent=10|child=11|time_ns=1\n"
                "CTOP1|CREATE|parent=11|child=12|time_ns=2\n"
                "CTOP1|EXIT|pid=10|time_ns=3\n",
                encoding="utf-8",
            )
            self.assertEqual(MODULE._partial_all_pids(path), {10, 11, 12})
            self.assertEqual(MODULE._partial_live_pids(path), {11, 12})

    def test_clean_source_and_embedded_marker_must_match_exactly(self):
        marker = {"head": "a" * 40, "tree": "b" * 40, "state": "clean"}
        MODULE.validate_source_binding("a" * 40, "b" * 40, False, marker)
        with self.assertRaisesRegex(MODULE.TopologyError, "tracked source is dirty"):
            MODULE.validate_source_binding("a" * 40, "b" * 40, True, marker)
        with self.assertRaisesRegex(MODULE.TopologyError, "does not match"):
            MODULE.validate_source_binding("c" * 40, "b" * 40, False, marker)
        with self.assertRaisesRegex(MODULE.TopologyError, "not clean"):
            MODULE.validate_source_binding(
                "a" * 40,
                "b" * 40,
                False,
                {**marker, "state": "dirty"},
            )

    def test_arm_birth_contract_and_trace_command_are_explicit(self):
        self.assertEqual(
            MODULE.ARM_BIRTHS,
            {
                "foreground-private": 0,
                "tty": 0,
                "logical-fork-storm": 0,
                "detached": 1,
                "docker-api": MODULE.API_CARRIER_COUNT,
            },
        )
        command = MODULE.trace_command(
            Path("/signed/carrick"),
            Path("/durable/lineage.d"),
            Path("/tmp/arm.raw"),
            ["run", "image", "/bin/true"],
        )
        self.assertEqual(command[:2], ["/signed/carrick", "trace"])
        self.assertIn("--script", command)
        self.assertNotIn("dtrace", command[0])

    def test_api_chunk_and_exec_frame_parsers_preserve_exact_bytes(self):
        self.assertEqual(
            MODULE._decode_chunked(b"6\r\nmarker\r\n6\r\n-bytes\r\n0\r\n\r\n"),
            b"marker-bytes",
        )
        frames = (
            b"\x01\0\0\0\0\0\0\x03out"
            b"\x02\0\0\0\0\0\0\x03err"
        )
        self.assertEqual(MODULE.parse_docker_exec_frames(frames), (b"out", b"err"))


if __name__ == "__main__":
    unittest.main()

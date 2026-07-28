#!/usr/bin/env python3

import copy
import dataclasses
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import direct_binding_mechanism as mechanism


def nativeperf_lines(
    *,
    gateway: int,
    direct: int,
    indirect: int,
    fault: int = 0,
    unsupported: int = 0,
) -> list[str]:
    syscall = gateway - direct - indirect - fault - unsupported
    if syscall < 0:
        raise ValueError("invalid synthetic exit vector")
    prefix = "NATIVEPERF1|thread|complete=1|pid=42|tid=42|era=1|frame="
    return [
        prefix
        + f"core|gateway_entries={gateway}|reconciled_exits={gateway}|overflowed=0|"
        "thread_cpu_ns=40",
        prefix
        + f"exits|exit_syscall={syscall}|exit_resolve_direct={direct}|"
        f"exit_resolve_indirect={indirect}|exit_sensitive=0|exit_fault={fault}|"
        f"exit_kick=0|exit_stale_generation=0|exit_unsupported={unsupported}",
        prefix
        + "sensitive|sensitive_exclusive=0|sensitive_read_tpidr=0|"
        "sensitive_write_tpidr=0|sensitive_read_ctr=0|sensitive_read_dczid=0|"
        "sensitive_dc_zva=0|sensitive_dc_cvau=0|sensitive_ic_ivau=0",
        prefix
        + f"phases-a|phase_prepare_index_ns=10|phase_prepare_index_count={gateway}|"
        "phase_translate_ns=3|phase_translate_count=1|phase_translated_run_ns=20|"
        f"phase_translated_run_count={gateway}|phase_finish_exit_ns=4|"
        f"phase_finish_exit_count={gateway}",
        prefix
        + "phases-b|phase_sensitive_emulation_ns=0|"
        "phase_sensitive_emulation_count=0|phase_syscall_dispatch_ns=5|"
        f"phase_syscall_dispatch_count={syscall}|phase_loop_quiesce_ns=2|"
        f"phase_loop_quiesce_count={gateway}|phase_blocked_ns=0|"
        f"phase_blocked_count={syscall}|phase_blocked_cpu_ns=0",
        prefix
        + f"resolver-thread|translate_phase_nested_ns=3|resolver_exits={direct + indirect}|"
        f"one_entry_hits=0|gateway_entries={gateway}|syscall_exits={syscall}|"
        f"direct_resolver_exits={direct}",
        prefix
        + "resolver-process|translations=1|duplicate_publications=0|"
        "cache_lookups=1|cache_lookup_hits=0|invalidated_blocks=0",
        prefix
        + "resolver-times|nested_translation_ns=3|nested_translation_decode_ns=1|"
        "nested_translation_plan_ns=1|nested_translation_emit_ns=1|"
        "nested_translation_publication_ns=0",
        prefix + "cache-gauge|cache_used_bytes=64|cache_capacity_bytes=4096",
        prefix
        + "process|startup_wall_ns=100|startup_cpu_ns=10|process_cpu_ns=40",
        "NATIVEPERF1|supervisor|self_cpu_ns=0|children_cpu_ns=40",
    ]


def raw_lines(
    *,
    gateway: int,
    direct: int,
    indirect: int,
    eligible: int,
    publish: int,
    clear: int = 0,
    validation: int = 0,
    fault: int = 0,
    unsupported: int = 0,
) -> list[str]:
    syscall = gateway - direct - indirect - fault - unsupported
    rows = [
        f"DSRPROF1|count|phase=gateway-total|pid=42|value={gateway}",
        f"DSRPROF1|count|phase=translation-attempts|pid=42|value={direct}",
        f"DSRPROF1|count|phase=direct-total|pid=42|kind=1|value={direct}",
        f"DSRPROF1|count|phase=indirect-total|pid=42|kind=2|value={indirect}",
    ]
    for kind, value in [
        (1, syscall),
        (2, direct),
        (3, indirect),
        (4, fault),
        (5, 0),
        (6, 0),
        (7, unsupported),
    ]:
        rows.append(
            f"DSRPROF1|count|phase=gateway-kind|pid=42|kind={kind}|value={value}"
        )
    for kind, value in [
        (7, eligible),
        (8, publish),
        (9, 0),
        (10, clear),
        (11, validation),
        (12, 1),
    ]:
        rows.append(
            f"DSRPROF1|count|phase=binding-event|pid=42|kind={kind}|value={value}"
        )
    rows.extend(
        [
            f"DSRPROF1|count|phase=binding-cell|pid=42|cell_va=0x8000|value={eligible}",
            f"DSRPROF1|count|phase=binding-publish-cell|pid=42|cell_va=0x8000|value={publish}",
            f"DSRPROF1|count|phase=binding-clear-cell|pid=42|cell_va=0x8000|kind=1|value={clear}",
            "DSRPROF1|count|phase=binding-unit|pid=42|unit_id=0x1234|"
            "record_count=1|binding_data_bytes=8|value=1",
            "DSRPROF1|complete|profile=dsr-indirect|bounded=0|target_exit_reason=1",
        ]
    )
    return rows


class MechanismFixture:
    def __init__(self, root: pathlib.Path):
        self.root = root

    def receipt(
        self,
        variant: str,
        *,
        gateway: int,
        direct: int,
        indirect: int,
        eligible: int,
        publish: int,
        clear: int = 0,
        validation: int = 0,
        status: int = 0,
        bounded: bool = False,
        build_stdout: str = "ok\nBUILD_OK\n",
        fault: int = 0,
        unsupported: int = 0,
    ) -> mechanism.CaptureReceipt:
        directory = self.root / variant
        directory.mkdir(parents=True, exist_ok=True)
        run_id = f"mechanism-{variant}-1"
        capture_variant = (
            "precursor" if variant.startswith("precursor") else "candidate"
        )
        raw = directory / "trace.log"
        summary = directory / "summary.jsonl"
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        raw_rows = raw_lines(
            gateway=gateway,
            direct=direct,
            indirect=indirect,
            eligible=eligible,
            publish=publish,
            clear=clear,
            validation=validation,
            fault=fault,
            unsupported=unsupported,
        )
        if bounded:
            raw_rows[-1] = (
                "DSRPROF1|complete|profile=dsr-indirect|bounded=1|"
                "target_exit_reason=1"
            )
        raw.write_text("\n".join(raw_rows) + "\n")
        summary_rows = mechanism.synthetic_summary_rows(
            raw_rows,
            run_id=run_id,
            git_sha="a" * 40,
            binary_sha256="b" * 64,
            host="fixture-host",
            bounded=bounded,
        )
        summary.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in summary_rows)
        )
        stdout.write_text(build_stdout)
        stderr.write_text(
            "diagnostic before protocol\n"
            + "\n".join(
                nativeperf_lines(
                    gateway=gateway,
                    direct=direct,
                    indirect=indirect,
                    fault=fault,
                    unsupported=unsupported,
                )
            )
            + "\ndiagnostic after protocol\n"
        )
        controlled = {
            key: (
                "1"
                if capture_variant == "candidate"
                and key
                in {
                    "CARRICK_DSR_ARTIFACT_SPIKE",
                    "CARRICK_DSR_SHARED_TRANSLATION",
                    "CARRICK_DSR_DIRECT_BINDINGS",
                    "CARRICK_DSR_PROFILE",
                }
                else (
                    "1"
                    if capture_variant == "precursor"
                    and key
                    in {
                        "CARRICK_DSR_ARTIFACT_SPIKE",
                        "CARRICK_DSR_SHARED_TRANSLATION",
                        "CARRICK_DSR_PROFILE",
                    }
                    else None
                )
            )
            for key in mechanism.native_go_build.PERFORMANCE_CONTROL_KEYS
        }
        common = {
            "git_commit": "a" * 40,
            "git_status": [],
            "binary_sha256": "b" * 64,
            "host": "fixture-host",
            "image": {
                "id": "sha256:image",
                "repo_digests": ["image@sha256:digest"],
            },
            "controlled_environment": controlled,
            "foreign_processes": [],
            "docker_oracles": [],
        }
        payload = {
            "schema": mechanism.RECEIPT_SCHEMA,
            "variant": capture_variant,
            "run_id": run_id,
            "argv": ["carrick", "trace", "--profile", "dsr-indirect"],
            "workload": mechanism.native_go_build.guest_script(),
            "provenance": {"pre": common, "post": copy.deepcopy(common)},
            "command": {
                "status": status,
                "build_ok": build_stdout.splitlines().count("BUILD_OK") == 1,
            },
            "cleanup": {
                "status": 0,
                "stdout": "",
                "stderr": "",
                "descendants": [],
            },
            "summary": {
                "run_id": run_id,
                "git_sha": "a" * 40,
                "git_dirty": False,
                "binary_sha256": "b" * 64,
                "host": "fixture-host",
                "completion": {
                    "complete": not bounded,
                    "bounded": bounded,
                    "target_exit_reason": 1,
                    "high_cardinality_overflow": False,
                    "incomplete_pairs": 0,
                    "cardinality": {
                        "indirect_sources": 0,
                        "indirect_pairs": 0,
                    },
                    "drops": {
                        "principal_drops": 0,
                        "aggregation_drops": 0,
                        "dynamic_drops": 0,
                        "other_drops": 0,
                        "interrupted": False,
                    },
                },
            },
            "environment_sha256": mechanism.sha256_json(controlled),
            "image_sha256": mechanism.sha256_json(common["image"]),
            "artifacts": {
                name: mechanism.bind_artifact(path)
                for name, path in {
                    "raw_trace": raw,
                    "summary_jsonl": summary,
                    "command_stdout": stdout,
                    "command_stderr": stderr,
                }.items()
            },
        }
        receipt_path = directory / "receipt.json"
        mechanism.write_json_atomic(receipt_path, payload)
        return mechanism.parse_receipt(receipt_path)


class DirectBindingMechanismTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = MechanismFixture(pathlib.Path(self.temporary.name))

    def good_pair(self):
        return (
            self.fixture.receipt(
                "precursor",
                gateway=200,
                direct=100,
                indirect=20,
                eligible=100,
                publish=1,
            ),
            self.fixture.receipt(
                "candidate",
                gateway=100,
                direct=4,
                indirect=20,
                eligible=4,
                publish=1,
            ),
        )

    def test_complete_vector_and_eligible_collapse_are_published(self):
        precursor, candidate = self.good_pair()

        result = mechanism.compare(precursor, candidate)

        self.assertTrue(result["accepted"])
        self.assertEqual(result["collapse"], {"S": 96, "D": 96, "G": 100})
        self.assertEqual(
            result["runs"]["candidate"]["binding_events"],
            {str(kind): value for kind, value in [(7, 4), (8, 1), (9, 0), (10, 0), (11, 0), (12, 1)]},
        )

    def test_missing_summary_drop_or_provenance_field_rejects_the_pair(self):
        precursor, candidate = self.good_pair()
        payload = json.loads(candidate.path.read_text())
        del payload["summary"]["completion"]["drops"]
        mechanism.write_json_atomic(candidate.path, payload)

        with self.assertRaisesRegex(mechanism.EvidenceError, "drops"):
            mechanism.compare(precursor, mechanism.parse_receipt(candidate.path))

    def test_bounded_interrupted_or_nonzero_status_rejects_the_pair(self):
        precursor, _ = self.good_pair()
        bounded = self.fixture.receipt(
            "candidate-bounded",
            gateway=100,
            direct=4,
            indirect=20,
            eligible=4,
            publish=1,
            bounded=True,
        )
        nonzero = self.fixture.receipt(
            "candidate-nonzero",
            gateway=100,
            direct=4,
            indirect=20,
            eligible=4,
            publish=1,
            status=9,
        )

        with self.assertRaisesRegex(mechanism.EvidenceError, "bounded"):
            mechanism.compare(precursor, bounded)
        with self.assertRaisesRegex(mechanism.EvidenceError, "command status"):
            mechanism.compare(precursor, nonzero)

    def test_build_ok_must_be_an_exact_stdout_line(self):
        precursor, _ = self.good_pair()
        candidate = self.fixture.receipt(
            "candidate-marker",
            gateway=100,
            direct=4,
            indirect=20,
            eligible=4,
            publish=1,
            build_stdout="prefix-BUILD_OK-suffix\n",
        )

        with self.assertRaisesRegex(mechanism.EvidenceError, "exact BUILD_OK"):
            mechanism.compare(precursor, candidate)

    def test_capture_receipt_binds_artifact_hashes_and_frozen_provenance(self):
        precursor, _ = self.good_pair()
        payload = json.loads(precursor.path.read_text())

        self.assertEqual(set(payload["artifacts"]), {
            "raw_trace",
            "summary_jsonl",
            "command_stdout",
            "command_stderr",
        })
        self.assertNotIn("profile_stderr", payload["artifacts"])
        self.assertEqual(
            payload["provenance"]["pre"], payload["provenance"]["post"]
        )
        for artifact in payload["artifacts"].values():
            self.assertRegex(artifact["sha256"], r"^[0-9a-f]{64}$")

    def test_compare_recomputes_hashes_and_rejects_receipt_mismatch(self):
        precursor, candidate = self.good_pair()
        stderr = pathlib.Path(
            json.loads(candidate.path.read_text())["artifacts"]["command_stderr"][
                "path"
            ]
        )
        stderr.write_text(stderr.read_text() + "mutation\n")

        with self.assertRaisesRegex(mechanism.EvidenceError, "hash mismatch"):
            mechanism.compare(precursor, candidate)

    def test_cleanup_failure_records_output_and_suppresses_candidate(self):
        root = pathlib.Path(self.temporary.name) / "capture"
        config = mechanism.CaptureConfig(
            repo=pathlib.Path(self.temporary.name),
            output_dir=root,
            variant="precursor",
            run_id="capture-1",
        )
        before = mechanism.synthetic_snapshot("precursor")
        completed = mock.Mock(returncode=0, stdout="BUILD_OK\n", stderr="native\n")
        cleanup = mechanism.CleanupEvidence(
            status=3,
            stdout="cleanup stdout",
            stderr="cleanup stderr",
            descendants=("pid=99",),
        )
        with (
            mock.patch.object(mechanism, "capture_snapshot", return_value=before),
            mock.patch.object(mechanism, "_run_trace", return_value=completed),
            mock.patch.object(mechanism, "_cleanup", return_value=cleanup),
        ):
            receipt = mechanism.capture_one(config)

        payload = json.loads(receipt.path.read_text())
        self.assertEqual(payload["cleanup"]["status"], 3)
        self.assertEqual(payload["cleanup"]["stderr"], "cleanup stderr")
        self.assertFalse(receipt.valid_for_followup)

    def test_capture_rejects_pre_post_drift_or_foreign_census(self):
        precursor, candidate = self.good_pair()
        payload = json.loads(candidate.path.read_text())
        payload["provenance"]["post"]["binary_sha256"] = "c" * 64
        mechanism.write_json_atomic(candidate.path, payload)
        drifted = mechanism.parse_receipt(candidate.path)

        with self.assertRaisesRegex(mechanism.EvidenceError, "provenance drift"):
            mechanism.compare(precursor, drifted)

        payload = json.loads(precursor.path.read_text())
        payload["provenance"]["pre"]["foreign_processes"] = ["pid=77"]
        payload["provenance"]["post"]["foreign_processes"] = ["pid=77"]
        mechanism.write_json_atomic(precursor.path, payload)
        with self.assertRaisesRegex(mechanism.EvidenceError, "foreign"):
            mechanism.compare(mechanism.parse_receipt(precursor.path), candidate)

    def test_capture_pair_uses_fixed_variants_not_ambient_features(self):
        with mock.patch.dict(
            mechanism.os.environ,
            {
                "CARRICK_DSR_DIRECT_BINDINGS": "ambient",
                "CARRICK_DSR_PROFILE": "ambient",
            },
            clear=False,
        ):
            precursor = mechanism.capture_environment("precursor")
            candidate = mechanism.capture_environment("candidate")

        self.assertNotIn("CARRICK_DSR_DIRECT_BINDINGS", precursor)
        self.assertEqual(candidate["CARRICK_DSR_DIRECT_BINDINGS"], "1")
        self.assertEqual(precursor["CARRICK_DSR_PROFILE"], "1")
        self.assertEqual(candidate["CARRICK_DSR_PROFILE"], "1")

    def test_missing_gateway_translation_or_complete_nativeperf_rejects_the_pair(self):
        precursor, candidate = self.good_pair()
        raw_path = pathlib.Path(
            json.loads(candidate.path.read_text())["artifacts"]["raw_trace"]["path"]
        )
        raw_path.write_text(
            "\n".join(
                line
                for line in raw_path.read_text().splitlines()
                if "phase=translation-attempts" not in line
            )
            + "\n"
        )
        payload = json.loads(candidate.path.read_text())
        payload["artifacts"]["raw_trace"] = mechanism.bind_artifact(raw_path)
        mechanism.write_json_atomic(candidate.path, payload)

        with self.assertRaisesRegex(mechanism.EvidenceError, "translation-attempts"):
            mechanism.compare(precursor, mechanism.parse_receipt(candidate.path))

    def test_raw_dtrace_and_nativeperf_exit_vectors_must_reconcile(self):
        precursor, candidate = self.good_pair()
        stderr_path = pathlib.Path(
            json.loads(candidate.path.read_text())["artifacts"]["command_stderr"][
                "path"
            ]
        )
        stderr_path.write_text(
            stderr_path.read_text().replace(
                "exit_resolve_direct=4", "exit_resolve_direct=3"
            )
        )
        payload = json.loads(candidate.path.read_text())
        payload["artifacts"]["command_stderr"] = mechanism.bind_artifact(stderr_path)
        mechanism.write_json_atomic(candidate.path, payload)

        with self.assertRaisesRegex(mechanism.EvidenceError, "NATIVEPERF"):
            mechanism.compare(precursor, mechanism.parse_receipt(candidate.path))

    def test_raw_and_summary_overlapping_metrics_must_reconcile(self):
        precursor, candidate = self.good_pair()
        summary_path = pathlib.Path(
            json.loads(candidate.path.read_text())["artifacts"]["summary_jsonl"][
                "path"
            ]
        )
        rows = [json.loads(line) for line in summary_path.read_text().splitlines()]
        row = next(
            row
            for row in rows
            if row["scope"].get("phase") == "direct-total"
        )
        row["metric"]["count"] += 1
        summary_path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        )
        payload = json.loads(candidate.path.read_text())
        payload["artifacts"]["summary_jsonl"] = mechanism.bind_artifact(summary_path)
        mechanism.write_json_atomic(candidate.path, payload)

        with self.assertRaisesRegex(mechanism.EvidenceError, "raw/summary"):
            mechanism.compare(precursor, mechanism.parse_receipt(candidate.path))

    def test_reclassification_into_indirect_or_other_gateway_exits_rejects(self):
        precursor, _ = self.good_pair()
        indirect = self.fixture.receipt(
            "candidate-indirect",
            gateway=100,
            direct=4,
            indirect=30,
            eligible=4,
            publish=1,
        )
        other = self.fixture.receipt(
            "candidate-other",
            gateway=120,
            direct=4,
            indirect=20,
            eligible=4,
            publish=1,
        )

        with self.assertRaisesRegex(mechanism.EvidenceError, "indirect growth"):
            mechanism.compare(precursor, indirect)
        with self.assertRaisesRegex(mechanism.EvidenceError, "non-direct growth"):
            mechanism.compare(precursor, other)

    def test_publications_are_bounded_per_pid_cell_and_globally(self):
        precursor, _ = self.good_pair()
        candidate = self.fixture.receipt(
            "candidate-publishes",
            gateway=100,
            direct=4,
            indirect=20,
            eligible=4,
            publish=3,
        )

        with self.assertRaisesRegex(mechanism.EvidenceError, "publication invariant"):
            mechanism.compare(precursor, candidate)

    def test_zero_vectors_are_explicit_and_unknown_kinds_reject(self):
        precursor, candidate = self.good_pair()
        run = mechanism.parse_trace(candidate)
        self.assertEqual(run.binding_events[9], 0)
        raw_path = run.raw_path
        raw_path.write_text(
            raw_path.read_text().replace(
                "phase=binding-event|pid=42|kind=12",
                "phase=binding-event|pid=42|kind=13",
            )
        )
        payload = json.loads(candidate.path.read_text())
        payload["artifacts"]["raw_trace"] = mechanism.bind_artifact(raw_path)
        mechanism.write_json_atomic(candidate.path, payload)

        with self.assertRaisesRegex(mechanism.EvidenceError, "unknown binding event"):
            mechanism.parse_trace(mechanism.parse_receipt(candidate.path))

    def test_clear_and_validation_reasons_are_nonzero_and_known(self):
        precursor, candidate = self.good_pair()
        raw_path = pathlib.Path(
            json.loads(candidate.path.read_text())["artifacts"]["raw_trace"]["path"]
        )
        raw_path.write_text(
            raw_path.read_text().replace(
                "phase=binding-clear-cell|pid=42|cell_va=0x8000|kind=1",
                "phase=binding-clear-cell|pid=42|cell_va=0x8000|kind=0",
            )
        )
        payload = json.loads(candidate.path.read_text())
        payload["artifacts"]["raw_trace"] = mechanism.bind_artifact(raw_path)
        mechanism.write_json_atomic(candidate.path, payload)

        with self.assertRaisesRegex(mechanism.EvidenceError, "clear reason"):
            mechanism.parse_trace(mechanism.parse_receipt(candidate.path))

    def test_active_source_after_cross_unit_hit_selects_exit_time_authority(self):
        records = [
            mechanism.ManifestRecord("A", 0x1000, 0x2000, 0, 0x8000),
            mechanism.ManifestRecord("B", 0x2000, 0x3000, 7, 0x9000),
        ]

        selected = mechanism.select_exit_record(records, 0x2000, 0x3000, 0x9000, 7)

        self.assertEqual(selected.unit, "B")

    def test_duplicate_source_target_never_guesses_active_source(self):
        records = [
            mechanism.ManifestRecord("A", 0x2000, 0x3000, 0, None),
            mechanism.ManifestRecord("B", 0x2000, 0x3000, 0, None),
        ]

        with self.assertRaisesRegex(mechanism.EvidenceError, "ambiguous"):
            mechanism.select_exit_record(records, 0x2000, 0x3000, None, None)


if __name__ == "__main__":
    unittest.main()

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
        "sensitive_write_tpidr=0|sensitive_read_counter=0|sensitive_read_ctr=0|"
        "sensitive_read_dczid=0|"
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
        + "resolver-process|translations=1|optimistic_decode_discards=2|"
        "optimistic_decode_discard_ns=17|cache_lookups=1|"
        "cache_lookup_hits=0|invalidated_blocks=0",
        prefix
        + "resolver-times|nested_translation_ns=3|nested_translation_decode_ns=18|"
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
            f"DSRPROF1|count|phase=binding-validation|pid=42|source_pc=0x4000|"
            f"kind=1|cell_va=0x8000|value={validation}",
            "DSRPROF1|count|phase=binding-unit|pid=42|unit_id=0x1234|"
            "record_count=1|binding_data_bytes=8|value=1",
            "DSRPROF1|complete|profile=dsr-indirect|bounded=0|target_exit_reason=1",
        ]
    )
    return rows


class MechanismFixture:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.repo = root / "repo"
        self.binary = self.repo / "target/release/carrick"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"fixture signed carrick")
        self.binary_sha256 = mechanism.sha256_file(self.binary)
        self.image = "localhost:5005/carrick-go-conformance:1.24"

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
        capture_variant = (
            "precursor" if variant.startswith("precursor") else "candidate"
        )
        run_id = f"direct-binding-{capture_variant}-fixture-{variant}"
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
            binary_sha256=self.binary_sha256,
            host="fixture-host",
            bounded=bounded,
        )
        run_command = [
            str(self.binary.resolve()),
            "run",
            "--exec-backend",
            "native",
            "-e",
            f"CARRICK_RUN_ID={run_id}",
            "-w",
            "/tmp",
            self.image,
            "/bin/sh",
            "-c",
            mechanism.native_go_build.guest_script(),
        ]
        for row in summary_rows:
            row["command"] = run_command[1:]
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
                    "CARRICK_DSR_PERSISTENT_STORE",
                    "CARRICK_DSR_DIRECT_BINDINGS",
                    "CARRICK_DSR_PROFILE",
                }
                else (
                    "1"
                    if capture_variant == "precursor"
                    and key
                    in {
                        "CARRICK_DSR_ARTIFACT_SPIKE",
                        "CARRICK_DSR_PERSISTENT_STORE",
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
            "repository": str(self.repo.resolve()),
            "binary_path": str(self.binary.resolve()),
            "binary_sha256": self.binary_sha256,
            "host": "fixture-host",
            "image_ref": self.image,
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
            "inputs": {
                "repository": str(self.repo.resolve()),
                "binary": str(self.binary.resolve()),
                "image": self.image,
                "profile": "dsr-indirect",
                "summary_schema": "carrick.dsr-profile.v1",
            },
            "argv": [
                str(self.binary.resolve()),
                "trace",
                "--profile",
                "dsr-indirect",
                "--trace-out",
                str(raw.resolve()),
                "--summary-jsonl",
                str(summary.resolve()),
                "--",
                *run_command[1:],
            ],
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
                "binary_sha256": self.binary_sha256,
                "host": "fixture-host",
                "command": run_command[1:],
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

    def rewrite_raw(
        self,
        receipt: mechanism.CaptureReceipt,
        transform,
    ) -> mechanism.CaptureReceipt:
        payload = json.loads(receipt.path.read_text())
        raw_path = pathlib.Path(payload["artifacts"]["raw_trace"]["path"])
        raw_rows = transform(raw_path.read_text().splitlines())
        raw_path.write_text("\n".join(raw_rows) + "\n")
        summary_path = pathlib.Path(payload["artifacts"]["summary_jsonl"]["path"])
        summary_rows = mechanism.synthetic_summary_rows(
            raw_rows,
            run_id=str(payload["run_id"]),
            git_sha=str(payload["summary"]["git_sha"]),
            binary_sha256=str(payload["summary"]["binary_sha256"]),
            host=str(payload["summary"]["host"]),
            bounded=False,
        )
        for row in summary_rows:
            row["command"] = payload["summary"]["command"]
        summary_path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in summary_rows)
        )
        payload["summary"]["completion"] = summary_rows[0]["completion"]
        payload["artifacts"]["raw_trace"] = mechanism.bind_artifact(raw_path)
        payload["artifacts"]["summary_jsonl"] = mechanism.bind_artifact(summary_path)
        mechanism.write_json_atomic(receipt.path, payload)
        return mechanism.parse_receipt(receipt.path)

    def rewrite_bound_artifact(
        self,
        receipt: mechanism.CaptureReceipt,
        artifact_name: str,
        transform,
    ) -> mechanism.CaptureReceipt:
        payload = json.loads(receipt.path.read_text())
        artifact_path = pathlib.Path(
            payload["artifacts"][artifact_name]["path"]
        )
        artifact_path.write_text(transform(artifact_path.read_text()))
        payload["artifacts"][artifact_name] = mechanism.bind_artifact(
            artifact_path
        )
        mechanism.write_json_atomic(receipt.path, payload)
        return mechanism.parse_receipt(receipt.path)


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
        self.assertEqual(
            result["runs"]["candidate"]["binding_cells"],
            [{"pid": 42, "cell": 0x8000, "value": 4}],
        )
        self.assertEqual(
            result["runs"]["candidate"]["unit_loads"],
            [
                {
                    "pid": 42,
                    "unit_id": 0x1234,
                    "record_count": 1,
                    "binding_data_bytes": 8,
                    "value": 1,
                }
            ],
        )

    def test_profile_script_preserves_natural_exit_and_bounded_fallback(self):
        script = (
            pathlib.Path(__file__).resolve().parents[2]
            / "scripts/dtrace/dsr-indirect.d"
        ).read_text()

        self.assertIn("tracked[pid] = 0;\n    active = 0;\n    exit(0);", script)
        self.assertIn("bounded = 1;\n    exit(0);", script)
        self.assertRegex(script, r"(?m)^tick-1s\n/secs >= 60/$")

    def test_capture_environment_rejects_every_foreign_ambient_control(self):
        for value in ("1", ""):
            with self.subTest(value=value), mock.patch.dict(
                mechanism.os.environ,
                {"PATH": "/bin", "CARRICK_FOREIGN_CONTROL": value},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "CARRICK_FOREIGN_CONTROL"
                ):
                    mechanism.capture_environment("candidate")

    def test_receipt_variant_requires_its_exact_effective_environment(self):
        precursor, candidate = self.good_pair()
        payload = json.loads(candidate.path.read_text())
        wrong = mechanism.synthetic_snapshot("precursor")["controlled_environment"]
        payload["provenance"]["pre"]["controlled_environment"] = wrong
        payload["provenance"]["post"]["controlled_environment"] = copy.deepcopy(wrong)
        payload["environment_sha256"] = mechanism.sha256_json(wrong)
        mechanism.write_json_atomic(candidate.path, payload)

        with self.assertRaisesRegex(
            mechanism.EvidenceError, "fixed candidate environment"
        ):
            mechanism.compare(
                precursor,
                mechanism.parse_receipt(candidate.path),
            )

    def test_receipt_artifacts_and_inputs_are_one_exact_capture(self):
        mutations = {}

        def alias_artifact(receipt, payload):
            payload["artifacts"]["raw_trace"] = copy.deepcopy(
                payload["artifacts"]["command_stdout"]
            )

        mutations["aliased artifact"] = (
            alias_artifact,
            "distinct",
        )

        def outside_artifact(receipt, payload):
            source = pathlib.Path(
                payload["artifacts"]["command_stdout"]["path"]
            )
            outside = receipt.path.parent.parent / "outside-stdout.log"
            outside.write_bytes(source.read_bytes())
            payload["artifacts"]["command_stdout"] = mechanism.bind_artifact(outside)

        mutations["outside artifact"] = (
            outside_artifact,
            "capture directory",
        )

        def wrong_argv(_receipt, payload):
            payload["argv"] = ["carrick", "trace", "--profile", "dsr-indirect"]

        mutations["wrong argv"] = (wrong_argv, "exact argv")

        def wrong_workload(_receipt, payload):
            payload["workload"] = "echo BUILD_OK"

        mutations["wrong workload"] = (wrong_workload, "fixed workload")

        def wrong_inputs(_receipt, payload):
            payload["inputs"]["image"] = "other/image:latest"

        mutations["wrong inputs"] = (wrong_inputs, "image input")

        for index, (name, (mutate, reason)) in enumerate(mutations.items()):
            with self.subTest(name=name):
                receipt = self.fixture.receipt(
                    f"candidate-authority-{index}",
                    gateway=100,
                    direct=4,
                    indirect=20,
                    eligible=4,
                    publish=1,
                )
                payload = json.loads(receipt.path.read_text())
                mutate(receipt, payload)
                mechanism.write_json_atomic(receipt.path, payload)
                with self.assertRaisesRegex(mechanism.EvidenceError, reason):
                    mechanism.validate_receipt(
                        mechanism.parse_receipt(receipt.path),
                        require_variant="candidate",
                    )

    def test_summary_schema_command_and_run_id_match_receipt_authority(self):
        for index, field in enumerate(("schema", "profile", "command", "run_id")):
            with self.subTest(field=field):
                receipt = self.fixture.receipt(
                    f"candidate-summary-{index}",
                    gateway=100,
                    direct=4,
                    indirect=20,
                    eligible=4,
                    publish=1,
                )
                payload = json.loads(receipt.path.read_text())
                summary_path = pathlib.Path(
                    payload["artifacts"]["summary_jsonl"]["path"]
                )
                rows = [
                    json.loads(line)
                    for line in summary_path.read_text().splitlines()
                ]
                if field == "schema":
                    for row in rows:
                        row["schema"] = "other.schema"
                elif field == "profile":
                    for row in rows:
                        row["profile"] = "dsr"
                elif field == "command":
                    for row in rows:
                        row["command"] = ["run", "other-image"]
                    payload["summary"]["command"] = ["run", "other-image"]
                else:
                    wrong_run_id = "direct-binding-candidate-other"
                    for row in rows:
                        row["run_id"] = wrong_run_id
                    payload["run_id"] = wrong_run_id
                    payload["summary"]["run_id"] = wrong_run_id
                summary_path.write_text(
                    "".join(
                        json.dumps(row, sort_keys=True) + "\n" for row in rows
                    )
                )
                payload["artifacts"]["summary_jsonl"] = mechanism.bind_artifact(
                    summary_path
                )
                mechanism.write_json_atomic(receipt.path, payload)

                with self.assertRaisesRegex(
                    mechanism.EvidenceError,
                    "schema|profile|command|run ID",
                ):
                    mechanism.parse_trace(
                        mechanism.parse_receipt(receipt.path)
                    )

    def test_precursor_rejection_retains_exact_reason_and_parseable_counters(self):
        precursor, _ = self.good_pair()
        payload = json.loads(precursor.path.read_text())
        payload["cleanup"] = {
            "status": 3,
            "stdout": "cleanup stdout",
            "stderr": "cleanup stderr",
            "descendants": [],
        }
        mechanism.write_json_atomic(precursor.path, payload)
        precursor = mechanism.parse_receipt(precursor.path)
        output = pathlib.Path(self.temporary.name) / "rejected-pair.json"

        with mock.patch.object(
            mechanism, "capture_one", return_value=precursor
        ):
            result = mechanism.capture_pair(
                self.fixture.repo,
                pathlib.Path(self.temporary.name) / "captures",
                output,
                5,
            )

        self.assertFalse(result["accepted"])
        self.assertEqual(
            result["rejection_reasons"],
            [
                "cleanup status is nonzero: 3 "
                "stdout='cleanup stdout' stderr='cleanup stderr'"
            ],
        )
        self.assertEqual(
            result["available_runs"]["precursor"]["binding_events"]["7"],
            100,
        )
        self.assertEqual(json.loads(output.read_text()), result)

    def test_rejected_run_retains_independent_planes_after_specialized_error(self):
        precursor, candidate = self.good_pair()

        def malformed_unit(rows):
            return [
                line.replace("unit_id=0x1234", "unit_id=bad")
                if "phase=binding-unit|" in line
                else line
                for line in rows
            ]

        candidate = self.fixture.rewrite_raw(candidate, malformed_unit)
        output = pathlib.Path(self.temporary.name) / "partial-evidence.json"
        with mock.patch.object(
            mechanism,
            "capture_one",
            side_effect=(precursor, candidate),
        ):
            result = mechanism.capture_pair(
                self.fixture.repo,
                pathlib.Path(self.temporary.name) / "captures",
                output,
                5,
            )

        self.assertFalse(result["accepted"])
        self.assertIn("candidate", result["available_runs"])
        available = result["available_runs"]["candidate"]
        self.assertEqual(available["gateway_total"], 100)
        self.assertEqual(available["binding_events"]["12"], 1)
        self.assertEqual(available["native_gateway"], 100)
        self.assertEqual(available["native_exits"]["2"], 4)
        direct_summary = next(
            row
            for row in available["summary_metrics"]
            if row["scope"].get("phase") == "direct-total"
        )
        self.assertEqual(direct_summary["count"], 4)
        self.assertEqual(
            available["evidence_errors"],
            {
                "raw_aggregates": [],
                "specialized": ["invalid integer unit ID='bad'"],
                "summary": [],
                "nativeperf": [],
                "reconciliation": [
                    "binding-unit total does not reconcile with kind=12"
                ],
            },
        )
        self.assertEqual(json.loads(output.read_text()), result)

    def test_rejected_run_retains_valid_summary_siblings_and_field_error(self):
        precursor, candidate = self.good_pair()
        malformed_line = None

        def corrupt_one_count(text):
            nonlocal malformed_line
            rows = text.splitlines()
            for index, line in enumerate(rows):
                row = json.loads(line)
                if row["scope"].get("phase") == "binding-unit":
                    row["metric"]["count"] = "bad"
                    rows[index] = json.dumps(row, sort_keys=True)
                    malformed_line = index + 1
                    break
            return "\n".join(rows) + "\n"

        candidate = self.fixture.rewrite_bound_artifact(
            candidate,
            "summary_jsonl",
            corrupt_one_count,
        )
        output = pathlib.Path(self.temporary.name) / "summary-partial.json"

        status = mechanism.main(
            [
                "compare",
                "--precursor-receipt",
                str(precursor.path),
                "--candidate-receipt",
                str(candidate.path),
                "--output",
                str(output),
            ]
        )

        self.assertEqual(status, 1)
        available = json.loads(output.read_text())["available_runs"]["candidate"]
        direct_summaries = [
            row
            for row in available["summary_metrics"]
            if row["scope"].get("phase") == "direct-total"
        ]
        self.assertEqual(len(direct_summaries), 1)
        self.assertEqual(direct_summaries[0]["count"], 4)
        self.assertEqual(
            available["evidence_errors"]["summary"],
            [
                f"summary line {malformed_line}.metric.count: "
                "summary metric.count is not an integer"
            ],
        )

    def test_rejected_run_retains_valid_native_records_and_sibling_counters(self):
        precursor, candidate = self.good_pair()

        def corrupt_one_native_counter(text):
            return text.replace("exit_fault=0", "exit_fault=bad", 1)

        candidate = self.fixture.rewrite_bound_artifact(
            candidate,
            "command_stderr",
            corrupt_one_native_counter,
        )
        output = pathlib.Path(self.temporary.name) / "native-partial.json"

        status = mechanism.main(
            [
                "compare",
                "--precursor-receipt",
                str(precursor.path),
                "--candidate-receipt",
                str(candidate.path),
                "--output",
                str(output),
            ]
        )

        self.assertEqual(status, 1)
        available = json.loads(output.read_text())["available_runs"]["candidate"]
        self.assertEqual(available["native_gateway"], 100)
        self.assertEqual(available["native_exits"]["2"], 4)
        core = next(
            row for row in available["native_records"] if row.get("frame") == "core"
        )
        exits = next(
            row for row in available["native_records"] if row.get("frame") == "exits"
        )
        self.assertEqual(core["counters"]["gateway_entries"], 100)
        self.assertEqual(exits["counters"]["exit_resolve_indirect"], 20)
        self.assertNotIn("exit_fault", exits["counters"])
        self.assertEqual(
            available["evidence_errors"]["nativeperf"],
            [
                "NATIVEPERF1 line 3.thread.exits.exit_fault: "
                "profile field exit_fault is not an unsigned decimal integer"
            ],
        )

    def test_rejected_run_publishes_complete_partial_raw_metric_map(self):
        precursor, candidate = self.good_pair()

        def corrupt_one_raw_value(text):
            return text.replace(
                "phase=translation-attempts|pid=42|value=4",
                "phase=translation-attempts|pid=42|value=bad",
                1,
            )

        candidate = self.fixture.rewrite_bound_artifact(
            candidate,
            "raw_trace",
            corrupt_one_raw_value,
        )
        output = pathlib.Path(self.temporary.name) / "raw-partial.json"

        status = mechanism.main(
            [
                "compare",
                "--precursor-receipt",
                str(precursor.path),
                "--candidate-receipt",
                str(candidate.path),
                "--output",
                str(output),
            ]
        )

        self.assertEqual(status, 1)
        available = json.loads(output.read_text())["available_runs"]["candidate"]
        self.assertIn("raw_metrics", available)
        self.assertEqual(len(available["raw_metrics"]), 21)
        gateway = next(
            row
            for row in available["raw_metrics"]
            if row["key"].get("phase") == "gateway-total"
        )
        self.assertEqual(
            gateway,
            {
                "key": {
                    "record_type": "count",
                    "phase": "gateway-total",
                    "pid": 42,
                },
                "value": 100,
            },
        )
        self.assertEqual(available["binding_events"]["7"], 4)
        self.assertEqual(
            available["evidence_errors"]["raw_aggregates"],
            [
                "raw line 2.value: invalid integer value='bad'",
                "raw trace is missing required translation-attempts metric",
            ],
        )

    def test_malformed_summary_scope_cannot_escape_atomic_rejection_projection(self):
        precursor, candidate = self.good_pair()
        malformed_line = None

        def corrupt_one_scope(text):
            nonlocal malformed_line
            rows = text.splitlines()
            for index, line in enumerate(rows):
                row = json.loads(line)
                if row["scope"].get("phase") == "binding-unit":
                    row["scope"]["pid"] = "not-a-number"
                    rows[index] = json.dumps(row, sort_keys=True)
                    malformed_line = index + 1
                    break
            return "\n".join(rows) + "\n"

        candidate = self.fixture.rewrite_bound_artifact(
            candidate,
            "summary_jsonl",
            corrupt_one_scope,
        )
        output = pathlib.Path(self.temporary.name) / "summary-scope-partial.json"

        try:
            status = mechanism.main(
                [
                    "compare",
                    "--precursor-receipt",
                    str(precursor.path),
                    "--candidate-receipt",
                    str(candidate.path),
                    "--output",
                    str(output),
                ]
            )
        except (mechanism.EvidenceError, ValueError) as error:
            self.fail(f"rejection projector escaped instead of publishing: {error}")

        self.assertEqual(status, 1)
        rejected = json.loads(output.read_text())
        self.assertFalse(rejected["accepted"])
        available = rejected["available_runs"]["candidate"]
        direct_summary = next(
            row
            for row in available["summary_metrics"]
            if row["scope"].get("phase") == "direct-total"
        )
        self.assertEqual(direct_summary["count"], 4)
        self.assertEqual(
            available["evidence_errors"]["summary"],
            [
                f"summary line {malformed_line}.scope.pid: "
                "invalid integer pid='not-a-number'"
            ],
        )

    def test_malformed_numeric_receipt_is_an_atomic_typed_rejection(self):
        precursor, candidate = self.good_pair()
        payload = json.loads(candidate.path.read_text())
        payload["command"]["status"] = "not-a-number"
        mechanism.write_json_atomic(candidate.path, payload)
        output = pathlib.Path(self.temporary.name) / "malformed.json"

        status = mechanism.main(
            [
                "compare",
                "--precursor-receipt",
                str(precursor.path),
                "--candidate-receipt",
                str(candidate.path),
                "--output",
                str(output),
            ]
        )

        self.assertEqual(status, 1)
        rejected = json.loads(output.read_text())
        self.assertFalse(rejected["accepted"])
        self.assertIn("command.status is not an integer", rejected["rejection_reasons"][0])

    def test_specialized_dtrace_rows_reconcile_with_event_vector(self):
        cases = (
            ("binding-publish-cell", "kind=8", {"publish": 1}),
            ("binding-clear-cell", "kind=10", {"clear": 1}),
            ("binding-validation", "kind=11", {"validation": 1}),
            ("binding-unit", "kind=12", {}),
        )
        for index, (phase, event, options) in enumerate(cases):
            with self.subTest(phase=phase):
                receipt = self.fixture.receipt(
                    f"candidate-specialized-{index}",
                    gateway=100,
                    direct=4,
                    indirect=20,
                    eligible=4,
                    publish=options.get("publish", 1),
                    clear=options.get("clear", 0),
                    validation=options.get("validation", 0),
                )

                def zero_specialized(rows):
                    return [
                        (
                            line.rsplit("value=", 1)[0] + "value=0"
                            if f"phase={phase}|" in line
                            else line
                        )
                        for line in rows
                    ]

                receipt = self.fixture.rewrite_raw(receipt, zero_specialized)
                with self.assertRaisesRegex(
                    mechanism.EvidenceError,
                    f"{phase}.*{event}|{event}.*{phase}",
                ):
                    mechanism.parse_trace(receipt)

    def test_specialized_dtrace_identities_are_nonzero_and_typed(self):
        candidate = self.fixture.receipt(
            "candidate-invalid-specialized",
            gateway=100,
            direct=4,
            indirect=20,
            eligible=4,
            publish=1,
        )

        def zero_unit_id(rows):
            return [
                line.replace("unit_id=0x1234", "unit_id=0")
                if "phase=binding-unit|" in line
                else line
                for line in rows
            ]

        candidate = self.fixture.rewrite_raw(candidate, zero_unit_id)
        with self.assertRaisesRegex(mechanism.EvidenceError, "unit.*zero"):
            mechanism.parse_trace(candidate)

    def test_unit_loaded_accepts_zero_and_disabled_binding_declarations(self):
        candidate = self.fixture.receipt(
            "candidate-valid-unit-shapes",
            gateway=100,
            direct=4,
            indirect=20,
            eligible=4,
            publish=1,
        )

        def valid_zero_and_disabled_units(rows):
            rewritten = []
            for line in rows:
                if "phase=binding-event|pid=42|kind=12|" in line:
                    line = line.rsplit("value=", 1)[0] + "value=3"
                if "phase=binding-unit|" in line:
                    line = line.replace(
                        "record_count=1|binding_data_bytes=8|value=1",
                        "record_count=0|binding_data_bytes=0|value=1",
                    )
                    rewritten.append(line)
                    rewritten.append(
                        "DSRPROF1|count|phase=binding-unit|pid=42|"
                        "unit_id=0x5678|record_count=3|"
                        "binding_data_bytes=0|value=2"
                    )
                    continue
                rewritten.append(line)
            return rewritten

        candidate = self.fixture.rewrite_raw(
            candidate,
            valid_zero_and_disabled_units,
        )
        run = mechanism.parse_trace(candidate)

        self.assertEqual(
            mechanism._run_payload(run)["unit_loads"],
            [
                {
                    "pid": 42,
                    "unit_id": 0x1234,
                    "record_count": 0,
                    "binding_data_bytes": 0,
                    "value": 1,
                },
                {
                    "pid": 42,
                    "unit_id": 0x5678,
                    "record_count": 3,
                    "binding_data_bytes": 0,
                    "value": 2,
                },
            ],
        )
        self.assertEqual(run.binding_events[12], 3)

    def test_task15_explicit_capture_command_and_stable_artifact_layout(self):
        arguments = [
            "capture-pair",
            "--repo",
            ".",
            "--binary",
            "target/release/carrick",
            "--image",
            "localhost:5005/carrick-go-conformance:1.24",
            "--artifact-dir",
            "target/perf/direct-binding-mechanism-v1",
            "--output",
            "target/perf/direct-binding-mechanism-v1.json",
        ]
        try:
            parsed = mechanism.parse_args(arguments)
        except SystemExit as error:
            self.fail(f"Task 15 capture command does not compose: {error}")

        self.assertEqual(parsed.repo, pathlib.Path("."))
        self.assertEqual(parsed.binary, pathlib.Path("target/release/carrick"))
        self.assertEqual(
            parsed.image, "localhost:5005/carrick-go-conformance:1.24"
        )
        self.assertEqual(
            parsed.artifact_dir,
            pathlib.Path("target/perf/direct-binding-mechanism-v1"),
        )
        config = mechanism.CaptureConfig(
            repo=self.fixture.repo,
            output_dir=pathlib.Path(self.temporary.name) / "artifacts",
            variant="precursor",
            run_id="direct-binding-precursor-test",
        )
        paths = mechanism._capture_paths(config)
        self.assertEqual(
            paths["receipt"],
            (config.output_dir / "precursor/receipt.json").resolve(),
        )

    def test_capture_pair_rejects_existing_slots_without_overwriting_evidence(self):
        artifact_dir = pathlib.Path(self.temporary.name) / "stable-captures"
        output = pathlib.Path(self.temporary.name) / "stable-pair.json"
        precursor, candidate = self.good_pair()
        with mock.patch.object(
            mechanism,
            "capture_one",
            side_effect=(precursor, candidate),
        ):
            first = mechanism.capture_pair(
                self.fixture.repo,
                artifact_dir,
                output,
                5,
            )
        self.assertTrue(first["accepted"])

        retained_paths = [output]
        for variant, receipt in (
            ("precursor", precursor),
            ("candidate", candidate),
        ):
            directory = artifact_dir / variant
            directory.mkdir(parents=True)
            payload = receipt.payload
            for artifact_name, filename in (
                ("raw_trace", "trace.log"),
                ("summary_jsonl", "summary.jsonl"),
                ("command_stdout", "stdout.log"),
                ("command_stderr", "stderr.log"),
            ):
                destination = directory / filename
                destination.write_bytes(
                    pathlib.Path(
                        payload["artifacts"][artifact_name]["path"]
                    ).read_bytes()
                )
                retained_paths.append(destination)
            stable_receipt = directory / "receipt.json"
            stable_receipt.write_bytes(receipt.path.read_bytes())
            retained_paths.append(stable_receipt)
        before = {
            path: mechanism.sha256_file(path)
            for path in retained_paths
        }
        repeat_precursor = self.fixture.receipt(
            "precursor-repeat",
            gateway=200,
            direct=100,
            indirect=20,
            eligible=100,
            publish=1,
        )
        repeat_candidate = self.fixture.receipt(
            "candidate-repeat",
            gateway=100,
            direct=4,
            indirect=20,
            eligible=4,
            publish=1,
        )

        with mock.patch.object(
            mechanism,
            "capture_one",
            side_effect=(repeat_precursor, repeat_candidate),
        ) as capture:
            second = mechanism.capture_pair(
                self.fixture.repo,
                artifact_dir,
                output,
                5,
            )

        self.assertFalse(second["accepted"])
        self.assertIn("already exists", second["rejection_reasons"][0])
        capture.assert_not_called()
        self.assertEqual(
            {
                path: mechanism.sha256_file(path)
                for path in retained_paths
            },
            before,
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
            mock.patch.object(
                mechanism,
                "capture_snapshot",
                return_value=before,
            ) as snapshot,
            mock.patch.object(
                mechanism,
                "_run_trace",
                return_value=completed,
            ) as run_trace,
            mock.patch.object(mechanism, "_cleanup", return_value=cleanup),
        ):
            receipt = mechanism.capture_one(config)

        payload = json.loads(receipt.path.read_text())
        self.assertEqual(payload["cleanup"]["status"], 3)
        self.assertEqual(payload["cleanup"]["stderr"], "cleanup stderr")
        self.assertFalse(receipt.valid_for_followup)
        capture = run_trace.call_args.args[2]
        self.assertTrue(
            all(call.args[1] is capture for call in snapshot.call_args_list)
        )
        self.assertEqual(
            {
                key: capture.subprocess.get(key)
                for key in mechanism.native_go_build.PERFORMANCE_CONTROL_KEYS
            },
            capture.controlled,
        )

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

    def test_harness_rejects_inherited_known_controls_before_fixed_overlay(self):
        for key in (
            "CARRICK_DSR_DIRECT_BINDINGS",
            "CARRICK_DSR_PROFILE",
        ):
            for value in ("ambient", ""):
                with self.subTest(key=key, value=value), mock.patch.dict(
                    mechanism.os.environ,
                    {"PATH": "/bin", key: value},
                    clear=True,
                ):
                    with self.assertRaisesRegex(RuntimeError, key):
                        mechanism.capture_environment("candidate")
        with mock.patch.dict(
            mechanism.os.environ,
            {"PATH": "/bin"},
            clear=True,
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

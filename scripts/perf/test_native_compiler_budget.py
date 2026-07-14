#!/usr/bin/env python3

import hashlib
import dataclasses
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import native_compiler_budget as budget


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_w2_manifest_json(input_path: pathlib.Path) -> dict:
    result = {
        "schema": "carrick.native-compiler-workload.v1",
        "name": "w2-fixture",
        "image": "example.invalid/image:1",
        "image_digest": "sha256:" + "1" * 64,
        "workdir": "/work",
        "argv": ["/usr/local/go/pkg/tool/linux_arm64/compile", "-o", "/work/out.a", "/work/input.go"],
        "env": [],
        "files": [{
            "guest_path": "/work/input.go",
            "fixture_path": str(input_path.relative_to(input_path.parent.parent)),
            "sha256": sha256(input_path.read_bytes()),
        }],
        "executable_sha256": "2" * 64,
        "expected_exit": 0,
        "expected_stdout_sha256": sha256(b""),
        "max_traps": 1_000_000,
        "native_page_profile": "native16k",
        "capture": {
            "kind": "w2-toolexec",
            "source": "docker-toolexec",
            "candidate_count": 1,
            "captured_argv_index": 3,
            "capture_environment": [
                ["CARRICK_TOOLEXEC_LOG", "/capture/toolexec.bin"],
                ["GOFLAGS", "-work -toolexec=/capture/native-compiler-toolexec.sh"],
            ],
            "replay_environment": [],
            "expected_output_guest_path": "/work/out.a",
            "expected_output_sha256": "3" * 64,
            "docker_replays": [
                {"exit_status": 0, "stdout_sha256": sha256(b""), "output_sha256": "3" * 64},
                {"exit_status": 0, "stdout_sha256": sha256(b""), "output_sha256": "3" * 64},
            ],
            "representativeness": {
                "accepted_rule": "smallest natural child preserving W1 hottest-thread exclusive decision",
                "profile_cleanup_status": 0,
                "profile_stderr_sha256": "4" * 64,
                "profile_summary_sha256": "5" * 64,
                "w1_profile_sha256": "6" * 64,
                "w1_hottest": {
                    "gateway_entries": 100,
                    "exit_resolve_direct": 10,
                    "exit_resolve_indirect": 20,
                    "exit_sensitive": 70,
                    "sensitive_exclusive": 40,
                },
                "w2_hottest": {
                    "gateway_entries": 80,
                    "exit_resolve_direct": 10,
                    "exit_resolve_indirect": 20,
                    "exit_sensitive": 50,
                    "sensitive_exclusive": 35,
                },
            },
            "rejected_candidates": [],
            "w1_stderr_sha256": sha256(b""),
            "w1_stdout_sha256": sha256(b"w1"),
            "w1_profile_evidence_path": "evidence.json",
            "w1_profile_evidence_sha256": "0" * 64,
        },
    }
    evidence = {
        "schema": "carrick.native-compiler-w1-profile-evidence.v1",
        "run_id": "fixture-run",
        "binary_sha256": "7" * 64,
        "manifest_sha256": "8" * 64,
        "raw_profile_source": "target/native-compiler-task2-review/fixture/stderr",
        "raw_profile_sha256": "6" * 64,
        "complete_thread_groups": 1,
        "frames_per_group": 9,
        "required_frames": sorted(budget.REQUIRED_FRAMES),
        "hottest": {
            **result["capture"]["representativeness"]["w1_hottest"],
            "pid": 41,
            "tid": 42,
            "era": 7,
        },
        "outcome": {
            "kind": "max-traps",
            "exit_status": 2,
            "work_units_completed": 0,
            "work_units_expected": 1,
            "ceiling_marker_thread_id": 42,
            "ceiling_marker_traps": 100,
            "ceiling_profile_identity": [41, 42, 7],
            "gateway_entries": 100,
            "gateway_limit": 100,
        },
        "cleanup": {"status": "clean", "descendants_absent": True, "receipt_sha256": "9" * 64},
        "timing": {"wall_ns": 1, "user_ns": 1, "system_ns": 0, "peak_rss_bytes": 1},
    }
    evidence_path = input_path.parent.parent / "evidence.json"
    evidence_path.write_text(json.dumps(evidence, sort_keys=True) + "\n")
    result["capture"]["w1_profile_evidence_sha256"] = sha256(evidence_path.read_bytes())
    return result


def dtrace_rows(run_id="run-1", pid=42):
    completion = {
        "complete": True,
        "bounded": False,
        "target_exit_reason": 1,
        "high_cardinality_overflow": False,
        "incomplete_pairs": 0,
        "cardinality": {"indirect_sources": 1, "indirect_pairs": 1},
        "drops": {
            "interrupted": False,
            "principal_drops": 0,
            "aggregation_drops": 0,
            "dynamic_drops": 0,
            "other_drops": 0,
        },
    }
    base = {
        "schema": "carrick.dsr-profile.v1",
        "profile": "dsr",
        "run_id": run_id,
        "git_sha": "a" * 40,
        "git_dirty": False,
        "binary_sha256": "b" * 64,
        "command": ["carrick", "run"],
        "host": "test-host",
        "sampling_interval": None,
        "completion": completion,
    }
    return [
        {**base, "scope": {"phase": "prepare", "pid": pid, "kind": 1},
         "metric": {"type": "exact", "count": 1, "total_ns": 1,
                    "minimum_ns": 1, "maximum_ns": 1}},
        {**base, "scope": {"phase": "prepare", "pid": pid, "kind": 2},
         "metric": {"type": "exact", "count": 1, "total_ns": 1,
                    "minimum_ns": 1, "maximum_ns": 1}},
        {**base, "scope": {"phase": "run", "pid": pid, "kind": 1},
         "metric": {"type": "exact", "count": 1, "total_ns": 1,
                    "minimum_ns": 1, "maximum_ns": 1}},
        {**base, "scope": {"phase": "run", "pid": pid, "kind": 2},
         "metric": {"type": "exact", "count": 1, "total_ns": 1,
                    "minimum_ns": 1, "maximum_ns": 1}},
        {**base, "scope": {}, "metric": {"type": "completion"}},
    ]


def profile_with_budget(
    *, gateway_entries: int, sensitive_exclusive: int, syscall_dispatch_ns: int
):
    lines = nativeperf_frames()
    lines[0] = lines[0].replace("gateway_entries=2", f"gateway_entries={gateway_entries}").replace(
        "reconciled_exits=2", f"reconciled_exits={gateway_entries}"
    )
    lines[1] = lines[1].replace("exit_syscall=1", "exit_syscall=0").replace(
        "exit_resolve_direct=1", "exit_resolve_direct=0"
    ).replace("exit_sensitive=0", f"exit_sensitive={sensitive_exclusive}")
    lines[1] = lines[1].replace(
        "exit_unsupported=0",
        f"exit_unsupported={gateway_entries - sensitive_exclusive}",
    )
    lines[2] = lines[2].replace(
        "sensitive_exclusive=0", f"sensitive_exclusive={sensitive_exclusive}"
    )
    lines[4] = lines[4].replace(
        "phase_syscall_dispatch_ns=5", f"phase_syscall_dispatch_ns={syscall_dispatch_ns}"
    ).replace("phase_syscall_dispatch_count=1", "phase_syscall_dispatch_count=0").replace(
        "phase_blocked_count=1", "phase_blocked_count=0"
    ).replace(
        "phase_sensitive_emulation_count=0",
        f"phase_sensitive_emulation_count={sensitive_exclusive}",
    )
    lines[3] = lines[3].replace(
        "phase_prepare_index_count=2", f"phase_prepare_index_count={gateway_entries}"
    ).replace(
        "phase_translated_run_count=2", f"phase_translated_run_count={gateway_entries}"
    ).replace("phase_finish_exit_count=2", f"phase_finish_exit_count={gateway_entries}")
    lines[4] = lines[4].replace(
        "phase_loop_quiesce_count=2", f"phase_loop_quiesce_count={gateway_entries}"
    )
    lines[5] = lines[5].replace("gateway_entries=2", f"gateway_entries={gateway_entries}").replace(
        "syscall_exits=1", "syscall_exits=0"
    ).replace("direct_resolver_exits=1", "direct_resolver_exits=0")
    return budget.parse_nativeperf(lines)


def strict_abba_records(
    profile, profiled_wall_ns=105, untraced_cpu_ns=100, profiled_cpu_ns=100
):
    records = []
    for label in budget.abba_schedule(samples=5):
        plane = "untraced" if label.startswith("off-") else "profiled"
        repetition = 0 if label.endswith("warmup") else int(label.rsplit("-", 1)[1])
        records.append(
            budget.RunRecord.synthetic(
                profile=profile if plane == "profiled" else None,
                plane=plane,
                repetition=repetition,
                run_id=label,
                schedule_label=label,
                wall_ns=100 if plane == "untraced" else profiled_wall_ns,
                cpu_ns=untraced_cpu_ns if plane == "untraced" else profiled_cpu_ns,
            )
        )
    return records


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        fixture = self.root / "fixture"
        fixture.mkdir()
        (fixture / "input.go").write_text("package input\n", encoding="utf-8")
        self.manifest_path = self.root / "manifest.json"
        self.manifest = {
            "schema": "carrick.native-compiler-workload.v1",
            "name": "fixture",
            "image": "example.invalid/image:1",
            "image_digest": "sha256:" + "1" * 64,
            "workdir": "/work",
            "argv": [
                "/usr/local/go/pkg/tool/linux_arm64/compile",
                "-o",
                "/work/out.a",
                "input.go",
            ],
            "env": [["GOARCH", "arm64"], ["GOOS", "linux"]],
            "files": [
                {
                    "guest_path": "/work/input.go",
                    "fixture_path": "fixture/input.go",
                    "sha256": sha256(b"package input\n"),
                }
            ],
            "executable_sha256": "2" * 64,
            "expected_exit": 0,
            "expected_stdout_sha256": sha256(b""),
            "max_traps": 1_000_000,
            "native_page_profile": "native16k",
            "capture": strict_w2_manifest_json(fixture / "input.go")["capture"],
        }
        self.manifest["capture"]["replay_environment"] = self.manifest["env"]
        self.write_manifest()

    def tearDown(self):
        self.temp.cleanup()

    def write_manifest(self):
        self.manifest_path.write_text(
            json.dumps(self.manifest, sort_keys=True) + "\n", encoding="utf-8"
        )

    def test_load_manifest_accepts_hashed_fixture(self):
        loaded = budget.load_manifest(self.manifest_path)
        self.assertEqual(loaded.name, "fixture")
        self.assertEqual(loaded.argv[0], "/usr/local/go/pkg/tool/linux_arm64/compile")

    def test_manifest_resolves_and_reconciles_tree_backed_w1_evidence(self):
        evidence_path = self.root / "evidence.json"
        evidence = json.loads(evidence_path.read_text())
        evidence["hottest"]["sensitive_exclusive"] = 39
        evidence_path.write_text(json.dumps(evidence, sort_keys=True) + "\n")
        self.manifest["capture"]["w1_profile_evidence_sha256"] = sha256(
            evidence_path.read_bytes()
        )
        self.write_manifest()
        with self.assertRaisesRegex(budget.BudgetError, "hottest counters"):
            budget.load_manifest(self.manifest_path)

    def test_manifest_rejects_changed_w1_evidence_hash(self):
        evidence_path = self.root / "evidence.json"
        evidence_path.write_text(evidence_path.read_text() + " ")
        with self.assertRaisesRegex(budget.BudgetError, "evidence SHA-256 mismatch"):
            budget.load_manifest(self.manifest_path)

    def test_manifest_rejects_changed_input_hash(self):
        (self.root / "fixture/input.go").write_text(
            "package changed\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(budget.BudgetError, "sha256 mismatch"):
            budget.load_manifest(self.manifest_path)

    def test_manifest_rejects_duplicate_json_key(self):
        self.manifest_path.write_text(
            '{"schema":"carrick.native-compiler-workload.v1",'
            '"schema":"carrick.native-compiler-workload.v1"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(budget.BudgetError, "duplicate JSON key"):
            budget.load_manifest(self.manifest_path)

    def test_manifest_rejects_unknown_field_and_unordered_environment(self):
        self.manifest["unknown"] = True
        self.write_manifest()
        with self.assertRaisesRegex(budget.BudgetError, "unknown manifest field"):
            budget.load_manifest(self.manifest_path)
        del self.manifest["unknown"]
        self.manifest["env"].reverse()
        self.write_manifest()
        with self.assertRaisesRegex(budget.BudgetError, "environment.*sorted"):
            budget.load_manifest(self.manifest_path)

    def test_manifest_rejects_relative_executable(self):
        self.manifest["argv"][0] = "compile"
        self.write_manifest()
        with self.assertRaisesRegex(budget.BudgetError, r"argv\[0\].*absolute"):
            budget.load_manifest(self.manifest_path)

    def test_go_test_duration_normalization_preserves_content_contract(self):
        self.manifest["capture"] = {
            "kind": "w1-go-test",
            "go_version": "go1.24.13 linux/arm64",
            "source": "exact-go-types-reducer",
            "stdout_normalization": "go-test-duration",
        }
        self.write_manifest()
        loaded = budget.load_manifest(self.manifest_path)
        first = b"--- PASS: TestImplicitsInfo (1.35s)\nPASS\n"
        second = b"--- PASS: TestImplicitsInfo (9.99s)\nPASS\n"
        self.assertEqual(budget.stdout_digest(loaded, first), budget.stdout_digest(loaded, second))

    def test_fixture_workload_materializes_exact_paths_before_exec(self):
        loaded = budget.load_manifest(self.manifest_path)
        mount, argv = budget.materialized_guest_command(loaded)
        self.assertEqual(mount, (self.root / "fixture").resolve())
        self.assertEqual(argv[:2], ("/bin/sh", "-c"))
        self.assertIn("cp '/native-compiler-w2/input.go' '/work/input.go'", argv[2])
        self.assertEqual(argv[-len(loaded.argv) :], loaded.argv)

    def test_work_product_contract_rejects_missing_duplicate_or_changed_digest(self):
        self.write_manifest()
        loaded = budget.load_manifest(self.manifest_path)
        valid = "NATIVEWORK1|output_sha256=" + "3" * 64
        budget.validate_work_product(loaded, [valid])
        with self.assertRaisesRegex(budget.BudgetError, "missing work-product"):
            budget.validate_work_product(loaded, [])
        with self.assertRaisesRegex(budget.BudgetError, "duplicate work-product"):
            budget.validate_work_product(loaded, [valid, valid])
        with self.assertRaisesRegex(budget.BudgetError, "work-product digest mismatch"):
            budget.validate_work_product(
                loaded, ["NATIVEWORK1|output_sha256=" + "4" * 64]
            )


FRAME_NAMES = (
    "core",
    "exits",
    "sensitive",
    "phases-a",
    "phases-b",
    "resolver-thread",
    "resolver-process",
    "resolver-times",
    "cache-gauge",
)


def nativeperf_frames(pid=10, tid=11, era=12):
    prefix = f"NATIVEPERF1|thread|complete=1|pid={pid}|tid={tid}|era={era}|frame="
    return [
        prefix + "core|gateway_entries=2|reconciled_exits=2|overflowed=0",
        prefix
        + "exits|exit_syscall=1|exit_resolve_direct=1|exit_resolve_indirect=0|"
        "exit_sensitive=0|exit_fault=0|exit_kick=0|exit_stale_generation=0|"
        "exit_unsupported=0",
        prefix
        + "sensitive|sensitive_exclusive=0|sensitive_read_tpidr=0|"
        "sensitive_write_tpidr=0|sensitive_read_ctr=0|sensitive_read_dczid=0|"
        "sensitive_dc_zva=0|sensitive_dc_cvau=0|sensitive_ic_ivau=0",
        prefix
        + "phases-a|phase_prepare_index_ns=10|phase_prepare_index_count=2|"
        "phase_translate_ns=3|phase_translate_count=1|phase_translated_run_ns=20|"
        "phase_translated_run_count=2|phase_finish_exit_ns=4|phase_finish_exit_count=2",
        prefix
        + "phases-b|phase_sensitive_emulation_ns=0|phase_sensitive_emulation_count=0|"
        "phase_syscall_dispatch_ns=5|phase_syscall_dispatch_count=1|"
        "phase_loop_quiesce_ns=2|phase_loop_quiesce_count=2|phase_blocked_ns=0|"
        "phase_blocked_count=1",
        prefix
        + "resolver-thread|translate_phase_nested_ns=3|resolver_exits=1|"
        "one_entry_hits=0|gateway_entries=2|syscall_exits=1|direct_resolver_exits=1",
        prefix
        + "resolver-process|translations=1|duplicate_publications=0|cache_lookups=1|"
        "cache_lookup_hits=0|invalidated_blocks=0",
        prefix
        + "resolver-times|nested_translation_ns=3|nested_translation_decode_ns=1|"
        "nested_translation_plan_ns=1|nested_translation_emit_ns=1|"
        "nested_translation_publication_ns=0",
        prefix + "cache-gauge|cache_used_bytes=64|cache_capacity_bytes=4096",
    ]


class NativePerfTests(unittest.TestCase):
    def test_profile_requires_complete_unique_nine_frame_groups(self):
        profile = budget.parse_nativeperf(nativeperf_frames())
        budget.validate_profile(profile)
        self.assertEqual(profile.threads[0].gateway_entries, 2)
        self.assertEqual(profile.threads[0].frames, frozenset(FRAME_NAMES))

    def test_profile_keeps_process_deltas_distinct_from_cache_gauges(self):
        first = nativeperf_frames(pid=10)
        second = nativeperf_frames(pid=20)
        second[-1] = second[-1].replace("cache_used_bytes=64", "cache_used_bytes=1")
        profile = budget.parse_nativeperf(first + second)
        budget.validate_profile(profile)
        self.assertEqual(
            sum(thread.value("resolver-process", "translations") for thread in profile.threads),
            2,
        )
        self.assertEqual(
            [thread.value("cache-gauge", "cache_used_bytes") for thread in profile.threads],
            [64, 1],
        )
        missing_delta = [line for line in first if "frame=resolver-process" not in line]
        with self.assertRaisesRegex(budget.BudgetError, "missing profile frames.*resolver-process"):
            budget.parse_nativeperf(missing_delta)

    def test_profile_decision_inputs_use_hottest_thread_and_cpu_deltas(self):
        profile = budget.parse_nativeperf(nativeperf_frames())
        budget.validate_profile(profile)
        values = dict(budget.profile_decision_inputs(profile, cpu_ns=100))
        self.assertEqual(values["sensitive_exclusive"], 0.0)
        self.assertEqual(values["resolver_recurrence"], 0.5)
        self.assertEqual(values["cold_translation_ns"], 3)
        self.assertNotIn("first_resolution_ns", values)
        self.assertEqual(values["syscall_dispatch_ns"], 5)
        self.assertEqual(values["blocked_residual_ns"], 0)

    def test_profile_rejects_duplicate_frame(self):
        lines = nativeperf_frames()
        with self.assertRaisesRegex(budget.BudgetError, "duplicate frame"):
            budget.parse_nativeperf(lines + [lines[0]])

    def test_profile_rejects_incomplete_group(self):
        with self.assertRaisesRegex(budget.BudgetError, "missing profile frames"):
            budget.parse_nativeperf(nativeperf_frames()[:-1])

    def test_profile_rejects_duplicate_thread_identity(self):
        first = nativeperf_frames()
        second = nativeperf_frames()
        with self.assertRaisesRegex(budget.BudgetError, "duplicate thread"):
            budget.validate_profile(budget.parse_nativeperf(first + second))

    def test_profile_rejects_invalid_overflow_and_exit_mismatch(self):
        with self.assertRaisesRegex(budget.BudgetError, "invalid native profile"):
            budget.parse_nativeperf(
                ["NATIVEPERF1|invalid|complete=0|pid=10|tid=11|era=12|reason=counter-overflow"]
            )
        overflow = nativeperf_frames()
        overflow[0] = overflow[0].replace("overflowed=0", "overflowed=1")
        with self.assertRaisesRegex(budget.BudgetError, "overflow"):
            budget.validate_profile(budget.parse_nativeperf(overflow))
        mismatch = nativeperf_frames()
        mismatch[0] = mismatch[0].replace("reconciled_exits=2", "reconciled_exits=1")
        with self.assertRaisesRegex(budget.BudgetError, "exit reconciliation"):
            budget.validate_profile(budget.parse_nativeperf(mismatch))

    def test_profile_rejects_unknown_or_duplicate_fields(self):
        unknown = nativeperf_frames()
        unknown[0] += "|surprise=1"
        with self.assertRaisesRegex(budget.BudgetError, "unknown field"):
            budget.parse_nativeperf(unknown)
        duplicate = nativeperf_frames()
        duplicate[0] += "|gateway_entries=2"
        with self.assertRaisesRegex(budget.BudgetError, "duplicate protocol field"):
            budget.parse_nativeperf(duplicate)


class CaptureAndScheduleTests(unittest.TestCase):
    def test_docker_phase_rejects_any_live_carrick_process(self):
        clean = "  10 launchd\n  20 Docker Desktop\n"
        budget.validate_no_live_carrick(clean)
        with self.assertRaisesRegex(budget.BudgetError, "Carrick process.*431"):
            budget.validate_no_live_carrick(
                "  10 launchd\n  431 carrick\n  432 carrick:task2-w2\n"
            )

    def test_toolexec_wrapper_records_then_execs_real_tool(self):
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / "capture.bin"
            wrapper = pathlib.Path(__file__).with_name("native-compiler-toolexec.sh")
            result = subprocess.run(
                [wrapper, "/usr/bin/printf", "%s", "ok"],
                env={**os.environ, "CARRICK_TOOLEXEC_LOG": str(log)},
                check=True,
                capture_output=True,
            )
            self.assertEqual(result.stdout, b"ok")
            self.assertEqual(
                budget.parse_toolexec_capture(log.read_bytes()),
                [("/usr/bin/printf", "%s", "ok")],
            )

    def test_toolexec_wrapper_keeps_concurrent_records_atomic(self):
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / "capture.bin"
            wrapper = pathlib.Path(__file__).with_name("native-compiler-toolexec.sh")
            env = {**os.environ, "CARRICK_TOOLEXEC_LOG": str(log)}
            processes = [
                subprocess.Popen(
                    [wrapper, "/usr/bin/true", f"argument-{index}-" + "x" * 200],
                    env=env,
                )
                for index in range(32)
            ]
            self.assertTrue(all(process.wait() == 0 for process in processes))
            records = budget.parse_toolexec_capture(log.read_bytes())
            self.assertEqual(len(records), 32)
            self.assertEqual(len(set(records)), 32)

    def test_toolexec_records_are_nul_delimited_and_incomplete_fails_closed(self):
        raw = b"TOOLEXEC1\0/tool/compile\0-o\0out.o\0input.go\0\0"
        self.assertEqual(
            budget.parse_toolexec_capture(raw),
            [("/tool/compile", "-o", "out.o", "input.go")],
        )
        with self.assertRaisesRegex(budget.BudgetError, "incomplete toolexec"):
            budget.parse_toolexec_capture(raw[:-1])

    def test_abba_schedule_has_warmups_then_five_samples_per_mode(self):
        schedule = budget.abba_schedule(samples=5)
        self.assertEqual(schedule[:2], ("off-warmup", "on-warmup"))
        self.assertEqual(len(schedule), 12)
        self.assertEqual(schedule[2:6], ("off-1", "on-1", "on-2", "off-2"))
        self.assertEqual(schedule[-2:], ("off-5", "on-5"))
        self.assertEqual(sum(item.startswith("off-") for item in schedule[2:]), 5)
        self.assertEqual(sum(item.startswith("on-") for item in schedule[2:]), 5)

    def test_resolved_abba_schedule_drives_every_label_and_plane(self):
        entries = budget.resolve_run_schedule("abba-5")
        self.assertEqual(len(entries), 12)
        self.assertEqual(entries[0], ("off-warmup", "untraced", 0))
        self.assertEqual(entries[1], ("on-warmup", "profiled", 0))
        self.assertEqual(entries[-2:], (("off-5", "untraced", 5), ("on-5", "profiled", 5)))
        explicit = ",".join(budget.abba_schedule(samples=5))
        self.assertEqual(budget.resolve_run_schedule(explicit), entries)
        with self.assertRaisesRegex(budget.BudgetError, "complete ABBA"):
            budget.resolve_run_schedule("off-1,on-1")

    def test_time_l_parser_requires_all_fields(self):
        parsed = budget.parse_time_l(
            "0.01 real 0.02 user 0.03 sys\n"
            "  123456  maximum resident set size\n"
            "  0  involuntary context switches\n"
        )
        self.assertEqual(parsed.wall_ns, 10_000_000)
        self.assertEqual(parsed.user_ns, 20_000_000)
        self.assertEqual(parsed.system_ns, 30_000_000)
        self.assertEqual(parsed.peak_rss_bytes, 123456)
        with self.assertRaisesRegex(budget.BudgetError, "malformed /usr/bin/time"):
            budget.parse_time_l("0.01 real 0.02 user 0.03 sys\n")


class ReviewFixContractTests(unittest.TestCase):
    def test_carrick_transaction_always_cleans_up_and_writes_receipt(self):
        for failure in ("launch", "time", "artifact-parse"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                artifact = pathlib.Path(temp)
                calls = []

                def operation():
                    raise RuntimeError(failure)

                def cleanup(run_id):
                    calls.append(("cleanup", run_id))
                    return subprocess.CompletedProcess(["kill.sh", run_id], 0, "reaped\n", "")

                def absent(run_id):
                    calls.append(("absent", run_id))

                with self.assertRaisesRegex(RuntimeError, failure):
                    budget.carrick_transaction(
                        pathlib.Path(temp),
                        artifact,
                        "review-run",
                        operation,
                        cleanup_runner=cleanup,
                        absence_checker=absent,
                    )
                self.assertEqual(
                    calls,
                    [("cleanup", "review-run"), ("absent", "review-run")],
                )
                receipt = json.loads((artifact / "cleanup.json").read_text())
                self.assertEqual(receipt["status"], "clean")
                self.assertTrue(receipt["descendants_absent"])

    def test_cleanup_failure_is_receipted_and_dominates_operation_success(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = pathlib.Path(temp)

            def cleanup(run_id):
                return subprocess.CompletedProcess(["kill.sh", run_id], 1, "", "denied")

            with self.assertRaisesRegex(budget.BudgetError, "scoped cleanup failed"):
                budget.carrick_transaction(
                    pathlib.Path(temp),
                    artifact,
                    "review-run",
                    lambda: "result",
                    cleanup_runner=cleanup,
                    absence_checker=lambda _: None,
                )
            receipt = json.loads((artifact / "cleanup.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertFalse(receipt["descendants_absent"])

    def test_carrick_preflight_is_a_consumed_receipt_not_a_docker_call(self):
        manifest = mock.Mock(
            name="manifest",
            manifest_path=pathlib.Path("/tmp/w1.json"),
            image_digest="sha256:" + "1" * 64,
            executable_sha256="2" * 64,
            files=(),
        )
        receipt = budget.OracleReceipt(
            schema="carrick.native-compiler-oracle-preflight.v1",
            manifest_sha256="3" * 64,
            image_digest=manifest.image_digest,
            executable_sha256=manifest.executable_sha256,
            guest_files=(),
            oracle_status="verified",
        )
        with mock.patch.object(budget, "_sha256_path", return_value="3" * 64), mock.patch.object(
            budget, "_assert_image_identity", side_effect=AssertionError("Docker called")
        ):
            budget.validate_oracle_receipt(manifest, receipt)
        changed = dataclasses.replace(receipt, image_digest="sha256:" + "4" * 64)
        with mock.patch.object(budget, "_sha256_path", return_value="3" * 64):
            with self.assertRaisesRegex(budget.BudgetError, "preflight.*image"):
                budget.validate_oracle_receipt(manifest, changed)

    def test_dtrace_command_and_summary_are_durable_and_strict(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = pathlib.Path(temp)
            command = budget.dtrace_command(
                pathlib.Path("/repo/target/release/carrick"),
                ["/repo/target/release/carrick", "run", "image", "/bin/true"],
                artifact,
            )
            self.assertEqual(command[:4], [
                "/repo/target/release/carrick",
                "trace",
                "--profile",
                "dsr",
            ])
            self.assertIn(str(artifact / "dtrace.raw"), command)
            self.assertIn(str(artifact / "dtrace-summary.jsonl"), command)

            summary = artifact / "dtrace-summary.jsonl"
            rows = dtrace_rows(run_id="run-1", pid=42)
            summary.write_text("".join(json.dumps(row) + "\n" for row in rows))
            parsed = budget.parse_dtrace_summary(summary, expected_run_id="run-1")
            self.assertTrue(parsed.complete)
            self.assertEqual(parsed.per_pid_gateway_counts, ((42, 2),))
            self.assertEqual(parsed.exit_mix, ((1, 1), (2, 1)))
            bad = [
                {**row, "completion": {**row["completion"], "incomplete_pairs": 1}}
                for row in rows
            ]
            summary.write_text("".join(json.dumps(row) + "\n" for row in bad))
            with self.assertRaisesRegex(budget.BudgetError, "DTrace.*incomplete"):
                budget.parse_dtrace_summary(summary, expected_run_id="run-1")

    def test_typed_outcomes_record_trap_ceiling_but_analysis_rejects_it(self):
        marker = budget.parse_max_traps_marker(
            ["native Darwin guest thread 42 error: guest did not exit after 1000000 traps"]
        )
        self.assertIsNotNone(marker)
        outcome = budget.classify_outcome(
            engine="carrick",
            status=2,
            expected_status=0,
            stdout_matches=False,
            gateway_entries=1_000_000,
            gateway_limit=1_000_000,
            max_traps_marker=marker,
            ceiling_profile_identity=(41, 42, 7),
        )
        self.assertEqual(outcome.kind, "max-traps")
        self.assertEqual(outcome.exit_status, 2)
        self.assertEqual(outcome.work_units_completed, 0)
        record = budget.RunRecord.synthetic(outcome=outcome)
        with self.assertRaisesRegex(budget.BudgetError, "completed outcomes"):
            budget.analyze([record])

    def test_exit_two_without_exact_max_traps_marker_is_failed(self):
        outcome = budget.classify_outcome(
            engine="carrick",
            status=2,
            expected_status=0,
            stdout_matches=False,
            gateway_entries=1_000_000,
            gateway_limit=1_000_000,
            max_traps_marker=None,
        )
        self.assertEqual(outcome.kind, "failed")

    def test_forged_or_mismatched_max_traps_marker_is_rejected(self):
        with self.assertRaisesRegex(budget.BudgetError, "marker.*ceiling"):
            budget.classify_outcome(
                engine="carrick",
                status=2,
                expected_status=0,
                stdout_matches=False,
                gateway_entries=999_999,
                gateway_limit=1_000_000,
                max_traps_marker=budget.MaxTrapsMarker(42, 1_000_000),
                ceiling_profile_identity=(41, 42, 7),
            )
        with self.assertRaisesRegex(budget.BudgetError, "conflicting max-traps"):
            budget.parse_max_traps_marker(
                [
                    "native Darwin guest thread 42 error: guest did not exit after 1000000 traps",
                    "native Darwin guest thread 42 error: guest did not exit after 999999 traps",
                ]
            )

    def test_max_traps_marker_binds_unique_tid_profile_group(self):
        marker = budget.MaxTrapsMarker(42, 1_000_000)
        at_ceiling = budget.ProfileThread(
            41,
            42,
            7,
            frozenset(),
            (("core.gateway_entries", 1_000_000),),
        )
        unrelated = dataclasses.replace(at_ceiling, pid=99, tid=77, era=8)
        self.assertEqual(
            budget.reconcile_max_traps_marker(
                budget.ProfileRun((at_ceiling, unrelated)), marker, 1_000_000
            ),
            (41, 42, 7),
        )
        ambiguous = dataclasses.replace(at_ceiling, pid=43, era=9)
        with self.assertRaisesRegex(budget.BudgetError, "one exact profile group"):
            budget.reconcile_max_traps_marker(
                budget.ProfileRun((at_ceiling, ambiguous)), marker, 1_000_000
            )

    def test_baseline_schedule_is_explicit_two_phase_w1_w2(self):
        schedule = budget.baseline_schedule(samples=5)
        self.assertEqual(schedule[:4], (
            ("carrick", "w1", "warmup", 0),
            ("carrick", "w2", "warmup", 0),
            ("carrick", "w1", "measured", 1),
            ("carrick", "w2", "measured", 1),
        ))
        self.assertEqual(schedule[12:16], (
            ("docker", "w1", "warmup", 0),
            ("docker", "w2", "warmup", 0),
            ("docker", "w1", "measured", 1),
            ("docker", "w2", "measured", 1),
        ))
        first_docker = next(index for index, row in enumerate(schedule) if row[0] == "docker")
        self.assertTrue(all(row[0] == "carrick" for row in schedule[:first_docker]))
        self.assertTrue(all(row[0] == "docker" for row in schedule[first_docker:]))

    def test_materialization_fails_closed_on_stale_or_missing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            fixture = root / "fixture"
            fixture.mkdir()
            (fixture / "input.go").write_text("package p\n")
            output = root / "out.a"
            output.write_text("stale")
            manifest = budget.WorkloadManifest(
                budget.WORKLOAD_SCHEMA,
                "fixture",
                "example.invalid/image:1",
                "sha256:" + "1" * 64,
                str(root),
                ("/usr/bin/true", "-o", str(output), str(root / "input.go")),
                (),
                (budget.HashedFile(str(root / "input.go"), "input.go", sha256(b"package p\n")),),
                "2" * 64,
                0,
                sha256(b""),
                1_000_000,
                "native16k",
                budget.W2Capture(
                    "w2-toolexec",
                    "test",
                    1,
                    (("CARRICK_TOOLEXEC_LOG", "/tmp/log"), ("GOFLAGS", "-work")),
                    (),
                    0,
                    str(output),
                    "3" * 64,
                    (
                        budget.DockerReplay(0, sha256(b""), "3" * 64),
                        budget.DockerReplay(0, sha256(b""), "3" * 64),
                    ),
                    sha256(b"w1"),
                    sha256(b""),
                    "evidence.json",
                    "4" * 64,
                    (),
                    (),
                ),
                fixture / "manifest.json",
            )
            _, argv = budget.materialized_guest_command(manifest, mount_path=fixture)
            self.assertIn("set -eu", argv[2])
            self.assertIn(f"rm -f '{output}'", argv[2])
            result = subprocess.run(argv, check=False, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

    def test_time_uses_dedicated_file_and_preserves_workload_stderr(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = pathlib.Path(temp) / "artifact"
            status, timing, _, stderr = budget._time_command(
                ["/bin/sh", "-c", "printf workload-error >&2"],
                pathlib.Path(temp),
                {**os.environ, "LC_ALL": "C"},
                artifact,
            )
            self.assertEqual(status, 0)
            self.assertEqual(stderr.read_bytes(), b"workload-error")
            self.assertGreaterEqual(timing.wall_ns, 0)
            self.assertTrue((artifact / "time.txt").read_text())
            self.assertTrue((artifact / "monotonic-diagnostic.json").is_file())

    def test_capture_schema_rejects_unknown_replay_and_environment_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            fixture = root / "fixture"
            fixture.mkdir()
            (fixture / "input.go").write_text("package p\n")
            base = strict_w2_manifest_json(fixture / "input.go")
            path = root / "manifest.json"
            base["capture"]["unknown"] = True
            path.write_text(json.dumps(base))
            with self.assertRaisesRegex(budget.BudgetError, "unknown W2 capture field"):
                budget.load_manifest(path)
            del base["capture"]["unknown"]
            base["capture"]["docker_replays"][1]["output_sha256"] = "f" * 64
            path.write_text(json.dumps(base))
            with self.assertRaisesRegex(budget.BudgetError, "matching Docker replay"):
                budget.load_manifest(path)
            base["capture"]["docker_replays"][1]["output_sha256"] = "3" * 64
            base["env"] = [["GOFLAGS", "-work"]]
            base["capture"]["replay_environment"] = base["env"]
            path.write_text(json.dumps(base))
            with self.assertRaisesRegex(budget.BudgetError, "capture-only environment"):
                budget.load_manifest(path)

    def test_additive_profile_model_counts_every_sensitive_kind_and_reconciles_cpu(self):
        lines = nativeperf_frames()
        lines[0] = lines[0].replace("gateway_entries=2", "gateway_entries=4").replace(
            "reconciled_exits=2", "reconciled_exits=4"
        )
        lines[1] = lines[1].replace("exit_resolve_direct=1", "exit_resolve_direct=0").replace(
            "exit_sensitive=0", "exit_sensitive=3"
        )
        lines[2] = lines[2].replace("sensitive_exclusive=0", "sensitive_exclusive=2").replace(
            "sensitive_dc_zva=0", "sensitive_dc_zva=1"
        )
        lines[3] = lines[3].replace("phase_prepare_index_count=2", "phase_prepare_index_count=4").replace(
            "phase_translated_run_count=2", "phase_translated_run_count=4"
        ).replace("phase_finish_exit_count=2", "phase_finish_exit_count=4")
        lines[4] = lines[4].replace(
            "phase_sensitive_emulation_ns=0|phase_sensitive_emulation_count=0",
            "phase_sensitive_emulation_ns=6|phase_sensitive_emulation_count=3",
        ).replace("phase_loop_quiesce_count=2", "phase_loop_quiesce_count=4")
        lines[5] = lines[5].replace("gateway_entries=2", "gateway_entries=4").replace(
            "direct_resolver_exits=1", "direct_resolver_exits=0"
        )
        profile = budget.parse_nativeperf(lines)
        counts = budget.derive_count_evidence(profile)
        self.assertEqual(dict(counts.sensitive_shares)["exclusive"], 0.5)
        self.assertEqual(dict(counts.sensitive_shares)["dc-zva"], 0.25)
        self.assertFalse(counts.resolver_recurring_pc_verified)
        # 10 + 3 + 20 + 4 + 6 + 5 + 2 = 50 on-CPU ns. Blocked is
        # separately retained and never double-counted into the CPU sum.
        additive = budget.derive_additive_cpu_evidence(profile, cpu_ns=50)
        self.assertEqual(additive.exclusive_sum_ns, 50)
        self.assertEqual(additive.blocked_ns, 0)
        self.assertEqual(additive.residual_ns, 0)
        self.assertIsNone(additive.first_resolution_ns)
        with self.assertRaisesRegex(budget.BudgetError, "negative additive residual"):
            budget.derive_additive_cpu_evidence(profile, cpu_ns=49)
        with self.assertRaisesRegex(budget.BudgetError, "2%"):
            budget.derive_additive_cpu_evidence(profile, cpu_ns=52)

    def test_result_wire_is_strict_tagged_and_recomputes_profile_inputs(self):
        profile = budget.parse_nativeperf(nativeperf_frames())
        record = budget.RunRecord.synthetic(profile=profile, schedule_label="on-1")
        encoded = budget.run_record_json(record)
        self.assertEqual(encoded["record"], "run")
        self.assertEqual(encoded["outcome"]["kind"], "completed")
        self.assertIn("timing", encoded)
        self.assertNotIn("decision_inputs", encoded)
        decoded = budget.parse_result_row(encoded)
        self.assertEqual(decoded.profile, profile)
        changed = json.loads(json.dumps(encoded))
        changed["timing"]["invented"] = 1
        with self.assertRaisesRegex(budget.BudgetError, "unknown timing field"):
            budget.parse_result_row(changed)

    def test_analyze_check_requires_exact_order_warmups_and_one_decision(self):
        profile = profile_with_budget(
            gateway_entries=100,
            sensitive_exclusive=40,
            syscall_dispatch_ns=5,
        )
        records = strict_abba_records(profile=profile, profiled_wall_ns=105)
        decision = budget.analyze(records)
        rows = [budget.run_record_json(record) for record in records]
        rows.append(budget.decision_record_json(decision))
        with tempfile.TemporaryDirectory() as temp:
            evidence = pathlib.Path(temp) / "evidence.jsonl"
            evidence.write_text("".join(json.dumps(row) + "\n" for row in rows))
            self.assertEqual(budget.analyze_evidence(evidence, check=True), decision)
            missing_warmup = [row for row in rows if row.get("schedule_label") != "off-warmup"]
            evidence.write_text("".join(json.dumps(row) + "\n" for row in missing_warmup))
            with self.assertRaisesRegex(budget.BudgetError, "exact ABBA order including warmups"):
                budget.analyze_evidence(evidence, check=True)
            evidence.write_text(
                "".join(json.dumps(row) + "\n" for row in [*rows, rows[-1]])
            )
            with self.assertRaisesRegex(budget.BudgetError, "exactly one decision"):
                budget.analyze_evidence(evidence, check=True)

    def test_analyzer_never_combines_count_and_cpu_fractions(self):
        profile = profile_with_budget(
            gateway_entries=100,
            sensitive_exclusive=29,
            syscall_dispatch_ns=31,
        )
        records = strict_abba_records(
            profile=profile,
            profiled_wall_ns=105,
            untraced_cpu_ns=100,
            profiled_cpu_ns=70,
        )
        decision = budget.analyze(records)
        self.assertEqual(decision.selected_slice, "syscall-dispatch")
        self.assertNotIn("two-term", decision.basis)


class AnalyzerTests(unittest.TestCase):
    def abba_records(self, profiled_wall_ns=105, sensitive=46, syscall_ns=0):
        return strict_abba_records(
            profile_with_budget(
                gateway_entries=100,
                sensitive_exclusive=sensitive,
                syscall_dispatch_ns=syscall_ns,
            ),
            profiled_wall_ns=profiled_wall_ns,
            untraced_cpu_ns=100,
            profiled_cpu_ns=100,
        )

    def test_decision_ignores_dtrace_wall_and_uses_profile_counts(self):
        records = self.abba_records()
        dtrace = budget.DtraceEvidence(True, False, 0, (), (), (), (("slow", 999),))
        records = [dataclasses.replace(record, dtrace=dtrace) for record in records]
        self.assertEqual(budget.analyze(records).selected_slice, "sensitive-exclusive")

    def test_fixed_sensitive_kind_order_and_fail_closed_resolver(self):
        profile = profile_with_budget(
            gateway_entries=100, sensitive_exclusive=35, syscall_dispatch_ns=0
        )
        records = strict_abba_records(profile)
        self.assertEqual(budget.analyze(records).selected_slice, "sensitive-exclusive")
        resolver_only = profile_with_budget(
            gateway_entries=100, sensitive_exclusive=0, syscall_dispatch_ns=0
        )
        with self.assertRaisesRegex(budget.BudgetError, "no independently verified"):
            budget.analyze(strict_abba_records(resolver_only, profiled_cpu_ns=39))

    def test_cleanup_failure_cannot_be_analyzed(self):
        records = self.abba_records()
        failed = dataclasses.replace(
            records[0], cleanup=budget.CleanupReceipt("failed", 1, False, "", "")
        )
        with self.assertRaisesRegex(budget.BudgetError, "cleanup metadata"):
            budget.analyze([failed, *records[1:]])

    def test_analysis_requires_exact_unique_measured_abba_labels(self):
        records = self.abba_records()
        missing = records[:-1]
        with self.assertRaisesRegex(budget.BudgetError, "exact ABBA order"):
            budget.analyze(missing)
        duplicate = [*records[:-1], dataclasses.replace(records[-1], schedule_label="on-4")]
        with self.assertRaisesRegex(budget.BudgetError, "exact ABBA order"):
            budget.analyze(duplicate)

    def test_analysis_requires_one_workload_and_binary(self):
        records = self.abba_records()
        mixed_workload = [dataclasses.replace(records[0], workload="other"), *records[1:]]
        with self.assertRaisesRegex(budget.BudgetError, "one workload, binary"):
            budget.analyze(mixed_workload)
        mixed_binary = [
            dataclasses.replace(records[0], binary_sha256="1" * 64),
            *records[1:],
        ]
        with self.assertRaisesRegex(budget.BudgetError, "one workload, binary"):
            budget.analyze(mixed_binary)

    def test_analysis_fails_without_complete_profiled_count_evidence(self):
        records = self.abba_records()
        records = [
            dataclasses.replace(record, profile=None)
            if record.plane == "profiled"
            else record
            for record in records
        ]
        with self.assertRaisesRegex(budget.BudgetError, "profiled count evidence"):
            budget.analyze(records)

    def test_high_abba_tax_excludes_duration_based_aot_decision(self):
        with self.assertRaisesRegex(budget.BudgetError, "duration evidence unavailable"):
            budget.analyze(self.abba_records(profiled_wall_ns=120, sensitive=0))

    def test_count_decision_reports_high_abba_tax_without_gating_counts(self):
        records = self.abba_records(profiled_wall_ns=120)
        decision = budget.analyze(records)
        self.assertEqual(decision.selected_slice, "sensitive-exclusive")
        self.assertAlmostEqual(decision.profile_tax, 0.20)
        self.assertFalse(decision.duration_evidence_usable)

    def test_aot_is_unavailable_without_first_resolution_and_pc_proof(self):
        with self.assertRaisesRegex(budget.BudgetError, "no independently verified"):
            budget.analyze(
                strict_abba_records(
                    profile_with_budget(
                        gateway_entries=100,
                        sensitive_exclusive=0,
                        syscall_dispatch_ns=0,
                    ),
                    profiled_wall_ns=105,
                    untraced_cpu_ns=100,
                    profiled_cpu_ns=39,
                )
            )


if __name__ == "__main__":
    unittest.main()

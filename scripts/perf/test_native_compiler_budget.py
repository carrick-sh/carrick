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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import native_compiler_budget as budget


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
            "argv": ["/usr/local/go/pkg/tool/linux_arm64/compile", "input.go"],
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
            "capture": {"source": "docker-toolexec", "captured_argv_index": 3},
        }
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
        self.manifest["capture"]["stdout_normalization"] = "go-test-duration"
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
        self.manifest["capture"].update(
            {
                "expected_output_guest_path": "/work/out.a",
                "expected_output_sha256": "3" * 64,
            }
        )
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


class AnalyzerTests(unittest.TestCase):
    def record(self, **shares):
        defaults = {
            "sensitive_exclusive": 0.0,
            "resolver_recurrence": 0.0,
            "cold_translation_ns": 0.0,
            "first_resolution_ns": 0.0,
            "syscall_dispatch_ns": 0.0,
            "blocked_residual_ns": 0.0,
        }
        defaults.update(shares)
        return budget.RunRecord.synthetic(**defaults)

    def test_decision_uses_untraced_cpu_not_dtrace_wall(self):
        records = self.abba_records(
            profiled_wall_ns=105,
            sensitive_exclusive=0.46,
            cold_translation_ns=12.0,
        )
        records = [
            record.with_dtrace_wall_shares({"cold_translation": 0.90})
            if record.plane == "profiled"
            else record
            for record in records
        ]
        self.assertEqual(budget.analyze(records).selected_slice, "sensitive-exclusive")

    def test_decision_fixed_tie_order_and_two_term_fallback(self):
        tied = self.abba_records(
            105, sensitive_exclusive=0.35, resolver_recurrence=0.35
        )
        self.assertEqual(budget.analyze(tied).selected_slice, "sensitive-exclusive")
        pair = self.abba_records(
            105, sensitive_exclusive=0.29, resolver_recurrence=0.32
        )
        self.assertEqual(budget.analyze(pair).selected_slice, "resolver-recurrence")
        two = self.abba_records(
            105,
            sensitive_exclusive=0.29,
            resolver_recurrence=0.29,
            cold_translation_ns=0,
            first_resolution_ns=0,
        )
        with self.assertRaisesRegex(budget.BudgetError, "no two-term slice"):
            budget.analyze(two)

    def test_cleanup_failure_and_warmups_cannot_be_analyzed(self):
        records = self.abba_records(105, sensitive_exclusive=0.46)
        failed = dataclasses.replace(records[0], cleanup_ok=False)
        with self.assertRaisesRegex(budget.BudgetError, "invalid or incomplete"):
            budget.analyze([failed, *records[1:]])
        warmup = dataclasses.replace(records[0], schedule_label="off-warmup")
        with self.assertRaisesRegex(budget.BudgetError, "measured run"):
            budget.analyze([warmup])

    def abba_records(self, profiled_wall_ns, **profiled_shares):
        records = []
        for index in range(1, 6):
            off = self.record()
            records.append(
                dataclasses.replace(
                    off,
                    plane="untraced",
                    repetition=index,
                    run_id=f"off-{index}",
                    wall_ns=100,
                    user_ns=100,
                    system_ns=0,
                    decision_inputs=(),
                    schedule_label=f"off-{index}",
                )
            )
            shares = {
                "sensitive_exclusive": 0.0,
                "resolver_recurrence": 0.0,
                "cold_translation_ns": 20,
                "first_resolution_ns": 15,
            }
            shares.update(profiled_shares)
            on = self.record(**shares)
            records.append(
                dataclasses.replace(
                    on,
                    plane="profiled",
                    repetition=index,
                    run_id=f"on-{index}",
                    wall_ns=profiled_wall_ns,
                    user_ns=100,
                    system_ns=0,
                    schedule_label=f"on-{index}",
                )
            )
        return records

    def test_analysis_requires_exact_unique_measured_abba_labels(self):
        records = self.abba_records(105, sensitive_exclusive=0.46)
        missing = records[:-1]
        with self.assertRaisesRegex(budget.BudgetError, "complete measured ABBA"):
            budget.analyze(missing)
        duplicate = [*records[:-1], dataclasses.replace(records[-1], schedule_label="on-4")]
        with self.assertRaisesRegex(budget.BudgetError, "complete measured ABBA"):
            budget.analyze(duplicate)

    def test_analysis_requires_one_workload_and_binary(self):
        records = self.abba_records(105, sensitive_exclusive=0.46)
        mixed_workload = [dataclasses.replace(records[0], workload="other"), *records[1:]]
        with self.assertRaisesRegex(budget.BudgetError, "one workload and binary"):
            budget.analyze(mixed_workload)
        mixed_binary = [
            dataclasses.replace(records[0], binary_sha256="1" * 64),
            *records[1:],
        ]
        with self.assertRaisesRegex(budget.BudgetError, "one workload and binary"):
            budget.analyze(mixed_binary)

    def test_analysis_fails_without_complete_profiled_count_evidence(self):
        records = self.abba_records(105)
        records = [
            dataclasses.replace(record, decision_inputs=())
            if record.plane == "profiled"
            else record
            for record in records
        ]
        with self.assertRaisesRegex(budget.BudgetError, "profiled count evidence"):
            budget.analyze(records)

    def test_high_abba_tax_excludes_duration_based_aot_decision(self):
        with self.assertRaisesRegex(budget.BudgetError, "duration evidence unavailable"):
            budget.analyze(self.abba_records(profiled_wall_ns=120))

    def test_count_decision_reports_high_abba_tax_without_gating_counts(self):
        records = self.abba_records(profiled_wall_ns=120)
        records = [
            dataclasses.replace(
                record,
                decision_inputs=tuple(
                    sorted({**dict(record.decision_inputs), "sensitive_exclusive": 0.46}.items())
                ),
            )
            if record.plane == "profiled"
            else record
            for record in records
        ]
        decision = budget.analyze(records)
        self.assertEqual(decision.selected_slice, "sensitive-exclusive")
        self.assertAlmostEqual(decision.profile_tax, 0.20)
        self.assertFalse(decision.duration_evidence_usable)

    def test_aot_decision_requires_low_tax_untraced_cpu_and_run_ids(self):
        decision = budget.analyze(self.abba_records(profiled_wall_ns=105))
        self.assertEqual(decision.selected_slice, "cold-translation-aot-design")
        self.assertEqual(decision.share, 0.35)
        self.assertLessEqual(decision.profile_tax, 0.10)
        self.assertTrue(decision.duration_evidence_usable)
        self.assertEqual(
            decision.supporting_run_ids,
            tuple(f"{mode}-{index}" for index in range(1, 6) for mode in ("off", "on")),
        )


if __name__ == "__main__":
    unittest.main()

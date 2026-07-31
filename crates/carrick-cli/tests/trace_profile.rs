#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn cli() -> Command {
    Command::cargo_bin("carrick").unwrap()
}

#[test]
fn native_profile_qualification_fixtures_are_hidden_and_deterministic() {
    cli()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("__native-profile-birth-fixture").not())
        .stdout(predicates::str::contains("__native-profile-terminal-fixture").not())
        .stdout(predicates::str::contains("__native-profile-validate-qualification").not());

    cli()
        .args(["__native-profile-birth-fixture", "--hold-ms", "10"])
        .assert()
        .success()
        .stdout("BIRTH_FIXTURE_OK\n");

    cli()
        .args(["__native-profile-terminal-fixture", "--mode", "thread"])
        .assert()
        .success()
        .stdout("TERMINAL_THREAD_ARMED\nTERMINAL_THREAD_OK\n");

    cli()
        .args(["__native-profile-terminal-fixture", "--mode", "process"])
        .assert()
        .success()
        .stdout("TERMINAL_PROCESS_ARMED\n");

    for arguments in [
        vec![
            "__native-profile-birth-fixture",
            "--hold-ms",
            "10",
            "--quiet",
        ],
        vec![
            "__native-profile-terminal-fixture",
            "--mode",
            "thread",
            "--quiet",
        ],
        vec![
            "__native-profile-terminal-fixture",
            "--mode",
            "process",
            "--quiet",
        ],
    ] {
        cli().args(arguments).assert().success().stdout("");
    }
}

#[test]
fn native_profile_qualification_scripts_bind_observed_identity_and_scope() {
    let scripts = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/dtrace");
    let birth = std::fs::read_to_string(scripts.join("native-birth-qualify.d")).unwrap();
    for contract in [
        "carrick*:::host-process-birth",
        "proc:::create",
        "parent_observations < 2",
        "child_context_seen < 2",
        "copyinstr(arg1) == \"BIRTH_FIXTURE_OK\\n\"",
        "child_exit_reason",
        "target_exit_reason",
        "timed_out",
        "violations",
    ] {
        assert!(
            birth.contains(contract),
            "missing birth contract {contract:?}"
        );
    }
    assert!(
        !birth.contains("curpsinfo->pr_start"),
        "Darwin proc-provider start fields were live-proven zero"
    );

    let terminal = std::fs::read_to_string(scripts.join("native-terminal-qualify.d")).unwrap();
    for contract in [
        "syscall:::entry",
        "syscall:::return",
        "mach_trap:::entry",
        "mach_trap:::return",
        "proc:::lwp-exit",
        "proc:::exit",
        "scope=thread",
        "scope=process",
        "returning_controls",
        "candidate_count",
        "timed_out",
        "violations",
    ] {
        assert!(
            terminal.contains(contract),
            "missing terminal contract {contract:?}"
        );
    }
}

const DSRPROF2_FIXTURE: &str = concat!(
    "DSRPROF2|header|profile=native-wall|raw_schema=carrick.dsrprof.raw.v2|os_build=26A123|program_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|birth_qualification_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb|terminal_qualification_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc|wall_hz=197|cpu_hz=499\n",
    "DSRPROF2|target-birth|pid=100|start_sec=10|start_usec=20|image=1|epoch=0\n",
    "DSRPROF2|range-reset|pid=100|start_sec=10|start_usec=20|image=1|epoch=0\n",
    "DSRPROF2|range-private|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|sequence=1|start=0x1000|end=0x2000\n",
    "DSRPROF2|range-shared|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|sequence=2|unit_id=7|start=0x3000|end=0x3800\n",
    "DSRPROF2|range-shared|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|sequence=3|unit_id=8|start=0x4000|end=0x4800\n",
    "DSRPROF2|range-ready|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|final_sequence=3\n",
    "DSRPROF2|host-image-base|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|base=0x100000000\n",
    "DSRPROF2|host-image-catalog|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|payload={\"ranges\":[{\"start\":4294967296,\"end\":4294971392,\"path\":\"/carrick\"}]}\n",
    "DSRPROF2|guest-image-base|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|base=0x400000\n",
    "DSRPROF2|cpu-user|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|pc=0x1100|count=3\n",
    "DSRPROF2|kernel-enter|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|provider=syscall|function=read|class=named-syscall|timestamp_ns=1000\n",
    "DSRPROF2|kernel-return|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|provider=syscall|function=read|class=named-syscall|timestamp_ns=1200\n",
    "DSRPROF2|offcpu-block|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|episode=1|kind=voluntary|pc=0x1150|timestamp_ns=1300\n",
    "DSRPROF2|offcpu-wake|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|episode=1|observed_pid=100|observed_sec=10|observed_usec=20|observed_image=1|observed_epoch=0|timestamp_ns=1800\n",
    "DSRPROF2|offcpu|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=voluntary|pc=0x1150|count=1|total_ns=500\n",
    "DSRPROF2|process-create|child_pid=101|child_sec=11|child_usec=21|child_image=1|child_epoch=0|parent_pid=100|parent_sec=10|parent_usec=20|parent_image=1|parent_epoch=0\n",
    "DSRPROF2|fork-inherit|child_pid=101|child_sec=11|child_usec=21|parent_pid=100|parent_sec=10|parent_usec=20|parent_image=1|parent_epoch=0|range_frontier=3|mapping_frontier=0\n",
    "DSRPROF2|range-reset|pid=101|start_sec=11|start_usec=21|image=1|epoch=1\n",
    "DSRPROF2|range-private|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|sequence=1|start=0x1000|end=0x2000\n",
    "DSRPROF2|range-shared|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|sequence=2|unit_id=7|start=0x3000|end=0x3800\n",
    "DSRPROF2|range-shared|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|sequence=3|unit_id=8|start=0x4000|end=0x4800\n",
    "DSRPROF2|range-ready|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|final_sequence=3\n",
    "DSRPROF2|range-shared|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|sequence=4|unit_id=9|start=0x5000|end=0x5800\n",
    "DSRPROF2|range-ready|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|final_sequence=4\n",
    "DSRPROF2|exec-attempt|pid=101|start_sec=11|start_usec=21|image=1|epoch=1\n",
    "DSRPROF2|exec-failure|pid=101|start_sec=11|start_usec=21|image=1|epoch=1\n",
    "DSRPROF2|exec-attempt|pid=101|start_sec=11|start_usec=21|image=1|epoch=1\n",
    "DSRPROF2|exec-success|pid=101|start_sec=11|start_usec=21|retired_image=1|retired_epoch=1|new_image=2|new_epoch=0\n",
    "DSRPROF2|range-reset|pid=101|start_sec=11|start_usec=21|image=2|epoch=0\n",
    "DSRPROF2|range-private|pid=101|start_sec=11|start_usec=21|image=2|epoch=0|sequence=1|start=0x6000|end=0x7000\n",
    "DSRPROF2|range-ready|pid=101|start_sec=11|start_usec=21|image=2|epoch=0|final_sequence=1\n",
    "DSRPROF2|process-exit|pid=101|start_sec=11|start_usec=21|image=2|epoch=0|reason=1\n",
    "DSRPROF2|process-exit|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|reason=1\n",
    "DSRPROF2|wall-state|kind=on-cpu|count=10\n",
    "DSRPROF2|wall-state|kind=all-sleeping|count=1\n",
    "DSRPROF2|complete|profile=native-wall|bounded=0|target_exit_reason=1|live_at_end=0\n",
);

fn validate_dsrprof2_fixture(contents: &str, extra_args: &[&str]) -> assert_cmd::assert::Assert {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut file, contents.as_bytes()).unwrap();
    let mut command = cli();
    command
        .arg("__native-profile-validate")
        .arg("--input")
        .arg(file.path())
        .args(extra_args);
    command.assert()
}

#[test]
fn dsrprof2_accepts_birth_keyed_lifecycle_fixture() {
    validate_dsrprof2_fixture(DSRPROF2_FIXTURE, &[])
        .success()
        .stdout(contains("DSRPROF2_VALID"));
}

#[test]
fn dsrprof2_preserves_exact_stack_blocks() {
    let process_create = "DSRPROF2|process-create|child_pid=101|child_sec=11|child_usec=21|child_image=1|child_epoch=0|parent_pid=100|parent_sec=10|parent_usec=20|parent_image=1|parent_epoch=0";
    let stack = concat!(
        "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=offcpu-voluntary|count=1|total_ns=500\n",
        "libsystem_kernel.dylib`__psynch_cvwait+0xa\n",
        "carrick`wait_for_translation+0x20\n",
        "DSRSTACK2|end\n",
    );
    let valid = DSRPROF2_FIXTURE.replacen(process_create, &format!("{stack}{process_create}"), 1);
    validate_dsrprof2_fixture(&valid, &[]).success();

    for corrupt_stack in [
        "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=offcpu-voluntary|count=1|total_ns=500\nDSRSTACK2|end\n",
        "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=offcpu-voluntary|count=1|total_ns=500|extra=1\nframe\nDSRSTACK2|end\n",
        "DSRSTACK2|end\n",
        "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=offcpu-voluntary|count=1|total_ns=500\nDSRPROF2|wall-state|kind=on-cpu|count=1\nDSRSTACK2|end\n",
    ] {
        let corrupt = DSRPROF2_FIXTURE.replacen(
            process_create,
            &format!("{corrupt_stack}{process_create}"),
            1,
        );
        validate_dsrprof2_fixture(&corrupt, &[]).failure();
    }
}

#[test]
fn dsrprof2_rejects_corrupt_lifecycle_fixtures() {
    let process_create = "DSRPROF2|process-create|child_pid=101|child_sec=11|child_usec=21|child_image=1|child_epoch=0|parent_pid=100|parent_sec=10|parent_usec=20|parent_image=1|parent_epoch=0";
    let fork_inherit = "DSRPROF2|fork-inherit|child_pid=101|child_sec=11|child_usec=21|parent_pid=100|parent_sec=10|parent_usec=20|parent_image=1|parent_epoch=0|range_frontier=3|mapping_frontier=0";
    let cpu_user =
        "DSRPROF2|cpu-user|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|pc=0x1100|count=3";
    let target_birth = "DSRPROF2|target-birth|pid=100|start_sec=10|start_usec=20|image=1|epoch=0";
    let parent_later_range = "DSRPROF2|range-shared|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|sequence=4|unit_id=9|start=0x5000|end=0x5800";
    let kernel_return = "DSRPROF2|kernel-return|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|provider=syscall|function=read|class=named-syscall|timestamp_ns=1200";
    let offcpu_block = "DSRPROF2|offcpu-block|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|episode=1|kind=voluntary|pc=0x1150|timestamp_ns=1300";
    let offcpu_wake = "DSRPROF2|offcpu-wake|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|episode=1|observed_pid=100|observed_sec=10|observed_usec=20|observed_image=1|observed_epoch=0|timestamp_ns=1800";
    let offcpu_summary = "DSRPROF2|offcpu|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=voluntary|pc=0x1150|count=1|total_ns=500";
    let exec_success = "DSRPROF2|exec-success|pid=101|start_sec=11|start_usec=21|retired_image=1|retired_epoch=1|new_image=2|new_epoch=0";
    let old_host_catalog = "DSRPROF2|host-image-catalog|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|payload={\"ranges\":[{\"start\":4294967296,\"end\":4294971392,\"path\":\"/carrick\"}]}";

    let duplicate_create = DSRPROF2_FIXTURE.replacen(
        fork_inherit,
        &format!("{process_create}\n{fork_inherit}"),
        1,
    );
    let sample_before_birth = DSRPROF2_FIXTURE
        .replacen(&format!("{cpu_user}\n"), "", 1)
        .replacen(target_birth, &format!("{cpu_user}\n{target_birth}"), 1);
    let add_before_reset = DSRPROF2_FIXTURE.replacen(
        concat!(
            "DSRPROF2|range-reset|pid=100|start_sec=10|start_usec=20|image=1|epoch=0\n",
            "DSRPROF2|range-private|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|sequence=1|start=0x1000|end=0x2000"
        ),
        concat!(
            "DSRPROF2|range-private|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|sequence=1|start=0x1000|end=0x2000\n",
            "DSRPROF2|range-reset|pid=100|start_sec=10|start_usec=20|image=1|epoch=0"
        ),
        1,
    );
    let child_inherits_later_addition = DSRPROF2_FIXTURE
        .replacen(&format!("{parent_later_range}\n"), "", 1)
        .replacen(
            process_create,
            &format!("{parent_later_range}\n{process_create}"),
            1,
        );
    let nested_out_of_order = DSRPROF2_FIXTURE.replacen(
        kernel_return,
        &format!(
            "DSRPROF2|kernel-enter|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|provider=syscall|function=write|class=named-syscall|timestamp_ns=1100\n{kernel_return}"
        ),
        1,
    );
    let terminal_close_returning = DSRPROF2_FIXTURE.replacen(
        kernel_return,
        "DSRPROF2|kernel-terminal-close|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|provider=syscall|function=read|class=named-syscall|scope=thread|timestamp_ns=1200",
        1,
    );
    let duplicate_offcpu_block =
        DSRPROF2_FIXTURE.replacen(offcpu_wake, &format!("{offcpu_block}\n{offcpu_wake}"), 1);
    let duplicate_offcpu_summary = DSRPROF2_FIXTURE.replacen(
        process_create,
        &format!("{offcpu_summary}\n{process_create}"),
        1,
    );
    let host_catalog_after_exec = DSRPROF2_FIXTURE.replacen(
        exec_success,
        &format!("{exec_success}\n{old_host_catalog}"),
        1,
    );
    let retired_transition_reuse = DSRPROF2_FIXTURE.replacen(
        exec_success,
        &format!(
            "{exec_success}\nDSRPROF2|kernel-enter|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|tid=101|provider=syscall|function=read|class=named-syscall|timestamp_ns=2000"
        ),
        1,
    );
    let child_inherits_after_frontier = DSRPROF2_FIXTURE.replacen(
        "DSRPROF2|range-ready|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|final_sequence=3",
        concat!(
            "DSRPROF2|range-shared|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|sequence=4|unit_id=9|start=0x5000|end=0x5800\n",
            "DSRPROF2|range-ready|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|final_sequence=4"
        ),
        1,
    );

    for corrupt in [
        DSRPROF2_FIXTURE.replacen("start_usec=20|image=1|epoch=0|pc=0x1100", "start_usec=22|image=1|epoch=0|pc=0x1100", 1),
        duplicate_create,
        sample_before_birth,
        DSRPROF2_FIXTURE.replacen("image=1|epoch=0|sequence=1", "image=0|epoch=0|sequence=1", 1),
        add_before_reset,
        DSRPROF2_FIXTURE.replacen("sequence=2|unit_id=7", "sequence=1|unit_id=7", 1),
        DSRPROF2_FIXTURE.replacen("sequence=2|unit_id=7", "sequence=3|unit_id=7", 1),
        DSRPROF2_FIXTURE.replacen("start=0x3000|end=0x3800", "start=0x1800|end=0x2800", 1),
        DSRPROF2_FIXTURE.replacen("final_sequence=3", "final_sequence=2", 1),
        DSRPROF2_FIXTURE.replacen("range_frontier=3", "range_frontier=4", 1),
        child_inherits_later_addition,
        child_inherits_after_frontier,
        DSRPROF2_FIXTURE.replacen("DSRPROF2|range-shared|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|sequence=2|unit_id=7|start=0x3000|end=0x3800", "DSRPROF2|range-shared|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|sequence=2|unit_id=7|start=0x3000|end=0x3900", 1),
        DSRPROF2_FIXTURE.replacen("observed_image=1", "observed_image=2", 1),
        DSRPROF2_FIXTURE.replacen("provider=syscall|function=read|class=named-syscall|timestamp_ns=1200", "provider=mach_trap|function=read|class=named-syscall|timestamp_ns=1200", 1),
        DSRPROF2_FIXTURE.replacen("function=read|class=named-syscall|timestamp_ns=1200", "function=write|class=named-syscall|timestamp_ns=1200", 1),
        DSRPROF2_FIXTURE.replacen("function=read|class=named-syscall|timestamp_ns=1200", "function=read|class=mach-trap|timestamp_ns=1200", 1),
        DSRPROF2_FIXTURE.replacen("image=1|epoch=0|tid=100|provider=syscall|function=read|class=named-syscall|timestamp_ns=1200", "image=2|epoch=0|tid=100|provider=syscall|function=read|class=named-syscall|timestamp_ns=1200", 1),
        nested_out_of_order,
        terminal_close_returning,
        DSRPROF2_FIXTURE.replacen(&format!("{kernel_return}\n"), "", 1),
        duplicate_offcpu_block,
        DSRPROF2_FIXTURE.replacen(&format!("{offcpu_wake}\n"), "", 1),
        DSRPROF2_FIXTURE.replacen("count=1|total_ns=500", "count=1|total_ns=501", 1),
        DSRPROF2_FIXTURE.replacen(&format!("{offcpu_summary}\n"), "", 1),
        duplicate_offcpu_summary,
        host_catalog_after_exec,
        retired_transition_reuse,
        DSRPROF2_FIXTURE.replacen("retired_image=1", "retired_image=2", 1),
        DSRPROF2_FIXTURE.replacen("mapping_frontier=0", "mapping_frontier=1", 1),
        DSRPROF2_FIXTURE.replacen("DSRPROF2|range-ready|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|final_sequence=3\n", "", 1),
        DSRPROF2_FIXTURE.replacen("DSRPROF2|range-ready|pid=101|start_sec=11|start_usec=21|image=2|epoch=0|final_sequence=1\n", "", 1),
        DSRPROF2_FIXTURE.replacen("live_at_end=0", "live_at_end=1", 1),
        DSRPROF2_FIXTURE.replacen("DSRPROF2|wall-state", "DSRPROF2|unknown", 1),
        DSRPROF2_FIXTURE.replacen("DSRPROF2|process-create", "DSRPROF2|process-create|unknown=1", 1),
        DSRPROF2_FIXTURE.replacen("pid=100|start_sec=10", "pid=4294967296|start_sec=10", 1),
        format!("DSRPROF1|count|phase=run|value=1\n{DSRPROF2_FIXTURE}"),
    ] {
        validate_dsrprof2_fixture(&corrupt, &[]).failure();
    }
    validate_dsrprof2_fixture(DSRPROF2_FIXTURE, &["--principal-drops", "1"]).failure();
}

#[test]
fn trace_profile_argument_relationships_are_enforced() {
    cli()
        .args([
            "trace",
            "--summary-jsonl",
            "/tmp/s.jsonl",
            "--",
            "run-elf",
            "/tmp/p",
        ])
        .assert()
        .failure()
        .stderr(contains("profile"));
    cli()
        .args([
            "trace",
            "--profile",
            "dsr",
            "--summary-jsonl",
            "/tmp/s.jsonl",
            "--script",
            "x.d",
            "--",
            "run-elf",
            "/tmp/p",
        ])
        .assert()
        .failure()
        .stderr(contains("cannot be used"));
}

#[test]
fn trace_profile_keeps_raw_and_summary_outputs_distinct() {
    cli()
        .args([
            "trace",
            "--profile",
            "dsr",
            "--trace-out",
            "/tmp/same.jsonl",
            "--summary-jsonl",
            "/tmp/same.jsonl",
            "--",
            "run-elf",
            "/tmp/p",
        ])
        .assert()
        .failure()
        .stderr(contains("different files"));
}

#[test]
fn bundled_profile_scripts_emit_one_versioned_completion() {
    for (name, profile) in [
        ("dsr-profile.d", "dsr"),
        ("dsr-indirect.d", "dsr-indirect"),
        ("dsr-fork.d", "dsr-fork"),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/dtrace")
            .join(name);
        let script = std::fs::read_to_string(path).unwrap();
        let completion =
            format!("DSRPROF1|complete|profile={profile}|bounded=%d|target_exit_reason=%d");
        assert_eq!(script.matches(&completion).count(), 1);
        assert!(script.contains("proc:::create"));
        assert!(script.contains("progenyof($target)"));
        assert!(script.contains("pid == $target"));
        assert!(script.contains("target_exit_reason = arg0"));
    }
}

#[test]
fn broad_profile_pairs_phases_and_emits_exact_metric_shapes() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/dtrace/dsr-profile.d");
    let script = std::fs::read_to_string(path).unwrap();
    for probe in [
        "dsr-prepare-begin",
        "dsr-run-begin",
        "dsr-translate-begin",
        "dsr-translate-subphase-begin",
        "dsr-translate-subphase-end",
        "dsr-resolve-begin",
        "syscall-entry",
        "dsr-cache-event",
        "dsr-cache-capacity",
        "dsr-cache-lifecycle",
    ] {
        assert!(script.contains(probe), "missing {probe}");
    }
    for record in [
        "DSRPROF1|count|phase=run",
        "DSRPROF1|total|phase=run",
        "DSRPROF1|minimum|phase=run",
        "DSRPROF1|maximum|phase=run",
        "DSRPROF1|sample|phase=run",
        "DSRPROF1|incomplete|phase=run",
        "DSRPROF1|count|phase=translation-subphase",
        "DSRPROF1|total|phase=translation-subphase",
        "DSRPROF1|minimum|phase=translation-subphase",
        "DSRPROF1|maximum|phase=translation-subphase",
        "DSRPROF1|incomplete|phase=translation-subphase",
        "DSRPROF1|high-water|metric=cache-bytes",
    ] {
        assert!(script.contains(record), "missing {record}");
    }
    for declaration in [
        "self->translate_subphase_active = 0",
        "self->translate_subphase_kind = 0",
        "self->translate_wait_active = 0",
    ] {
        assert!(script.contains(declaration), "missing {declaration}");
    }
    assert!(
        script.contains("/secs >= 45/"),
        "broad profile must leave enough bounded time for profiled V8"
    );
}

#[test]
fn indirect_profile_aggregates_sources_pairs_and_exact_total_once() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/dtrace/dsr-indirect.d");
    let script = std::fs::read_to_string(path).unwrap();
    assert!(script.contains("dsr-resolve-begin"));
    assert!(script.contains("dsr-resolve-end"));
    assert!(script.contains("arg1 == 2"));
    assert!(script.contains("@source[pid, arg2]"));
    assert!(script.contains("@pair[pid, arg2, arg3]"));
    assert_eq!(
        script
            .matches("DSRPROF1|count|phase=indirect-total")
            .count(),
        1
    );
    assert_eq!(
        script
            .matches("DSRPROF1|count|phase=indirect-outcome")
            .count(),
        1
    );
}

#[test]
fn fork_profile_pairs_repair_reset_and_first_prepare_latency() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/dtrace/dsr-fork.d");
    let script = std::fs::read_to_string(path).unwrap();
    for probe in [
        "dsr-cache-lifecycle",
        "dsr-exec-map-detail",
        "dsr-prepare-begin",
        "fork-pre",
        "fork-post",
        "proc:::exec-success",
        "syscall::fork:entry",
        "syscall::fork:return",
    ] {
        assert!(script.contains(probe), "missing {probe}");
    }
    for phase in ["host-self-reexec-startup", "host-self-reexec-cli-dispatch"] {
        assert!(
            script.contains(&format!("DSRPROF1|sample|phase={phase}")),
            "missing {phase} sample"
        );
    }
    for phase in [
        "fork-child-repair",
        "first-prepare-after-fork",
        "host-self-reexec",
        "host-self-reexec-preflight",
        "host-self-reexec-capsule-prepare",
        "host-self-reexec-capsule",
        "host-self-reexec-dispatcher",
        "host-self-reexec-image-load",
        "host-self-reexec-prepared-build",
        "host-self-reexec-prepared-validate",
        "host-self-reexec-prepared-map",
        "host-self-reexec-reset",
        "host-self-reexec-restore",
        "exec-reset",
        "first-prepare-after-exec",
        "exec-image-unmap",
        "exec-image-map",
        "exec-cache-reset",
        "exec-relocation",
        "exec-translator-handoff",
        "exec-map-mmap",
        "exec-map-copy",
        "exec-map-icache",
        "exec-map-protect",
        "exec-map-vvar",
    ] {
        assert!(
            script.contains(&format!("DSRPROF1|sample|phase={phase}")),
            "missing {phase} sample"
        );
        assert!(
            script.contains(&format!("DSRPROF1|incomplete|phase={phase}")),
            "missing {phase} incomplete row"
        );
    }
    for declaration in [
        "prepared_build_started[$target, 0] = 0",
        "prepared_validate_started[$target, 0] = 0",
        "prepared_map_started[$target, 0] = 0",
    ] {
        assert!(
            script.contains(declaration),
            "missing associative-array declaration {declaration}"
        );
    }
}

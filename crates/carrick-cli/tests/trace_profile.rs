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
        "arg0 == 1 && arg2 == 17",
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
    assert!(
        !birth.contains("copyin(arg1)") && !birth.contains("copyinstr(arg1)"),
        "host syscall arguments carry guest virtual addresses; dereferencing the marker drops the probe"
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
        "arg0 == 1 && arg2 == 22",
        "arg0 == 1 && arg2 == 19",
        "arg0 == 1 && arg2 == 23",
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
    assert!(
        !terminal.contains("copyin(arg1)") && !terminal.contains("copyinstr(arg1)"),
        "host syscall arguments carry guest virtual addresses; dereferencing a terminal marker drops the probe"
    );
}

const DSRPROF2_FIXTURE: &str = include_str!("fixtures/dsrprof2-valid.raw");

/// The DTrace spelling of one USDT probe, DERIVED from the Rust provider
/// declaration that emits it.
///
/// The two spellings differ only by `__` -> `-`, which is mechanical — but a
/// hardcoded literal in this test would stay green through a rename in
/// `carrick-observability`, leaving a D script that COMPILES and silently
/// never fires. Asserting the declaration still exists ties the script to the
/// probe at test time; Task 9's zero-event rejection is the runtime backstop.
fn usdt_probe_spelling(rust_declaration: &str) -> String {
    let provider = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../carrick-observability/src/probes.rs");
    let source = std::fs::read_to_string(&provider).unwrap();
    assert!(
        source.contains(&format!("fn {rust_declaration}(")),
        "carrick-observability no longer declares the USDT probe {rust_declaration}; \
         dsr-live-arena.d names its DTrace spelling and would stop firing"
    );
    assert!(
        !rust_declaration.contains('-'),
        "a Rust provider declaration separates words with `__`, never `-`"
    );
    format!("carrick*:::{}", rust_declaration.replace("__", "-"))
}

fn dsr_live_arena_script_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/dtrace/dsr-live-arena.d")
}

/// The digest the shipped template authenticates with. Recomputed here from
/// the file on disk, so a stream fixture that hardcoded a stale digest fails.
fn dsr_live_arena_program_sha256() -> String {
    use sha2::{Digest, Sha256};
    let template = std::fs::read(dsr_live_arena_script_path()).unwrap();
    format!("{:x}", Sha256::digest(&template))
}

fn dsr_live_arena_stream(header: Option<&str>, outcomes: &[(u32, u64)], attempts: u64) -> String {
    let mut lines = Vec::new();
    if let Some(header) = header {
        lines.push(header.to_owned());
    }
    for (kind, value) in outcomes {
        lines.push(format!(
            "DSRPROF1|count|phase=live-outcome|pid=4242|kind={kind}|value={value}"
        ));
    }
    lines.push(format!(
        "DSRPROF1|count|phase=translation-attempts|pid=4242|value={attempts}"
    ));
    lines
        .push("DSRPROF1|complete|profile=dsr-live-arena|bounded=0|target_exit_reason=1".to_owned());
    lines.join("\n")
}

fn validate_dsr_live_arena(contents: &str, with_program: bool) -> assert_cmd::assert::Assert {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut file, contents.as_bytes()).unwrap();
    let mut command = cli();
    command
        .arg("__native-profile-validate")
        .arg("--input")
        .arg(file.path());
    if with_program {
        command.arg("--program").arg(dsr_live_arena_script_path());
    }
    command.assert()
}

#[test]
fn dsr_live_arena_profile_binds_its_outcomes_and_bounds_the_capture() {
    let script = std::fs::read_to_string(dsr_live_arena_script_path()).unwrap();

    // Exactly one header slot: a second would let a rendered program carry
    // two digests, which is no authentication at all.
    assert_eq!(script.matches("/*%CARRICK_LIVE_ARENA_HEADER%*/").count(), 1);
    assert_eq!(
        script
            .matches("DSRPROF1|complete|profile=dsr-live-arena|bounded=%d|target_exit_reason=%d")
            .count(),
        1
    );
    for declaration in [
        "dsr__cache__event",
        "dsr__live__chunk__revoked",
        "dsr__translate__begin",
    ] {
        let probe = usdt_probe_spelling(declaration);
        assert!(script.contains(&probe), "missing probe {probe}");
    }
    // The live outcome kinds start at 13; 7..12 belong to `dsr-indirect.d`'s
    // direct-binding vocabulary and must not be swept in here.
    assert!(script.contains("arg1 >= 13"));
    // The header names `execname` to explain why it is wrong; a PREDICATE on
    // it would silently track nothing once the host self-re-exec renames the
    // process mid-run, so screening must key on pid/progeny.
    assert!(!script.contains("execname =="));
    assert!(!script.contains("execname !="));
    assert!(script.contains("progenyof($target)"));
    assert!(script.contains("pid == $target"));
    assert!(script.contains("target_exit_reason = arg0"));
    assert!(script.contains("bounded = 1;"));
    // Every outcome kind is pre-declared, so a kind that never fires still
    // reports a row and the parser can tell "zero" from "absent".
    for kind in 13..=18 {
        assert!(
            script.contains(&format!("@outcome[$target, {kind}] = sum(0);")),
            "outcome kind {kind} is not pre-declared"
        );
    }
}

#[test]
fn dsr_live_arena_accepts_an_authenticated_capture_with_outcomes() {
    let header = format!(
        "DSRLIVE1|header|profile=dsr-live-arena|program_sha256={}",
        dsr_live_arena_program_sha256()
    );
    let stream = dsr_live_arena_stream(Some(&header), &[(13, 57212), (16, 4)], 30208);
    validate_dsr_live_arena(&stream, true)
        .success()
        .stdout(contains("DSRLIVE1_VALID"));
}

#[test]
fn dsr_live_arena_rejects_a_zero_event_capture() {
    let header = format!(
        "DSRLIVE1|header|profile=dsr-live-arena|program_sha256={}",
        dsr_live_arena_program_sha256()
    );
    let stream = dsr_live_arena_stream(
        Some(&header),
        &[(13, 0), (14, 0), (15, 0), (16, 0), (17, 0), (18, 0)],
        30208,
    );
    validate_dsr_live_arena(&stream, true)
        .failure()
        .stderr(contains("zero live-arena outcome events"));
}

#[test]
fn dsr_live_arena_rejects_an_unauthenticated_or_foreign_capture() {
    let header = format!(
        "DSRLIVE1|header|profile=dsr-live-arena|program_sha256={}",
        dsr_live_arena_program_sha256()
    );

    // No header at all.
    validate_dsr_live_arena(&dsr_live_arena_stream(None, &[(13, 7)], 9), true)
        .failure()
        .stderr(contains("no authenticated DSRLIVE1 header"));

    // A header naming a different D program.
    let foreign = format!(
        "DSRLIVE1|header|profile=dsr-live-arena|program_sha256={}",
        "a".repeat(64)
    );
    validate_dsr_live_arena(&dsr_live_arena_stream(Some(&foreign), &[(13, 7)], 9), true)
        .failure()
        .stderr(contains("was produced by D program"));

    // Two headers.
    let doubled = format!(
        "{header}\n{}",
        dsr_live_arena_stream(Some(&header), &[(13, 7)], 9)
    );
    validate_dsr_live_arena(&doubled, true)
        .failure()
        .stderr(contains("duplicate dsr-live-arena header"));

    // Outcomes but no translation denominator.
    validate_dsr_live_arena(&dsr_live_arena_stream(Some(&header), &[(13, 7)], 0), true)
        .failure()
        .stderr(contains("no translation attempts"));
}

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
fn dsrprof2_accepts_summary_mode_without_transition_events() {
    let summary_only = DSRPROF2_FIXTURE
        .lines()
        .filter(|line| {
            ![
                "DSRPROF2|kernel-enter|",
                "DSRPROF2|kernel-return|",
                "DSRPROF2|kernel-terminal-close|",
                "DSRPROF2|offcpu-block|",
                "DSRPROF2|offcpu-wake|",
            ]
            .iter()
            .any(|prefix| line.starts_with(prefix))
        })
        .collect::<Vec<_>>()
        .join("\n");

    validate_dsrprof2_fixture(&summary_only, &[])
        .success()
        .stdout(contains("DSRPROF2_VALID"));
}

#[test]
fn dsrprof2_accepts_committed_shared_range_after_initial_ready() {
    let parent_ready = "DSRPROF2|range-ready|pid=100|start_sec=10|start_usec=20|image=1|epoch=0";
    assert_eq!(DSRPROF2_FIXTURE.matches(parent_ready).count(), 1);

    validate_dsrprof2_fixture(DSRPROF2_FIXTURE, &[])
        .success()
        .stdout(contains("DSRPROF2_VALID"));
}

#[test]
fn dsrprof2_fork_inherits_dynamic_shared_frontier_after_initial_ready() {
    let parent_range = "DSRPROF2|range-shared|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|sequence=4|unit_id=9|start=0x5000|end=0x5800";
    let process_create = "DSRPROF2|process-create|child_pid=101|child_sec=11|child_usec=21|child_image=1|child_epoch=0|parent_pid=100|parent_sec=10|parent_usec=20|parent_image=1|parent_epoch=0";
    let child_ready =
        "DSRPROF2|range-ready|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|final_sequence=3";
    let child_ready_four =
        "DSRPROF2|range-ready|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|final_sequence=4";
    let child_range = "DSRPROF2|range-shared|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|sequence=4|unit_id=9|start=0x5000|end=0x5800";
    let runtime_lifecycle = DSRPROF2_FIXTURE
        .replacen(&format!("{parent_range}\n"), "", 1)
        .replacen(
            process_create,
            &format!("{parent_range}\n{process_create}"),
            1,
        )
        .replacen("range_frontier=3", "range_frontier=4", 1)
        .replacen(
            child_ready,
            &format!("{child_range}\n{child_ready_four}"),
            1,
        );

    validate_dsrprof2_fixture(&runtime_lifecycle, &[])
        .success()
        .stdout(contains("DSRPROF2_VALID"));
}

#[test]
fn dsrprof2_accepts_duplicate_exec_observation_for_same_image() {
    let attempt = "DSRPROF2|exec-attempt|pid=101|start_sec=11|start_usec=21|image=1|epoch=1";
    let repeated = DSRPROF2_FIXTURE.replacen(attempt, &format!("{attempt}\n{attempt}"), 1);

    validate_dsrprof2_fixture(&repeated, &[])
        .success()
        .stdout(contains("DSRPROF2_VALID"));
}

#[test]
fn dsrprof2_retires_unresolved_exec_observation_at_process_exit() {
    let exit = "DSRPROF2|process-exit|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|reason=1";
    let attempt = "DSRPROF2|exec-attempt|pid=100|start_sec=10|start_usec=20|image=1|epoch=0";
    let unresolved = DSRPROF2_FIXTURE.replacen(exit, &format!("{attempt}\n{exit}"), 1);

    validate_dsrprof2_fixture(&unresolved, &[])
        .success()
        .stdout(contains("DSRPROF2_VALID"));
}

#[test]
fn dsrprof2_reports_completion_violation_category() {
    let corrupt = DSRPROF2_FIXTURE
        .replacen("bounded=0", "bounded=1", 1)
        .replacen("offcpu_violations=0", "offcpu_violations=7", 1);

    validate_dsrprof2_fixture(&corrupt, &[])
        .failure()
        .stderr(contains("offcpu_violations=7"));
}

#[test]
fn dsrprof2_names_dynamic_drop_subcategories() {
    validate_dsrprof2_fixture(
        DSRPROF2_FIXTURE,
        &["--dynamic-rinse-drops", "7", "--dynamic-dirty-drops", "11"],
    )
    .failure()
    .stderr(contains("dynamic=0"))
    .stderr(contains("dynamic_rinse=7"))
    .stderr(contains("dynamic_dirty=11"));
}

#[test]
fn dsrprof2_preserves_exact_stack_blocks() {
    let existing_stack = concat!(
        "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=offcpu-voluntary|total_ns=500\n\n",
        "0x1150\n",
        "0x1200\n",
        "DSRSTACK2|end\n",
    );
    let stack = concat!(
        "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=offcpu-voluntary|total_ns=500\n\n",
        "libsystem_kernel.dylib`__psynch_cvwait+0xa\n",
        "carrick`wait_for_translation+0x20\n",
        "DSRSTACK2|end\n",
    );
    let valid = DSRPROF2_FIXTURE.replacen(existing_stack, stack, 1);
    validate_dsrprof2_fixture(&valid, &[]).success();

    for corrupt_stack in [
        "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=offcpu-voluntary|total_ns=500\nDSRSTACK2|end\n",
        "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=offcpu-voluntary|total_ns=500|extra=1\nframe\nDSRSTACK2|end\n",
        "DSRSTACK2|end\n",
        "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=offcpu-voluntary|total_ns=500\nDSRPROF2|wall-state|kind=on-cpu|count=1\nDSRSTACK2|end\n",
    ] {
        let corrupt = DSRPROF2_FIXTURE.replacen(existing_stack, corrupt_stack, 1);
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
    let repeated_parent_ready =
        "DSRPROF2|range-ready|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|final_sequence=4";
    let kernel_return = "DSRPROF2|kernel-return|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|provider=syscall|function=read|class=named-syscall|timestamp_ns=1200";
    let offcpu_block = "DSRPROF2|offcpu-block|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|episode=1|kind=voluntary|pc=0x1150|timestamp_ns=1300";
    let offcpu_wake = "DSRPROF2|offcpu-wake|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|episode=1|observed_pid=100|observed_sec=10|observed_usec=20|observed_image=1|observed_epoch=0|timestamp_ns=1800";
    let offcpu_summary = "DSRPROF2|offcpu|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=voluntary|pc=0x1150|count=1|total_ns=500";
    let exec_success = "DSRPROF2|exec-success|pid=101|start_sec=11|start_usec=21|retired_image=1|retired_epoch=1|new_image=2|new_epoch=0";
    let old_host_catalog = "DSRPROF2|host-image-catalog|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|payload={\"ok\":{\"pid\":101,\"ranges\":[{\"start\":4294967296,\"end\":4294971392,\"path\":\"/carrick\"}]}}";

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
    let repeated_range_ready = DSRPROF2_FIXTURE.replacen(
        parent_later_range,
        &format!("{parent_later_range}\n{repeated_parent_ready}"),
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
        repeated_range_ready,
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
        DSRPROF2_FIXTURE.replacen("\"pid\":100", "\"pid\":999", 1),
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
fn native_wall_profile_emits_categorized_completion_contract() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/dtrace/native-wall.d");
    let script = std::fs::read_to_string(path).unwrap();
    let completion = "DSRPROF2|complete|profile=native-wall|bounded=%d|timed_out=%d|identity_violations=%d|lifecycle_violations=%d|range_violations=%d|kernel_violations=%d|offcpu_violations=%d|probe_errors=%d|target_exit_reason=%d|live_at_end=%d|elapsed_ns=%d|bound_limit_s=%d";

    assert_eq!(script.matches(completion).count(), 1);
    assert!(
        !script.contains("dtrace:::BEGIN\n{\n\tstarted = timestamp;"),
        "elapsed authority must not include launch time before the native owner exists"
    );
    assert!(script.split("\n\n").any(|clause| {
        clause.contains("carrick*:::host-translated-range-reset\n/root_pid == (pid_t)0")
            && clause.contains("started = timestamp;")
    }));
    assert!(script.contains("stopped = pid == root_pid ? timestamp : stopped;"));
    assert!(script.contains("(stopped != 0 ? stopped : timestamp) - started"));
    for counter in [
        "identity_violations",
        "lifecycle_violations",
        "range_violations",
        "kernel_violations",
        "offcpu_violations",
        "probe_errors",
    ] {
        assert!(
            script.contains(&format!("{counter} = 0")),
            "missing initialization for {counter}"
        );
    }
    assert!(
        !script.contains("\n\tviolations =") && !script.contains("\n\tviolations++"),
        "native-wall must not collapse integrity failures into an opaque counter"
    );
    for transition in [
        "printf(\"DSRPROF2|kernel-enter|",
        "printf(\"DSRPROF2|kernel-return|",
        "printf(\"DSRPROF2|kernel-terminal-close|",
        "printf(\"DSRPROF2|offcpu-block|",
        "printf(\"DSRPROF2|offcpu-wake|",
    ] {
        assert!(
            !script.contains(transition),
            "native-wall summary mode must not emit hot transition record {transition:?}"
        );
    }

    for probe in [
        "proc:::create\n",
        "proc:::exec\n",
        "proc:::exec-failure\n",
        "proc:::exec-success\n",
        "syscall:::return\n",
    ] {
        assert_eq!(
            script.matches(probe).count(),
            1,
            "state validation and mutation for {probe:?} must share one DTrace clause"
        );
    }
    assert!(
        script.split("\n\n").any(|clause| {
            clause.starts_with("sched:::off-cpu\n")
                && clause.contains("offcpu_violations +=")
                && clause.contains("off_open[pid, tid] =")
        }),
        "off-CPU duplicate validation and episode opening must share one DTrace clause"
    );
    for hot_zero_store in ["\tkernel_depth[pid, tid]--;", "\toff_open[pid, tid] = 0;"] {
        assert!(
            !script.contains(hot_zero_store),
            "zero deallocates a DTrace associative entry onto its dirty list: {hot_zero_store:?}"
        );
    }
    for sentinel_contract in [
        "kernel_depth[pid, tid] > (uint64_t)1",
        "kernel_depth[pid, tid] = (uint64_t)(this->depth + 1)",
        "kernel_depth[pid, tid] = this->valid ? this->depth : kernel_depth[pid, tid];",
        "off_open[pid, tid] == 2",
        "off_open[pid, tid] = 2;",
        "off_open[pid, tid] = 1;",
    ] {
        assert!(
            script.contains(sentinel_contract),
            "missing nonzero idle-sentinel contract {sentinel_contract:?}"
        );
    }
    for thread_lifecycle_contract in [
        "proc:::lwp-start",
        "thread_lifecycle[pid, tid] = 1;",
        "thread_lifecycle[pid, tid] = 2;",
    ] {
        assert!(
            script.contains(thread_lifecycle_contract),
            "missing terminal-thread scheduler exclusion {thread_lifecycle_contract:?}"
        );
    }
    assert!(
        script.matches("thread_lifecycle[pid, tid] != 2").count() >= 4,
        "every scheduler state/episode clause must exclude post-lwp-exit events"
    );
    assert!(
        script.contains("|unit_id=%u|start=%#x|end=%#x"),
        "64-bit translated unit identities must use unsigned DTrace serialization"
    );
}

#[test]
fn native_wall_capture_bound_is_a_substitutable_declared_parameter() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/dtrace/native-wall.d");
    let script = std::fs::read_to_string(path).unwrap();

    // The bound must be a named variable with exactly one substitution slot,
    // not a `tick-180s` probe-name literal: a 380 s policy-ON workload has to
    // be capturable without editing (and so re-hashing) the D program.
    assert_eq!(
        script.matches("/* CARRICK_DSRPROF2_BOUND */").count(),
        1,
        "the capture bound needs exactly one substitution slot"
    );
    assert!(
        script
            .lines()
            .all(|line| !line.starts_with("tick-") || !line.ends_with('s') || line == "tick-10s"),
        "the bound must not be frozen into a probe name; only the 10 s \
         accumulation tick may name a seconds interval"
    );
    assert!(
        script.contains("bound_limit_s = (uint64_t)180;"),
        "the unrendered template must stay a legal D program with the shipped default"
    );
    assert!(
        script.split("\n\n").any(
            |clause| clause.contains("/bound_elapsed_s >= bound_limit_s/")
                && clause.contains("timed_out = 1;")
                && clause.contains("exit(0);")
        ),
        "the timeout exit must be guarded by the accumulated elapsed bound"
    );
    assert!(
        script.contains("|bound_limit_s=%d"),
        "the stream must self-describe the bound that was in force"
    );
}

#[test]
fn native_wall_profile_uses_single_sample_and_offcpu_stack_authorities() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/dtrace/native-wall.d");
    let script = std::fs::read_to_string(path).unwrap();
    let kernel_sample = script
        .split("\n\n")
        .find(|clause| {
            clause.starts_with("profile-499\n")
                && clause.contains("@cpu_kernel[")
                && clause.contains("@cpu_kernel_stack[")
        })
        .expect("authoritative kernel sampling clause");
    assert!(kernel_sample.contains("this->function ="));
    assert!(kernel_sample.contains("this->class, this->function, arg0"));
    assert!(!script.contains(concat!("@cpu_kernel_", "syscall")));
    assert!(script.contains(
        "DSRPROF2|cpu-kernel|pid=%d|start_sec=%d|start_usec=%d|image=%d|epoch=%d|class=%s|function=%s|pc=%#x|count=%@d"
    ));

    let offcpu_completion = script
        .split("\n\n")
        .find(|clause| clause.starts_with("sched:::on-cpu\n") && clause.contains("@off_stack_ns["))
        .expect("off-CPU completion clause");
    assert_eq!(offcpu_completion.matches("ustack(24)").count(), 1);
    assert!(!script.contains(concat!("@off_stack_", "count")));
    assert!(script.contains("kind=offcpu-%s|total_ns=%@d\\n%kDSRSTACK2|end\\n"));
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
fn indirect_profile_is_self_bounded_and_defines_its_completion_flag() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/dtrace/dsr-indirect.d");
    let script = std::fs::read_to_string(path).unwrap();

    assert!(
        script.contains("tick-1s"),
        "the in-process consumer waits for custom profiles to exit themselves"
    );
    assert!(
        script.contains("/secs >= 60/"),
        "the indirect profile must bound a wedged target"
    );
    assert!(
        script.contains("bounded = 1;"),
        "the timeout path must define the completion flag consumed in END"
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

#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Verdict witnesses for `carrick-xtask smoke-signed` (#893): the receipt is
//! computed fail-closed from the signed runner's full log.
use carrick_xtask::smoke_signed::{CaseRole, CaseStatus, Observed, evaluate, parse_cleanup};

const RUN: &str = "smoke-0123456789ab-1";
const EXE: &str = "/w/target/release/deps/smoke_signed-dc850b466f639fc8";
const NEG: &str = "/w/target/release/deps/entitlement_negative-60c7932505d0ef9b.noent.4242";

fn test_line(name: &str, ok: bool) -> String {
    if ok {
        format!("test {name} ... smoke-signed: case={name} wall_ms=12 panicking=false\nok\n")
    } else {
        format!(
            "test {name} ... smoke-signed: case={name} wall_ms=7 panicking=true\n\
             thread '{name}' panicked at x.rs:1:1:\nboom\nFAILED\n"
        )
    }
}

/// A runner log in `scripts/test-signed.sh --nocapture` shape.
fn log(results: &[(&str, bool)], finished: bool, leak: u64) -> String {
    let mut out = String::from(
        "fixtures: verified 1195 executables for abc by input_identity feed (bundle built at abc)\n\
         \x20   Finished `release` profile [optimized + debuginfo] target(s) in 5m 18s\n",
    );
    out += &format!(
        "test-signed: running {EXE} smoke_ --include-ignored --nocapture\n\nrunning 4 tests\n"
    );
    for (name, ok) in results {
        out += &test_line(name, *ok);
    }
    let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).collect();
    if finished {
        if failed.is_empty() {
            out += &format!(
                "\ntest result: ok. {} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.02s\n\n",
                results.len()
            );
        } else {
            out += "\nfailures:\n\nfailures:\n";
            for (name, _) in &failed {
                out += &format!("    {name}\n");
            }
            out += &format!(
                "\ntest result: FAILED. {} passed; {} failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.02s\n\n",
                results.len() - failed.len(),
                failed.len()
            );
            out += &format!("test-signed: FAIL {EXE}\n");
        }
    } else {
        out += &format!("test-signed: FAIL {EXE}\n");
    }
    out += &format!("remaining carrick procs (run-id {RUN}-b1) = {leak}\n");
    out += &format!("remaining carrick procs (run-id {RUN}-b1-cli) = 0\n");
    out += &format!(
        "test-signed: negative control on {NEG}\n\nrunning 1 test\n\
         test unsigned_executable_maps_hv_denied_to_entitlement ... ok\n\n\
         test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s\n\n"
    );
    out += &format!("remaining carrick procs (run-id {RUN}-neg) = 0\n");
    out += &format!("remaining carrick procs (run-id {RUN}) = 0\n");
    out += &format!("remaining carrick procs (run-id {RUN}-cli) = 0\n");
    out
}

const BOOT: &str = "smoke_root_exit_then_successor_bootstrap_in_one_carrier";
const PIPE: &str = "smoke_pipe_round_trips_complete";
const EXEC: &str = "smoke_exec_replaces_root_image";
const FORK: &str = "smoke_fork_pipe_then_wait_reaps_child";
const NATIVE: &str = "smoke_native_child_exec_after_fork_and_wait";

fn observed(log: &str, exit: i32) -> Observed<'_> {
    Observed {
        log,
        runner_exit_code: Some(exit),
        run_id: RUN,
        clean_tree: true,
        tree_unchanged: true,
    }
}

#[test]
fn required_pass_with_informational_failure_is_green() {
    let text = log(
        &[
            (EXEC, true),
            (NATIVE, true),
            (FORK, false),
            (PIPE, true),
            (BOOT, true),
        ],
        true,
        0,
    );
    let verdict = evaluate(&observed(&text, 1));
    assert!(verdict.passed, "{:?}", verdict.failures);
    let fork = verdict.cases.iter().find(|c| c.name == FORK).unwrap();
    assert_eq!(fork.role, CaseRole::Informational);
    assert_eq!(fork.status, CaseStatus::Failed);
    let boot = verdict.cases.iter().find(|c| c.name == BOOT).unwrap();
    assert_eq!(boot.status, CaseStatus::Passed);
    assert_eq!(boot.wall_ms, Some(12));
    assert!(verdict.negative_control_passed);
    assert_eq!(verdict.cleanup.len(), 5);
    assert_eq!(
        verdict.executable.as_deref(),
        Some(std::path::Path::new(EXE))
    );
}

#[test]
fn all_pass_with_runner_success_is_green() {
    let text = log(
        &[
            (EXEC, true),
            (NATIVE, true),
            (FORK, true),
            (PIPE, true),
            (BOOT, true),
        ],
        true,
        0,
    );
    assert!(evaluate(&observed(&text, 0)).passed);
}

#[test]
fn failed_successor_bootstrap_is_red() {
    let text = log(
        &[
            (EXEC, true),
            (NATIVE, true),
            (FORK, false),
            (PIPE, true),
            (BOOT, false),
        ],
        true,
        0,
    );
    let verdict = evaluate(&observed(&text, 1));
    assert!(!verdict.passed);
    assert!(verdict.failures.iter().any(|f| f.contains(BOOT)));
}

#[test]
fn killed_binary_is_red_and_unrun_cases_are_not_run() {
    // A carrier fatal aborts the process mid-case: no result line follows.
    let text = log(&[(EXEC, true)], false, 0);
    let verdict = evaluate(&observed(&text, 1));
    assert!(!verdict.passed);
    let pipe = verdict.cases.iter().find(|c| c.name == PIPE).unwrap();
    assert_eq!(pipe.status, CaseStatus::NotRun);
    let exec = verdict.cases.iter().find(|c| c.name == EXEC).unwrap();
    assert_eq!(exec.status, CaseStatus::Failed, "unfinished binary");
    assert!(
        verdict
            .failures
            .iter()
            .any(|f| f.contains("did not finish"))
    );
}

#[test]
fn cleanup_leak_is_red() {
    let text = log(
        &[
            (EXEC, true),
            (NATIVE, true),
            (FORK, true),
            (PIPE, true),
            (BOOT, true),
        ],
        true,
        2,
    );
    let verdict = evaluate(&observed(&text, 0));
    assert!(!verdict.passed);
    assert!(verdict.failures.iter().any(|f| f.contains("left 2")));
}

#[test]
fn test_outside_the_smoke_set_is_red() {
    let text = log(
        &[
            (EXEC, true),
            (NATIVE, true),
            (FORK, true),
            (PIPE, true),
            (BOOT, true),
            ("smoke_new_case", true),
        ],
        true,
        0,
    );
    let verdict = evaluate(&observed(&text, 0));
    assert!(!verdict.passed);
    assert_eq!(verdict.unexpected_tests, ["smoke_signed::smoke_new_case"]);
}

#[test]
fn dirty_or_moved_tree_never_qualifies() {
    let text = log(
        &[
            (EXEC, true),
            (NATIVE, true),
            (FORK, true),
            (PIPE, true),
            (BOOT, true),
        ],
        true,
        0,
    );
    let mut dirty = observed(&text, 0);
    dirty.clean_tree = false;
    assert!(!evaluate(&dirty).passed);
    let mut moved = observed(&text, 0);
    moved.tree_unchanged = false;
    assert!(!evaluate(&moved).passed);
}

#[test]
fn runner_failure_without_itemized_cause_is_red() {
    // Build or signing failed: the runner never ran the smoke executable.
    let text = format!(
        "error: could not compile `carrick-embed`\nremaining carrick procs (run-id {RUN}) = 0\n"
    );
    let verdict = evaluate(&observed(&text, 101));
    assert!(!verdict.passed);
    assert!(verdict.cases.iter().all(|c| c.status == CaseStatus::NotRun));
    assert!(!verdict.negative_control_passed);
}

#[test]
fn cleanup_lines_are_parsed_exactly() {
    let cleanup = parse_cleanup(
        "pass 1: killing 1 procs (run-id a)\nremaining carrick procs (run-id a) = 0\n\
         remaining carrick procs (run-id a-cli) = 3\n",
    );
    assert_eq!(cleanup.len(), 2);
    assert_eq!(cleanup[1].run_id, "a-cli");
    assert_eq!(cleanup[1].remaining, 3);
}

const FATAL: &str = "carrick: FATAL: detached address-space retirement failed: \
    release structural stage-2 reference: ReceiptMismatch((661424963584, 2097152))";

/// 14abec7f3 (#855): every root exit printed this fatal yet the guest exits
/// read as success, so the successor case passed semantically.
#[test]
fn carrier_fatal_during_a_passing_required_case_is_red() {
    let text = log(
        &[
            (EXEC, true),
            (NATIVE, true),
            (FORK, true),
            (PIPE, true),
            (BOOT, true),
        ],
        true,
        0,
    )
    .replace(
        &format!("test {BOOT} ... "),
        &format!("test {BOOT} ... {FATAL}\n"),
    );
    let verdict = evaluate(&observed(&text, 0));
    assert!(!verdict.passed);
    let boot = verdict.cases.iter().find(|c| c.name == BOOT).unwrap();
    assert!(boot.fatal);
    assert_eq!(boot.status, CaseStatus::Failed);
    assert_eq!(verdict.fatals.len(), 1);
    assert_eq!(verdict.fatals[0].case.as_deref(), Some(BOOT));
}

#[test]
fn carrier_fatal_in_an_informational_case_is_recorded_not_decisive() {
    let text = log(
        &[
            (EXEC, true),
            (NATIVE, true),
            (FORK, false),
            (PIPE, true),
            (BOOT, true),
        ],
        true,
        0,
    )
    .replace(
        &format!("test {FORK} ... "),
        &format!("test {FORK} ... {FATAL}\n"),
    );
    let verdict = evaluate(&observed(&text, 1));
    assert!(verdict.passed, "{:?}", verdict.failures);
    assert!(verdict.cases.iter().find(|c| c.name == FORK).unwrap().fatal);
}

#[test]
fn carrier_fatal_outside_any_case_is_red() {
    let text = format!(
        "{FATAL}\n{}",
        log(
            &[
                (EXEC, true),
                (NATIVE, true),
                (FORK, true),
                (PIPE, true),
                (BOOT, true)
            ],
            true,
            0,
        )
    );
    let verdict = evaluate(&observed(&text, 0));
    assert!(!verdict.passed);
    assert_eq!(verdict.fatals[0].case, None);
}

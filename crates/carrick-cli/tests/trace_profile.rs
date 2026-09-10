#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn cli() -> Command {
    Command::cargo_bin("carrick").unwrap()
}

/// The AMP1 fixture carries `@PROGRAM_SHA256@` rather than a literal digest.
/// The header must name the digest of the *bundled template*, which changes
/// every time the D program is edited, so a literal would make the fixture
/// silently stale — and "stale fixture" and "rejected stream" would become
/// indistinguishable, which is the exact failure this profile exists to avoid.
const AMP1_FIXTURE: &str = include_str!("fixtures/amp1-valid.raw");
const AMP1_PROGRAM: &str = include_str!("../../../scripts/dtrace/native-amplification.d");

fn amp1_program_sha256() -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(AMP1_PROGRAM.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The fixture's traced target, as the header carries it. The in-file
/// `amplification_profile` tests derive these from `NativeShapeTarget::parse`,
/// which is what pins the capture path's rendering; out here they are the two
/// determinants a comparison must refuse to cross, so they are named constants
/// this suite can drift on purpose.
const AMP1_IMAGE: &str = "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AMP1_TARGET_ARGV_SHA256: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";

fn amp1_stream() -> String {
    AMP1_FIXTURE
        .replace("@PROGRAM_SHA256@", &amp1_program_sha256())
        .replace("@IMAGE@", AMP1_IMAGE)
        .replace("@TARGET_ARGV_SHA256@", AMP1_TARGET_ARGV_SHA256)
}

fn validate_amp1(contents: &str, extra_args: &[&str]) -> assert_cmd::assert::Assert {
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
fn amp1_accepts_a_complete_amplification_capture() {
    validate_amp1(&amp1_stream(), &[])
        .success()
        .stdout(contains("AMP1_VALID"));
}

#[test]
fn amp1_rejects_a_wrong_backend_capture() {
    // `native-syscall-service-*` never fires under the VMM backend, so every
    // host call lands in `carrick-only` and the guest denominator is zero. That
    // is a named error, never a summary of an empty ledger.
    let wrong_backend = amp1_stream()
        .replacen(
            "AMP1|metric=guest-syscall-total|count=6",
            "AMP1|metric=guest-syscall-total|count=0",
            1,
        )
        .replacen("AMP1|guest_slot=58|count=4\n", "", 1)
        .replacen("AMP1|guest_slot=224|count=2\n", "", 1);

    validate_amp1(&wrong_backend, &[])
        .failure()
        .stderr(contains("wrong-backend"));
}

#[test]
fn amp1_rejects_a_truncated_capture() {
    let truncated = amp1_stream().replacen(
        "AMP1|section=totals",
        "AMP1|section=truncated|reason=bound-limit|elapsed_s=600|bound_limit_s=600\nAMP1|section=totals",
        1,
    );

    validate_amp1(&truncated, &[])
        .failure()
        .stderr(contains("truncated"));
}

#[test]
fn amp1_rejects_a_program_digest_mismatch() {
    // A `--script` capture, or an edited program, cannot authenticate its own
    // stream: the header must name the bundled template's digest.
    let foreign = AMP1_FIXTURE.replace(
        "@PROGRAM_SHA256@",
        "3333333333333333333333333333333333333333333333333333333333333333",
    );

    validate_amp1(&foreign, &[])
        .failure()
        .stderr(contains("does not name the bundled"));
}

#[test]
fn amp1_rejects_nonzero_drop_counters_from_either_source() {
    // In-band: the counters this program owns.
    for (source, line) in [
        ("dtrace-error", "AMP1|drop|source=dtrace-error|count=0"),
        (
            "service-window-reentry",
            "AMP1|drop|source=service-window-reentry|count=0",
        ),
        (
            "service-end-unmatched",
            "AMP1|drop|source=service-end-unmatched|count=0",
        ),
    ] {
        let dropped = amp1_stream().replacen(line, &line.replace("count=0", "count=3"), 1);
        validate_amp1(&dropped, &[])
            .failure()
            .stderr(contains(source));
    }

    // Consumer-side: libdtrace's own drop counters are not readable from D, so
    // they arrive through the run report and are enforced here.
    for flag in [
        "--principal-drops",
        "--aggregation-drops",
        "--dynamic-drops",
        "--dynamic-rinse-drops",
        "--dynamic-dirty-drops",
        "--other-drops",
    ] {
        validate_amp1(&amp1_stream(), &[flag, "1"])
            .failure()
            .stderr(contains("drop"));
    }
}

#[test]
fn amp1_accepts_the_inherited_service_ends_every_threaded_guest_produces() {
    // `NativeSyscallServiceSpan::inherited_open` fires NO entry probe — the
    // parent already fired it — but the spawned child thread fires `-end` on a
    // NEW host tid, and the fork child fires one from a new pid. That is
    // EXPECTED control flow on every `clone(CLONE_THREAD)` and every fork, so
    // it is its own class and must never be a refusal: treating it as an
    // unmatched end refuses a ledger on any real build.
    let threaded = amp1_stream().replacen(
        "AMP1|window|class=inherited-end|count=3",
        "AMP1|window|class=inherited-end|count=8291",
        1,
    );
    validate_amp1(&threaded, &[])
        .success()
        .stdout(contains("AMP1_VALID"));

    // The discriminator still catches a genuine double close: an `-end` on a
    // thread whose window already closed is a pairing corruption.
    let double_close = amp1_stream().replacen(
        "AMP1|drop|source=service-end-unmatched|count=0",
        "AMP1|drop|source=service-end-unmatched|count=1",
        1,
    );
    validate_amp1(&double_close, &[])
        .failure()
        .stderr(contains("service-end-unmatched"));

    // ... and the section itself is required, for the same reason every other
    // section is: absent is not zero.
    let without = amp1_stream()
        .lines()
        .filter(|line| !line.starts_with("AMP1|window|") && *line != "AMP1|section=window-events")
        .collect::<Vec<_>>()
        .join("\n");
    validate_amp1(&without, &[])
        .failure()
        .stderr(contains("window-events"));
}

#[test]
fn amp1_requires_a_qualified_terminal_roster_in_both_scopes() {
    // The launch authority refuses to exist unless the qualification observed
    // both a thread- and a process-terminating call, so an empty or half roster
    // means the substitution never happened — an unrendered template.
    for dropped in [
        "AMP1|terminal-call|provider=syscall|function=exit|scope=process\n",
        "AMP1|terminal-call|provider=syscall|function=bsdthread_terminate|scope=thread\n",
    ] {
        let partial = amp1_stream().replacen(dropped, "", 1);
        validate_amp1(&partial, &[])
            .failure()
            .stderr(contains("terminal"));
    }
}

#[test]
fn amp1_rejects_a_declared_join_that_never_armed() {
    // `dtrace_consumer` compiles with `DTRACE_C_ZDEFS`, so a probe description
    // that matches NOTHING is silent rather than an error, and the D BEGIN
    // seeds every total `sum(0)` so a printed zero stays distinguishable from a
    // section that printed nothing. Together those make an unarmed join look
    // exactly like an armed one that saw no events: section markers present,
    // rows absent, totals a legal zero — and per-op closure then holds at
    // 0 == 0 while the ledger loses the entire mass that join exists to catch.
    let unarmed_mach = amp1_stream()
        .lines()
        .filter(|line| !line.contains("|trap="))
        .map(|line| {
            line.replace(
                "mach-trap-entry-total|count=5",
                "mach-trap-entry-total|count=0",
            )
            .replace(
                "mach-trap-return-total|count=5",
                "mach-trap-return-total|count=0",
            )
            .replace("mach-trap-cpu-ns|count=4000", "mach-trap-cpu-ns|count=0")
        })
        .collect::<Vec<_>>()
        .join("\n");
    validate_amp1(&unarmed_mach, &[])
        .failure()
        .stderr(contains("mach-trap-entry-total").and(contains("never armed")));

    // The fault join is three independent probe descriptions in one clause, so
    // ZDEFS can silence any one of them on its own.
    let unarmed_cow = amp1_stream()
        .lines()
        .filter(|line| !line.contains("|kind=cow_fault"))
        .collect::<Vec<_>>()
        .join("\n")
        .replace(
            "AMP1|section=fault-totals",
            "AMP1|section=fault-totals\nAMP1|kind=cow_fault|count=0",
        );
    validate_amp1(&unarmed_cow, &[])
        .failure()
        .stderr(contains("cow_fault").and(contains("never armed")));
}

#[test]
fn amp1_rejects_a_missing_drop_section() {
    // Absent is not zero: a section that printed nothing must never be read as
    // a section that printed a zero.
    let without_drops = amp1_stream()
        .lines()
        .filter(|line| !line.starts_with("AMP1|drop") && *line != "AMP1|section=drops")
        .collect::<Vec<_>>()
        .join("\n");

    validate_amp1(&without_drops, &[])
        .failure()
        .stderr(contains("drops"));
}

#[test]
fn amp1_rejects_corrupt_amplification_records() {
    for corrupt in [
        // `guest_slot=0` is unreachable by construction (1 is carrick-only and
        // a guest op is `nr + 2`), so it means the encoding drifted.
        amp1_stream().replacen("AMP1|guest_slot=58|count=4", "AMP1|guest_slot=0|count=4", 1),
        // A stream that never reached its END clause.
        amp1_stream().replacen("AMP1|complete|profile=native-amplification", "", 1),
        // A required section that never printed.
        amp1_stream().replacen("AMP1|section=faults\n", "", 1),
        // A required total that never printed.
        amp1_stream().replacen("AMP1|metric=mach-trap-cpu-ns|count=4000\n", "", 1),
        // Wrong profile in the header.
        amp1_stream().replacen(
            "profile=native-amplification|raw_schema",
            "profile=native-fault|raw_schema",
            1,
        ),
        // Wrong raw schema.
        amp1_stream().replacen(
            "raw_schema=carrick.amplification.raw.v1",
            "raw_schema=carrick.amplification.raw.v2",
            1,
        ),
        // The declared buffer sizes must match the pragmas the bundled program
        // actually ran with; they are determinants, not decoration.
        amp1_stream().replacen("aggsize=64m", "aggsize=32m", 1),
        // An unknown record kind.
        amp1_stream().replacen(
            "AMP1|section=drops",
            "AMP1|section=drops\nAMP1|surprise|value=1",
            1,
        ),
        // A duplicated aggregation row.
        amp1_stream().replacen(
            "AMP1|guest_slot=58|host=openat|count=7",
            "AMP1|guest_slot=58|host=openat|count=7\nAMP1|guest_slot=58|host=openat|count=7",
            1,
        ),
        // No header at all.
        amp1_stream().lines().skip(1).collect::<Vec<_>>().join("\n"),
    ] {
        validate_amp1(&corrupt, &[]).failure();
    }
}

fn amplification_ledger(
    stream: &str,
    extra_args: &[&std::ffi::OsStr],
) -> (assert_cmd::assert::Assert, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path().join("amp1.raw");
    std::fs::write(&raw, stream).unwrap();
    let mut command = cli();
    command
        .args(["debug", "amplification-ledger"])
        .arg(&raw)
        .args(extra_args);
    (command.assert(), directory)
}

/// The end-to-end contract as an operator meets it: one authenticated stream in,
/// one canonical ledger out. The arithmetic itself is pinned by the in-file
/// `debug_amplification` tests; what this suite adds is that the subcommand is
/// actually reachable and that its refusals reach the exit status.
#[test]
fn amplification_ledger_publishes_a_canonical_ledger_from_an_authenticated_capture() {
    let (assert, _directory) = amplification_ledger(&amp1_stream(), &[]);
    let output = assert.success().get_output().stdout.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.ends_with('\n') && text.matches('\n').count() == 1);
    let ledger: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
    assert_eq!(ledger["schema"], "carrick.amplification-ledger.v1");
    // The guest ops are named from `carrick_abi::syscall`, not from the stream:
    // AMP1 carries canonical NUMBERS and copies no strings.
    assert_eq!(ledger["ledger"][0]["guest_op"]["name"], "openat");
    assert_eq!(ledger["ledger"][1]["guest_op"]["name"], "mmap");
    assert_eq!(
        ledger["ledger"][0]["host_call_amplification"]["numerator"],
        10
    );
    assert_eq!(
        ledger["ledger"][0]["host_call_amplification"]["denominator"],
        4
    );
    // `carrick-only` has no amplification cell to fill; that is a property of
    // the type, asserted here as the shape an operator actually receives.
    assert!(
        ledger["carrick_only"]
            .get("host_call_amplification")
            .is_none()
    );
    assert_eq!(
        ledger["carrick_only"]["probable_instrument"]["host_calls"],
        5
    );
    assert_eq!(ledger["budget"]["probable_instrument_cpu_ns"], 500);
}

#[test]
fn amplification_ledger_refuses_a_capture_that_is_not_evidence() {
    // A `--script` capture cannot authenticate its own stream, so it can never
    // become a ledger -- the whole point of moving this census under --profile.
    let (assert, _foreign) = amplification_ledger(
        &amp1_stream().replace(
            &amp1_program_sha256(),
            "5555555555555555555555555555555555555555555555555555555555555555",
        ),
        &[],
    );
    assert
        .failure()
        .stderr(contains("does not name the bundled"));

    // A silently dropped event makes every ratio SMALLER, which reads as lower
    // amplification and would be banked as good news.
    let (assert, _dropped) = amplification_ledger(
        &amp1_stream().replacen(
            "AMP1|drop|source=dtrace-error|count=0",
            "AMP1|drop|source=dtrace-error|count=7",
            1,
        ),
        &[],
    );
    assert.failure().stderr(contains("dtrace-error"));

    // A per-op sum that no longer meets the capture's own independent total.
    let (assert, _skewed) = amplification_ledger(
        &amp1_stream().replacen(
            "AMP1|metric=host-syscall-entry-total|count=20",
            "AMP1|metric=host-syscall-entry-total|count=26",
            1,
        ),
        &[],
    );
    assert
        .failure()
        .stderr(contains("closure failed").and(contains("host syscalls")));
}

/// The laundering hole this record closes, stated so the test is not read as a
/// formality: libdtrace's consumer-side drop counters are NOT readable from D
/// and used to live only in the live `DTraceRunReport`, so a raw file left
/// behind by a FAILED capture read as clean offline. And a dynamic drop that
/// loses a `service_slot[pid, tid]` entry moves a `(guest_op, host_call)` row
/// into `carrick-only` WITHOUT changing a single closure sum — its symptom is
/// an amplification that IMPROVED. The in-band record is that corruption's only
/// detector, so the reader requires it (absent is not zero) and refuses every
/// nonzero counter by name.
#[test]
fn amplification_ledger_requires_the_in_band_consumer_drop_record() {
    let without = amp1_stream()
        .lines()
        .filter(|line| !line.starts_with("AMP1|consumer-drops|"))
        .collect::<Vec<_>>()
        .join("\n");
    let (assert, _directory) = amplification_ledger(&format!("{without}\n"), &[]);
    assert.failure().stderr(contains("consumer-drops"));

    for counter in [
        "principal",
        "aggregation",
        "dynamic",
        "dynamic_rinse",
        "dynamic_dirty",
        "other",
        "interrupted",
    ] {
        let dropped = amp1_stream().replacen(&format!("|{counter}=0"), &format!("|{counter}=3"), 1);
        assert_ne!(
            dropped,
            amp1_stream(),
            "the fixture must carry a {counter} consumer-drop counter to corrupt"
        );
        let (assert, _directory) = amplification_ledger(&dropped, &[]);
        assert
            .failure()
            .stderr(contains("libdtrace").and(contains(counter)));
    }
}

fn published_ledger(stream: &str, directory: &std::path::Path, name: &str) -> std::path::PathBuf {
    let raw = directory.join(format!("{name}.raw"));
    std::fs::write(&raw, stream).unwrap();
    let ledger = directory.join(format!("{name}.ledger.json"));
    cli()
        .args(["debug", "amplification-ledger"])
        .arg(&raw)
        .arg("--output")
        .arg(&ledger)
        .assert()
        .success();
    ledger
}

fn compare_ledgers(a: &std::path::Path, b: &std::path::Path) -> assert_cmd::assert::Assert {
    cli()
        .args(["debug", "amplification-compare"])
        .arg(a)
        .arg(b)
        .assert()
}

/// Two censuses of the same capture must difference to EXACT zeros, and the
/// arithmetic is integer: a float delta would make "did this lever move the
/// mmap row" a platform question.
#[test]
fn amplification_compare_reports_exact_zeros_for_identical_censuses() {
    let directory = tempfile::tempdir().unwrap();
    let a = published_ledger(&amp1_stream(), directory.path(), "a");
    let b = published_ledger(&amp1_stream(), directory.path(), "b");

    let output = compare_ledgers(&a, &b)
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.ends_with('\n') && text.matches('\n').count() == 1);
    let report: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
    assert_eq!(report["schema"], "carrick.amplification-comparison.v1");

    for row in report["ledger_rows"].as_array().unwrap() {
        for delta in [
            "guest_count_delta",
            "host_calls_delta",
            "host_cpu_ns_delta",
            "mach_traps_delta",
        ] {
            assert_eq!(row[delta], 0, "{} {delta}", row["guest_op"]["name"]);
        }
        for fraction in [
            "host_call_amplification_delta",
            "host_cpu_ns_per_guest_op_delta",
        ] {
            assert_eq!(row[fraction]["numerator"], 0, "{fraction}");
        }
    }
    assert_eq!(report["totals"]["host_syscalls"]["delta"], 0);
    assert_eq!(report["totals"]["host_syscall_cpu_ns"]["delta"], 0);
    assert_eq!(report["carrick_only"]["host_cpu_ns"]["delta"], 0);
}

/// A comparator that will cross an instrument version, a fixture, or a host
/// build is worse than no comparator: it produces a plausible delta between two
/// numbers that were never comparable. `program_sha256` is on this list because
/// Task 2 deliberately moved the bundled-digest check OUT of the ledger parser —
/// folding it in would make every published ledger unparseable the moment
/// `native-amplification.d` is edited, destroying the archive.
#[test]
fn amplification_compare_refuses_every_capture_determinant_drift() {
    let directory = tempfile::tempdir().unwrap();
    let baseline = published_ledger(&amp1_stream(), directory.path(), "baseline");
    let baseline_text = std::fs::read_to_string(&baseline).unwrap();

    for (index, (needle, replacement, message)) in [
        (
            "\"program_sha256\":\"",
            format!("\"program_sha256\":\"{}", "7".repeat(64)),
            "program",
        ),
        (
            "\"joins\":\"syscall,mach,fault\"",
            "\"joins\":\"syscall,mach\"".to_owned(),
            "joins",
        ),
        (
            "\"aggsize\":\"64m\"",
            "\"aggsize\":\"32m\"".to_owned(),
            "buffer",
        ),
        (
            "\"os_build\":\"27A5295i\"",
            "\"os_build\":\"27A5295j\"".to_owned(),
            "os build",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let drifted = if needle == "\"program_sha256\":\"" {
            // Replace only the digest that follows the key, leaving the
            // birth/terminal receipts alone.
            let at = baseline_text.find(needle).unwrap();
            let mut text = baseline_text.clone();
            text.replace_range(at..at + needle.len() + 64, &replacement);
            text
        } else {
            assert!(
                baseline_text.contains(needle),
                "the ledger must carry {needle} as a determinant"
            );
            baseline_text.replacen(needle, &replacement, 1)
        };
        let candidate = directory.path().join(format!("drift-{index}.json"));
        std::fs::write(&candidate, drifted).unwrap();
        compare_ledgers(&baseline, &candidate)
            .failure()
            .stderr(contains(message));
    }

    // The guest-op SET is a determinant too: two censuses that measured
    // different operations have no row-wise difference to report. Slot 66 is
    // canonical 64, a different real syscall, so closure still holds.
    let other_ops = published_ledger(
        &amp1_stream().replace("guest_slot=224", "guest_slot=66"),
        directory.path(),
        "other-ops",
    );
    compare_ledgers(&baseline, &other_ops)
        .failure()
        .stderr(contains("guest operation"));

    // And the fixture: a ledger of a different image or a different guest
    // command is not a before/after of anything.
    let other_fixture = published_ledger(
        &amp1_stream().replace(
            "target_argv_sha256=3333333333333333333333333333333333333333333333333333333333333333",
            "target_argv_sha256=4444444444444444444444444444444444444444444444444444444444444444",
        ),
        directory.path(),
        "other-fixture",
    );
    compare_ledgers(&baseline, &other_fixture)
        .failure()
        .stderr(contains("target"));
}

#[test]
fn amplification_ledger_publishes_deterministically_and_never_clobbers() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path().join("amp1.raw");
    std::fs::write(&raw, amp1_stream()).unwrap();
    let published = directory.path().join("ledger.json");

    cli()
        .args(["debug", "amplification-ledger"])
        .arg(&raw)
        .arg("--output")
        .arg(&published)
        .assert()
        .success();
    let first = std::fs::read(&published).unwrap();

    // A published artifact is never silently replaced.
    cli()
        .args(["debug", "amplification-ledger"])
        .arg(&raw)
        .arg("--output")
        .arg(&published)
        .assert()
        .failure()
        .stderr(contains("already exists"));
    assert_eq!(std::fs::read(&published).unwrap(), first);

    // Byte-identical on a re-run of the SAME command. Provenance is part of the
    // artifact by design -- the invocation and its `CARRICK_RUN_ID` are what let
    // a later reader tie a ledger to the capture that produced it -- so the
    // determinism claim is about a fixed invocation, which is exactly what a
    // capture driver replays.
    let ledger_of = || {
        String::from_utf8(
            cli()
                .args(["debug", "amplification-ledger"])
                .arg(&raw)
                .env("CARRICK_RUN_ID", "amp-determinism")
                .assert()
                .success()
                .get_output()
                .stdout
                .clone(),
        )
        .unwrap()
    };
    assert_eq!(ledger_of(), ledger_of());
}

/// The AMP1 header is a durable artifact and names the idioms it refuses, so a
/// negative contract has to be asserted against the CODE, not the prose. D uses
/// only block comments.
fn strip_d_comments(source: &str) -> String {
    let mut code = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(open) = rest.find("/*") {
        code.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        match after.find("*/") {
            Some(close) => rest = &after[close + 2..],
            None => return code,
        }
    }
    code.push_str(rest);
    code
}

#[test]
fn native_amplification_program_scopes_bounds_and_sections_are_pinned() {
    let script = AMP1_PROGRAM;
    let code = strip_d_comments(script);
    let code = code.as_str();

    // Scoping: `tracked[]` from `$target` + `proc:::create`, never `execname`.
    assert!(code.contains("tracked[$target] = 1;"));
    assert!(code.contains("tracked[args[0]->pr_pid] = 1;"));
    assert!(
        !code.contains("execname"),
        "carrick trace runs libdtrace in-process inside a `carrick` binary; an \
         execname screen counts the tracer's own syscalls as the guest's"
    );

    // Four probe families, one program.
    for probe in [
        "carrick*:::native-syscall-service-entry",
        "carrick*:::native-syscall-service-end",
        "syscall:::entry",
        "syscall:::return",
        "mach_trap:::entry",
        "mach_trap:::return",
        "vminfo:::as_fault",
        "vminfo:::zfod",
        "vminfo:::cow_fault",
        // The service window is NOT a balanced pair: a terminal handoff emits
        // no `-end` at all, so the slot has to retire on the two events every
        // handoff site is followed by.
        "proc:::exec-success",
        "proc:::lwp-exit",
    ] {
        assert!(code.contains(probe), "missing probe {probe}");
    }

    // Guest ops cross the boundary as canonical NUMBERS, never as copied
    // strings: the number is the typed domain the reader resolves.
    assert!(
        !code.contains("copyin"),
        "the guest-op name is arg1 and the number is arg0; AMP1 keys on the \
         number so no per-guest-syscall copyin exists"
    );
    assert!(code.contains("service_slot[pid, tid] = (uint64_t)arg0 + (uint64_t)2;"));

    // The consumer-side drop counters are NOT readable from D (header fact
    // 10), so this program must not appear to own them: `carrick trace`
    // appends the `AMP1|consumer-drops|...` record after libdtrace finishes,
    // and a D `printf` of the same record would be a fabricated verdict.
    assert!(
        !code.contains("consumer-drops"),
        "libdtrace's own drop counters cannot be read from D; the record is \
         written by the capture command, not printed by the program"
    );

    // No kernel-stack ranking, ever.
    assert!(!code.contains("ustack("));
    assert!(!code.contains("stack("));

    // Every required section marker is an unconditional printf, and every
    // required total is seeded so an empty aggregation still prints a zero.
    for section in [
        "AMP1|section=terminal-calls",
        "AMP1|section=totals",
        "AMP1|section=fault-totals",
        "AMP1|section=guest-syscalls",
        "AMP1|section=host-syscalls",
        "AMP1|section=host-syscall-cpu",
        "AMP1|section=host-syscall-returns",
        "AMP1|section=mach-traps",
        "AMP1|section=mach-trap-cpu",
        "AMP1|section=mach-trap-returns",
        "AMP1|section=faults",
        "AMP1|section=window-events",
        "AMP1|section=drops",
    ] {
        assert_eq!(
            code.matches(section).count(),
            1,
            "section marker {section} must be printed exactly once"
        );
    }
    for seed in [
        "@guest_total = sum(0);",
        "@host_entry_total = sum(0);",
        "@host_return_total = sum(0);",
        "@host_cpu_total = sum(0);",
        "@mach_entry_total = sum(0);",
        "@mach_return_total = sum(0);",
        "@mach_cpu_total = sum(0);",
        "@fault_total[\"as_fault\"] = sum(0);",
        "@fault_total[\"zfod\"] = sum(0);",
        "@fault_total[\"cow_fault\"] = sum(0);",
        "@drop_service_reentry = sum(0);",
        "@drop_service_unmatched = sum(0);",
        "@window_inherited_end = sum(0);",
        "@probe_errors = sum(0);",
    ] {
        assert!(
            code.contains(seed),
            "printa on an empty aggregation prints nothing; missing seed {seed}"
        );
    }

    // An unsynchronized D global would let a lost read-modify-write at the
    // 0/nonzero boundary make a corrupted stream read as clean — fail-OPEN in
    // the counter whose entire job is to fail closed.
    assert!(!code.contains("probe_errors++"));
    assert!(code.contains("@probe_errors = sum(1);"));

    // Inherited spans close from a child tid/pid that never opened a window, so
    // the never-seen (0) and idle (1) sentinels must stay distinguishable —
    // that is the whole discriminator between expected control flow and a
    // genuine double close, and both reads must precede the single write in one
    // clause.
    // Comment stripping leaves blank runs, so clauses are trimmed before the
    // boundary check.
    let clause_at = |probe: &str| {
        code.split("\n\n")
            .map(str::trim_start)
            .find(|clause| clause.starts_with(probe))
            .map(str::to_owned)
    };
    let end_clause =
        clause_at("carrick*:::native-syscall-service-end").expect("service-end clause");
    assert!(end_clause.contains(
        "@window_inherited_end =\n\t    sum(service_slot[pid, tid] == (uint64_t)0 ? 1 : 0);"
    ));
    assert!(end_clause.contains(
        "@drop_service_unmatched =\n\t    sum(service_slot[pid, tid] == (uint64_t)1 ? 1 : 0);"
    ));
    assert_eq!(
        code.matches("carrick*:::native-syscall-service-end")
            .count(),
        1,
        "a second clause on this probe would observe the first clause's mutation"
    );
    for retirement in ["proc:::exec-success", "proc:::lwp-exit"] {
        let clause =
            clause_at(retirement).unwrap_or_else(|| panic!("missing {retirement} slot retirement"));
        assert!(
            clause.contains("service_slot[pid, tid] = (uint64_t)0;"),
            "{retirement} must retire the slot to NEVER-SEEN so a reused tid's \
             inherited end is not read as a double close"
        );
    }

    // Nonzero retirement sentinels: assigning 0 deallocates the entry onto
    // DTrace's dirty list.
    assert!(code.contains("service_slot[pid, tid] = (uint64_t)1;"));
    assert!(code.contains("self->amp_cpu = (uint64_t)1;"));
    assert!(code.contains("self->amp_mach_cpu = (uint64_t)1;"));
    assert!(!code.contains("self->amp_cpu = 0;"));

    // Host CPU-ns is `vtimestamp`, never `timestamp`: a blocked call must not
    // masquerade as kernel work.
    assert!(code.contains("self->amp_cpu = vtimestamp + (uint64_t)1;"));
    assert!(code.contains("self->amp_mach_cpu = vtimestamp + (uint64_t)1;"));

    // The truncation marker and the declared, substitutable bound.
    assert!(code.contains("AMP1|section=truncated|reason=bound-limit"));
    assert_eq!(script.matches("/* CARRICK_AMP1_BOUND */").count(), 1);
    assert!(
        code.contains("bound_limit_s = (uint64_t)600;"),
        "the unrendered template must stay a legal D program with its default"
    );
    assert_eq!(script.matches("/* CARRICK_AMP1_HEADER */").count(), 1);
    assert_eq!(script.matches("/* CARRICK_AMP1_TERMINALS */").count(), 1);
    assert!(
        code.lines()
            .all(|line| !line.starts_with("tick-") || line == "tick-10s"),
        "the bound must not be frozen into a probe name"
    );
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
            "hvpatch-identity-host-safety",
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
            "hvpatch-identity-host-safety",
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
fn hvpatch_alias_sharing_trace_fails_closed() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/dtrace/hvpatch-alias-sharing.d");
    let script = std::fs::read_to_string(path).unwrap();

    assert!(script.contains("walks = 0;"));
    assert!(script.contains("fault_walks = 0;"));
    assert!(script.contains("fault_ttbrs = 0;"));
    assert!(
        script.contains("exit(3);"),
        "provider errors must fail immediately"
    );
    assert!(
        script.contains("exit(4);"),
        "timeouts must fail immediately"
    );
    assert!(
        script.contains("maps && faults && walks && fault_walks && fault_ttbrs && !errors"),
        "target exit must require a complete companion capture"
    );
}

#[test]
fn hvpatch_alias_sharing_saved_capture_validator_fails_closed() {
    let validator = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/dtrace/validate-hvpatch-alias-sharing.sh");
    let temp = tempfile::tempdir().unwrap();
    let cases = [
        (
            "ok",
            "HVPATCHALIAS|end|maps=1|faults=1|walks=1|fault_walks=1|fault_ttbrs=1|bounded=0|errors=0\n",
            0,
        ),
        (
            "zero",
            "HVPATCHALIAS|end|maps=0|faults=0|walks=0|fault_walks=0|fault_ttbrs=0|bounded=0|errors=0\n",
            2,
        ),
        ("incomplete", "HVPATCHALIAS|map|ipa=1\n", 2),
        (
            "provider-error",
            "HVPATCHALIAS|error|fault=1\nHVPATCHALIAS|end|maps=1|faults=1|walks=1|fault_walks=1|fault_ttbrs=1|bounded=0|errors=1\n",
            3,
        ),
        (
            "timeout",
            "HVPATCHALIAS|end|maps=1|faults=1|walks=1|fault_walks=1|fault_ttbrs=1|bounded=1|errors=0\n",
            4,
        ),
    ];

    for (name, capture, expected) in cases {
        let path = temp.path().join(name);
        std::fs::write(&path, capture).unwrap();
        let status = std::process::Command::new("sh")
            .arg(&validator)
            .arg(&path)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(expected), "fixture {name}");
    }
}

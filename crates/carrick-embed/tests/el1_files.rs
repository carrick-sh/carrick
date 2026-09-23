//! Signed EL1 regular file delegation verification.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;

use carrick_embed::{ContainerBuilder, read_el1_counters, reset_el1_counters};
use carrick_image::PullPolicy;

/// Contract test: 10,000 write+lseek pairs served at EL1 on a delegated regular file.
#[test]
fn el1_files_contract() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/usr/bin/perl",
                "-e",
                r#"
open(my $fh, "+>", "/tmp/contract_10k.txt") or die "open: $!";
syswrite($fh, "x") or die "warmup write: $!";
sysseek($fh, 0, 0) or die "warmup seek: $!";
for (my $i = 0; $i < 10000; $i++) {
    syswrite($fh, "x") or die "write: $!";
    sysseek($fh, 0, 0) or die "seek: $!";
}
close($fh);
print "contract_ok\n";
"#,
            ])
            .run_blocking(),
    );

    assert!(result.success(), "exit_code={}", result.exit_code);
    assert_eq!(result.stdout_utf8().trim(), "contract_ok");

    let counters = read_el1_counters().expect("EL1 counters should be populated");
    let served_writes = counters.served[64].load(Ordering::Relaxed);
    let forwarded_writes = counters.forwarded[64].load(Ordering::Relaxed);
    let served_seeks = counters.served[62].load(Ordering::Relaxed);
    let _forwarded_seeks = counters.forwarded[62].load(Ordering::Relaxed);
    assert!(
        served_writes >= 10_000,
        "expected at least 10,000 writes served at EL1, got {served_writes} (forwarded: {forwarded_writes})"
    );
    assert!(
        served_seeks >= 10_000,
        "expected at least 10,000 seeks served at EL1, got {served_seeks} (forwarded: {_forwarded_seeks})"
    );
}

/// Read-after-write from second process after first process exits (proving recall on teardown).
#[test]
fn el1_files_recall_on_teardown() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/bin/sh",
                "-c",
                r#"
/usr/bin/perl -e '
open(my $fh, ">", "/tmp/recall_test.txt") or die "open: $!";
syswrite($fh, "teardown_recall_payload_12345\n") or die "write: $!";
close($fh);
exit(0);
' && /usr/bin/perl -e '
open(my $fh, "<", "/tmp/recall_test.txt") or die "open: $!";
my $buf;
sysread($fh, $buf, 30) or die "read: $!";
close($fh);
print "got: $buf";
'
"#,
            ])
            .run_blocking(),
    );

    assert!(result.success(), "exit_code={}", result.exit_code);
    assert_eq!(
        result.stdout_utf8().trim(),
        "got: teardown_recall_payload_12345"
    );
}

struct Watchdog {
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn start(timeout: std::time::Duration) -> Self {
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done_clone = done.clone();
        let run_id = common::run_id();
        let handle = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed() < timeout {
                if done_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if !done_clone.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "WATCHDOG: timeout ({timeout:?}) exceeded for CARRICK_RUN_ID={run_id}; reaping with scripts/sudo/kill.sh"
                );
                let kill_script = common::repo_root().join("scripts/sudo/kill.sh");
                let _ = std::process::Command::new(kill_script)
                    .arg(&run_id)
                    .status();
            }
        });
        Self {
            done,
            handle: Some(handle),
        }
    }

    fn disarm(mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Exit-group stress test: multi-threaded guest where threads hammer write/lseek on a
/// delegated regular file while the main thread calls exit_group; run 20 times.
#[test]
fn el1_files_exit_group_stress() {
    let _guard = common::guest_lock();

    for iteration in 1..=20 {
        let watchdog = Watchdog::start(std::time::Duration::from_secs(30));
        let builder = common::interceptor_probe_builder("exit-group-stress");
        let result = common::run_or_fail(builder.run_blocking());
        watchdog.disarm();
        assert!(
            result.success(),
            "iteration {iteration} failed with exit_code={}",
            result.exit_code
        );
    }
}

/// Signal stress test: a thread in a tight EL1-served write/lseek loop receives
/// SIGUSR1 from another thread and its handler runs within 1 s; run 20 times.
#[test]
fn el1_files_signal_stress() {
    let _guard = common::guest_lock();

    for iteration in 1..=20 {
        let watchdog = Watchdog::start(std::time::Duration::from_secs(30));
        let builder = common::interceptor_probe_builder("signal-stress");
        let result = common::run_or_fail(builder.run_blocking());
        watchdog.disarm();
        assert!(
            result.success(),
            "iteration {iteration} failed with exit_code={}",
            result.exit_code
        );
    }
}

/// B1 test: serving thread blocks (nanosleep 10 ms) between batches and
/// served[64] keeps growing afterwards (would fail if generation was tied to task scheduling generation).
#[test]
fn el1_files_blocking_survives_task_reschedule() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    for iteration in 1..=20 {
        let watchdog = Watchdog::start(std::time::Duration::from_secs(30));
        let result = common::run_or_fail(
            ContainerBuilder::from_image(common::SMOKE_IMAGE)
                .pull_policy(PullPolicy::Missing)
                .command([
                    "/usr/bin/perl",
                    "-e",
                    r#"
open(my $fh, "+>", "/tmp/blocking_test.txt") or die "open: $!";
syswrite($fh, "x") or die "warmup write: $!";
sysseek($fh, 0, 0) or die "warmup seek: $!";

# Batch 1
for (my $i = 0; $i < 500; $i++) {
    syswrite($fh, "x") or die "write 1: $!";
    sysseek($fh, 0, 0) or die "seek 1: $!";
}

# Block / sleep to force task switch-out and bump task scheduling generation
select(undef, undef, undef, 0.01); # 10 ms sleep

# Batch 2
for (my $i = 0; $i < 500; $i++) {
    syswrite($fh, "x") or die "write 2: $!";
    sysseek($fh, 0, 0) or die "seek 2: $!";
}

close($fh);
print "blocking_ok\n";
"#,
                ])
                .run_blocking(),
        );
        watchdog.disarm();

        assert!(
            result.success(),
            "iteration {iteration} failed with exit_code={}, stderr: {}",
            result.exit_code,
            result.stderr_utf8()
        );
        assert_eq!(result.stdout_utf8().trim(), "blocking_ok");

        let counters = read_el1_counters().expect("EL1 counters should be populated");
        let served_writes = counters.served[64].load(Ordering::Relaxed);
        assert!(
            served_writes >= 950,
            "iteration {iteration}: expected at least 950 writes served at EL1 across sleep boundary, got {served_writes}"
        );
    }
}

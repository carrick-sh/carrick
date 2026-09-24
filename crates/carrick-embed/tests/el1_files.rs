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
    carrick_kernel::el1_delegation::reset_delegation_counts();

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
    // Forwards are a fixed startup population (perl's startup fstat calls
    // recall the file and start one short backoff); they must not grow with
    // the loop, and every other iteration is served in-guest.
    const STARTUP_FORWARD_BOUND: u64 = 64;
    let population = carrick_kernel::el1_delegation::delegation_counts();
    assert!(
        forwarded_writes + _forwarded_seeks <= STARTUP_FORWARD_BOUND,
        "lseek+write forwards {} exceed the fixed startup bound {STARTUP_FORWARD_BOUND}; served writes {served_writes}, seeks {served_seeks}; delegation population: {population:?}",
        forwarded_writes + _forwarded_seeks
    );
    assert!(
        served_writes >= 10_000 - STARTUP_FORWARD_BOUND
            && served_seeks >= 10_000 - STARTUP_FORWARD_BOUND,
        "expected the loop served at EL1: writes {served_writes} (forwarded {forwarded_writes}), seeks {served_seeks} (forwarded {_forwarded_seeks}); delegation population: {population:?}"
    );
}

/// Contract `kernel.el1.files.shared-inode`: two open descriptions of one
/// inode stay in the zone. Each keeps its own offset (open(2): a new open file
/// description); both see the same bytes (one inode). The script checks those
/// Linux semantics itself and dies on any violation; the counters prove the
/// interleaved loop is served in-guest.
#[test]
fn el1_files_shared_inode_contract() {
    const ITERATIONS: u64 = 2000;
    const MIN_SERVED_PERMILLE: u64 = 900;
    let _guard = common::guest_lock();
    reset_el1_counters();
    carrick_kernel::el1_delegation::reset_delegation_counts();

    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/usr/bin/perl",
                "-e",
                r#"
open(my $a, "+>", "/tmp/shared_inode.txt") or die "open a: $!";
open(my $b, "+<", "/tmp/shared_inode.txt") or die "open b: $!";
my $buf;
for (my $i = 0; $i < 2000; $i++) {
    my $c = chr(65 + $i % 26);
    sysseek($a, 0, 0) // die "seek a: $!";
    syswrite($a, $c) == 1 or die "write a: $!";
    sysseek($b, 0, 0) // die "seek b: $!";
    sysread($b, $buf, 1) == 1 or die "read b at $i: $!";
    $buf eq $c or die "b saw '$buf' for '$c' at $i";
}
# Independent offsets: both are at 1; a write through a at 1 is read by b at 1.
sysseek($a, 0, 1) == 1 or die "a offset";
sysseek($b, 0, 1) == 1 or die "b offset";
syswrite($a, "xyz") == 3 or die "write xyz";
sysread($b, $buf, 3) == 3 or die "read xyz: $!";
$buf eq "xyz" or die "b read '$buf'";
my @st = stat($b);
$st[7] == 4 or die "size $st[7]";
print "shared_inode_ok
";
"#,
            ])
            .run_blocking(),
    );

    assert!(
        result.success(),
        "exit_code={}: {}",
        result.exit_code,
        result.stderr_utf8()
    );
    assert_eq!(result.stdout_utf8().trim(), "shared_inode_ok");
    let counters = read_el1_counters().expect("EL1 counters should be populated");
    let population = carrick_kernel::el1_delegation::delegation_counts();
    let mut failures = Vec::new();
    for (nr, count) in [
        (62usize, 2 * ITERATIONS),
        (63, ITERATIONS),
        (64, ITERATIONS),
    ] {
        let served = counters.served[nr].load(Ordering::Relaxed);
        if served * 1000 < count * MIN_SERVED_PERMILLE {
            failures.push(format!("syscall {nr}: served {served} of {count}"));
        }
    }
    assert!(
        failures.is_empty(),
        "shared-inode loop not served in-guest: {failures:?}; population {population:?}"
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

/// Two processes on the same file: writer delegated at EL1, reader opens and reads while writer is still alive.
/// Inode-level exclusivity (B3) ensures writer is recalled and reader sees current bytes.
#[test]
fn el1_files_inode_exclusivity_two_processes() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/usr/bin/perl",
                "-e",
                r#"
open(my $wfh, "+>", "/tmp/shared_excl.txt") or die "open writer: $!";
# Warm up and delegate:
for (my $i = 0; $i < 50; $i++) {
    syswrite($wfh, "x") or die "write: $!";
    sysseek($wfh, 0, 0) or die "seek: $!";
}
syswrite($wfh, "writer_payload_abcde\n") or die "write: $!";

my $pid = fork();
if (!defined $pid) { die "fork: $!"; }
if ($pid == 0) {
    # Child opens the same file while parent still has it open:
    open(my $rfh, "<", "/tmp/shared_excl.txt") or die "child open: $!";
    my $buf;
    sysread($rfh, $buf, 100) or die "child read: $!";
    close($rfh);
    print "child_got: $buf";
    exit(0);
} else {
    waitpid($pid, 0);
    close($wfh);
}
"#,
            ])
            .run_blocking(),
    );

    assert!(result.success(), "exit_code={}", result.exit_code);
    assert_eq!(
        result.stdout_utf8().trim(),
        "child_got: writer_payload_abcde"
    );
}

/// Memfd sealing recall test: guest creates an unsealed memfd (with MFD_ALLOW_SEALING),
/// performs repeated write+lseek operations (served at EL1), then seals it with
/// F_ADD_SEALS (F_SEAL_WRITE). Subsequent write must be rejected with EPERM,
/// proving EL1 delegation was recalled and subsequent operations trap to Carrick host.
#[test]
fn el1_files_memfd_never_delegated_and_seals_hold() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/usr/bin/perl",
                "-e",
                r#"
my $name = "test_memfd\0";
my $fd = syscall(279, $name, 2); # memfd_create("test_memfd", MFD_ALLOW_SEALING=2)
if ($fd < 0) { die "memfd_create failed: $!"; }

open(my $fh, "+<&=", $fd) or die "open fd: $!";

# Writes and seeks that would delegate a host regular file:
syswrite($fh, "x") or die "warmup write: $!";
sysseek($fh, 0, 0) or die "warmup seek: $!";
for (my $i = 0; $i < 50; $i++) {
    syswrite($fh, "x") or die "write $i: $!";
    sysseek($fh, 0, 0) or die "seek $i: $!";
}

# Seal the memfd against writes: fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE)
# On aarch64 Linux, fcntl syscall is 25:
my $ret = syscall(25, $fd, 1033, 8);
if ($ret < 0) { die "fcntl F_ADD_SEALS failed: $!"; }

# Attempt write after sealing: must fail with EPERM (errno 1)
my $w = syswrite($fh, "y");
if (defined $w) {
    die "write succeeded after F_SEAL_WRITE!";
}
if ($! != 1) {
    die "expected EPERM (1), got errno: " . int($!);
}

close($fh);
print "memfd_seal_ok\n";
"#,
            ])
            .run_blocking(),
    );

    assert!(
        result.success(),
        "exit_code={}, stderr={}",
        result.exit_code,
        result.stderr_utf8()
    );
    assert_eq!(result.stdout_utf8().trim(), "memfd_seal_ok");

    // memfds are in-memory descriptions: they keep their single host path and
    // are never delegated, so the seal is enforced by the host write path.
    let counters = read_el1_counters().expect("EL1 counters should be populated");
    let served_writes = counters.served[64].load(Ordering::Relaxed);
    assert_eq!(
        served_writes, 0,
        "memfd writes must never be served at EL1, got {served_writes}"
    );
}

/// Multi-threaded kick delivery: Thread 1 opens a file, does one EL1-served write/seek,
/// then enters an EL0 spin loop (`while(1){}`). Thread 2 sleeps briefly (50 ms) then calls
/// `exit_group(0)`. Watchdog bounds at 2 s. Assert exit succeeds; run 20 iterations.
#[test]
fn el1_files_kick_delivery_spin_loop() {
    let _guard = common::guest_lock();

    for iteration in 1..=20 {
        let watchdog = Watchdog::start(std::time::Duration::from_secs(2));
        let builder = common::interceptor_probe_builder("spin-loop-exit");
        let result = common::run_or_fail(builder.run_blocking());
        watchdog.disarm();
        assert!(
            result.success(),
            "iteration {iteration} failed with exit_code={}, stderr: {}",
            result.exit_code,
            result.stderr_utf8()
        );
    }
}

/// Multi-threaded kick delivery via signal: Thread 1 opens a file, does one EL1-served write/seek,
/// then enters an EL0 spin loop. Sibling thread sends SIGUSR1 via tgkill.
/// Watchdog bounds at 2 s. Assert handler runs within 1 s and process exits 0; run 20 iterations.
#[test]
fn el1_files_kick_delivery_spin_loop_signal() {
    let _guard = common::guest_lock();

    for iteration in 1..=20 {
        let watchdog = Watchdog::start(std::time::Duration::from_secs(2));
        let builder = common::interceptor_probe_builder("spin-loop-signal");
        let result = common::run_or_fail(builder.run_blocking());
        watchdog.disarm();
        assert!(
            result.success(),
            "iteration {iteration} failed with exit_code={}, stderr: {}",
            result.exit_code,
            result.stderr_utf8()
        );
    }
}

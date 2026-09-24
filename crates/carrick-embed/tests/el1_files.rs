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

/// Contract `kernel.el1.files.path-mutation`: an in-zone file mutated
/// through another path (`O_TRUNC` by a second open, `truncate(2)` by path,
/// `ftruncate(2)` through another description) shows exactly the Linux
/// result through every description. The fixture checks sizes and bytes
/// itself; the counters prove the writes before each mutation were served
/// in-guest, so the zone's copy is what the mutation must not lose.
#[test]
fn el1_files_path_mutation_contract() {
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
my $buf;
# O_TRUNC by a second open empties the file for every description.
open(my $a, "+>", "/tmp/pm_otrunc.txt") or die "open a: $!";
syswrite($a, "hello") == 5 or die for 1..64;
open(my $b, ">", "/tmp/pm_otrunc.txt") or die "open b: $!";
close($b);
my @st = stat("/tmp/pm_otrunc.txt");
$st[7] == 0 or die "O_TRUNC: size $st[7], want 0";
sysseek($a, 0, 0) // die; sysread($a, $buf, 10) == 0 or die "O_TRUNC: a read old bytes";
# truncate(2) by path shortens the file for the open description.
open(my $c, "+>", "/tmp/pm_truncate.txt") or die "open c: $!";
syswrite($c, "hello") == 5 or die for 1..64;
truncate("/tmp/pm_truncate.txt", 2) or die "truncate: $!";
@st = stat($c); $st[7] == 2 or die "truncate: size $st[7], want 2";
sysseek($c, 0, 0) // die; sysread($c, $buf, 10) == 2 or die "truncate: read";
$buf eq "he" or die "truncate: read '$buf'";
# ftruncate(2) through another description of the same inode.
open(my $d, "+>", "/tmp/pm_ftruncate.txt") or die "open d: $!";
syswrite($d, "hello") == 5 or die for 1..64;
open(my $e, "+<", "/tmp/pm_ftruncate.txt") or die "open e: $!";
truncate($e, 3) or die "ftruncate: $!";
sysseek($d, 0, 0) // die; sysread($d, $buf, 10) == 3 or die "ftruncate: read";
$buf eq "hel" or die "ftruncate: read '$buf'";
print "path_mutation_ok\n";
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
    assert_eq!(result.stdout_utf8().trim(), "path_mutation_ok");
    let counters = read_el1_counters().expect("EL1 counters should be populated");
    let served_writes = counters.served[64].load(Ordering::Relaxed);
    assert!(
        served_writes >= 3 * 60,
        "the pre-mutation writes must be served in-guest for this contract to exercise the zone, got {served_writes}"
    );
}

/// Contract `kernel.el1.zone-entry-at-open`: a file enters the zone at
/// open and only there. A demotion (a shared mmap of the file) is final for
/// that open description: its later seeks, writes and reads are host-served
/// and correct however many follow, and a watch added afterwards does not
/// pull it back in. A fresh open of the same file enters the zone again.
///
/// Each phase uses its own syscalls so the carrier-wide EL1 counters
/// attribute them: pwrite64 (68) in the zone from open; lseek/write/read
/// (62/64/63) on the demoted description; pread64 (67) after the fresh
/// open. The script checks the Linux results itself and loads no module, so
/// perl reads no other regular file that the zone could serve.
#[test]
fn el1_zone_entry_at_open_contract() {
    const N: u64 = 500;
    /// Operations of an in-zone phase that may be forwarded (contention,
    /// the first access racing the entry at open).
    const FORWARD_BOUND: u64 = 16;
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
my $N = 500;
my $path = "/tmp/zone_entry.txt";
my $buf;
open(my $a, "+>", $path) or die "open: $!";
# In the zone from open: pwrite64 only.
for (my $i = 0; $i < $N; $i++) {
    syscall(68, fileno($a), chr(65 + $i % 26), 1, $i % 64) == 1 or die "pwrite $i: $!";
}
# Demote: a shared mapping of the file takes the inode out of the zone.
my $addr = syscall(222, 0, 4096, 1, 1, fileno($a), 0);
$addr != -1 or die "mmap: $!";
syscall(215, $addr, 4096) == 0 or die "munmap: $!";
# The demoted description stays on the host path for its whole life. Half
# way through, a watch on the demoted file is added: a host watch, which must
# not pull it back in either.
my $q;
my $wd;
for (my $i = 0; $i < 2 * $N; $i++) {
    if ($i == $N) {
        $q = syscall(26, 0x800);
        $q >= 0 or die "inotify_init1: $!";
        $wd = syscall(27, $q, "$path\0", 2);
        $wd >= 0 or die "add_watch: $!";
    }
    my $c = chr(97 + $i % 26);
    my $at = $i % 64;
    defined(sysseek($a, $at, 0)) or die "seek $i: $!";
    syswrite($a, $c) == 1 or die "write $i: $!";
    defined(sysseek($a, $at, 0)) or die "seek back $i: $!";
    sysread($a, $buf, 1) == 1 or die "read $i: $!";
    $buf eq $c or die "demoted read '$buf' for '$c' at $i";
}
# The host-served writes reached the watching instance.
my $pending = pack("i", 0);
syscall(29, $q, 0x541B, $pending) == 0 or die "FIONREAD: $!";
unpack("i", $pending) > 0 or die "no IN_MODIFY queued for the host-served writes";
syscall(28, $q, $wd) == 0 or die "rm_watch: $!";
syscall(57, $q) == 0 or die "close inotify: $!";
my $expect = "";
for (my $k = 0; $k < 64; $k++) {
    my $last = $k;
    $last += 64 while $last + 64 < 2 * $N;
    $expect .= chr(97 + $last % 26);
}
close($a) or die "close: $!";
# A fresh open enters the zone again: pread64 only.
open(my $c, "+<", $path) or die "reopen: $!";
for (my $i = 0; $i < $N; $i++) {
    my $b = "\0";
    syscall(67, fileno($c), $b, 1, $i % 64) == 1 or die "pread $i: $!";
    $b eq substr($expect, $i % 64, 1) or die "reopened pread '$b' at $i";
}
close($c) or die "close reopened: $!";
print "zone_entry_ok\n";
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
    assert_eq!(result.stdout_utf8().trim(), "zone_entry_ok");
    let counters = read_el1_counters().expect("EL1 counters should be populated");
    let served = |nr: usize| counters.served[nr].load(Ordering::Relaxed);
    let forwarded = |nr: usize| counters.forwarded[nr].load(Ordering::Relaxed);
    let population = carrick_kernel::el1_delegation::delegation_counts();
    let report = format!(
        "served pwrite64={} lseek={} write={} read={} pread64={}; forwarded lseek={} write={} read={}; population {population:?}",
        served(68),
        served(62),
        served(64),
        served(63),
        served(67),
        forwarded(62),
        forwarded(64),
        forwarded(63),
    );
    eprintln!("el1_zone_entry_at_open_contract: {report}");
    let mut failures = Vec::new();
    // Entry at open: the first phase is served in the zone.
    if served(68) + FORWARD_BOUND < N {
        failures.push("the file did not enter the zone at open (pwrite64 not served)");
    }
    // Demotion is final for the description: none of its later operations
    // is served in-guest, and all of them ran on the host.
    if served(62) != 0 || served(64) != 0 || served(63) != 0 {
        failures.push("the demoted description re-entered the zone (lseek/write/read served)");
    }
    if forwarded(64) < 2 * N || forwarded(62) < 4 * N || forwarded(63) < 2 * N {
        failures.push("the demoted phase did not run on the host");
    }
    // A fresh open enters again.
    if served(67) + FORWARD_BOUND < N {
        failures.push("a fresh open did not enter the zone (pread64 not served)");
    }
    assert!(
        failures.is_empty(),
        "zone entry at open: {failures:?}; {report}"
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

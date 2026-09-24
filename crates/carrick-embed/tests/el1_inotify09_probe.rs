//! Director diagnostic: EL1 served/forwarded counters for LTP inotify09 itself.
//!
//! Run ONLY through `just test-embed el1_inotify09_probe` (scripts/test-signed.sh).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;

use carrick_embed::{ContainerBuilder, read_el1_counters, reset_el1_counters};
use carrick_image::PullPolicy;

#[test]
fn el1_inotify09_probe() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    carrick_kernel::el1_delegation::reset_delegation_counts();
    let start = std::time::Instant::now();
    let result = common::run_or_fail(
        ContainerBuilder::from_image("localhost:5050/ltp:arm64")
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "/opt/ltp/testcases/bin/inotify09"])
            .run_blocking(),
    );
    let wall = start.elapsed();
    let err = result.stderr_utf8();
    for line in err.lines().filter(|l| {
        l.contains("fuzzy_sync")
            || l.contains("TPASS")
            || l.contains("TFAIL")
            || l.contains("TBROK")
    }) {
        eprintln!("LTP| {line}");
    }
    let counters = read_el1_counters().expect("EL1 counters should be populated");
    eprintln!("WALL| {wall:?} exit={}", result.exit_code);
    for nr in 0..512usize {
        let s = counters.served[nr].load(Ordering::Relaxed);
        let f = counters.forwarded[nr].load(Ordering::Relaxed);
        if s + f > 0 {
            eprintln!("NR| {nr:>3} served={s:>10} forwarded={f:>10}");
        }
    }
    eprintln!(
        "POP| {:?}",
        carrick_kernel::el1_delegation::delegation_counts()
    );
    assert!(result.success(), "exit_code={}", result.exit_code);
}

/// Director diagnostic: per-iteration cost of add_watch/write/lseek/rm_watch
/// when the loop is served in-guest (single thread, the fixture shape).
#[test]
fn el1_inotify_loop_bench() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/usr/bin/perl",
                "-e",
                r#"
use strict; use warnings;
sub now { my $ts = "\0" x 16; syscall(113, 1, $ts); my ($sec, $ns) = unpack("q q", $ts); return $sec + $ns / 1e9; }
my $path = "/tmp/bench_inotify.txt\0";
open(my $fh, "+>", "/tmp/bench_inotify.txt") or die "open: $!";
my $q = syscall(26, 0x800 | 0x80000); die "init: $!" if $q < 0;
my $wd0 = syscall(27, $q, $path, 2); syscall(28, $q, $wd0);
for my $i (0..999) { my $wd = syscall(27, $q, $path, 2); syswrite($fh, "x"); sysseek($fh, 0, 0); syscall(28, $q, $wd); }
my $n = 200000; my $t0 = now();
for my $i (1..$n) { my $wd = syscall(27, $q, $path, 2); syswrite($fh, "x"); sysseek($fh, 0, 0); syscall(28, $q, $wd); }
my $dt = now() - $t0;
printf("loop_ns_per_iter=%.0f\n", $dt * 1e9 / $n);
my $t1 = now(); for my $i (1..$n) { syscall(172); } my $g = now() - $t1;
printf("getpid_ns=%.0f\n", $g * 1e9 / $n);
"#,
            ])
            .run_blocking(),
    );
    eprintln!("BENCH| {}", result.stdout_utf8().trim().replace('\n', " "));
    eprintln!(
        "BENCHERR| {}",
        result.stderr_utf8().trim().replace('\n', " | ")
    );
    let Some(counters) = read_el1_counters() else {
        eprintln!("BENCH| no EL1 counters (EL1 disabled)");
        return;
    };
    for nr in [27usize, 28, 62, 64, 172] {
        eprintln!(
            "BENCH| nr {nr} served={} forwarded={}",
            counters.served[nr].load(Ordering::Relaxed),
            counters.forwarded[nr].load(Ordering::Relaxed)
        );
    }
    assert!(result.success(), "exit_code={}", result.exit_code);
}

//! Signed EL1 delegated inotify verification.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;

use carrick_embed::{ContainerBuilder, read_el1_counters, reset_el1_counters};
use carrick_image::PullPolicy;

/// Contract test: 1,000 iterations of inotify_add_watch, write, lseek, inotify_rm_watch
/// on a delegated regular file served entirely at EL1 without VM exits in steady state.
#[test]
fn el1_inotify_contract() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/usr/bin/perl",
                "-e",
                r#"
use strict;
use warnings;
use POSIX qw(:fcntl_h);

my $SYS_inotify_init1 = 26;
my $SYS_inotify_add_watch = 27;
my $SYS_inotify_rm_watch = 28;

my $path = "/tmp/contract_inotify.txt\0";
open(my $fh, "+>", "/tmp/contract_inotify.txt") or die "open: $!";
my $q = syscall($SYS_inotify_init1, 0x800 | 0x80000);
die "inotify_init1: $!" if $q < 0;

# Warm up
my $wd0 = syscall($SYS_inotify_add_watch, $q, $path, 2);
die "warmup add_watch: $!" if $wd0 < 0;
syscall($SYS_inotify_rm_watch, $q, $wd0);

for (my $i = 0; $i < 1000; $i++) {
    my $wd = syscall($SYS_inotify_add_watch, $q, $path, 2);
    die "add_watch: $!" if $wd < 0;
    syswrite($fh, "x") or die "write: $!";
    sysseek($fh, 0, 0);
    my $rm = syscall($SYS_inotify_rm_watch, $q, $wd);
    if ($rm != 0) {
        die "failed at i=$i wd=$wd rm=$rm: $!";
    }
}

close($fh);
POSIX::close($q);
print "contract_ok\n";
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
    assert_eq!(result.stdout_utf8().trim(), "contract_ok");

    let counters = read_el1_counters().expect("EL1 counters should be populated");
    let served_add_watch = counters.served[27].load(Ordering::Relaxed);
    let forwarded_add_watch = counters.forwarded[27].load(Ordering::Relaxed);
    let served_rm_watch = counters.served[28].load(Ordering::Relaxed);
    let forwarded_rm_watch = counters.forwarded[28].load(Ordering::Relaxed);
    let served_writes = counters.served[64].load(Ordering::Relaxed);
    let served_seeks = counters.served[62].load(Ordering::Relaxed);

    eprintln!(
        "el1_inotify_contract: add_watch served={served_add_watch}, fwd={forwarded_add_watch}; rm_watch served={served_rm_watch}, fwd={forwarded_rm_watch}; write served={served_writes}; seek served={served_seeks}"
    );

    assert!(
        served_add_watch >= 990,
        "expected >= 990 add_watch served at EL1, got {served_add_watch} (forwarded: {forwarded_add_watch})"
    );
    assert!(
        served_rm_watch >= 1000,
        "expected >= 1000 rm_watch served at EL1, got {served_rm_watch} (forwarded: {forwarded_rm_watch})"
    );
    assert!(
        served_writes >= 1000,
        "expected >= 1000 writes served at EL1, got {served_writes}"
    );
    assert!(
        served_seeks >= 1000,
        "expected >= 1000 seeks served at EL1, got {served_seeks}"
    );
}

/// Verify queue shape and event stream match Linux oracle rows for churn and serial_full.
#[test]
fn el1_inotify_queue_shape() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/usr/bin/perl",
                "-e",
                r#"
use strict;
use warnings;
use POSIX qw(:fcntl_h);

my $SYS_inotify_init1 = 26;
my $SYS_inotify_add_watch = 27;
my $SYS_inotify_rm_watch = 28;

my $path = "/tmp/shape_inotify.txt\0";
open(my $fh, "+>", "/tmp/shape_inotify.txt") or die "open: $!";

for my $mode ('churn', 'serial_full') {
    for my $n (1, 8, 32, 128) {
        my $q = syscall($SYS_inotify_init1, 0x800 | 0x80000);
        die "init1: $!" if $q < 0;
        my %seen_wds;
        for (my $i = 0; $i < $n; $i++) {
            my $wd = syscall($SYS_inotify_add_watch, $q, $path, 2);
            die "add: $!" if $wd < 0;
            $seen_wds{$wd} = 1;
            if ($mode eq 'serial_full') {
                syswrite($fh, "x" x 64) == 64 or die "write: $!";
                sysseek($fh, 0, 0);
            }
            syscall($SYS_inotify_rm_watch, $q, $wd) == 0 or die "rm: $!";
        }
        my $distinct = scalar(keys %seen_wds);
        die "distinct $distinct != $n" if $distinct != $n;
        my $data = "";
        while (1) {
            my $chunk;
            my $r = POSIX::read($q, $chunk, 65536);
            last if !defined($r) || $r <= 0;
            $data .= $chunk;
        }
        my $pos = 0;
        my $events = 0;
        my $ignored = 0;
        my $modify = 0;
        while ($pos < length($data)) {
            my ($wd, $mask, $cookie, $len) = unpack("iIII", substr($data, $pos, 16));
            $events++;
            $ignored++ if ($mask & 0x8000) != 0;
            $modify++ if ($mask & 2) != 0;
            $pos += 16 + $len;
        }
        if ($mode eq 'churn') {
            die "churn events $events != $n" if $events != $n;
            die "churn ignored $ignored != $n" if $ignored != $n;
        } else {
            die "serial events $events != " . (2 * $n) if $events != 2 * $n;
            die "serial ignored $ignored != $n" if $ignored != $n;
            die "serial modify $modify != $n" if $modify != $n;
        }
        POSIX::close($q);
    }
}
close($fh);
unlink("/tmp/shape_inotify.txt");
print "shape_ok\n";
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
    assert_eq!(result.stdout_utf8().trim(), "shape_ok");
}

/// Verify that adding a non-delegated watch or a parent directory watch recalls the file.
#[test]
fn el1_inotify_recall_on_dir_watch() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/usr/bin/perl",
                "-e",
                r#"
use strict;
use warnings;
use POSIX qw(:fcntl_h);

my $SYS_inotify_init1 = 26;
my $SYS_inotify_add_watch = 27;

mkdir("/tmp/inotify_dir", 0755);
my $dir_path = "/tmp/inotify_dir\0";
my $file_path = "/tmp/inotify_dir/file.txt\0";
open(my $fh, "+>", "/tmp/inotify_dir/file.txt") or die "open: $!";

my $q1 = syscall($SYS_inotify_init1, 0x800 | 0x80000);
my $wd1 = syscall($SYS_inotify_add_watch, $q1, $file_path, 2);
die "add file: $!" if $wd1 < 0;

syswrite($fh, "hello") or die "write: $!";

# Add parent dir watch
my $q2 = syscall($SYS_inotify_init1, 0x800 | 0x80000);
my $wd2 = syscall($SYS_inotify_add_watch, $q2, $dir_path, 2);
die "add dir: $!" if $wd2 < 0;

# Host write still works after recall
syswrite($fh, "world") or die "write 2: $!";

close($fh);
POSIX::close($q1);
POSIX::close($q2);
print "recall_ok\n";
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
    assert_eq!(result.stdout_utf8().trim(), "recall_ok");
}

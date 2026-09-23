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
    let served_seeks = counters.served[62].load(Ordering::Relaxed);
    assert!(
        served_writes >= 10_000,
        "expected at least 10,000 writes served at EL1, got {served_writes}"
    );
    assert!(
        served_seeks >= 10_000,
        "expected at least 10,000 seeks served at EL1, got {served_seeks}"
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

/// Exit-group stress test: multi-threaded guest where threads hammer write/lseek on a
/// delegated regular file while the main thread calls exit_group; run 20 times.
#[test]
fn el1_files_exit_group_stress() {
    let _guard = common::guest_lock();

    for iteration in 1..=20 {
        let builder = common::interceptor_probe_builder("exit-group-stress");
        let result = common::run_or_fail(builder.run_blocking());
        assert!(
            result.success(),
            "iteration {iteration} failed with exit_code={}",
            result.exit_code
        );
    }
}

//! First production IPC routing witness; not the full IPC acceptance suite.
//! Run through scripts/test-signed.sh carrick-embed el1_ipc_live_routing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_embed::{ContainerBuilder, PullPolicy, read_el1_counters, reset_el1_counters};
use std::sync::atomic::Ordering;

#[test]
fn el1_ipc_live_routing() {
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
pipe(my $r, my $w) or die "pipe: $!";
my $event = syscall(19, 0, 2048);
$event >= 0 or die "eventfd: $!";
for my $i (1..1024) {
    my $payload = pack("Q<", $i);
    syswrite($w, $payload) == 8 or die "pipe write: $!";
    my $received = "";
    sysread($r, $received, 8) == 8 or die "pipe read: $!";
    $received eq $payload or die "pipe bytes at $i";
    syscall(64, $event, $payload, 8) == 8 or die "eventfd write: $!";
    $received = "\0" x 8;
    syscall(63, $event, $received, 8) == 8 or die "eventfd read: $!";
    $received eq $payload or die "eventfd value at $i";
}
close($r) or die "close reader: $!";
close($w) or die "close writer: $!";
syscall(57, $event) == 0 or die "close eventfd: $!";
print "ipc_routing_ok\n";
"#,
            ])
            .run_blocking(),
    );
    assert!(
        result.success(),
        "exit {}: {}",
        result.exit_code,
        result.stderr_utf8()
    );
    assert_eq!(result.stdout_utf8().trim(), "ipc_routing_ok");
    let counters = read_el1_counters().expect("real EL1 execution counters");
    let reads = counters.served[63].load(Ordering::Relaxed);
    let writes = counters.served[64].load(Ordering::Relaxed);
    let forwarded_reads = counters.forwarded[63].load(Ordering::Relaxed);
    let forwarded_writes = counters.forwarded[64].load(Ordering::Relaxed);
    eprintln!(
        "whole-run routing observation: served read={reads} write={writes}, forwarded read={forwarded_reads} write={forwarded_writes}"
    );
    // There are 2048 data transfers in each direction. Startup also performs
    // file I/O, so these are whole-run routing witnesses, not scoped zero-exit
    // budgets. The full vertical still requires the five exact IPC witnesses.
    assert!(
        reads >= 2048 && writes >= 2048,
        "pipe/eventfd loop did not execute in EL1"
    );
}

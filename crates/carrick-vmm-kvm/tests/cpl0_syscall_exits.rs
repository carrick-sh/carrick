//! Live KVM budget witness for `kernel.x86.ring-syscall-exits` (#2679): a
//! syscall the production x86 CPL0 ring serves must cost the host no VM
//! exit. The census is the carrier's own in-kernel KVM statistics
//! (`KVM_GET_STATS_FD` on its two vCPUs), so it counts exits the host kernel
//! handles without returning to Carrick, such as an intercepted CR4 read.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used, clippy::panic)]

#[path = "common/kvm_pool_fixture.rs"]
#[allow(dead_code)]
mod kvm_pool_fixture;

use carrick_vmm_kvm::kvm::KernelStatTotals;

/// Rounds per scale point; each round is two ring-served syscalls
/// (`getppid`, then `rt_sigprocmask` copying the old mask out).
const SCALE_POINTS: [u32; 3] = [256, 2048, 16384];
const SYSCALLS_PER_ROUND: u64 = 2;

struct Point {
    rounds: u32,
    exits: u64,
    emulations: u64,
}

fn counter(totals: &KernelStatTotals, name: &str) -> u64 {
    totals
        .get(name)
        .unwrap_or_else(|| panic!("IncompleteMeasurement: KVM stat `{name}` is not published"))
}

fn run_point(rounds: u32) -> Point {
    let elf = kvm_pool_fixture::assemble_fixture(
        "native_root_syscall_exits.S",
        &[&format!("-DLOOP_COUNT={rounds}")],
    );
    let mut census = None;
    let outcome = kvm_pool_fixture::run_pool_fixture_with(&elf, 128, |carrier| {
        census = Some(carrier.kernel_stats().expect("carrier KVM stats census"));
    });
    assert_eq!(
        outcome.run.exit_code, 0,
        "every round's getppid and rt_sigprocmask must succeed in ring (91 = wrong answer)"
    );
    let totals = census
        .expect("census bound before the run")
        .totals()
        .expect("read carrier KVM stats");
    Point {
        rounds,
        exits: counter(&totals, "exits"),
        emulations: counter(&totals, "insn_emulation"),
    }
}

/// Structural budget: the exits and software-emulated instructions of a run
/// must not grow with the number of ring-served syscalls. Asynchronous exits
/// (the host timer, a preemption) scale with wall time, not calls, so the
/// exit slope is bounded at one per 64 syscalls; an emulated instruction is
/// never part of a ring-served syscall, so its slope is bounded at one per
/// 1024 syscalls (fixed boot work cancels between scale points).
#[test]
fn serial_host_native_root_ring_syscalls_cost_no_vm_exit() {
    const TEST: &str = "serial_host_native_root_ring_syscalls_cost_no_vm_exit";
    // Bound the whole fixture in a child test process, so a lost wake fails
    // within the bound instead of hanging the lane.
    if !kvm_pool_fixture::bounded_child::in_bounded_child(TEST, std::time::Duration::from_secs(120))
    {
        return;
    }
    let points: Vec<Point> = SCALE_POINTS
        .iter()
        .map(|rounds| run_point(*rounds))
        .collect();
    let base = &points[0];
    for point in &points {
        eprintln!(
            "rounds={} syscalls={} exits={} insn_emulation={}",
            point.rounds,
            u64::from(point.rounds) * SYSCALLS_PER_ROUND,
            point.exits,
            point.emulations
        );
    }
    for point in &points[1..] {
        let syscalls = u64::from(point.rounds - base.rounds) * SYSCALLS_PER_ROUND;
        let exits = point.exits.saturating_sub(base.exits);
        let emulations = point.emulations.saturating_sub(base.emulations);
        assert!(
            exits <= syscalls / 64,
            "WorkBudgetExceeded: {exits} more KVM exits for {syscalls} more ring syscalls \
             (budget {}); rounds {} vs {}",
            syscalls / 64,
            point.rounds,
            base.rounds
        );
        assert!(
            emulations <= syscalls / 1024,
            "WorkBudgetExceeded: {emulations} more emulated instructions for {syscalls} more \
             ring syscalls (budget {}); rounds {} vs {}",
            syscalls / 1024,
            point.rounds,
            base.rounds
        );
    }
}

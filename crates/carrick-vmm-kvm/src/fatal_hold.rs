//! Discovery diagnostics (C4 harness, never lands): hold a carrier at a
//! non-panic fatal exit, such as an unacknowledged shootdown, so a debugger
//! can read the peer vCPU while it is still where the sender gave up on it.
//!
//! With `CARRICK_DISCOVER_FATAL_HOLD=<dir>`, the vCPU thread that took the
//! fatal writes `<dir>/fatal-hold.<pid>.txt` (its own registers, the guest
//! RAM windows, the shootdown table and both CPU bindings), then waits for
//! `<dir>/fatal-hold.<pid>.done` or `CARRICK_DISCOVER_FATAL_HOLD_SECS`
//! (default 120) before the exit goes on to fail the carrier as before.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use carrick_x86::cpl0_entry::{CPL0_CPU_COUNT, CpuBinding, ShootdownTable};
use carrick_x86_cpl0_host::cpl0_boot::{BINDING_OFFSET, META_GPA, STRIDE};

use crate::KvmVcpu;
use crate::cpl0_boot::GuestRam;

fn table_text(out: &mut String, label: &str, table: &ShootdownTable) {
    let _ = writeln!(
        out,
        "{label} next_generation={} fixture_hold_ipi={}",
        table.next_generation.load(Ordering::Acquire),
        table.fixture_hold_ipi.load(Ordering::Acquire),
    );
    for (cpu, kick) in table.kick_checks.iter().enumerate() {
        let _ = writeln!(
            out,
            "{label} kick_checks[{cpu}]={}",
            kick.load(Ordering::Acquire)
        );
    }
    for (cpu, member) in table.members.iter().enumerate() {
        let _ = writeln!(
            out,
            "{label} member[{cpu}] revision={} root={:#x} mm_key={:#x} owner_generation={} running={}",
            member.revision.load(Ordering::Acquire),
            member.root.load(Ordering::Acquire),
            member.mm_key.load(Ordering::Acquire),
            member.owner_generation.load(Ordering::Acquire),
            member.running.load(Ordering::Acquire),
        );
    }
    for (sender, request) in table.requests.iter().enumerate() {
        let ack: Vec<u64> = (0..CPL0_CPU_COUNT)
            .map(|cpu| request.ack[cpu].load(Ordering::Acquire))
            .collect();
        let served: Vec<u64> = (0..CPL0_CPU_COUNT)
            .map(|cpu| request.served[cpu].load(Ordering::Acquire))
            .collect();
        let _ = writeln!(
            out,
            "{label} request[{sender}] root={:#x} mm_key={:#x} owner_generation={} generation={} ack={ack:?} served={served:?}",
            request.root.load(Ordering::Acquire),
            request.mm_key.load(Ordering::Acquire),
            request.owner_generation.load(Ordering::Acquire),
            request.generation.load(Ordering::Acquire),
        );
    }
}

fn bindings_text(out: &mut String, label: &str, ram: &GuestRam) {
    for cpu in 0..CPL0_CPU_COUNT as u64 {
        let gpa = META_GPA + BINDING_OFFSET + cpu * STRIDE;
        let Some(ptr) = ram.host_ptr(gpa, size_of::<CpuBinding>()) else {
            let _ = writeln!(out, "{label} binding[{cpu}] gpa={gpa:#x} unmapped");
            continue;
        };
        // SAFETY: the retained RAM owns the binding page for the carrier's
        // lifetime; only its published atomics and plain words are read.
        let binding = unsafe { &*ptr.cast::<CpuBinding>() };
        let _ = writeln!(
            out,
            "{label} binding[{cpu}] gpa={gpa:#x} kernel_stack={:#x} task={:#x} entries={} publications={} completions={} entry_kick={} return_kick={} pending_irqs={:#x} fault_active={} fault_frame={:#x} fault_address={:#x} fault_reason={} mm_owner_generation={} last_seen_generation={} shootdown_table={:#x}",
            binding.kernel_stack,
            binding.task_address,
            binding.entries.load(Ordering::Acquire),
            binding.publications.load(Ordering::Acquire),
            binding.completions.load(Ordering::Acquire),
            binding.entry_kick.load(Ordering::Acquire),
            binding.return_kick.load(Ordering::Acquire),
            binding.pending_irqs.load(Ordering::Acquire),
            binding.fault_active.load(Ordering::Acquire),
            binding.fault_frame.load(Ordering::Acquire),
            binding.fault_address.load(Ordering::Acquire),
            binding.fault_reason.load(Ordering::Acquire),
            binding.mm_owner_generation.load(Ordering::Acquire),
            binding.last_seen_generation.load(Ordering::Acquire),
            binding.shootdown_table_address,
        );
    }
}

fn write_atomically(path: &PathBuf, text: &str) {
    let staging = path.with_extension("staging");
    if std::fs::write(&staging, text).is_ok() {
        let _ = std::fs::rename(&staging, path);
    }
}

/// Hold the carrier at a fatal-port exit that carries the panic sentinel,
/// when discovery asked for it. Returns at once otherwise.
pub(crate) fn hold_at_fatal(cpu: &KvmVcpu, table: &ShootdownTable, slot: usize, ram: &GuestRam) {
    let Some(dir) = std::env::var_os("CARRICK_DISCOVER_FATAL_HOLD") else {
        return;
    };
    let Ok(regs) = cpu.fd().get_regs() else {
        return;
    };
    if regs.rax != carrick_el1_abi::PANIC_SENTINEL {
        return;
    }
    let cr3 = cpu.fd().get_sregs().map(|sregs| sregs.cr3).unwrap_or(0);
    let pid = std::process::id();
    // SAFETY: gettid has no preconditions.
    let tid = unsafe { libc::gettid() };
    let mut out = String::new();
    let _ = writeln!(out, "pid={pid} tid={tid} slot={slot}");
    let _ = writeln!(
        out,
        "sender rip={:#x} rsp={:#x} rbp={:#x} rflags={:#x} rsi={:#x} rdi={:#x} cr3={cr3:#x} peer={} generation={}",
        regs.rip,
        regs.rsp,
        regs.rbp,
        regs.rflags,
        regs.rsi,
        regs.rdi,
        regs.rsi >> 32,
        regs.rsi & 0xffff_ffff,
    );
    for (gpa, host, len) in ram.slot_windows() {
        let _ = writeln!(
            out,
            "window gpa={gpa:#x} host={:#x} len={len:#x}",
            host as usize
        );
    }
    table_text(&mut out, "at-fatal", table);
    bindings_text(&mut out, "at-fatal", ram);
    let dir = PathBuf::from(dir);
    let marker = dir.join(format!("fatal-hold.{pid}.txt"));
    write_atomically(&marker, &out);
    let bound = std::env::var("CARRICK_DISCOVER_FATAL_HOLD_SECS")
        .ok()
        .and_then(|secs| secs.parse().ok())
        .unwrap_or(120);
    let done = dir.join(format!("fatal-hold.{pid}.done"));
    let start = Instant::now();
    while !done.exists() && start.elapsed() < Duration::from_secs(bound) {
        std::thread::sleep(Duration::from_millis(100));
    }
    table_text(&mut out, "at-release", table);
    bindings_text(&mut out, "at-release", ram);
    write_atomically(&marker, &out);
}

//! Guest-side reducer for `hvpatch-syscall-host-tax.d`: a tight loop of ONE
//! guest syscall kind, so the ledger's "host syscalls per guest syscall" ratio
//! is read against a denominator nothing else contaminates.
//!
//! WHY IT EXISTS. Two host syscalls are (were) issued unconditionally on every
//! guest syscall — a `CLOCK_THREAD_CPUTIME_ID` read before and after the
//! dispatch scope — and one host `fstat` on every guest `close`. Both are flat
//! taxes: they do not show up as any one subsystem's cost, so a realistic
//! workload hides them inside its own noise. A loop that issues 200k of a
//! single, otherwise-free syscall makes the tax the ONLY term.
//!
//! WHAT IT MEASURES. Nothing by itself — it is the denominator. The ledger
//! script counts the host syscalls carrick issues inside each guest syscall's
//! service window; this program decides which window kind that is.
//!
//! MODES (argv[1]):
//!   ebadf N     — N x `close(-1)`: the cheapest syscall that still reaches
//!                 carrick's DISPATCH path. It fails EBADF out of the fd table
//!                 and must touch the host for nothing at all, so every host
//!                 syscall the ledger counts inside one of these windows is
//!                 pure dispatch tax.
//!   openclose N — N x `openat`+`close` of the same path. The `close` window
//!                 is where the record-lock `fstat` lives.
//!   getpid N    — N x `getpid`. This is the CONTROL, not the denominator:
//!                 carrick answers the identity syscalls in an EL1 shim
//!                 (`SyscallDispatcher::identity_fast_path_enabled`) without
//!                 entering dispatch at all, so it emits no `syscall-entry`
//!                 probe and the ledger shows no `guest=getpid` row. A run that
//!                 DOES show one means the fast path was disabled (a seccomp
//!                 filter or an observer demanding full visibility) and the
//!                 other modes' numbers are being read on a different lane.
//!   spin N      — N x 1000 iterations of arithmetic and NO syscall at all:
//!                 pure guest USER cpu. It is the control for the accounting
//!                 contract — guest execution must land in `utime`, never in
//!                 `stime`.
//!   noop N      — N iterations of no syscall at all, as the control that the
//!                 loop itself costs nothing.
//!
//! Every mode ends by printing the guest-visible CPU accounting —
//! `getrusage(RUSAGE_SELF)` utime/stime, `times()` tms_utime/tms_stime and
//! `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` — so the same run that measures the
//! tax also states what the fix must not break.
//!
//! BUILD (no Docker; matches the AGENTS.md libc-only probe recipe):
//!   rustc -O --edition 2021 --target aarch64-unknown-linux-musl \
//!         -C target-feature=+crt-static -C linker=rust-lld \
//!         -C link-self-contained=yes \
//!         -o /tmp/syscall-tax-reducer scripts/dtrace/syscall-tax-reducer.rs
//!
//! (`rust-lld` + `link-self-contained` because the system `cc` on macOS cannot
//! emit Linux ELF — the same recipe `conformance-probes/.cargo/config.toml`
//! uses for its cross targets.)
//!
//! RUN (bind-mount it; the guest image needs nothing of its own):
//!   carrick run --name $rid -v /tmp/syscall-tax-reducer:/reducer \
//!       ubuntu:24.04 /reducer ebadf 200000
//!
//! The syscalls are raw `svc #0` so no libc wrapper (and no libc caching of
//! `getpid`) sits between the loop and the guest kernel.

#![allow(clippy::missing_safety_doc)]

use std::arch::asm;

const SYS_OPENAT: u64 = 56;
const SYS_CLOSE: u64 = 57;
const SYS_GETPID: u64 = 172;
const SYS_WRITE: u64 = 64;
const SYS_CLOCK_GETTIME: u64 = 113;
const SYS_TIMES: u64 = 153;
const SYS_GETRUSAGE: u64 = 165;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
const RUSAGE_SELF: u64 = 0;
const AT_FDCWD: u64 = (-100i64) as u64;
const O_RDONLY: u64 = 0;

#[inline(never)]
unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 => ret,
            in("x1") a1,
            in("x2") a2,
            options(nostack)
        );
    }
    ret
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("ebadf");
    let iterations: u64 = args
        .get(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(200_000);

    // `openat` needs a path that certainly exists in any base image and that
    // carrick resolves the same way every iteration, so the open window's cost
    // is the steady-state one rather than a first-touch miss.
    let path = c"/etc/hostname";
    let mut accumulator: i64 = 0;

    match mode {
        // `close` of a descriptor no fd table can hold: dispatch runs, the fd
        // lookup misses, EBADF comes straight back. -1 rather than a large
        // number so it can never collide with a real descriptor.
        "ebadf" => {
            for _ in 0..iterations {
                accumulator = accumulator
                    .wrapping_add(unsafe { syscall3(SYS_CLOSE, (-1i64) as u64, 0, 0) });
            }
        }
        "getpid" => {
            for _ in 0..iterations {
                accumulator = accumulator.wrapping_add(unsafe { syscall3(SYS_GETPID, 0, 0, 0) });
            }
        }
        "openclose" => {
            for _ in 0..iterations {
                let fd = unsafe { syscall3(SYS_OPENAT, AT_FDCWD, path.as_ptr() as u64, O_RDONLY) };
                if fd < 0 {
                    accumulator = accumulator.wrapping_add(fd);
                    continue;
                }
                accumulator =
                    accumulator.wrapping_add(unsafe { syscall3(SYS_CLOSE, fd as u64, 0, 0) });
            }
        }
        "spin" => {
            let mut value: u64 = 1;
            for _ in 0..iterations {
                for _ in 0..1000u64 {
                    value = std::hint::black_box(value.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1));
                }
            }
            accumulator = accumulator.wrapping_add(value as i64);
        }
        "noop" => {
            for index in 0..iterations {
                accumulator = accumulator.wrapping_add(index as i64);
            }
        }
        other => {
            let message = format!("unknown mode {other}\n");
            unsafe {
                syscall3(SYS_WRITE, 2, message.as_ptr() as u64, message.len() as u64);
            }
            std::process::exit(2);
        }
    }

    // The accounting contract, read the way a guest reads it. Printed AFTER the
    // loop so the numbers describe the work the loop just did.
    //
    // `rusage` is two `timeval`s (utime, stime) of two `i64`s each; `tms` is
    // four `clock_t` (= i64 on aarch64 Linux) — utime, stime, cutime, cstime —
    // in USER_HZ ticks; `timespec` is two `i64`s.
    let mut rusage = [0i64; 4];
    let mut tms = [0i64; 4];
    let mut thread_cpu = [0i64; 2];
    unsafe {
        syscall3(SYS_GETRUSAGE, RUSAGE_SELF, rusage.as_mut_ptr() as u64, 0);
        syscall3(SYS_TIMES, tms.as_mut_ptr() as u64, 0, 0);
        syscall3(
            SYS_CLOCK_GETTIME,
            CLOCK_THREAD_CPUTIME_ID,
            thread_cpu.as_mut_ptr() as u64,
            0,
        );
    }
    let rusage_utime_us = rusage[0] * 1_000_000 + rusage[1];
    let rusage_stime_us = rusage[2] * 1_000_000 + rusage[3];
    let thread_cpu_us = thread_cpu[0] * 1_000_000 + thread_cpu[1] / 1000;

    // One report line, written with the same raw path so the summary itself
    // does not add a libc-shaped tail of syscalls to the ledger.
    let report = format!(
        "REDUCER mode={mode} iterations={iterations} acc={accumulator} \
rusage_utime_us={rusage_utime_us} rusage_stime_us={rusage_stime_us} \
times_utime_ticks={} times_stime_ticks={} thread_cputime_us={thread_cpu_us}\n",
        tms[0], tms[1]
    );
    unsafe {
        syscall3(SYS_WRITE, 1, report.as_ptr() as u64, report.len() as u64);
    }
}

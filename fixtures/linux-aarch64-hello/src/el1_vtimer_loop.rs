//! EL1 plan 1a: a loop of EL1-served syscalls after one forwarded marker.
//!
//! The signed test asks the host to arm the guest virtual timer on the vCPU
//! that resumes the marker (`getppid`, forwarded to the host); the EL1 IRQ
//! window of a later served `lseek` must take the timer with no host exit in
//! between. Prints `vtimer loop ok`.
//!
//! No runtime dependencies (the fixture build links no core).
#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::{AT_FDCWD, SYS_OPENAT, SYS_WRITE, exit, syscall0, syscall3, syscall4};

const SYS_LSEEK: u64 = 62;
const SYS_GETPPID: u64 = 173;
const O_RDWR_CREAT_TRUNC: u64 = 0o2 | 0o100 | 0o1000;
/// Served lseeks before the marker, so the file is in the EL1 zone.
const WARMUP: u64 = 1_000;
/// Served lseeks after it: far longer than the probe's timer delay.
const LOOP: u64 = 2_000_000;

static PATH: [u8; 21] = *b"/tmp/el1_vtimer_loop\0";
static OK: [u8; 15] = *b"vtimer loop ok\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // SAFETY: raw Linux syscalls on buffers this fixture owns.
    unsafe {
        let fd = syscall4(
            SYS_OPENAT,
            AT_FDCWD,
            PATH.as_ptr() as u64,
            O_RDWR_CREAT_TRUNC,
            0o600,
        );
        if fd < 0 {
            exit(10);
        }
        if syscall3(SYS_WRITE, fd as u64, OK.as_ptr() as u64, 1) != 1 {
            exit(11);
        }
        let mut i = 0;
        while i < WARMUP {
            if syscall3(SYS_LSEEK, fd as u64, 0, 0) != 0 {
                exit(12);
            }
            i += 1;
        }
        // The marker: forwarded to the host, which arms the timer on resume.
        let _ = syscall0(SYS_GETPPID);
        let mut i = 0;
        while i < LOOP {
            if syscall3(SYS_LSEEK, fd as u64, 0, 0) != 0 {
                exit(13);
            }
            i += 1;
        }
        if syscall3(SYS_WRITE, 1, OK.as_ptr() as u64, OK.len() as u64) != OK.len() as i64 {
            exit(14);
        }
        exit(0)
    }
}

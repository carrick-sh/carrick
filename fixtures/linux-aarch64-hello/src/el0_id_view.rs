//! EL0 view of `ID_AA64PFR0_EL1` (EL1 plan 1a). Linux emulates EL0 reads of
//! the ID registers and does not expose the GIC system-register field (bits
//! 27:24) to userspace, and a GIC-less Hypervisor.framework vCPU reports 0
//! there. Carrick's HVF carrier VM has the in-kernel GIC, whose vCPUs report
//! 1; the EL0 view must still read 0. Prints `id_aa64pfr0_gic=<hex digit>`.
//!
//! No runtime dependencies: the buffer is written through a raw pointer,
//! never indexed.
#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::{SYS_WRITE, exit, syscall3};
use core::arch::asm;

const HEX: &[u8; 16] = b"0123456789abcdef";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let pfr0: u64;
    // SAFETY: an EL0 MRS of an ID register, which Linux emulates for EL0.
    unsafe { asm!("mrs {}, id_aa64pfr0_el1", out(reg) pfr0, options(nomem, nostack)) };
    let mut line = *b"id_aa64pfr0_gic=?\n";
    // SAFETY: the field is 4 bits, so the digit index is below 16, and byte 16
    // lies inside the 18-byte line.
    unsafe {
        *line.as_mut_ptr().add(16) = HEX.as_ptr().add(((pfr0 >> 24) & 0xf) as usize).read();
    }
    // SAFETY: a write of a local buffer to stdout.
    let written = unsafe { syscall3(SYS_WRITE, 1, line.as_ptr() as u64, line.len() as u64) };
    exit(if written == line.len() as i64 { 0 } else { 1 })
}

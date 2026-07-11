//! AArch64 syscall register-preservation probe.
//!
//! Carrick's EL1 identity-syscall shim services getpid/getuid/getgid/geteuid/
//! getegid/gettid without a VM exit. Native Linux preserves the non-return GPRs
//! across `svc`; glibc's stackful clone child path can keep live state there
//! before calling getpid(). This probe makes that ABI property line-exact.

#[cfg(target_arch = "aarch64")]
fn main() {
    let observed = unsafe { observed_after_getpid() };
    println!("getpid_returned_positive={}", observed.pid > 0);
    println!(
        "getpid_preserved_x10={}",
        observed.x10_after == SENTINEL_X10
    );
    println!(
        "getpid_preserved_x12={}",
        observed.x12_after == SENTINEL_X12
    );
    println!(
        "getpid_preserved_x16={}",
        observed.x16_after == SENTINEL_X16
    );
    println!(
        "getpid_preserved_x18={}",
        observed.x18_after == SENTINEL_X18
    );
    println!(
        "getpid_preserved_nzcv={}",
        observed.nzcv_after == SENTINEL_NZCV
    );
    println!("getpid_preserved_d0={}", observed.d0_after == SENTINEL_D0);
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    println!("aarch64_syscall_reg_probe_skipped=true");
}

#[cfg(target_arch = "aarch64")]
const SENTINEL_X10: usize = 0x5678;
#[cfg(target_arch = "aarch64")]
const SENTINEL_X12: usize = 0x9abc;
#[cfg(target_arch = "aarch64")]
const SENTINEL_X16: usize = 0x1234;
#[cfg(target_arch = "aarch64")]
const SENTINEL_X18: usize = 0xdef0;
#[cfg(target_arch = "aarch64")]
const SENTINEL_NZCV: usize = 0x6000_0000;
#[cfg(target_arch = "aarch64")]
const SENTINEL_D0: usize = 0x2468;

#[cfg(target_arch = "aarch64")]
struct Observed {
    pid: usize,
    x10_after: usize,
    x12_after: usize,
    x16_after: usize,
    x18_after: usize,
    nzcv_after: usize,
    d0_after: usize,
}

#[cfg(target_arch = "aarch64")]
unsafe fn observed_after_getpid() -> Observed {
    let pid: usize;
    let x10_after: usize;
    let x12_after: usize;
    let x16_after: usize;
    let x18_after: usize;
    let nzcv_after: usize;
    let d0_after: usize;
    unsafe {
        core::arch::asm!(
            "mov x10, #0x5678",
            "mov x12, #0x9abc",
            "mov x16, #0x1234",
            "mov x18, #0xdef0",
            "mov x9, #0x2468",
            "fmov d0, x9",
            "cmp xzr, xzr",
            "svc #0",
            "mrs x11, nzcv",
            "fmov x9, d0",
            inout("x8") libc::SYS_getpid as usize => _,
            lateout("x0") pid,
            lateout("x9") d0_after,
            lateout("x10") x10_after,
            lateout("x11") nzcv_after,
            lateout("x12") x12_after,
            lateout("x16") x16_after,
            lateout("x18") x18_after,
            lateout("v0") _,
            options(nostack),
        );
    }
    Observed {
        pid,
        x10_after,
        x12_after,
        x16_after,
        x18_after,
        nzcv_after,
        d0_after,
    }
}

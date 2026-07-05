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
struct Observed {
    pid: usize,
    x10_after: usize,
    x12_after: usize,
    x16_after: usize,
}

#[cfg(target_arch = "aarch64")]
unsafe fn observed_after_getpid() -> Observed {
    let pid: usize;
    let x10_after: usize;
    let x12_after: usize;
    let x16_after: usize;
    unsafe {
        core::arch::asm!(
            "mov x10, #0x5678",
            "mov x12, #0x9abc",
            "mov x16, #0x1234",
            "svc #0",
            inout("x8") libc::SYS_getpid as usize => _,
            lateout("x0") pid,
            lateout("x10") x10_after,
            lateout("x12") x12_after,
            lateout("x16") x16_after,
            options(nostack),
        );
    }
    Observed {
        pid,
        x10_after,
        x12_after,
        x16_after,
    }
}

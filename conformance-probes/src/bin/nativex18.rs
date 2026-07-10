//! A native Darwin backend must preserve Linux's ordinary x18 register across
//! a guarded 4K-on-16K data access. macOS normally reserves and clears x18 on
//! kernel returns, so this catches a missing custom-x18 ABI boundary.

use conformance_probes::report;

#[cfg(target_arch = "aarch64")]
fn main() {
    const HOST_PAGE: usize = 16 * 1024;
    const LINUX_PAGE: usize = 4 * 1024;
    const SENTINEL: u64 = 0x1234_5678_9abc_def0;
    const VALUE: u64 = 0x0fed_cba9_8765_4321;
    let iterations = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| {
            std::env::var("CARRICK_TEST_ITERS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
        })
        .filter(|value| *value != 0)
        .unwrap_or(1024);

    unsafe {
        let raw = libc::mmap(
            core::ptr::null_mut(),
            2 * HOST_PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if raw == libc::MAP_FAILED {
            report!(setup_ok = false, guarded_load_ok = false, x18_preserved = false);
            return;
        }

        let aligned = ((raw as usize) + HOST_PAGE - 1) & !(HOST_PAGE - 1);
        let target = (aligned + LINUX_PAGE) as *mut u64;
        target.write_unaligned(VALUE);
        if libc::mprotect(aligned as *mut libc::c_void, LINUX_PAGE, libc::PROT_READ) != 0 {
            report!(setup_ok = false, guarded_load_ok = false, x18_preserved = false);
            libc::munmap(raw, 2 * HOST_PAGE);
            return;
        }

        let passed: u64;
        core::arch::asm!(
            "mov x18, {sentinel}",
            "mov x9, {iterations}",
            "2:",
            "ldr x10, [{target}]",
            "cmp x10, {expected}",
            "b.ne 3f",
            "cmp x18, {sentinel}",
            "b.ne 3f",
            "subs x9, x9, #1",
            "b.ne 2b",
            "mov {passed}, #1",
            "b 4f",
            "3:",
            "mov {passed}, #0",
            "4:",
            sentinel = in(reg) SENTINEL,
            target = in(reg) target,
            expected = in(reg) VALUE,
            iterations = in(reg) iterations,
            passed = lateout(reg) passed,
            out("x9") _,
            out("x10") _,
            out("x18") _,
            options(nostack),
        );

        report!(
            setup_ok = true,
            guarded_load_ok = passed != 0,
            x18_preserved = passed != 0,
            iterations = iterations,
        );
        libc::munmap(raw, 2 * HOST_PAGE);
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    report!(setup_ok = false, guarded_load_ok = false, x18_preserved = false);
}

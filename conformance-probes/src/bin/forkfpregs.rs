//! fork()/clone() must give the child (and preserve in the parent) the full
//! SIMD/FP register file (V0-V31, FPSR, FPCR). carrick's fork rebuilds a fresh
//! vCPU and restores only GPRs + system regs (VcpuSnapshot has no V-reg fields,
//! trap.rs:684/2020/2056), so vector state is zeroed across the clone — for BOTH
//! parent and child. Masked for ordinary libc fork() (AAPCS only callee-saves
//! V8-V15, handled by the wrapper), so we use a RAW clone svc with the V-set and
//! V-read in one asm block straddling the syscall, defeating that masking.
//!
//! Linux: child_v*_preserved and parent_v*_ok all true. carrick: V0/V20 read
//! back as 0 -> false. Deterministic booleans.

use conformance_probes::report;
use core::arch::asm;

fn main() {
    unsafe {
        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            report!(setup_ok = false);
            return;
        }
        let (r, w) = (fds[0], fds[1]);

        let parent_v0: u64;
        let parent_v20: u64;
        asm!(
            // Distinctive patterns: v0 lanes = 0xDEADBEEF, v20 lanes = 0x56781234.
            "movz x9, #0xBEEF",
            "movk x9, #0xDEAD, lsl #16",
            "dup v0.2d, x9",
            "movz x10, #0x1234",
            "movk x10, #0x5678, lsl #16",
            "dup v20.2d, x10",
            // raw clone(flags=SIGCHLD, child_stack=0, ...) == fork (COW stack).
            "mov x0, #17",
            "mov x1, #0",
            "mov x2, #0",
            "mov x3, #0",
            "mov x4, #0",
            "mov x8, #220",
            "svc #0",
            "cbnz x0, 20f",
            // ---- child ----
            "umov x9, v0.d[0]",
            "umov x10, v20.d[0]",
            "sub sp, sp, #16",
            "str x9, [sp]",
            "str x10, [sp, #8]",
            "mov w0, {wfd:w}",
            "mov x1, sp",
            "mov x2, #16",
            "mov x8, #64",     // write
            "svc #0",
            "mov x0, #0",
            "mov x8, #93",     // exit
            "svc #0",
            "10:",
            "b 10b",
            // ---- parent ----
            "20:",
            "umov {pv0}, v0.d[0]",
            "umov {pv20}, v20.d[0]",
            wfd = in(reg) w,
            pv0 = out(reg) parent_v0,
            pv20 = out(reg) parent_v20,
            out("x0") _, out("x1") _, out("x2") _, out("x3") _, out("x4") _,
            out("x8") _, out("x9") _, out("x10") _,
        );

        libc::close(w);
        let mut buf = [0u8; 16];
        let mut got = 0usize;
        while got < 16 {
            let n = libc::read(
                r,
                buf.as_mut_ptr().add(got) as *mut libc::c_void,
                16 - got,
            );
            if n <= 0 {
                break;
            }
            got += n as usize;
        }
        let child_v0 = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let child_v20 = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let mut st = 0;
        while libc::wait4(-1, &mut st, 0, core::ptr::null_mut()) < 0 {}

        let want_v0: u64 = 0xDEAD_BEEF;
        let want_v20: u64 = 0x5678_1234;
        report!(
            parent_v0_ok = parent_v0 == want_v0,
            parent_v20_ok = parent_v20 == want_v20,
            child_v0_preserved = child_v0 == want_v0,
            child_v20_preserved = child_v20 == want_v20,
        );
    }
}

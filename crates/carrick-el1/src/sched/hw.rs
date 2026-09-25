//! EL1's hardware side of the in-guest switch: the fixup-guarded user-word
//! load, the system-register moves and the audited FP/SIMD save/load
//! routines. The only inline assembly of the in-guest scheduler lives here
//! (EL1 guest code, not a host operation; the EL1 image checker audits its
//! instructions).

#[cfg(target_os = "none")]
use super::ThreadCpu;
use super::UserWord;
use carrick_el1_abi::CurrentTask;
#[cfg(target_os = "none")]
use carrick_el1_abi::{ThreadCtx, TrapFrame};

/// EL1's user-word reader: stage-1 permission check, then one fixup-guarded
/// unprivileged 32-bit load (single-copy atomic for an aligned word).
pub struct HardwareUserWord;

impl UserWord for HardwareUserWord {
    #[cfg(target_os = "none")]
    fn read_u32(&self, task: &CurrentTask, uaddr: u64) -> Option<u32> {
        use crate::file::MemoryValidator;
        if crate::file::HardwareValidator.readable_bytes(uaddr, 4) < 4 {
            return None;
        }
        let fixup_ptr = &task.fixup_pc as *const _ as *const u64;
        let mut ok: u64 = 1;
        let value: u64;
        // SAFETY: a fault on the user word is intercepted by the EL1 fixup,
        // which resumes at label 2.
        unsafe {
            core::arch::asm!(
                "adr {tmp}, 2f",
                "str {tmp}, [{fixup}]",
                "ldtr {val:w}, [{addr}]",
                "str xzr, [{fixup}]",
                "b 3f",
                "2:",
                "str xzr, [{fixup}]",
                "mov {ok}, #0",
                "mov {val}, #0",
                "3:",
                tmp = out(reg) _,
                fixup = in(reg) fixup_ptr,
                addr = in(reg) uaddr,
                val = out(reg) value,
                ok = inout(reg) ok,
                options(nostack)
            );
        }
        (ok != 0).then_some(value as u32)
    }

    #[cfg(not(target_os = "none"))]
    fn read_u32(&self, _task: &CurrentTask, uaddr: u64) -> Option<u32> {
        // Host builds (unit tests): the "user" word is host memory.
        // SAFETY: tests pass the address of a live, aligned u32.
        Some(unsafe { core::ptr::read_volatile(uaddr as *const u32) })
    }
}

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".arch armv8-a+fp+simd",
    ".global carrick_el1_fpsimd_save",
    ".type carrick_el1_fpsimd_save, %function",
    // x0: the 16-byte-aligned V0..V31 area, FPSR and FPCR follow it.
    "carrick_el1_fpsimd_save:",
    "stp q0, q1, [x0, #0]",
    "stp q2, q3, [x0, #32]",
    "stp q4, q5, [x0, #64]",
    "stp q6, q7, [x0, #96]",
    "stp q8, q9, [x0, #128]",
    "stp q10, q11, [x0, #160]",
    "stp q12, q13, [x0, #192]",
    "stp q14, q15, [x0, #224]",
    "stp q16, q17, [x0, #256]",
    "stp q18, q19, [x0, #288]",
    "stp q20, q21, [x0, #320]",
    "stp q22, q23, [x0, #352]",
    "stp q24, q25, [x0, #384]",
    "stp q26, q27, [x0, #416]",
    "stp q28, q29, [x0, #448]",
    "stp q30, q31, [x0, #480]",
    "mrs x1, fpsr",
    "mrs x2, fpcr",
    "str x1, [x0, #512]",
    "str x2, [x0, #520]",
    "ret",
    ".size carrick_el1_fpsimd_save, . - carrick_el1_fpsimd_save",
    ".global carrick_el1_fpsimd_load",
    ".type carrick_el1_fpsimd_load, %function",
    "carrick_el1_fpsimd_load:",
    "ldp q0, q1, [x0, #0]",
    "ldp q2, q3, [x0, #32]",
    "ldp q4, q5, [x0, #64]",
    "ldp q6, q7, [x0, #96]",
    "ldp q8, q9, [x0, #128]",
    "ldp q10, q11, [x0, #160]",
    "ldp q12, q13, [x0, #192]",
    "ldp q14, q15, [x0, #224]",
    "ldp q16, q17, [x0, #256]",
    "ldp q18, q19, [x0, #288]",
    "ldp q20, q21, [x0, #320]",
    "ldp q22, q23, [x0, #352]",
    "ldp q24, q25, [x0, #384]",
    "ldp q26, q27, [x0, #416]",
    "ldp q28, q29, [x0, #448]",
    "ldp q30, q31, [x0, #480]",
    "ldr x1, [x0, #512]",
    "ldr x2, [x0, #520]",
    "msr fpsr, x1",
    "msr fpcr, x2",
    "ret",
    ".size carrick_el1_fpsimd_load, . - carrick_el1_fpsimd_load",
);

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn carrick_el1_fpsimd_save(area: *mut u8);
    fn carrick_el1_fpsimd_load(area: *const u8);
}

// The routines above address FPSR/FPCR at V + 512.
const _: () = assert!(
    carrick_sched_core::THREAD_CTX_FPSR_OFFSET == carrick_sched_core::THREAD_CTX_V_OFFSET + 512
);

/// EL1's switch: system registers by `mrs`/`msr`, FP/SIMD by the audited
/// routines above (the only FP/SIMD instructions in the image).
#[cfg(target_os = "none")]
pub struct HardwareCpu;

#[cfg(target_os = "none")]
impl ThreadCpu for HardwareCpu {
    fn save(&mut self, frame: &TrapFrame, ctx: &mut ThreadCtx) {
        ctx.x = frame.x;
        ctx.pc = frame.elr;
        ctx.pstate = frame.spsr;
        // SAFETY: EL1 system-register reads of the interrupted EL0 thread.
        unsafe {
            core::arch::asm!(
                "mrs {a}, sp_el0",
                "mrs {b}, tpidr_el0",
                "mrs {c}, tpidrro_el0",
                "mrs {d}, contextidr_el1",
                a = out(reg) ctx.sp_el0,
                b = out(reg) ctx.tpidr_el0,
                c = out(reg) ctx.tpidrro_el0,
                d = out(reg) ctx.contextidr_el1,
                options(nostack, nomem)
            );
            let area =
                (ctx as *mut ThreadCtx as *mut u8).add(carrick_sched_core::THREAD_CTX_V_OFFSET);
            carrick_el1_fpsimd_save(area);
        }
    }

    fn load(&mut self, frame: &mut TrapFrame, ctx: &ThreadCtx) {
        frame.x = ctx.x;
        frame.elr = ctx.pc;
        frame.spsr = ctx.pstate;
        // SAFETY: EL1 loads the switched-in thread's EL0 state; the vector's
        // return path restores the frame and `eret`s into it.
        unsafe {
            core::arch::asm!(
                "msr sp_el0, {a}",
                "msr tpidr_el0, {b}",
                "msr tpidrro_el0, {c}",
                "msr contextidr_el1, {d}",
                "isb",
                a = in(reg) ctx.sp_el0,
                b = in(reg) ctx.tpidr_el0,
                c = in(reg) ctx.tpidrro_el0,
                d = in(reg) ctx.contextidr_el1,
                options(nostack, nomem)
            );
            let area =
                (ctx as *const ThreadCtx as *const u8).add(carrick_sched_core::THREAD_CTX_V_OFFSET);
            carrick_el1_fpsimd_load(area);
        }
    }

    fn now(&self) -> u64 {
        let value: u64;
        // SAFETY: reading the virtual counter.
        unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) value, options(nostack, nomem)) };
        value
    }
}

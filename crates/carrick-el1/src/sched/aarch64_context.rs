//! AArch64 frame/system-register and audited FP/SIMD context leaf.
//! No scheduling, lifecycle, task-allocation or memory-owner policy.
use carrick_el1_abi::{ThreadCtx, TrapFrame};

pub(crate) fn save_frame(frame: &TrapFrame, ctx: &mut ThreadCtx) {
    ctx.x = frame.x;
    ctx.pc = frame.elr;
    ctx.pstate = frame.spsr;
}
pub(crate) fn load_frame(frame: &mut TrapFrame, ctx: &ThreadCtx) {
    frame.x = ctx.x;
    frame.elr = ctx.pc;
    frame.spsr = ctx.pstate;
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
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

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
unsafe extern "C" {
    fn carrick_el1_fpsimd_save(area: *mut u8);
    fn carrick_el1_fpsimd_load(area: *const u8);
}

// The routines above address FPSR/FPCR at V + 512.
const _: () = assert!(
    carrick_sched_core::THREAD_CTX_FPSR_OFFSET == carrick_sched_core::THREAD_CTX_V_OFFSET + 512
);

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub(super) fn save(frame: &TrapFrame, ctx: &mut ThreadCtx) {
    save_frame(frame, ctx);
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
        let area = (ctx as *mut ThreadCtx as *mut u8).add(carrick_sched_core::THREAD_CTX_V_OFFSET);
        carrick_el1_fpsimd_save(area);
    }
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub(super) fn load(frame: &mut TrapFrame, ctx: &ThreadCtx) {
    load_frame(frame, ctx);
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

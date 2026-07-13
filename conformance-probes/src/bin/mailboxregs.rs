//! AArch64 ordinary-syscall register-preservation witness for the HVF mailbox.

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
    .text
    .p2align 2
    .global mailboxregs_observe
    .type mailboxregs_observe, %function
mailboxregs_observe:
    sub sp, sp, #512
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    str x0, [sp, #96]
    mov x9, sp
    str x9, [sp, #104]

    mov x1,  #0x1001
    mov x2,  #0x1002
    mov x3,  #0x1003
    mov x4,  #0x1004
    mov x5,  #0x1005
    mov x6,  #0x1006
    mov x7,  #0x1007
    mov x8,  #173
    mov x9,  #0x1009
    mov x10, #0x100a
    mov x11, #0x100b
    mov x12, #0x100c
    mov x13, #0x100d
    mov x14, #0x100e
    mov x15, #0x100f
    mov x16, #0x1010
    mov x17, #0x1011
    mov x18, #0x1012
    mov x19, #0x1013
    mov x20, #0x1014
    mov x21, #0x1015
    mov x22, #0x1016
    mov x23, #0x1017
    mov x24, #0x1018
    mov x25, #0x1019
    mov x26, #0x101a
    mov x27, #0x101b
    mov x28, #0x101c
    mov x29, #0x101d
    mov x30, #0x101e
    svc #0

    stp x0,  x1,  [sp, #128]
    stp x2,  x3,  [sp, #144]
    stp x4,  x5,  [sp, #160]
    stp x6,  x7,  [sp, #176]
    stp x8,  x9,  [sp, #192]
    stp x10, x11, [sp, #208]
    stp x12, x13, [sp, #224]
    stp x14, x15, [sp, #240]
    stp x16, x17, [sp, #256]
    stp x18, x19, [sp, #272]
    stp x20, x21, [sp, #288]
    stp x22, x23, [sp, #304]
    stp x24, x25, [sp, #320]
    stp x26, x27, [sp, #336]
    stp x28, x29, [sp, #352]
    str x30, [sp, #368]
    ldr x0, [sp, #104]
    str x0, [sp, #376]
    mov x0, sp
    str x0, [sp, #384]

    ldr x0, [sp, #96]
    add x1, sp, #128
    mov x2, #33
1:
    ldr x3, [x1], #8
    str x3, [x0], #8
    subs x2, x2, #1
    b.ne 1b

    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    add sp, sp, #512
    ret
    .size mailboxregs_observe, .-mailboxregs_observe
"#
);

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn mailboxregs_observe(observed: *mut u64);
}

#[cfg(target_arch = "aarch64")]
fn main() {
    let mut observed = [0_u64; 33];
    unsafe { mailboxregs_observe(observed.as_mut_ptr()) };

    let mut mismatch_mask = 0_u32;
    for register in 1..=30_usize {
        let expected = if register == 8 {
            libc::SYS_getppid as u64
        } else {
            0x1000 + register as u64
        };
        if observed[register] != expected {
            mismatch_mask |= 1_u32 << (register - 1);
        }
    }

    println!(
        "mailboxregs return_positive={} mismatch_mask={mismatch_mask:#010x} sp_preserved={}",
        observed[0] > 0,
        observed[31] == observed[32]
    );
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    println!("mailboxregs skipped_non_aarch64=true");
}

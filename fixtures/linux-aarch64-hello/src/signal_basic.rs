// Smallest possible rt_sigaction + raise(SIGINT) probe.
//
// 1. Install a SIGINT (signum 2) handler via rt_sigaction(2). The
//    sigaction's `sa_handler` is our `handler` symbol; `sa_restorer`
//    is our `restorer` symbol; `sa_flags` is SA_RESTORER (0x04000000)
//    so the kernel knows to honour the restorer rather than rejecting
//    the action with EINVAL on some configurations.
// 2. Call kill(1, 2) — Carrick runs as pid 1 in the bootstrap, so
//    this is equivalent to `raise(SIGINT)`. (We could getpid() but
//    the bootstrap pid is fixed.)
// 3. If the handler runs, it exits with code 42 (the "signal delivered"
//    sentinel). If it doesn't, control falls through to the final
//    exit_group(99) ("signal NOT delivered") path.
//
// The handler itself just calls exit_group(42); it never returns,
// so the restorer is never actually executed. We still wire one up
// for correctness because Carrick rejects handlers with sa_restorer
// == 0 (see `deliver_pending_signal` in src/runtime.rs).

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    // ----- Build a `struct kernel_sigaction` on the stack:
    //   offset 0  : sa_handler (8 bytes)
    //   offset 8  : sa_flags   (8 bytes)
    //   offset 16 : sa_restorer (8 bytes)
    //   offset 24 : sa_mask    (128 bytes, _NSIG / 8 = 128)
    // Total: 152 bytes — round up to 160 for 16-byte alignment.
    sub sp, sp, #160

    // sa_handler = handler
    adrp x0, handler
    add  x0, x0, :lo12:handler
    str  x0, [sp, #0]

    // sa_flags = SA_RESTORER = 0x04000000
    mov  x0, #0x04000000
    str  x0, [sp, #8]

    // sa_restorer = restorer
    adrp x0, restorer
    add  x0, x0, :lo12:restorer
    str  x0, [sp, #16]

    // Zero the 128-byte sa_mask.
    str  xzr, [sp, #24]
    str  xzr, [sp, #32]
    str  xzr, [sp, #40]
    str  xzr, [sp, #48]
    str  xzr, [sp, #56]
    str  xzr, [sp, #64]
    str  xzr, [sp, #72]
    str  xzr, [sp, #80]
    str  xzr, [sp, #88]
    str  xzr, [sp, #96]
    str  xzr, [sp, #104]
    str  xzr, [sp, #112]
    str  xzr, [sp, #120]
    str  xzr, [sp, #128]
    str  xzr, [sp, #136]
    str  xzr, [sp, #144]

    // rt_sigaction(SIGINT=2, &act, NULL, 8)
    mov  x0, #2          // signum
    mov  x1, sp          // new action
    mov  x2, #0          // old action
    mov  x3, #8          // sigset size (_NSIG / 8 on aarch64 = 8)
    mov  x8, #134        // SYS_rt_sigaction
    svc  #0

    // kill(1, 2)  — raise SIGINT on ourselves.
    mov  x0, #1          // bootstrap pid
    mov  x1, #2          // SIGINT
    mov  x8, #129        // SYS_kill
    svc  #0

    // If the handler hasn't run yet, give the runtime one more chance
    // to deliver: invoke a benign syscall (getpid) so the trap loop
    // drains the pending slot.
    mov  x8, #172        // SYS_getpid
    svc  #0

    // If we get here, the signal wasn't delivered. Exit 99.
    mov  x0, #99
    mov  x8, #94         // SYS_exit_group
    svc  #0

handler:
    // x0 contains the signum on entry. We don't use it. Just exit 42.
    mov  x0, #42
    mov  x8, #94         // SYS_exit_group
    svc  #0
    // Defensive: if exit_group ever returns, fall through to restorer.

restorer:
    // The kernel jumps here when the handler returns. Issue rt_sigreturn.
    mov  x8, #139        // SYS_rt_sigreturn
    svc  #0
    // rt_sigreturn doesn't return; if it ever does, exit with a marker.
    mov  x0, #77
    mov  x8, #94
    svc  #0
"#
);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

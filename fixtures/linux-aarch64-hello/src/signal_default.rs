// Default-action termination probe.
//
// Calls kill(1, SIGTERM=15) WITHOUT installing a handler. The runtime
// should observe the pending signal, find no handler registered, and
// terminate the process with exit code 128 + 15 = 143.

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    // kill(1, 15)  — raise SIGTERM on ourselves; no handler installed.
    mov  x0, #1
    mov  x1, #15
    mov  x8, #129        // SYS_kill
    svc  #0

    // Trigger one more syscall so the runtime's signal-check pass runs.
    mov  x8, #172        // SYS_getpid
    svc  #0

    // If we get here, the signal wasn't delivered. Exit 99.
    mov  x0, #99
    mov  x8, #94         // SYS_exit_group
    svc  #0
"#
);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

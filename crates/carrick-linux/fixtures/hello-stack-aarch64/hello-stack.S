// Freestanding aarch64 Linux fixture for the carrick-linux KVM backend that
// EXERCISES THE INITIAL STACK (Phase C / C1: full memory map + initial stack).
//
// Unlike hello.S (which never touches SP), this reads argc from [sp] and does
// a push/pop, so it only prints "ok" if:
//   * SP was programmed from the initial stack (with_linux_initial_stack), and
//   * the stack region near 1 TiB is actually backed by a KVM memory slot
//     (read AND write) — an unbacked stack faults to KVM_EXIT_MMIO instead.
//
// aarch64 Linux syscall ABI: number in x8, args x0..x5, `svc #0`, ret in x0.
// write = 64, exit_group = 94. argv[0]=path so argc == 1.
.text
.global _start
_start:
    ldr     x9, [sp]            // x9 = argc  (faults if SP/stack unbacked)
    cmp     x9, #1
    b.lt    fail                // argc < 1 -> initial stack not set up

    str     x9, [sp, #-16]!     // push argc (prove the stack is WRITABLE)
    ldr     x10, [sp], #16      // pop it back
    cmp     x9, x10
    b.ne    fail                // stack write/read mismatch

    mov     x0, #1              // fd = 1 (stdout)
    adr     x1, msg             // buf = &"ok\n"
    mov     x2, #3              // count = 3
    mov     x8, #64             // __NR_write
    svc     #0
    mov     x0, #0              // status = 0
    mov     x8, #94             // __NR_exit_group
    svc     #0
fail:
    mov     x0, #1              // status = 1
    mov     x8, #94             // __NR_exit_group
    svc     #0
msg:
    .ascii  "ok\n"

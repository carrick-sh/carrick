// Freestanding aarch64 Linux test fixture for the carrick-linux KVM MVP's
// fork(2) primitive (Phase 2, Task 2). No libc / no CRT startup so the thin
// shim (run_elf.rs) can drive it directly — it only services the raw syscalls
// clone/wait4/write/exit_group, which is exactly the fork primitive under test.
//
// Behaviour (mirrors the C fork/wait4 oracle):
//   pid = clone(SIGCHLD, child_stack=0)   // == fork()
//   if (pid == 0) exit_group(42)          // child
//   wait4(pid, &status, 0, 0)             // parent reaps the child
//   if (status != (42<<8)) exit_group(1)  // WIFEXITED && WEXITSTATUS==42
//   write(1, "fork-ok\n", 8)
//   exit_group(0)
//
// aarch64 Linux syscall ABI: number in x8, args x0..x5, trap via `svc #0`,
// return value in x0. clone = 220, wait4 = 260, write = 64, exit_group = 94.
// A normal child exit(42) yields wait status 0x2A00 (exit code in bits 8..15,
// no signal in the low 7 bits): WIFEXITED(status) && WEXITSTATUS(status)==42.
.text
.global _start
_start:
    // pid = clone(SIGCHLD, 0, 0, 0, 0)
    mov     x0, #17             // flags = SIGCHLD (a plain fork())
    mov     x1, #0              // child_stack = 0 (inherit/COW the parent's)
    mov     x2, #0              // ptid
    mov     x3, #0              // tls
    mov     x4, #0              // ctid
    mov     x8, #220            // __NR_clone
    svc     #0
    // x0 = 0 in the child, child pid (>0) in the parent.
    cbnz    x0, parent

child:
    mov     x0, #42             // status = 42
    mov     x8, #94             // __NR_exit_group
    svc     #0

parent:
    // Save the child pid in x10 across the wait4 svc (no stack available).
    mov     x10, x0             // x10 = child pid
    // wait4(pid, &status, 0, 0)
    mov     x0, x10             // pid
    adr     x1, status          // &status
    mov     x2, #0              // options
    mov     x3, #0              // rusage = NULL
    mov     x8, #260            // __NR_wait4
    svc     #0
    // Assert wait4 returned the child pid.
    cmp     x0, x10
    b.ne    fail
    // Load the 32-bit wait status and assert it == 42<<8 (0x2A00).
    adr     x9, status
    ldr     w0, [x9]
    mov     w1, #0x2A00         // 42 << 8
    cmp     w0, w1
    b.ne    fail
    // write(1, "fork-ok\n", 8)
    mov     x0, #1
    adr     x1, msg
    mov     x2, #8
    mov     x8, #64
    svc     #0
    // exit_group(0)
    mov     x0, #0
    mov     x8, #94
    svc     #0

fail:
    mov     x0, #1
    mov     x8, #94             // __NR_exit_group
    svc     #0

.data
msg:
    .ascii  "fork-ok\n"
.align 3
status:
    .word   0

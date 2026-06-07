// Freestanding aarch64 Linux test fixture for the carrick-linux KVM MVP's
// fork(2) + pipe2(2) primitive (Phase 2, Task 3). No libc / no CRT startup so
// the thin shim (run_elf.rs) can drive it directly — it only services the raw
// syscalls pipe2/clone/close/write/read/wait4/exit_group, which exercises the
// fork primitive + pipe fd inheritance across the fork boundary.
//
// Behaviour:
//   pipe2(fds, O_CLOEXEC)          // fds[0]=rfd, fds[1]=wfd
//   pid = clone(SIGCHLD, 0, ...)   // == fork()
//   PARENT:
//     close(fds[0])                // close read end
//     write(fds[1], "hi", 2)       // send 2 bytes to child
//     close(fds[1])                // close write end (EOF to child)
//     wait4(pid, &status, 0, 0)    // reap child
//     assert WIFEXITED && WEXITSTATUS==42
//     write(1, "pipe-ok\n", 8)     // signal success
//     exit_group(0)
//   CHILD:
//     close(fds[1])                // close write end
//     read(fds[0], buf, 2)         // receive bytes from parent
//     if read != 2 or buf != "hi": exit_group(1)
//     exit_group(42)               // signal OK to parent via exit code
//
// aarch64 Linux syscall ABI: number in x8, args x0..x5, trap via `svc #0`,
// return value in x0. Syscall numbers:
//   close=57, pipe2=59, read=63, write=64, clone=220, wait4=260, exit_group=94
// O_CLOEXEC = 0x80000 on aarch64/Linux.
// SIGCHLD = 17.
//
// The child exit(42) yields wait status 0x2A00 (exit code in bits 8..15, no
// signal in the low 7 bits): WIFEXITED(status) && WEXITSTATUS(status)==42.
.text
.global _start
_start:
    // pipe2(fds, O_CLOEXEC)
    adr     x0, fds             // x0 = &fds
    mov     x1, #0x80000        // O_CLOEXEC
    mov     x8, #59             // __NR_pipe2
    svc     #0
    cmp     x0, #0
    b.lt    fail

    // pid = clone(SIGCHLD, 0, 0, 0, 0)
    mov     x0, #17             // flags = SIGCHLD (plain fork())
    mov     x1, #0              // child_stack = 0 (COW inherit)
    mov     x2, #0              // ptid
    mov     x3, #0              // tls
    mov     x4, #0              // ctid
    mov     x8, #220            // __NR_clone
    svc     #0
    // x0 = 0 in the child, child pid (>0) in the parent.
    cbnz    x0, parent

child:
    // Close the write end (fds[1]).
    adr     x9, fds
    ldr     w0, [x9, #4]        // fds[1] = write fd
    mov     x8, #57             // __NR_close
    svc     #0

    // read(fds[0], buf, 2) — expect 2 bytes.
    adr     x9, fds
    ldr     w0, [x9, #0]        // fds[0] = read fd
    adr     x1, buf
    mov     x2, #2
    mov     x8, #63             // __NR_read
    svc     #0
    // Check we read exactly 2 bytes.
    cmp     x0, #2
    b.ne    child_fail

    // Check buf == "hi".
    adr     x9, buf
    ldrb    w0, [x9, #0]
    cmp     w0, #'h'
    b.ne    child_fail
    ldrb    w0, [x9, #1]
    cmp     w0, #'i'
    b.ne    child_fail

    // Success: exit(42).
    mov     x0, #42
    mov     x8, #94             // __NR_exit_group
    svc     #0

child_fail:
    mov     x0, #1
    mov     x8, #94             // __NR_exit_group
    svc     #0

parent:
    // Save the child pid in x10 across subsequent svcs.
    mov     x10, x0             // x10 = child pid

    // Close the read end (fds[0]).
    adr     x9, fds
    ldr     w0, [x9, #0]        // fds[0] = read fd
    mov     x8, #57             // __NR_close
    svc     #0

    // write(fds[1], "hi", 2).
    adr     x9, fds
    ldr     w0, [x9, #4]        // fds[1] = write fd
    adr     x1, msg_hi
    mov     x2, #2
    mov     x8, #64             // __NR_write
    svc     #0
    cmp     x0, #2
    b.ne    fail

    // Close the write end (fds[1]) so child gets EOF.
    adr     x9, fds
    ldr     w0, [x9, #4]        // fds[1] = write fd
    mov     x8, #57             // __NR_close
    svc     #0

    // wait4(pid, &status, 0, 0).
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

    // write(1, "pipe-ok\n", 8)
    mov     x0, #1
    adr     x1, msg_ok
    mov     x2, #8
    mov     x8, #64             // __NR_write
    svc     #0

    // exit_group(0)
    mov     x0, #0
    mov     x8, #94             // __NR_exit_group
    svc     #0

fail:
    mov     x0, #1
    mov     x8, #94             // __NR_exit_group
    svc     #0

.data
.align 2
fds:
    .word   0                   // fds[0] = read fd (filled by pipe2)
    .word   0                   // fds[1] = write fd (filled by pipe2)
msg_hi:
    .ascii  "hi"
msg_ok:
    .ascii  "pipe-ok\n"
buf:
    .space  2
.align 3
status:
    .word   0

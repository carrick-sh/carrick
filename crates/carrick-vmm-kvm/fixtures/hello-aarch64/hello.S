// Freestanding aarch64 Linux test fixture for the carrick-vmm-kvm MVP.
// No libc, no CRT startup: the entry point is _start and the program
// issues exactly two syscalls — write(1,"ok\n",3) then exit_group(0).
// aarch64 Linux syscall ABI: number in x8, args x0..x5, trap via `svc #0`,
// return value in x0.  write = 64, exit_group = 94.
.text
.global _start
_start:
    mov     x0, #1          // fd = 1 (stdout)
    adr     x1, msg         // buf = &"ok\n"
    mov     x2, #3          // count = 3
    mov     x8, #64         // __NR_write
    svc     #0
    mov     x0, #0          // status = 0
    mov     x8, #94         // __NR_exit_group
    svc     #0
msg:
    .ascii  "ok\n"

// Freestanding aarch64 Linux execve TARGET for the carrick-vmm-kvm
// execve_into primitive (Phase 2, Task 4). No libc / no CRT startup so the
// thin shim (run_elf.rs) can run it directly after `execve_into` replaces the
// guest image in place: it issues a single `exit_group(0)` and nothing else.
//
// Used by the `fork-execve-true` driver: the forked child `execve`s this image
// (replacing its address space), which then exits 0; the parent's `wait4`
// asserts WEXITSTATUS == 0.
//
// aarch64 Linux syscall ABI: number in x8, args x0..x5, trap via `svc #0`.
// exit_group = 94.
.text
.global _start
_start:
    mov     x0, #0              // status = 0
    mov     x8, #94             // __NR_exit_group
    svc     #0

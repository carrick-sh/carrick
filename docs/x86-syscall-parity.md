# Carrick AArch64 vs x86_64 Syscall Parity Census

This document provides an exhaustive, line-by-line census comparing Linux syscall support between the mature AArch64/HVF reference implementation and the x86_64 guest emulation engine in Carrick.

## Theory of Operation & Dispatch Architecture

Carrick implements Linux system calls without a guest Linux kernel. System calls are trapped by the hypervisor and dispatched to host-native primitives in Rust. Carrick's BKL-free `SyscallDispatcher` (`crates/carrick-kernel/src/dispatch/mod.rs`) is partitioned into narrow subsystem locks (`io`, `mem`, `proc`, `creds`, `signal`, `sysv`, etc.).

### Syscall Trapping & Registration
- **AArch64:** The guest issues `svc #0`, trapping at EL1. The trap handler (`crates/carrick-vmm-hvf/src/trap.rs`) extracts the syscall number from register `x8` and arguments from `x0..=x5`. These numbers match the standard Linux asm-generic numbering (`0..=462`) enumerated in `carrick_abi::syscall::AARCH64_SYSCALLS`.
- **x86_64:** The guest issues `SYSCALL`, trapping at privilege level 0. The trap handler in `crates/carrick-x86/src/engine.rs:1052` extracts the syscall number from `rax` and arguments from `rdi, rsi, rdx, r10, r8, r9`. Because x86_64 uses historical Linux syscall numbering dating back to Linux 2.6 and carries legacy non-`*at` interfaces, the x86 trap engine routes the raw frame through `normalize_syscall` before entering the dispatcher.

### Normalization Pipeline (`carrick_hal::x8664_arch::normalize_syscall`)
Located in [`crates/carrick-hal/src/x8664_arch.rs:1105`](../crates/carrick-hal/src/x8664_arch.rs), this pure ABI stage standardizes x86 frames into `SyscallNorm`:
1. **Architecture-Specific Operations:** `arch_prctl` (x86 #158) does not exist in asm-generic. It is intercepted at line 1108 and serviced directly via `service_arch_prctl` (`crates/carrick-hal/src/x8664_arch.rs:149`, called from `crates/carrick-x86/src/engine.rs:1061`) to manage the guest `FS_BASE` and `GS_BASE` segment registers for thread-local storage (TLS).
2. **Process Lifecycle Desugaring:** Legacy `fork` (x86 #57, line 1114) and `vfork` (x86 #58, line 1123) are rewritten into canonical `clone` (#220) with preset flag masks (`LINUX_SIGCHLD` and `LINUX_CLONE_VM | LINUX_CLONE_VFORK | LINUX_SIGCHLD` respectively).
3. **Clone Argument Normalization:** x86_64 raw `clone` (#56) passes `(flags, stack, ptid, ctid, tls)`. Asm-generic `clone` expects `(flags, stack, ptid, tls, ctid)`. `normalize_syscall` swaps arguments 3 and 4 at line 1565.
4. **x86 144-Byte Struct Stat Layout:** Linux x86_64 uses a 144-byte `struct stat` layout (`LinuxX8664Stat`) with distinct member offsets and padding compared to AArch64's 128-byte layout. x86 `stat` (#4), `fstat` (#5), `lstat` (#6), and `newfstatat` (#262) are mapped to private numbers `CARRICK_PRIVATE_X86_STAT/FSTAT/LSTAT/NEWFSTATAT` and serviced by dedicated x86 stat handlers in `crates/carrick-kernel/src/dispatch/fs/stat.rs:576-630`.
5. **Multiplexing & Time Divergence:**
   - x86 `poll` (#7) passes timeout as an integer millisecond scalar in arg2 with no sigmask. Direct remapping to `ppoll` would interpret timeout 0 as a NULL pointer (infinite block). Line 1139 maps it to `CARRICK_PRIVATE_X86_POLL`, serviced in `crates/carrick-kernel/src/dispatch/net.rs:3197`.
   - x86 `select` (#23) takes `struct timeval` (`tv_usec`) rather than `struct timespec` (`tv_nsec`). Line 1152 maps it to `CARRICK_PRIVATE_X86_SELECT`, serviced in `crates/carrick-kernel/src/dispatch/net.rs:2817`.
   - x86 `pause` (#34) maps to `ppoll(0, 0, 0, 0, 0, 0)` at line 1164, pausing until an unblocked signal is delivered.
   - x86 `alarm` (#37) and `time` (#201) are mapped to `CARRICK_PRIVATE_X86_ALARM` and `CARRICK_PRIVATE_X86_TIME`, serviced in `crates/carrick-kernel/src/dispatch/time.rs:489, 853`.
   - x86 `epoll_create` (#213) validates `size > 0` (returning `-EINVAL` if non-positive), mapped to `CARRICK_PRIVATE_X86_EPOLL_CREATE` in `crates/carrick-kernel/src/dispatch/net/epoll_ops.rs:3720`.
6. **Legacy Path Rewriting:** Calls taking bare paths (`open`, `access`, `mkdir`, `unlink`, `rmdir`, `rename`, `link`, `symlink`, `readlink`, `chmod`, `chown`, `lchown`, `mknod`) are rewritten with `AT_FDCWD` to their corresponding `*at` forms. Flag bit differences in `open`/`openat` (`O_DIRECT`, `O_LARGEFILE`, `O_DIRECTORY`, `O_NOFOLLOW`) and `pipe2` (`O_DIRECT`) are translated to their asm-generic constants.

### Static Translation Table (`carrick_abi::syscall_x86_64::X86_64_SYSCALLS`)
Any x86 syscall not intercepted by `normalize_syscall` is resolved through `X86_64_SYSCALLS` in [`crates/carrick-abi/src/syscall_x86_64.rs:104`](../crates/carrick-abi/src/syscall_x86_64.rs). Entries marked `SyscallRemap::Direct(c)` are routed to canonical number `c`. Unrecognized or deferred entries resolve to `SyscallRemap::Unknown` -> `CARRICK_PRIVATE_X86_UNSUPPORTED` (-ENOSYS).

## Census Counts

Top-level census comparing AArch64 and x86_64 Linux system call support in Carrick:

| Category | Count | Definition & Scope |
|---|---:|---|
| **Emulated on both** | **246** | Canonical syscalls with `SupportLevel::BringUp` on AArch64 that are reachable and actively serviced on x86_64 (244 via `Direct`, 2 via x86 stat handlers). Plus 2 `Planned` stubs (`execveat`, `clone3`) supported on both. |
| **AArch64-only (active emulation)** | **0** | Zero syscalls are emulated on AArch64 but missing on x86_64. 100% emulation parity across all implemented system calls. |
| **AArch64-only (ABI table presence)** | **20** | 20 `*_time64` syscalls (#403..414, 416..423 in `carrick_abi::syscall::AARCH64_SYSCALLS`) exist in asm-generic for 32-bit time migration; they do not exist in the 64-bit x86_64 Linux ABI and are `Deferred` in Carrick. |
| **x86-only (actively emulated)** | **32** | 32 x86 syscalls with no asm-generic counterpart are emulated: 1 architecture-native (`arch_prctl`), 8 with dedicated x86 handlers (`stat`, `lstat`, `poll`, `select`, `dup2`, `alarm`, `time`, `epoll_create`), and 23 normalized into canonical `*at`/`2` forms. |
| **x86-only (deferred / unsupported)** | **25** | 4 deferred legacy shims (`getdents`, `utime`, `utimes`, `futimesat`) returning -ENOSYS pending argument conversion, plus 21 obsolete/unsupported Linux x86 syscalls (`uselib`, `iopl`, `modify_ldt`, etc.) returning honest -ENOSYS. |
| **x86-only (total Linux ABI)** | **57** | Total Linux system calls present in the x86_64 ABI that have no direct asm-generic number (32 emulated + 25 deferred/unsupported). |
| **Missing on x86 but emulated on AArch64** | **0** | Exactly 0. Parity is complete for every emulated system call. |

---

## Canonical Syscalls Parity Table (AArch64 0..=462)

This table enumerates every canonical system call defined in `carrick_abi::syscall::AARCH64_SYSCALLS` (338 entries total). Syscall numbers absent from the sequence (`244..=259`, `295..=402`, and `415`) are unassigned in Linux asm-generic/AArch64.

| AArch64 Nr | x86_64 Nr | Syscall | AArch64 Support Level | x86_64 Reachability | Evidence / Implementation Notes |
|---|---|---|---|---|---|
| 0 | 206 | `io_setup` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:528`: `direct(206, "io_setup", 0)` |
| 1 | 207 | `io_destroy` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:530`: `direct(207, "io_destroy", 1)` |
| 2 | 209 | `io_submit` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:534`: `direct(209, "io_submit", 2)` |
| 3 | 210 | `io_cancel` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:536`: `direct(210, "io_cancel", 3)` |
| 4 | 208 | `io_getevents` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:532`: `direct(208, "io_getevents", 4)` |
| 5 | 188 | `setxattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:490`: `direct(188, "setxattr", 5)` |
| 6 | 189 | `lsetxattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:492`: `direct(189, "lsetxattr", 6)` |
| 7 | 190 | `fsetxattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:494`: `direct(190, "fsetxattr", 7)` |
| 8 | 191 | `getxattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:496`: `direct(191, "getxattr", 8)` |
| 9 | 192 | `lgetxattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:498`: `direct(192, "lgetxattr", 9)` |
| 10 | 193 | `fgetxattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:500`: `direct(193, "fgetxattr", 10)` |
| 11 | 194 | `listxattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:502`: `direct(194, "listxattr", 11)` |
| 12 | 195 | `llistxattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:504`: `direct(195, "llistxattr", 12)` |
| 13 | 196 | `flistxattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:506`: `direct(196, "flistxattr", 13)` |
| 14 | 197 | `removexattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:508`: `direct(197, "removexattr", 14)` |
| 15 | 198 | `lremovexattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:510`: `direct(198, "lremovexattr", 15)` |
| 16 | 199 | `fremovexattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:512`: `direct(199, "fremovexattr", 16)` |
| 17 | 79 | `getcwd` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:293`: `direct(79, "getcwd", 17)` |
| 18 | 212 | `lookup_dcookie` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:539`: `direct(212, "lookup_dcookie", 18)` |
| 19 | 290 | `eventfd2` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:697`: Mapped via `direct(290, "eventfd2", 19)`. Also legacy `eventfd` (#284) normalizes to canonical 19 at `crates/carrick-hal/src/x8664_arch.rs:1230`. |
| 20 | 291 | `epoll_create1` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:699`: `direct(291, "epoll_create1", 20)` |
| 21 | 233 | `epoll_ctl` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:581`: `direct(233, "epoll_ctl", 21)` |
| 22 | 281 | `epoll_pwait` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:679`: Mapped via `direct(281, "epoll_pwait", 22)`. Also legacy `epoll_wait` (#232) normalizes to canonical 22 at `crates/carrick-hal/src/x8664_arch.rs:1181`. |
| 23 | 32 | `dup` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:179`: `direct(32, "dup", 23)` |
| 24 | 292 | `dup3` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:701`: `direct(292, "dup3", 24)` |
| 25 | 72 | `fcntl` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:278`: `direct(72, "fcntl", 25)` |
| 26 | 294 | `inotify_init1` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:705`: Mapped via `direct(294, "inotify_init1", 26)`. Also legacy `inotify_init` (#253) normalizes to canonical 26 at `crates/carrick-hal/src/x8664_arch.rs:1210`. |
| 27 | 254 | `inotify_add_watch` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:622`: `direct(254, "inotify_add_watch", 27)` |
| 28 | 255 | `inotify_rm_watch` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:624`: `direct(255, "inotify_rm_watch", 28)` |
| 29 | 16 | `ioctl` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:147`: `direct(16, "ioctl", 29)` |
| 30 | 251 | `ioprio_set` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:616`: `direct(251, "ioprio_set", 30)` |
| 31 | 252 | `ioprio_get` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:618`: `direct(252, "ioprio_get", 31)` |
| 32 | 73 | `flock` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:280`: `direct(73, "flock", 32)` |
| 33 | 259 | `mknodat` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:632`: Mapped via `direct(259, "mknodat", 33)`. Also legacy `mknod` (#133) normalizes to canonical 33 at `crates/carrick-hal/src/x8664_arch.rs:1504`. |
| 34 | 258 | `mkdirat` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:630`: Mapped via `direct(258, "mkdirat", 34)`. Also legacy `mkdir` (#83) normalizes to canonical 34 at `crates/carrick-hal/src/x8664_arch.rs:1362`. |
| 35 | 263 | `unlinkat` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:642`: Mapped via `direct(263, "unlinkat", 35)`. Also legacy `unlink` (#87) and `rmdir` (#84) normalize to canonical 35 at `crates/carrick-hal/src/x8664_arch.rs:1433/1442`. |
| 36 | 266 | `symlinkat` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:648`: Mapped via `direct(266, "symlinkat", 36)`. Also legacy `symlink` (#88) normalizes to canonical 36 at `crates/carrick-hal/src/x8664_arch.rs:1493`. |
| 37 | 265 | `linkat` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:646`: Mapped via `direct(265, "linkat", 37)`. Also legacy `link` (#86) normalizes to canonical 37 at `crates/carrick-hal/src/x8664_arch.rs:1475`. |
| 38 | 264 | `renameat` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:644`: Mapped via `direct(264, "renameat", 38)`. Also legacy `rename` (#82) normalizes to canonical 38 at `crates/carrick-hal/src/x8664_arch.rs:1459`. |
| 39 | 166 | `umount2` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:460`: `direct(166, "umount2", 39)` |
| 40 | 165 | `mount` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:458`: `direct(165, "mount", 40)` |
| 41 | 155 | `pivot_root` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:437`: `direct(155, "pivot_root", 41)` |
| 42 | 180 | `nfsservctl` | `Deferred` | missing on x86 (obsolete, unmapped / -ENOSYS) | `crates/carrick-abi/src/syscall_x86_64.rs:892`: obsolete on x86_64; omitted from table -> -ENOSYS |
| 43 | 137 | `statfs` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:402`: `direct(137, "statfs", 43)` |
| 44 | 138 | `fstatfs` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:404`: `direct(138, "fstatfs", 44)` |
| 45 | 76 | `truncate` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:286`: `direct(76, "truncate", 45)` |
| 46 | 77 | `ftruncate` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:288`: `direct(77, "ftruncate", 46)` |
| 47 | 285 | `fallocate` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:687`: `direct(285, "fallocate", 47)` |
| 48 | 269 | `faccessat` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:654`: Mapped via `direct(269, "faccessat", 48)`. Also legacy `access` (#21) normalizes to canonical 48 at `crates/carrick-hal/src/x8664_arch.rs:1279`. |
| 49 | 80 | `chdir` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:295`: `direct(80, "chdir", 49)` |
| 50 | 81 | `fchdir` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:297`: `direct(81, "fchdir", 50)` |
| 51 | 161 | `chroot` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:450`: `direct(161, "chroot", 51)` |
| 52 | 91 | `fchmod` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:312`: `direct(91, "fchmod", 52)` |
| 53 | 268 | `fchmodat` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:652`: Mapped via `direct(268, "fchmodat", 53)`. Also legacy `chmod` (#90) normalizes to canonical 53 at `crates/carrick-hal/src/x8664_arch.rs:1514`. |
| 54 | 260 | `fchownat` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:634`: Mapped via `direct(260, "fchownat", 54)`. Also legacy `chown` (#92) and `lchown` (#94) normalize to canonical 54 at `crates/carrick-hal/src/x8664_arch.rs:1524/1534`. |
| 55 | 93 | `fchown` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:315`: `direct(93, "fchown", 55)` |
| 56 | 257 | `openat` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:628`: Normalized in `carrick_hal::x8664_arch::normalize_syscall` (`crates/carrick-hal/src/x8664_arch.rs:1393`) with x86 O_* flag translation. Also legacy `open` (#2) and `creat` (#85) rewrite to canonical 56. |
| 57 | 3 | `close` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:113`: `direct(3, "close", 57)` |
| 58 | 153 | `vhangup` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:433`: `direct(153, "vhangup", 58)` |
| 59 | 293 | `pipe2` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:703`: Normalized in `carrick_hal::x8664_arch::normalize_syscall` (`crates/carrick-hal/src/x8664_arch.rs:1333`) with `O_DIRECT` bit translation (0x4000 -> 0x10000). Also legacy `pipe` (#22) rewrites to canonical 59. |
| 60 | 179 | `quotactl` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:481`: `direct(179, "quotactl", 60)` |
| 61 | 217 | `getdents64` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:546`: `direct(217, "getdents64", 61)` |
| 62 | 8 | `lseek` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:129`: `direct(8, "lseek", 62)` |
| 63 | 0 | `read` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:106`: `direct(0, "read", 63)` |
| 64 | 1 | `write` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:108`: `direct(1, "write", 64)` |
| 65 | 19 | `readv` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:153`: `direct(19, "readv", 65)` |
| 66 | 20 | `writev` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:155`: `direct(20, "writev", 66)` |
| 67 | 17 | `pread64` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:149`: `direct(17, "pread64", 67)` |
| 68 | 18 | `pwrite64` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:151`: `direct(18, "pwrite64", 68)` |
| 69 | 295 | `preadv` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:707`: `direct(295, "preadv", 69)` |
| 70 | 296 | `pwritev` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:709`: `direct(296, "pwritev", 70)` |
| 71 | 40 | `sendfile` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:197`: `direct(40, "sendfile", 71)` |
| 72 | 270 | `pselect6` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:656`: `direct(270, "pselect6", 72)` |
| 73 | 271 | `ppoll` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:658`: Mapped via `direct(271, "ppoll", 73)`. Also legacy `pause` (#34) normalizes to canonical 73 at `crates/carrick-hal/src/x8664_arch.rs:1164`. Note that x86 `poll` (#7) is intercepted to `CARRICK_PRIVATE_X86_POLL` at line 1139. |
| 74 | 289 | `signalfd4` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:695`: Mapped via `direct(289, "signalfd4", 74)`. Also legacy `signalfd` (#282) normalizes to canonical 74 at `crates/carrick-hal/src/x8664_arch.rs:1220`. |
| 75 | 278 | `vmsplice` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:673`: `direct(278, "vmsplice", 75)` |
| 76 | 275 | `splice` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:667`: `direct(275, "splice", 76)` |
| 77 | 276 | `tee` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:669`: `direct(276, "tee", 77)` |
| 78 | 267 | `readlinkat` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:650`: Mapped via `direct(267, "readlinkat", 78)`. Also legacy `readlink` (#89) normalizes to canonical 78 at `crates/carrick-hal/src/x8664_arch.rs:1353`. |
| 79 | 262 | `newfstatat` | `BringUp` | x86-specific handler (`x86_newfstatat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1315` -> `CARRICK_PRIVATE_X86_NEWFSTATAT`; Handler: `crates/carrick-kernel/src/dispatch/fs/stat.rs:618` (writes 144-byte `LinuxX8664Stat`), routed at `crates/carrick-kernel/src/dispatch/fs.rs:104` |
| 80 | 5 | `fstat` | `BringUp` | x86-specific handler (`x86_fstat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1297` -> `CARRICK_PRIVATE_X86_FSTAT`; Handler: `crates/carrick-kernel/src/dispatch/fs/stat.rs:589` (writes 144-byte `LinuxX8664Stat`), routed at `crates/carrick-kernel/src/dispatch/fs.rs:102` |
| 81 | 162 | `sync` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:452`: `direct(162, "sync", 81)` |
| 82 | 74 | `fsync` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:282`: `direct(74, "fsync", 82)` |
| 83 | 75 | `fdatasync` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:284`: `direct(75, "fdatasync", 83)` |
| 84 | 277 | `sync_file_range` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:671`: `direct(277, "sync_file_range", 84)` |
| 85 | 283 | `timerfd_create` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:683`: `direct(283, "timerfd_create", 85)` |
| 86 | 286 | `timerfd_settime` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:689`: `direct(286, "timerfd_settime", 86)` |
| 87 | 287 | `timerfd_gettime` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:691`: `direct(287, "timerfd_gettime", 87)` |
| 88 | 280 | `utimensat` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:677`: `direct(280, "utimensat", 88)` |
| 89 | 163 | `acct` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:454`: `direct(163, "acct", 89)` |
| 90 | 125 | `capget` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:380`: `direct(125, "capget", 90)` |
| 91 | 126 | `capset` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:382`: `direct(126, "capset", 91)` |
| 92 | 135 | `personality` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:399`: `direct(135, "personality", 92)` |
| 93 | 60 | `exit` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:249`: `direct(60, "exit", 93)` |
| 94 | 231 | `exit_group` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:574`: `direct(231, "exit_group", 94)` |
| 95 | 247 | `waitid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:608`: `direct(247, "waitid", 95)` |
| 96 | 218 | `set_tid_address` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:548`: `direct(218, "set_tid_address", 96)` |
| 97 | 272 | `unshare` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:660`: `direct(272, "unshare", 97)` |
| 98 | 202 | `futex` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:520`: `direct(202, "futex", 98)` |
| 99 | 273 | `set_robust_list` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:663`: `direct(273, "set_robust_list", 99)` |
| 100 | 274 | `get_robust_list` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:665`: `direct(274, "get_robust_list", 100)` |
| 101 | 35 | `nanosleep` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:187`: `direct(35, "nanosleep", 101)` |
| 102 | 36 | `getitimer` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:189`: `direct(36, "getitimer", 102)` |
| 103 | 38 | `setitimer` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:193`: `direct(38, "setitimer", 103)` |
| 104 | 246 | `kexec_load` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:606`: `direct(246, "kexec_load", 104)` |
| 105 | 175 | `init_module` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:475`: `direct(175, "init_module", 105)` |
| 106 | 176 | `delete_module` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:477`: `direct(176, "delete_module", 106)` |
| 107 | 222 | `timer_create` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:556`: `direct(222, "timer_create", 107)` |
| 108 | 224 | `timer_gettime` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:560`: `direct(224, "timer_gettime", 108)` |
| 109 | 225 | `timer_getoverrun` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:562`: `direct(225, "timer_getoverrun", 109)` |
| 110 | 223 | `timer_settime` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:558`: `direct(223, "timer_settime", 110)` |
| 111 | 226 | `timer_delete` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:564`: `direct(226, "timer_delete", 111)` |
| 112 | 227 | `clock_settime` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:566`: `direct(227, "clock_settime", 112)` |
| 113 | 228 | `clock_gettime` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:568`: `direct(228, "clock_gettime", 113)` |
| 114 | 229 | `clock_getres` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:570`: `direct(229, "clock_getres", 114)` |
| 115 | 230 | `clock_nanosleep` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:572`: `direct(230, "clock_nanosleep", 115)` |
| 116 | 103 | `syslog` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:335`: `direct(103, "syslog", 116)` |
| 117 | 101 | `ptrace` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:331`: `direct(101, "ptrace", 117)` |
| 118 | 142 | `sched_setparam` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:411`: `direct(142, "sched_setparam", 118)` |
| 119 | 144 | `sched_setscheduler` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:415`: `direct(144, "sched_setscheduler", 119)` |
| 120 | 145 | `sched_getscheduler` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:417`: `direct(145, "sched_getscheduler", 120)` |
| 121 | 143 | `sched_getparam` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:413`: `direct(143, "sched_getparam", 121)` |
| 122 | 203 | `sched_setaffinity` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:522`: `direct(203, "sched_setaffinity", 122)` |
| 123 | 204 | `sched_getaffinity` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:524`: `direct(204, "sched_getaffinity", 123)` |
| 124 | 24 | `sched_yield` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:163`: `direct(24, "sched_yield", 124)` |
| 125 | 146 | `sched_get_priority_max` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:419`: `direct(146, "sched_get_priority_max", 125)` |
| 126 | 147 | `sched_get_priority_min` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:421`: `direct(147, "sched_get_priority_min", 126)` |
| 127 | 148 | `sched_rr_get_interval` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:423`: `direct(148, "sched_rr_get_interval", 127)` |
| 128 | 219 | `restart_syscall` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:550`: `direct(219, "restart_syscall", 128)` |
| 129 | 62 | `kill` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:254`: `direct(62, "kill", 129)` |
| 130 | 200 | `tkill` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:515`: `direct(200, "tkill", 130)` |
| 131 | 234 | `tgkill` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:583`: `direct(234, "tgkill", 131)` |
| 132 | 131 | `sigaltstack` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:393`: `direct(131, "sigaltstack", 132)` |
| 133 | 130 | `rt_sigsuspend` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:390`: `direct(130, "rt_sigsuspend", 133)` |
| 134 | 13 | `rt_sigaction` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:139`: `direct(13, "rt_sigaction", 134)` |
| 135 | 14 | `rt_sigprocmask` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:141`: `direct(14, "rt_sigprocmask", 135)` |
| 136 | 127 | `rt_sigpending` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:384`: `direct(127, "rt_sigpending", 136)` |
| 137 | 128 | `rt_sigtimedwait` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:386`: `direct(128, "rt_sigtimedwait", 137)` |
| 138 | 129 | `rt_sigqueueinfo` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:388`: `direct(129, "rt_sigqueueinfo", 138)` |
| 139 | 15 | `rt_sigreturn` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:145`: `direct(15, "rt_sigreturn", 139)` |
| 140 | 141 | `setpriority` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:409`: `direct(141, "setpriority", 140)` |
| 141 | 140 | `getpriority` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:407`: `direct(140, "getpriority", 141)` |
| 142 | 169 | `reboot` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:466`: `direct(169, "reboot", 142)` |
| 143 | 114 | `setregid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:358`: `direct(114, "setregid", 143)` |
| 144 | 106 | `setgid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:341`: `direct(106, "setgid", 144)` |
| 145 | 113 | `setreuid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:356`: `direct(113, "setreuid", 145)` |
| 146 | 105 | `setuid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:339`: `direct(105, "setuid", 146)` |
| 147 | 117 | `setresuid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:364`: `direct(117, "setresuid", 147)` |
| 148 | 118 | `getresuid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:366`: `direct(118, "getresuid", 148)` |
| 149 | 119 | `setresgid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:368`: `direct(119, "setresgid", 149)` |
| 150 | 120 | `getresgid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:370`: `direct(120, "getresgid", 150)` |
| 151 | 122 | `setfsuid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:374`: `direct(122, "setfsuid", 151)` |
| 152 | 123 | `setfsgid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:376`: `direct(123, "setfsgid", 152)` |
| 153 | 100 | `times` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:329`: `direct(100, "times", 153)` |
| 154 | 109 | `setpgid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:347`: `direct(109, "setpgid", 154)` |
| 155 | 121 | `getpgid` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:372`: Mapped via `direct(121, "getpgid", 155)`. Also legacy `getpgrp` (#111) normalizes to canonical 155 at `crates/carrick-hal/src/x8664_arch.rs:1240`. |
| 156 | 124 | `getsid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:378`: `direct(124, "getsid", 156)` |
| 157 | 112 | `setsid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:354`: `direct(112, "setsid", 157)` |
| 158 | 115 | `getgroups` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:360`: `direct(115, "getgroups", 158)` |
| 159 | 116 | `setgroups` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:362`: `direct(116, "setgroups", 159)` |
| 160 | 63 | `uname` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:260`: `direct(63, "uname", 160)` |
| 161 | 170 | `sethostname` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:468`: `direct(170, "sethostname", 161)` |
| 162 | 171 | `setdomainname` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:470`: `direct(171, "setdomainname", 162)` |
| 163 | 97 | `getrlimit` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:323`: `direct(97, "getrlimit", 163)` |
| 164 | 160 | `setrlimit` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:448`: `direct(160, "setrlimit", 164)` |
| 165 | 98 | `getrusage` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:325`: `direct(98, "getrusage", 165)` |
| 166 | 95 | `umask` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:319`: `direct(95, "umask", 166)` |
| 167 | 157 | `prctl` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:440`: `direct(157, "prctl", 167)` |
| 168 | 309 | `getcpu` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:735`: `direct(309, "getcpu", 168)` |
| 169 | 96 | `gettimeofday` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:321`: `direct(96, "gettimeofday", 169)` |
| 170 | 164 | `settimeofday` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:456`: `direct(164, "settimeofday", 170)` |
| 171 | 159 | `adjtimex` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:446`: `direct(159, "adjtimex", 171)` |
| 172 | 39 | `getpid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:195`: `direct(39, "getpid", 172)` |
| 173 | 110 | `getppid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:349`: `direct(110, "getppid", 173)` |
| 174 | 102 | `getuid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:333`: `direct(102, "getuid", 174)` |
| 175 | 107 | `geteuid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:343`: `direct(107, "geteuid", 175)` |
| 176 | 104 | `getgid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:337`: `direct(104, "getgid", 176)` |
| 177 | 108 | `getegid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:345`: `direct(108, "getegid", 177)` |
| 178 | 186 | `gettid` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:486`: `direct(186, "gettid", 178)` |
| 179 | 99 | `sysinfo` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:327`: `direct(99, "sysinfo", 179)` |
| 180 | 240 | `mq_open` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:594`: `direct(240, "mq_open", 180)` |
| 181 | 241 | `mq_unlink` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:596`: `direct(241, "mq_unlink", 181)` |
| 182 | 242 | `mq_timedsend` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:598`: `direct(242, "mq_timedsend", 182)` |
| 183 | 243 | `mq_timedreceive` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:600`: `direct(243, "mq_timedreceive", 183)` |
| 184 | 244 | `mq_notify` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:602`: `direct(244, "mq_notify", 184)` |
| 185 | 245 | `mq_getsetattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:604`: `direct(245, "mq_getsetattr", 185)` |
| 186 | 68 | `msgget` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:270`: `direct(68, "msgget", 186)` |
| 187 | 71 | `msgctl` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:276`: `direct(71, "msgctl", 187)` |
| 188 | 70 | `msgrcv` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:274`: `direct(70, "msgrcv", 188)` |
| 189 | 69 | `msgsnd` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:272`: `direct(69, "msgsnd", 189)` |
| 190 | 64 | `semget` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:262`: `direct(64, "semget", 190)` |
| 191 | 66 | `semctl` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:266`: `direct(66, "semctl", 191)` |
| 192 | 220 | `semtimedop` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:552`: `direct(220, "semtimedop", 192)` |
| 193 | 65 | `semop` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:264`: `direct(65, "semop", 193)` |
| 194 | 29 | `shmget` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:173`: `direct(29, "shmget", 194)` |
| 195 | 31 | `shmctl` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:177`: `direct(31, "shmctl", 195)` |
| 196 | 30 | `shmat` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:175`: `direct(30, "shmat", 196)` |
| 197 | 67 | `shmdt` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:268`: `direct(67, "shmdt", 197)` |
| 198 | 41 | `socket` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:199`: `direct(41, "socket", 198)` |
| 199 | 53 | `socketpair` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:223`: `direct(53, "socketpair", 199)` |
| 200 | 49 | `bind` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:215`: `direct(49, "bind", 200)` |
| 201 | 50 | `listen` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:217`: `direct(50, "listen", 201)` |
| 202 | 43 | `accept` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:203`: `direct(43, "accept", 202)` |
| 203 | 42 | `connect` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:201`: `direct(42, "connect", 203)` |
| 204 | 51 | `getsockname` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:219`: `direct(51, "getsockname", 204)` |
| 205 | 52 | `getpeername` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:221`: `direct(52, "getpeername", 205)` |
| 206 | 44 | `sendto` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:205`: `direct(44, "sendto", 206)` |
| 207 | 45 | `recvfrom` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:207`: `direct(45, "recvfrom", 207)` |
| 208 | 54 | `setsockopt` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:225`: `direct(54, "setsockopt", 208)` |
| 209 | 55 | `getsockopt` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:227`: `direct(55, "getsockopt", 209)` |
| 210 | 48 | `shutdown` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:213`: `direct(48, "shutdown", 210)` |
| 211 | 46 | `sendmsg` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:209`: `direct(46, "sendmsg", 211)` |
| 212 | 47 | `recvmsg` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:211`: `direct(47, "recvmsg", 212)` |
| 213 | 187 | `readahead` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:488`: `direct(187, "readahead", 213)` |
| 214 | 12 | `brk` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:137`: `direct(12, "brk", 214)` |
| 215 | 11 | `munmap` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:135`: `direct(11, "munmap", 215)` |
| 216 | 25 | `mremap` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:165`: `direct(25, "mremap", 216)` |
| 217 | 248 | `add_key` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:610`: `direct(248, "add_key", 217)` |
| 218 | 249 | `request_key` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:612`: `direct(249, "request_key", 218)` |
| 219 | 250 | `keyctl` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:614`: `direct(250, "keyctl", 219)` |
| 220 | 56 | `clone` | `BringUp` | routed to shared dispatcher (via normalize shim) | `crates/carrick-abi/src/syscall_x86_64.rs:235`: Normalized in `carrick_hal::x8664_arch::normalize_syscall` (`crates/carrick-hal/src/x8664_arch.rs:1565`) with args[3]<->args[4] (tls vs child_tid) swap. Also legacy `fork` (#57) and `vfork` (#58) rewrite to canonical 220. |
| 221 | 59 | `execve` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:247`: `direct(59, "execve", 221)` |
| 222 | 9 | `mmap` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:131`: `direct(9, "mmap", 222)` |
| 223 | 221 | `fadvise64` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:554`: `direct(221, "fadvise64", 223)` |
| 224 | 167 | `swapon` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:462`: `direct(167, "swapon", 224)` |
| 225 | 168 | `swapoff` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:464`: `direct(168, "swapoff", 225)` |
| 226 | 10 | `mprotect` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:133`: `direct(10, "mprotect", 226)` |
| 227 | 26 | `msync` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:167`: `direct(26, "msync", 227)` |
| 228 | 149 | `mlock` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:425`: `direct(149, "mlock", 228)` |
| 229 | 150 | `munlock` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:427`: `direct(150, "munlock", 229)` |
| 230 | 151 | `mlockall` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:429`: `direct(151, "mlockall", 230)` |
| 231 | 152 | `munlockall` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:431`: `direct(152, "munlockall", 231)` |
| 232 | 27 | `mincore` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:169`: `direct(27, "mincore", 232)` |
| 233 | 28 | `madvise` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:171`: `direct(28, "madvise", 233)` |
| 234 | 216 | `remap_file_pages` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:544`: `direct(216, "remap_file_pages", 234)` |
| 235 | 237 | `mbind` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:588`: `direct(237, "mbind", 235)` |
| 236 | 239 | `get_mempolicy` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:592`: `direct(239, "get_mempolicy", 236)` |
| 237 | 238 | `set_mempolicy` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:590`: `direct(238, "set_mempolicy", 237)` |
| 238 | 256 | `migrate_pages` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:626`: `direct(256, "migrate_pages", 238)` |
| 239 | 279 | `move_pages` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:675`: `direct(279, "move_pages", 239)` |
| 240 | 297 | `rt_tgsigqueueinfo` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:711`: `direct(297, "rt_tgsigqueueinfo", 240)` |
| 241 | 298 | `perf_event_open` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:713`: `direct(298, "perf_event_open", 241)` |
| 242 | 288 | `accept4` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:693`: `direct(288, "accept4", 242)` |
| 243 | 299 | `recvmmsg` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:715`: `direct(299, "recvmmsg", 243)` |
| 260 | 61 | `wait4` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:252`: `direct(61, "wait4", 260)` |
| 261 | 302 | `prlimit64` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:721`: `direct(302, "prlimit64", 261)` |
| 262 | 300 | `fanotify_init` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:717`: `direct(300, "fanotify_init", 262)` |
| 263 | 301 | `fanotify_mark` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:719`: `direct(301, "fanotify_mark", 263)` |
| 264 | 303 | `name_to_handle_at` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:723`: `direct(303, "name_to_handle_at", 264)` |
| 265 | 304 | `open_by_handle_at` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:725`: `direct(304, "open_by_handle_at", 265)` |
| 266 | 305 | `clock_adjtime` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:727`: `direct(305, "clock_adjtime", 266)` |
| 267 | 306 | `syncfs` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:729`: `direct(306, "syncfs", 267)` |
| 268 | 308 | `setns` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:733`: `direct(308, "setns", 268)` |
| 269 | 307 | `sendmmsg` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:731`: `direct(307, "sendmmsg", 269)` |
| 270 | 310 | `process_vm_readv` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:737`: `direct(310, "process_vm_readv", 270)` |
| 271 | 311 | `process_vm_writev` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:739`: `direct(311, "process_vm_writev", 271)` |
| 272 | 312 | `kcmp` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:741`: `direct(312, "kcmp", 272)` |
| 273 | 313 | `finit_module` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:743`: `direct(313, "finit_module", 273)` |
| 274 | 314 | `sched_setattr` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:745`: `direct(314, "sched_setattr", 274)` |
| 275 | 315 | `sched_getattr` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:747`: `direct(315, "sched_getattr", 275)` |
| 276 | 316 | `renameat2` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:749`: `direct(316, "renameat2", 276)` |
| 277 | 317 | `seccomp` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:751`: `direct(317, "seccomp", 277)` |
| 278 | 318 | `getrandom` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:753`: `direct(318, "getrandom", 278)` |
| 279 | 319 | `memfd_create` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:755`: `direct(319, "memfd_create", 279)` |
| 280 | 321 | `bpf` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:759`: `direct(321, "bpf", 280)` |
| 281 | 322 | `execveat` | `Planned` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:761`: `direct(322, "execveat", 281)` |
| 282 | 323 | `userfaultfd` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:763`: `direct(323, "userfaultfd", 282)` |
| 283 | 324 | `membarrier` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:765`: `direct(324, "membarrier", 283)` |
| 284 | 325 | `mlock2` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:767`: `direct(325, "mlock2", 284)` |
| 285 | 326 | `copy_file_range` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:769`: `direct(326, "copy_file_range", 285)` |
| 286 | 327 | `preadv2` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:771`: `direct(327, "preadv2", 286)` |
| 287 | 328 | `pwritev2` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:773`: `direct(328, "pwritev2", 287)` |
| 288 | 329 | `pkey_mprotect` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:775`: `direct(329, "pkey_mprotect", 288)` |
| 289 | 330 | `pkey_alloc` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:777`: `direct(330, "pkey_alloc", 289)` |
| 290 | 331 | `pkey_free` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:779`: `direct(331, "pkey_free", 290)` |
| 291 | 332 | `statx` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:781`: `direct(332, "statx", 291)` |
| 292 | 333 | `io_pgetevents` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:783`: `direct(333, "io_pgetevents", 292)` |
| 293 | 334 | `rseq` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:785`: `direct(334, "rseq", 293)` |
| 294 | 320 | `kexec_file_load` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:757`: `direct(320, "kexec_file_load", 294)` |
| 403 | — | `clock_gettime64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 404 | — | `clock_settime64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 405 | — | `clock_adjtime64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 406 | — | `clock_getres_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 407 | — | `clock_nanosleep_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 408 | — | `timer_gettime64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 409 | — | `timer_settime64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 410 | — | `timerfd_gettime64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 411 | — | `timerfd_settime64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 412 | — | `utimensat_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 413 | — | `pselect6_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 414 | — | `ppoll_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 416 | — | `io_pgetevents_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 417 | — | `recvmmsg_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 418 | — | `mq_timedsend_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 419 | — | `mq_timedreceive_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 420 | — | `semtimedop_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 421 | — | `rt_sigtimedwait_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 422 | — | `futex_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 423 | — | `sched_rr_get_interval_time64` | `Deferred` | missing on x86 (time64 variant absent from 64-bit x86_64 ABI) | asm-generic 32-bit-on-64-bit migration syscall; absent from x86_64 Linux kernel table; Deferred in Carrick |
| 424 | 424 | `pidfd_send_signal` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:787`: `direct(424, "pidfd_send_signal", 424)` |
| 425 | 425 | `io_uring_setup` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:789`: `direct(425, "io_uring_setup", 425)` |
| 426 | 426 | `io_uring_enter` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:791`: `direct(426, "io_uring_enter", 426)` |
| 427 | 427 | `io_uring_register` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:793`: `direct(427, "io_uring_register", 427)` |
| 428 | 428 | `open_tree` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:795`: `direct(428, "open_tree", 428)` |
| 429 | 429 | `move_mount` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:797`: `direct(429, "move_mount", 429)` |
| 430 | 430 | `fsopen` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:799`: `direct(430, "fsopen", 430)` |
| 431 | 431 | `fsconfig` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:801`: `direct(431, "fsconfig", 431)` |
| 432 | 432 | `fsmount` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:803`: `direct(432, "fsmount", 432)` |
| 433 | 433 | `fspick` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:805`: `direct(433, "fspick", 433)` |
| 434 | 434 | `pidfd_open` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:807`: `direct(434, "pidfd_open", 434)` |
| 435 | 435 | `clone3` | `Planned` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:810`: `direct(435, "clone3", 435)` |
| 436 | 436 | `close_range` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:812`: `direct(436, "close_range", 436)` |
| 437 | 437 | `openat2` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:814`: `direct(437, "openat2", 437)` |
| 438 | 438 | `pidfd_getfd` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:816`: `direct(438, "pidfd_getfd", 438)` |
| 439 | 439 | `faccessat2` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:818`: `direct(439, "faccessat2", 439)` |
| 440 | 440 | `process_madvise` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:820`: `direct(440, "process_madvise", 440)` |
| 441 | 441 | `epoll_pwait2` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:822`: `direct(441, "epoll_pwait2", 441)` |
| 442 | 442 | `mount_setattr` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:824`: `direct(442, "mount_setattr", 442)` |
| 443 | 443 | `quotactl_fd` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:826`: `direct(443, "quotactl_fd", 443)` |
| 444 | 444 | `landlock_create_ruleset` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:828`: `direct(444, "landlock_create_ruleset", 444)` |
| 445 | 445 | `landlock_add_rule` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:830`: `direct(445, "landlock_add_rule", 445)` |
| 446 | 446 | `landlock_restrict_self` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:832`: `direct(446, "landlock_restrict_self", 446)` |
| 447 | 447 | `memfd_secret` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:834`: `direct(447, "memfd_secret", 447)` |
| 448 | 448 | `process_mrelease` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:836`: `direct(448, "process_mrelease", 448)` |
| 449 | 449 | `futex_waitv` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:838`: `direct(449, "futex_waitv", 449)` |
| 450 | 450 | `set_mempolicy_home_node` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:840`: `direct(450, "set_mempolicy_home_node", 450)` |
| 451 | 451 | `cachestat` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:842`: `direct(451, "cachestat", 451)` |
| 452 | 452 | `fchmodat2` | `BringUp` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:844`: `direct(452, "fchmodat2", 452)` |
| 453 | 453 | `map_shadow_stack` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:846`: `direct(453, "map_shadow_stack", 453)` |
| 454 | 454 | `futex_wake` | `Deferred` | routed to shared dispatcher | `crates/carrick-abi/src/syscall_x86_64.rs:848`: `direct(454, "futex_wake", 454)` |
| 455 | 455 | `futex_wait` | `Deferred` | missing / unmapped on x86 (-ENOSYS in Carrick) | Newer Linux syscall (futex_wait); absent from `X86_64_SYSCALLS` -> -ENOSYS; Deferred in Carrick |
| 456 | 456 | `futex_requeue` | `Deferred` | missing / unmapped on x86 (-ENOSYS in Carrick) | Newer Linux syscall (futex_requeue); absent from `X86_64_SYSCALLS` -> -ENOSYS; Deferred in Carrick |
| 457 | 457 | `statmount` | `Deferred` | missing / unmapped on x86 (-ENOSYS in Carrick) | Newer Linux syscall (statmount); absent from `X86_64_SYSCALLS` -> -ENOSYS; Deferred in Carrick |
| 458 | 458 | `listmount` | `Deferred` | missing / unmapped on x86 (-ENOSYS in Carrick) | Newer Linux syscall (listmount); absent from `X86_64_SYSCALLS` -> -ENOSYS; Deferred in Carrick |
| 459 | 459 | `lsm_get_self_attr` | `Deferred` | missing / unmapped on x86 (-ENOSYS in Carrick) | Newer Linux syscall (lsm_get_self_attr); absent from `X86_64_SYSCALLS` -> -ENOSYS; Deferred in Carrick |
| 460 | 460 | `lsm_set_self_attr` | `Deferred` | missing / unmapped on x86 (-ENOSYS in Carrick) | Newer Linux syscall (lsm_set_self_attr); absent from `X86_64_SYSCALLS` -> -ENOSYS; Deferred in Carrick |
| 461 | 461 | `lsm_list_modules` | `Deferred` | missing / unmapped on x86 (-ENOSYS in Carrick) | Newer Linux syscall (lsm_list_modules); absent from `X86_64_SYSCALLS` -> -ENOSYS; Deferred in Carrick |
| 462 | 462 | `mseal` | `Deferred` | missing / unmapped on x86 (-ENOSYS in Carrick) | Newer Linux syscall (mseal); absent from `X86_64_SYSCALLS` -> -ENOSYS; Deferred in Carrick |

---

## x86_64 Architecture-Specific & Legacy Syscalls Table

This table enumerates all 57 system calls present in Linux x86_64 that do not have an identical asm-generic number, classifying each into an x86-specific handler, a normalized `*at`/`2` mapping, a deferred legacy shim, or an honest -ENOSYS.

| AArch64 Nr | x86_64 Nr | Syscall | AArch64 Support Level | x86_64 Reachability | Evidence / Implementation Notes |
|---|---|---|---|---|---|
| — | 2 | `open` | — | x86-only syscall: normalized to *at/2 form (`openat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1376` -> canonical `openat` (#56) with `AT_FDCWD` + x86 O_* flag bit translation |
| — | 4 | `stat` | — | x86-only syscall: x86-specific handler (`x86_stat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1288` -> `CARRICK_PRIVATE_X86_STAT`; Handler: `crates/carrick-kernel/src/dispatch/fs/stat.rs:576` (writes 144-byte `LinuxX8664Stat`), routed at `crates/carrick-kernel/src/dispatch/fs.rs:101` |
| — | 6 | `lstat` | — | x86-only syscall: x86-specific handler (`x86_lstat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1306` -> `CARRICK_PRIVATE_X86_LSTAT`; Handler: `crates/carrick-kernel/src/dispatch/fs/stat.rs:600` (writes 144-byte `LinuxX8664Stat` with AT_SYMLINK_NOFOLLOW), routed at `crates/carrick-kernel/src/dispatch/fs.rs:103` |
| — | 7 | `poll` | — | x86-only syscall: x86-specific handler (`ppoll` poll-mode) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1139` -> `CARRICK_PRIVATE_X86_POLL`; Handler: `crates/carrick-kernel/src/dispatch/net.rs:3197` (treats arg2 as int timeout_ms, no sigmask), routed at `crates/carrick-kernel/src/dispatch/net.rs:119` |
| — | 21 | `access` | — | x86-only syscall: normalized to *at/2 form (`faccessat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1279` -> canonical `faccessat` (#48) with `AT_FDCWD` and `flags=0` |
| — | 22 | `pipe` | — | x86-only syscall: normalized to *at/2 form (`pipe2`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1324` -> canonical `pipe2` (#59) with `flags=0` |
| — | 23 | `select` | — | x86-only syscall: x86-specific handler (`pselect6` select-mode) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1152` -> `CARRICK_PRIVATE_X86_SELECT`; Handler: `crates/carrick-kernel/src/dispatch/net.rs:2817` (reads arg4 as `struct timeval*`, no sigmask), routed at `crates/carrick-kernel/src/dispatch/net.rs:122` |
| — | 33 | `dup2` | — | x86-only syscall: x86-specific handler (`dup2`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1252` -> `CARRICK_PRIVATE_X86_DUP2`; Handler: `crates/carrick-kernel/src/dispatch/fs/close_dup.rs:259` (no-op success on oldfd==newfd), routed at `crates/carrick-kernel/src/dispatch/fs.rs:100` |
| — | 34 | `pause` | — | x86-only syscall: normalized to *at/2 form (`ppoll`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1164` -> canonical `ppoll` (#73) with zeroed arguments (infinite interruptible signal wait) |
| — | 37 | `alarm` | — | x86-only syscall: x86-specific handler (`x86_alarm`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1261` -> `CARRICK_PRIVATE_X86_ALARM`; Handler: `crates/carrick-kernel/src/dispatch/time.rs:489`, routed at `crates/carrick-kernel/src/dispatch/time.rs:76` |
| — | 57 | `fork` | — | x86-only syscall: normalized to *at/2 form (`clone`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1114` -> canonical `clone` (#220) with `LINUX_SIGCHLD` |
| — | 58 | `vfork` | — | x86-only syscall: normalized to *at/2 form (`clone`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1123` -> canonical `clone` (#220) with `CLONE_VM | CLONE_VFORK | LINUX_SIGCHLD` |
| — | 78 | `getdents` | — | x86-only syscall: missing / deferred legacy shim | Documented in `crates/carrick-abi/src/syscall_x86_64.rs:860`; requires 32-bit `linux_dirent` -> 64-bit `linux_dirent64` conversion; unmapped -> -ENOSYS |
| — | 82 | `rename` | — | x86-only syscall: normalized to *at/2 form (`renameat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1459` -> canonical `renameat` (#38) with `AT_FDCWD` for old and new dirfds |
| — | 83 | `mkdir` | — | x86-only syscall: normalized to *at/2 form (`mkdirat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1362` -> canonical `mkdirat` (#34) with `AT_FDCWD` |
| — | 84 | `rmdir` | — | x86-only syscall: normalized to *at/2 form (`unlinkat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1442` -> canonical `unlinkat` (#35) with `AT_FDCWD` and `AT_REMOVEDIR` |
| — | 85 | `creat` | — | x86-only syscall: normalized to *at/2 form (`openat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1411` -> canonical `openat` (#56) with `AT_FDCWD` and `O_CREAT|O_WRONLY|O_TRUNC` |
| — | 86 | `link` | — | x86-only syscall: normalized to *at/2 form (`linkat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1475` -> canonical `linkat` (#37) with `AT_FDCWD` for old and new dirfds, `flags=0` |
| — | 87 | `unlink` | — | x86-only syscall: normalized to *at/2 form (`unlinkat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1433` -> canonical `unlinkat` (#35) with `AT_FDCWD` and `flags=0` |
| — | 88 | `symlink` | — | x86-only syscall: normalized to *at/2 form (`symlinkat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1493` -> canonical `symlinkat` (#36) with target, `AT_FDCWD`, and linkpath |
| — | 89 | `readlink` | — | x86-only syscall: normalized to *at/2 form (`readlinkat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1353` -> canonical `readlinkat` (#78) with `AT_FDCWD` |
| — | 90 | `chmod` | — | x86-only syscall: normalized to *at/2 form (`fchmodat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1514` -> canonical `fchmodat` (#53) with `AT_FDCWD` and `flags=0` |
| — | 92 | `chown` | — | x86-only syscall: normalized to *at/2 form (`fchownat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1524` -> canonical `fchownat` (#54) with `AT_FDCWD` and `flags=0` |
| — | 94 | `lchown` | — | x86-only syscall: normalized to *at/2 form (`fchownat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1534` -> canonical `fchownat` (#54) with `AT_FDCWD` and `flags=AT_SYMLINK_NOFOLLOW` |
| — | 111 | `getpgrp` | — | x86-only syscall: normalized to *at/2 form (`getpgid`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1240` -> canonical `getpgid` (#155) with `pid=0` |
| — | 132 | `utime` | — | x86-only syscall: missing / deferred legacy shim | Documented in `crates/carrick-abi/src/syscall_x86_64.rs:871`; requires `struct utimbuf` -> `struct timespec[2]` conversion to `utimensat`; unmapped -> -ENOSYS |
| — | 133 | `mknod` | — | x86-only syscall: normalized to *at/2 form (`mknodat`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1504` -> canonical `mknodat` (#33) with `AT_FDCWD` |
| — | 134 | `uselib` | — | x86-only syscall: missing / honest -ENOSYS | Obsolete shared-library syscall; cited in `crates/carrick-abi/src/syscall_x86_64.rs:890`; omitted from table -> -ENOSYS |
| — | 136 | `ustat` | — | x86-only syscall: missing / honest -ENOSYS | Obsolete filesystem stats; cited in `crates/carrick-abi/src/syscall_x86_64.rs:890`; omitted from table -> -ENOSYS |
| — | 139 | `sysfs` | — | x86-only syscall: missing / honest -ENOSYS | Obsolete system call; cited in `crates/carrick-abi/src/syscall_x86_64.rs:891`; omitted from table -> -ENOSYS |
| — | 154 | `modify_ldt` | — | x86-only syscall: missing / honest -ENOSYS | x86-specific LDT table management; cited in `crates/carrick-abi/src/syscall_x86_64.rs:891`; omitted from table -> -ENOSYS |
| — | 156 | `_sysctl` | — | x86-only syscall: missing / honest -ENOSYS | Deprecated binary sysctl; cited in `crates/carrick-abi/src/syscall_x86_64.rs:891`; omitted from table -> -ENOSYS |
| — | 158 | `arch_prctl` | — | x86-only syscall: x86-specific handler (`service_arch_prctl`) | Intercepted at `crates/carrick-hal/src/x8664_arch.rs:1108` -> `SyscallNorm::ArchPrctl`; Handler: `crates/carrick-hal/src/x8664_arch.rs:149`, called from `crates/carrick-x86/src/engine.rs:1061` |
| — | 172 | `iopl` | — | x86-only syscall: missing / honest -ENOSYS | x86 I/O privilege level; cited in `crates/carrick-abi/src/syscall_x86_64.rs:891`; omitted from table -> -ENOSYS |
| — | 173 | `ioperm` | — | x86-only syscall: missing / honest -ENOSYS | x86 I/O port permissions; cited in `crates/carrick-abi/src/syscall_x86_64.rs:891`; omitted from table -> -ENOSYS |
| — | 174 | `create_module` | — | x86-only syscall: missing / honest -ENOSYS | Obsolete Linux kernel module call; cited in `crates/carrick-abi/src/syscall_x86_64.rs:892`; omitted from table -> -ENOSYS |
| — | 177 | `get_kernel_syms` | — | x86-only syscall: missing / honest -ENOSYS | Obsolete Linux kernel module call; cited in `crates/carrick-abi/src/syscall_x86_64.rs:892`; omitted from table -> -ENOSYS |
| — | 178 | `query_module` | — | x86-only syscall: missing / honest -ENOSYS | Obsolete Linux kernel module call; cited in `crates/carrick-abi/src/syscall_x86_64.rs:892`; omitted from table -> -ENOSYS |
| — | 180 | `nfsservctl` | — | x86-only syscall: missing / honest -ENOSYS | Obsolete NFS daemon control; cited in `crates/carrick-abi/src/syscall_x86_64.rs:892`; omitted from table -> -ENOSYS |
| — | 181 | `getpmsg` | — | x86-only syscall: missing / honest -ENOSYS | Reserved/unimplemented in upstream Linux; cited in `crates/carrick-abi/src/syscall_x86_64.rs:892`; omitted from table -> -ENOSYS |
| — | 182 | `putpmsg` | — | x86-only syscall: missing / honest -ENOSYS | Reserved/unimplemented in upstream Linux; cited in `crates/carrick-abi/src/syscall_x86_64.rs:892`; omitted from table -> -ENOSYS |
| — | 183 | `afs_syscall` | — | x86-only syscall: missing / honest -ENOSYS | Reserved for AFS; cited in `crates/carrick-abi/src/syscall_x86_64.rs:893`; omitted from table -> -ENOSYS |
| — | 184 | `tuxcall` | — | x86-only syscall: missing / honest -ENOSYS | Reserved for TUX web server; cited in `crates/carrick-abi/src/syscall_x86_64.rs:893`; omitted from table -> -ENOSYS |
| — | 185 | `security` | — | x86-only syscall: missing / honest -ENOSYS | Reserved for security modules; cited in `crates/carrick-abi/src/syscall_x86_64.rs:893`; omitted from table -> -ENOSYS |
| — | 201 | `time` | — | x86-only syscall: x86-specific handler (`x86_time`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1270` -> `CARRICK_PRIVATE_X86_TIME`; Handler: `crates/carrick-kernel/src/dispatch/time.rs:853`, routed at `crates/carrick-kernel/src/dispatch/time.rs:77` |
| — | 205 | `set_thread_area` | — | x86-only syscall: missing / honest -ENOSYS | x86 segment register TLS; superseded by `arch_prctl`; cited in `crates/carrick-abi/src/syscall_x86_64.rs:894`; omitted from table -> -ENOSYS |
| — | 211 | `get_thread_area` | — | x86-only syscall: missing / honest -ENOSYS | x86 segment register TLS; cited in `crates/carrick-abi/src/syscall_x86_64.rs:894`; omitted from table -> -ENOSYS |
| — | 213 | `epoll_create` | — | x86-only syscall: x86-specific handler (`x86_epoll_create`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1196` -> `CARRICK_PRIVATE_X86_EPOLL_CREATE`; Handler: `crates/carrick-kernel/src/dispatch/net/epoll_ops.rs:3720` (enforces `size > 0`), routed at `crates/carrick-kernel/src/dispatch/net.rs:113` |
| — | 214 | `epoll_ctl_old` | — | x86-only syscall: missing / honest -ENOSYS | Obsolete Linux 2.5 epoll variant; cited in `crates/carrick-abi/src/syscall_x86_64.rs:894`; omitted from table -> -ENOSYS |
| — | 215 | `epoll_wait_old` | — | x86-only syscall: missing / honest -ENOSYS | Obsolete Linux 2.5 epoll variant; cited in `crates/carrick-abi/src/syscall_x86_64.rs:895`; omitted from table -> -ENOSYS |
| — | 232 | `epoll_wait` | — | x86-only syscall: normalized to *at/2 form (`epoll_pwait`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1181` -> canonical `epoll_pwait` (#22) with trailing `sigmask=0, sigsetsize=0` |
| — | 235 | `utimes` | — | x86-only syscall: missing / deferred legacy shim | Documented in `crates/carrick-abi/src/syscall_x86_64.rs:875`; requires `struct timeval[2]` -> `struct timespec[2]` conversion to `utimensat`; unmapped -> -ENOSYS |
| — | 236 | `vserver` | — | x86-only syscall: missing / honest -ENOSYS | Non-upstream Linux vserver extension; cited in `crates/carrick-abi/src/syscall_x86_64.rs:895`; omitted from table -> -ENOSYS |
| — | 253 | `inotify_init` | — | x86-only syscall: normalized to *at/2 form (`inotify_init1`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1210` -> canonical `inotify_init1` (#26) with `flags=0` |
| — | 261 | `futimesat` | — | x86-only syscall: missing / deferred legacy shim | Documented in `crates/carrick-abi/src/syscall_x86_64.rs:877`; requires `struct timeval[2]` -> `struct timespec[2]` conversion to `utimensat`; unmapped -> -ENOSYS |
| — | 282 | `signalfd` | — | x86-only syscall: normalized to *at/2 form (`signalfd4`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1220` -> canonical `signalfd4` (#74) with `flags=0` |
| — | 284 | `eventfd` | — | x86-only syscall: normalized to *at/2 form (`eventfd2`) | Normalized at `crates/carrick-hal/src/x8664_arch.rs:1230` -> canonical `eventfd2` (#19) with `flags=0` |

---

## x86-Only Legacy Syscalls & Normalization Details

Linux on x86_64 preserves system calls from earlier kernel vintages that asm-generic and AArch64 omitted in favor of directory-relative (`*at`) or flag-extended (`2`/`4`) system calls. In Carrick, these calls are normalized in `carrick_hal::x8664_arch::normalize_syscall` (`crates/carrick-hal/src/x8664_arch.rs:1105`) or serviced by private subsystem handlers.

### 1. File & Directory Syscalls Normalized to `*at` Forms
| Legacy x86 Syscall | Target Canonical Form | Normalization Mechanism & Flag Fixups |
|---|---|---|
| `open(path, flags, mode)` (#2) | `openat(AT_FDCWD, path, flags, mode)` (#56) | Prepends `AT_FDCWD`. Runs `translate_x86_open_flags` to translate x86 `O_*` flags (`O_DIRECT` 0x4000->0x10000, `O_LARGEFILE` 0x8000->0, `O_DIRECTORY` 0x10000->0x4000, `O_NOFOLLOW` 0x20000->0x8000). (`x8664_arch.rs:1376`) |
| `creat(path, mode)` (#85) | `openat(AT_FDCWD, path, flags, mode)` (#56) | Prepends `AT_FDCWD`. Synthesizes `flags = O_CREAT | O_WRONLY | O_TRUNC`. Passes `mode` to arg3. (`x8664_arch.rs:1411`) |
| `access(path, mode)` (#21) | `faccessat(AT_FDCWD, path, mode, 0)` (#48) | Prepends `AT_FDCWD`. Appends trailing `flags = 0`. (`x8664_arch.rs:1279`) |
| `mkdir(path, mode)` (#83) | `mkdirat(AT_FDCWD, path, mode)` (#34) | Prepends `AT_FDCWD`. Mode passes through unmodified. (`x8664_arch.rs:1362`) |
| `unlink(path)` (#87) | `unlinkat(AT_FDCWD, path, 0)` (#35) | Prepends `AT_FDCWD`. Appends `flags = 0`. (`x8664_arch.rs:1433`) |
| `rmdir(path)` (#84) | `unlinkat(AT_FDCWD, path, AT_REMOVEDIR)` (#35) | Prepends `AT_FDCWD`. Appends `flags = AT_REMOVEDIR` (0x200). (`x8664_arch.rs:1442`) |
| `rename(old, new)` (#82) | `renameat(AT_FDCWD, old, AT_FDCWD, new)` (#38) | Prepends `AT_FDCWD` to both paths. (`x8664_arch.rs:1459`) |
| `link(old, new)` (#86) | `linkat(AT_FDCWD, old, AT_FDCWD, new, 0)` (#37) | Prepends `AT_FDCWD` to both paths. Appends `flags = 0` (no `AT_SYMLINK_FOLLOW`). (`x8664_arch.rs:1475`) |
| `symlink(target, linkpath)` (#88) | `symlinkat(target, AT_FDCWD, linkpath)` (#36) | Inserts `AT_FDCWD` as the second argument (directory fd for linkpath). (`x8664_arch.rs:1493`) |
| `readlink(path, buf, bufsiz)` (#89) | `readlinkat(AT_FDCWD, path, buf, bufsiz)` (#78) | Prepends `AT_FDCWD`. Buffer and length pass through. (`x8664_arch.rs:1353`) |
| `chmod(path, mode)` (#90) | `fchmodat(AT_FDCWD, path, mode, 0)` (#53) | Prepends `AT_FDCWD`. Appends `flags = 0` (follows symlinks). (`x8664_arch.rs:1514`) |
| `chown(path, uid, gid)` (#92) | `fchownat(AT_FDCWD, path, uid, gid, 0)` (#54) | Prepends `AT_FDCWD`. Appends `flags = 0` (follows symlinks). Sentinel `-1` passes through. (`x8664_arch.rs:1524`) |
| `lchown(path, uid, gid)` (#94) | `fchownat(AT_FDCWD, path, uid, gid, AT_SYMLINK_NOFOLLOW)` (#54) | Prepends `AT_FDCWD`. Appends `flags = AT_SYMLINK_NOFOLLOW` (0x100). (`x8664_arch.rs:1534`) |
| `mknod(path, mode, dev)` (#133) | `mknodat(AT_FDCWD, path, mode, dev)` (#33) | Prepends `AT_FDCWD`. Device number and mode pass through. (`x8664_arch.rs:1504`) |

### 2. Descriptor & IPC Syscalls Normalized to Extended (`2` / `4`) Forms
| Legacy x86 Syscall | Target Canonical Form | Normalization Mechanism & Semantic Distinctions |
|---|---|---|
| `pipe(pipefd)` (#22) | `pipe2(pipefd, 0)` (#59) | Appends `flags = 0`. (`x8664_arch.rs:1324`) |
| `pipe2(pipefd, flags)` (#293) | `pipe2(pipefd, canon_flags)` (#59) | Translates `O_DIRECT` bit from x86 0x4000 to canonical 0x10000; passes `O_CLOEXEC` and `O_NONBLOCK` through. (`x8664_arch.rs:1333`) |
| `pause()` (#34) | `ppoll(0, 0, 0, 0, 0, 0)` (#73) | Canonical asm-generic libc emits `ppoll(NULL, 0, NULL, NULL)` for `pause()`. Carrick normalizes x86 `pause()` to zeroed `ppoll` so it parks on signal wait without polling. (`x8664_arch.rs:1164`) |
| `fork()` (#57) | `clone(SIGCHLD, 0, 0, 0, 0, 0)` (#220) | Desugars to canonical `clone` with `flags = LINUX_SIGCHLD` (0x11). (`x8664_arch.rs:1114`) |
| `vfork()` (#58) | `clone(CLONE_VM \| CLONE_VFORK \| SIGCHLD, ...)` (#220) | Desugars to canonical `clone` with `flags = CLONE_VM | CLONE_VFORK | SIGCHLD`. (`x8664_arch.rs:1123`) |
| `getpgrp()` (#111) | `getpgid(0)` (#155) | Maps POSIX `getpgrp()` to `getpgid(0)`, returning current process group. (`x8664_arch.rs:1240`) |
| `epoll_wait(epfd, events, maxevents, timeout)` (#232) | `epoll_pwait(..., NULL, 0)` (#22) | Synthesizes trailing `sigmask = NULL` and `sigsetsize = 0`. (`x8664_arch.rs:1181`) |
| `inotify_init()` (#253) | `inotify_init1(0)` (#26) | Appends `flags = 0`. (`x8664_arch.rs:1210`) |
| `signalfd(fd, mask, sizemask)` (#282) | `signalfd4(fd, mask, sizemask, 0)` (#74) | Appends `flags = 0`. (`x8664_arch.rs:1220`) |
| `eventfd(initval)` (#284) | `eventfd2(initval, 0)` (#19) | Appends `flags = 0`. (`x8664_arch.rs:1230`) |

### 3. Syscalls Requiring Dedicated x86 Handlers (Not Direct Normalization)
Certain x86 syscalls cannot be naively normalized to their asm-generic successors due to ABI semantic conflicts, struct layout differences, or scalar argument encodings:

1. **`dup2(oldfd, newfd)` (#33) vs `dup3` (#24):**
   - Under POSIX and Linux, `dup2(fd, fd)` with a valid open descriptor is a successful no-op returning `fd`. In contrast, `dup3(fd, fd, flags)` explicitly returns `-EINVAL`. Mapping `dup2` directly to `dup3` would break valid application code. Carrick routes x86 `dup2` to `CARRICK_PRIVATE_X86_DUP2` (`crates/carrick-hal/src/x8664_arch.rs:1252`), serviced by `dup2` in `crates/carrick-kernel/src/dispatch/fs/close_dup.rs:259`.
2. **`stat` (#4), `fstat` (#5), `lstat` (#6), `newfstatat` (#262) (`LinuxX8664Stat`):**
   - The Linux x86_64 `struct stat` layout is 144 bytes (`LinuxX8664Stat`), whereas AArch64 uses a 128-byte `struct stat` layout (`LinuxAarch64Stat`). Writing the AArch64 structure into an x86 buffer causes buffer misalignments and corruption in guest runtimes. All four syscalls are routed to private numbers (`CARRICK_PRIVATE_X86_STAT/FSTAT/LSTAT/NEWFSTATAT`) and write the exact 144-byte structure (`crates/carrick-kernel/src/dispatch/fs/stat.rs:576, 589, 600, 618`).
3. **`poll(fds, nfds, timeout_ms)` (#7) vs `ppoll` (#73):**
   - `poll` takes an integer timeout scalar in milliseconds. `ppoll` takes a pointer to `struct timespec`. At program startup, musl probes descriptor validity via `poll(fds, n, 0)`. If routed directly to `ppoll`, argument 2 (`0`) is decoded as a NULL pointer (`None` timeout -> wait forever), hanging the guest. Carrick routes it to `CARRICK_PRIVATE_X86_POLL`, where the handler branches on `is_poll` and reads `timeout_ms` directly (`crates/carrick-kernel/src/dispatch/net.rs:3197`).
4. **`select(nfds, r, w, e, timeout)` (#23) vs `pselect6` (#72):**
   - `select` accepts a pointer to `struct timeval` (`tv_sec`, `tv_usec`), while `pselect6` accepts `struct timespec` (`tv_sec`, `tv_nsec`) and a sigmask. Carrick routes x86 `select` to `CARRICK_PRIVATE_X86_SELECT`, where `crates/carrick-kernel/src/dispatch/net.rs:2817` translates `timeval` into milliseconds.
5. **`epoll_create(size)` (#213) vs `epoll_create1` (#20):**
   - While modern Linux kernels ignore `size`, the kernel ABI strictly rejects `size <= 0` with `-EINVAL`. Direct normalization to `epoll_create1(0)` would drop this check and violate LTP compliance (`epoll_create02`). Carrick routes it to `CARRICK_PRIVATE_X86_EPOLL_CREATE` (`crates/carrick-kernel/src/dispatch/net/epoll_ops.rs:3720`), enforcing `size > 0`.
6. **`alarm(seconds)` (#37) & `time(tloc)` (#201):**
   - Neither syscall exists in asm-generic (where libc uses `setitimer` or `clock_gettime`). Carrick services them via `CARRICK_PRIVATE_X86_ALARM` (`crates/carrick-kernel/src/dispatch/time.rs:489`) and `CARRICK_PRIVATE_X86_TIME` (`crates/carrick-kernel/src/dispatch/time.rs:853`).

### 4. Deferred Legacy Shims (Awaiting Argument Conversion)
Four legacy x86_64 syscalls have asm-generic successors but require structured argument translation in Carrick. They currently return `-ENOSYS` via `SyscallRemap::Unknown`:
- `getdents(fd, dirp, count)` (x86 #78): Requires translating 32-bit `linux_dirent` structures into 64-bit `linux_dirent64` (`getdents64` #61).
- `utime(filename, times)` (x86 #132): Requires converting `struct utimbuf` to `struct timespec[2]` (`utimensat` #88).
- `utimes(filename, times)` (x86 #235): Requires converting `struct timeval[2]` to `struct timespec[2]` (`utimensat` #88).
- `futimesat(dfd, filename, times)` (x86 #261): Requires converting `struct timeval[2]` to `struct timespec[2]` (`utimensat` #88).

### 5. Obsolete and Absent Linux System Calls (Honest -ENOSYS)
The remaining 21 x86_64 system calls are either hardware-specific to real x86 PC architecture (`iopl`, `ioperm`, `modify_ldt`), obsolete 1990s kernel interfaces removed from modern Linux (`uselib`, `ustat`, `sysfs`, `_sysctl`, module manipulation calls), or unassigned/vendor-specific stubs (`vserver`, `tuxcall`, `afs_syscall`). Carrick deliberately does not emulate them and returns honest `-ENOSYS` (`SyscallRemap::Unknown`), allowing callers to degrade gracefully.

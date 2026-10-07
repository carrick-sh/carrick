# x86 legacy syscall translation audit

Scope: Linux x86_64 calls used by static libc startup, file/descriptor APIs,
process APIs and their older wrappers. This is a source audit of the shared
`carrick-syscall-abi` table / `decode_x86_64` and the existing
`carrick-hal::X8664GuestArch::normalize_syscall`, not a claim that every libc
version emits every call below. No other legacy syscall is implemented here.

The production KVM initial carrier currently forwards only write and terminal
exit. Other host forwards fail with `unported initial x86 syscall N`, including
calls whose ordinal translation exists. Shared host dispatch and real
scheduler/lifecycle custody are tracked under PR #81. A table entry is not an
execution binding.

The shared guest decoder's missing entries yield canonical `u64::MAX` and
forward; a fully bound host dispatcher would return ENOSYS (38). The current
initial carrier instead refuses the native syscall. The older host HAL has
additional argument lowering that the shared guest decoder does not inherit.
Its unknown calls go to the typed unsupported sink and ENOSYS.

| Native number / call | Shared guest table today | Existing HAL / full kernel behavior |
| --- | --- | --- |
| 2 open | absent | openat(56), AT_FDCWD plus translated flags |
| 4 stat | absent | private x86 stat writer, 144-byte result |
| 5 fstat | absent | private x86 fstat writer, 144-byte result |
| 6 lstat | absent | private x86 lstat writer, no-follow lookup |
| 7 poll | private ppoll integer-timeout route | same ppoll handler; exact signed millisecond conversion |
| 21 access | absent | faccessat(48), AT_FDCWD and flags zero |
| 22 pipe | absent | pipe2(59), flags zero |
| 23 select | absent | private pselect6 handler, timeval timeout, no replacement mask |
| 33 dup2 | absent | private dup2 handler; same-fd success differs from dup3 |
| 34 pause | absent | ppoll(73), NULL timeout and no fds |
| 37 alarm | absent | private alarm handler |
| 57 fork | private fork ordinal only; no family binding here | lowers to clone(220), SIGCHLD |
| 58 vfork | absent | clone(220), CLONE_VM + CLONE_VFORK + SIGCHLD |
| 78 getdents | absent | ENOSYS; legacy linux_dirent packing not translated to getdents64 |
| 82 rename | absent | renameat(38), both dirfds AT_FDCWD |
| 83 mkdir | absent | mkdirat(34), AT_FDCWD |
| 84 rmdir | absent | unlinkat(35), AT_REMOVEDIR |
| 85 creat | absent | openat(56), O_CREAT + O_WRONLY + O_TRUNC |
| 86 link | absent | linkat(37), AT_FDCWD and flags zero |
| 87 unlink | absent | unlinkat(35), AT_FDCWD and flags zero |
| 88 symlink | absent | symlinkat(36), inserted destination dirfd |
| 89 readlink | absent | readlinkat(78), AT_FDCWD |
| 90 chmod | absent | fchmodat(53), AT_FDCWD |
| 92 chown | absent | fchownat(54), AT_FDCWD and flags zero |
| 94 lchown | absent | fchownat(54), AT_SYMLINK_NOFOLLOW |
| 111 getpgrp | absent | getpgid(155), pid zero |
| 132 utime | absent | ENOSYS; utimbuf-to-timespec conversion not bound |
| 133 mknod | absent | mknodat(33), AT_FDCWD |
| 201 time | absent | private time handler; copies seconds when pointer supplied |
| 213 epoll_create | absent | private epoll_create handler, validates size before creation |
| 232 epoll_wait | absent | epoll_pwait(22), NULL mask |
| 235 utimes | absent | ENOSYS; timeval[2]-to-timespec[2] not bound |
| 253 inotify_init | absent | inotify_init1(26), flags zero |
| 261 futimesat | absent | ENOSYS; timeval[2]-to-timespec[2] not bound |
| 282 signalfd | absent | signalfd4(74), flags zero |
| 284 eventfd | absent | eventfd2(19), flags zero |

`fstat` and `newfstatat` have generic names but incompatible x86 result records.
Native newfstatat(262) is Direct(79) in the shared table; the HAL deliberately
uses a private x86 writer. Before binding it, #81 must retain the x86 record
shape. Likewise x86 epoll_event records are packed 12 bytes; a direct ordinal
for epoll_ctl/epoll_pwait does not prove correct record copying.

The obsolete or ISA-privileged calls below are also absent/unsupported, but
are not ordinary modern musl/glibc startup dependencies: uselib(134),
ustat(136), sysfs(139), modify_ldt(154), _sysctl(156), iopl(172), ioperm(173),
create_module(174), get_kernel_syms(177), query_module(178), nfsservctl(180),
getpmsg(181), putpmsg(182), afs_syscall(183), tuxcall(184), security(185),
set_thread_area(205), get_thread_area(211), epoll_ctl_old(214),
epoll_wait_old(215), vserver(236). TLS uses arch_prctl(158), not the old
thread-area calls.

Poll's signed timeout interpretation and stop/continue deadline accounting
follow [poll(2)](https://man7.org/linux/man-pages/man2/poll.2.html) and
[restart_syscall(2)](https://man7.org/linux/man-pages/man2/restart_syscall.2.html).
A caught handler returns EINTR (4), even with SA_RESTART; stop/continue retains
the admitted absolute deadline and therefore deducts stopped time. The VM-free
continuation test exercises both finite and infinite waits. The musl CLI red
at syscall 7 is retained evidence of the missing #81 execution binding.

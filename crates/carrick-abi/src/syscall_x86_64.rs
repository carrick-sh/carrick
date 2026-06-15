//! x86_64 Linux syscall number table and canonical remap.
//!
//! Maps x86_64 syscall numbers to their canonical (aarch64/asm-generic)
//! equivalents used by carrick's unified dispatcher. Numbers are sourced
//! from published references:
//!   - `syscalls(2)` man page (man7.org)
//!   - filippo.io/linux-syscall-table (x86_64 column)
//!   - OSDev Wiki "System calls" (x86_64 ABI table)
//!
//! Each canonical (`Direct(N)`) target is cross-checked against
//! `carrick_abi::syscall::AARCH64_SYSCALLS` in this file's compile-time
//! guard (see below) to ensure the remap is self-consistent with carrick's
//! own canonical numbering.
//!
//! CLEAN-ROOM: no Linux kernel source (`arch/x86/entry/syscalls/syscall_64.tbl`,
//! `unistd_64.h`) or glibc source was used. Numbers come exclusively from the
//! published references cited above.
//!
//! The table now covers the WHOLE x86_64 Linux syscall ABI (numbers 0..454):
//! every x86_64 syscall whose NAME also appears in `AARCH64_SYSCALLS` with a
//! matching argument shape is a `Direct(canonical)`. Legacy x86_64-only
//! syscalls whose arg shape differs from their asm-generic successor
//! (`open` vs `openat`, `dup2` vs `dup3`, `stat`/`fstat`/`lstat` vs
//! `newfstatat`, `select` vs `pselect6`, `poll` is the lone exception below as
//! musl calls it with timeout 0) are deliberately LEFT OUT (→ `Unknown` →
//! -ENOSYS); adding a naive `Direct` for them would silently mis-dispatch the
//! wrong arg shape, which is worse than an honest ENOSYS. Those are listed in
//! a clearly-marked comment block at the end of the table as needing a
//! `normalize_syscall` arg-translation shim (deferred, oracle-gated).
//!
//! `arch_prctl`=158 stays `native` (the backend services FS/GS base). fork(57)
//! and vfork(58) are NOT table entries — they are desugared to clone(220)
//! BEFORE the table lookup in `carrick_hal::x8664_arch::normalize_syscall`.

/// How a guest-ISA syscall number reaches the canonical (aarch64/asm-generic)
/// dispatcher. Defined here in `carrick-abi` (the leaf crate) so both
/// `carrick-abi` and `carrick-hal` can share it without a dependency cycle.
/// `carrick-hal::guest_arch` re-exports this type.
///
/// Phase 2 carries `Direct` and `Unknown`; the legacy-shim class (x86_64
/// `open`→`openat` etc.) gets its variant when the first shim lands
/// (oracle-gated — M2's musl-static startup is at-era and needs none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallRemap {
    /// Same semantics, different number: dispatch as `canonical` with args
    /// unchanged.
    Direct(u64),
    /// ISA-private syscall the backend services natively (x86_64 `arch_prctl`).
    Native,
    /// No canonical equivalent / not in the table: honest -ENOSYS.
    Unknown,
}

/// A single x86_64 syscall table entry: the x86_64 number, its name, and
/// how it reaches carrick's canonical dispatcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X8664Syscall {
    pub number: u64,
    pub name: &'static str,
    pub remap: SyscallRemap,
}

const fn direct(number: u64, name: &'static str, canonical: u64) -> X8664Syscall {
    X8664Syscall {
        number,
        name,
        remap: SyscallRemap::Direct(canonical),
    }
}

const fn native(number: u64, name: &'static str) -> X8664Syscall {
    X8664Syscall {
        number,
        name,
        remap: SyscallRemap::Native,
    }
}

/// Binary-search the x86_64 syscall table for `number`. Returns `None` if the
/// number is not in the initial table (the caller should answer -ENOSYS, logged
/// via `X86_64_SYSCALLS` search or a raw number).
pub fn lookup_x86_64(number: u64) -> Option<&'static X8664Syscall> {
    X86_64_SYSCALLS
        .binary_search_by_key(&number, |s| s.number)
        .ok()
        .map(|i| &X86_64_SYSCALLS[i])
}

/// The full x86_64 syscall table — the WHOLE x86_64 Linux ABI (numbers 0..454).
///
/// Sources for x86_64 numbers (cited per-entry in inline comments):
///   syscalls(2) man7.org §"Architecture calling conventions" (x86-64 table);
///   filippo.io/linux-syscall-table; OSDev "System calls".
///
/// Sources for canonical (Direct) targets: carrick's own `AARCH64_SYSCALLS`
/// in `carrick_abi::syscall` — every `Direct(N)` below names a syscall whose
/// NAME also appears in `AARCH64_SYSCALLS` at number `N`. This is enforced at
/// test time by `every_direct_canonical_matches_aarch64_by_name` (see
/// `mod tests`), which iterates this table and proves each Direct target's
/// number+name agrees with the canonical table.
///
/// MUST stay strictly sorted by `number` for `lookup_x86_64`'s binary search.
pub static X86_64_SYSCALLS: &[X8664Syscall] = &[
    // x86_64=0 (syscalls(2)/filippo) → canonical read=63
    direct(0, "read", 63),
    // x86_64=1 (syscalls(2)/filippo) → canonical write=64
    direct(1, "write", 64),
    // x86_64=2 open: LEGACY x86_64-only (asm-generic has openat=56 only). Arg
    // shape differs (open(path,flags,mode) vs openat(dfd,path,flags,mode)) →
    // LEFT OUT, needs a normalize shim. (see deferred block below)
    // x86_64=3 (syscalls(2)/filippo) → canonical close=57
    direct(3, "close", 57),
    // x86_64=4 stat, 5 fstat, 6 lstat: LEGACY (asm-generic has newfstatat=79,
    // fstat=80, statx=291). stat/lstat have no 1:1; even fstat differs in
    // struct layout — LEFT OUT. (see deferred block below)
    // x86_64=7 (syscalls(2)/filippo) → canonical ppoll=73.
    // musl calls poll(fds, n, 0) at startup to probe fd validity (non-blocking).
    // NOTE: poll(fds,n,timeout_ms) vs ppoll(fds,n,*timespec,*sigmask,size) is a
    // DIFFERENT arg shape; this Direct is a known-imperfect bring-up convenience
    // (the dispatcher's ppoll handler tolerates the musl startup probe). It is
    // also listed in the deferred shim block for an eventual real translation.
    direct(7, "poll", 73),
    // x86_64=8 lseek → canonical lseek=62 (SAME name+shape: fd,off,whence)
    direct(8, "lseek", 62),
    // x86_64=9 (syscalls(2)/filippo) → canonical mmap=222
    direct(9, "mmap", 222),
    // x86_64=10 (syscalls(2)/filippo) → canonical mprotect=226
    direct(10, "mprotect", 226),
    // x86_64=11 (syscalls(2)/filippo) → canonical munmap=215
    direct(11, "munmap", 215),
    // x86_64=12 (syscalls(2)/filippo) → canonical brk=214
    direct(12, "brk", 214),
    // x86_64=13 (syscalls(2)/filippo) → canonical rt_sigaction=134
    direct(13, "rt_sigaction", 134),
    // x86_64=14 (syscalls(2)/filippo) → canonical rt_sigprocmask=135
    direct(14, "rt_sigprocmask", 135),
    // x86_64=15 (syscalls(2)/filippo) → canonical rt_sigreturn=139.
    // The signal handler's restorer invokes it to return from a handler; the
    // dispatcher routes 139 → DispatchOutcome::SigReturn → engine.restore_from_sigframe.
    direct(15, "rt_sigreturn", 139),
    // x86_64=16 (syscalls(2)/filippo) → canonical ioctl=29
    direct(16, "ioctl", 29),
    // x86_64=17 pread64 → canonical pread64=67 (SAME name+shape)
    direct(17, "pread64", 67),
    // x86_64=18 pwrite64 → canonical pwrite64=68 (SAME name+shape)
    direct(18, "pwrite64", 68),
    // x86_64=19 readv → canonical readv=65 (SAME name+shape)
    direct(19, "readv", 65),
    // x86_64=20 (syscalls(2)/filippo) → canonical writev=66
    direct(20, "writev", 66),
    // x86_64=21 access: LEGACY (asm-generic has faccessat=48). access(path,mode)
    // vs faccessat(dfd,path,mode,flags) → LEFT OUT. (see deferred block)
    // x86_64=22 pipe: LEGACY (asm-generic has pipe2=59). Handled in
    // x8664_arch::normalize_syscall as pipe2(fd, flags=0).
    // x86_64=23 select: LEGACY (asm-generic has pselect6=72). DIFFERENT shape →
    // LEFT OUT. (see deferred block)
    // x86_64=24 sched_yield → canonical sched_yield=124 (SAME name+shape)
    direct(24, "sched_yield", 124),
    // x86_64=25 mremap → canonical mremap=216 (SAME name+shape)
    direct(25, "mremap", 216),
    // x86_64=26 msync → canonical msync=227 (SAME name+shape)
    direct(26, "msync", 227),
    // x86_64=27 mincore → canonical mincore=232 (SAME name+shape)
    direct(27, "mincore", 232),
    // x86_64=28 madvise → canonical madvise=233 (SAME name+shape)
    direct(28, "madvise", 233),
    // x86_64=29 shmget → canonical shmget=194 (SAME name+shape)
    direct(29, "shmget", 194),
    // x86_64=30 shmat → canonical shmat=196 (SAME name+shape)
    direct(30, "shmat", 196),
    // x86_64=31 shmctl → canonical shmctl=195 (SAME name+shape)
    direct(31, "shmctl", 195),
    // x86_64=32 dup → canonical dup=23 (SAME name+shape: dup(oldfd))
    direct(32, "dup", 23),
    // x86_64=33 dup2: LEGACY (asm-generic has dup3=24). dup2(old,new) vs
    // dup3(old,new,flags) — and dup2(fd,fd) is a no-op-success where dup3 EINVALs
    // → LEFT OUT. (see deferred block)
    // x86_64=34 pause: LEGACY x86_64-only, NO asm-generic equivalent → Unknown.
    // x86_64=35 nanosleep → canonical nanosleep=101 (SAME name+shape)
    direct(35, "nanosleep", 101),
    // x86_64=36 getitimer → canonical getitimer=102 (SAME name+shape)
    direct(36, "getitimer", 102),
    // x86_64=37 alarm: LEGACY x86_64-only, NO asm-generic equivalent → Unknown
    // (libc on asm-generic implements alarm via setitimer/timer_*).
    // x86_64=38 setitimer → canonical setitimer=103 (SAME name+shape)
    direct(38, "setitimer", 103),
    // x86_64=39 getpid → canonical getpid=172 (SAME name+shape)
    direct(39, "getpid", 172),
    // x86_64=40 sendfile → canonical sendfile=71 (SAME name+shape)
    direct(40, "sendfile", 71),
    // x86_64=41 socket → canonical socket=198 (SAME name+shape)
    direct(41, "socket", 198),
    // x86_64=42 connect → canonical connect=203 (SAME name+shape)
    direct(42, "connect", 203),
    // x86_64=43 accept → canonical accept=202 (SAME name+shape)
    direct(43, "accept", 202),
    // x86_64=44 sendto → canonical sendto=206 (SAME name+shape)
    direct(44, "sendto", 206),
    // x86_64=45 recvfrom → canonical recvfrom=207 (SAME name+shape)
    direct(45, "recvfrom", 207),
    // x86_64=46 sendmsg → canonical sendmsg=211 (SAME name+shape)
    direct(46, "sendmsg", 211),
    // x86_64=47 recvmsg → canonical recvmsg=212 (SAME name+shape)
    direct(47, "recvmsg", 212),
    // x86_64=48 shutdown → canonical shutdown=210 (SAME name+shape)
    direct(48, "shutdown", 210),
    // x86_64=49 bind → canonical bind=200 (SAME name+shape)
    direct(49, "bind", 200),
    // x86_64=50 listen → canonical listen=201 (SAME name+shape)
    direct(50, "listen", 201),
    // x86_64=51 getsockname → canonical getsockname=204 (SAME name+shape)
    direct(51, "getsockname", 204),
    // x86_64=52 getpeername → canonical getpeername=205 (SAME name+shape)
    direct(52, "getpeername", 205),
    // x86_64=53 socketpair → canonical socketpair=199 (SAME name+shape)
    direct(53, "socketpair", 199),
    // x86_64=54 setsockopt → canonical setsockopt=208 (SAME name+shape)
    direct(54, "setsockopt", 208),
    // x86_64=55 getsockopt → canonical getsockopt=209 (SAME name+shape)
    direct(55, "getsockopt", 209),
    // x86_64=56 (syscalls(2)/filippo) → canonical clone=220.
    // musl/glibc fork() AND pthread_create() both lower to SYS_clone on x86-64
    // (neither libc emits SYS_fork/SYS_vfork). The shared dispatcher's clone
    // handler routes thread-create (CLONE_VM|CLONE_THREAD) vs process-fork
    // (SIGCHLD) by flags. NOTE: the x86-64 raw clone arg order swaps tls/child_tid
    // vs the asm-generic order the dispatcher expects — the x86 engine normalizes
    // it (x8664_arch::normalize_syscall). Source: clone(2) man-page.
    direct(56, "clone", 220),
    // x86_64=57 fork / 58 vfork: NOT table entries. Desugared to clone(220)
    // BEFORE the table lookup in x8664_arch::normalize_syscall (asm-generic has
    // no SYS_fork/SYS_vfork). DO NOT add here.
    // x86_64=59 (syscalls(2)/filippo) → canonical execve=221.
    // glibc/musl execve() lowers to SYS_execve(59); the shared dispatcher's
    // execve handler returns DispatchOutcome::Execve → the loop's handle_execve
    // → engine.execve_into (the SP2 fresh-VM image replacement). WITHOUT this
    // entry x86_64 execve(59) falls through to Unknown → -ENOSYS, so the guest's
    // execve fails before ever reaching the dispatcher (trap-confirmed on the
    // bhyve dispatcher lane with the bhyve-execve fixture). Source: execve(2)
    // man-page; the canonical 221 cross-checked against AARCH64_SYSCALLS.
    direct(59, "execve", 221),
    // x86_64=60 (syscalls(2)/filippo) → canonical exit=93
    direct(60, "exit", 93),
    // x86_64=61 (syscalls(2)/filippo) → canonical wait4=260.
    // A forking parent reaps its child via wait4.
    direct(61, "wait4", 260),
    // x86_64=62 kill → canonical kill=129 (SAME name+shape)
    direct(62, "kill", 129),
    // x86_64=63 (syscalls(2)/filippo) → canonical uname=160.
    // WITHOUT this entry x86_64 uname(63) falls through to Unknown and passes its
    // raw number 63 to the ISA-neutral dispatcher, which COLLIDES with canonical
    // read=63 → uname is mis-dispatched as read and fails. Trap-confirmed on the
    // KVM-x86 dispatcher lane (the x86-fsprobe fixture).
    direct(63, "uname", 160),
    // x86_64=64 semget → canonical semget=190 (SAME name+shape)
    direct(64, "semget", 190),
    // x86_64=65 semop → canonical semop=193 (SAME name+shape)
    direct(65, "semop", 193),
    // x86_64=66 semctl → canonical semctl=191 (SAME name+shape)
    direct(66, "semctl", 191),
    // x86_64=67 shmdt → canonical shmdt=197 (SAME name+shape)
    direct(67, "shmdt", 197),
    // x86_64=68 msgget → canonical msgget=186 (SAME name+shape)
    direct(68, "msgget", 186),
    // x86_64=69 msgsnd → canonical msgsnd=189 (SAME name+shape)
    direct(69, "msgsnd", 189),
    // x86_64=70 msgrcv → canonical msgrcv=188 (SAME name+shape)
    direct(70, "msgrcv", 188),
    // x86_64=71 msgctl → canonical msgctl=187 (SAME name+shape)
    direct(71, "msgctl", 187),
    // x86_64=72 fcntl → canonical fcntl=25 (SAME name+shape)
    direct(72, "fcntl", 25),
    // x86_64=73 flock → canonical flock=32 (SAME name+shape)
    direct(73, "flock", 32),
    // x86_64=74 fsync → canonical fsync=82 (SAME name+shape)
    direct(74, "fsync", 82),
    // x86_64=75 fdatasync → canonical fdatasync=83 (SAME name+shape)
    direct(75, "fdatasync", 83),
    // x86_64=76 truncate → canonical truncate=45 (SAME name+shape)
    direct(76, "truncate", 45),
    // x86_64=77 ftruncate → canonical ftruncate=46 (SAME name+shape)
    direct(77, "ftruncate", 46),
    // x86_64=78 getdents: LEGACY (asm-generic has getdents64=61). Old getdents
    // returns the 32-bit linux_dirent layout, getdents64 the 64-bit one →
    // DIFFERENT struct → LEFT OUT. (see deferred block)
    // x86_64=79 getcwd → canonical getcwd=17 (SAME name+shape)
    direct(79, "getcwd", 17),
    // x86_64=80 chdir → canonical chdir=49 (SAME name+shape)
    direct(80, "chdir", 49),
    // x86_64=81 fchdir → canonical fchdir=50 (SAME name+shape)
    direct(81, "fchdir", 50),
    // x86_64=82 rename: LEGACY (asm-generic has renameat=38). rename(old,new) vs
    // renameat(odfd,old,ndfd,new) → LEFT OUT. (see deferred block)
    // x86_64=83 mkdir: LEGACY (asm-generic has mkdirat=34) → LEFT OUT.
    // x86_64=84 rmdir: LEGACY (asm-generic has unlinkat=35 w/ AT_REMOVEDIR) →
    // LEFT OUT. (see deferred block)
    // x86_64=85 creat: LEGACY x86_64-only (asm-generic uses openat) → LEFT OUT.
    // x86_64=86 link: LEGACY (asm-generic has linkat=37) → LEFT OUT.
    // x86_64=87 unlink: LEGACY (asm-generic has unlinkat=35) → LEFT OUT.
    // x86_64=88 symlink: LEGACY (asm-generic has symlinkat=36) → LEFT OUT.
    // x86_64=89 readlink: LEGACY (asm-generic has readlinkat=78) → LEFT OUT.
    // x86_64=90 chmod: LEGACY (asm-generic has fchmodat=53) → LEFT OUT.
    // x86_64=91 fchmod → canonical fchmod=52 (SAME name+shape)
    direct(91, "fchmod", 52),
    // x86_64=92 chown: LEGACY (asm-generic has fchownat=54) → LEFT OUT.
    // x86_64=93 fchown → canonical fchown=55 (SAME name+shape)
    direct(93, "fchown", 55),
    // x86_64=94 lchown: LEGACY (asm-generic has fchownat=54 w/ AT_SYMLINK_NOFOLLOW)
    // → LEFT OUT. (see deferred block)
    // x86_64=95 umask → canonical umask=166 (SAME name+shape)
    direct(95, "umask", 166),
    // x86_64=96 gettimeofday → canonical gettimeofday=169 (SAME name+shape)
    direct(96, "gettimeofday", 169),
    // x86_64=97 getrlimit → canonical getrlimit=163 (SAME name+shape)
    direct(97, "getrlimit", 163),
    // x86_64=98 getrusage → canonical getrusage=165 (SAME name+shape)
    direct(98, "getrusage", 165),
    // x86_64=99 sysinfo → canonical sysinfo=179 (SAME name+shape)
    direct(99, "sysinfo", 179),
    // x86_64=100 times → canonical times=153 (SAME name+shape)
    direct(100, "times", 153),
    // x86_64=101 ptrace → canonical ptrace=117 (SAME name+shape)
    direct(101, "ptrace", 117),
    // x86_64=102 getuid → canonical getuid=174 (SAME name+shape)
    direct(102, "getuid", 174),
    // x86_64=103 syslog → canonical syslog=116 (SAME name+shape)
    direct(103, "syslog", 116),
    // x86_64=104 getgid → canonical getgid=176 (SAME name+shape)
    direct(104, "getgid", 176),
    // x86_64=105 setuid → canonical setuid=146 (SAME name+shape)
    direct(105, "setuid", 146),
    // x86_64=106 setgid → canonical setgid=144 (SAME name+shape)
    direct(106, "setgid", 144),
    // x86_64=107 geteuid → canonical geteuid=175 (SAME name+shape)
    direct(107, "geteuid", 175),
    // x86_64=108 getegid → canonical getegid=177 (SAME name+shape)
    direct(108, "getegid", 177),
    // x86_64=109 setpgid → canonical setpgid=154 (SAME name+shape)
    direct(109, "setpgid", 154),
    // x86_64=110 getppid → canonical getppid=173 (SAME name+shape)
    direct(110, "getppid", 173),
    // x86_64=111 getpgrp: LEGACY x86_64-only, NO asm-generic equivalent
    // (asm-generic uses getpgid(0)) → Unknown.
    // x86_64=112 setsid → canonical setsid=157 (SAME name+shape)
    direct(112, "setsid", 157),
    // x86_64=113 setreuid → canonical setreuid=145 (SAME name+shape)
    direct(113, "setreuid", 145),
    // x86_64=114 setregid → canonical setregid=143 (SAME name+shape)
    direct(114, "setregid", 143),
    // x86_64=115 getgroups → canonical getgroups=158 (SAME name+shape)
    direct(115, "getgroups", 158),
    // x86_64=116 setgroups → canonical setgroups=159 (SAME name+shape)
    direct(116, "setgroups", 159),
    // x86_64=117 setresuid → canonical setresuid=147 (SAME name+shape)
    direct(117, "setresuid", 147),
    // x86_64=118 getresuid → canonical getresuid=148 (SAME name+shape)
    direct(118, "getresuid", 148),
    // x86_64=119 setresgid → canonical setresgid=149 (SAME name+shape)
    direct(119, "setresgid", 149),
    // x86_64=120 getresgid → canonical getresgid=150 (SAME name+shape)
    direct(120, "getresgid", 150),
    // x86_64=121 getpgid → canonical getpgid=155 (SAME name+shape)
    direct(121, "getpgid", 155),
    // x86_64=122 setfsuid → canonical setfsuid=151 (SAME name+shape)
    direct(122, "setfsuid", 151),
    // x86_64=123 setfsgid → canonical setfsgid=152 (SAME name+shape)
    direct(123, "setfsgid", 152),
    // x86_64=124 getsid → canonical getsid=156 (SAME name+shape)
    direct(124, "getsid", 156),
    // x86_64=125 capget → canonical capget=90 (SAME name+shape)
    direct(125, "capget", 90),
    // x86_64=126 capset → canonical capset=91 (SAME name+shape)
    direct(126, "capset", 91),
    // x86_64=127 rt_sigpending → canonical rt_sigpending=136 (SAME name+shape)
    direct(127, "rt_sigpending", 136),
    // x86_64=128 rt_sigtimedwait → canonical rt_sigtimedwait=137 (SAME name+shape)
    direct(128, "rt_sigtimedwait", 137),
    // x86_64=129 rt_sigqueueinfo → canonical rt_sigqueueinfo=138 (SAME name+shape)
    direct(129, "rt_sigqueueinfo", 138),
    // x86_64=130 rt_sigsuspend → canonical rt_sigsuspend=133 (SAME name+shape)
    direct(130, "rt_sigsuspend", 133),
    // x86_64=131 (syscalls(2)/filippo) → canonical sigaltstack=132.
    // musl calls sigaltstack at startup to establish an alternate signal stack.
    direct(131, "sigaltstack", 132),
    // x86_64=132 utime: LEGACY x86_64-only (asm-generic has utimensat=88).
    // utime(path, *utimbuf) vs utimensat(dfd,path,*timespec[2],flags) → LEFT OUT.
    // x86_64=133 mknod: LEGACY (asm-generic has mknodat=33) → LEFT OUT.
    // x86_64=134 uselib: obsolete x86_64-only, NO asm-generic equivalent → Unknown.
    // x86_64=135 personality → canonical personality=92 (SAME name+shape)
    direct(135, "personality", 92),
    // x86_64=136 ustat: obsolete x86_64-only, NO asm-generic equivalent → Unknown.
    // x86_64=137 statfs → canonical statfs=43 (SAME name+shape)
    direct(137, "statfs", 43),
    // x86_64=138 fstatfs → canonical fstatfs=44 (SAME name+shape)
    direct(138, "fstatfs", 44),
    // x86_64=139 sysfs: obsolete x86_64-only, NO asm-generic equivalent → Unknown.
    // x86_64=140 getpriority → canonical getpriority=141 (SAME name+shape)
    direct(140, "getpriority", 141),
    // x86_64=141 setpriority → canonical setpriority=140 (SAME name+shape)
    direct(141, "setpriority", 140),
    // x86_64=142 sched_setparam → canonical sched_setparam=118 (SAME name+shape)
    direct(142, "sched_setparam", 118),
    // x86_64=143 sched_getparam → canonical sched_getparam=121 (SAME name+shape)
    direct(143, "sched_getparam", 121),
    // x86_64=144 sched_setscheduler → canonical sched_setscheduler=119 (SAME)
    direct(144, "sched_setscheduler", 119),
    // x86_64=145 sched_getscheduler → canonical sched_getscheduler=120 (SAME)
    direct(145, "sched_getscheduler", 120),
    // x86_64=146 sched_get_priority_max → canonical sched_get_priority_max=125
    direct(146, "sched_get_priority_max", 125),
    // x86_64=147 sched_get_priority_min → canonical sched_get_priority_min=126
    direct(147, "sched_get_priority_min", 126),
    // x86_64=148 sched_rr_get_interval → canonical sched_rr_get_interval=127
    direct(148, "sched_rr_get_interval", 127),
    // x86_64=149 mlock → canonical mlock=228 (SAME name+shape)
    direct(149, "mlock", 228),
    // x86_64=150 munlock → canonical munlock=229 (SAME name+shape)
    direct(150, "munlock", 229),
    // x86_64=151 mlockall → canonical mlockall=230 (SAME name+shape)
    direct(151, "mlockall", 230),
    // x86_64=152 munlockall → canonical munlockall=231 (SAME name+shape)
    direct(152, "munlockall", 231),
    // x86_64=153 vhangup → canonical vhangup=58 (SAME name+shape)
    direct(153, "vhangup", 58),
    // x86_64=154 modify_ldt: x86_64-private LDT op, NO asm-generic equivalent →
    // Unknown (architecture-specific, like arch_prctl but not serviced natively).
    // x86_64=155 pivot_root → canonical pivot_root=41 (SAME name+shape)
    direct(155, "pivot_root", 41),
    // x86_64=156 _sysctl: obsolete x86_64-only, NO asm-generic equivalent → Unknown.
    // x86_64=157 prctl → canonical prctl=167 (SAME name+shape)
    direct(157, "prctl", 167),
    // x86_64=158 (syscalls(2)/filippo): arch_prctl is x86_64-private (sets FS/GS
    // base via ARCH_SET_FS / ARCH_SET_GS); the bhyve/KVM backend services it
    // natively (normalize_syscall returns SyscallNorm::ArchPrctl before lookup).
    native(158, "arch_prctl"),
    // x86_64=159 adjtimex → canonical adjtimex=171 (SAME name+shape)
    direct(159, "adjtimex", 171),
    // x86_64=160 setrlimit → canonical setrlimit=164 (SAME name+shape)
    direct(160, "setrlimit", 164),
    // x86_64=161 chroot → canonical chroot=51 (SAME name+shape)
    direct(161, "chroot", 51),
    // x86_64=162 sync → canonical sync=81 (SAME name+shape)
    direct(162, "sync", 81),
    // x86_64=163 acct → canonical acct=89 (SAME name+shape)
    direct(163, "acct", 89),
    // x86_64=164 settimeofday → canonical settimeofday=170 (SAME name+shape)
    direct(164, "settimeofday", 170),
    // x86_64=165 mount → canonical mount=40 (SAME name+shape)
    direct(165, "mount", 40),
    // x86_64=166 umount2 → canonical umount2=39 (SAME name+shape)
    direct(166, "umount2", 39),
    // x86_64=167 swapon → canonical swapon=224 (SAME name+shape)
    direct(167, "swapon", 224),
    // x86_64=168 swapoff → canonical swapoff=225 (SAME name+shape)
    direct(168, "swapoff", 225),
    // x86_64=169 reboot → canonical reboot=142 (SAME name+shape)
    direct(169, "reboot", 142),
    // x86_64=170 sethostname → canonical sethostname=161 (SAME name+shape)
    direct(170, "sethostname", 161),
    // x86_64=171 setdomainname → canonical setdomainname=162 (SAME name+shape)
    direct(171, "setdomainname", 162),
    // x86_64=172 iopl: x86_64-private I/O privilege op, NO asm-generic equivalent → Unknown.
    // x86_64=173 ioperm: x86_64-private I/O permission op, NO asm-generic equivalent → Unknown.
    // x86_64=174 create_module: obsolete x86_64-only → Unknown.
    // x86_64=175 init_module → canonical init_module=105 (SAME name+shape)
    direct(175, "init_module", 105),
    // x86_64=176 delete_module → canonical delete_module=106 (SAME name+shape)
    direct(176, "delete_module", 106),
    // x86_64=177 get_kernel_syms: obsolete x86_64-only → Unknown.
    // x86_64=178 query_module: obsolete x86_64-only → Unknown.
    // x86_64=179 quotactl → canonical quotactl=60 (SAME name+shape)
    direct(179, "quotactl", 60),
    // x86_64=180 nfsservctl: obsolete x86_64-only (asm-generic 42 is reserved/ENOSYS) → Unknown.
    // x86_64=181 getpmsg, 182 putpmsg, 183 afs_syscall, 184 tuxcall, 185 security:
    //   unimplemented/reserved x86_64 numbers, NO asm-generic equivalent → Unknown.
    // x86_64=186 (syscalls(2)/filippo) → canonical gettid=178
    direct(186, "gettid", 178),
    // x86_64=187 readahead → canonical readahead=213 (SAME name+shape)
    direct(187, "readahead", 213),
    // x86_64=188 setxattr → canonical setxattr=5 (SAME name+shape)
    direct(188, "setxattr", 5),
    // x86_64=189 lsetxattr → canonical lsetxattr=6 (SAME name+shape)
    direct(189, "lsetxattr", 6),
    // x86_64=190 fsetxattr → canonical fsetxattr=7 (SAME name+shape)
    direct(190, "fsetxattr", 7),
    // x86_64=191 getxattr → canonical getxattr=8 (SAME name+shape)
    direct(191, "getxattr", 8),
    // x86_64=192 lgetxattr → canonical lgetxattr=9 (SAME name+shape)
    direct(192, "lgetxattr", 9),
    // x86_64=193 fgetxattr → canonical fgetxattr=10 (SAME name+shape)
    direct(193, "fgetxattr", 10),
    // x86_64=194 listxattr → canonical listxattr=11 (SAME name+shape)
    direct(194, "listxattr", 11),
    // x86_64=195 llistxattr → canonical llistxattr=12 (SAME name+shape)
    direct(195, "llistxattr", 12),
    // x86_64=196 flistxattr → canonical flistxattr=13 (SAME name+shape)
    direct(196, "flistxattr", 13),
    // x86_64=197 removexattr → canonical removexattr=14 (SAME name+shape)
    direct(197, "removexattr", 14),
    // x86_64=198 lremovexattr → canonical lremovexattr=15 (SAME name+shape)
    direct(198, "lremovexattr", 15),
    // x86_64=199 fremovexattr → canonical fremovexattr=16 (SAME name+shape)
    direct(199, "fremovexattr", 16),
    // x86_64=200 (syscalls(2)/filippo) → canonical tkill=130.
    // musl calls tkill(tid, SIGABRT) to abort.
    direct(200, "tkill", 130),
    // x86_64=201 time: LEGACY x86_64-only, NO asm-generic equivalent → Unknown
    // (asm-generic implements time() via clock_gettime/gettimeofday).
    // x86_64=202 (syscalls(2)/filippo) → canonical futex=98.
    // pthread mutex/join block on futex.
    direct(202, "futex", 98),
    // x86_64=203 sched_setaffinity → canonical sched_setaffinity=122 (SAME)
    direct(203, "sched_setaffinity", 122),
    // x86_64=204 sched_getaffinity → canonical sched_getaffinity=123 (SAME)
    direct(204, "sched_getaffinity", 123),
    // x86_64=205 set_thread_area: x86_64-private TLS op (LDT/GDT), NO asm-generic
    //   equivalent → Unknown.
    // x86_64=206 io_setup → canonical io_setup=0 (SAME name+shape)
    direct(206, "io_setup", 0),
    // x86_64=207 io_destroy → canonical io_destroy=1 (SAME name+shape)
    direct(207, "io_destroy", 1),
    // x86_64=208 io_getevents → canonical io_getevents=4 (SAME name+shape)
    direct(208, "io_getevents", 4),
    // x86_64=209 io_submit → canonical io_submit=2 (SAME name+shape)
    direct(209, "io_submit", 2),
    // x86_64=210 io_cancel → canonical io_cancel=3 (SAME name+shape)
    direct(210, "io_cancel", 3),
    // x86_64=211 get_thread_area: x86_64-private TLS op, NO asm-generic equiv → Unknown.
    // x86_64=212 lookup_dcookie → canonical lookup_dcookie=18 (SAME name+shape)
    direct(212, "lookup_dcookie", 18),
    // x86_64=213 epoll_create: LEGACY (asm-generic has epoll_create1=20).
    // epoll_create(size) vs epoll_create1(flags) → DIFFERENT semantics → LEFT OUT.
    // x86_64=214 epoll_ctl_old, 215 epoll_wait_old: obsolete x86_64-only → Unknown.
    // x86_64=216 remap_file_pages → canonical remap_file_pages=234 (SAME)
    direct(216, "remap_file_pages", 234),
    // x86_64=217 getdents64 → canonical getdents64=61 (SAME name+shape)
    direct(217, "getdents64", 61),
    // x86_64=218 (syscalls(2)/filippo) → canonical set_tid_address=96
    direct(218, "set_tid_address", 96),
    // x86_64=219 restart_syscall → canonical restart_syscall=128 (SAME name+shape)
    direct(219, "restart_syscall", 128),
    // x86_64=220 semtimedop → canonical semtimedop=192 (SAME name+shape)
    direct(220, "semtimedop", 192),
    // x86_64=221 fadvise64 → canonical fadvise64=223 (SAME name+shape)
    direct(221, "fadvise64", 223),
    // x86_64=222 timer_create → canonical timer_create=107 (SAME name+shape)
    direct(222, "timer_create", 107),
    // x86_64=223 timer_settime → canonical timer_settime=110 (SAME name+shape)
    direct(223, "timer_settime", 110),
    // x86_64=224 timer_gettime → canonical timer_gettime=108 (SAME name+shape)
    direct(224, "timer_gettime", 108),
    // x86_64=225 timer_getoverrun → canonical timer_getoverrun=109 (SAME)
    direct(225, "timer_getoverrun", 109),
    // x86_64=226 timer_delete → canonical timer_delete=111 (SAME name+shape)
    direct(226, "timer_delete", 111),
    // x86_64=227 clock_settime → canonical clock_settime=112 (SAME name+shape)
    direct(227, "clock_settime", 112),
    // x86_64=228 clock_gettime → canonical clock_gettime=113 (SAME name+shape)
    direct(228, "clock_gettime", 113),
    // x86_64=229 clock_getres → canonical clock_getres=114 (SAME name+shape)
    direct(229, "clock_getres", 114),
    // x86_64=230 clock_nanosleep → canonical clock_nanosleep=115 (SAME name+shape)
    direct(230, "clock_nanosleep", 115),
    // x86_64=231 (syscalls(2)/filippo) → canonical exit_group=94
    direct(231, "exit_group", 94),
    // x86_64=232 epoll_wait: LEGACY (asm-generic has epoll_pwait=22).
    // epoll_wait(epfd,events,max,timeout) vs epoll_pwait(...,*sigmask,size) →
    // DIFFERENT arg shape → LEFT OUT. (see deferred block)
    // x86_64=233 epoll_ctl → canonical epoll_ctl=21 (SAME name+shape)
    direct(233, "epoll_ctl", 21),
    // x86_64=234 tgkill → canonical tgkill=131 (SAME name+shape)
    direct(234, "tgkill", 131),
    // x86_64=235 utimes: LEGACY x86_64-only (asm-generic has utimensat=88).
    // utimes(path,*timeval[2]) vs utimensat(dfd,path,*timespec[2],flags) → LEFT OUT.
    // x86_64=236 vserver: never implemented, reserved x86_64-only → Unknown.
    // x86_64=237 mbind → canonical mbind=235 (SAME name+shape)
    direct(237, "mbind", 235),
    // x86_64=238 set_mempolicy → canonical set_mempolicy=237 (SAME name+shape)
    direct(238, "set_mempolicy", 237),
    // x86_64=239 get_mempolicy → canonical get_mempolicy=236 (SAME name+shape)
    direct(239, "get_mempolicy", 236),
    // x86_64=240 mq_open → canonical mq_open=180 (SAME name+shape)
    direct(240, "mq_open", 180),
    // x86_64=241 mq_unlink → canonical mq_unlink=181 (SAME name+shape)
    direct(241, "mq_unlink", 181),
    // x86_64=242 mq_timedsend → canonical mq_timedsend=182 (SAME name+shape)
    direct(242, "mq_timedsend", 182),
    // x86_64=243 mq_timedreceive → canonical mq_timedreceive=183 (SAME name+shape)
    direct(243, "mq_timedreceive", 183),
    // x86_64=244 mq_notify → canonical mq_notify=184 (SAME name+shape)
    direct(244, "mq_notify", 184),
    // x86_64=245 mq_getsetattr → canonical mq_getsetattr=185 (SAME name+shape)
    direct(245, "mq_getsetattr", 185),
    // x86_64=246 kexec_load → canonical kexec_load=104 (SAME name+shape)
    direct(246, "kexec_load", 104),
    // x86_64=247 waitid → canonical waitid=95 (SAME name+shape)
    direct(247, "waitid", 95),
    // x86_64=248 add_key → canonical add_key=217 (SAME name+shape)
    direct(248, "add_key", 217),
    // x86_64=249 request_key → canonical request_key=218 (SAME name+shape)
    direct(249, "request_key", 218),
    // x86_64=250 keyctl → canonical keyctl=219 (SAME name+shape)
    direct(250, "keyctl", 219),
    // x86_64=251 ioprio_set → canonical ioprio_set=30 (SAME name+shape)
    direct(251, "ioprio_set", 30),
    // x86_64=252 ioprio_get → canonical ioprio_get=31 (SAME name+shape)
    direct(252, "ioprio_get", 31),
    // x86_64=253 inotify_init: LEGACY (asm-generic has inotify_init1=26).
    // inotify_init() vs inotify_init1(flags) → DIFFERENT arity → LEFT OUT.
    // x86_64=254 inotify_add_watch → canonical inotify_add_watch=27 (SAME)
    direct(254, "inotify_add_watch", 27),
    // x86_64=255 inotify_rm_watch → canonical inotify_rm_watch=28 (SAME)
    direct(255, "inotify_rm_watch", 28),
    // x86_64=256 migrate_pages → canonical migrate_pages=238 (SAME name+shape)
    direct(256, "migrate_pages", 238),
    // x86_64=257 openat → canonical openat=56 (SAME name+shape)
    direct(257, "openat", 56),
    // x86_64=258 mkdirat → canonical mkdirat=34 (SAME name+shape)
    direct(258, "mkdirat", 34),
    // x86_64=259 mknodat → canonical mknodat=33 (SAME name+shape)
    direct(259, "mknodat", 33),
    // x86_64=260 fchownat → canonical fchownat=54 (SAME name+shape)
    direct(260, "fchownat", 54),
    // x86_64=261 futimesat: LEGACY x86_64-only (asm-generic has utimensat=88).
    // futimesat(dfd,path,*timeval[2]) vs utimensat(dfd,path,*timespec[2],flags) →
    // LEFT OUT. (see deferred block)
    // x86_64=262 newfstatat → canonical newfstatat=79 (SAME name+shape)
    direct(262, "newfstatat", 79),
    // x86_64=263 unlinkat → canonical unlinkat=35 (SAME name+shape)
    direct(263, "unlinkat", 35),
    // x86_64=264 renameat → canonical renameat=38 (SAME name+shape)
    direct(264, "renameat", 38),
    // x86_64=265 linkat → canonical linkat=37 (SAME name+shape)
    direct(265, "linkat", 37),
    // x86_64=266 symlinkat → canonical symlinkat=36 (SAME name+shape)
    direct(266, "symlinkat", 36),
    // x86_64=267 readlinkat → canonical readlinkat=78 (SAME name+shape)
    direct(267, "readlinkat", 78),
    // x86_64=268 fchmodat → canonical fchmodat=53 (SAME name+shape)
    direct(268, "fchmodat", 53),
    // x86_64=269 faccessat → canonical faccessat=48 (SAME name+shape)
    direct(269, "faccessat", 48),
    // x86_64=270 pselect6 → canonical pselect6=72 (SAME name+shape)
    direct(270, "pselect6", 72),
    // x86_64=271 ppoll → canonical ppoll=73 (SAME name+shape)
    direct(271, "ppoll", 73),
    // x86_64=272 unshare → canonical unshare=97 (SAME name+shape)
    direct(272, "unshare", 97),
    // x86_64=273 (syscalls(2)/filippo) → canonical set_robust_list=99.
    // glibc/musl thread setup registers a robust-futex list.
    direct(273, "set_robust_list", 99),
    // x86_64=274 get_robust_list → canonical get_robust_list=100 (SAME name+shape)
    direct(274, "get_robust_list", 100),
    // x86_64=275 splice → canonical splice=76 (SAME name+shape)
    direct(275, "splice", 76),
    // x86_64=276 tee → canonical tee=77 (SAME name+shape)
    direct(276, "tee", 77),
    // x86_64=277 sync_file_range → canonical sync_file_range=84 (SAME name+shape)
    direct(277, "sync_file_range", 84),
    // x86_64=278 vmsplice → canonical vmsplice=75 (SAME name+shape)
    direct(278, "vmsplice", 75),
    // x86_64=279 move_pages → canonical move_pages=239 (SAME name+shape)
    direct(279, "move_pages", 239),
    // x86_64=280 utimensat → canonical utimensat=88 (SAME name+shape)
    direct(280, "utimensat", 88),
    // x86_64=281 epoll_pwait → canonical epoll_pwait=22 (SAME name+shape)
    direct(281, "epoll_pwait", 22),
    // x86_64=282 signalfd: LEGACY (asm-generic has signalfd4=74).
    // signalfd(fd,*mask,sizemask) vs signalfd4(fd,*mask,sizemask,flags) → LEFT OUT.
    // x86_64=283 timerfd_create → canonical timerfd_create=85 (SAME name+shape)
    direct(283, "timerfd_create", 85),
    // x86_64=284 eventfd: LEGACY (asm-generic has eventfd2=19).
    // eventfd(count) vs eventfd2(count,flags) → DIFFERENT arity → LEFT OUT.
    // x86_64=285 fallocate → canonical fallocate=47 (SAME name+shape)
    direct(285, "fallocate", 47),
    // x86_64=286 timerfd_settime → canonical timerfd_settime=86 (SAME name+shape)
    direct(286, "timerfd_settime", 86),
    // x86_64=287 timerfd_gettime → canonical timerfd_gettime=87 (SAME name+shape)
    direct(287, "timerfd_gettime", 87),
    // x86_64=288 accept4 → canonical accept4=242 (SAME name+shape)
    direct(288, "accept4", 242),
    // x86_64=289 signalfd4 → canonical signalfd4=74 (SAME name+shape)
    direct(289, "signalfd4", 74),
    // x86_64=290 eventfd2 → canonical eventfd2=19 (SAME name+shape)
    direct(290, "eventfd2", 19),
    // x86_64=291 epoll_create1 → canonical epoll_create1=20 (SAME name+shape)
    direct(291, "epoll_create1", 20),
    // x86_64=292 dup3 → canonical dup3=24 (SAME name+shape)
    direct(292, "dup3", 24),
    // x86_64=293 pipe2 → canonical pipe2=59 (SAME name+shape)
    direct(293, "pipe2", 59),
    // x86_64=294 inotify_init1 → canonical inotify_init1=26 (SAME name+shape)
    direct(294, "inotify_init1", 26),
    // x86_64=295 preadv → canonical preadv=69 (SAME name+shape)
    direct(295, "preadv", 69),
    // x86_64=296 pwritev → canonical pwritev=70 (SAME name+shape)
    direct(296, "pwritev", 70),
    // x86_64=297 rt_tgsigqueueinfo → canonical rt_tgsigqueueinfo=240 (SAME)
    direct(297, "rt_tgsigqueueinfo", 240),
    // x86_64=298 perf_event_open → canonical perf_event_open=241 (SAME name+shape)
    direct(298, "perf_event_open", 241),
    // x86_64=299 recvmmsg → canonical recvmmsg=243 (SAME name+shape)
    direct(299, "recvmmsg", 243),
    // x86_64=300 fanotify_init → canonical fanotify_init=262 (SAME name+shape)
    direct(300, "fanotify_init", 262),
    // x86_64=301 fanotify_mark → canonical fanotify_mark=263 (SAME name+shape)
    direct(301, "fanotify_mark", 263),
    // x86_64=302 prlimit64 → canonical prlimit64=261 (SAME name+shape)
    direct(302, "prlimit64", 261),
    // x86_64=303 name_to_handle_at → canonical name_to_handle_at=264 (SAME)
    direct(303, "name_to_handle_at", 264),
    // x86_64=304 open_by_handle_at → canonical open_by_handle_at=265 (SAME)
    direct(304, "open_by_handle_at", 265),
    // x86_64=305 clock_adjtime → canonical clock_adjtime=266 (SAME name+shape)
    direct(305, "clock_adjtime", 266),
    // x86_64=306 syncfs → canonical syncfs=267 (SAME name+shape)
    direct(306, "syncfs", 267),
    // x86_64=307 sendmmsg → canonical sendmmsg=269 (SAME name+shape)
    direct(307, "sendmmsg", 269),
    // x86_64=308 setns → canonical setns=268 (SAME name+shape)
    direct(308, "setns", 268),
    // x86_64=309 getcpu → canonical getcpu=168 (SAME name+shape)
    direct(309, "getcpu", 168),
    // x86_64=310 process_vm_readv → canonical process_vm_readv=270 (SAME)
    direct(310, "process_vm_readv", 270),
    // x86_64=311 process_vm_writev → canonical process_vm_writev=271 (SAME)
    direct(311, "process_vm_writev", 271),
    // x86_64=312 kcmp → canonical kcmp=272 (SAME name+shape)
    direct(312, "kcmp", 272),
    // x86_64=313 finit_module → canonical finit_module=273 (SAME name+shape)
    direct(313, "finit_module", 273),
    // x86_64=314 sched_setattr → canonical sched_setattr=274 (SAME name+shape)
    direct(314, "sched_setattr", 274),
    // x86_64=315 sched_getattr → canonical sched_getattr=275 (SAME name+shape)
    direct(315, "sched_getattr", 275),
    // x86_64=316 renameat2 → canonical renameat2=276 (SAME name+shape)
    direct(316, "renameat2", 276),
    // x86_64=317 seccomp → canonical seccomp=277 (SAME name+shape)
    direct(317, "seccomp", 277),
    // x86_64=318 getrandom → canonical getrandom=278 (SAME name+shape)
    direct(318, "getrandom", 278),
    // x86_64=319 memfd_create → canonical memfd_create=279 (SAME name+shape)
    direct(319, "memfd_create", 279),
    // x86_64=320 kexec_file_load → canonical kexec_file_load=294 (SAME name+shape)
    direct(320, "kexec_file_load", 294),
    // x86_64=321 bpf → canonical bpf=280 (SAME name+shape)
    direct(321, "bpf", 280),
    // x86_64=322 execveat → canonical execveat=281 (SAME name+shape)
    direct(322, "execveat", 281),
    // x86_64=323 userfaultfd → canonical userfaultfd=282 (SAME name+shape)
    direct(323, "userfaultfd", 282),
    // x86_64=324 membarrier → canonical membarrier=283 (SAME name+shape)
    direct(324, "membarrier", 283),
    // x86_64=325 mlock2 → canonical mlock2=284 (SAME name+shape)
    direct(325, "mlock2", 284),
    // x86_64=326 copy_file_range → canonical copy_file_range=285 (SAME name+shape)
    direct(326, "copy_file_range", 285),
    // x86_64=327 preadv2 → canonical preadv2=286 (SAME name+shape)
    direct(327, "preadv2", 286),
    // x86_64=328 pwritev2 → canonical pwritev2=287 (SAME name+shape)
    direct(328, "pwritev2", 287),
    // x86_64=329 pkey_mprotect → canonical pkey_mprotect=288 (SAME name+shape)
    direct(329, "pkey_mprotect", 288),
    // x86_64=330 pkey_alloc → canonical pkey_alloc=289 (SAME name+shape)
    direct(330, "pkey_alloc", 289),
    // x86_64=331 pkey_free → canonical pkey_free=290 (SAME name+shape)
    direct(331, "pkey_free", 290),
    // x86_64=332 statx → canonical statx=291 (SAME name+shape)
    direct(332, "statx", 291),
    // x86_64=333 io_pgetevents → canonical io_pgetevents=292 (SAME name+shape)
    direct(333, "io_pgetevents", 292),
    // x86_64=334 rseq → canonical rseq=293 (SAME name+shape)
    direct(334, "rseq", 293),
    // x86_64=424 pidfd_send_signal → canonical pidfd_send_signal=424 (SAME number+shape)
    direct(424, "pidfd_send_signal", 424),
    // x86_64=425 io_uring_setup → canonical io_uring_setup=425 (SAME number+shape)
    direct(425, "io_uring_setup", 425),
    // x86_64=426 io_uring_enter → canonical io_uring_enter=426 (SAME number+shape)
    direct(426, "io_uring_enter", 426),
    // x86_64=427 io_uring_register → canonical io_uring_register=427 (SAME number+shape)
    direct(427, "io_uring_register", 427),
    // x86_64=428 open_tree → canonical open_tree=428 (SAME number+shape)
    direct(428, "open_tree", 428),
    // x86_64=429 move_mount → canonical move_mount=429 (SAME number+shape)
    direct(429, "move_mount", 429),
    // x86_64=430 fsopen → canonical fsopen=430 (SAME number+shape)
    direct(430, "fsopen", 430),
    // x86_64=431 fsconfig → canonical fsconfig=431 (SAME number+shape)
    direct(431, "fsconfig", 431),
    // x86_64=432 fsmount → canonical fsmount=432 (SAME number+shape)
    direct(432, "fsmount", 432),
    // x86_64=433 fspick → canonical fspick=433 (SAME number+shape)
    direct(433, "fspick", 433),
    // x86_64=434 pidfd_open → canonical pidfd_open=434 (SAME number+shape)
    direct(434, "pidfd_open", 434),
    // x86_64=435 clone3 → canonical clone3=435 (SAME number; struct-based, NO arg
    // swap — normalize_syscall deliberately does NOT desugar/swap 435).
    direct(435, "clone3", 435),
    // x86_64=436 close_range → canonical close_range=436 (SAME number+shape)
    direct(436, "close_range", 436),
    // x86_64=437 openat2 → canonical openat2=437 (SAME number+shape)
    direct(437, "openat2", 437),
    // x86_64=438 pidfd_getfd → canonical pidfd_getfd=438 (SAME number+shape)
    direct(438, "pidfd_getfd", 438),
    // x86_64=439 faccessat2 → canonical faccessat2=439 (SAME number+shape)
    direct(439, "faccessat2", 439),
    // x86_64=440 process_madvise → canonical process_madvise=440 (SAME number+shape)
    direct(440, "process_madvise", 440),
    // x86_64=441 epoll_pwait2 → canonical epoll_pwait2=441 (SAME number+shape)
    direct(441, "epoll_pwait2", 441),
    // x86_64=442 mount_setattr → canonical mount_setattr=442 (SAME number+shape)
    direct(442, "mount_setattr", 442),
    // x86_64=443 quotactl_fd → canonical quotactl_fd=443 (SAME number+shape)
    direct(443, "quotactl_fd", 443),
    // x86_64=444 landlock_create_ruleset → canonical 444 (SAME number+shape)
    direct(444, "landlock_create_ruleset", 444),
    // x86_64=445 landlock_add_rule → canonical landlock_add_rule=445 (SAME)
    direct(445, "landlock_add_rule", 445),
    // x86_64=446 landlock_restrict_self → canonical 446 (SAME number+shape)
    direct(446, "landlock_restrict_self", 446),
    // x86_64=447 memfd_secret → canonical memfd_secret=447 (SAME number+shape)
    direct(447, "memfd_secret", 447),
    // x86_64=448 process_mrelease → canonical process_mrelease=448 (SAME)
    direct(448, "process_mrelease", 448),
    // x86_64=449 futex_waitv → canonical futex_waitv=449 (SAME number+shape)
    direct(449, "futex_waitv", 449),
    // x86_64=450 set_mempolicy_home_node → canonical 450 (SAME number+shape)
    direct(450, "set_mempolicy_home_node", 450),
    // x86_64=451 cachestat → canonical cachestat=451 (SAME number+shape)
    direct(451, "cachestat", 451),
    // x86_64=452 fchmodat2 → canonical fchmodat2=452 (SAME number+shape)
    direct(452, "fchmodat2", 452),
    // x86_64=453 map_shadow_stack → canonical map_shadow_stack=453 (SAME)
    direct(453, "map_shadow_stack", 453),
    // x86_64=454 futex_wake → canonical futex_wake=454 (SAME number+shape)
    direct(454, "futex_wake", 454),
    // ── DEFERRED: legacy x86_64-only syscalls left OUT (Unknown → -ENOSYS) ──────
    //
    // Each has an asm-generic SUCCESSOR with a DIFFERENT name AND a different arg
    // shape; emitting a naive Direct(successor) would silently feed the wrong arg
    // layout to the canonical handler (worse than an honest ENOSYS). They need a
    // per-syscall arg-translation shim in x8664_arch::normalize_syscall (deferred,
    // oracle-gated). All numbers from syscalls(2)/filippo/OSDev.
    //
    //   2   open        → openat(56):     prepend AT_FDCWD; (path,flags,mode)→(dfd,path,flags,mode)
    //   4   stat        → newfstatat(79): prepend AT_FDCWD + flags=0; statbuf layout differs
    //   5   fstat       → fstat(80):      x86-64 struct stat layout ≠ asm-generic (field offsets)
    //   6   lstat       → newfstatat(79): AT_FDCWD + AT_SYMLINK_NOFOLLOW
    //   21  access      → faccessat(48):  prepend AT_FDCWD; append flags=0
    //   23  select      → pselect6(72):   timeval→timespec; no sigmask arg
    //   33  dup2        → dup3(24):       dup2(fd,fd)=success no-op vs dup3 EINVAL; no flags arg
    //   78  getdents    → getdents64(61): 32-bit linux_dirent vs 64-bit linux_dirent64
    //   82  rename      → renameat(38):   prepend AT_FDCWD to both paths
    //   83  mkdir       → mkdirat(34):    prepend AT_FDCWD
    //   84  rmdir       → unlinkat(35):   prepend AT_FDCWD; set AT_REMOVEDIR
    //   85  creat       → openat(56):     flags=O_CREAT|O_WRONLY|O_TRUNC; prepend AT_FDCWD
    //   86  link        → linkat(37):     prepend AT_FDCWD to both; flags=0
    //   87  unlink      → unlinkat(35):   prepend AT_FDCWD; flags=0
    //   88  symlink     → symlinkat(36):  insert AT_FDCWD before newpath
    //   89  readlink    → readlinkat(78): prepend AT_FDCWD
    //   90  chmod       → fchmodat(53):   prepend AT_FDCWD; append flags=0
    //   92  chown       → fchownat(54):   prepend AT_FDCWD; append flags=0
    //   94  lchown      → fchownat(54):   prepend AT_FDCWD; flags=AT_SYMLINK_NOFOLLOW
    //   132 utime       → utimensat(88):  utimbuf→timespec[2]; prepend AT_FDCWD
    //   133 mknod       → mknodat(33):    prepend AT_FDCWD
    //   201 time        → (no successor):  asm-generic libc uses clock_gettime/gettimeofday
    //   213 epoll_create→ epoll_create1(20): size arg dropped; flags=0
    //   232 epoll_wait  → epoll_pwait(22): append sigmask=NULL, sigsetsize=0
    //   235 utimes      → utimensat(88):  timeval[2]→timespec[2]; prepend AT_FDCWD
    //   253 inotify_init→ inotify_init1(26): append flags=0
    //   261 futimesat   → utimensat(88):  timeval[2]→timespec[2]
    //   282 signalfd    → signalfd4(74):  append flags=0
    //   284 eventfd     → eventfd2(19):   append flags=0
    //   7   poll        → ppoll(73):      timeout_ms→*timespec; (the Direct above is
    //                                     a bring-up convenience, NOT a faithful shim)
    //
    // Also LEFT OUT (no asm-generic equivalent AT ALL → honest -ENOSYS, NOT a
    // shim candidate): 34 pause, 37 alarm, 111 getpgrp, 134 uselib, 136 ustat,
    // 139 sysfs, 154 modify_ldt, 156 _sysctl, 172 iopl, 173 ioperm,
    // 174 create_module, 177 get_kernel_syms, 178 query_module, 180 nfsservctl,
    // 181 getpmsg, 182 putpmsg, 183 afs_syscall, 184 tuxcall, 185 security,
    // 205 set_thread_area, 211 get_thread_area, 214 epoll_ctl_old,
    // 215 epoll_wait_old, 236 vserver.
];

// Compile-time guard: the table MUST stay strictly sorted (uniqueness +
// binary-search validity). A bad insert or duplicate fails the BUILD with
// this message rather than silently producing wrong lookups at runtime.
const _: () = {
    let mut i = 1;
    while i < X86_64_SYSCALLS.len() {
        assert!(
            X86_64_SYSCALLS[i - 1].number < X86_64_SYSCALLS[i].number,
            "X86_64_SYSCALLS must stay strictly sorted by syscall number \
             (binary_search validity + number uniqueness)",
        );
        i += 1;
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_remaps_to_canonical_64() {
        let e = lookup_x86_64(1).expect("write must be in the table");
        assert_eq!(e.name, "write");
        assert_eq!(e.remap, SyscallRemap::Direct(64));
    }

    #[test]
    fn exit_remaps_to_canonical_93() {
        let e = lookup_x86_64(60).expect("exit must be in the table");
        assert_eq!(e.name, "exit");
        assert_eq!(e.remap, SyscallRemap::Direct(93));
    }

    #[test]
    fn exit_group_remaps_to_canonical_94() {
        let e = lookup_x86_64(231).expect("exit_group must be in the table");
        assert_eq!(e.name, "exit_group");
        assert_eq!(e.remap, SyscallRemap::Direct(94));
    }

    #[test]
    fn brk_remaps_to_canonical_214() {
        let e = lookup_x86_64(12).expect("brk must be in the table");
        assert_eq!(e.name, "brk");
        assert_eq!(e.remap, SyscallRemap::Direct(214));
    }

    #[test]
    fn mmap_remaps_to_canonical_222() {
        let e = lookup_x86_64(9).expect("mmap must be in the table");
        assert_eq!(e.name, "mmap");
        assert_eq!(e.remap, SyscallRemap::Direct(222));
    }

    #[test]
    fn rt_sigreturn_remaps_to_canonical_139() {
        let e = lookup_x86_64(15).expect("rt_sigreturn must be in the table");
        assert_eq!(e.name, "rt_sigreturn");
        assert_eq!(e.remap, SyscallRemap::Direct(139));
    }

    #[test]
    fn clone_remaps_to_canonical_220() {
        let e = lookup_x86_64(56).expect("clone must be in the table");
        assert_eq!(e.name, "clone");
        assert_eq!(e.remap, SyscallRemap::Direct(220));
    }

    #[test]
    fn wait4_remaps_to_canonical_260() {
        let e = lookup_x86_64(61).expect("wait4 must be in the table");
        assert_eq!(e.name, "wait4");
        assert_eq!(e.remap, SyscallRemap::Direct(260));
    }

    #[test]
    fn futex_gettid_set_robust_list_present() {
        assert_eq!(lookup_x86_64(202).unwrap().remap, SyscallRemap::Direct(98)); // futex
        assert_eq!(lookup_x86_64(186).unwrap().remap, SyscallRemap::Direct(178)); // gettid
        assert_eq!(lookup_x86_64(273).unwrap().remap, SyscallRemap::Direct(99)); // set_robust_list
    }

    #[test]
    fn arch_prctl_is_native() {
        let e = lookup_x86_64(158).expect("arch_prctl must be in the table");
        assert_eq!(e.name, "arch_prctl");
        assert_eq!(e.remap, SyscallRemap::Native);
    }

    #[test]
    fn iopl_is_not_in_table() {
        // x86_64 iopl=172 — not in our initial table (no canonical equivalent)
        assert!(lookup_x86_64(172).is_none());
    }

    #[test]
    fn table_is_strictly_sorted() {
        for w in X86_64_SYSCALLS.windows(2) {
            assert!(
                w[0].number < w[1].number,
                "X86_64_SYSCALLS out of order: {} >= {}",
                w[0].number,
                w[1].number
            );
        }
    }

    /// The real cross-check the file's doc comment promises: for every
    /// `Direct(c)` entry, prove there EXISTS an `AARCH64_SYSCALLS` entry at
    /// number `c` whose name equals this x86 entry's name. This catches any
    /// wrong canonical mapping (e.g. a typo'd number that lands on a different
    /// canonical syscall) at test time — the const sortedness guard cannot do
    /// this because it can't index `AARCH64_SYSCALLS` by name in const context.
    #[test]
    fn every_direct_canonical_matches_aarch64_by_name() {
        // `aarch64_table()` is the public accessor for `AARCH64_SYSCALLS`
        // (the static itself is module-private).
        let aarch64 = crate::syscall::aarch64_table();
        // The ONE documented exception: x86_64 `poll`(7) is a Direct to the
        // DIFFERENTLY-named canonical `ppoll`(73). It is a deliberate bring-up
        // convenience for the musl startup fd-probe `poll(fds,n,0)` (also listed
        // in the deferred-shim block above as needing a real timeout→timespec
        // translation). Every OTHER Direct must name-match exactly.
        for e in X86_64_SYSCALLS {
            if let SyscallRemap::Direct(canonical) = e.remap {
                let found = aarch64
                    .iter()
                    .find(|a| a.number == canonical)
                    .unwrap_or_else(|| {
                        panic!(
                            "x86_64 {}={} maps to canonical {} which is absent from AARCH64_SYSCALLS",
                            e.name, e.number, canonical
                        )
                    });
                if e.name == "poll" && found.name == "ppoll" {
                    continue; // documented bring-up exception (see comment above)
                }
                assert_eq!(
                    found.name, e.name,
                    "x86_64 {}={} → Direct({}) but AARCH64_SYSCALLS[{}] is named {:?}, not {:?}",
                    e.name, e.number, canonical, canonical, found.name, e.name
                );
            }
        }
    }

    /// Sanity floor: the table now covers the whole ABI, so it must hold far
    /// more than the original ~31-entry incremental subset.
    #[test]
    fn table_covers_the_whole_abi() {
        assert!(
            X86_64_SYSCALLS.len() > 200,
            "expected the full x86_64 ABI (>200 entries), got {}",
            X86_64_SYSCALLS.len()
        );
    }
}

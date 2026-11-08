# Ring-owned pipe metadata (#1901)

Contract: `kernel.el1.ipc-fd-authority`.

Linux authority: stat(2), fcntl(2), F_GETFL(2const), F_GETPIPE_SZ(2const),
pipe(7), ioctl(2), dup(2), close(2), and lseek(2). Both pipe ends identify
one inode; separate live pipes differ. Description status flags and capacity
are shared by aliases; descriptor close-on-exec flags are private.

The structural invariant is zero host descriptor operations for a ring-owned
pipe. The production-dispatch witnesses require a completed ring route for
each call. They use the existing two-live-child native-fork fixture and test
the borrowed root table as well as the fork child's owned table. Each case
creates its pipe through pipe2. All I/O in these cases is nonblocking.

The first witness set covers fstat, empty-path newfstatat, fcntl status and
fd flags, both fcntl duplication commands, pipe capacity, FIONREAD, FIONBIO,
TCGETS, lseek, dup, dup3 and close. It is deliberately red before routing
and metadata repairs. Exec inheritance, FIOCLEX/FIONCLEX, shrink-EBUSY,
contention and x86 execution still need witnesses. No signed or end-to-end
CPython result is claimed by these VM-free tests.

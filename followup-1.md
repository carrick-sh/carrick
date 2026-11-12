# followup-1: descriptor-operand crossings on the x86 root need a table the root does not have

Part of #2157 (B1 left these unflipped on purpose): fsetxattr, fgetxattr, flistxattr, fremovexattr,
flock, fchdir, getdents64 (as a crossing), fsync, fdatasync, sync_file_range, syncfs, readahead,
fadvise64, fchown, fchmod. All carry `FdOperand::Fd{index:0}` and the shared resolver classifies
them correctly (host object -> pass/rewrite, closed -> EBADF, ring-held -> counted ENOSYS).

Why they stay unflipped. The shared handlers look the descriptor up in the *host kernel's* fd
table (`this.open_file(fd)`, `host_file_fd_for_flush`). The x86 root's stdio and every file it
opens live in the ring (a staged `openat` is a ring description over a carrier fd, e.g. guest
fd 3 is carrier fd 33), so that table is empty. Probe on a dup2'd stdout pipe, native vs carrick
(flipped build, before unflipping):

| call | native | carrick |
|---|---|---|
| fsync / fdatasync | -22 | 0 |
| flock | 0 | -9 |
| fadvise64 | -29 | 0 |
| sync_file_range | -29 | -9 |
| fchdir | -20 | -9 |
| fgetxattr / fsetxattr / flistxattr / fremovexattr | -61 / -1 / 0 / -1 | -9 |
| fchmod | 0 (and fstat(1) shows the new mode) | 0, but fstat(1) mode unchanged: no host effect |

Fix direction: either serve them through the ring's host-file venue (new `HostFileCall` ops
beside `Ftruncate`, which B1 did route for the root) or give the root's kernel context the
ring's descriptor view. Witness: the metadata/files/xattr fixtures already carry the
pipe-and-dup2 shape; add the calls back with their native results.

# followup-4: a ring-held directory descriptor as dirfd, and path inputs on never-touched pages

Part of #2157. (a) `FdOperand::DirFd` is "consulted only for a relative path and resolved by the
path's owner". The x86 root's directory descriptors are ring descriptions, so mkdirat/unlinkat/
renameat/... with a relative path and a ring-held dirfd crosses with a number the host kernel
does not have (EBADF at best). The B1 witnesses use AT_FDCWD only. Needs a dirfd -> path
resolution in ring before the crossing.
(b) A path *read* from a never-touched anonymous page: `mkdirat(AT_FDCWD, <untouched page>, 0755)`
answers -14 on carrick and -2 (ENOENT, the empty string) natively. T3 in B1 prepares *outputs*
only. Real paths are written before use, so this is a degenerate case, but a file-backed or
copy-on-write path page could hit it.

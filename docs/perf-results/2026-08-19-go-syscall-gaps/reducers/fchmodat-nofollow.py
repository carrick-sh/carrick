#!/usr/bin/env python3
"""RED-FIRST: fchmodat/fchmodat2 with AT_SYMLINK_NOFOLLOW.

Go's TestFchmodat expects EOPNOTSUPP; carrick returns success. Ask the raw
syscalls directly on both sides so the gap is attributed to a syscall answer.
aarch64: fchmodat=53, fchmodat2=452. AT_SYMLINK_NOFOLLOW=0x100.
"""
import ctypes, errno, os, sys

libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD, AT_SYMLINK_NOFOLLOW = -100, 0x100
SYS_fchmodat, SYS_fchmodat2 = 53, 452

os.chdir("/tmp")
for p in ("f_reg", "f_link"):
    try: os.remove(p)
    except OSError: pass
open("f_reg", "w").close()
os.symlink("f_reg", "f_link")

def call(nr, name, path, flags):
    ctypes.set_errno(0)
    if nr == SYS_fchmodat:
        rc = libc.syscall(nr, AT_FDCWD, path.encode(), 0o644, flags)
    else:
        rc = libc.syscall(nr, AT_FDCWD, path.encode(), 0o644, flags)
    e = ctypes.get_errno()
    print("%-10s(%-6s, flags=0x%03x) rc=%-3d errno=%d (%s)"
          % (name, path, flags, rc, e, errno.errorcode.get(e, "-")), flush=True)

for path in ("f_reg", "f_link"):
    call(SYS_fchmodat,  "fchmodat",  path, 0)
    call(SYS_fchmodat,  "fchmodat",  path, AT_SYMLINK_NOFOLLOW)
    call(SYS_fchmodat2, "fchmodat2", path, AT_SYMLINK_NOFOLLOW)
sys.stdout.flush()

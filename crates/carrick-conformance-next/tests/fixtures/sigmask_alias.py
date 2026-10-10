import ctypes as c
import platform

arch = platform.machine().lower()
if arch in ("aarch64", "arm64"):
    SYS_rt_sigprocmask = 135
elif arch in ("x86_64", "amd64"):
    SYS_rt_sigprocmask = 14
else:
    raise ValueError(f"unsupported arch {arch}")

libc = c.CDLL(None, use_errno=True)
syscall = libc.syscall

SIG_BLOCK = 0
SIG_UNBLOCK = 1
SIG_SETMASK = 2
SIGSET_SIZE = 8

def get_mask():
    cur = c.c_uint64(0)
    res = syscall(SYS_rt_sigprocmask, SIG_SETMASK, None, c.byref(cur), SIGSET_SIZE)
    assert res == 0, f"failed to read mask: res={res}, errno={c.get_errno()}"
    return cur.value

def set_mask(val):
    new_mask = c.c_uint64(val)
    res = syscall(SYS_rt_sigprocmask, SIG_SETMASK, c.byref(new_mask), None, SIGSET_SIZE)
    assert res == 0, f"failed to set mask: res={res}, errno={c.get_errno()}"

# 1. Normal non-aliased case:
# Set initial mask to 0x10, then block 0x20 into a separate oldset buffer.
set_mask(0x10)
normal_set = c.c_uint64(0x20)
normal_old = c.c_uint64(0)
c.set_errno(0)
res = syscall(SYS_rt_sigprocmask, SIG_BLOCK, c.byref(normal_set), c.byref(normal_old), SIGSET_SIZE)
err = c.get_errno()
mask = get_mask()
print(f"normal_res={res}", flush=True)
print(f"normal_errno={err}", flush=True)
print(f"normal_oldset={hex(normal_old.value)}", flush=True)
print(f"normal_mask={hex(mask)}", flush=True)

# 2. Invalid how with valid set and oldset buffers:
# oldset buffer has a sentinel value; Linux validates `how` before writing oldset,
# leaving oldset untouched and returning -1 with EINVAL (22).
sentinel = 0x12345678deadbeef
invalid_old = c.c_uint64(sentinel)
valid_set = c.c_uint64(0x40)
c.set_errno(0)
res = syscall(SYS_rt_sigprocmask, 999, c.byref(valid_set), c.byref(invalid_old), SIGSET_SIZE)
err = c.get_errno()
mask = get_mask()
print(f"invalid_how_res={res}", flush=True)
print(f"invalid_how_errno={err}", flush=True)
print(f"invalid_how_oldset={hex(invalid_old.value)}", flush=True)
print(f"invalid_how_mask={hex(mask)}", flush=True)

# 3. Aliased set and oldset:
# Caller passes the same buffer for both set and oldset.
# Set initial mask to 0x10, buffer has 0x20.
# Linux reads the new set before writing the old set to the buffer,
# so the new mask becomes 0x10 | 0x20 = 0x30, and the buffer receives 0x10.
set_mask(0x10)
aliased_buf = c.c_uint64(0x20)
c.set_errno(0)
res = syscall(SYS_rt_sigprocmask, SIG_BLOCK, c.byref(aliased_buf), c.byref(aliased_buf), SIGSET_SIZE)
err = c.get_errno()
mask = get_mask()
print(f"aliased_res={res}", flush=True)
print(f"aliased_errno={err}", flush=True)
print(f"aliased_oldset={hex(aliased_buf.value)}", flush=True)
print(f"aliased_mask={hex(mask)}", flush=True)

import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
libc.realloc.restype = ctypes.c_void_p
libc.realloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.malloc.restype = ctypes.c_void_p

# glibc realloc on a >128K block uses mremap — the dict-growth shape.
size = 0x22000
p = libc.malloc(size)
ctypes.memset(p, 0xAB, size)
for newsize in (0x26000, 0x30000, 0x44000, 0x60000, 0x90000, 0xd0000, 0x140000):
    p = libc.realloc(p, newsize)
    ctypes.memset(p, 0xAB, newsize)   # dirty every byte after each grow
    size = newsize

def check(tag):
    buf = (ctypes.c_ubyte * size).from_address(p)
    bad = [off for off in range(0, size, 4096) if buf[off] != 0xAB]
    print(f"{tag}: {len(bad)} corrupt pages" + (f" first_offsets={[hex(o) for o in bad[:5]]}" if bad else ""), flush=True)
    return len(bad)

c = os.fork()
if c == 0:
    os._exit(1 if check("child") else 0)
_, st = os.waitpid(c, 0)
rc = check("parent")
print("verdict:", "FAIL" if (rc or os.waitstatus_to_exitcode(st)) else "ok", flush=True)

"""Discarding the executable header must restore its file bytes, not zeros."""
import ctypes
import os
import signal

libc = ctypes.CDLL(None, use_errno=True)
libc.getauxval.argtypes = [ctypes.c_ulong]
libc.getauxval.restype = ctypes.c_ulong
libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.madvise.restype = ctypes.c_int
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.mprotect.restype = ctypes.c_int
page = libc.getauxval(3) & ~4095  # AT_PHDR, Linux guest page size
assert page != 0
before = ctypes.string_at(page, 16)
assert before[:4] == b"\x7fELF", before.hex()
ctypes.set_errno(0)
rc = libc.madvise(page, 4096, 4)  # MADV_DONTNEED
assert rc == 0, (rc, ctypes.get_errno())
after = ctypes.string_at(page, 16)
assert after == before, (before.hex(), after.hex())
# A guest write is private even when a later discard restores the boot image.
assert libc.mprotect(page, 4096, 7) == 0, ctypes.get_errno()
ctypes.c_ubyte.from_address(page + 15).value = 0x5A
dirty = ctypes.string_at(page, 16)
assert dirty != before
signal.alarm(15)
child = os.fork()
if child == 0:
    rc = libc.madvise(page, 4096, 4)
    good = rc == 0 and ctypes.string_at(page, 16) == before
    os._exit(0 if good else 1)
_, status = os.waitpid(child, 0)
assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
assert ctypes.string_at(page, 16) == dirty, "child discard changed parent"
assert libc.madvise(page, 4096, 4) == 0, ctypes.get_errno()
assert ctypes.string_at(page, 16) == before
signal.alarm(0)
print("private_file_exec_discard=ok", flush=True)
os._exit(0)

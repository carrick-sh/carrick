import ctypes
import mmap
import os
import signal
import sys
import tempfile

signal.alarm(10)
libc = ctypes.CDLL(None, use_errno=True)
libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.mremap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int, ctypes.c_void_p]
libc.mremap.restype = ctypes.c_void_p

def address(view):
    return ctypes.addressof(ctypes.c_char.from_buffer(view))

factory = tempfile.NamedTemporaryFile if "named" in sys.argv else tempfile.TemporaryFile
with factory() as source:
    source.write(b''.join(bytes([page + 1]) * 4096 for page in range(8)))
    source.flush()
    view = mmap.mmap(source.fileno(), 32768, access=mmap.ACCESS_COPY)
    ptr = address(view)
    destination = mmap.mmap(-1, 65536, access=mmap.ACCESS_COPY) if "private-dest" in sys.argv else mmap.mmap(-1, 65536)
    dest = ((address(destination) + 16383) & ~16383) + 4096
    before = ctypes.c_ubyte.from_address(dest - 4096)
    after = ctypes.c_ubyte.from_address(dest + 32768)
    before.value = 0x31
    after.value = 0x32
    view[0] = 0x51
    moved = libc.mremap(ptr, 32768, 32768, 3, dest)
    assert moved == dest, (moved, ctypes.get_errno())
    view.close()
    data = (ctypes.c_ubyte * 32768).from_address(dest)
    assert data[0] == 0x51
    data[8192] = 0x52
    os.pwrite(source.fileno(), b'\x61', 8192)
    assert data[8192] == 0x52
    result = libc.madvise(dest + 8192, 4096, mmap.MADV_DONTNEED)
    assert result == 0, (result, ctypes.get_errno())
    assert data[8192] == 0x61, ('restore', data[8192])
    os.pwrite(source.fileno(), b'\x62', 8192)
    assert data[8192] == 0x62, ('clean_visibility', data[8192], hex(ptr), hex(dest))
    data[8192] = 0x63
    assert os.pread(source.fileno(), 1, 8192) == b'\x62', 'post-discard COW preserves source'
    assert data[8192] == 0x63
    assert data[0] == 0x51, 'dirty neighbor preserved'
    assert (before.value, after.value) == (0x31, 0x32), 'outside mapping neighbors preserved'
    del before, after, data
    destination.close()
signal.alarm(0)
print('private_file_discard_shifted=ok')

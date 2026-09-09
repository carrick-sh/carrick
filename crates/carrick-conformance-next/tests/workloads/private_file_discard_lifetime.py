import ctypes
import mmap
import os
import signal
import tempfile

signal.alarm(10)
libc = ctypes.CDLL(None, use_errno=True)
libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.mremap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int, ctypes.c_void_p]
libc.mremap.restype = ctypes.c_void_p

def address(view):
    return ctypes.addressof(ctypes.c_char.from_buffer(view))

def checked(result):
    assert result == 0, (result, ctypes.get_errno())

with tempfile.TemporaryDirectory() as directory:
    path = directory + '/source'
    original = b''.join(bytes([page + 1]) * 4096 for page in range(8))
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    assert os.write(fd, original) == len(original)
    view = mmap.mmap(fd, len(original), access=mmap.ACCESS_COPY)
    ptr = address(view)
    view[0] = 0x51
    view[4096] = 0x52
    os.pwrite(fd, b'\x61', 4096)
    assert view[4096] == 0x52
    checked(libc.madvise(ptr + 4096, 4096, mmap.MADV_DONTNEED))
    assert view[4096] == 0x61
    os.pwrite(fd, b'\x62', 4096)
    assert view[4096] == 0x62, 'discard must restore clean-page file visibility'
    assert view[0] == 0x51
    os.close(fd)
    os.unlink(path)
    with open(path, 'wb') as replacement:
        replacement.write(b'\x7f' * len(original))
    view[8192] = 0x53
    checked(libc.mprotect(ptr + 8192, 4096, 0))
    checked(libc.madvise(ptr + 8192, 4096, mmap.MADV_DONTNEED))
    checked(libc.mprotect(ptr + 8192, 4096, mmap.PROT_READ | mmap.PROT_WRITE))
    assert view[8192] == 3, 'discard must retain the unlinked source inode'
    view[12288] = 0x54
    checked(libc.mprotect(ptr + 12288, 4096, mmap.PROT_READ))
    checked(libc.madvise(ptr + 12288, 4096, mmap.MADV_DONTNEED))
    assert view[12288] == 4
    checked(libc.mprotect(ptr + 12288, 4096, mmap.PROT_READ | mmap.PROT_WRITE))
    destination = mmap.mmap(-1, len(original) + 16384)
    dest = (address(destination) + 16383) & ~16383
    moved = libc.mremap(ptr, len(original), len(original), 3, dest)
    assert moved == dest, (moved, ctypes.get_errno())
    view.close()
    bytes_at_dest = (ctypes.c_ubyte * len(original)).from_address(dest)
    assert bytes_at_dest[0] == 0x51
    bytes_at_dest[8192] = 0x55
    checked(libc.munmap(dest + 4096, 4096))
    checked(libc.madvise(dest + 8192, 4096, mmap.MADV_DONTNEED))
    assert bytes_at_dest[8192] == 3, 'trimmed/remapped source offset must survive'
    assert bytes_at_dest[0] == 0x51
    del bytes_at_dest
    destination.close()
signal.alarm(0)
print('private_file_discard_lifetime=ok')

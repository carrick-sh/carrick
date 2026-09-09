import ctypes
import mmap
import os
import select
import signal

signal.alarm(10)
fd = os.open('/bin/sh', os.O_RDONLY)
length = 32768
assert os.fstat(fd).st_size >= length
original = os.pread(fd, length, 0)
with mmap.mmap(fd, length, access=mmap.ACCESS_COPY) as view:
    address = ctypes.addressof(ctypes.c_char.from_buffer(view))
    base = (-address) % 16384
    first = original[base] ^ 0x55
    second = original[base + 4096] ^ 0xAA
    third = original[base + 8192] ^ 0x33
    view[base] = first
    view[base + 4096] = second
    assert os.pread(fd, length, 0) == original
    with mmap.mmap(fd, length, access=mmap.ACCESS_COPY) as independent:
        assert independent[:] == original
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        signal.alarm(8)
        os.close(ready_read)
        os.close(release_write)
        try:
            view[base] = first ^ 1
            view[base + 8192] = third
            os.write(ready_write, b'r')
            assert select.select([release_read], [], [], 5)[0]
            assert os.read(release_read, 1) == b'r'
            assert view[base] == first ^ 1
            assert view[base + 4096] == second
            assert view[base + 8192] == third
        except BaseException:
            os._exit(1)
        os._exit(0)
    os.close(ready_write)
    os.close(release_read)
    assert select.select([ready_read], [], [], 5)[0]
    assert os.read(ready_read, 1) == b'r'
    assert view[base] == first
    assert view[base + 8192] == original[base + 8192]
    view[base + 4096] = second ^ 1
    os.write(release_write, b'r')
    assert os.waitpid(pid, 0) == (pid, 0)
    view.madvise(mmap.MADV_DONTNEED, base + 4096, 4096)
    assert view[base + 4096] == original[base + 4096], (view[base + 4096], original[base + 4096])
    assert view[base] == first
    assert os.pread(fd, length, 0) == original
    with mmap.mmap(fd, length, access=mmap.ACCESS_COPY) as independent:
        assert independent[:] == original
    os.close(ready_read)
    os.close(release_write)
os.close(fd)
signal.alarm(0)
print('immutable_private_file=ok')

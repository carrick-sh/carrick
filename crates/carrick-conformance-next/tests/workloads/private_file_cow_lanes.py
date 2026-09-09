import ctypes
import mmap
import os
import select
import signal
import tempfile

signal.alarm(10)
with tempfile.TemporaryFile() as file:
    file.write(b"\x11" * 32768)
    file.flush()
    with mmap.mmap(file.fileno(), 32768, access=mmap.ACCESS_COPY) as view:
        address = ctypes.addressof(ctypes.c_char.from_buffer(view))
        base = (-address) % 16384
        view[base] = 0x22
        os.pwrite(file.fileno(), b"\x33", base + 4096 + 7)
        assert view[base + 4096 + 7] == 0x33
        view[base + 4096 + 8] = 0x44
        assert view[base] == 0x22
        assert view[base + 4096 + 7] == 0x33
        os.pwrite(file.fileno(), b"\x55", base + 4096 + 7)
        assert view[base + 4096 + 7] == 0x33
        os.pwrite(file.fileno(), b"\x66", base + 8192 + 7)
        assert view[base + 8192 + 7] == 0x66
        ready_read, ready_write = os.pipe()
        release_read, release_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            signal.alarm(8)
            os.close(ready_read)
            os.close(release_write)
            try:
                view[base] = 0x23
                view[base + 8192 + 8] = 0x77
                os.write(ready_write, b"r")
                assert select.select([release_read], [], [], 5)[0]
                assert os.read(release_read, 1) == b"r"
                assert view[base + 8192 + 8] == 0x77
                assert view[base] == 0x23 and view[base + 4096 + 8] == 0x44
            except BaseException:
                os._exit(1)
            os._exit(0)
        os.close(ready_write)
        os.close(release_read)
        assert select.select([ready_read], [], [], 5)[0]
        assert os.read(ready_read, 1) == b"r"
        assert view[base] == 0x22
        assert view[base + 8192 + 8] == 0x11
        view[base + 4096 + 8] = 0x45
        view[base + 8192 + 8] = 0x88
        os.write(release_write, b"r")
        assert os.waitpid(pid, 0) == (pid, 0)
        assert view[base + 8192 + 8] == 0x88
        assert view[base] == 0x22 and view[base + 4096 + 8] == 0x45
        assert os.pread(file.fileno(), 1, base) == b"\x11"
        assert os.pread(file.fileno(), 1, base + 8192 + 8) == b"\x11"
        os.pwrite(file.fileno(), b"\x99", base + 12288 + 7)
        assert view[base + 12288 + 7] == 0x99
        view[base + 12288 + 8] = 0xAA
        assert view[base + 12288 + 7] == 0x99
        assert view[base + 8192 + 8] == 0x88
        os.close(ready_read)
        os.close(release_write)
signal.alarm(0)
print("private_file_cow_lanes=ok")

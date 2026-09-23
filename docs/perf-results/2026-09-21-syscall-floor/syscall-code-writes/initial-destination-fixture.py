import ctypes as c
import os
import select
import socket
import sys

lib = c.CDLL(None, use_errno=True)

class Iov(c.Structure):
    _fields_ = [("base", c.c_void_p), ("length", c.c_size_t)]

lib.mmap.restype = c.c_void_p
lib.mmap.argtypes = [c.c_void_p, c.c_size_t, c.c_int, c.c_int, c.c_int, c.c_long]
lib.mprotect.argtypes = [c.c_void_p, c.c_size_t, c.c_int]
lib.munmap.argtypes = [c.c_void_p, c.c_size_t]
lib.readv.restype = c.c_ssize_t
lib.readv.argtypes = [c.c_int, c.POINTER(Iov), c.c_int]
lib.preadv.restype = c.c_ssize_t
lib.preadv.argtypes = [c.c_int, c.POINTER(Iov), c.c_int, c.c_long]
lib.read.restype = c.c_ssize_t
lib.read.argtypes = [c.c_int, c.c_void_p, c.c_size_t]
lib.recvfrom.restype = c.c_ssize_t
lib.recvfrom.argtypes = [c.c_int, c.c_void_p, c.c_size_t, c.c_int, c.c_void_p, c.c_void_p]
lib.clock_gettime.argtypes = [c.c_int, c.c_void_p]

source = b"0123456789abcdef" * 2048
fd = os.open(sys.argv[1], os.O_RDONLY)
p = lib.mmap(None, 16384, 3, 0x22, -1, 0)
assert p is not None and p != c.c_void_p(-1).value
# No assumption about Linux mmap returning a 16 KiB-aligned address.
c.memset(p, 0x33, 16384)
vec = (Iov * 2)(Iov(p + 4095, 3), Iov(p + 8191, 5))
assert lib.readv(fd, vec, 2) == 8, c.get_errno()
assert c.string_at(p + 4095, 3) + c.string_at(p + 8191, 5) == source[:8]
print("readv_cross_page=ok", flush=True)

assert lib.preadv(fd, vec, 2, 7) == 8, c.get_errno()
assert c.string_at(p + 4095, 3) + c.string_at(p + 8191, 5) == source[7:15]
assert os.lseek(fd, 0, os.SEEK_CUR) == 8
print("preadv_offset=ok", flush=True)

os.lseek(fd, 0, os.SEEK_SET)
assert lib.read(fd, p, 8192) == 8192, c.get_errno()
assert c.string_at(p, 8192) == source[:8192]
print("large_read=ok", flush=True)

assert lib.clock_gettime(1, p + 4096 - 8) == 0, c.get_errno()
nanoseconds = c.c_long.from_address(p + 4096).value
assert 0 <= nanoseconds < 1000000000
print("ordinary_copy_cross_page=ok", flush=True)

assert lib.mprotect(p + 8192, 4096, 1) == 0
denied = (Iov * 1)(Iov(p + 8192, 4))
c.set_errno(0)
assert (lib.readv(fd, denied, 1), c.get_errno()) == (-1, 14)
assert os.lseek(fd, 0, os.SEEK_CUR) == 8192
assert lib.mprotect(p + 8192, 4096, 3) == 0
print("readonly_efault=ok", flush=True)

receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver.bind(("127.0.0.1", 0))
sender.sendto(b"socket-data", receiver.getsockname())
assert select.select([receiver], [], [], 5)[0], "UDP readiness timeout"
assert lib.recvfrom(receiver.fileno(), p + 4092, 11, socket.MSG_DONTWAIT, None, None) == 11, c.get_errno()
assert c.string_at(p + 4092, 11) == b"socket-data"
sender.close()
receiver.close()
print("recvfrom_cross_page=ok", flush=True)

c.memset(p, 0x5a, 16384)
pid = os.fork()
if pid == 0:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        assert lib.readv(fd, vec, 2) == 8, c.get_errno()
        assert c.string_at(p + 4095, 3) + c.string_at(p + 8191, 5) == source[:8]
        os._exit(0)
    except BaseException:
        os._exit(9)
_, status = os.waitpid(pid, 0)
assert status == 0, status
assert c.string_at(p, 16384) == b"Z" * 16384
print("fork_cow_isolation=ok", flush=True)
assert lib.munmap(p, 16384) == 0
os.close(fd)

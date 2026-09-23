
import ctypes as c, os, select
lib = c.CDLL(None, use_errno=True)
class Iov(c.Structure):
    _fields_ = [('base', c.c_void_p), ('length', c.c_size_t)]
lib.mmap.restype = c.c_void_p
lib.mmap.argtypes = [c.c_void_p,c.c_size_t,c.c_int,c.c_int,c.c_int,c.c_long]
lib.munmap.argtypes = [c.c_void_p,c.c_size_t]
lib.process_vm_writev.restype = c.c_ssize_t
lib.process_vm_writev.argtypes = [c.c_int,c.POINTER(Iov),c.c_ulong,c.POINTER(Iov),c.c_ulong,c.c_ulong]
path = '/usr/local/lib/libpython3.12.so.1.0'
fd = os.open(path, os.O_RDONLY)
size = os.fstat(fd).st_size
original = os.pread(fd, 8192, 0)
assert len(original) == 8192
p = lib.mmap(None,size,3,2,fd,0)
assert p is not None and p != c.c_void_p(-1).value
assert p % 16384 == 0, hex(p)
os.close(fd)
rd, wr = os.pipe()
ready_rd, ready_wr = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(wr)
    os.close(ready_rd)
    os.write(ready_wr,b'R')
    os.close(ready_wr)
    poll = select.poll()
    poll.register(rd, select.POLLIN)
    if not poll.poll(3000):
        os._exit(3)
    if os.read(rd,1) != b'1':
        os._exit(4)
    got = c.string_at(p + 64, 8)
    adjacent = c.string_at(p, 1) + c.string_at(p + 4096, 1)
    expected_adjacent = original[:1] + original[4096:4097]
    os._exit(0 if got == b'PRIVATE!' and adjacent == expected_adjacent else 5)
os.close(rd)
os.close(ready_wr)
ready = select.poll()
ready.register(ready_rd,select.POLLIN)
assert ready.poll(3000) and os.read(ready_rd,1) == b'R'
os.close(ready_rd)
value = c.create_string_buffer(b'PRIVATE!')
local = Iov(c.addressof(value),8)
remote = Iov(p+64,8)
c.set_errno(0)
rc = lib.process_vm_writev(pid,c.byref(local),1,c.byref(remote),1,0)
err = c.get_errno()
os.write(wr,b'1' if rc == 8 else b'0')
os.close(wr)
_, status = os.waitpid(pid,0)
print('foreign_file_write_rc=%d errno=%d child_status=%d' % (rc,err,status), flush=True)
assert rc == 8 and status == 0, (rc,err,status)
assert c.string_at(p+64,8) == original[64:72], 'foreign write changed parent mapping'
check = os.open(path, os.O_RDONLY)
assert os.pread(check, 8, 64) == original[64:72], 'foreign write changed file'
os.close(check)
assert lib.munmap(p,size) == 0
print('foreign_immutable_private_file_copyout=ok')

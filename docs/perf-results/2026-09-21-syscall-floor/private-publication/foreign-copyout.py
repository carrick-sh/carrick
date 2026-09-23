
import ctypes as c, os, select, sys
lib = c.CDLL(None, use_errno=True)
class Iov(c.Structure):
    _fields_ = [('base', c.c_void_p), ('length', c.c_size_t)]
lib.mmap.restype = c.c_void_p
lib.mmap.argtypes = [c.c_void_p,c.c_size_t,c.c_int,c.c_int,c.c_int,c.c_long]
lib.munmap.argtypes = [c.c_void_p,c.c_size_t]
lib.process_vm_writev.restype = c.c_ssize_t
lib.process_vm_writev.argtypes = [c.c_int,c.POINTER(Iov),c.c_ulong,c.POINTER(Iov),c.c_ulong,c.c_ulong]
p = lib.mmap(None,8192,3,0x22,-1,0)
assert p is not None and p != c.c_void_p(-1).value
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
    os._exit(0 if c.c_uint64.from_address(p+64).value == 0x12345678 and c.c_ubyte.from_address(p+4096).value == 0 else 5)
os.close(rd)
os.close(ready_wr)
def wait_ready():
    ready = select.poll()
    ready.register(ready_rd,select.POLLIN)
    assert ready.poll(3000) and os.read(ready_rd,1) == b'R'
    os.close(ready_rd)
if sys.argv[1] == 'ready':
    wait_ready()
value = c.c_uint64(0x12345678)
local = Iov(c.addressof(value),8)
remote = Iov(p+64,8)
c.set_errno(0)
rc = lib.process_vm_writev(pid,c.byref(local),1,c.byref(remote),1,0)
err = c.get_errno()
if sys.argv[1] == 'immediate':
    wait_ready()
os.write(wr,b'1' if rc == 8 else b'0')
os.close(wr)
_, status = os.waitpid(pid,0)
print('foreign_write_rc=%d errno=%d child_status=%d' % (rc,err,status), flush=True)
assert rc == 8 and status == 0, (rc,err,status)
assert c.c_uint64.from_address(p+64).value == 0, 'foreign write changed parent'
assert lib.munmap(p,8192) == 0
print('foreign_pristine_copyout=ok')

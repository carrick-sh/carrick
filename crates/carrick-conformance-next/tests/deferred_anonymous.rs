//! Syscall copyout must validate logical anonymous memory before first touch.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

#[test]
fn deferred_anonymous_epoll_copyout() {
    let _guard = common::guest_lock();
    let script = r#"
import ctypes as c
lib = c.CDLL(None, use_errno=True)
class Event(c.Structure):
    _fields_ = [('events', c.c_uint32), ('data', c.c_uint64)]
lib.mmap.restype = c.c_void_p
lib.mmap.argtypes = [c.c_void_p,c.c_size_t,c.c_int,c.c_int,c.c_int,c.c_long]
lib.mprotect.argtypes = [c.c_void_p,c.c_size_t,c.c_int]
lib.munmap.argtypes = [c.c_void_p,c.c_size_t]
lib.epoll_wait.argtypes = [c.c_int,c.c_void_p,c.c_int,c.c_int]
lib.epoll_ctl.argtypes = [c.c_int,c.c_int,c.c_int,c.c_void_p]
ep = lib.epoll_create1(0)
fd = lib.eventfd(1,0)
assert ep >= 0 and fd >= 0
registered = Event(1,0x12345678)
assert lib.epoll_ctl(ep,1,fd,c.byref(registered)) == 0
for case in ['fresh','mixed','readonly','none','hole']:
    p = lib.mmap(None,8192,3,0x22,-1,0)
    assert p is not None and p != c.c_void_p(-1).value
    out = p
    if case == 'mixed':
        c.c_ubyte.from_address(p).value = 91
        out = p + 4096 - 8
    if case in ('readonly','none'):
        assert lib.mprotect(p,8192,1 if case == 'readonly' else 0) == 0
    if case == 'hole':
        assert lib.munmap(p,8192) == 0
    c.set_errno(0)
    rc = lib.epoll_wait(ep,out,1,0)
    err = c.get_errno()
    if case in ('fresh','mixed'):
        assert rc == 1, (case,rc,err)
        assert Event.from_address(out).data == registered.data
        if case == 'mixed':
            assert c.c_ubyte.from_address(p).value == 91
    else:
        assert (rc,err) == (-1,14), (case,rc,err)
    if case != 'hole':
        assert lib.munmap(p,8192) == 0
    print(case + '=ok')
assert lib.close(fd) == 0 and lib.close(ep) == 0
"#;
    let container = TestContainer::new("python:3.12-slim").pull_policy(PullPolicy::Missing);
    let (result, _) = common::run_or_fail(container.run_with_audit(["python3", "-c", script]));
    result.assert_success();
    result.assert_exit_code(0);
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert_eq!(
        result.stdout_utf8(),
        "fresh=ok\nmixed=ok\nreadonly=ok\nnone=ok\nhole=ok\n"
    );
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}

#[test]
fn deferred_anonymous_foreign_copyout() {
    let _guard = common::guest_lock();
    let script = r#"
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
"#;
    for mode in ["immediate", "ready"] {
        let container = TestContainer::new("python:3.12-slim").pull_policy(PullPolicy::Missing);
        let (result, _) =
            common::run_or_fail(container.run_with_audit(["python3", "-c", script, mode]));
        result.assert_success();
        result.assert_exit_code(0);
        assert_eq!(result.signal, None);
        assert!(!result.trap_limit_hit);
        assert_eq!(result.terminal_reason, None);
        assert_eq!(
            result.stdout_utf8(),
            "foreign_write_rc=8 errno=0 child_status=0\nforeign_pristine_copyout=ok\n"
        );
        assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
    }
}

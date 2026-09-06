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

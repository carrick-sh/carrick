"""Queue a message after the receiver parks at an overflowing guest pointer."""
import ctypes
import errno
import os
import time

libc = ctypes.CDLL(None, use_errno=True)
libc.msgget.argtypes = [ctypes.c_int, ctypes.c_int]
libc.msgget.restype = ctypes.c_int
libc.msgsnd.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.msgsnd.restype = ctypes.c_int
libc.msgrcv.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
                        ctypes.c_long, ctypes.c_int]
libc.msgrcv.restype = ctypes.c_ssize_t


class Message(ctypes.Structure):
    _fields_ = [("mtype", ctypes.c_long), ("text", ctypes.c_char)]


queue = libc.msgget(0, 0o600)
assert queue >= 0, ctypes.get_errno()
child = os.fork()
try:
    if child == 0:
        time.sleep(0.02)
        message = Message(1, b"x")
        result = libc.msgsnd(queue, ctypes.byref(message), 1, 0)
        os._exit(0 if result == 0 else 1)
    result = libc.msgrcv(queue, ctypes.c_void_p((1 << 64) - 4), 1, 0, 0)
    assert result == -1, result
    assert ctypes.get_errno() == errno.EFAULT, ctypes.get_errno()
    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
    print("MSGRCV_EFAULT_14")
finally:
    if child != 0:
        libc.msgctl(queue, 0, 0)

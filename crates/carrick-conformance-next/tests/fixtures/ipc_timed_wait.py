"""Bounded SysV semaphore timeout witness; cleanup even on assertion failure."""
import ctypes
import errno
import time

libc = ctypes.CDLL(None, use_errno=True)


class Sembuf(ctypes.Structure):
    _fields_ = [("sem_num", ctypes.c_ushort), ("sem_op", ctypes.c_short),
                ("sem_flg", ctypes.c_short)]


class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


libc.semget.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
libc.semget.restype = ctypes.c_int
libc.semtimedop.argtypes = [ctypes.c_int, ctypes.POINTER(Sembuf), ctypes.c_size_t,
                            ctypes.POINTER(Timespec)]
libc.semtimedop.restype = ctypes.c_int
semid = libc.semget(0, 1, 0o600)
assert semid >= 0, ctypes.get_errno()
try:
    op = Sembuf(0, -1, 0)
    timeout = Timespec(0, 1_000_000)
    start = time.monotonic()
    result = libc.semtimedop(semid, ctypes.byref(op), 1, ctypes.byref(timeout))
    elapsed = time.monotonic() - start
    assert result == -1, result
    assert ctypes.get_errno() == errno.EAGAIN, ctypes.get_errno()
    assert elapsed < 5, elapsed
    print("SEMTIMEDOP_EAGAIN_11")
finally:
    libc.semctl(semid, 0, 0)

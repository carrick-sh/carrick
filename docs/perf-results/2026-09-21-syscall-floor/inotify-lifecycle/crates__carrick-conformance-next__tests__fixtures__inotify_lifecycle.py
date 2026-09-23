# SPDX-License-Identifier: Apache-2.0 OR MIT
# Independent public-ABI contract; no LTP implementation source.
import ctypes as c, errno, os, struct
lib = c.CDLL(None, use_errno=True)
lib.inotify_add_watch.argtypes = [c.c_int, c.c_char_p, c.c_uint]
path = ('/tmp/carrick-inotify-lifecycle-' + str(os.getpid())).encode()
f = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)

def instance():
    q = lib.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert q >= 0
    return q

def add(q):
    wd = lib.inotify_add_watch(q, path, 2)
    assert wd > 0
    return wd

def remove(q, wd):
    assert lib.inotify_rm_watch(q, wd) == 0

def queued(q):
    n = c.c_int(-1)
    assert lib.ioctl(q, 0x541b, c.byref(n)) == 0
    return n.value

def records(q, size=65536):
    try: data = os.read(q, size)
    except BlockingIOError: return []
    assert len(data) % 16 == 0
    result = list(struct.iter_unpack('iIII', data))
    assert all(cookie == 0 and length == 0 for wd, mask, cookie, length in result)
    return [(wd, mask) for wd, mask, cookie, length in result]

for n in [1, 8, 32, 128]:
    q = instance()
    ids = []
    for i in range(n):
        wd = add(q); ids.append(wd); remove(q, wd)
    assert len(set(ids)) == n, (n, ids)
    assert queued(q) == 16 * n, (n, queued(q))
    first = records(q, 16)
    assert first == [(ids[0], 0x8000)]
    assert queued(q) == 16 * (n-1)
    rest = records(q)
    assert first + rest == [(wd, 0x8000) for wd in ids]
    assert queued(q) == 0 and records(q) == []
    current = add(q)
    c.set_errno(0)
    assert lib.inotify_rm_watch(q, ids[-1]) == -1 and c.get_errno() == errno.EINVAL
    assert os.write(f, b'x' * 64) == 64 and os.lseek(f, 0, 0) == 0
    remove(q, current)
    assert records(q) == [(current, 2), (current, 0x8000)]
    os.close(q)
    print('churn_scale_%d=ok' % n)

limit = int(open('/proc/sys/fs/inotify/max_queued_events').read())
assert 1 <= limit <= 65536
q = instance()
ids = []
for i in range(limit + 2):
    wd = add(q); ids.append(wd); remove(q, wd)
assert queued(q) == 16 * (limit + 1)
all_events = []
while True:
    batch = records(q)
    if not batch: break
    all_events += batch
assert all_events == [(wd, 0x8000) for wd in ids[:limit]] + [(-1, 0x4000)]
assert queued(q) == 0
wd = add(q); remove(q, wd)
assert records(q) == [(wd, 0x8000)]
os.close(q)
print('overflow_drain_rearm=ok')
os.close(f); os.unlink(path)
print('probe_complete=1')

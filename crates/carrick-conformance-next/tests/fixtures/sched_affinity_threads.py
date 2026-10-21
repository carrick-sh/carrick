import ctypes as c
import platform
import threading
import sys

arch = platform.machine().lower()
if arch in ("aarch64", "arm64"):
    SYS_sched_setaffinity, SYS_sched_getaffinity = 122, 123
elif arch in ("x86_64", "amd64"):
    SYS_sched_setaffinity, SYS_sched_getaffinity = 203, 204
else:
    raise ValueError(f"unsupported arch {arch}")

libc = c.CDLL(None, use_errno=True)
# The Linux oracle may have more CPUs than the carrier. Avoid assuming CPU 0
# belongs to the oracle's cpuset or that its kernel mask fits in eight bytes.
Mask = c.c_ubyte * 128
# A larger request measures min(4096, kernel cpumask bytes). Since 128 <=
# 4096, min(128, this result) is exactly the oracle's raw-return size rule.
ReferenceMask = c.c_ubyte * 4096
reference = ReferenceMask()
c.set_errno(0)
reference_res = libc.syscall(SYS_sched_getaffinity, 0, c.sizeof(reference), c.byref(reference))
assert reference_res > 0 and c.get_errno() == 0
expected_get_res = min(c.sizeof(Mask), reference_res)

def setaffinity(pid, cpu_id):
    mask = Mask()
    mask[cpu_id // 8] = 1 << (cpu_id % 8)
    c.set_errno(0)
    rc = libc.syscall(SYS_sched_setaffinity, pid, c.sizeof(mask), c.byref(mask))
    return rc, c.get_errno()

def getaffinity(pid):
    mask = Mask()
    c.set_errno(0)
    rc = libc.syscall(SYS_sched_getaffinity, pid, c.sizeof(mask), c.byref(mask))
    err = c.get_errno()
    return rc, err, int.from_bytes(bytes(mask), "little")

init_rc, init_err, init_mask = getaffinity(0)
assert init_rc > 0 and init_err == 0 and init_mask != 0
cpus = [cpu for cpu in range(1024) if init_mask & (1 << cpu)]
main_cpu = cpus[0]
worker_cpu = cpus[1] if len(cpus) > 1 else main_cpu
main_set_res, main_set_err = setaffinity(0, main_cpu)
main_get_res, main_get_err, main_mask = getaffinity(0)
main_reflected = main_mask == (1 << main_cpu)

thread_out = {}
ready = threading.Event()
release = threading.Event()
def worker():
    inherited_res, inherited_err, inherited_mask = getaffinity(0)
    thread_out["inherited"] = (
        inherited_res > 0 and inherited_err == 0 and inherited_mask == main_mask
    )
    t_set_res, t_set_err = setaffinity(0, worker_cpu)
    t_get_res, t_get_err, t_mask = getaffinity(0)
    thread_out.update(set_res=t_set_res, set_err=t_set_err,
                      get_res=t_get_res, get_err=t_get_err,
                      reflected=t_mask == (1 << worker_cpu))
    ready.set()
    assert release.wait(5), "main thread did not release worker"

t = threading.Thread(target=worker, daemon=True)
t.start()
assert ready.wait(5), "worker did not publish affinity"
# Both threads are alive when the caller checks its independent mask.
main_post_res, main_post_err, main_post_mask = getaffinity(0)
threads_independent = (
    main_post_res > 0 and main_post_err == 0 and main_post_mask == main_mask
)
release.set()
t.join(timeout=5)
assert not t.is_alive(), "worker did not exit"

print(f"main_setaffinity_res={main_set_res}", flush=True)
print(f"main_setaffinity_errno={main_set_err}", flush=True)
print(f"main_getaffinity_size_rule={str(main_get_res == expected_get_res).lower()}", flush=True)
print(f"main_getaffinity_raw={main_get_res}", file=sys.stderr, flush=True)
print(f"main_getaffinity_errno={main_get_err}", flush=True)
print(f"main_mask_reflected={str(main_reflected).lower()}", flush=True)
print(f"thread_setaffinity_res={thread_out['set_res']}", flush=True)
print(f"thread_setaffinity_errno={thread_out['set_err']}", flush=True)
print(f"thread_getaffinity_size_rule={str(thread_out['get_res'] == expected_get_res).lower()}", flush=True)
print(f"thread_getaffinity_raw={thread_out['get_res']}", file=sys.stderr, flush=True)
print(f"thread_getaffinity_errno={thread_out['get_err']}", flush=True)
print(f"thread_mask_reflected={str(thread_out['reflected']).lower()}", flush=True)
print(f"threads_independent={str(threads_independent).lower()}", flush=True)
print(f"clone_mask_inherited={str(thread_out['inherited']).lower()}", flush=True)

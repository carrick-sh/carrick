#!/usr/bin/env python3
"""Per-process native cost of short commands: wall, user, sys CPU and page
faults per child, via fork/exec + wait4 rusage. Runs unchanged under Docker
and Carrick. usage: rusage.py N"""
import os, resource, subprocess, sys, time
N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
NODE = "/opt/nodejs-conformance/bin/node24"
CASES = [
    ("true", ["/bin/true"]),
    ("python_pass", ["python3", "-c", "pass"]),
    ("node_e0", [NODE, "-e", "0"]),
    ("testpy_import", ["python3", "/opt/node-src/v24/tools/test.py", "--help"]),
]
for name, argv in CASES:
    walls, ut, st, flt, cs = [], 0.0, 0.0, 0, 0
    for _ in range(N):
        t0 = time.perf_counter()
        pid = os.fork()
        if pid == 0:
            fd = os.open(os.devnull, os.O_WRONLY)
            os.dup2(fd, 1); os.dup2(fd, 2)
            os.execvp(argv[0], argv)
        _, status, ru = os.wait4(pid, 0)
        walls.append((time.perf_counter() - t0) * 1000)
        ut += ru.ru_utime; st += ru.ru_stime; flt += ru.ru_minflt + ru.ru_majflt; cs += ru.ru_nvcsw + ru.ru_nivcsw
    walls.sort()
    print(f"RUSAGE {name} n={N} wall_p50_ms={walls[N//2]:.1f} wall_min_ms={walls[0]:.1f} "
          f"user_ms={ut*1000/N:.1f} sys_ms={st*1000/N:.1f} faults={flt/N:.0f} ctxsw={cs/N:.0f} nproc={os.cpu_count()}")

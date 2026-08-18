import os, sys, mmap

# Double-fork page-content probe: parent forks CHILD; the CHILD then dirties
# a large anon buffer (like the forkserver importing modules); the child forks
# a GRANDCHILD, which verifies every page. The interned-dict corruption shape.
N = 8 << 20  # 8 MiB
def check(buf, tag):
    bad = []
    for off in range(0, N, 4096):
        if buf[off] != 0xAB:
            bad.append(off)
    print(f"{tag}: {len(bad)} corrupt pages" + (f" first={bad[:4]}" if bad else ""), flush=True)
    return len(bad)

if __name__ == '__main__':
    c = os.fork()
    if c == 0:
        buf = mmap.mmap(-1, N)                     # anon private in the CHILD
        buf[:] = b'\xAB' * N                       # dirty every page post-fork
        g = os.fork()
        if g == 0:
            os._exit(1 if check(buf, "grandchild") else 0)
        _, st = os.waitpid(g, 0)
        rc = check(buf, "child-after")
        os._exit(1 if (rc or os.waitstatus_to_exitcode(st)) else 0)
    _, st = os.waitpid(c, 0)
    print("verdict:", "FAIL" if os.waitstatus_to_exitcode(st) else "ok", flush=True)

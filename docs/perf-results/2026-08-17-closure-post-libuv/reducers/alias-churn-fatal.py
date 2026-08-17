import os, mmap, sys, tempfile
N = int(sys.argv[1]) if len(sys.argv) > 1 else 800
keep = []
for i in range(N):
    f = tempfile.TemporaryFile(dir="/dev/shm" if os.path.isdir("/dev/shm") else "/tmp")
    f.write(b"\0" * 4096); f.flush()
    m = mmap.mmap(f.fileno(), 4096, mmap.MAP_SHARED)
    m[0:4] = b"test"
    m.close(); f.close()
    if i % 100 == 0:
        print("alias cycle %d" % i, flush=True)
print("completed %d MAP_SHARED map/unmap cycles" % N, flush=True)

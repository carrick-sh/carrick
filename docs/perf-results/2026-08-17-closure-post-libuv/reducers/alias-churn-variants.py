import os, mmap, sys, tempfile
N = int(sys.argv[1]); SZ = int(sys.argv[2]); SHARED = sys.argv[3] == "shared"
flag = mmap.MAP_SHARED if SHARED else mmap.MAP_PRIVATE
for i in range(N):
    f = tempfile.TemporaryFile(dir="/dev/shm" if os.path.isdir("/dev/shm") else "/tmp")
    f.write(b"\0" * SZ); f.flush()
    m = mmap.mmap(f.fileno(), SZ, flag)
    m[0:4] = b"test"
    m.close(); f.close()
    if i % 200 == 0:
        print("cycle %d" % i, flush=True)
print("completed %d" % N, flush=True)

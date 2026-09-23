import ctypes as c, os, select
lib = c.CDLL(None, use_errno=True)
lib.mmap.restype = c.c_void_p
lib.mmap.argtypes = [c.c_void_p,c.c_size_t,c.c_int,c.c_int,c.c_int,c.c_long]
lib.madvise.argtypes = [c.c_void_p,c.c_size_t,c.c_int]
lib.mprotect.argtypes = [c.c_void_p,c.c_size_t,c.c_int]
lib.munmap.argtypes = [c.c_void_p,c.c_size_t]

def zero(p, n):
    assert lib.madvise(p, n, 4) == 0
    assert c.string_at(p, n) == bytes(n)

for pages in [1,8,32,128]:
    n = pages*4096
    # Force complete host-granule coverage at scales >= 8 pages so the
    # retirement path, not just its partial-granule fallback, is exercised.
    raw_len = n+16384
    raw_p = lib.mmap(None,raw_len,3,0x22,-1,0)
    assert raw_p is not None and raw_p != c.c_void_p(-1).value
    p = (raw_p+16383) & -16384
    # Two discards before any read/write; the full range is still pristine.
    assert lib.madvise(p,n,4) == 0
    zero(p,n)
    # A partially dirty range must not skip its materialized bytes.
    c.c_ubyte.from_address(p).value = 91
    c.c_ubyte.from_address(p+n-1).value = 93
    zero(p,n)
    # Child discard must not clear the parent's shared COW source.
    c.memset(p,0x5a,n)
    r,w = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(r)
            zero(p,n)
            os.write(w,b'K')
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.close(w)
    assert select.select([r],[],[],5)[0], 'child did not complete'
    assert os.read(r,1) == b'K'
    os.close(r)
    assert os.waitpid(child,0) == (child,0)
    assert c.string_at(p,n) == bytes([0x5a])*n
    zero(p,n)
    # Read-only anonymous discard still discards bytes; permissions stay read-only.
    c.memset(p,0x31,n)
    assert lib.mprotect(p,n,1) == 0
    zero(p,n)
    assert lib.mprotect(p,n,3) == 0
    assert lib.munmap(raw_p,raw_len) == 0
    print('pristine_scrub_pages='+str(pages)+'=ok',flush=True)

# A Linux page can occupy only part of a host granule. Preserve both neighbors
# and the fork peer while discarding the child's middle page.
n = 16384
p = lib.mmap(None,n,3,0x22,-1,0)
assert p is not None and p != c.c_void_p(-1).value
c.memset(p,0x62,n)
r,w = os.pipe()
child = os.fork()
if child == 0:
    try:
        os.close(r)
        zero(p+4096,4096)
        assert c.string_at(p,4096) == bytes([0x62])*4096
        assert c.string_at(p+8192,8192) == bytes([0x62])*8192
        os.write(w,b'K')
        os._exit(0)
    except BaseException:
        os._exit(1)
os.close(w)
assert select.select([r],[],[],5)[0], 'partial discard child did not complete'
assert os.read(r,1) == b'K'
os.close(r)
assert os.waitpid(child,0) == (child,0)
assert c.string_at(p,n) == bytes([0x62])*n
assert lib.munmap(p,n) == 0
print('partial_scrub_fork=ok',flush=True)

# A shared VMA must not suppress discard of its private neighbor.
n = 32768
p = lib.mmap(None,n,3,0x22,-1,0)
assert p is not None and p != c.c_void_p(-1).value
q = lib.mmap(p+16384,16384,3,0x31,-1,0)  # SHARED|ANONYMOUS|FIXED
assert q == p+16384
c.memset(p,0x73,n)
assert lib.mprotect(p,16384,1) == 0
assert lib.madvise(p,n,4) == 0
assert c.string_at(p,16384) == bytes(16384)
assert c.string_at(q,16384) == bytes([0x73])*16384
assert lib.munmap(p,n) == 0
print('mixed_scrub_private_shared=ok',flush=True)

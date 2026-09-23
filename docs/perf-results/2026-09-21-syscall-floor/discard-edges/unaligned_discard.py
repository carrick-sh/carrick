import ctypes as c, os, select
lib = c.CDLL(None, use_errno=True)
lib.mmap.restype = c.c_void_p
lib.mmap.argtypes = [c.c_void_p,c.c_size_t,c.c_int,c.c_int,c.c_int,c.c_long]
lib.madvise.argtypes = [c.c_void_p,c.c_size_t,c.c_int]
lib.mprotect.argtypes = [c.c_void_p,c.c_size_t,c.c_int]
lib.munmap.argtypes = [c.c_void_p,c.c_size_t]
G = 16384
for scale in [1,8,32,128]:
    for offset in [0,4096,8192,12288]:
        size = (scale+5)*G
        p = lib.mmap(None,size,3,0x22,-1,0)
        assert p is not None and p != c.c_void_p(-1).value
        aligned = (p+G-1)&~(G-1)
        start = aligned+G+offset
        end = aligned+(scale+3)*G+4096
        c.memset(p,0x5a,size)
        rd,wr = os.pipe()
        child=os.fork()
        assert child >= 0
        if child == 0:
            os.close(wr)
            wait=select.poll();wait.register(rd,select.POLLIN)
            if not wait.poll(3000) or os.read(rd,1)!=b'R':os._exit(3)
            os._exit(0 if c.string_at(p,size)==b'Z'*size else 4)
        os.close(rd)
        # Exercise read-only private discard as well as writable ranges.
        if offset in [4096,12288]:assert lib.mprotect(p,size,1)==0
        assert lib.madvise(start,end-start,4)==0
        assert c.string_at(p,start-p)==b'Z'*(start-p)
        assert c.string_at(start,end-start)==b'\0'*(end-start)
        assert c.string_at(end,p+size-end)==b'Z'*(p+size-end)
        # Repeated discard after reads have faulted the zero contents back in.
        assert lib.madvise(start,end-start,4)==0
        assert c.string_at(start,end-start)==b'\0'*(end-start)
        assert c.string_at(p,start-p)==b'Z'*(start-p)
        assert c.string_at(end,p+size-end)==b'Z'*(p+size-end)
        os.write(wr,b'R');os.close(wr)
        _,status=os.waitpid(child,0);assert status==0,status
        assert lib.munmap(p,size)==0
    print('unaligned_discard_pages=%d=ok'%scale,flush=True)

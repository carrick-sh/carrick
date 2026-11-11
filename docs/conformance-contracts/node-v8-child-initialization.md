# Node 24.16.0 native-child initialization attribution (#1846)

Source authority: [Node v24.16.0, BSD/MIT V8 sources](https://github.com/nodejs/node/tree/v24.16.0/deps/v8/src).
No glibc or Linux kernel implementation source was consulted.

A search of all `deps/v8/src` finds exactly one release `CHECK_EQ(0, ret)`
(and no `CHECK(0 == ret)`): `base/platform/platform-posix.cc:604`.
On Linux it checks `madvise(address, size, MADV_DONTNEED)` (advice 4).
`Heap::SetUp` -> `CodeRange::InitReservation` -> `PageAllocator` ->
`OS::DiscardSystemPages` reaches this after the non-jitless code reservation
is made RWX (`heap/code-range.cc:232-254`). The pointer and length are the
allocatable code range, excluding any nonallocatable prefix. This attribution
is a source inference, pending exact signed workload confirmation.

## Checked calls and neighbouring candidates

Paths below are relative to `deps/v8/src` at that tag. Only the first row
matches the reported expression including the variable name `ret`.

| Site | Call and arguments | Check / relevance on Linux arm64 |
|---|---|---|
| `base/platform/platform-posix.cc:600-604` | `madvise(base, length, 4 /* MADV_DONTNEED */)` | `CHECK_EQ(0, ret)`; code-range precommit/discard and no-access permission transitions |
| `base/platform/platform-posix.cc:477,497,504` | `munmap(base, page-aligned length)` | `CHECK_EQ(0, munmap(...))`; allocation alignment trimming, free/release paths |
| `base/platform/platform-posix.cc:513-519` | `mprotect(base, length, prot)`; prot NONE=0, RW=3, RX=5, RWX=7 | Nonzero return requires errno ENOMEM, not `0 == ret` |
| `base/platform/platform-posix.cc:620-627` | `mmap(base, length, PROT_NONE, MAP_FIXED\|MAP_ANONYMOUS\|MAP_PRIVATE\|MAP_NORESERVE, -1, 0)` | Decommit checks ENOMEM on failure and exact returned address, not zero |
| `base/platform/platform-posix.cc:157-205,432-464` | `mmap(hint, aligned length, permission-derived prot, MAP_PRIVATE\|MAP_ANONYMOUS [\|MAP_NORESERVE], -1, 0)` | Reservation failure propagates null; prefix/suffix trimmed with checked munmap |
| `base/platform/platform-posix.cc:695,698,709` | `unlink(temp-name)`, `ftruncate(shared-fd, length)`, `close(shared-fd)` | Direct zero checks in optional shared-memory APIs, not the ordinary anonymous code-range path |
| `base/platform/platform-posix.cc:1393-1409` | `pthread_getattr_np(pthread_self(), &attr)`, `pthread_attr_getstack(&attr, &base, &size)`, `pthread_attr_destroy(&attr)` | First failure falls back for main thread; getstack has `CHECK(!error)`; destroy unchecked. Library APIs, not direct syscall identities; man-pages name `/proc/self/maps` and getrlimit for main-thread query |
| `base/platform/platform-posix.cc:1255-1281` | `pthread_attr_init(&attr)`, optional `pthread_attr_setstacksize(&attr, stack_size)`, `pthread_create(&thread,&attr,ThreadEntry,this)`, destroy | Attribute init/destroy use `DCHECK` via result handling; create/setstacksize failures return false; no `ret` check |
| `base/platform/platform-posix.cc:1326-1353` | `pthread_key_create(&key,nullptr)`, delete(key), setspecific(key,value) | Debug-only zero checks of `result`; no reported release expression |
| `base/platform/memory-protection-key.cc:86` | `pkey_set(key, permissions)` | Checked zero but gated by `V8_HAS_PKU_JIT_WRITE_PROTECT`, x64-only; pkey_alloc(0,0) and pkey_mprotect(base,len,prot,key) propagate failure |
| `base/platform/platform-posix.cc:1200` | `prctl(PR_SET_NAME, truncated_thread_name)` | Return unchecked; no reported expression |
| `sandbox/testing.cc:748` | `sigaltstack(&signalstack,nullptr)` | Direct zero check only in sandbox testing crash-filter setup; not normal Isolate initialization |
| all `src` | `membarrier` | No call in bundled V8 sources |

`platform-linux.cc` has no matching release zero-return check. Linux remap
uses `mremap(old,0,size,MREMAP_FIXED|MREMAP_MAYMOVE,new)` or file-backed
`mmap(new,size,prot,MAP_FIXED|MAP_PRIVATE,fd,offset)`; failures return false or
check pointer identity. Debug alignment checks are arithmetic, not syscalls.

Linux authority: [madvise(2)](https://man7.org/linux/man-pages/man2/madvise.2.html),
[mprotect(2)](https://man7.org/linux/man-pages/man2/mprotect.2.html), and
[pthread_getattr_np(3)](https://man7.org/linux/man-pages/man3/pthread_getattr_np.3.html).
MADV_DONTNEED on a valid unlocked private anonymous range returns zero and
subsequent reads see zero-filled pages. A successful no-op is insufficient.
The first witness must use the production fork, exec adoption and syscall
entry, with two live processes, rather than a routing helper.

On the admitted GitHub main, #1830, #1740 and #1792 are OPEN/unmerged.
No prerequisite workaround belongs in this slice. The reported post-SIGABRT
hang remains separate: it needs its own production termination/wait witness;
this attribution does not establish its cause.

## Round 2 admission reduction

The native witness extends the existing fork/exec fixture in
`aarch64_process_tests/native_exec_pipe_tests.rs`. It keeps the admitted parent
and exec child alive, enters the registered child, dispatches canonical ordinal
233, and applies the shipping final-capture policy with the registry's actual
thread-group owner. It requires `madvise(0x400000, 0, 4)` to return zero.
The zero-length call isolates admission; it does not pretend to own a populated
V8 reservation. The existing pipe witness retains its test name and assertions.

This limitation is material: the VM-free dispatcher's default anonymous venue
is absent (`El1PendingFamilies::anonymous_venue`, non-`target_os = "none"`).
Supplying the child's physical `FixtureMapping` venue over the admitted
successor MM tests the production delegated anonymous path without inventing
semantics. The production crossing table marks Madvise temporary, and no ring
stage handles it yet.

The separate Linux-only exec-child control reserves 128 MiB with PROT_NONE,
trims a page at each end, makes 2 MiB RWX, writes it, discards it and checks every
byte is zero. It also checks the zero-length reduction, NONE/RW/RX/RWX
transitions, and MAP_FIXED|MAP_NORESERVE anonymous decommit/readback. Its parent
stays alive and bounds the exec child at ten seconds. This is a local native
Linux control, not the native ARM64 Docker oracle or Carrick guest evidence.

Contract: `kernel.mm.anonymous-discard`; the new admission binding does not
change its existing backend-call budget or claim a structural measurement.
No signed Node result is claimed here. The post-SIGABRT hang is still a
separate termination/wait investigation, with no fix here.

Observed red: after settling the completed exec setup boundary,
`serial_host_native_fork_exec_madvise_dontneed_returns_zero` returns raw `-38`
(ENOSYS), expected `0`, for `(address=0x400000, length=0, advice=4)`.
The production dispatcher forwards; final capture refuses it once as a child
call, with zero carrier-venue refusals.

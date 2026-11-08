# Ring-owned pipe metadata (#1901)

Contract: `kernel.el1.ipc-fd-authority`.

Linux authority: stat(2), fcntl(2), F_GETFL(2const), F_GETPIPE_SZ(2const),
pipe(7), ioctl(2), dup(2), close(2), and lseek(2). Both pipe ends identify
one inode; separate live pipes differ. Description status flags and capacity
are shared by aliases; descriptor close-on-exec flags are private.

The structural invariant is zero host descriptor operations for a ring-owned
pipe. The production-dispatch witnesses require a completed ring route for
each call. They use the existing two-live-child native-fork fixture and test
the borrowed root table as well as the fork child's owned table. Each case
creates its pipe through pipe2. All I/O in these cases is nonblocking.

The first witness set covers fstat, empty-path newfstatat, fcntl status and
fd flags, both fcntl duplication commands, pipe capacity, FIONREAD, FIONBIO,
TCGETS, lseek, dup, dup3 and close. It is deliberately red before routing
and metadata repairs. Exec-successor and FIOCLEX/FIONCLEX cases extend the
same matrix. The exec
fixture also checks an inherited CLOEXEC alias is removed while the parent
keeps it, and the non-CLOEXEC pipe ends survive. Capacity witnesses require
EBUSY(16) when shrinking below 4097 buffered bytes, preserve the old capacity,
and require the same shrink to succeed after draining. A combined CPython
metadata pattern probes both a freshly created pipe and inherited fd 3.
Contention and x86 execution still need witnesses. No signed or end-to-end
CPython result is claimed by these VM-free tests.

## Shared implementation and ownership

The director's decision on #1901 assigns lock-release notification to #1845.
Metadata therefore acquires the existing fd authority and `IpcObjectGuard`
through the same wait path as current pipe operations. It adds no lock-release
protocol. The bounded Busy-once production-dispatch witness holds the real
object lock, observes the existing wait path, releases it and requires the
original query to complete.

Pipe stat, empty-path stat, capacity, FIONREAD, FIONBIO, close-on-exec ioctl,
terminal refusal and seek refusal use the shared descriptor family. Scalar
input is imported before operation admission through typed guest copy; refused
input uses the existing owner preparation. Completed stat/count output releases
the description pin before the existing `ProcessNative::complete_copyout`
owner retains its bytes across memory waits. Duplication, close and fcntl flags
continue through fd-core's existing owner. A missing entry in an authoritative
root table returns EBADF(9), including a repeated close.

The host provision/recheck/reclaim resize transaction now lives in `IpcRegion`.
Both venues use it, with pipe-core rounding and EBUSY(16) for a shrink below
buffered bytes. A concurrent resize reclaims the unused allocation and resamples
the current capacity before replacing storage. Wake publication remains under
the object lock and delivery follows unlock in each venue.

`LinuxPipeIdentity`, exported by `carrick-abi` from its syscall ABI leaf, derives
one inode from the IPC object's index and generation. Both pipe ends and all
aliases share that identity; separate live pipes differ. The host and ring use
this record and the ABI's shared ARM and x86 stat encoders.

Native exec previously swept only delegated slots. The existing fd-core exec
selection now also supports deferred physical release. After consuming successful
exec adoption, the native owner sweeps its private ring table, outside all
delegated-map guards, and settles releases at the existing host boundary. Failed
exec before adoption leaves the table unchanged. Parent tables stay live.

The CPL0 production witness runs real metadata syscalls and checks both pipe
ends' inode, a distinct second live pipe, x86 stat layouts, flags, capacity,
ioctl, duplication, close and errno numbers. The full x86 I/O reproduction
still waits on #1756: `ipc_transfer` requires an ARM frame. No per-ISA IPC
implementation is introduced. Signed/HVF execution and CPython subprocess
remain director-owned verification; VM-free ARM-frame tests are not that proof.

## AT_EMPTY_PATH pathname admission (round 3)

`stat(2)` permits an empty pathname with `AT_EMPTY_PATH`; it does not
require one. `AT_FDCWD` selects cwd even for an empty path, and an absolute
path ignores dirfd. The shared metadata handler must classify these inputs
before consulting the pipe descriptor authority. Nonempty paths and cwd
queries return unchanged to the existing `Newfstatat` path staging owner.
Only a genuine empty-path query on a zone pipe retains the ring stat owner.

`x86_production_forward::at_empty_path_*` drives the production dispatcher
with both ARM and decoded x86 frames against a real IPC descriptor table.
The three pathname forms must forward with untouched output, then stage one
path request through the existing owner without a descriptor lookup. Each
ISA also has a pipe control requiring an in-ring completion and FIFO mode in
its native stat layout. These are routing and staging witnesses, not a claim
of signed path-service execution. The native amd64 Linux syscall oracle
returns 0 for the same three forms and the pipe control.

## Queue-release integration (round 5)

The shared `notify_native_wake` retains reader, writer and attached-epoll
publication and supplies the existing scheduler completion venue for every
notification. Queue custody, initialization, deferred handbacks and ISA
doorbells remain owned by the scheduler's queue-release protocol (#1909).
No new completion mechanism or per-ISA metadata path is introduced.

After rebasing, removing only the production cwd classification makes both
ARM and decoded-x86 empty-cwd witnesses return EBADF(9) instead of forwarding
to the path owner. Restoring it passes all eight pathname/control witnesses.
The automatically merged surface registry also needs its existing allocation
binding placed after the x86 integration bindings to retain sorted admission.

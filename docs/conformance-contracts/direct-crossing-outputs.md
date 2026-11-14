# Direct crossing outputs (#2300)

Contract: `kernel.el1.arm-ring-first-crossing`.

Linux authority (man pages only):

- https://man7.org/linux/man-pages/man2/getrandom.2.html
- https://man7.org/linux/man-pages/man2/statx.2.html
- https://man7.org/linux/man-pages/man2/epoll_wait.2.html
- https://man7.org/linux/man-pages/man2/copy_file_range.2.html
- https://man7.org/linux/man-pages/man2/readv.2.html

The first witness calls production `crossing_output_stage`, checks the exact
range population, then leaves each output untouched in turn. It must select
that output for preparation before allowing a host effect. The host-root
`SyscallDispatcher` statx witness compares real committed bytes with its
crossing declaration after an owner refusal. The x86 `stage_call` witness
enters via the production decoder, not a synthetic crossing helper.

Existing venues, preserved by this slice:

| Declaration | ARM consumer | x86 consumer |
| --- | --- | --- |
| getrandom | Host-root dispatcher, existing entropy service | Native entropy service; no host crossing |
| statx | Host-root dispatcher | Native host-file staging and host-root dispatcher |
| copy_file_range | Host-root dispatcher | No host crossing |
| epoll_pwait2 | Host-root dispatcher, ring poll family | No host crossing |
| epoll_pwait | Host-root dispatcher, ring poll family | Crossing preparer on family decline; ring poll family otherwise |

ARM NativeProcess refusals do not consume these declarations and must remain
counted ENOSYS. The host-root copyout prepares independently of metadata;
metadata equality is an audit witness, not evidence of a new ARM executor.
The crossing set is unchanged. `preadv2` writes the iovec-referenced buffers,
not its iovec array, and stays with the indirect family.

Preparation visits one contiguous range per record or byte buffer, without
allocating a range array on the guest stack. Epoll arrays use the calling
ISA's record stride and signed int count. Nullable copy offsets are omitted
independently. Runtime supply and completed copyout acceptance must be
reported separately from preparation selection; a passing selection test
alone cannot establish live guest acceptance.

The declarations close six output-argument gaps (getrandom, statx, both copy
offsets, and the two epoll variants), lowering the census ceiling from 50 to
44 in the implementation commit. The host-root copy_file_range path now
secures both optional offset words with the existing `copyout::prepare`
mechanism before writing the destination file or updating either cursor.
Its red production witness returned EFAULT on an owner refusal; after the fix
it returns the owner wait with no file or offset effect, then copies the
exact payload and commits both advanced offsets on redispatch. Null input
and output offsets are exercised independently.

The ARM host-root entropy and epoll witnesses compare committed ranges with
their declarations, check owner refusal before output, and verify entropy's
committed bytes and epoll's exact mask/payload. The KVM fixture exercises real
untouched statx and packed epoll output pages; these existing native venues
already passed before the declaration change. This is not evidence that
ARM NativeProcess can execute these refused crossings.

The remaining fixed-record/byte-count census family has thirteen arguments:
read, pread64, getdents64, sendfile, fstat, newfstatat, timerfd_settime,
timerfd_gettime, clock_getres, times, socketpair, nanosleep, clock_nanosleep.
The host-root dispatcher owns their ARM copyout; sleeps capture the actual
production sleep request and fold interrupted completion without a real
wait. Absolute clock_nanosleep has no remainder range. On x86, direct file
buffers and private stat layouts use native host-file staging. The other
operations gain no x86 host crossing or new executor from a declaration.
The KVM file mode uses distinct untouched anonymous pages and validates
read/pread payloads, both x86 stat modes, and the expected directory name.

clock_gettime remains #2278-owned. preadv2/readv/preadv/vmsplice are indirect;
pselect6 and splice have multiple outputs; socket length-dependent buffers,
message headers and command-selected ioctl/fcntl outputs are separate shapes.
mincore's output length is a derived page count rather than a byte-count
argument, so it remains outside this fixed-record/byte-count slice.

Additional Linux man-page authority:

- https://man7.org/linux/man-pages/man2/read.2.html
- https://man7.org/linux/man-pages/man2/stat.2.html
- https://man7.org/linux/man-pages/man2/getdents.2.html
- https://man7.org/linux/man-pages/man2/sendfile.2.html
- https://man7.org/linux/man-pages/man2/timerfd_create.2.html
- https://man7.org/linux/man-pages/man2/clock_getres.2.html
- https://man7.org/linux/man-pages/man2/times.2.html
- https://man7.org/linux/man-pages/man2/socketpair.2.html
- https://man7.org/linux/man-pages/man2/nanosleep.2.html
- https://man7.org/linux/man-pages/man2/clock_nanosleep.2.html

The second implementation step lowers the ceiling by another thirteen, from
44 to 31 (nineteen arguments retired in total). sendfile had the same raw
offset-write defect as copy_file_range; both its socket and buffered paths
now retain a typed prepared output before effects. All four old raw offset
writes and their error-collapse debt entries are retired.

The delegated-stdio KVM mode reaches genuine read/pread host crossings into
two untouched pages. Forward counters record two entries per operation: one
prepares and rewinds, the next crosses. Bounded host strace confirmed exactly
one real read and one pread with the expected payloads; the counter is not a
count of host effects. Other KVM modes cover existing native file staging and
ring epoll output separately. No ARM NativeProcess executor is introduced.

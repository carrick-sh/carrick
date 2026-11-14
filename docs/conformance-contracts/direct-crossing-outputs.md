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

# Follow-up: an x86 fork child's blocking poll on a zone pipe never returns

Found while building the #2250 P0-1 KVM witness (Part of #1482).

On x86 CPL0 (KVM), a fork child that blocks in `poll(&{fd, POLLIN}, 1, -1)`
on a zone pipe's read end does not return even when every writer of that
pipe has closed (POLLHUP should be immediate). Linux returns 1 with
POLLHUP. The root's own blocking poll on a pipe whose writers are children
does return.

Reproduce: in `native_owed_return_table_full.S`, have each holder close its
inherited write end of a second pipe and then `poll` that pipe's read end
with timeout -1, while the root closes its write end and reaps. The run
never completes (bounded by a 60 s `recv_timeout`; the native oracle exits
0 at once). The holders' exits alone (no poll) complete.

This is distinct from #1756 (no ring IPC venue for a child's zone pipe
read/write: those answer ENOSYS). A wait that never completes is a hang.
The witness fixture now avoids child polls (holders sleep and the root
kills them).

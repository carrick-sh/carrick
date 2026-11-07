# Slice 5a: sendfile witness venue

The owner resolved the earlier native-sendfile prerequisite on #1695:
slice 5a migrates the copy sites that exist today. Its sendfile witness uses
the production host `SyscallDispatcher`, and getdents64 uses production
native staging and service completion. Native sendfile routing is separate
work in #1790; this slice adds no routed syscall or host-file wire operation.

The host witness requires one offset input or output refusal before a
three-byte sendfile completes exactly once. The explicit offset advances
from 1 to 4 while the source description offset remains unchanged.

The native directory witness stages getdents64 and supplies one claimed
carrier reply. Completion transfers that reply to the existing retained
output owner before copying. A temporary refusal parks through its existing
CarrierWork route; resumption publishes the same directory entry without
issuing another directory request. The shared completion path also serves
native read and pread output. ARM uses its existing exact-MM output adapter;
x86 uses its existing bounded owner-copy adapter. No ISA-specific syscall
policy is added.

The VM-free witnesses and their limits are described in
[the file-transfer contract note](../conformance-contracts/guest-copy-file-transfers.md).
Signed HVF, Docker comparison and exact-artifact promotion remain higher-layer
verification; these witnesses do not claim those results.

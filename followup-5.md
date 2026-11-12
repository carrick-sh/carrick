# followup-5: T3 prepares the first page of a variable-length output

Part of #2157. B1's `OperandSpec::output_range` prepares fixed records fully (statfs: 120 bytes)
and a variable buffer (getcwd, readlinkat, getxattr, listxattr) up to the end of its first page,
because the result length is not known before the effect. A result longer than the first page
that lands on a further untouched or copy-on-write page still answers EFAULT through the
forward venue. Proper fix: fault supply inside `ForwardVenue` copy-out (cpl0_boot.rs) or an
owned continuation, then drop the first-page clamp. iovec/msghdr outputs stay with #1396.

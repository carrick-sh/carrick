# followup-2: sendfile and copy_file_range have two descriptors

Part of #2157. `FdOperand::Unresolved` makes the resolver answer a counted ENOSYS in ring.
Flipping them needs a resolver verdict for two descriptors (or a ring venue op). Left unflipped.

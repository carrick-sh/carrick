# Host-crossing output declarations (#2300)

Contract: `kernel.el1.arm-ring-first-crossing`.

Every allowed crossing must account for every potentially written Linux user
pointer, including nullable outputs, command-dependent outputs, indirect I/O
vectors, socket length words and error-only sleep remainders. The authority is
the corresponding Linux man-page, not the set of currently routed operations.
In particular, the raw pselect6 syscall updates its timeout even though the libc
wrapper hides that update; sendmmsg writes each returned message length:

- https://man7.org/linux/man-pages/man2/select.2.html
- https://man7.org/linux/man-pages/man2/sendmmsg.2.html
- https://man7.org/linux/man-pages/man2/recvmmsg.2.html
- https://man7.org/linux/man-pages/man2/ioctl.2.html
- https://man7.org/linux/man-pages/man2/fcntl.2.html

`carrick-abi::syscall::Syscall::output_arguments` is the audited ABI direction
metadata. `None` is unaudited; `Some(&[])` is an explicit output-free audit.
Each index identifies a pointer root, not necessarily a contiguous output
range. For example readv names the iovec root, whose elements identify output
buffers. The crossing census reports unaudited calls and every missing output
argument together, for both ISA sets. It does not silently equate an unknown
entry with an output-free syscall. A count-only ceiling makes this a decrease-only
ratchet: additions above the ceiling fail, and fixing declarations requires
lowering the ceiling in the same commit. There is no per-syscall exemption list.

Existing mechanisms:

- `personality-linux/dispatch.rs`: `OutputOperand` describes optional fixed records
  or a bounded buffer. `OperandSpec::output_ranges` resolves every record.
- `personality-linux/native_host_file.rs`: `stage` checks staged output;
  `crossing_output_stage` asks the owner to prepare the first uncovered byte.
- `el1-linux/dispatch.rs`: `native_crossing_output_stage` connects ARM's
  production crossing capture to that common preparer.
- `x86-cpl0/native_stage.rs`: `stage_call` uses `admit_or_cross`; rejected
  venue admission still passes through the common crossing output preparer.

The new audit is a red witness, not proof that every named call currently
fails at runtime: some calls already stage their output in a separate venue
but do not declare it. Resolving those declarations must identify that venue
and test its production entry. Multiple ranges, indirect outputs and
command-dependent buffers must not be mislabeled as output-free or as a
single unconditional direct buffer merely to make the census pass.

The original red witness fails on GitHub main with clock_gettime among the
missing outputs. This PR is based on main and does not include #2278's
clock_gettime declaration. The census retains that gap under its count ceiling.
The remaining declarations and end-to-end physical-supply/copyout witnesses
remain #2300 work. No runtime performance claim is made by the static audit.

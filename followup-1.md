# followup-1: x86 exec built stack is fixed at 64 KiB

The CPL0 editor builds the initial stack into INITIAL_STACK_SIZE (64 KiB).
Exec arguments Linux accepts (up to ARG_MAX, 2 MiB) but past that tail are
left unrouted (ENOSYS) by `X86ExecImage::from_program`, never a false E2BIG.
Boot has the same limit. Size the built stack to the argument tail (bounded
by the growsdown reservation) in boot and exec together.
Found in #1093 S4c slice c (PR #2205).

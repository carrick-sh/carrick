# Retained IPC frame mechanics (#1040 prerequisite)

The `kernel.el1.ipc-two-process` contract requires a parked read to re-enter
with its original syscall inputs and retained operation token before looking
up the numeric descriptor. Linux pipe blocking semantics remain the authority;
frame restoration is only one component of this obligation.

`ipc::frame::IpcFrame` separates syscall register mechanics from IPC ownership.
Its bounded snapshot contains six argument words, the native syscall number
and the post-instruction PC. It does not duplicate the scheduler's custody of
TLS, extended state, nonargument registers or the user stack. ARM selects the
SVC address by subtracting four bytes and authenticating instruction alignment.
x86 selects the SYSCALL address by subtracting two bytes from the hardware
return PC in `rcx`, using the existing unaligned-PC constructor. The distinct
`user_rcx` field is never used as a return address. Restoration calculates from
the snapshot so repeated restoration does not rewind another instruction.
Invalid re-entry leaves the live frame unchanged.

The production ARM IPC park calls the same adapter. The frame tests compile
the production x86 frame definition on the host; they prove register mechanics,
not instruction execution, scheduling, endpoint retention or copyout supply.
No descriptor lookup, syscall routing, copy cursor or wait queue policy changes
in this prerequisite. Each save/restore copies a fixed eight words.

The requested x86 blocking pipe-read witness is still missing: its production
entry passes neither a scheduler venue nor an IPC venue, while the existing
IPC scheduler transport carries `Aarch64ParkedContext`. The frame adapter alone
does not authorize replacing either with another ISA's context or claiming an
in-ring read. A common continuation transport and the real x86 IPC venue,
followed by a red-first KVM park/write/wake witness, remain necessary.

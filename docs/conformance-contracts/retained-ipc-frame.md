# Retained IPC frame mechanics (#1040 prerequisite)

The `kernel.el1.ipc-two-process` contract requires a parked read to re-enter
with its original syscall inputs and retained operation token before looking
up the numeric descriptor. Linux pipe blocking semantics remain the authority;
frame restoration is only one component of this obligation.

`carrick_el1::substrate::ipc::frame::IpcFrame` separates syscall register
mechanics from IPC ownership.
Its bounded snapshot contains six argument words, the native syscall number
and the post-instruction PC. It does not duplicate the scheduler's custody of
TLS, extended state, nonargument registers or the user stack. ARM selects the
SVC address by subtracting four bytes and authenticating instruction alignment.
x86 selects the SYSCALL address by subtracting two bytes from the hardware
return PC in `rcx`, using the existing unaligned-PC constructor. The distinct
`user_rcx` field is never used as a return address. Restoration calculates from
the snapshot so repeated restoration does not rewind another instruction.
Invalid re-entry leaves the live frame unchanged.

The neutral `with_ipc_reentry` transport presents the instruction address to
the context saver and restores the live entry afterward, including when the
saver returns Busy or Changed. Invalid re-entry never calls the saver. It
copies only the fixed syscall snapshot; it neither clones a machine context
nor owns a descriptor, queue ticket or operation token. The production ARM
IPC park uses this transport before consuming the park result.

The frame tests compile the production x86 frame definition on the host;
they prove register mechanics,
not instruction execution, scheduling, endpoint retention or copyout supply.
No descriptor lookup, syscall routing, copy cursor or wait queue policy changes
in this prerequisite. Each save/restore copies a fixed eight words.

`IpcScheduler` now binds the shared IPC client to associated saved-context
and frame types. IPC admission, transfer, owner-wait enrollment, operation
retention and epoll no longer name `Sched` or `Aarch64ParkedContext`. The ARM
implementation delegates to the existing scheduler methods, including park
receipt consumption and wake delivery. `LinuxIpcFrame` separates canonical
arguments/results and the Linux restart/handback markers from neutral register
saves. The saved native ordinal remains owned by `IpcFrame`. This prerequisite
changes neither the routing allowlist nor the current ARM epoll wire format.

The x86 blocking pipe-read witness is still missing. Its production dispatch
passes no IPC venue; the CPL0 host carrier has no IPC-directory/pool mapping
or IPC-table-map publication. Calling the ARM `guest_venue` would access a
window that x86 has not installed. The context-neutral interface is therefore
necessary but insufficient for a runtime claim. An x86 implementation must
bind the real retained authority, save full native context (including XSAVE
and TLS), hand its typed park receipt to the common entry completion owner,
and wake through the existing scheduler before a red-first KVM park/write/wake
witness can pass. It must also preserve x86's packed epoll layout and native
signal restart semantics when those families are admitted. No x86 execution,
readv/pselect6 routing or signed acceptance is claimed by this prerequisite.

The adapter's behavioural negative control replaces ARM's four-byte rewind
with eight bytes and x86's two-byte rewind with four bytes. The focused frame
suite then exits 101: the ARM entry is 4092 rather than 4096, the x86 entry is
4094 rather than 4096, and the unaligned x86 entry is 4095 rather than 4097.
The tests check both the production park's `ipc_reentry_pc` and snapshot
restoration, so a wrong offset cannot pass by changing only one adapter method.

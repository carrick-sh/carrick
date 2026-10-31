# Host-classified synchronous faults (#1075)

`kernel.el1.signal-delivery-owner` includes native-owner MAPERR (signal 11,
si_code 1) and file-past-EOF BUS_ADRERR (signal 7, si_code 2), retaining the
exact fault address. Authority is `sigaction(2)` and `signal(7)`. One retained
payload per exact thread crosses the host VMA classification boundary; no host
signal action is selected. The existing native checkpoint and shared signal
owner select the action once. Blocked or ignored synchronous faults become
default, and that selected default returns to the existing host core/exit path
without a second ptrace stop. Busy admission retains the payload and forwards.
The compiled fault stack chain charges the larger resolver/checkpoint prefix;
no extra execution pool or second signal frame builder is introduced.
The retained Busy path currently re-enters across the host boundary without
a release subscription; park-and-probe completion remains tracked by #1083.

VM-free bindings cover both numeric payloads, native handler frames, selected
default, ignored and blocked actions, and action replacement before delivery.
The retained-home Busy witness exercises the same admission path, then releases
the holder and requires successful delivery with no retained payload. Engines
without a native fault entry (currently x86, seam #1084) return a typed absent
venue; runtime preserves signal termination and clears the published payload.
A two-live-thread witness enters the production fault wrapper with admission
already closed by a sibling's exit_group; the single inner venue owner marks
a terminal fallback rather than retrying the owner checkpoint. A host witness
consumes that default payload and runs the production terminal-loser path,
finishing only the faulting thread while preserving the sibling's exit claim.
A retained payload is admitted only on an actual fault or the explicit host-fault checkpoint, never on a syscall or interrupt return.
Closed-gate and absent-venue settlement use bounded slot reads and one
settlement. The existing
`siglongjmpaltstack` probe now recovers from real MAPERR and file-past-EOF faults
through `siglongjmp`, and checks default and blocked signal 11 in fork children
with a five-second pipe wait. Its updated source requires deliberate native
Linux oracle refresh and fresh ARM libc executables; no cached result is claimed
for that changed input. Signed probe/frame execution and the existing
`crash_parked_thread` core witness remain director-owned on HVF. No Docker or
HVF is available on ctb-w1. CPL0 already delivers MAPERR through the shared
owner; missing file-backed classification and host-to-native checkpoint wiring
are tracked by #1084 (related cancellation seam #1078).

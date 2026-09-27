# Allocator grant completion: skipped guest instruction

Signed source `bd604a876c05fbfe0c50e540c42c6504da92d452` passes the
basic allocation phase and fails growth with rc=201. The negative entitlement
control passes and original/debugger run scopes have zero remaining processes.
Exact failed executable identity is in `identity.json`; no acceptance claimed.

LLDB confirms the first growth request maps 1,572,864 bytes successfully
(`rc=0`). A separate unchanged-binary capture reads guest PC
193340645316 = `0x2d04001fc4`. Exact guest disassembly places HVC #6 at
`0x2d04001fc0` and the status comparison at `0x2d04001fc4`.
The handler's additional PC+4 therefore skips the status comparison and
feeds stale NZCV to the following conditional comparison.

Remove PC advancement from every grant/return response, including refusals.
HVF already advances past HVC. Compile-check passes; signed verification of
this correction remains pending. This is part of kernel.el1.metadata-allocation,
not allocator or memory checkpoint acceptance. Host backing/custody and the
remaining allocator witnesses still require closure.

Guest ELF SHA-256: `30366634f817a6920e5a2fcd5d4a872f98abc68e76eb3cd926677f71b3b9b99d`.
LLDB runs are diagnostic, not workload timing evidence.

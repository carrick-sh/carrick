title: resolve x86 Node idle-peer fault handback
parent: #2271

Evidence from the prior-round PR receipts (not rerun in round 2):
node-version and node-child exit 125 on main e2e10d32a and round-1 head 905ed7c95: idle CPL0 peer needs a host task handback: FaultDoorbellWord(14). They stop before proving this PR's IPC paths.

Acceptance:
Capture the carrier fault record and scheduler state with bounded supported tracing/debugging. Attribute the missing owner handback from actual values, add a shared red-first witness, and rerun both Node rows on the exact artifact. Keep changes in the fault owner lane; do not add host IPC forwarding.

Clean room: consult specifications and man pages; do not read copyleft source.

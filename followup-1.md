title: x86 parked native exec holds its ticket until the fork stock releases, even when the ring cancels
parent: #2273

A fork child's exec whose successor tables the fork stock cannot grant parks
on the host with its service ticket outstanding (`ParkedNativeExec`,
`crates/carrick-x86-cpl0-host/src/cpl0_exec.rs`). The host probes it only
after a crossing that returns tables. If the ring cancels that ticket meanwhile
(SIGKILL, exit_group of the exec'ing process), the host acknowledges the
cancellation only once a table returns. If no holder ever returns one, the
dying process's cancellation waits on it.

Acceptance: a witness that kills a child whose exec is parked behind a stock
holder that never returns. The kill must complete with the cancellation
acknowledged and the preparation released, with no polling. The park path
itself has no KVM witness on this branch, because no current fixture exhausts
the stock.

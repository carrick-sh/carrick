# Anonymous reservation supply: exact retirement completion

Part of #898. This prerequisite sits between the physical inventory layer and
the native private supply transaction. Its implementation inventory is recorded
on #898, before the change, rather than pinned to source lines here.

`PhysicalRetirementCompletion` belongs to one exact physical owner.
Its read-only wait retains the VM generation, record identity and logical owner
generation after directory removal or IPA reuse. Only successful terminal
finalization marks completion. Pin drop, unmap alone, record absence, producer
Drop and failed allocation return do not provide that proof.

Waiters enroll through the existing `PhysicalMemoryWait` contract, then probe
readiness once. Completion captures callback effects but invokes none under
owner guards. `GlobalFrameHostOwner` retains those effects in the same owner,
using its existing pending-owner directory and detached idle retirement queue.
The named persistent-executor idle boundary publishes them after owner guards
drop. The neutral owner classifies a last requested mapped pin as `ReadyToRetry`;
the carrier requests the same existing retirement turn. There is no new
worker wait, timer, polling loop, service journal or notification venue.

Like the existing callback registry, an already captured callback can run after
its enrollment is dropped. Consumers must authenticate their exact operation
and tolerate a stale wake. Dropping an enrollment before completion removes its
callback; dropping the producer never manufactures a successful completion.

This changes production physical-owner finalization and pin-to-idle mechanics,
so the full signed gate applies. No native supply consumer is enabled here:
there is no new successful supply ACK, speculative allocation or adoption.
Portable tests cover enrollment timing, unrelated identities, reuse,
cancellation and callback reentry after unlocking. The macOS adapter tests
cover real retained pins, finalization failure, idle completion and IPA reuse;
they cannot execute on the Linux worker.

S3 must consume this completion in the same `PrivateSupplyTransaction`, retain
inventory undo exactly once, and implement an owned Pending ring continuation.
Pre-delivery cancellation retains its service ticket; post-delivery cancellation
retains its reply until physical and table settlement permit ACK. It also keeps
the S3 review fixes for refusal handling, lock order, zero table counts and early
error cleanup. S3 remains unlanded until that path is complete.

Speculative stock, adoption, fork/exec/exit lifecycle and native deferred returns
remain above it. The final composed native layer removes the ignored slope
witness and must pass its unchanged strict service budget.

# Memory foundation development integration

Base: IPC integration 3e255ab20. Join elastic-return 8f268dee4 after source
review of physical receipt ownership, MM/carrier attribution, exact owner
retirement, pooled backing lifetime, failure and reuse tests.

The additive public exports retain IPC registration and add the scoped frame
observer types. The compiler-capture conflict retains the existing capture
unchanged: it is stale and must be regenerated on the clean final integration,
not represented as evidence for this source. Transition/global-state inventories
retain the semantic removal of the process-global accounting owner.

Verification: six el1_lifecycle_ tests, partial-discard peer-retention at
1/8/64, and carrick-embed test compile passed. The initial sandboxed embed
check failed to generate macOS USDT; the same command with required host
access passed. No signed execution or checkpoint acceptance is claimed.

Next: review and join descriptor/COW c555f5dd1, resolve shared ABI/runtime
interfaces, then connect reservation ownership and remaining host writers.
Guest descriptor activation remains guarded by copyout/backend conversion.
Existing signed accounting consumers must adopt checked scope/completeness
and retained observers before claiming the new physical-return proof.

## Descriptor/COW foundation joined

Join c555f5dd1 onto 3f8e349fc (the elastic-return merge). Review covered the
transaction/receipt identity boundary, slot admission/claim, rollback and
TLBI obligations, ABI placement, MM lane admission, fork drain and COW
continuation interfaces. This remains an unaccepted development integration;
full source/writer census and end-to-end qualification are still required.

Retain both pipe and MMU ABI dependencies and both carrier global-state rows.
Line-position conflicts preserve existing values pending clean reconciliation.
Compiler capture stays wholly unchanged and explicitly stale.

Combined checks passed: 97 EL1, 55 ABI and 152 MMU core tests; 37 runtime
guest-filter tests; three architecture guest-authority tests; embed test
compile and affected Clippy. No test retries or budget changes.

Production admission still refuses host_copyout=false/backend_writers=false.
GuestCowContinuation and the guest copy-window helper currently have only
test callers. Their existence does not prove production guest COW. Next is
reservation authority integration followed by actual copyout/backend routing,
scoped T6 observation and signed memory evidence. Do not flip admission bits
or remove the host pause before these writers are converted.

## Carrier reservation provider connection

Join reservation candidate f2efa3716 onto 8fc9513fd and connect its provider
to the persistent factory before worker admission. CarrierMetadataAccess
retains the existing PersistentCarrierMappings and exact VM generation;
dynamic extent resolution uses the existing exact-token resolver. Runtime
prepared views retain mapping pins, cache unchanged storage generations, and
lock the exact MM through the owned region's ZoneTables, not global pointers.

The new lifetime witness failed on absent access and passes after connection;
it retains mapping ownership across dropping the factory reference and rejects
access after exact custody retirement. Its initial host-only fixture required
an unmapped fixed lease to avoid invoking a real HVF unmap during cleanup.
The corrected semantic red and green are retained.

Checks: 27 kernel reservation-filter tests, 114 EL1 and 56 ABI tests, lifetime
witness and affected runtime Clippy pass. This does not activate anonymous
policy: legacy MemState admission still refuses a second anonymous owner.
The signed first-touch regression is next. The reservation branch's earlier
active-target fixture race, full source review, inventory reconciliation and
full acceptance remain open.

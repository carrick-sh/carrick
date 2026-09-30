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

# Fork-armed prepared first writes (#2226 cause A)

Contract: `kernel.el1.fault-entry`.

An untouched prepared leaf can carry Linux write intent while fork has armed
it read-only for copy-on-write. Publishing that leaf for a first write must
make it resident without making the shared backing writable. The retried
store then enters the existing COW resolver and gets private backing. ARM's
Publish already follows this rule; the x86 descriptor transaction now agrees.
A competing publication must authenticate both the expected backing and
writable or COW write intent before accepting an already-resident leaf.

The VM-free descriptor witness exercises the production transaction. The KVM
CLI witness runs two live processes: child and parent first-write different
untouched pages, check inherited data, and verify that each other's writes
remain private. Native x86 Linux runs the same static ELF. These bindings do
not change existing budgets or claim signed ARM acceptance. MM editor
contention in the fault path is cause B, owned separately by #2263.

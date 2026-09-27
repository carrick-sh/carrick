# Signed allocator with carrier custody and stage-2 records

Source b61195767 (full revision in identity files). The focused signed allocator
test exits 0. Basic allocation, 10 MiB growth beyond the bootstrap, full return
of 5,767,168 granted bytes, and recovery after one denied grant pass. Three
successful grants have exactly three completed returns. Negative entitlement
control passes; original and CLI cleanup scopes both have zero processes.
Exact test executable, CLI and fixture identities are preserved.

This verifies the combined coherent backing, carrier ownership/generation,
and stage-2 ledger changes in the real guest path. It does not close the full
allocator contract: concurrent guest use/pending host work, bounded-work and
retention evidence, and private test-control gating remain.

IRQ protocol remains explicitly unresolved: memory.rs documents that EL1
never unmasks IRQs, while alloc.rs restores its entry DAIF before synchronous
HVC #6. Restoring an already-masked state does not establish the brief's
no-host-wait-while-masked requirement. Do not unmask IRQs casually: current-EL
IRQ vectors deliberately fail loud. This needs a protocol-level resolution
within the existing scheduler/continuation architecture before acceptance.

No workload speedup or first-touch acceptance is claimed; the full EL1
migration goal remains active.

# Signed fault-entry green and controls

Source: `0c30348a22c322e2ef528687a0e0994f4a5cab4a`.
The same fixture used for the committed signed red now passes
`el1_memory_fault_entry_preserves_context` through the signed embed runner.
The unentitled negative control passes and scoped cleanup reports zero
remaining processes. The fixture also passes on the pinned native arm64
Docker oracle; its phase completed before signed guest execution.

The tested executable was frozen before subsequent signing. Its SHA-256 is
`8fc03453e05af357039d6273b6ff6c8ea3ac0be00183d340d34a7f104f16f1de`.
The fixture SHA-256 is
`e33f7cae1859cf978a1f1cb0e765deb1a903fbe1f40244a6fa36d321b416eb67`.
The receipt and manifest retain CDHash, UUID, entitlement and DOF evidence.

The same frozen executable passes both `CARRICK_EL1=0` and
`CARRICK_HVF_GIC=0` controls. The former accepts zero/absent EL1 fault
counts; the latter requires positive entry counts. Both retain the Linux
fixture assertions and zero-process cleanup. Executable hashes were checked
again when preserving this evidence.

This accepts the focused fault-entry/context-preservation increment only.
The fault handler still forwards to the host. In-guest first-touch service,
integrated CI, broader signed promotion and workload timing remain open.

# Retryable rollback after resolver revocation

Base candidate: `22323a34316e4fb0927242d5a24ced06edf64f81`.
Contract: `kernel.fork.stage1-image`.

Both `aarch64::tests::rollback_revocation` tests were added to the real
MMU-core crate before modifying rollback. Both failed: rollback returned
success and discarded its journal after a resolver that passed preflight
refused a write. Backing remained allocated and aligned throughout; this
witness tests resolution failure, not memory deallocation races.

The correction keeps the journal and staged entries until all host stores
succeed, returning `UnresolvedArena` at the actual failed resolution. A
partial restore retains the journal and succeeds on retry when resolution
is available again. Arena return and bookkeeping happen after completion.
It adds no allocation or owner pin and retains linear journal traversal.

Commands (all with `RUSTC_WRAPPER=`):
- `cargo test -p carrick-mmu-core --lib rollback_revocation -- --nocapture`: red, 2 failures.
- `cargo test -p carrick-mmu-core --lib`: green, 82 passed.
- `cargo test -p carrick-mem --lib`: green, 171 passed.
- `cargo test -p carrick-aarch64 --lib stage1_authority`: green, 20 passed.
- `cargo clippy -p carrick-mmu-core --all-targets -- -D warnings`: exit 0.

This is a director correction on the unaccepted live-table candidate.
Backing authority across access and retirement, snapshot recovery, complete
runtime integration, signed promotion, and workload timing remain open.

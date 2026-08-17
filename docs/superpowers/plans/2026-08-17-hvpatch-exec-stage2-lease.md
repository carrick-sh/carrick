# HVPatch exec stage-2 lease closure

## Goal

Make `node-app-smoke`, `node-v8-smoke`, and `node-libuv` reach their real TAP
entrypoints without `execve_rebuild` losing the global-frame stage-2 lease.
Do not treat Node version output or a cleanup-path change as completion.

## Proven failure

All three Carrick rows fail before TAP with the same missing lease for IPA
`0x100000000`, size `1523712`, followed by an EL1 maintenance failure. The
Docker app/v8 arms execute normally; libuv has a separate Docker-side failure
that must remain separately classified. The likely owner is
`HvfGuestState::execve_rebuild` and its `global_frame_exec_plan` transaction in
`crates/carrick-vmm-hvf/src/trap.rs`.

## Execution

1. Freeze the current signed binary receipt and prove the focused row red:

   ```sh
   just conformance full --lane hvf --suite node-app-smoke \
     --workers 1 --flake-retries 0 \
     --jsonl target/conformance/node-exec-red.jsonl
   ```

2. Capture the failed transaction with `carrick trace` using
   `scripts/dtrace/hvpatch-phase4-exec-replace-stages.d` and
   `scripts/dtrace/hvpatch-global-frame-stage2-inventory.d`. Require nonzero
   events, zero drops, and exact owner generation / IPA / lease transitions.
   If tracing changes the failure, use `carrick debug lldb-run --stop-on-signal
   11` and preserve a modified-memory core from the VM carrier.

3. Add a red unit test around the identified transaction boundary before the
   runtime change. The test must reproduce the exact missing/stale lease or
   premature-retirement condition; it may not merely assert that exec succeeds.

4. Fix the stage-1, stage-2, frame-inventory, and owner-generation publication
   as one rollback-capable transaction. Rearchitecture the exec plan if the
   trace proves the current ownership split cannot make that atomic.

5. Prove the reducer green on the newly signed binary, then run all three Node
   rows with exact TAP parsing:

   ```sh
   just conformance full --lane hvf \
     --suite node-app-smoke --suite node-v8-smoke --suite node-libuv \
     --workers 1 --flake-retries 0 \
     --jsonl target/conformance/node-exec-green.jsonl
   ```

6. Run the relevant Rust unit tests, `RUST_TEST_THREADS=1 just ci`, the complete
   closure probes, and the full cached-oracle closure checkpoint. Commit the
   reducer/trace artifact first, the runtime fix second, and ledger refresh
   last.


# Follow-up: post-no-return SIGSEGV witness for x86 root exec needs a production failpoint

Done item 2 also asks for a failure past the point of no return to end the root with SIGSEGV. This round has no witness for it: no x86 exec crosses the no-return arm yet, and there is no production failpoint to force a post-arm failure.

ARM has `HvpatchExecInventoryFailureInjection` (gated by `CARRICK_HVPATCH_EXEC_INVENTORY_FAILURE`, `vcpu_loop/exec.rs:644`, `:684`) for this. The x86 venue round should add the equivalent through the shared driver, not an x86-only hook. It should also take #2171's `ExecPastNoReturn` verdict once that lands; #2171 is still open, so `fail_past_no_return` on main takes a cause string.

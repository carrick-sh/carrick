# followup-1: #2146's closing note says slice d turns the x86 root-exec witnesses green; it cannot

Found in the work on #2235, step 1 (main `ace226052`).

The note that closed #2146 says slice d (#2235) "wires the routing that turns these
witnesses green". Those three witnesses (`production_root_exec_*` in
`cpl0_initial_mm.rs`, branch `fix/2142-root-exec`) are about **root** exec. On x86,
`settle_unwired_native_service` (`crates/carrick-el1-linux/src/dispatch.rs:1309`) stages
only a fork child's exec (`native_exec_claimed`, `dispatch.rs:528`). For the root it
returns the counted ENOSYS (`dispatch.rs:1335-1344`), and slice d does not change that
path.

Turning those witnesses green also needs:
- #2142 design slice 2 (a venue-typed `PendingExecReplacement`, `Cpl0TaskBindingDirectory::replace_exec`, and root rebinding);
- slice 4 (the x86 `RootExecVenue` and the director-owned crossing flip of rows 221/281).

#2188 already records this dependency.

**Proposal:** correct the routing on #2235/#2146. Use #2149's
`native_fork_child_execs_static_successor` as slice d's witness, and keep #2146's three
witnesses for #2142 slice 4.

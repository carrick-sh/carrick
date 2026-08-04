# Current-default exec/exit attribution plan

**Date:** 2026-08-03
**Goal:** decide whether process fork/exec/exit/reap work is a >=10% end-to-end
CPU or critical-wall opportunity on the shipped-default cold Go build, using
the 20-exec workload as a mechanism cross-check.

## Authority and constraints

- Reuse the existing opt-in `CARRICK_EXEC_STAMPS=<absolute path>` export. With
  the variable unset, the production path remains its existing single env
  lookup and performs no clock, rusage, file-open, or write call.
- Replace the untyped `EXECSTAMP1` line with one `EXECSTAMP2` record containing
  monotonic time, cumulative process user/system CPU, cumulative calling-thread
  user/system CPU, and a validity mask. Parent-return and terminal-reap records
  name the exact host child PID; reap records also carry that child's exact
  `wait4` rusage.
- Add a Rust `carrick debug exec-stamp-census` consumer. It accepts only v2,
  rejects malformed, duplicate, regressing, ambiguous, or incomplete chains,
  and emits one provenance-ready JSON report. No compatibility parser is kept.
- Export is the only new persistence mechanism. A crash leaves all completed
  O_APPEND records readable. For the crash itself, save a core and read the
  existing always-on event ring with `carrick debug lldb-run`; do not add a
  second in-memory lifecycle ledger.
- All timing remains untraced. DTrace may rank a mechanism later but cannot
  supply an absolute exec/exit total because active DOF re-registration
  perturbs every self-exec.

## Tasks

1. **Make the export complete and typed.** Add exact v2 rendering and metrics
   tests first, then wire child PID/rusage at the existing native fork and
   terminal `wait4` seams. Prove every record is still one append write.
2. **Add the fail-closed census.** Reconstruct repeated per-PID exec epochs,
   parent fork pairs, terminal child reaps, and leaf exit residuals. Report
   per-segment wall and CPU distributions, population coverage, and shares of
   caller-supplied total CPU/workload wall.
3. **Capture two workloads.** Use a newly signed binary and a dedicated,
   initially empty store per workload. Require successful workload markers,
   zero incomplete/ambiguous chains, source/binary/image/store receipts, and
   quiet preflight. Run the 20-exec micro first, then the cold build.
4. **Apply the gate.** Pursue one production hypothesis only if the cold build
   shows >=10% measured CPU or critical-wall opportunity and the 20-exec shape
   names the same segment. Otherwise stop this line and move to the next
   non-overlapping bucket. Never promote traced timing or summed concurrent
   wall intervals into an end-to-end claim.
5. **Close cleanly.** Keep the general export/census if it is lossless and
   opt-in, write durable evidence, update `handoff.md`, run focused tests and
   `RUST_TEST_THREADS=1 just ci`, and commit narrowly. The official 10.4446x
  ratio changes only after a clean serialized Carrick-then-Docker scoreboard.

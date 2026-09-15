# Ecosystem campaign wrap-up — 2026-09-14

The user requested stopping development and fast-forwarding the consolidated campaign to local main. This is an integration checkpoint, not completion of the ecosystem correctness/performance goal. No push is authorized or performed.

## Accepted implementation and validation

The integration branch `codex/sep13-inner-integration` contains 61 campaign commits through `cc1c1d80ba9a2ef632d8dda2d39c9192b3741b87`, followed by position-only host-authority reconciliation and this handoff. Main started at `7a381803487b5111c08d5f5442c40d31191295bb`.

Work includes initial named-credential resolution from the prepared image root, partial MADV_DONTFORK handling, descriptor/wait correctness, loopback TCP lifecycle corrections, root mkdir transaction admission, and oracle/verdict accounting improvements. Container cache experiments were not accepted into this integration.

All local receipts below are under `/Volumes/CaseSensitive/carrick/target/conformance/sep13-review/`.

- Latest signed CLI receipt: `sep14-disconnect-final-artifact.json`; source cc1c1d80b; SHA-256 `24b0343bca9f4b0065491f66d5121985f52dfea392a9899230ee5ee2b38a3e78`. Entitlement, signature and DOF checked. Binary remains in the integration worktree's target/release directory; fast-forwarding source does not rebuild main's binary.
- TCP disconnect probe: signed red failure followed by musl/GNU green, unentitled negative control passing, scoped cleanup zero. Receipts: `sep14-disconnect-signed-{red,green}.log` and associated artifacts JSONL.
- Source-stable host gates: `sep14-disconnect-host-gates/results.json`; formatting, runtime (2895 passed, 2 ignored), integration and workspace clippy passed.
- Fresh serial Docker/Carrick workload verification: `sep14-disconnect-workloads/verification.json`; connect01 7/7 MATCH; pathlib 461/461 MATCH with 148 matched skips; connect02 still fails at post-disconnect bind with ENOTSOCK. Three unique rows, unchanged artifact, no remaining scoped Carrick or Docker processes.
- Last broad public ladder, on an earlier artifact: probes green (902 generic, 31 dedicated, retained 46 passed/1 ignored), smoke 23/23 MATCH, full 2127 rows: 1249 MATCH and 878 INCOMPLETE. Receipts: `sep14-corrected-public-{probes,smoke,full}/`. INCOMPLETE includes shared failures, skips/empty classifications, deadlines and real divergences; it is not 878 established runtime defects.

The newest artifact has NOT repeated the entire public probes → smoke → full ladder. Full conformance and the performance goal remain unaccepted. The host-authority refresh is a macOS subset capture; Linux, FreeBSD and NetBSD capture profiles remain pending, not silently accepted.

## Next work, in priority order

1. Finish the post-disconnect pure INET lifecycle. connect02 now gets past AF_UNSPEC but bind returns ENOTSOCK. Native oracle `sep14-tcp-rebind-oracle.json` covers eight IPv4/IPv6 client/accepted cases: rebind to wildcard succeeds with a new port, aliases see it, a second bind returns EINVAL, and listen/connect can transfer again. Preserve endpoint identity/options and transactional port/listener ownership; a bind-only host fallback is insufficient.
2. Resolve XMLRPC readiness routing with direct continuation evidence. Core `sep14-xmlrpc-full-lldb/` contains a live listener with one queued connection and coherent strong/weak ownership. This refutes the earlier dead-Weak/lost-enqueue diagnosis. Continuation 91 has host fds, on_timeout=0 and no watched descriptions, which matches the ppoll all-host path; it has NOT been established to be accept. Verify its saved syscall before fixing routing. Hypothesis: host-only polling misses in-zone listener readiness. Controls vary under debugger/tracing, so do not claim deterministic prefix dependence.
3. Bound fork planning by live mappings while preserving structural owners. `sep14-futex-mapping-amplification.md` and JSON quantify 22 live plus 5765 shadowed rows scanned by TaskMappingIndex::iter in build_process_plan (5787 total, 263 times the live count). This proves algorithmic amplification, not its wall-time share. Naively deleting/skipping owner-bearing shadowed rows is unsafe. Use authenticated structural ownership and add a red churn fixture before implementation. Core: `sep14-futex-full-lldb/`; post-detach ETIMEDOUT is potentially a debugger-stop artifact.
4. Rebuild/sign from final source, record exact provenance, run the public ladder and machine-count every declared ecosystem row. Performance claims require paired same-host measurements; incidental CPU load is allowed by the user but cannot substitute for comparison controls.

Old core executable `sep14-046b-core-carrick` (SHA-256 `02889f31744aceda67e09a4fb575d5f9b6a5a09c031d4297db61392637e063c0`) is preserved for symbolication. See the append-only `sep14-blocking-scheduling-audit.md`, with the corrected XMLRPC hypothesis above taking precedence over its earlier accept inference.

## Preserved work outside integration

No experimental worktree or branch is deleted. `agy/sep13-inner-tcp` is integrated; `agy/sep13-partial-dontfork` is patch-equivalent to integrated work. `agy/sep13-user-resolution` retains eight divergent cache/identity experiments through 35b16f7db plus dirty compression dependency changes and examples; these are abandoned alternatives, not part of the accepted inner-workload implementation. The detached `sep13-tcp-expanded-red` worktree retains its old red probe/oracle edits. The `/private/tmp/carrick-b93-timers` worktree is preserved. Main's four untracked September 13 plan files are preserved unchanged.

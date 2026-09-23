# Named-user startup recovery plan

Approved first workstream of the September 13 correctness recovery goal.

Goal: eliminate repeated full-rootfs reconstruction during named user/group lookup, preserving image semantics.
Architecture: reuse the existing published immutable layer cache via a narrow read-only RootFs constructor. Reuse default scratch-root selection, ordered layer identity, atomic publication and confined path resolution. Numeric users keep their no-lookup fast path. No parallel account cache or mutable cache authority.

Evidence: target/conformance/sep13-review/review.md, startup-lldb.txt and user-comparison.json. Named root access01 took 4.693s versus numeric 0:0 at 0.183s; 1393 LTP rows timed out.

Implementation scope: engine/src/lib.rs; runtime/src/rootfs.rs and layer_cache.rs; minimal scratch-root API seam and adjacent tests.

- [ ] Deterministic red-first test proves warm lookup does not decode/rebuild complete layers; use extraction accounting, not timing assertions.
- [ ] Preserve upper passwd/group replacement, whiteouts, symlinks and confinement, ordered distinct layer stacks, named/mixed/numeric users and groups, unknown-name errors and image defaults.
- [ ] Expose immutable read authority only; route engine lookup through it. Cold extraction happens through existing atomic cache publication; report errors honestly.
- [ ] Run RUSTC_WRAPPER= cargo test -p carrick-engine --lib -- --test-threads=1.
- [ ] Run RUSTC_WRAPPER= cargo test -p carrick-runtime --lib rootfs -- --test-threads=1 and the layer_cache filter. Run formatting and relevant package clippy.
- [ ] Director reviews actual diff, identity and confinement, and reruns tests before signing a candidate.
- [ ] Director verifies original named-user LTP assertions at normal fanout, then promotes one signed artifact through probes -> smoke -> full. Any red rung blocks promotion.

No retries, larger deadlines, numeric-user workaround, expected gaps, shared release replacement by worker, or push. TCP, partial MADV_DONTFORK and remaining deadlines retain their approved scope.

User explicitly approved Antigravity external sharing after the review rejection. Worker user-resolution is running in .worktrees/sep13-user-resolution, conversation 2b8cf0e1-4bfc-4169-9b92-10e8887eb3a1, AGY_RUN_ID=sep13-correctness. Director acceptance remains pending.

## Current checkpoint

- Antigravity initial patch reviewed; first revision removed production resettable counters and added noncanonical-path keying, but canonical-looking paths still aliased and directory counts did not prove no decompression.
- Director stopped the second turn's repeated inventory checks via run-scoped manager and sent review-2 into the same conversation (turn 3). Existing worker commits and changes retained; no integration.
- Fresh native-arm64 Docker suites all exit zero: go-net_smtp, cpython-httplib, cpython-urllib2_localnet, node-app-smoke, node-libuv. Cache untouched; evidence fresh-oracle/results.json under sep13-review.
- Two pre-inzone/current comparisons: SMTP and HTTP each pass twice on preserved 457da5fb6521ff7b and fail twice on current fa1ec82e. Evidence tcp-attribution/results.json. These runs are correctness attribution, not performance measurements; worker host builds were separate but potentially concurrent.
- Main remains 7a3818034. New TCP plan retains endpoint ownership/rollback scope. Startup acceptance and all signed promotion gates remain pending.

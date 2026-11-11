# Performance results

Moved from `AGENTS.md` (#2118).

- Data: [`docs/perf-results/overhead-campaign-narrative.md`](docs/perf-results/overhead-campaign-narrative.md)
  is **historical**: its figures (cold go-build 10.18x) measured the native
  lane removed in `f9933c9da`, and the `native-amplification` AMP1 profile
  records nothing on HVPatch (no `native_syscall_service_entry` call site).
  Don't cite them; the paired HVPatch baseline is #357, the ledger port #356,
  and `hvpatch-exit-attribution` is the profile to measure with (#363).

Measure with `hvpatch-exit-attribution` (#363); the paired HVPatch baseline is #357.

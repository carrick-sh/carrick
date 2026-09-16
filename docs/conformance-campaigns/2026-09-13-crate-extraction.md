# Crate extraction campaign — acceptance receipts

Plan: [`docs/superpowers/plans/2026-09-13-extract-carrick-vfs-and-carrick-kernel.md`](../superpowers/plans/2026-09-13-extract-carrick-vfs-and-carrick-kernel.md).
Branch `feat/sep15-extract-vfs-kernel`, merge base `acbddc406` (main, 2026-09-15).

Every receipt below is a pair: the branch binary and the UNMODIFIED merge-base
binary, run through the same gate on the same host in the same hour, so a row is
attributed to the branch only when it fails on the branch and passes on the base.

## Phase 1 receipt — `carrick-vfs` extracted (2026-09-16)

| | Branch | Base (unmodified `acbddc406`) |
|---|---|---|
| Source HEAD | `401df015d` | `acbddc406` |
| Binary SHA-256 | `b40134ca433c87697493fd872ea7d883a663ed86b4802e5c57c675bf44cb3a39` | `fb4eceae5f5ee789d08b0a0a05b3ca0cb4775ff9aad8fe99d81993919109520e` |
| CDHash | `1b85aadc05c4bfa985c2cf4cde67d52325336673` | `0fe4b0f2e3bbad8300aa53d36c66f36dfa867828` |
| LC_UUID | `B37609B0-55EE-39C6-94A8-EC78C3EF38AA` | recorded in the base log |
| Hypervisor entitlement / `__dof_carrick` | present / 1 section | present / 1 section |
| Run ids | `p1accept-29611` (conformance+probes+embed), `probes-branch-*` | `baseaccept-57012` |
| Host state | no sibling builds or guests, Docker VM idle (0.5 GB), images identical to every other worktree | same |

### `just conformance full` (tier full, 2,127 rows, cached oracle)

| | Branch | Base |
|---|---|---|
| MATCH | 2082 | 2083 |
| DIFF (excused) | 13 | 13 |
| Gating (REGRESSION + unexcused TIMEOUT) | 26 | 25 |

The 25 base failures are all present in the branch's 26. Branch-only row:
`ltp-mq_notify03` (TIMEOUT `[blocked]`, carrick 5/5 vs oracle 7/7); re-sampled
3× on each binary with `--suite ltp-mq_notify03 --flake-retries 0`: **MATCH 7/7
on every sample, both binaries** — load noise, not a regression.

**The 25 shared failures are pre-existing on main in this environment and are
not attributable to the branch.** They are, for the owner's attention:

- REGRESSION vs the blessed baseline (which says `match` for each):
  `ltp-accept02` ("Multicast group was copied!"), `ltp-epoll_wait05` ("Wrong
  number of events reported 0"), `ltp-recv01` (MSG_ERRQUEUE errno 0 vs 11),
  `ltp-recvmsg01`, `ltp-send02`, `ltp-setsockopt02`, `ltp-sendfile09`,
  `ltp-sendfile09_64`, `ltp-ioctl02`, `ltp-test_ioctl`, `ltp-execve03`,
  `ltp-lseek11` (short read; already `regression` in the 2026-09-08 main run),
  `cpython-socket` (634/657).
- TIMEOUT `[blocked]` (harness-classified real hangs, 0 `[starved]`):
  `ltp-epoll-ltp`, `ltp-fork14`, `ltp-futex_cmp_requeue01`, `ltp-inotify09`,
  `ltp-msgstress01`, `ltp-pipe06`, `ltp-shmctl05`, `ltp-timerfd_settime02`,
  `go-go_types`, `go-net`, `go-net_http`, `cpython-tarfile`.

The blessed `baseline.jsonl` at the merge base is therefore not reproducible on
this host today for those rows. Image digests (`ltp:arm64` `bc75ded4…`,
`carrick-go-conformance:1.24` `357a0879…`) match every other worktree's
recorded digests, so the images are not the variable. Not investigated further
here: it is outside the branch's scope and needs the owner's attribution on
`main` (the 2026-09-14 ecosystem run on `7142d2438` reported 0 regressions).

### `just conformance-probes`

Branch: **EXIT 0** — every gating lane MATCH (`generic_probe_shard_{0,1,2}`,
retained runners, CLI process-boundary contract). Report-only, non-gating
DIFFs as labelled by the harness: `arm64:gnu:tlbibroadcast` (1/33) and the
whole `amd64:musl` Rosetta lane (26/26). The first attempt failed for an
environmental reason unrelated to the code: a fresh worktree carries no probe
store; the store was synced from `.worktrees/sep14-tcp-dualstack` (same commit,
probe sources verified identical).

### `just test-embed`

Both binaries: **the same four failures, nothing else** —
`children_run_concurrently`, `fault_latency_is_independent_of_sibling_fork`
(two-process timing-shape tests) and `explicit_carrier_runs_two_isolated_containers`,
`explicit_carrier_shutdown_cancels_a_live_guest_and_joins_it`. Pre-existing;
not attributable to the branch.

### Verdict

No regression attributable to the Phase 1 extraction on any gate. The environment's
25 pre-existing gating rows and 4 embed failures are reported above for the owner.

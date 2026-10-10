# N2 L2 red witnesses: descriptors and pipes

Test-only preparation against `b1167c6e19811c5b3a601d979cedca844656454f`.
Readiness plan: PR #25 at `94567dd6f` (fetched without merging).
No production path changes; no N1/N2 row is closed. The six new tests in
`crates/carrick-el1/tests/n2_readiness_fd_pipe.rs` are auto-discovered and
explicitly ignored as `N2 red witness: ...` pending owner integration.

Contracts: `kernel.el1.fd-single-owner`, `kernel.el1.ipc-lifecycle`; the
`kernel.el1.creation-native-path` registration belongs to the future driver.
Linux authority is `pipe(2)`, `pipe(7)`, `close(2)`, `fork(2)`, `clone(2)` and
`execve(2)`. Structural expectations are zero semantic forwards, exact copied
bytes, retained OFD identity, and a single final endpoint release. Existing
B-prep pair/revision algorithms and their deterministic budgets are unchanged.

## Witnesses and observed reds

All six individually selected `--ignored --exact --nocapture` runs compiled,
ran exactly one test and exited **101 at the stated assertion**. Counts below
are ordered by scale 1/8/64. Every expected forward vector is `[0, 0, 0]`.

| Witness | Row | Observed red | Production change required |
| --- | --- | --- | --- |
| `pipe2_owns_pair_publication_at_1_8_64` | 9 | Dispatcher pipe2 forwards `[2, 16, 128]` | Own creation/copyout/publication in EL1 using the existing pair transaction. Stdio occupies 0–2 in the same table; successful results must install paired reader/writer OFDs and CLOEXEC. |
| `pair_copyout_refusal_preserves_both_tables_at_1_8_64` | 9 | `serve_ipc` forwards `[2, 2, 2]` | Bind refused pair copy to the owner. A first writable fd word followed by an unavailable second word must leave the sentinel and both slots unchanged and return EFAULT (14). |
| `close_after_fork_and_exec_keeps_pins_and_releases_once_at_1_8_64` | 9 | Dispatcher close forwards `[2, 16, 128]` | Remove slots in EL1 across independent tables sharing OFDs; retain the operation pin until its one final release and EOF. |
| `three_page_resume_survives_close_reuse_then_requires_final_close_at_1_8_64` | 9 | Final reader close forwards `[2, 16, 128]` | Compose EL1 final close with the existing retained operation and endpoint authority. Exact-prefix continuation controls already pass; they cannot replace the red close assertion. |
| `broken_pipe_requires_owner_completion_at_1_8_64` | 9/10 | Dispatcher write forwards `[2, 16, 128]` | Bind Linux EPIPE (32)/SIGPIPE selection to the owner, including a prefix already written. |
| `close_owns_one_namespace_for_all_backings_at_1_8_64` | 9 | Dispatcher close forwards `[14, 70, 518]` | Own slot removal for stdio/host descriptions, pipes, eventfd and epoll in the same authority. Physical host release stays separate from Linux slot selection. |

The fixture owns and frees its aligned directory/pool allocations. Both task
identities (101/102), serials (1101/1102), MM identities (71/83), open spaces,
and table-map entries remain live throughout each case. No host syscall
fallback runs. Existing dispatcher read/write service on both slots is a
positive admission control in the fork/CLOEXEC witness.

The copyout witness injects refusal through the production `serve_ipc` API:
the dispatcher does not expose a configurable UserCopy on this base. Both
identities use the same synthetic VA at the last four bytes of a page, with
the second fd word in the missing next page. It checks the full surviving table and
both absent output slots. It does not claim to have exercised N1 permits or
concurrent observation during pair publication; B-prep tests retain the latter
atomicity and logarithmic slot-search proof.

Fork, CLONE_FILES table sharing, exec unshare and CLOEXEC are **public fd-core
setup**, not production clone/exec routing. The close witness checks shared
OFD holds `(2, 1)` before issuing the two owner closes; successful close must
leave `(0, 1)` until final unpin. Its post-close release/EOF assertions are
conditional on the route no longer forwarding, so they are not green evidence
on this base. The all-backing witness pins each description during close,
allowing host-resource custody to remain a physical-release obligation.

The continuation witness fills a one-page pipe from a three-page source,
stores/reloads the real IPC operation token after each step, closes both
numeric writer slots through the existing core, and reuses the number for a
different object. It then completes only the remaining bytes, releases the
old writer once and observes EOF. Counts are exactly 12,288 / 98,304 / 786,432
bytes; each source byte is visited once. The final reader closes still forward.
Suspension is a substrate capacity boundary, **not an injected Linux signal**.
The broken-pipe control separately writes a one-page prefix, removes the last
reader, and observes the core SIGPIPE decision without copying more source.
Its dispatcher write is a fresh call requiring EPIPE, not a resumed signal
completion.

## Open driver bindings

- Accepted N1 UserTransfer permits: exact-generation preparation, rollback,
  retained-read/write drain and owner copy faults across two real same-VA MMs.
- Production fork/CLONE_FILES/exec publication; N1's staged host-file OFD
  cursor across dup/fork/SCM_RIGHTS. No competing cursor is introduced here.
- Delivery/selection of actual SIGPIPE and interruption after a written prefix;
  these public APIs expose a core decision, not a Linux signal-owner binding.
- Real scheduler suspend/resume/cancellation and default-pool progress. This
  fixture calls `transfer` in bounded steps, not the runtime executor.
- Driver contract registration, signed embed, native-arm64 Docker differential,
  ratios, and exact-artifact acceptance. No guest, Docker or load generator
  ran; there is no signed acceptance receipt.

## Commands and receipts

Source `/Volumes/carrick/dev/env.sh` before each command. For each witness in
the table, the red command was:

```sh
CARRICK_RUN_ID=n2-l2-<receipt> cargo test -p carrick-el1 --test n2_readiness_fd_pipe <witness> -- --ignored --exact --nocapture
```

Receipt suffixes, in table order: `pair`, `copyout`, `close`, `resume`,
`broken`, `backings`. Full logs on cloudmac are `/tmp/n2-l2-<receipt>.log`.
The logs are local diagnostics, not portable acceptance artifacts; the
observed red vectors are retained above and in the commit body.

```sh
CARRICK_RUN_ID=n2-l2-core cargo test -p carrick-fd-core -p carrick-pipe-core --lib
CARRICK_RUN_ID=n2-l2 cargo test -p carrick-el1 --test n2_readiness_fd_pipe -- --nocapture
CARRICK_RUN_ID=n2-l2-clippy just clippy
CARRICK_RUN_ID=n2-l2-fmt just fmt-check
CARRICK_RUN_ID=n2-l2-domains just lint-domains
```

Core controls: **38 fd tests + 30 pipe tests passed**. Default new-target run:
**0 failed, 6 ignored**, as required for this explicitly red-first phase.
Logs: `/tmp/n2-l2-core.log`, `/tmp/n2-l2-default.log`.
`just clippy`, `just fmt-check` and `just lint-domains` passed; logs:
`/tmp/n2-l2-clippy.log`, `/tmp/n2-l2-fmt.log`, `/tmp/n2-l2-domains.log`.
The authority census executed macOS CLI/runtime/HVF profiles (618 reviewed
rows); Linux/FreeBSD/NetBSD profiles remain pending. This is a local subset
pass, not cross-host acceptance.

Pre-push `CARRICK_RUN_ID=n2-l2-ci just ci` exited 101 at rustdoc;
`/tmp/n2-l2-ci.log` records unresolved links in unchanged
`crates/carrick-mmu-core/src/aarch64.rs:299,826,889,949,1831` (`5:0`,
`publish_existing_invalid_private_pages`, `1`). Format, Clippy, full local
domain checks, dependency policy, matrix, layering, portable-kernel checks
and workspace build passed before that failure. Host tests and integration
tests after rustdoc were not reached. This is an inherited, out-of-fence
full-CI blocker, not a passing acceptance receipt. The run used test commit
`c57b49942`; subsequent changes only record its result in this document and
the commit message.

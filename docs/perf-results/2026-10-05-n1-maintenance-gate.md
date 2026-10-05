# N1 fork integration and backing-maintenance gate

Status: **not review-ready; signed gate RED**. Tested source:
`e1435e4e06a83a57931f37cff46afbba8c23b7c2`, based on batch-5 main
`51bfe67f4`. This receipt and the trace-header qualification are later
non-executable changes; they do not claim a newly tested binary.

## Integrated work and host proof

Preserved n1-fork authorship while cherry-picking `71bd58268`, `c7b5fd6e2`,
`91d6b5549`, `fcf203fa3`, and `a0d40fe78`. The latest fetch immediately before
the gate still named `a0d40fe78`. Recomputed the worker's inventory-only
refreshes on the clean integrated tree. The Mac production trait bound needed
qualification after the worker restricted its import to tests.

`42e4070a4` implements typed pending-brk backing maintenance. The saved
`pending_brk_scrub_must_not_wait_for_its_own_gate` witness first failed on
ordinary UserWrite's own Gate at revision 2, then passed through the production
owner-maintenance binding. Its two-live-MM case retains the peer's shared
bytes while zeroing a fresh physical replacement. It also covers exact
request/incarnation rejection, stale physical generation, adjacent bytes,
regrowth, reused-VA refusal, and bounded descriptor work. Ordinary UserWrite
remains refused while the transaction gate is raised.

Host verification:

- 114 AArch64 lib tests, the two-MM owner-fork witness, 278 EL1 lib tests,
  134 EL1 ABI lib tests, and eight focused brk tests passed.
- Clean-tree inventory reconciliation and all four runtime-abort shards passed.
- Full `just ci` passed at `17f276152`, then again at `e1435e4e0`, including
  rustdoc and integration. No inherited rustdoc waiver is used.
- `just test-loom` passed all five tests (two fd-core, three terminal-clear).
  These existing models do not substitute for the new maintenance witness.
- Darwin provider listing found no `dtrace:::DROP`. Removed that ineffective
  clause; the existing Carrick consumer rejects all drop counters. The script
  compiled with `sudo -n /usr/sbin/dtrace -Z -e -s
  scripts/dtrace/hvpatch-owner-fork-refusal.d -c 'target/debug/carrick --version'`.

## Exact fixtures and signed artifacts

Native Linux VM `carrick@10.14.14.66` published this exact source using
`just fixtures-publish e1435e4e06a83a57931f37cff46afbba8c23b7c2` from the
clean detached `/home/carrick/dev/wt-n1-fixpub`. Its temporary worktree was
removed after copying and verifying the archive. No Docker was started.

Bundle: `target/fixtures/published/e1435e4e06a83a57931f37cff46afbba8c23b7c2/d35300ad6e73a7644b109a743baa70af7f870691c4a69e435a38f66cce701370.tar.gz`.
VM/Mac archive SHA-256 both:
`0e90e6d3193a5860db44371daddf42d6e8d0cc53dc4914f998cba1834e0c81b0`.
Restore verified **1,133 executables**, one durability flush.

All evidence is retained in `target/n1g2/maintenance-e1435e4e0/`, including
`gate.sh`, `gate.log`, fixture manifest, image metadata/layer hash verification,
raw outputs, exact D script, `SHA256SUMS`, and `cleanup-receipt.txt`.

| Artifact | SHA-256 | CDHash | LC_UUID |
|---|---|---|---|
| CLI `carrick` | `7e38ad4750e2fad2d4c86251d1c74df81aa9f50693df448193ab4455721e6cd1` | `9a4a26fcb5a5f4d6d207247eece8617e5a2e60d7` | `610B23B8-715F-3F19-91F5-7956A87E9E30` |
| `el1-sched-tests` | `3fcb09172edd5f01bcae55745b725457289a2211c014867c7f740fc8dac1ed42` | `e5a0ac5b366e7ed9b2ce3aa4b9dd5420a2562525` | `B08F2F66-DF1B-371D-A4C3-7DAFFCCB282A` |
| `copyout-tests` | `84d3d4026ee28de820eac381f63aaf145cb383bac843e810f946f610d902fd92` | `acccc8a4629fdcdaebfbed192e12528f67b54adb` | `950FF46C-BAB1-3A88-BC31-662A9F0CBA1F` |
| `hello-tests` | `225c0fbebede4f706404c79ce6b54b92bf260ae8a6d05031ddfaf946ee1b0abb` | `f97175631e7d6c4f71514207490caa02dc6f402f` | `FBE5ACC2-9621-374B-98BD-5895C64698FF` |

All four carry `com.apple.security.hypervisor` and `__dof_carrick`. The
standard embed signer signed 31 executables and invoked the exact hello test;
its full receipt is `hello-artifacts.jsonl`. The unentitled negative control
passed. Guest fixture SHA-256:

- scheduler: `c0f924f610978ede018dcc1fcaae633b3b74ced62df91cf5fed00c6fae1e254b`
- copyout: `d925c73ed2993e4714274566d6be38134d380f62e5b2487996cb25e678323a3b`

## One exclusive gate: complete, not passing

Invocation used `target/debug/carrick-xtask host-lease --mode gate --
/bin/bash /tmp/n1g2-maintenance-gate.sh` with the exact source and bundle
above. The retained `gate.sh` is the full command sequence. The lease covered
restore, `just build`, signing, every guest, traces and scoped cleanup.
`RUST_LOG` was unset. No retries or altered budgets/concurrency were used.
Artifact hashes were checked before and after their runs; they did not change.

Signed embed hello, CLI `/bin/sh -c 'echo hello world'`, and the entitlement
negative control passed. All six comparison tests returned 101:

| Test suffix (`el1_`) | Previous 77b7d5e71 failure | This artifact |
|---|---|---|
| `anonymous_reservations_stay_in_guest` | brk backing scrub abort | Guest reports `anonymous-reservations count=64 pages=160 mmaps=65 brks=2 ok=true`; teardown then refuses `clear-child-tid claim differs from its captured thread` |
| `delegated_root_concurrent_vma_ops` | fork failed | Same guest fork failure |
| `delegated_root_map_fixed_over_cow_pages` | fork failed round 0 | Same guest fork failure at round 0 |
| `fork_cow_resolves_in_guest` | page-table region not mapped | Refuses `clear-child-tid claim differs from its captured thread`; no success claim |
| `thread_lifecycle_ptrace_traceclone` | fork failed | Same guest fork failure |
| `thread_lifecycle_spawn_slope` | fork failed | Same guest fork failure |

The anonymous fixture provides live evidence that invalidation, private scrub
and regrowth now finish; its final test result is still red. Main's prior
completing workloads/budget failures are recorded in the batch-5 receipt.
No fresh main control was run for the newly exposed teardown error.

Copyout is **8/10**, not accepted. Runs 2 and 10 fail with:
`owner supply declined an exact grant after predecessor reconciliation`.
The other eight complete the unchanged read/pread/recvfrom fixture and all
300 race rounds each. Do not replace these failures with earlier 10/10
receipts or characterize them as timing noise. The failure-only message does
not yet establish which exact grant/residency identity was refused.

Summary: `ten=1 hello=0 cli=0 six=1 traces=0`; gate process exit **1**.
Every one of the **21 unique run IDs** has `remaining carrick procs = 0`,
including hello's helper control, six cases, ten copyout runs and two traces.
The gate command returned and released its exclusive lease.

## Fork diagnostics to forward to n1-fork

Both traces ran after all uninstrumented cases under the same lease, retained
scheduler executable and CLI. Command form:

```sh
CARRICK_RUN_ID=<unique> RUST_TEST_THREADS=1 target/release/carrick trace \
  --script scripts/dtrace/hvpatch-owner-fork-refusal.d --require-script-exit \
  --trace-out <raw> -- --external <retained-el1-sched-tests> <exact-test> \
  --exact --nocapture
```

The trace CLI returned zero for each required script receipt, proving no
consumer drops or interruption and a successful script exit. The external
guest tests themselves returned 101; a successful capture is not a successful
fork. One failure-only probe plus two closed-child controls fired per case;
no hot-path tracing was enabled. These are diagnostic, instrumented runs.

VMA (`owner-fork-vma.raw`):

```text
OWNERFORKREFUSAL1|closed-child|mm=2|pid=7601
OWNERFORKREFUSAL1|closed-child|mm=3|pid=7601
OWNERFORKREFUSAL1|refused|errno=22|stage=3|parent_mm=2|child_mm=3|generation=12|pid=7601
OWNERFORKREFUSAL1|summary|closed_children=2|refusals=1|errors=0|bounded=0
```

Ptrace (`owner-fork-ptrace.raw`):

```text
OWNERFORKREFUSAL1|closed-child|mm=2|pid=7627
OWNERFORKREFUSAL1|closed-child|mm=3|pid=7627
OWNERFORKREFUSAL1|refused|errno=22|stage=3|parent_mm=2|child_mm=3|generation=8|pid=7627
OWNERFORKREFUSAL1|summary|closed_children=2|refusals=1|errors=0|bounded=0
```

Stage 3 names the table-pool/live-words acquisition interval, before census.
It does not identify which predicate inside that interval failed. Recommend
n1-fork add the corresponding two-live-MM contract witness before changing
production custody. Separately, the driver must diagnose the exact captured
thread behind `PendingChildTidClear::new` and the owner-supply false return
in `vcpu_loop/binding.rs`, preserving the retained failing artifact. Use
contracts and trace/lldb evidence; no timing or concurrency changes as closure.
No helper PR integration, batch-6 rebase, or whole-N1 acceptance is claimed.

# N2 L3 preparatory red witnesses

Base: `b1167c6e19811c5b3a601d979cedca844656454f`, cloudmac, 2026-10-04.
Scope: two auto-discovered integration targets only; no production, manifest,
registry, N1, or driver-reserved file changes. Every new test has an explicit
`N2 red witness` ignore. No readiness row or signed layer is closed.

Contracts: `kernel.futex.contention` and the readiness plan's
`kernel.el1.creation-native-path` ownership requirement (the latter descriptor
is absent on this base and remains driver-owned). Linux authorities are
`sched_setaffinity(2)` thread selection, `futex(2)` compare-before-enroll/EAGAIN,
and `poll(2)` readiness sets and immediate timeout. No Docker oracle was run.

## Witnesses and observed reds

Names below are exact test filters. All scale points ran before the final
failure assertion, rather than stopping after the first failing scale.

| Target / witness | Row | Observed red | Production change needed |
| --- | --- | --- | --- |
| kernel-example: `remote_affinity_selects_exact_live_thread` | 5 | Live remote nonleader returns errno **3**, target mask stays 3 instead of 1; caller stays 2. | Resolve the exact remote thread in the task graph, apply Linux permissions, and publish that thread's eligibility. |
| kernel-example: `remote_affinity_selects_exact_live_process_leader` | 5 | Returns success **0**, but target mask stays 3 instead of 1. | Publish remote eligibility instead of acknowledging a no-op; preserve caller mask. |
| kernel-example: `ppoll_readiness_before_enrollment_has_one_owned_completion` | 8 | At 1/8/32 pipe descriptors, **2** ppoll dispatches instead of **1**. | Own the decoded set and typed completion through the enrollment race and copy out once without Linux redispatch. |
| kernel-example: `ppoll_readiness_after_enrollment_has_one_owned_completion` | 8 | Same **2 versus 1** dispatch failure at all scales. | Resume the owned set directly after readiness. |
| el1: `shared_futex_mismatch_is_owned_in_both_live_mms` | 7 | `Forward`, unchanged x0 **1073745920**, rather than `Served/-11`; forwards **2/16/64** at scales 1/8/32. | Serve shared futex comparison with exact owner memory/key admission in Linux personality; do not forward Linux selection. |
| el1: `empty_ppoll_timeout_is_owned_in_both_live_mms` | 8 | `Forward` rather than `Served/0`; forwards **2/16/64**. | Route ppoll decode and immediate completion through the Linux owner. |

Affinity runs use fixed seeds **3, 7, 19** and a 512-transition bound, two
distinct live process/MM contexts, and 1/8/32 requests. The first failure
(seed 3, scale 32) is captured and strictly replayed, then reduced to 8 and 1
operations and replayed again. Original and one-operation JSON receipts are
printed in `/tmp/n2-l3-schedule-red.log` and extracted into
`/tmp/n2-l3-affinity-receipts.jsonl`; the minimal receipts have four
decisions. This is operation-count reduction, not general schedule delta
debugging. The fixture needs at least two exposed guest CPUs.

The ppoll tests use actual pipe/fork/ppoll dispatch and continuation work
metrics. Both processes retain their descriptors until poll completes. The
writer targets only the final member of each 1/8/32-element set; all returned
revents are checked. Each case observes and requires exactly one enrollment,
park, wake publication, and resume, with no unknown/dropped measurements. Only
the redundant Linux dispatch budget fails. Bounded checkpoints place readiness
before enrollment or after parking. These are deterministic orderings, **not**
seeded ppoll schedules: today's schedule harness explicitly rejects external
readiness. The affinity receipts must not be represented as wait receipts.

The EL1 witnesses use the real region dispatcher with two open zone MM
identities (71/83), distinct task/thread identities, and the same guest VA.
They supply read-only `UserWord` access and reject CPU switching. These are
nonblocking owner-entry witnesses, not full admitted wait-operation proofs.

## Unsupported layers and driver requests

- **TID reuse:** the public graph allocator does not offer bounded numeric
  reuse; `set_next_for_tests` is private and `cfg(test)`. Supplying the same
  backend `ThreadId` does not reuse a guest `LinuxTid`. A rejected preparatory
  fixture exposed this distinction and was removed; its setup assertion is
  not claimed as red evidence. Driver must expose a legitimate bounded reuse
  fixture while retaining both processes and checking exact generations.
- **Seeded all-zone/mixed waits, timeout versus signal restoration:** scheduled
  external readiness is unsupported in `EX/src/schedule.rs`/`driver.rs`.
  Driver must bind the production owned set, physical completion input and
  L4 interruption/temporary-mask reducer, then capture/replay/shrink those
  races. Empty ppoll and unscheduled all-pipe sets do not cover mixed sets.
- **Shared futex after unmap/reuse:** `UserWord` exposes value reads, not a
  retained shared mapping identity. Driver must bind N1 exact-generation
  UserTransfer/mapping custody and shared key retirement before this race can
  be represented faithfully. The mismatch witness cannot establish wake
  cardinality or affected-waiter queue work; those remain open.
- **Default-pool exhaustion: UnsupportedLayer.** The scripted backend uses
  host threads per actor. Driver must add the real bounded-executor fixture,
  retain the unchanged default pool, and run 32 partial writers plus a
  runnable reader. No service-slot or host-thread population substitutes.
- Register the leaf bindings and any missing wait-set work metrics through
  the reserved contract/observability files. Preserve neutral keys, owned
  sets and typed completions; Linux masks, errors and futex policy stay in
  personality. No secondary transport or owner was introduced here.

## Verification receipts

All commands source `/Volumes/carrick/dev/env.sh` and stamp `CARRICK_RUN_ID`.

```sh
CARRICK_RUN_ID=n2-l3-schedule cargo test -p carrick-kernel-example --test n2_readiness_wait -- --ignored --nocapture
CARRICK_RUN_ID=n2-l3-owner cargo test -p carrick-el1 --test n2_readiness_wait_owner -- --ignored --nocapture
CARRICK_RUN_ID=n2-l3-schedule-green cargo test -p carrick-kernel-example --test n2_readiness_wait
CARRICK_RUN_ID=n2-l3-owner-green cargo test -p carrick-el1 --test n2_readiness_wait_owner
CARRICK_RUN_ID=n2-l3-clippy just clippy
CARRICK_RUN_ID=n2-l3-fmt-check just fmt-check
CARRICK_RUN_ID=n2-l3-lint just lint-domains
```

Red logs: `/tmp/n2-l3-{schedule,owner}-red.log` (expected exit 101, four and
two behavioral failures). Ordinary target logs:
`/tmp/n2-l3-{schedule,owner}-green.log` (all new witnesses ignored).
Gate logs: `/tmp/n2-l3-{clippy,fmt-check,lint,ci}.log`.
Both ordinary targets, Clippy, formatting and domain lint exited **0**.
The live authority census passed macOS CLI/runtime/HVF profiles and explicitly
leaves Linux/FreeBSD/NetBSD profiles pending.

The additional pre-push `just ci` exited **101** at `just doc`, after the
earlier gates passed. Unchanged `crates/carrick-mmu-core/src/aarch64.rs` has
broken rustdoc links: `[5:0]` at line 299,
`publish_existing_invalid_private_pages` at 826/889/949, and `[1]` at 1831.
That file is byte-identical to base and outside this leaf's edit fence; no
production documentation fix or gate bypass was made. CI did not reach host
or integration tests. Signed acceptance, real runtime capacity, native-arm64
oracle and promotion remain unrun. Scoped cleanup reported zero remaining
processes for `n2-l3-schedule` and `n2-l3-owner`.

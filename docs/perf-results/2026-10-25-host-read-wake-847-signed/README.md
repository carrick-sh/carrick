# Issue #847 signed hardware evidence

This receipt records the final cloudmac/HVF proof for PR #855 at source
`6c45f14f90cb22c5f1279fb0ab92b433c61f45f3`. The exact fixture archive was:

```text
/Volumes/carrick-build/fixtures/published/6c45f14f90cb22c5f1279fb0ab92b433c61f45f3/0433bf8b71d3b9322075f45100a4387ce048ccbb59675a513dd401a487d574f4.tar.gz
```

`just fixtures-verify` and `just fixtures-restore` both passed. The bundle
contained 1,195 executables, its input identity was
`51121dd5bd4ec2eec8fe50e254d8bfc363a302fe3c0a61f54b14fbf6d70c7e25`,
and its archive SHA-256 was
`879d123f4bd670a5f93c3bd39669d98178c7254e85361a619f772ec5b1c59e80`.

## Result

`el1_sched_host_blocked_read_resumes_by_guest_scheduling` completed all ten
requested repetitions without reproducing the #847 watchdog hang:

- Passed: `847-final-hostread-01` through `-05`, and `-07` through `-10`
  (9/10).
- Failed quickly: `847-final-hostread-06` (1/10). It exited in 1.42 seconds,
  signal `None`, after the guest reported
  `read(fd=5) iter=427 rc=-1 errno=14`; stdout was
  `sock-pingpong failed at 427`. This run emitted no watchdog census and no
  Carrick fatal.
- Hangs/watchdogs: 0/10.

## Run 06 EFAULT attribution and correction

The failed run exited normally, so it produced no watchdog census or event-ring
post-mortem. Its exact signed log is retained at
`/tmp/847-final-hostread-06.log`; the only guest failure is the valid-buffer
`read(fd=5) iter=427 rc=-1 errno=14` quoted above. The source path was exact:
physical retention reported a stale selected leaf as an Editor wait, the
editor revision was current while the editor word was free, and
`OwnerMemoryPark::NoProducer` fabricated `EFAULT` without asking EL1 to select
the guest address again. Thus a completed edit or transient stage-2
replacement could be mistaken for an unmapped guest VMA.

The VM-free production witness
`serial_host_stale_selection_without_editor_reselects_and_parks_on_physical_producer`
reproduced that path with a valid mapping. Red-first, the saved syscall
returned `EFAULT` immediately instead of blocking on the exact physical
producer. The correction gives a producer-free Editor observation one bounded
authoritative redispatch. EL1 selection now decides whether the guest address
is actually unmapped; a still-mapped address either completes against its
current leaf or returns an exact owner/physical producer. The witness then
parks without polling, wakes on physical-retirement completion, and commits
the copyout. The later publication-producer correction below replaces the
temporary repeated-receipt invariant error with a named producer.

Portable verification on the correction:

- focused witness: 1 passed;
- owner-wait population: 15 passed;
- serialized `carrick-runtime` library: 818 passed, 9 ignored;
- `just fmt-check`, `just lint-domains`, `just clippy`, and
  `just clippy-linux`: passed;
- `just test-kernel`: passed.

The required signed 20/20 proof must use the exact post-correction fixture
bundle and is intentionally deferred until that bundle is relayed.

## Stage-2 publication producer correction

Review of `ba1e7db9b` found that its bounded reselect still treated each new
Editor receipt as progress. SELECT itself advances that receipt, so a valid
stage-1 leaf whose stage-2 record stayed absent could synchronously cycle
through SELECT, stale selection, and producer-free redispatch forever.

The follow-up keeps the `kernel.memory.owner-wait` conformance contract:
Linux `read(2)` returns `EFAULT` only when the destination is inaccessible,
and a transient physical publication cannot become either EFAULT or executor
polling. Physical retention now distinguishes an absent record with no live
backing owner (authoritative EL1 reselect) from an absent or `NotMapped`
record whose live global-frame, structural, or carrier owner must publish a
successor. The latter returns an IPA-scoped physical wait. That wait enrolls
before probing and becomes ready only after the exact mapped record and its
backing-owner identity are both visible, or after the authority retires so
EL1 can reselect and deliver the real mapping fault. Registration, replay
rebind, VM terminalization, and retirement publish after their state locks
drop.

The red-first VM-free witness
`valid_leaf_with_absent_stage2_record_waits_for_physical_publication` first
failed because retention returned `StaleSelection`. Green, it holds a live
owner across a terminal record gap, proves that allocating the successor is
not yet readiness, enrolls the production physical wait, publishes the exact
successor owner, observes one wake, and retains the mapped bytes without
EFAULT. The existing
`serial_host_stale_selection_without_editor_reselects_and_parks_on_physical_producer`
witness drives the runtime park and wake. A separate receipt-churn witness
proves that neither new owner receipts nor physical-wait generations reset
the redrive budget: only committed bytes reset it; terminal dispatch results
leave the loop directly.

Portable verification on this follow-up:

- `carrick-vmm-hvf` library: 790 passed, 3 ignored;
- `carrick-runtime` library: 819 passed, 9 ignored;
- focused user-transfer population: 15 passed;
- focused owner-redrive population: 2 passed;
- `just fmt-check`, `just clippy`, `just clippy-linux`,
  `just lint-domains`, and `just test-kernel`: passed.

No signed test was run because the source changed. The exact-candidate fixture
bundle is required before the requested signed 20/20 proof.

## Removal publication and pending stage-1 rewrite correction

Review of `2efa83419` found two remaining producer gaps. First, readiness can
change when a global owner, structural backing, per-MM structural owner, or
carrier record is removed, but several removal sites did not publish the
stage-2 availability stream. This included cleanup of a dangling owner that
named an already missing record: readiness became true without waking an
enrolled waiter. All directory removals now go through shared helpers that
publish only after their directory lock drops. Terminal record removal uses a
scoped removal owner whose drop releases the record lock before publishing, so
the pin-release and terminal-release paths cannot omit the wake.

Second, a valid stage-1 leaf may outlive retirement of its stage-2 authority
until the promised stage-1 rewrite publishes. An authoritative reselect can
therefore observe the same producer-free Editor cause while the editor word is
momentarily free. The first such observation still performs the authoritative
reselect. A second observation for the same MM and cause now names the pending
stage-1 rewrite and parks on that exact MM's Editor publication stream. It no
longer returns a carrier error, and receipt churn still does not count as
forward progress.

Red-first evidence:

- `removing_dangling_stage2_authority_wakes_publication_wait` observed the
  waiter become ready after direct removal but received zero callbacks; it now
  receives exactly one wake through the shared removal helper.
- `serial_host_stale_selection_without_editor_parks_on_pending_stage1_rewrite`
  reached
  `Runtime(Configuration("authoritative owner reselect repeated without a producer"))`;
  it now parks the production continuation, wakes when a real editor publishes,
  and completes the saved copyout.
- `owner_redrive_receipt_churn_names_the_pending_stage1_rewrite` proves a new
  Editor receipt for the same MM cannot disguise the owed rewrite producer or
  reset the stalled-pass accounting.

Portable verification on the final tree:

- focused production park/wake, receipt-churn, and authority-removal
  witnesses: 1 passed each;
- serialized `carrick-vmm-hvf` library: 791 passed, 3 ignored;
- serialized `carrick-runtime` library: 819 passed, 9 ignored;
- `just fmt-check`, `just clippy`, `just clippy-linux`,
  `just lint-domains`, and `just test-kernel`: passed.

No signed test was run because this correction changes source. The requested
20/20 hardware proof remains gated on its exact-candidate fixture bundle.

The first companion `el1_ipc_two_processes_blocking` repetition,
`847-final-two-process-01`, hit its 60-second watchdog. Per the director's
stop condition, the remaining two repetitions and all requested
`el1_sched_pipe_pingpong_stays_in_guest` and
`el1_ipc_pipe_blocking_roundtrips` repetitions were not run. Every completed
outer run was followed by `scripts/sudo/kill.sh <run-id>` and reported zero
remaining scoped processes.

This two-process watchdog is recorded only as companion evidence. The director
also reproduced its missing-second-process shape on main and explicitly moved
it out of this fix's scope.

## Signed executable identities

The signing harness re-signs the test executable on every invocation, so its
SHA-256 and CDHash legitimately differ by run. The LC_UUID remained
`FD63A5AE-28A7-3A89-9947-6841B09A8B0D` throughout.

| run ID | SHA-256 | CDHash |
|---|---|---|
| `847-final-hostread-01` | `f945603f48d7f13d27c51b4907b745b451dee1606babc09b11652284e4cfcc65` | `df08ce88cc078da0df0baddec7a0fad36e3b2431` |
| `847-final-hostread-02` | `b9416418518d491c0c5b5751a838bda6e1c6803ffcb0eaafe90ddf7bda90a587` | `1417903cc26ed701a73a3066736831fb58fda8a7` |
| `847-final-hostread-03` | `f94a1d4c92143f34612e0e4a525a3f84009bd5dcd4131308e1fadacfb95da157` | `30c6b444d6b124a3e0e88a7aa2d0431527db2aaf` |
| `847-final-hostread-04` | `63645534d513711943bc224f6b4d13307fd0c9478c65ae430145c39a5d64fec2` | `f880ced6a43abd654e2a7e0ac7be8fc980fdc124` |
| `847-final-hostread-05` | `c637a66fee8de55551edd06764b69b838572ea095de2bf1124a4facd523e7f5d` | `5c42ad9d8a4a7bf85ae4622de351004ff59ece37` |
| `847-final-hostread-06` | `45d25e9d43ed739e312a6807f80bd62a9b1dbe62e80a1fc81ee3b6be5eb1f37c` | `94e40a2d9d639c2582da0557f4bb4516cdd571e7` |
| `847-final-hostread-07` | `c12010432e06171237c07efc3de90712a57ccf7209238a122ccb511ee4f24204` | `74c6b642ad0ed985363b43e33e076a462ec0f218` |
| `847-final-hostread-08` | `e10559479b1082017b4f00c15f076d87ff66f17c8a63e78e85a9aa7d7e4d23e5` | `9a452eea16c675c5a6e61a6d64ac9ceba1a7cd68` |
| `847-final-hostread-09` | `c24a56270aa84d71f3e267a8f56590c5951289ddb6ca7964c0a5e9d4c91e37b6` | `737304ed6603bd5575b16dc4c16a43448bb5d1a0` |
| `847-final-hostread-10` | `c480ecc27f77ef9a9b3d292f002ef23f717e685391d61cec907ab1d27faaaff9` | `393f270591f1746520de3e2c2b4d870415a23811` |
| `847-final-two-process-01` | `6f083241659df7d8c7a9d02f9bd98ff94318014c9f5771d631f0e101ea515413` | `6bed03750b623f95c1488e2982e7c72f7bb2d8fc` |

## Watchdog census (verbatim)

```text
test el1_ipc_two_processes_blocking ... WATCHDOG: timeout (60s) exceeded for CARRICK_RUN_ID=847-final-two-process-01-b1; reaping with scripts/sudo/kill.sh
WATCHDOG zone census:
zone slot 0: state=IdleWfi driver=2 away=false mm=0 installed=0 cpu+1=1 current=0 host_record=0 len=0 queue=[] resched=0 timer_cval=0
zone slot 1: state=IdleWfi driver=3 away=false mm=0 installed=0 cpu+1=2 current=0 host_record=0 len=0 queue=[] resched=0 timer_cval=0
zone slot 2: state=IdleWfi driver=4 away=false mm=0 installed=0 cpu+1=3 current=0 host_record=0 len=0 queue=[] resched=0 timer_cval=0
zone slot 3: state=IdleWfi driver=5 away=false mm=0 installed=0 cpu+1=4 current=0 host_record=0 len=0 queue=[] resched=0 timer_cval=0
zone counters: el1_wakes=28 host_wakes=0 el1_parks=30 host_parks=0 switches=29 steals=14 service_exits=0 host_service_placements=0 host_ready_placements=0 resched_kicks=0 service_adoptions=0 exit_adoptions=0 host_handbacks=0 lost_adoptions=0 stale_services=0 held_refusals=0 host_queue_claims=2 host_executor_parks=0 host_queue_takes=0 foreign_adoptions=0
zone spaces: idle_ttbr=0x2d001f8000 el1_space_switches=29 el1_space_refusals=0 el1_cow_invalidations=0
zone space 1: mm=1 gate=0x0
zone record 3: claim=Parked { seq: 1 } handback=None tid=1 serial=2 mm=1 gen=1 home=None last_slot=None wanted=false cancelled=false entries=1 deadline=None
zone record 3 owner: incarnation=1 resume=UserReturn lifecycle_page=0x2d08080000 control_slot=0x2d08087d80
zone record 3 parked: first_wait_mm=1 first_wait_address=0x6000208ad0 resume=UserReturn saved_pc=0x2a5a00
zone record 4: claim=Parked { seq: 1 } handback=None tid=2 serial=5 mm=1 gen=1 home=None last_slot=None wanted=false cancelled=false entries=0 deadline=None
zone record 4 owner: incarnation=1 resume=UserReturn lifecycle_page=0x2d08080000 control_slot=0x2d08087c00
zone record 4 parked: wait_key_and_pc=unavailable-busy-or-changed-or-unlinked
zone record 4 object wait: queue=3 generation=1 operation=1:2
zone object queue 3: generation=1 epoch=1 head=4 tail=4 waiters=1 locked=false
ipc object 1 (queue 3 Readable): kind=pipe generation=0 read_seq=0 write_seq=0 host_subscribers=0 host_wake_owed=0 unread=0 capacity=65536 readers=1 writers=1
ipc host-wake index: owed_without_target=0 summary=0x0
reservation root 1: mm=1 lock_word=0x8000000000000000 notification_required=true holder=None
```

The runner wrote the post-mortem to
`target/embed-post-mortem/847-final-two-process-01-b1`; the worker preserved a
copy at `/tmp/847-final-two-process-01-b1.post-mortem` together with full run
logs, cleanup receipts, and the two failed signed executables.

## Structural owed stage-1 rewrite producer

Review of `c7b097f36` found that the runtime's inferred
`PendingStage1Rewrite` wait still depended on a comment-only promise. Two
producer-free Editor passes could park on a free Editor word even when no
retirement transaction owed a later stage-1 publication, recreating the
original lost-wake shape.

The stage-2 retirement crossing now creates a typed, generation-bearing
`OwedStage1Rewrite` entry before it removes backend authority. The entry is
scoped to the retired IPA range and the exact carrier-record incarnation.
Host retention can obtain a physical wait only from an entry that covers its
selected IPA. The wait subscribes before probing. A successful stage-1 editor
release re-reads the authoritative translation and completes only waits whose
old VA-to-IPA selection was rewritten or unmapped. Failed retirement rolls
the entry back, while terminal retirement retains it until MM teardown; entry
drop publishes every remaining waiter. The runtime's coarse two-pass
inference and forced-true Editor predicate are removed.

VM-free production witnesses:

- `production_retirement_waits_for_owed_stage1_rewrite_commit` drives the
  shared stage-2 backend-retirement crossing, retains through the production
  transfer consumer at a sub-16-KiB VA offset, parks on the exact obligation,
  and observes one wake when a real stage-1 unmap commits.
- `terminal_retirement_owed_rewrite_wakes_at_mm_teardown` drives terminal
  retirement, parks the production transfer consumer on the retained
  obligation, and observes its exact teardown publication.

Portable verification on this follow-up:

- focused production retirement/rewrite and terminal teardown witnesses:
  1 passed each;
- serialized `carrick-vmm-hvf` library: 793 passed, 3 ignored;
- serialized `carrick-runtime` library: 818 passed, 9 ignored;
- `just fmt-check`, `just clippy`, `just clippy-linux`,
  `just lint-domains`, and `just test-kernel`: passed;
- EL1 clippy image: 1,077,712 bytes loaded; maximum checked stack 11,951 of
  12,288 bytes (`signal terminal exit`).

No signed test was run because this correction changes source. The exact
candidate bundle is required before the requested signed 20/20 proof.

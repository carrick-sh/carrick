# ARM fork root-registry refusal (incomplete)

Source: `4b62f3a6ab981de754567ea326be3e9a238ac8df`.
Published bundle transport SHA-256:
`98586dfb8d6f0dd3b0999bcfb8e1930d722198aeabc5b55bb86b803a9e2464a7`.
Restore verified 1,135 executables; input identity:
`0196f252b697e4870b2d7296ae90df34823e2fac1ecac06b659a245545b543b1`.

Both foreground commands failed the warm-up assertion:

```sh
CARRICK_RUN_ID=arm-step5-sol2-4b62-fork-a CARRICK_ARM_RING_FIRST=0 scripts/test-signed.sh carrick-embed el1_fork_cow_resolves_in_guest --exact --nocapture
CARRICK_RUN_ID=arm-step5-sol2-4b62-fork-b CARRICK_ARM_RING_FIRST=0 scripts/test-signed.sh carrick-embed el1_fork_cow_resolves_in_guest --exact --nocapture
```

Each reported first admission stage 6 (RootRegistry), live TTBR0
`282136401674241` (presence bit included), process refusals
`[0, 2, 0, 0, 0, 0]`, `refused[134]=0`, and fork progress
`[1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0]`. No native fork failure;
zero surviving run-scoped processes. Both unentitled controls passed.
The logs are adjacent. Neither run proves child entry or fork acceptance.

The executable was `el1_sched-3c5925ab20bafee2`. Identity sampled during
run b's build, before its signing output (the preceding signed artifact):
SHA-256 `2d54c9f8d1298db2f2677c6e554e5040f96d3e069ea4f9b112a6ff26cea73df4`,
CDHash `5af6ec90e4f230cac2e72d069f914fbe2d97b6d4`.
After run b: SHA-256
`9ce955d15ec2336c23bcb85a50c0f407a058d73e79eaef73c597879f398ab933`,
CDHash `85a776c3e2bd836b0aad6a3c0477d7a29da39f6d`.
Run b's bytes are retained in ignored
`target/arm-step5-sol2/4b62-b/el1_sched-3c5925ab20bafee2`.
Run a's bytes were not copied before the next runner re-signed them; its
identity attribution is based on sampling timing, not a retained artifact.

The next diagnostic captures both observed and registered identity tuples:
(task, execution generation, MM key, thread generation, AddressContext
generation, scheduler record id, scheduler record incarnation). A tag of 1
means the complete first tuple is published; MAX means publication remains
in progress. An absent registered group is all zeros. This is failure-only
instrumentation; the successful fork path does not call its no-inline scratch
helper. Stack peak still requires exact guest-image verification.

The snapshot test was red with the new snapshot copy loop removed: all zeros
instead of both retained identities. It passes with the loop restored.

Still required: exact-input bundle for this diagnostic, two focused signed
runs, cause-directed fix with fork/migration and wrong-PID VM-free controls,
two green fork witnesses, then `just test-embed el1_` compared against the
34 explicit baseline failures plus six `el1_files` failures. The director has
also been asked for origin/main's two Linux KVM wait4 controls; no reply yet.

## Exact diagnostic artifact: f6301dc

The director published the diagnostic bundle built at
`f6301dc8256b7b8524a22ff87616961a06f549c7`, transport SHA-256
`ac75b1195ddbe2dc8374673b373735b05a6ee7fb097f8cd372553be3f97d9cea`.
The amended `431e556024a6acc4be24850e0b7d5bb4284d89f7` fixed a cfg(test)
layout expectation, but fixture identity correctly refused its different ABI
source bytes. The worktree temporarily detached at the exact committed f630
source, restored and verified the published bundle, ran twice, then returned
to `work/arm-adopt-step5` at 431. No other worktree was touched.

Commands used the same focused filter, `--exact --nocapture`, and explicit
`CARRICK_ARM_RING_FIRST=0`, with fresh IDs:
`arm-step5-sol2-f630-fork-a` and `arm-step5-sol2-f630-fork-b`.
Both failed stage 6, process refusals `[0,2,0,0,0,0]`, refused[134] zero,
no native fork failure, unchanged parent progress, and zero survivors.
Both unentitled controls passed. The tuple comparison was:

| Identity | Run a observed | Run b observed | Registered (both) |
|---|---:|---:|---:|
| Task | 1 | 1 | 1 |
| Host execution generation | 7 | 9 | 2 |
| MM key | 2 | 2 | 2 |
| Thread generation | 6 | 6 | 6 |
| AddressContext generation | 9 | 9 | 3 |
| Record id | 3 | 4 | 1 |
| Record incarnation | 9 | 9 | 3 |

Run a executable SHA-256:
`ff7750efdb97278631182ca16ad19c912b904ffd3b8d6c8288c1b5866dac04cf`;
CDHash `a65d801103f7bb970f1937df6930c00ad895b4b4`.
Run b executable SHA-256:
`68d5e5021de4b5081324fe5d2042d890ddfb7bebbb377eefb88601671ce6c071`;
CDHash `38714715736177f1f3eafcffb1277aa4119da320`.
Both signed executables are retained under
`target/arm-step5-sol2/f630-{a,b}/el1_sched-3c5925ab20bafee2`.

This names parent host-lane renewal, rather than a Group-stage refusal. A
renewed host execution binding and scheduler record cannot rename the retained
native process owner or become its AddressContext generation. The correction
retains the canonical owner address, validates task/MM/root/lifecycle/control/
thread identity plus the renewed execution binding, refuses a still-live old
record, and publishes owner/member/record indices together under custody.
Record indices retain the stable native owner key. Registered entry checks
its exact current record independently of its host execution generation.
The scheduler publishes visible PID from that registered record's owner.
The group and wrong-visible-PID checks remain mandatory.

`root_rehome_preserves_owner_and_migrated_child_admission` was red at the
previous Stale rehome refusal; it now proves renewed host binding, retained
owner and address, fork, one child migration, wrong-PID refusal, and successful
child admission. `switched_record_publishes_its_registered_visible_pid` was
red with PID publication removed (Some(41) versus Some(42)), and green with
publication restored. All 323 EL1 VM-free tests and scoped all-target clippy
passed. The exact guest stack audit remains 8176/8192 bytes.

The director's KVM control on main `cb835a712` failed the same two wait4
cases (eight passed, two failed), establishing a pre-existing main defect.
The director requested that those defects be tracked separately; this change
does not alter wait4 accounting.

Runtime closure still needs a bundle for the correction, two focused signed
passes on it, and then the full `el1_` comparison. These VM-free results and
the red diagnostic artifacts do not confer signed acceptance.

The first correction draft's full lint gate rejected direct personality
registry access from the scheduler substrate. The final interface supplies a
required selected-identity hook from the Linux scheduler client at every
scheduler construction. The substrate invokes the hook without importing
Linux policy. All 323 EL1 tests and scoped clippy pass with this interface;
`check-personality-boundary` reports nine clean substrate crates, and the
fork stack remains 8176/8192 bytes. The rejected draft is not signed evidence.

Deferred integration obligation from the director: after the identity work
lands and this branch rebases onto main, ARM scheduler resume must call
`resume_pending_lifecycle()` and route `take_run_failure()` through
`crate::isa::aarch64::complete_native_run_failure`, matching the x86 scheduler.
Add the VM-free exit-parked-behind-a-birth-claim / settlement / completed-exit
witness then. The director explicitly requested continuing rehome first;
that later integration has not been performed or claimed here.

## 2026-10-10: native child stranded on host adoption

The exact-input 63e4dbd50 bundle restored 1,135 verified executables. Focused
runs `arm-step5-sol2-63e4-fork-a-20261010` and
`arm-step5-sol2-63e4-fork-b-20261010` both hit the unchanged 120-second
watchdog. Both negative entitlement controls passed; both scoped reaps left
zero survivors. Run A was untraced. Run B was LLDB-paused for counters:
admission stage 0, process refusals `[0,0,0,0,0,0]`, refused[134] 0,
native failure 0, progress `[1,1,1,1,1,1,0,1,0,0,0]`, clone served 4,
forwarded 1. Those counters are unavailable for run A.

Retained executables under `target/arm-step5-sol2/63e4-a,b`:

- A SHA256 `e04e78cffad8cfc813f8a2c3f59539dcdaa773032cf623dc9f6a87217f4a70c6`,
  CDHash `f427bb1c79a16bd19d9836c9746c0b7d91dc4e09`.
- B SHA256 `367844a44561762724d9be30e2b8185d044c14506a6aa79c8077b70adb10842f`,
  CDHash `d4466a7bf97610250d031050b923f4c7fb148a78`.

A diagnostic reproduction `arm-step5-sol2-63e4-capture` attached to the
carrier PID 16553, saved all-thread backtraces, decoded the lifecycle ring
(212 events, zero errors), and saved a modified-memory host core before the
watchdog's scoped reap. Exact executable, core, ring/backtraces and coherent
kernel JSON are retained in `target/arm-step5-sol2/63e4-capture`. Executable
SHA256 `51f36991823f963bc2cd20bc1f2735930c8196339751f18b734965a7386515e7`,
CDHash `bccbf8ce44721c5938cf75b26c16ecd1587eaede`. Zero survivors afterward.
Attachment pauses execution; this is diagnostic evidence, not acceptance.

Ring event 65 is the only host CLONESPAWN: parent TID 1 creates TID 2;
subsequent TID 2 accesses name parent MM 2. This identifies the parent writer
thread, rather than the native fork child in MM 9. Exact forwarded flags were
not recorded by the old artifact. Added full-width host-clone ring records
and watchdog/witness reporting; the next signed artifact must establish them.

The child is queued but an idle slot's foreign-MM policy sends it through
`take_service_head` to host adoption. It has no host scheduler row. Its claim
is Host, entries 0; lost_adoptions is 1. VCPU-owning executors wait in
Hypervisor wait_for_interrupt; spare executors park in host condition waits.
There is no ring proof of an SGI: this ring does not record that publication.

Red-first: strengthening the migrated child test to use an idle target with
MM 0 fails migration (0 versus 1). An incarnation-bound native execution
grant now permits that registered child to switch into its published open MM
without a host row. Host-backed records retain the loaded-executor policy.
A second red control proves a paused native MM must remain queued rather than
become a host orphan. Grants reject wrong incarnations and clear on reuse.
The ARM scheduler test exercises the actual translation load from idle.
The full-width flags decoder test is red before the new ring records.

VM-free checks: 324 EL1, 133 ABI, 189 scheduler-core tests and the focused
kernel flags test pass. Signed confirmation, exact forwarded flags and the
el1_ baseline comparison remain open. No batch was run on the failed artifact.

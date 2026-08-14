# HVPatch global-frame IPA and stage-1 fork COW evidence

Date: 2026-08-14

Base: `b103d8ba04fa632682192d2eba1042dd7c1c7464`

Implementation: `ad0a945bb728737db969f921b70c5b95b22ee27b` plus review closure
`0d686ce7a0f74ed22ab15bed9430c6bf5a5059e4`

Lane: Darwin/arm64, signed `--exec-backend hvpatch`

## Decision and invariant

Task 4 is retained as a structural correctness change. No CPU win is required
by the controller ruling, and this run makes no timing claim: the structural
USDT receipt deliberately perturbs the measured path.

The implementation removes private fork isolation from stage-2 placement.
Every live physical extent has one stable global IPA and one stage-2 mapping
per live HVF VM generation. Each Linux mm instead owns an independent stage-1
root/ASID. At fork, parent and child private writable leaves name the same
`FrameId` and global IPA but are both read-only and non-global. A write fault
copies one 16 KiB compound frame and republishes only the faulting mm's leaf.

Task 1's semantic split remains binding:

- `Private` anonymous and file mappings take fork COW.
- `ForkSharedAnonymous` remains process-scoped but shares one frame across
  descendants.
- `GlobalShared` retains shared-file/global-IPA and futex identity.
- Guest-visible semantic fragments remain distinct from the exact
  HVF-granular `physical_ipa`/`physical_size` lifetime extent.

## RED-first evidence

The base HVPatch library suite was 134/134 green, including semantic
`forkcow`/`forkshared`; that was not structural proof. Focused red-first tests
then exposed the architecture directly:

1. Requiring a private fork mapping to inherit the parent's `FrameId` and IPA
   failed because `build_process_spec` selected an eager writable child-bank
   snapshot.
2. Requiring the private disposition to be shared read-only failed because the
   normal path selected `ChildPrivateSnapshot`.
3. Requiring a classifier for EL0 write-permission aborts failed on the first
   `DFSC=0x0d` input because no permission-COW fault path existed.
4. Receipt/probe tests required parent/child PTE parity, one COW transaction per
   winning mm/frame generation, exact stage-2 lifetimes, and fail-closed
   terminal state. The bank/snapshot base architecture could not produce those
   records.

Later behavioral and independent-review REDs caught further integration defects
before the final gate:

- a descendant fork could observe a stale exec authority binding;
- reclaiming an invalidated COW leaf could scrub the old semantic owner rather
  than the retained physical output, producing stale bytes after `mprotect`;
- private file fallback after HVPatch declined direct host-file mapping lost
  the beyond-EOF `SIGBUS` boundary.
- an old inventory reference could survive an exact COW split and delay
  retirement until process exit;
- parent fork arming and stage-2 allocation had fallible exits without complete
  typed rollback ownership;
- the structural validator accepted summary-only fault evidence and disjoint
  IPAs for one host extent;
- repeated same-VA retirement/reuse could route through an obsolete broad COW
  arm, leaving a new leaf read-only or naming a retired IPA.

Each was reduced to a focused host or validator mutation test before the
implementation correction. The final `mtforkcorrupt` fix was also exercised by
12 consecutive untraced signed runs before the differential batch.

## Architecture and state transitions

### Global frame lifetime

- Guest frames are allocated from a reusable global-IPA arena, with exact live
  extents, 16 KiB alignment, 2 MiB alignment for large frames, coalesced free
  space, and rejection of partial or duplicate release.
- Stage-1 page-table backing alone uses a 2 MiB per-mm root-slot pool. The slot
  tuple is an mm ownership token, not a guest-frame address range.
- The sole raw `hv_vm_map`/`hv_vm_unmap` boundaries emit stage-2 lifetime
  records. Reuse happens only after a successful exact unmap and inventory
  retirement.
- COW replaces the old inventory reference with exact prefix/suffix fragments;
  the replaced page is retired immediately when its last mm owner disappears.
  `munmap` and exec retirement use the physical `stage2_base`/`stage2_length`,
  not the smaller guest-visible semantic fragment.
- A typed `GlobalFrameStage2Lease` owns every fallible map/materialization path.
  It rolls back the stage-2 mapping, frame inventory, host backing, and global
  IPA reservation unless explicitly committed into the process specification.

### Fork publication

Under fork quiesce and topology exclusion:

1. classify live mappings from the authoritative alias and frame inventory;
2. prepare a new mm root slot/ASID and independent page-table graph;
3. construct the child page-table graph and all fallible child state;
4. make every writable private parent leaf read-only/non-global;
5. issue scoped stage-1 invalidation before the child can run;
6. publish child leaves against the identical inherited `FrameId`/global IPA;
7. commit kernel/mm inventory and child authority.

Parent arming is the last fallible publication boundary. If it fails, an exact
saved page-table image is restored and invalidated before returning; no parent
leaf is left armed by a failed fork.

Shared anonymous and shared-file mappings remain writable shared frames. EL1
kernel state is copied independently and never relies on a guest COW fault.
Ordinary fork attaches to the exact caller task; the stale caller-parent
association check remains only for `CLONE_PARENT`, whose semantics actually
consume that association.

### COW transaction and rollback

The faulting mm holds the COW quiesce/topology guards while it reserves a new
mapping/frame/global IPA, installs and copies the exact 16 KiB physical extent,
repoints and authenticates the stage-1 leaf, performs the scoped TLBI, commits
the kernel inventory, and publishes the alias. Guest syscall-copy writes pass
through the same authority. A typed intent distinguishes guest-visible writes,
backing maintenance, and privileged internal writes so maintenance can split a
frame without granting guest write permission.

Before the first publication the transaction retains a complete page-table
manager image and the old physical bytes. Any recoverable failure restores the
bytes and stage-1 manager, flushes, unmaps and retires the candidate frame, and
releases its global IPA. Failures after an indeterminate hardware boundary
abort rather than expose a half-published mm.

`mprotect`, partial `munmap`, retained invalid leaves, `brk` reuse, lazy high-VA
commitment, exec replacement, descendant fork, and shared-file `SIGBUS`
metadata all use the same frame/semantic-extent authority. The normal private
fork path contains no `ChildPrivateSnapshot`, sparse copy fallback, per-process
frame bank, or `mach_vm_remap(copy=TRUE)` authority; the obsolete Mach COW test
and host remap helper were removed.

When a retired same-VA page is reused, backing maintenance authenticates and
materializes the retired output before consulting any older broad COW arm, then
disarms the exact newly materialized fragment. `CowArmedRanges` otherwise picks
the most-specific containing arm. This prevents an obsolete arena-wide arm from
overriding the current alias generation.

## Authenticated structural receipt

Command shape (issued from the repository root with the probe bytes on stdin):

```sh
base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/forkheapalloc \
  | target/release/carrick trace --profile hvpatch-frame-cow \
      --trace-out /tmp/hybrid-task4-final-0d686ce7-20260814.raw \
      --forward-env CARRICK_RUN_ID=hybrid-task4-final-0d686ce7-20260814 \
      run --exec-backend hvpatch ubuntu:24.04 --raw --fs host \
      /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'
python3 scripts/validate-hvpatch-frame-cow.py --require-shared \
  /tmp/hybrid-task4-final-0d686ce7-20260814.raw
sudo -n scripts/sudo/kill.sh hybrid-task4-final-0d686ce7-20260814
```

Validated receipt:

```json
{"backing_maintenance_transactions":1,"cow_transactions":29,"guest_visible_transactions":28,"private_fork_frames":39,"privileged_internal_transactions":0,"pte_receipts":136,"raw_sha256":"7fb0cc0fe92d1cd1a25042b97f20f8f6dd4c80b5bdf44c15fa7109f0a1d615b4","schema":"carrick.hvpatch-frame-cow-receipt.v4","shared_fork_frames":4,"stage2_maps":118,"stage2_unmaps":118,"status":"validated"}
```

The serialized terminal record also reported `events=87`, `identities=87`,
`intents=87`, `triggers=29`, `trigger_identities=29`,
`permission_triggers=28`, `fork_identities=43`, `fork_frames=43`, `copies=29`,
`fault_ptes=28`, `fault_ttbrs=28`, `errors=0`, `drops=0`, `bounded=0`, and
`target_exited=1`. Trace, validation, and cleanup each returned zero. Every VM
generation closed with zero active stage-2 extents; cleanup reported
`remaining carrick procs ... = 0`.

The validator rejects zero or missing event classes, malformed or duplicate
fields, identity/data imbalance, illegal phase order, PTE PA/AP/nG mismatch,
unchanged or prematurely reused frames/IPAs, missing copy hashes, missing
stage-2 coverage, overlapping/unbalanced extents, nonzero drops/errors,
interruption, timeout, or an unobserved target exit. It walks terminal AArch64
L1/L2 block descriptors as well as L3 page descriptors, requires an exact typed
fault/PTE/TTBR join for guest-visible permission COW, and rejects one host
extent mapped at disjoint IPAs. Sixteen mutation/unit tests exercise those
rejection paths, including removal of all fault records from an otherwise
well-formed receipt.

## Signed differential behavior

The exact evidence binary was built with `scripts/build-signed.sh`. Each
`scripts/run-probe.sh` invocation set `CARRICK_EXEC_BACKEND=hvpatch`, ran Carrick
and Docker serially, reported `MATCH`, and scoped cleanup to its unique run ID.

| Probe | Run ID | Required edge | Cleanup |
|---|---|---|---:|
| `forkcow` | `cr-49564-19128` | data/BSS/heap/private-mmap isolation | 0 |
| `forkshared` | `cr-49608-23187` | shared anonymous descendant visibility | 0 |
| `forkheapalloc` | `cr-49650-26338` | post-fork heap allocation/reuse | 0 |
| `mtforkcorrupt` | `cr-49694-30398` | multithreaded fork canaries | 0 |
| `mmapfileforkwriteback` | `cr-49737-17620` | shared-file writeback across fork | 0 |
| `mmaptrimprotect` | `cr-49779-20771` | partial unmap, high VA, `mprotect` | 0 |
| `mmapprivfile` | `cr-49821-23922` | private file COW, truncation, `SIGBUS` | 0 |
| `mmapmunmap` | `cr-49863-27073` | map/unmap validation | 0 |
| `brkheapgrow` | `cr-49905-30224` | grow/shrink/regrow zero-fill | 0 |
| `forkhighva` | `cr-49948-608` | lazy high-VA fork survival | 0 |
| `mapfixedfork` | `cr-49991-20597` | fixed private replacement/isolation | 0 |
| `forksnapshot` | `cr-50033-23748` | stack/private mmap byte parity | 0 |
| `rosharedbus` | `cr-50075-26899` | read-only shared syscall access | 0 |
| `mmapfileshare_mt` | `cr-50119-30959` | multithreaded shared-file readers | 0 |
| `forkfault` | `cr-49554-4106` | private protection-fault delivery | 0 |

## Binary provenance

- SHA-256: `93c219ea8271aee2bb0b1a9c3a908d5908c81b1e56f841ac459f76c472adb6b4`
- LC_UUID: `9568CD79-8220-3ABF-A6EF-47F37C0D36CE` (`arm64`)
- Entitlement: `com.apple.security.hypervisor = true`
- DOF: `__TEXT,__dof_carrick`, size `0xc49e`

## Host gates

- `cargo test -p carrick-vmm-hvf --lib`: 150 passed.
- `python3 -m unittest scripts/test_validate_hvpatch_frame_cow.py`: 16 passed.
- `cargo test -p carrick-mem retained_output_resolves_invalidated_private_alias_without_revalidating_it`: passed.
- `RUST_TEST_THREADS=1 cargo test -p carrick-runtime mmap_private_hostfile_backend_refusal_falls_back_to_snapshot`: passed.
- `RUST_TEST_THREADS=1 cargo test -p carrick-runtime exiting_parent_reparents_live_and_zombie_children_to_root`: passed.
- `RUST_TEST_THREADS=1 just ci`: passed on the implementation tree, including
  fmt, clippy, domain lint, deny, matrix, build/check/doc, 1,593 runtime unit
  passes (5 ignored), 296 runtime integration passes, and the remaining
  workspace suites.

## Independent-review closure

The first independent review rejected the initial implementation on four
structural grounds. Commit `0d686ce7a0f74ed22ab15bed9430c6bf5a5059e4`
closes them with executable proof:

1. exact COW inventory replacement and last-reference retirement replace the
   old append-only alias lifetime;
2. all fallible child preparation precedes parent arming, and an exact
   page-table/TLBI rollback owns the arm boundary;
3. typed stage-2 leases cover fork, exec, ProcessSpec, mailbox, and
   materialization failure paths;
4. receipt schema v4 rejects summary-only fault evidence and host-extent IPA
   aliasing, and authenticates terminal block/page descriptors.

Late repeated-run failures additionally established the required ordering for
retired same-VA materialization versus stale COW arms. The focused routing RED,
12 consecutive untraced `mtforkcorrupt` runs, the signed differential batch,
and the structural receipt were all run after that correction.

## Regression signal and residual concern

No performance sample was taken; probe runtimes and the USDT trace are not a
performance experiment. The task is retained on structural correctness.

The historical `forksleepfork` fixture produced a faithful signed `MATCH` after
narrowing the stale-association check, but its alarm/sleep scheduling remains
timing-flaky under repeated traced/untraced runs. It is not used as Task 4
structural acceptance evidence. The deterministic descendant, heap, fault,
shared, multithreaded, and cleanup gates above are green.

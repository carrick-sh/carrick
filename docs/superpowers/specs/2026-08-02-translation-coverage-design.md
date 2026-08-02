# Translation coverage: why the shared-translation lane publishes nothing, and the persistent store that would fix it

**Date:** 2026-08-02 · **Status:** plan only — nothing implemented, no crate
source touched. · **Lane:** Darwin/aarch64 native DSR (`--exec-backend native`,
the shipped default). No VMM/HVF/KVM/bhyve behaviour is in scope. · **Campaign
task:** #13 (translation coverage / whole-image AOT). · **Read at** `6c7b624b`.

---

## 0. The ceiling, up front

**This workstream targets build-cold ~14.5x → ~10-11.5x. It does not reach the
2x bar. Nobody should plan around a number better than that.**

The sizing is committed, not argued
(`docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md` §5):
even **perfect** translation sharing removes ~75% of translation work
(~34% of thread CPU → ~8%), worth roughly **15-25% of total CPU**. The 2x bar
needs 28.3 CPU-s to become 4.2. This is the largest single lever identified in
the campaign and it still falls short by a factor of five.

Two further honesty notes that belong in the first section:

- **It is build-lane only.** On the steady-state compute workload translation is
  noise — `CARRICK_DSR_PROFILE` reports 2,066 translations across a 1.2 s run
  (same doc, §6). `handoff.md` names the campaign goal as the ~12x steady-state
  emitted-code penalty, and **nothing in this document touches it**. Every block
  an AOT cache serves is a block that still executes at today's inserted-word
  cost.
- **The baseline itself has moved and is not re-measured here.** §5 of the wall
  audit reads build-cold at 11,728 ms / **14.48x**; `handoff.md`'s later
  `workload-spread.sh` row reads ~11,550 ms / **~12-13.6x**, and compute has
  since gone 10.9x → 3.8x. The ceiling arithmetic is a **~21-31% reduction in
  build-lane wall** whatever today's exact baseline is; Phase 0 re-baselines
  before any number here is quoted as a delta.

What justifies doing it anyway is stated in §9: on prize it beats the other
live build-lane candidate by roughly 3x, it **subsumes** that candidate rather
than competing with it, and its blocker is now understood mechanically rather
than being a mystery.

---

## 1. Evidence this builds on — cite it, do not re-derive it

| fact | value | source |
|---|---|---|
| build-cold workload wall | 11,728 ms vs Docker 810 ms = **14.48x** | wall audit §1 |
| translations, one cold build | **433,249** over **107,320** distinct guest VAs, 34 processes | wall audit §5 |
| intra-process redundancy | **1.00x** — the per-thread block cache is already perfect | ibid. |
| cross-process redundancy | **4.04x**, an *upper* bound (a fixed PIE base aliases VAs across binaries) | ibid. |
| perfect-sharing ceiling | removes ~75% of translation work ≈ **15-25% of total CPU** → 14.5x → **10-11.5x** | ibid. |
| persistent authority, attempted | cold **+58%**, warm **+285%**, **0 units published** | ibid. |
| keys present in the cache dir | **exactly one**, across three runs, against 107,320 distinct blocks | ibid. |
| diagnosis | the blocker is **coverage**, not persistence | ibid. |
| `TranslationUnitKey` | fully content-addressed, stable across runs, already carries `translator_abi` | `handoff.md` "Measured and true" |
| the shared lane | **~90% of a persistent AOT cache.** Fix or rewrite the publication path; **do not delete the lane** — an earlier recommendation to delete it was wrong | ibid. |
| `codesign -s -` shell-out | **0.03 s** (16 MiB) / **0.08 s** (64 MiB) | `2026-07-26-file-backed-aot-cache-design.md` §1.4 |
| `dlopen` a generated dylib | cold **183 ms** (16 MiB) / **421 ms** (64 MiB); **warm 0.5-1.0 ms**; `dlsym` ~3 µs | ibid. |
| fork cost of the mapping | file-backed `dlopen` **−6 µs** vs baseline; `MAP_JIT` **+567 µs** | ibid. §1.1 |
| `mmap(PROT_EXEC)` on an unsigned file | **`EPERM`** — AMFI refuses. A signed dylib is the only supported route | ibid. §1.4 |

Two prior designs in this tree already ruled on the two ideas this document
revives. Both rulings were **provisional and are now superseded by
measurement**, and this document says so rather than quietly reversing them:

- `2026-07-26-container-lifetime-translation-cache-design.md` §8 rejected a
  **persistent cross-run store** — "it adds eviction, trust, tamper, upgrade,
  and stale-file policy *before proving that shared translations help one real
  container lifecycle*". That proof was attempted and **failed**: the
  container-lifetime lane publishes ~nothing (§2). The precondition for the
  rejection no longer holds.
- The same §8 deferred **eager whole-image translation** — "it maximizes
  theoretical reuse but translates cold code, delays first instruction, and
  greatly enlarges the first correctness surface. Demand recording measures
  which blocks deserve publication." Demand recording has now been measured, and
  it measures **one key**. §5 revisits eagerness on that evidence, and does not
  simply assume the old ruling was wrong.

---

## 2. The publication path as it exists

This section is the investigation result. Every claim carries a file:line at
`6c7b624b`; line numbers drift, symbol names do not. (The wall audit cites
`claim_recording` at `aot_cache.rs:1426`; at `6c7b624b` it is **:1339**.)

### 2.1 The store cannot span runs — by construction

`ContainerCacheAuthority::create` (`crates/carrick-native-darwin/src/aot_cache.rs:1014`)
allocates the cache directory as a `tempfile::Builder::…tempdir()`, and
`impl Drop for ContainerCacheAuthority` (`:1821`) ends in
`std::fs::remove_dir_all(&self.path)` (`:1830`), guarded only by
`CARRICK_DSR_KEEP_CONTAINER_CACHE=1` — a diagnostic that *prints a path and
leaks the directory*, not a persistence mode. The session is opened per
container run at `crates/carrick-runtime/src/native_darwin.rs:1721`
(`run_image_in_child`).

So the store's lifetime is exactly one container run. Nothing it contains — not
a unit, not a manifest, not a marker — can ever be observed by a later run.

### 2.2 The election requires a second sighting, and the marker is a file

`ContainerCacheAuthority::claim_recording` (`aot_cache.rs:1339`):

1. take a per-key `flock(LOCK_EX)` on `<stem>.lock` (`lock_unit`, `:1743`);
2. if `<stem>.dylib` **and** `<stem>.metadata-v3` both exist, return `false`
   (already published);
3. if `<stem>.seen` does **not** exist — create it and return **`false`**
   (`:1349-1363`). This is the "first sighting declines" policy;
4. otherwise read `<stem>.builder`; if that pid is still alive, return `false`;
5. otherwise write this pid into `<stem>.builder` and return **`true`**.

The state that decides "have I seen this before" is `<stem>.seen`, a file in the
directory of §2.1.

### 2.3 The two together: cross-run reuse is mechanically impossible

**The `.seen` marker lives in a directory that is `remove_dir_all`'d at
container exit.** Therefore, with the shipped scope, a second sighting can only
ever come from a *second process inside the same container* — never from a
second run. Cross-run reuse is not merely unrealised; it is excluded by
construction, independently of any performance property.

That is the mechanical cause the wall audit's "coverage, not persistence"
verdict points at, stated exactly: **container-lifetime scope AND the
second-sighting policy, together.** Removing either one alone leaves the other
in force.

### 2.4 The "exactly one key" result localises the loss *upstream of the election*

This is a deduction from the shipped code, and it sharpens the audit's finding.

`claim_recording` writes `<stem>.seen` on the **first** sighting of *any* key it
is asked about. A cache directory that holds exactly one key therefore proves
that `TranslationUnitStore::claim_recording` was **reached for exactly one key
in the entire run** — not that the election declined 107,000 times. The loss is
upstream, in how many keys `try_load_shared_unit` ever consults.

The reachability chain, from `ProcessState::try_load_shared_unit`
(`crates/carrick-dsr-aarch64/src/translator.rs:3025`), is:

1. `generation == CodeGeneration::INITIAL` (`:3032`);
2. `self.shared_translation` is `Some` — i.e. `configure_shared_translation`
   ran, `shared_enabled` was true, and it found at least one segment;
3. the translating guest VA falls inside a configured segment (`:3038-3046`);
4. this segment has not already been consulted by this process
   (`shared_unit_segments_consulted`, `:3048`);
5. `store.load(&key, …)` returns **`Ok(None)`** (`:3055-3062`) — only then is
   `claim_recording` called.

Step 5 hides a conflation worth naming as a defect on its own.
`ActiveContainerUnitStore::load` (`aot_cache.rs:1901`) returns
`Err(UnitMissReason::MissingPair)` when **no cache authority is installed at
all** (`:1912`), and `Ok(None)` when the *files* are missing (`:1915`). The call
site collapses both into `return Ok(None)` — but only the second reaches
`claim_recording`. **A descendant process that failed to adopt the authority is
therefore indistinguishable, at every observable point, from a process whose
lookups simply missed**, and it silently contributes zero coverage forever.
Whether that is what happened is a Phase 0 measurement, not a claim here; the
point is that today's instrumentation *cannot tell you*, and that is itself the
bug to fix first.

Candidate causes for "one key", in the order Phase 0 should discriminate them
(all hypotheses, none measured):

- **(a) The authority is not live in descendants.** Forked children inherit
  `CONTAINER_CACHE` through memory; the host self-re-exec that implements guest
  `execve` must carry it explicitly through the capsule
  (`native_darwin.rs:26-38`, `aot_cache_authority_snapshot` /
  `adopt_aot_cache_for_resume`). If adoption fails anywhere in that chain, every
  descendant is silently store-less per the conflation above.
- **(b) Segment enumeration covers too little.** `configure_shared_translation`
  (`crates/carrick-dsr-aarch64/src/mapped_memory.rs:796`) builds segments from
  `image.ro_spans()` filtered on `.exec` (`:817-822`), and `ro_spans` is
  documented in `crates/carrick-mem/src/memory.rs:685` as the read-only spans of
  **"the loaded ELF images (main binary + interpreter)"**. Anything the *guest's
  own* `ld.so` maps later is not in that set and can never become a unit.
  Adjacent spans are then merged (`mapped_memory.rs:823-833`), so a statically
  linked Go
  binary collapses to roughly one segment — meaning few keys per image by
  design, not by accident.
- **(c) Consultation is once per segment per process** (`:3048`), so a process
  that never executes inside a segment never proposes it at all.

### 2.5 Recording costs a second full assembly per block

When a segment *is* claimed, `shared_recording_segments` gains it (`:3059`), and
every subsequent translation in that segment additionally calls
`emit::record_portable_block_artifact` (`translator.rs:4363`, eligibility at
`:4334-4360`).

`record_portable_block_artifact`
(`crates/carrick-dsr-aarch64/src/emit.rs:5035`) runs a **complete second
`assemble_block_inner`** over the same plan, under
`DirectExitEmissionPolicy::PortableUnitAuthority`, with a recording sink
attached. On a translation-bound workload where emission is the dominant phase,
recording a segment therefore roughly **doubles** its translation cost.

Two consequences:

- **This is the most plausible mechanism for the warm +285%**, and it is a
  hypothesis, not a measurement. `claim_recording` reclaims a key whose recorded
  builder pid is dead (`aot_cache.rs:1366-1373`), and a cold `go build` is ~70
  short-lived processes. On a run where `.seen` markers already exist for every
  key — exactly what the persistent-authority experiment created — **every
  process is eligible to become the recorder for every segment it touches**,
  because the previous run's builder is always dead. Double assembly, everywhere,
  publishing nothing. Phase 0 measures this directly rather than asserting it;
  if it is wrong the redesign below is unaffected, but the sequencing is.
- **The good news buried in the same function:** `record_portable_block_artifact`
  takes only a `&BlockPlan`, a generation binding, an address mode and the source
  words. **It does not require the block to have executed.** Eager production is
  therefore reachable without inventing a new producer — §5.

### 2.6 Publication spawns two subprocesses per unit

`publish_unit_with_metadata_mode` (`aot_cache.rs:1142`) per unit: validate →
`flock` the key → emit a Mach-O (`crate::aot::emit_dylib`) → write a temp file →
`flush` → `sync_all` → **`sign_and_verify`** → `sync_all` → read the signed
dylib **back** → SHA-256 the whole thing → build and encode the manifest → write
a second temp → `flush` → `sync_all` → map-and-validate → two `rename`s.

`sign_and_verify` (`:1791`) is **two `std::process::Command` spawns of
`/usr/bin/codesign`** (`-s -`, then `--verify --strict`). The measured
shell-out is 0.03 s at 16 MiB and 0.08 s at 64 MiB, so publication is
**~0.06-0.16 s of subprocess per unit** before any I/O. The original design
already flagged this: "Signing is the last remaining process spawn"
(`2026-07-26-file-backed-aot-cache-design.md` §4.2), and the container-lifetime
design accepted it explicitly with "in-process CodeDirectory emission is a later
optimization if signing materially limits the workload" (§3.1). It now does.

### 2.7 The lane is opt-IN, which is why none of this was caught

`shared_translation_runtime_enabled` (`translator.rs:142`) requires
`CARRICK_DSR_SHARED_TRANSLATION=1`. Default: **off**.

AGENTS.md names this exact lane as its worked example of the failure mode: "the
whole container-lifetime shared-translation lane … in the tree, compiled, tested
and unreachable … That pattern hides regressions (nobody runs the arm), rots the
code (it drifts from the default path), and lets a 'landed' change never
actually land." A lane that publishes one unit per run is precisely what a
default-off arm decays into. The rot is documented in the tree itself:
`crates/carrick-dsr-aarch64/src/direct_binding.rs:518-534` records that
`classify_cold_exit` was **17-50x slower** with the lane on (">300 s against
17.2 s and 18.8 s controls") because a scan only had records to walk when
shared translation was enabled — "which is why it went unnoticed."

**Any plan here that does not end with the lane on by default has not fixed
anything.**

---

## 3. What a "unit" is today, and what would have to change

### 3.1 Granularity is already right

A unit is **one executable image segment**, not a block and not a whole image:
`TranslationUnitKey::for_segment`
(`crates/carrick-dsr-aarch64/src/shared_cache.rs:270`) over
`SharedImageConfig::key_for_segment` (`:1056`), where `segments` are the merged
exec `ro_spans` of §2.4(b). The key is

```
{ executable, segment_file_offset, segment_file_len, guest_va_start,
  guest_va_len, source_fingerprint, page_profile, address_mode, translator_abi }
```

and `file_stem()` (`:333`) is `SHA-256(serde_json(key))` in hex. It is fully
content-addressed and carries `TRANSLATOR_ABI_CURRENT` (currently `6`, `:21`),
so an ABI bump makes every old unit **miss** rather than corrupt. This is the
part `handoff.md` calls "~90% of a persistent AOT cache", and it is correct as
it stands. **Do not redesign the key.**

A unit's *contents* are `Vec<PortableBlockRecord>` packed by
`PendingTranslationUnit::pack` (`:518`): each candidate's template is
materialised to words, appended to one code blob, and recorded with its
`entry_offset`; intra-unit direct links are then rewritten against final unit
offsets (`:585`+). One exported base symbol per unit, block entry offsets in the
manifest — deliberately, so dyld metadata does not scale with block count
(container-lifetime design §3.1). Cap: `MAX_TRANSLATION_UNIT_CODE_BYTES` = 64
MiB (`:25`), a branch-range constraint, not a policy knob.

### 3.2 What is missing is *when* the contents are produced

Contents come only from blocks the process happened to execute, in a segment it
happened to claim, with `PublishOutcome` decided at process teardown
(`ProcessTranslator::publish_shared_candidates`, `translator.rs:2833`, driven
from `native_darwin.rs:2728 publish_native_shared_candidates`). One further
all-or-nothing gate lives there: a segment is dropped entirely if **any**
candidate's source generation has moved off `INITIAL` (`translator.rs:2864-2872`).

For a unit to be produced **eagerly per executable image at first exec**, three
things change and no more:

1. **A producer that enumerates block starts without executing them.** §5.
2. **A production trigger at image-configuration time** rather than at teardown:
   `configure_shared_translation` already has the image, the segments, the key
   and the store in hand (`mapped_memory.rs:796-941`) — it is the natural site.
3. **The election deleted.** With eager production there is no "second sighting"
   to wait for: the first process to see an unpublished key produces it, under
   the existing per-key `flock`, and every later process — in this run or any
   later run — loads it. `claim_recording` and the `.seen`/`.builder` protocol
   go away entirely, along with the `TranslationUnitStore::claim_recording`
   trait method and its `true` default (`shared_cache.rs:1001`).

---

## 4. The cost of a miss, and what a near-free miss must look like

The warm **+285%** says the miss path is not free. Here is what it does today.

### 4.1 Per *lookup* (once per segment per process, `translator.rs:3054`)

| step | cost |
|---|---|
| `configuration.image.segments.iter().find(…)` | linear scan, and it runs again per translation at `translator.rs:4322` |
| `ActiveContainerUnitStore::load` → `CONTAINER_CACHE.lock()` | a **process-global `Mutex`** (`aot_cache.rs:1909`) |
| `key.file_stem()` | `serde_json::to_vec` + SHA-256 + hex (`shared_cache.rs:333`) |
| `final_paths_with_metadata_mode` | two `format!` + two `PathBuf::join` |
| `dylib_path.is_file()`, `metadata_path.is_file()` | **2 `stat`s** (`aot_cache.rs:1444`) |

### 4.2 Then, on a miss, per key

| step | cost |
|---|---|
| `claim_recording` → `CONTAINER_CACHE.lock()` again | second global mutex acquisition |
| `key.file_stem()` **again** | second JSON serialisation + SHA-256 |
| `lock_unit` | `open(O_CREAT)` of `<stem>.lock` + **`flock(LOCK_EX)`** (`:1743`) |
| two more `is_file()` | 2 `stat`s |
| `seen.exists()` | 1 `stat` |
| create `<stem>.seen` | **1 file create + inode** |
| second sighting: read `.builder`, `kill(pid,0)`, create+write+flush `.builder` | 1 read, 1 signal probe, 1 create, 1 write, 1 flush |
| and then, if claimed | **every later translation in the segment assembles twice** (§2.5) |

So a miss costs, at minimum, two JSON+SHA-256 key derivations, an exclusive
file lock, five stats and a file creation — and at worst it enrols the process
as a recorder, doubling its emission work for zero published output.

### 4.3 The hit path, for contrast

`load_unit_with_metadata_mode` (`:1432`) is already reasonable and should not be
touched by this workstream: with keyed dylib identity on (the default), it reads
only the bounded load-command prefix rather than hashing a 60+ MiB image
(`:1514-1520`), maps and validates V3 metadata, `dlopen`s (`:1568`), `dlsym`s the
key-specific base export, pins protections with `mach_vm_protect`, and validates
binding cells. Warm `dlopen` is 0.5-1.0 ms; `dlsym` ~3 µs. **A hit is cheap
already. A miss is not.**

### 4.4 The requirement

> **A miss must cost one `stat` or one `mmap` of an index, and nothing else.**
> No subprocess. No per-key lock. No per-key file creation. No key derivation
> repeated. No enrolment side effect.

Concretely, for the design in §6:

- **Derive the stem once per (image, segment)** at configuration time and carry
  it in the segment record. It is a pure function of a key that never changes.
- **One `mmap`ed index per store, read-only**, listing published stems. A lookup
  is a binary search in mapped memory. A miss returns without touching the
  filesystem at all. The index is opened once per process, not once per key.
- **No lock on the miss path.** Locking belongs to *production*, which is rare,
  not to *lookup*, which is not.
- **No `.seen`, no `.builder`, no per-key `.lock`.** Deleted with the election
  (§3.2 item 3). They are three inodes per key of pure miss-path cost.
- **Lookup must never mutate process state.** Today a miss can enrol a recorder;
  after this change a miss enrols nothing.

---

## 5. The Rosetta comparison, honestly

The wall audit §5 frames the target as the Rosetta 2 shape: "translate once, key
by code identity, persist, reuse on every later launch", and
`2026-07-26-file-backed-aot-cache-design.md` §1.3 describes `oahd`
AOT-translating each binary once into `/var/db/oah/<UUID>/`. Carrick has no
first-party knowledge of Rosetta's internals; treat that as the *shape* being
imitated, not a specification.

### 5.1 What carrick can adopt — and mostly already has

| Rosetta property | carrick today |
|---|---|
| content-addressed key | **done** — `TranslationUnitKey` (§3.1), `translator_abi` included |
| file-backed, signed, `dlopen`ed code | **done** — `aot.rs` + `load_unit`; the only AMFI-supported route (unsigned `mmap(PROT_EXEC)` is `EPERM`) |
| free at fork | **done** — file-backed is −6 µs vs `MAP_JIT`'s +567 µs |
| persist across launches | **absent** — §2.1 |
| produce the whole image at first exec | **absent** — §2.5 |

The first three are the expensive parts and they are built. That is what
"~90% of a persistent AOT cache" means.

### 5.2 What carrick cannot adopt, and the one open question

Rosetta gets an ahead-of-time decode for free because it decodes a **known file
on disk** with a known entry point. Carrick discovers blocks lazily by
execution. So the question is precise: **can `carrick-dsr-aarch64`'s block
planner enumerate an image's code statically?**

**Partially, and the seam already exists.** `block::plan_block_with_segments`
(`crates/carrick-dsr-aarch64/src/block.rs:1051`) is a thin wrapper that supplies
a closure `|pc| memory.read_u32(pc.raw())` to
`plan_superblock_with_reader_for_counter_plan` (`:1059`). **The planner's only
dependency on live guest memory is that reader closure.** And the words are
already in hand without any memory at all: `SharedExecutableSegment.source_words`
is an `Arc<[u32]>` holding the segment's entire instruction stream
(`shared_cache.rs:1020`, filled at `mapped_memory.rs:864-888`). A static
enumerator feeds `source_words[(pc - guest_start)/4]` to the same planner and
gets the same `BlockPlan`; `record_portable_block_artifact` then turns that plan
into a unit record with no execution (§2.5). **No new decoder is needed.**

What is genuinely not available is **the set of block starts**:

- **A linear sweep is not viable**, even though AArch64 is fixed-width. Planning
  from every 4-byte offset in a segment yields one block per instruction, each
  ~25 instructions of guest code plus inserted words (`emit.rs:50-60` records
  "~25 entries each" for the PC map). That is a ~25x code blow-up against a 64
  MiB unit cap — the cap is hit long before a real image is covered, and almost
  every produced block is dead weight.
- **Recursive descent is viable and is the right shape.** Seed from the ELF
  entry point and each segment start; follow `PlannedExit::Direct` targets and
  `PlannedExit::Continue` fall-throughs, which the planner already resolves and
  classifies (`block.rs:34-84`); enqueue each newly discovered start. This
  terminates (finite segment, visited set) and produces exactly the block shape
  the runtime looks up.
- **Indirect targets are unreachable statically.** `PlannedExit::Indirect`
  covers computed branches, `blr` through function pointers, PLT dispatch,
  switch tables and every return. Recursive descent finds none of their targets.
  **Coverage from static enumeration is therefore strictly partial, and how
  partial is not knowable from the source — it must be measured.** That is
  Phase 0's whole job.
- **Cost and risk of eager production, stated plainly.** Producing a segment
  costs one `assemble_block_inner` per discovered block up front, on the exec
  path, before the guest's first instruction — the exact objection the
  container-lifetime design raised when it deferred this ("translates cold code,
  delays first instruction, and greatly enlarges the first correctness
  surface"). Two of the three are answerable with engineering (produce off the
  critical path; a unit is only *loaded* after full validation, so a bad unit is
  a miss, not a wrong-code bug). The third is not answerable by argument:
  eager production is only worth its latency if a large fraction of executed
  blocks are statically reachable. **If Phase 0 says otherwise, this workstream
  stops at Phase 2 and eagerness is abandoned — see the kill criteria.**

### 5.3 The hybrid that makes the arithmetic work regardless

Eager and demand production are not alternatives. The persistent store makes
**demand** production cumulative, which is the property the container-lifetime
scope threw away:

- run 1 executes and publishes what it reached;
- run 2 loads that, executes, and publishes what run 1 missed;
- the unit converges on the workload's true block set over a handful of runs,
  with **no static enumeration at all**.

Static enumeration only shortens the ramp. That is why persistence (Phase 2) is
sequenced **before** eager production (Phase 4), and why Phase 4 can be
cancelled outright without losing the ceiling.

---

## 6. Design: the persistent store

### 6.1 Directory layout

One store per host user, under `CARRICK_HOME` (the location the superseded
file-backed design already chose, §2.3 there), overridable by
`CARRICK_XLAT_STORE` for tests:

```
$CARRICK_HOME/xlat/
  v<TRANSLATOR_ABI_CURRENT>/          # one generation per translator ABI
    index                             # mmap-able, sorted, fixed-record
    units/<aa>/<stem>.dylib           # ad-hoc signed Mach-O, __TEXT = unit code
    units/<aa>/<stem>.metadata-v3     # mapped metadata (unchanged wire format)
    tmp/                              # staging; same filesystem, never scanned
```

- `<stem>` is today's `TranslationUnitKey::file_stem()` (SHA-256 hex) —
  unchanged. `<aa>` is its first byte, a two-hex-digit fan-out, so no directory
  holds more than ~1/256 of the store.
- Mode `0700` on `xlat/` and everything under it, matching the existing
  authority (`aot_cache.rs:1019`). A store is **per-user and never shared
  between users**: loading another user's signed code is a trust decision this
  project has not made and must not make implicitly.
- `v<abi>/` makes ABI rotation a directory operation. `translator_abi` is
  already inside the key, so a stale unit already **misses**; the directory
  generation additionally makes the dead set *findable* for GC in O(1) instead of
  requiring every stem to be re-derived.

### 6.2 The key

**Unchanged.** `TranslationUnitKey` (§3.1) is already content-addressed and
run-stable. The one change is *when* the stem is computed: once per (image,
segment) at `configure_shared_translation` time, carried in
`SharedExecutableSegment`, never recomputed per lookup (§4.4).

### 6.3 The index

A single file, replaced atomically, mapped `PROT_READ|MAP_PRIVATE` once per
process:

```
header : magic, format version, translator_abi, record_count, record_stride
records: [ stem: [u8;32], code_len: u32, flags: u32 ]  -- sorted by stem
```

- **Lookup is a binary search in mapped memory.** A miss touches no filesystem
  path, takes no lock, allocates nothing, and mutates nothing.
- **The index is a cache of the directory, never the authority.** A `dlopen`
  that fails, a metadata map that fails validation, or a file that has vanished
  is a **miss** and falls back to private JIT — exactly today's contract
  (`translator.rs:3055-3063`). The index can therefore be stale in the
  optimistic direction without any correctness consequence.
- Missing index ⇒ every lookup misses ⇒ the guest runs correctly on the JIT.
  **A corrupt store must degrade to today's behaviour, never to a failure.**
- **Fail-closed on the honest-instrumentation side, not on the guest side:** the
  store records `lookups / hits / index_missing / load_failed` through the
  existing `ResolverStat::SharedUnit*` counters (`translator.rs:1571-1573`,
  surfaced by `CARRICK_DSR_PROFILE`), and a run reporting zero lookups against a
  configured image is an **error in the gate**, not an empty summary. That is
  the rule the wall audit's "one key" result should have tripped a year of
  measurements ago.

### 6.4 Publication, and why a partial unit can never be loaded

Three independent barriers, in order:

1. **Staging + atomic rename.** Both files are written into `tmp/` on the same
   filesystem, `flush`ed, `sync_all`ed, then `rename`d into `units/`. `rename(2)`
   within a filesystem is atomic, so a reader sees either the complete file or
   no file. This is what `publish_unit` already does (`aot_cache.rs:1330-1335`)
   and it is kept verbatim.
2. **Pair-completeness is a load precondition.** `load_unit` already requires
   *both* `<stem>.dylib` and `<stem>.metadata-v3` to be regular files before
   doing anything else (`:1444`), and `publish_unit` removes a stale half-pair
   before republishing (`:1182-1199`). The dylib is renamed **first**, so the
   metadata rename is the commit point.
3. **The index entry is published last, and validation is independent of it.**
   A stem appears in the index only after both renames. But because the index is
   only a hint (§6.3), even a torn index cannot produce a load that skips
   validation: `dlopen` verifies the ad-hoc signature (AMFI), the keyed base
   export binds the image to *this exact key*, the V3 metadata is mapped and
   range-validated, section lengths are cross-checked against the manifest, and
   the source fingerprint is re-derived. **A partially written unit fails at
   `dlopen` or at metadata validation and becomes a miss.**

The index is itself replaced by write-to-`tmp` + `rename`, under one store-wide
`flock` held **only by the publisher**. Readers never lock.

### 6.5 Staleness

- **Translator ABI:** already in the key, and now also in the directory
  generation. Stale ⇒ miss. `TRANSLATOR_ABI_CURRENT` must be bumped by any
  change to emitted-code layout, `DsrContext`, recovery semantics, or
  address-mode lowering — the container-lifetime design §3.3 states this and it
  remains binding. **A stale unit is a wrong-code bug, not a slow path.**
- **Guest image content:** `source_fingerprint` covers the exact segment bytes
  and is re-validated on load (`aot_cache.rs:1497-1513`). A rebuilt guest binary
  produces a different key.
- **Host geometry:** `page_profile` and `address_mode` (including the exact
  `host_bias`) are in the key, so a unit built under one geometry misses under
  another rather than mis-executing.
- **Nothing else may be trusted.** In particular the store must not key on a
  path, an mtime, or a `CARRICK_RUN_ID`. The existing rule stands: "Run ids are
  diagnostic labels, not capabilities" (container-lifetime design §3.2).

### 6.6 GC and eviction

Disk growth is the price of persistence and it needs a policy that is boring:

- **Budget:** a byte cap (default 2 GiB, `CARRICK_XLAT_STORE_MAX_BYTES`), checked
  by the publisher after a successful publication, never by a reader.
- **Policy: LRU by atime of the dylib**, which the kernel maintains for free on
  `dlopen`. Evict whole `(dylib, metadata)` pairs oldest-first until under
  budget, then rewrite the index. `noatime` mounts degrade this to
  approximately-FIFO by mtime — acceptable, and stated rather than assumed.
- **Whole ABI generations are evicted wholesale** when `v<abi>/` is not the
  current one and has not been used within a grace period.
- **Eviction is not a correctness event.** A unit deleted between a reader's
  index hit and its `dlopen` is a miss.
- **`carrick debug xlat-store`** reports size, unit count, hit statistics and
  the current generation, and supports `--prune`. Per AGENTS.md ("Rust first;
  extend ourselves") this is a subcommand of our own binary, not a script.

### 6.7 What gets deleted

Per "no backward compatibility", the following go away in the commits that land
the replacement — not parked behind flags:

- `ContainerCacheAuthority`'s tempdir creation and its `Drop`/`remove_dir_all`
  (`aot_cache.rs:1014`, `:1821`), plus `CARRICK_DSR_KEEP_CONTAINER_CACHE`. The
  authority's fd-passing and identity validation are **kept** — they are how a
  descendant reaches the store across the self-re-exec.
- `claim_recording` everywhere: the method on `ContainerCacheAuthority`
  (`:1339`), the trait method and its default (`shared_cache.rs:1001`), the
  `ActiveContainerUnitStore` impl (`aot_cache.rs:1930`), the call site
  (`translator.rs:3058`), and the `.seen`/`.builder`/`.lock` file protocol.
- `shared_recording_segments` and the demand-recording branch
  (`translator.rs:4334-4387`) **only if** Phase 4 lands and static enumeration
  proves sufficient; otherwise it stays as the demand half of the hybrid (§5.3).
- `CARRICK_DSR_SHARED_TRANSLATION` as an opt-in gate (`translator.rs:142`),
  replaced by `CARRICK_DSR_SHARED_TRANSLATION=0` as an exact opt-out — and that
  hatch is itself deleted when the phase's gate result is banked.

---

## 7. Phased plan

Each phase is independently landable, independently gated, and carries a kill
criterion that means **delete**, not disable.

### Phase 0 — settle whether coverage is achievable (BLOCKING)

Nothing else may be planned in detail until this lands. It is a measurement
phase; it changes no runtime behaviour on the default path.

**0a. Fix the census's blind spot, then extend it.**
`xlat_census` (`translator.rs:11493-11559`) dumps via `libc::atexit`
(`:11555`). Carrick's guest `execve` is a **host self-re-exec**, and `execve`
does not run `atexit` handlers — so a process that execs **never writes its
census file**. Its 34-process coverage against a build that runs ~70 carrick
processes is consistent with exactly that, and it is the same defect the alloc
census has (wall audit §4 "The census's resolution limit"). Flush on the
pre-exec path so coverage is complete. **Until this lands, 433,249 and 107,320
are lower bounds and must not be used as denominators.**

**0b. Record the unit key alongside the guest VA.** Extend `record` to take the
executable digest and segment start so a distinct-VA count becomes a distinct
*unit-key* count. This is a few lines against an existing instrument and is
exactly what AGENTS.md's "look for what already exists" demands — do not build
a second census.

**0c. Aggregate in Rust.** `carrick debug xlat-census` reads the per-pid files
and reports: total translations, distinct VAs, distinct unit keys, per-key block
counts, process coverage (processes that wrote a file / processes observed), and
the share of translated blocks that fall inside a configured segment. Typed,
`just ci`-gated.

**0d. Answer the four questions, on one cold `go build`:**

1. **How many distinct unit keys does the workload actually have?** If it is a
   handful, per-key publication cost (§2.6) is amortised trivially and Phase 1's
   in-process signing is optional. If it is thousands, in-process signing is
   mandatory before anything else.
2. **What fraction of translated blocks falls inside a configured segment?**
   This bounds the whole workstream: blocks outside every segment can never be
   served by any unit, and §2.4(b) predicts guest-`ld.so`-mapped libraries are
   all outside. If the fraction is low, segment enumeration is the first fix and
   persistence is second.
3. **Where does the "one key" go?** Instrument the store to distinguish
   *no authority* from *file miss* (§2.4) and count both, per process. This
   discriminates hypotheses (a), (b) and (c).
4. **Does recording double emission?** A same-binary A/B with recording forced
   on for every consulted segment vs off, translations and wall both recorded.
   This confirms or refutes §2.5's warm-+285% hypothesis.

**0e. Bound static enumerability.** Offline, from the existing
`source_words`: recursive descent from segment starts and the ELF entry, and
report what fraction of the **executed** block starts (from 0b) it discovers.
This is the number that decides whether Phase 4 exists at all.

**Exit criterion:** a committed `docs/perf-results/2026-08-0X-…md` with those
five answers and a re-measured build-cold baseline.

**KILL:** if 0d.2 shows that under 40% of translated blocks fall inside any
configurable segment, this workstream's ceiling is not the 15-25% of CPU cited
in §0 but a fraction of it. **Re-derive the ceiling from the measured fraction
and re-rank against #14 before writing a line of Phase 1** — do not proceed on
the strength of a stale number.

### Phase 1 — make a miss free and publication cheap

Default ON. No behaviour change to what is published or when; this phase exists
so that later phases' misses are not self-defeating.

- Derive the stem once per (image, segment); carry it in
  `SharedExecutableSegment`.
- Hoist the per-translation segment scan (`translator.rs:4322`) out of the
  translate path.
- Replace the two `/usr/bin/codesign` spawns with **in-process ad-hoc
  CodeDirectory emission** in `carrick-native-darwin`. This was named as the
  intended follow-on by the container-lifetime design (§3.1) and is now on the
  critical path. Red-first: prove an in-process-signed dylib `dlopen`s and
  executes, and prove that a **tampered** one is rejected by AMFI, before wiring
  it in.
- Distinguish *no authority* from *file miss* at the store boundary and count
  both (this is 0d.3's instrument, promoted to production).

**Gate:** build-cold wall unchanged within noise with the lane OFF (this phase
must not regress the default path); with the lane ON, per-unit publication cost
drops by the measured `codesign` time and no unit content changes.
**KILL:** in-process signing produces an image AMFI rejects, or one that
`codesign --verify --strict` disagrees with. Revert to the subprocess and record
the finding; do not ship a signer we cannot verify with the platform's own tool.

### Phase 2 — persistence, with the election deleted

Default ON, exact hatch `CARRICK_DSR_SHARED_TRANSLATION=0`, hatch deleted when
the gate is banked. **This is the phase that carries the ceiling.**

- Implement §6: store layout, mmap-ed index, staged publication, GC.
- **Delete `claim_recording` and the `.seen`/`.builder` protocol** (§6.7). The
  first process to see an unpublished key produces it under the per-key lock.
- Keep demand recording as the producer (§5.3). Persistence alone makes it
  cumulative across runs.

**Gate:** the two-run test the superseded design already specified — "second
launch of the same guest performs zero translation (`translations=0` in the DSR
profile)" — relaxed to *materially fewer*, plus a cold/warm `workload-spread.sh`
build-cold pair.
**KILL — any of:**
- warm build-cold is not **better** than the same-binary control by ≥5%;
- cold build-cold regresses by >3% (production cost must be paid back within one
  reuse);
- units published per run is 0, or index hits per run is 0, on a workload with a
  configured segment (**zero is an error, never an empty result**);
- any new DIFF/CRASH/TIMEOUT in `just conformance-native smoke` that reproduces
  on a quiet machine and is absent from the control;
- `compute` or `fs-walk` regress beyond noise.

### Phase 3 — segment coverage

Only if 0d.2 says segments miss a large share of executed blocks. Extend segment
enumeration past `ro_spans` (main binary + interpreter) to executable regions the
guest maps itself, keyed by the backing file's content rather than its path.

**KILL:** if extending enumeration does not raise the in-segment block fraction
by ≥10 percentage points, delete it — the added key surface is pure miss-path
cost.

### Phase 4 — eager whole-image production

**Only if Phase 0e shows recursive descent discovers a large majority of
executed block starts, and only after Phase 2 has banked a positive result.**
Produce a unit at `configure_shared_translation` time via
`plan_block_with_segments` over `source_words` + `record_portable_block_artifact`
(§5.2), off the guest's critical path.

**KILL — any of:**
- first-instruction latency (the `startup` row of `workload-spread.sh`)
  regresses beyond noise;
- produced-but-never-executed blocks exceed 2x the executed set (the unit is
  mostly dead weight, and the 64 MiB cap will be hit by real images);
- build-cold does not improve over Phase 2 alone by ≥3%.

A killed Phase 4 costs nothing: §5.3's hybrid reaches the same steady state one
or two runs later.

---

## 8. Gates

One knob at a time, everything else held, **including core class** — this host
is 4 Performance + 6 Efficiency cores and `hw.logicalcpu` is not homogeneous.
Never run carrick and the Docker oracle concurrently.

**Primary — build-cold wall.** `scripts/perf/workload-spread.sh N` (N≥5) after
`just build`. Strictly serial phases, in-guest timing windows on both engines,
median reported. It writes **no files** — redirect stdout and transcribe
accepted numbers into `docs/perf-results/`. Requires the local registry at
`localhost:5005`. The `startup`, `compute` and `fs-walk` rows must not regress;
`build-cold` is the row this work moves. Note the script's own caveat: its
`build-warm` row shares no state across container runs, so it is
build-cold-equivalent — **the persistent store is exactly the change that would
make a real warm row meaningful, and Phase 2 should add one** (same GOCACHE
priming, second carrick run against a warm `$CARRICK_HOME/xlat`).

**Redundancy re-measure.** `CARRICK_XLAT_CENSUS_DIR` + the Phase-0 aggregator,
before and after. The headline is distinct **unit keys** and in-segment block
fraction, not distinct VAs. Its 4.04x cross-process figure is an upper bound (a
fixed PIE base aliases VAs across binaries) and must keep being reported as one.

**Store counters.** `CARRICK_DSR_PROFILE`'s `shared_unit_lookups /
shared_unit_hits / shared_unit_loads` (`translator.rs:1571-1573`), plus the new
no-authority / file-miss split. **A run with a configured image and zero lookups
fails the gate.**

**Correctness.** `just ci` (fmt-check → clippy → lint-domains → deny →
check-matrix → check → doc → test → test-integration), plus
`just conformance-native` (tier defaults to `smoke`; depends on `build`, so the
binary is signed). Two caveats to state with any result: the native overlay
`scripts/conformance/baseline.native-dsr.jsonl` is essentially empty and
unblessed, so its output is a **measurement, not a regression check**; and its
verdicts are load-coupled — run it on a quiet machine and sample each point ≥2x.

**Red-first, per phase.** Phase 1: a tampered in-process-signed dylib must be
rejected. Phase 2: a truncated dylib, a truncated metadata file, a half-pair, a
stale-`translator_abi` unit and a corrupt index must each produce a **miss with
a named reason**, proven red before the happy path is wired. Phase 4: a segment
whose recursive descent hits an unsupported instruction must produce a partial
unit that still validates, not a rejected one. A test that passes immediately
proves nothing.

**Attribution before fixing.** Any gate regression is attributed before it is
fixed: does Docker fail it too, does the pre-change binary fail it, what did the
baseline say. Verdicts here are load-probabilistic, so a one-run-per-point
bisect will converge on the wrong commit.

---

## 9. Ranking, and consistency with the sibling design

`docs/superpowers/specs/2026-08-02-dsr-assembler-arena-design.md` §8 ranks this
task (#13) **above** the assembler-arena task (#14): 21-31% of build wall
against 1-12%, with #13 partially subsuming #14 (an AOT-loaded block is
`PublishedBlockMetadata::Mapped` — it allocates neither the assembler's
transient state nor per-block retained metadata, so every block a unit serves is
a block #14 no longer has to make cheap; the reverse is not true).

**That ranking is correct and this document adopts it**, with three amendments
this investigation supports:

1. **#13's risk is lower than §8 credited.** §8 called it "high; the existing
   shared lane is measured +58% cold / +285% warm with 0 units published". The
   mechanism of the 0 is now localised (§2.3, §2.4) and the cost mechanism has a
   named, testable hypothesis (§2.5). A rewrite of a path whose failure is
   understood is ordinary work; the residual unknown is coverage, and Phase 0
   prices it before anything is built.
2. **#14's Phase 0 remains a shared prerequisite**, as §8 says — and this
   document adds a second instrument with the *same* `execve` blind spot
   (`xlat_census`, §7 Phase 0a). Fix both flushes in one change.
3. **Neither reaches the bar, and #13's non-overlap with the campaign goal is
   total.** `handoff.md` names the goal as the ~12x steady-state emitted-code
   penalty. Translation caching does not touch it. This work is worth doing
   because the build lane is real and users will benchmark it — not because it
   is progress toward 2x.

---

## 10. Task list for the next session

Phase 0 only. Do not start Phase 1 until the numbers are committed.

1. Flush `xlat_census` on the pre-`execve` self-re-exec path
   (`translator.rs:11527-11558`); do it in the same change as the `dhat`
   profiler flush that #14 Phase 0 needs.
2. Extend `xlat_census::record` to carry the executable digest and segment
   start, so distinct **unit keys** are countable.
3. Add `carrick debug xlat-census` (Rust, typed, `just ci`-gated) to aggregate
   per-pid files: translations, distinct VAs, distinct unit keys, per-key block
   counts, process coverage, in-segment fraction.
4. Split *no authority* from *file miss* at `ActiveContainerUnitStore::load`
   (`aot_cache.rs:1901`) and count both per process.
5. Run one cold `go build` with `CARRICK_DSR_SHARED_TRANSLATION=1` and record
   answers to 0d.1-0d.4.
6. Offline recursive-descent enumerability study over `source_words` (0e).
7. Re-baseline build-cold with `workload-spread.sh` in the same session.
8. Commit to `docs/perf-results/`, and **update §0 and §7 of this document in
   place** — do not leave the estimates standing once they are superseded.

---

## Appendix — findings that are defects on their own merits

Small, independently fixable, found while reading; none of them wait on this
plan.

- **Miss-reason conflation** (`aot_cache.rs:1901-1918`): a missing *authority*
  and a missing *file* are both `MissingPair`, and the call site
  (`translator.rs:3055-3063`) collapses them. A process contributing zero
  coverage is indistinguishable from one whose lookups merely missed.
- **The key is serialised and hashed twice per miss** (`shared_cache.rs:333`,
  called from both `load_unit` and `claim_recording`), for a value that is
  constant per segment for the life of the process.
- **`CARRICK_DSR_KEEP_CONTAINER_CACHE=1` leaks a directory and prints its path to
  stderr** (`aot_cache.rs:1824-1828`). A diagnostic that leaks is not a
  persistence mode; §6 replaces it.
- **The `xlat_census` `atexit` blind spot** (`translator.rs:11555`) — the same
  defect as the alloc census, in an instrument whose output this campaign has
  already cited as a denominator.
- **`workload-spread.sh`'s `build-warm` row measures nothing warm** and says so
  in a comment. It becomes meaningful only once a persistent store exists.

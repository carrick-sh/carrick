# COW fault service and process teardown: what the carrier CPU is (2026-10-01)

Diagnosis only, no code changes. Inputs: the lane-off arm of campaign
`el1ab-202610010107` (binary `c2c6b14f…`, built from 2bfa005b6), plus targeted
captures on the same workload (`cpython-threading`, `--randseed 0`) with four
new durable D scripts. Host shared with other agents, so wall/CPU numbers are
"suggests"; counts are exact.

## TL;DR

- **The A/B "COW fault service" class is only partly COW.**
  `hvpatch-carrier-cpu-attribution` files any stack through a `cow_engine`
  frame as COW. That module also holds the syscall memory accessors and
  sparse/private first-touch materialization, and the class also catches EL1
  grant-commit reconciliation. Re-filed:

  | bucket (share of all carrier samples, lane off) | cpython | node |
  |---|---|---|
  | **real frame COW** (`resolve_frame_cow_fault`) | **7.6%** | 0.35% |
  | EL1 grant-commit reconciliation (`reconcile_guest_frame_commits` → per-page stage-1 debug walk) | **4.2%** | **3.7%** |
  | sparse/private first-touch materialization | 1.8% | 2.9% |
  | munmap alias retirement | 0.9% | 2.1% |
  | syscall memory accessors (`mapping_for_range*`) | 0.8% | 2.2% |
  | fork COW arming | 0.8% | 0.0% |
  | `observe_frame_cow_protection` | 0.4% | 0.4% |
  | profile "cow" class total | 16.7% | 11.8% |

  On Node, real COW is 0.35%; the 12% was everything else.
- **A real COW costs about 40–50 µs of carrier CPU, of which the 16 KiB copy
  is about 10%.** The rest is bookkeeping: alias registry 31%, frame-inventory
  split and Kernel authority 21%, mapping index and source lookup 10%,
  stage-1 edit 10%, armed ranges 8%, TLB invalidation 2%.
- **63% of cpython's COW copies are of a frame the writer already solely
  owns.** Linux serves that write fault by reusing the page (no copy, no new
  frame). Carrick never does: the in-place grant (`pt-alias-receipt` phase 7,
  still described in `hvpatch-frame-cow.d`'s header) fired 0 times and is no
  longer in the source.
- **Teardown is about 4.3 ms of on-CPU time per process.** It splits: alias
  scope retirement 26%, physical owner retirement 25% (about 190 leases per
  process at ~5.6 µs each), `stage_retirement` 16%, other backend 13%, Kernel
  apply 11.5% and receipt authentication 7%. It grows with the inventory
  population n (n = 2511 mappings and ~1330 alias rows for the large cpython
  processes). Receipt authentication and the Kernel apply have O(n²)
  `Vec::contains` terms.

## Method

- **Re-filing:** the A/B's raw `carrier-cpu-attribution` stacks were
  re-symbolized against the exact measured binary (`atos` with the image
  slide). Shared-cache frames were symbolized against a live helper process
  with Hypervisor.framework loaded (`hv_trap` = Hypervisor.framework traps).
  Stacks were then re-bucketed by the outermost discriminating frame.
- **Counts:** `scripts/dtrace/hvpatch-cow-fault-structure.d` (USDT only, via
  `carrick trace`, every probe scoped to `$target`/progeny). The first,
  unscoped draft matched other agents' carriers on this host: forks rose
  from 78 to 264 and exits from 79 to 853.
- **Costs:** `scripts/dtrace/hvpatch-cow-fault-cost.d`,
  `hvpatch-process-teardown-phases.d` and
  `hvpatch-process-teardown-scaling.d` use the pid provider. Under
  `carrick trace`, `$target` *is* the carrier: the run process retitles
  itself `carrick:<name>: N containers`, and guest forks create no host
  processes. These scripts need `get-task-allow`, so they ran on a
  `just build-debug` of 313a1ab00 (`24b2f36f…`). Pid-provider names are
  demangled and need `??` for `::` and `?GT?` for `$GT$`; the script
  headers record this.

## Q1. Per-COW-fault cost

The `hvpatch-cow-fault-cost.d` capture found 38.5k
`HvfVmState::resolve_frame_cow_fault` calls, totalling 0.96 s on-CPU. The
distribution is bimodal: ~20.7k calls at 1–4 µs that commit no COW, and
~17.8k at 16–128 µs, which matches the 17.7k committed COWs. That gives
**≈ 50 µs per committed COW** under the bracket probes. The unperturbed
sampled profile gives 677 samples / 17.7k COWs ≈ **38 µs** (profile-997,
~1 ms per sample).

Inside the real-COW subtree (677 cpython samples):

| component | share | inherent? |
|---|---|---|
| alias registry (`mutate_known_external_alias_state`, `register_shared_alias`, retention aliases) | 31% | bookkeeping |
| frame-inventory split + Kernel authority (`cow_inventory_split_shape`, `commit_cow_inventory_split`, `KernelFrameCowAuthority::{apply,reserve,quiesce}`) | 21% | bookkeeping |
| 16 KiB copy + zero (`_platform_memmove` / `memset`) | 10% | **inherent** |
| mapping index / COW source lookup (`TaskMappingIndex`, `physical_cow_source_in`, `host_ptr_for_range`) | 10% | bookkeeping |
| stage-1 descriptor edit | 10% | partly inherent (one leaf write) |
| COW armed ranges (`CowArmedRanges::disarm/span_for`) | 8% | bookkeeping |
| other | 6.5% | |
| TLB invalidation (`invalidate_asid_on_vcpu` → `hv_trap`) | 2% | inherent |
| lock wait / allocator | <1% | |

Exits and fault decode sit outside the bracket. The A/B exit attribution puts
cpython's data-abort exits at 39,049 with 452 ms of host on-CPU time
(11.6 µs/exit average across all fault classes).

**Counts (cpython-threading, scoped census, 3 runs agree within 2%):**
- 17,725 committed COWs, 78 forks, 34 execs, 79 process exits. That is
  ≈ 227 COWs per fork and 228 per process.
- Per process: 27 of the 79 take none; 38 take 128–255; 8 take 256–511; 5
  take 64–127; one (the regrtest runner) takes 4096–8191.
- 40,234 private frames shared at fork (≈ 516 per fork); 44% of the frames a
  fork shares are later COWed.
- Trigger class: 99.5% stage-1 permission faults, 46 syscall guest writes,
  44 privileged internal.
- Region: mmap arena 75%, heap 23%, image/stack/low 1%.

**Native comparison.** Linux also takes one write-protect fault per written
4 KiB page after fork, so the fault count is not the gap. The gap is the
~40–50 µs per fault, against ~1–2 µs for a native COW fault (16 KiB copy
≈ 1 µs). It is also the copy-when-sole-owner behaviour below. Oracle commands
for the Docker phase (run alone, never alongside carrick):

```sh
# 1) minor faults, whole workload (self = the wrapper, children = regrtest
#    and every subprocess it waited on)
docker run --rm --platform linux/arm64 localhost:5050/cpython-test:3.12.13 \
  /usr/local/bin/python3 -c "import resource,subprocess,sys; \
subprocess.run([sys.executable,'-m','test','-v','--randseed','0','test_threading']); \
s=resource.getrusage(resource.RUSAGE_SELF); c=resource.getrusage(resource.RUSAGE_CHILDREN); \
print('MINFLT self', s.ru_minflt, 'children', c.ru_minflt, 'MAJFLT', s.ru_majflt+c.ru_majflt)"

# 2) write-protect faults split into copy vs reuse (bpftrace inside a privileged
#    oracle, per the ltp-conformance skill). Confirm the probe names first:
#    bpftrace -l 'kprobe:*wp_page*'; if wp_page_reuse is inlined, use do_wp_page
#    minus wp_page_copy.
docker run --rm --privileged --pid=host localhost:5050/cpython-test:3.12.13 sh -lc \
 'mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true;
  bpftrace -e "kprobe:do_wp_page /comm == \"python3\"/ { @wp = count(); }
               kprobe:wp_page_copy /comm == \"python3\"/ { @copy = count(); }
               tracepoint:sched:sched_process_fork /comm == \"python3\"/ { @fork = count(); }" \
   -c "/usr/local/bin/python3 -m test -v --randseed 0 test_threading"'
```

The carrick numbers to compare against are committed COWs 17.7k (all
copies) and forks 78. The expected native shape is wp faults of the same
order, with copies well below them.

## Q2. Fault structure

From `hvpatch-cow-fault-structure.d`, of 17,725 committed COWs:

| shape | COWs | share | meaning |
|---|---|---|---|
| **reusable** (shared OR child-gone) | **11,145** | **63%** | the writer was the frame's last owner: Linux reuses, carrick copies |
| ↳ shared | 6,070 | 34% | parent and child both copied the same old frame; the second copier was the sole owner |
| ↳ child-gone | 6,160 | 35% | the fork sharer (child) had already exec'd or exited when the parent wrote |
| repeat-same-4k | 5,968 | 34% | the same guest page COWed again in the same mm: the parent re-sharing its pages on every fork, then copying them again |
| repeat-other-4k | 510 | 3% | another 4 KiB page of an already-COWed 16 KiB granule |
| adjacent | 9,326 | 53% | a 16 KiB neighbour already COWed by the same mm |

Leaf receipts: phase 2 (copy published) 17,681; phase 7 (in-place grant)
**0**.

So the faults are not per-page work that a batch would naturally serve.
Linux takes them one page at a time as well. The waste is that two thirds of
them copy at all. "Adjacent" says a 32–64 KiB fault-around would cut the
fault count by up to about half. But it would copy neighbours that may never
be written, and most of those neighbours are reusable anyway, so it is a
second-order lever behind reuse. Parent and child do fault the same page (the
"shared" row). With reuse, only the first writer copies and the second keeps
the original.

## Q3. Teardown

`hvpatch-process-teardown-phases.d` saw 79 teardowns using 341 ms on-CPU,
4.3 ms each. The A/B estimate of 4.7 ms agrees.

| phase | share | what |
|---|---|---|
| alias scope retirement (`AliasRegistry::retire_scope`) | 26% | per alias row: `index_remove` plus 4 `AliasClassIndex::remove` (each a `position` scan of its bucket); ~1.4–1.9 µs per row on large processes |
| physical owner retirement (`retire_global_frame_host_owner_inner_in_using`) | 25% | 14,970 leases (≈ 190 per process), ~5.6 µs each: `hv_vm_unmap` plus host `munmap`/`madvise` per lease |
| `stage_retirement` | 16% | per extent: Kernel batch query, reference arithmetic, remainder records |
| other backend (validation `PhysicalExtentIndex`, mapping-row drop) | 13% | per mapping row |
| Kernel `apply_retirement_with_receipt` | 11.5% | per unmap event, plus `mappings.contains()` per event: **O(n²)** |
| receipt authentication (`authenticate_pending_retirement`) | 7% | `receipt.authorizes()` is `Vec::contains`, once per expected mapping: **O(n²)**; the pending filter is O(p·n) |

**What it scales with.** `hvpatch-process-teardown-scaling.d` counted the
inputs: mapping population n up to 2511 per process, alias rows up to
~1370, class-index removals at 4 per row. Every phase grows with n (Kernel
apply r = 0.74, apply plus authentication r = 0.75). Receipt authentication
is ~0.18 µs per mapping at n ≈ 1000 and ~0.29 µs at n = 2511, so its cost
per mapping rises with n, as the quadratic term predicts (≈ 0.74 ms of
authentication at n = 2511). Teardown is therefore proportional to the
process's mapping and alias population plus a quadratic receipt term. It is
not proportional to mapped bytes; owner retirement scales with leases, not
size.

## Levers (estimated shares of carrier CPU, lane off)

1. **Reuse the frame when the writer is its last owner (cpython ≈ 4%,
   Node ≈ 0.2%).**
   - When a write fault lands on a fork-armed page whose frame the Kernel
     counts at one mapping (the writer's) with no other backend holder,
     upgrade the leaf to writable in place.
   - That removes the copy, new frame, alias row, inventory split and
     stage-2 map for 63% of COWs (0.63 × 7.6% × ~0.85 of each one's cost),
     with fewer frames and leases to retire at exit as a knock-on.
   - The decision has to come from the same authority as retirement. The
     fork two-holder race showed that a backend-only count is not enough: a
     sibling's decided-but-unapplied unmap must still read as "shared" and
     copy.
   - Contract: a two-process test where the child exits, then the parent
     writes. Expect 0 copies and the same bytes.
2. **Stop revalidating EL1 grant commits with per-page full stage-1 debug
   walks (cpython ≈ 4%, Node ≈ 3.5%).**
   - `reconcile_guest_frame_commits` runs on every mutating fault and
     syscall boundary: 27k calls per cpython run.
   - 75% find nothing dirty, at ~3 µs each.
   - ~1.8k calls revalidate 128–255 dirty pages, each through
     `live_pt_debug_walk`: a `TTBR0_EL1` vCPU register read, a host lookup
     of the page-table region, and a resolver walk that does a
     `mapping_for_ipa_range` / `candidates_for_ipa_range` index search per
     level.
   - Resolve the table region once per call, walk to each L3 table once,
     and read the leaves of a grant directly. The cost would drop to one
     lookup per table, about 1–2% of today's.
   - The same resolver walk serves fork arming (0.8%) and deferred-COW
     authentication.
3. **Make teardown linear and batched (cpython ≈ 2–2.5%, Node and go
   ≈ 0.5%).**
   - Authenticate the retirement receipt with a sorted or hashed mapping
     set instead of `Vec::contains`, in both
     `authenticate_pending_retirement` and the Kernel's
     `apply_retirement_with_receipt`: ~18% of teardown, all of it O(n²).
   - Drop a retiring scope's class-index entries in bulk instead of four
     bucket scans per row: ~26%.
   - Retire contiguous stage-2 leases with one `hv_vm_unmap` and hand host
     backing back to the frame pool instead of per-lease `munmap`/`madvise`:
     ~25%, perhaps half of it recoverable.

**Measurement fix (no CPU, but it changes the ranking).** The
carrier-attribution classifier's `cow_engine` substring rule files
first-touch materialization, syscall accessors and grant reconciliation as
COW. Classify on the fault entry (`resolve_frame_cow_fault`), not the module.
This campaign's "COW 18% / 12%" is really "COW 7.6% / 0.35%".

## Artifacts

- Scripts (headers carry ABI qualification and perturbation):
  - `scripts/dtrace/hvpatch-cow-fault-structure.d`
  - `scripts/dtrace/hvpatch-cow-fault-cost.d`
  - `scripts/dtrace/hvpatch-process-teardown-phases.d`
  - `scripts/dtrace/hvpatch-process-teardown-scaling.d`
- Run IDs:
  - `cowc-struct-py4`, `cowc-struct-py5`, `cowc-struct-py6` (structure,
    binary `c2c6b14f…`)
  - `cowc-cost-py3` (COW and reconcile cost), `cowc-tdph2` (teardown
    phases), `cowc-td11` (teardown counts), all on binary `24b2f36f…`,
    313a1ab00 with `just build-debug`
  - All lane off (`CARRICK_EL1_DESCRIPTOR_LANE=0`).
- Re-filed A/B stacks: from
  `.worktrees/wt-land-g2/target/perf/el1-workload-ab/el1ab-202610010107-attribution/*lane-off-carrier-cpu-attribution.raw`.

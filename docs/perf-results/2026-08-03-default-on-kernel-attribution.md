# Default-on native kernel attribution

**Date:** 2026-08-03  
**Workload:** Darwin/AArch64 native cold `go build`  
**Decision:** **measurement accepted; selected runtime hypothesis rejected**

The two completed `native-wall` profiles are valid mechanism evidence, and the
offline selector found a stable kernel family. Exact KDK/LLDB attribution then
showed that the selected leaf is where a deferred sampling interrupt is
delivered, not where the corresponding CPU time was spent. No runtime change
and no H006 hypothesis is authorized from this selection.

## Bound inputs

Both profiles came from clean source `c7e36c87ce3eedbbc0c593f10540e36a30bba4aa`
and signed executable SHA-256
`8975e8b7c7fce94daa983a7964a7a6fbc5524bb0f6b46dcf7e2f32b603b51dbe`.
They ran the same cold-Go workload and completed naturally with zero principal,
aggregation, dynamic, dynamic-rinse, dynamic-dirty, or other drops.

| run | source | SHA-256 | elapsed | kernel/user CPU samples |
|---|---|---|---:|---:|
| A (`dsr-20260803T173236.992Z-97000`) | `target/perf/store-default-confirm/default-on-native-wall-fixed-a.jsonl` | `d42f20ded6e98da08c9d37712e7aeda4cf490dfe1da1e5437d45fef27c4fdb56` | 17.680 s | 10,541 / 9,323 |
| B (`dsr-20260803T173312.628Z-97152`) | `target/perf/store-default-confirm/default-on-native-wall-fixed-b.jsonl` | `0158c5beaec2760a1c0e2256e8bf11a2b6e0ba604854b99560249aeeee6b8b47` | 16.230 s | 9,378 / 8,624 |

The analyzer needed one evidence-consumer repair before these V2 summaries
could be read: PCs and stacks are unique within `(pid, sample class)`, and raw
kernel frames are symbolized by a separately hashed
`carrick.sampled-kernel-symbols.v1` overlay. Commit `6a23b776` validates that
scope, the exact requested/resolved/unresolved address partitions, their
big-endian-u64 SHA-256 hashes, and their binding to every raw profile address.
Its 21 analyzer tests and all 45 capture/receipt tests pass.

The derived result is
`target/perf/store-default-confirm/default-on-native-kernel-attribution-v1.json`
(SHA-256
`9c0289216b5da468643f3fbf161b5c6d3a7f0f32fd16eac73f851f7275699ac8`).
It reconciles PC count exactly to stack count in both runs and symbolizes
10,208/10,541 (96.84%) and 9,092/9,378 (96.95%) leaves. The shared top-ten
families cover 7,541/10,541 (71.54%) and 6,717/9,378 (71.63%) samples.

## Selection result

The selector returned `selectable` and chose
`kernel`ml_set_interrupts_enabled_with_debug`:

- stack-family counts: 4,096 and 3,614;
- shares: 38.86% and 38.54%;
- absolute drift: 0.32 percentage points;
- all minimum-share, mean-share, drift, symbolization, and shared-top-ten gates
  passed.

This is a candidate package only. Selection does not establish a causal
mechanism or a wall-time opportunity.

## Causal disqualification

The authenticated overlay binds the dominant live PC to
`0xfffffe0038dc0b00`. After subtracting the live KASLR slide `0x318d4000`, the
matching T8132 KDK reports:

```text
fffffe00074ecab4 s _ml_set_interrupts_enabled_with_debug
fffffe00074ecb54 S _ml_set_interrupts_enabled
```

The selected implementation is the local lowercase-`s` function, not the
separate exported trampoline. LLDB resolves the sampled address as
`ml_set_interrupts_enabled_with_debug + 76` at
`machine_routines_common.c:1281` and disassembles the boundary as:

```text
<+72>: msr DAIFClr, #0x7
<+76>: b   <+96>
```

`DAIFClr` re-enables interrupts. A profile timer that expired while interrupts
were masked is delivered immediately afterward, so the PC accumulates the
preceding interrupt-disabled interval. It does not show that the branch or the
function itself consumed that interval. The raw PC appeared 4,579 times in run
A and 4,085 times in run B; only one sample in each run landed at +104, and one
additional run-B sample landed at +108.

The stacks cannot recover the hidden caller: 4,073/4,096 selected-family
samples in A and 3,591/3,614 in B contain only that single frame. Therefore the
capture supports neither a causal critical section nor a defensible untraced
wall upper bound. Optimizing this function would be speculation.

## Perturbation and consequence

These traces took 16.23-17.68 s, versus the current untraced shipped-default
median of 9.326 s. Their sampled kernel share was 52.1-53.1%, versus the prior
untraced-attribution estimate near 32%. Several other shared top-ten families
are explicitly DTrace/fasttrap work. Absolute traced timing and the selected
share are therefore diagnostic, not performance authority.

The next measurement must avoid stack-based inference. Use untraced Carrick
mechanism counters to bind the 20-exec/process-lifecycle amplification to the
real cold-build critical path. Pursue an implementation only if that binding
shows at least a 10% end-to-end CPU or wall opportunity; otherwise move to the
next measured bucket.

# N1 x86 diagnosis: populated fork is blocked by physical stock

2026-10-08, Linux x86_64 KVM, parent `44dc5c15e` / `74b7e846f`.
These are deliberately RED diagnostic bindings, not acceptance evidence.
No shared-code defect has been established and no implementation is changed.

## Reproduce without Docker

```sh
CARRICK_REQUIRE_KVM=1 cargo test -p carrick-cli --no-default-features --features platform-linux --test x86_kvm_run mounted_static_x86_fork_cow_twenty_rounds -- --nocapture
CARRICK_REQUIRE_KVM=1 cargo test -p carrick-cli --no-default-features --features platform-linux --test x86_kvm_run mounted_static_x86_map_fixed_over_cow_thirty_two_rounds -- --nocapture
```

Both static ELFs complete natively (exit 7, `C` completion line). Both KVM
runs return exit 91 and the binary failure record `[0, 91]`: first fork,
zero-based round 0. Each uses the existing five-second execution bound and
requires the `kvm-x86-cpl0` receipt on success. They live in the existing
`x86_kvm_run` KVM test target, so the KVM lane runs them without a new gate.

Sequence: MAP_FIXED anonymous RW at `0x40000000`, length 65536; write `0x33`
to the first word of each of sixteen 4096-byte pages; fork. Fork is refused.
Thus neither workload reaches its post-fork stores or replacements on KVM.
The receipt authenticates MM 301, root 67112960, sixteen private pages,
incarnation 1, generation 6, and five portal exits.

These scalar reductions do not claim equivalence to the four concurrent
writers in `embed-el1-sched fork-cow 20 16`. The MAP_FIXED reduction replaces
whole mappings in both MMs for 32 rounds; the ARM fixture additionally checks
partial ranges, retained neighbors, already-broken COW, pipe synchronization,
and `/proc` rows. Those bindings, threaded lifecycle and IPC remain pending.

## Live debugger evidence

LLDB breakpoint at `cpl0_anonymous.rs:631` in
`Cpl0HostCustody::service_fork_stock` captures the actual request:

- `child_bytes = 40960` (ten tables), `parent_bytes = 4096` (one table).
- `self->grant_tables.len = 10`; eleven pages are needed.
- `self->fork_lifecycle_available = true`.
- Request and execution match: task 41, generation 11, MM 301, thread
  generation 101; root 67112960, context generation 1, carrier 1.

`take_fork_table_stock` refuses insufficient physical stock. This is the
KVM adapter, before shared fork publication or child COW execution.
The stock comes from unused initial image table grants, whose size depends
on initial image/stack pages, rather than an elastic fork request.

Debugger stops perturb the five-second watchdog: continuing the second
capture returned `initial process cancelled`, exit 125. That is not a
workload verdict; the uninstrumented tests independently return exit 91.

A second obstacle is explicit in the adapter: one reserved child lifecycle
region at metadata offsets `0x4000`/`0x5000`, with
`fork_lifecycle_available = false` after the first loan. Initialization remains
retained even on abort; reuse requires an exact retirement receipt. Repeated
fork workloads cannot be licensed by enlarging the table stock alone.

## Next architectural work

Provision physical table stock on demand with exact owner/grant custody,
then return or retain it under explicit commit/abort/retirement receipts.
Provision and reclaim lifecycle records by exact task/thread generation.
Do not enlarge fixed budgets, recycle metadata without a retirement receipt,
or introduce an ISA workaround in the shared owner. Once those physical
bindings exist, rerun these red tests, port the full threaded/partial-range
fixtures, and attribute any remaining failure before fixing shared code.

No Docker or signed HVF run was performed on this Linux host. These bindings
confer no ARM pass, structural COW budget pass, or runtime ratio claim.

Captured artifact SHA-256 (debug CLI, unchanged production sources):
`2f18d161c0ce64263449289137fb1d303d686d2a00a2552f6858f2080c8589aa`.
LLDB fork-COW ELF SHA-256:
`3b926833aee2c5a8721716219d6c3fc857bc68ef995e4954fa123d07043b5f5a`.

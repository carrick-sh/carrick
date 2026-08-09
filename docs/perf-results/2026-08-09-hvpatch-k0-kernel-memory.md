# HVPatch K0 kernel-memory qualification

**Date:** 2026-08-09  
**Verdict:** **GO for the K0 memory-HAL gate only**  
**Backend:** macOS/arm64 Hypervisor.framework  
**Source commit:** `abe7bd74aaa2e59ec78e206047bb381cdaa6a50b`  
**Run ID:** `k0-memory-qualified-20260809T181157Z-83382`

This result qualifies the kernel-first memory primitives required before the
Hybrid backend can proceed. It does **not** qualify K1–K6, make `hybrid` a
runnable backend, or change Carrick's experimental status.

## Authoritative artifact

The complete 490-record JSONL receipt is
[`hvpatch-k0-kernel-memory.jsonl`](hvpatch-k0-kernel-memory.jsonl).

| Artifact | SHA-256 |
|---|---|
| Signed probe binary | `77eab43fedd20fb3ac4288f2e3dbc9dacc6a2ef6812de4956bc7a7732d139e5b` |
| JSONL receipt | `84177916282181fd16b1fb0ef3a266a4111cfd5a6697ab1ce6b8816ef7458e2c` |

The receipt binds the run to the full source commit, binary digest, arm64 UUID
`4E65E85F-E23F-33F3-99BC-C3405C0ABDD3`, command line, host identity, macOS
build, kernel, page size, load average, and the Hypervisor.framework
entitlement. The tracked tree was clean when the exact commit was built.
Standard error was empty.

## Gate result

| Requirement | Evidence | Result |
|---|---|---|
| One process-wide HVF VM | Final record has `vm_create_count: 1`; checked vCPU and VM teardown completed before `GO` | PASS |
| Distinct ASID-tagged roots | Parent ASID `0x41` and child ASID `0x42` use distinct TTBR0 roots and non-global user leaves | PASS |
| Shared compound frames | Both roots observe the same 16 KiB frame before COW | PASS |
| Real permission-fault COW | 32 child writes fault on a read-only L3 leaf, copy one data frame and three child table frames, then resume the exact faulting store | PASS |
| Parent isolation | Every COW sample compares all 16,384 bytes of both frames; the shared parent frame and all live parent tables remain byte-identical | PASS |
| Break-before-make | The child root edge is invalidated before its output address changes; maintenance executes through the unaffected parent root | PASS |
| Scoped invalidation | 128 `tlbi aside1is` samples execute the exact `dsb ishst; tlbi; dsb ish; isb` sequence | PASS |
| Concurrent stage-2 operations | Four threads overlap disjoint map/unmap calls, reaching four calls in flight with zero failures | PASS |
| Fail-closed evidence | Exact sample populations are asserted, a 30-second watchdog bounds hangs, and `GO` is emitted only after checked teardown | PASS |

The stage-2 population contains 128 map and 128 unmap samples. Every mapped
host backing remains alive until after the one-VM qualification completes.

## Latency distributions

These are mechanism-qualification samples from a self-contained micro-VM, not
workload-performance authority.

| Operation | Samples | Min ns | p50 ns | p95 ns | Max ns |
|---|---:|---:|---:|---:|---:|
| Frame map | 128 | 750 | 2,458 | 7,167 | 9,125 |
| Frame unmap | 128 | 208 | 500 | 1,625 | 4,583 |
| ASID switch | 64 | 0 | 41 | 42 | 83 |
| ASID-scoped TLBI | 128 | 791 | 833 | 917 | 2,375 |
| COW permission fault | 32 | 833 | 917 | 959 | 1,000 |
| Three-frame table-path copy | 32 | 1,000 | 1,042 | 1,208 | 2,916 |
| Complete COW recovery | 32 | 4,833 | 4,958 | 5,208 | 12,292 |

Twenty-one of the 64 ASID-switch samples (32.8%) quantized to zero at the host
timer's resolution. The raw population is retained rather than altered; the
median and percentile values remain non-zero.

## Reproduction

The probe source is
[`crates/carrick-vmm-hvf/src/bin/hvf_kernel_memory_probe.rs`](../../crates/carrick-vmm-hvf/src/bin/hvf_kernel_memory_probe.rs).
The qualified run used:

```sh
COMMIT=$(git rev-parse HEAD)
cargo build --release -p carrick-vmm-hvf --bin hvf_kernel_memory_probe
codesign --force --sign - \
  --entitlements scripts/entitlements.plist \
  target/release/hvf_kernel_memory_probe
CARRICK_RUN_ID=k0-memory-qualified-20260809T181157Z-83382 \
CARRICK_SOURCE_COMMIT="$COMMIT" \
  target/release/hvf_kernel_memory_probe >k0.jsonl 2>k0.stderr
```

Validation receipts:

- `cargo test -p carrick-vmm-hvf --bin hvf_kernel_memory_probe`: 5 passed.
- `cargo clippy -p carrick-vmm-hvf --bin hvf_kernel_memory_probe -- -D warnings`: passed.
- `just ci`: passed after the final source correction and qualified live run.
- Independent final review found no blocker or high-severity issue in the BBM
  maintenance root, table-copy accounting, or live receipt.

## Next gate

K0 removes the memory-HAL blocker. The next work must implement and qualify K1,
the one-VM global-kernel boot/lifecycle foundation described in
[`hybrid.md`](../../hybrid.md). K0 is not permission to skip K1's rollback,
lifecycle, and evidence requirements.

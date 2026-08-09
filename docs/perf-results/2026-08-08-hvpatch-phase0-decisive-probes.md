# HvPatch Phase 0 decisive probes — GO with one design correction

Date: 2026-08-08

Controller: `/Volumes/CaseSensitive/carrick/hybrid.md`, Phase 0

Probe source: `ac37baf0f5354c71458866cb0518ddf32d29732a`

Normalized records: [`hvpatch-phase0-decisive-probes.jsonl`](hvpatch-phase0-decisive-probes.jsonl)

## Decision

**GO** for Phase 1. The load-bearing proposition is measured true: ordinary
EL0 branches to a separately mapped stage-1 RX island execute without returning
to the host, and an exit-free compute loop runs within 5.3% of the identical
host-native instruction stream at the median on this micro-fixture.

There is one required correction to the plan before Phase 1 implementation:
**do not patch `mrs tpidr_el0`**. It was exit-free in all 500,000 measured reads
and slightly faster than the proposed info-page load. The plan's projected
~680 ns MRS exit does not exist on this HVF configuration. Set `TPIDR_EL0` on
each vCPU, as the VMM lane already does, and reserve info-page patching for
operations that an empirical probe proves actually trap.

This GO proves the instruction/VM mechanism only. It does not prove the final
cold-build targets, syscall-island correctness, ELF patch safety, shared-VM
process isolation, or conformance. Those remain projections and later gates.

## Provenance

- Host: Mac16,12, arm64, 10 physical CPUs, 32 GiB, 16 KiB host pages.
- OS: macOS 27.0 (26A5388g), Darwin 27.0.0 RELEASE_ARM64_T8132.
- Toolchain: rustc 1.96.0 (ac68faa20 2026-05-25).
- All probes used Carrick's production `stage1_identity_page_tables`, EL0
  trampoline, and EL1 vector. The only host return accepted was the vector's
  `hvc #2`, with the underlying completion `ESR_EL1` checked as EC=0x15.
- Each binary was built from the source commit above in release mode, then
  ad-hoc signed with `scripts/entitlements.plist`. The entitlement inspection
  reported `com.apple.security.hypervisor=true`.
- Signed binary SHA-256:
  - `hvf_bl_exit_free_probe`: `a002d81b8e1dd8f68238f4dac6484f65296e7952c4510fc2eeba9356349fde7b`
  - `hvf_info_load_probe`: `ebbc5bf6de5d6b2461202d60090fdd401af79fdfd4f92cd1fcffe139e8ea6ae8`
  - `hvf_compute_baseline_probe`: `8a16b7b44865730a314518811ac57f912e172cb7507432a4d4b741c726146ec8`
- Load average at capture was 1.74–1.96. No Carrick workload or Docker oracle
  ran concurrently; these probes are self-contained and non-perturbing to a
  live guest workload.

Build and run commands:

```sh
cargo build --release -p carrick-vmm-hvf \
  --bin hvf_bl_exit_free_probe \
  --bin hvf_info_load_probe \
  --bin hvf_compute_baseline_probe
codesign --force --sign - --entitlements scripts/entitlements.plist \
  target/release/hvf_bl_exit_free_probe
codesign --force --sign - --entitlements scripts/entitlements.plist \
  target/release/hvf_info_load_probe
codesign --force --sign - --entitlements scripts/entitlements.plist \
  target/release/hvf_compute_baseline_probe
for run_index in {1..10}; do target/release/hvf_bl_exit_free_probe; done
target/release/hvf_info_load_probe
target/release/hvf_compute_baseline_probe
```

## Experiment 0a — cross-page `bl`

The guest executed `bl island; subs; b.ne` 100,000 times. The island was a
separate 16 KiB stage-1 RX mapping containing `mov x0,#42; ret`. A final `svc`
was the sole completion marker.

| Runs | Loop VM exits | Completion exits/run | ns/call min | median | max |
|---:|---:|---:|---:|---:|---:|
| 10 | 0 in every run | 1 | 0.833 | 0.905 | 1.022 |

Every run ended with `x0=42`, `x9=0`, exactly one `hv_vcpu_run` return, and
underlying completion `ESR_EL1=0x56000000`. The Phase 0a kill condition did
not fire.

## Experiment 0b — info-page load versus `TPIDR_EL0`

Each batch executed 100,000 reads and one final completion `svc`.

| Arm | Batches | Non-completion VM exits | ns/read min | median | max |
|---|---:|---:|---:|---:|---:|
| `ldr x0,[x20]` info page | 5 | 0 | 0.460 | 0.484 | 0.544 |
| `mrs x0,tpidr_el0` | 5 | 0 | 0.455 | 0.461 | 0.494 |

All reads returned `0x484942524944303b`. Contrary to the plan's expectation,
`mrs tpidr_el0` did not trap once. Its median was 4.8% lower than the load arm,
but these sub-nanosecond micro-results should be read primarily as a mechanism
classification: both are exit-free, and the MRS needs no patch.

## Experiment 0c — exit-free compute

The exact same hand-assembled dependent Fibonacci loop ran for 1,000,000
iterations in the stage-1 EL0 VM and in a host MAP_JIT page. Guest-first and
host-first order alternated across six batches. Both arms produced
`0xc506ab88705714bb` in every pair.

| Arm | Batches | Loop VM exits | ns/iteration min | median | max |
|---|---:|---:|---:|---:|---:|
| HVF stage-1 EL0 | 6 | 0 | 0.318 | 0.320 | 0.324 |
| Host MAP_JIT | 6 | n/a | 0.303 | 0.304 | 0.309 |

The paired median ratio is **1.053x** (HVF/host). The HVF measurement includes
one amortized final SVC completion exit; there were no exits during compute.

## Correctness and code gates

- Red-first encoding tests were observed failing before implementation.
- `cargo test -p carrick-vmm-hvf --bin hvf_bl_exit_free_probe --bin
  hvf_info_load_probe --bin hvf_compute_baseline_probe`: all three binaries
  ran the seven shared tests; 21 passed, 0 failed.
- `cargo clippy -p carrick-vmm-hvf --bins -- -D warnings`: pass.
- `just fmt-check`: pass after formatting.
- The pre-change isolated-worktree baseline `just test` passed, including
  1,230 runtime tests with 5 ignored and 0 failed.

The full `just ci` result below was captured after the probe and evidence
commits, so it is bound to the complete Phase 0 implementation tree.

## Phase boundary checkpoint

Phase 0 is **complete with GO**.

- Probe implementation: `ac37baf0` (`probe(hvpatch): qualify phase zero assumptions`).
- Evidence publication: `0b208397` (`docs(perf): record hvpatch phase zero go decision`).
- Gated tree: `0b208397161acd3bdfc1cf0d575e731c2b783592`, clean before the gate.
- Gate: `just ci` — PASS on 2026-08-08. Formatting, workspace clippy,
  typed-domain lint, dependency policy, support-matrix drift, compile/check/doc,
  serialized host tests, and integration suites all completed without failure.
- Correctness/conformance scope: mechanism probes and existing host gates only;
  no hvpatch conformance lane exists yet, and no Docker oracle was run.
- Measured decision: cross-page BL and compute are exit-free; compute is 1.053x
  host-native at the paired median; `TPIDR_EL0` is also exit-free and remains
  unpatched.
- Next decision: proceed to Phase 1 minimal product wiring, preserving the
  correction above. The first product-path performance proof remains the
  20-exec `compile -V` fixture; Phase 0 does not project its result.

## Phase 1 constraints carried forward

1. Preserve the measured cross-page BL mechanism and fail closed when a patch
   target is outside the signed ±128 MiB range.
2. Do not rewrite `mrs tpidr_el0`; configure the architectural register per
   vCPU. Re-probe any other proposed MRS rewrite before adding it.
3. Keep a final slow `svc` fallback in every island path until the syscall's
   Docker-oracle correctness probe is green.
4. Treat the 1.053x compute ratio as a mechanism result, not a cold-build
   forecast. Phase 1's `compile -V` fixture is the first product-path number.
5. The shared-VM process model and its fd/signal/memory isolation remain the
   dominant correctness risks; Phase 0 did not reduce them.

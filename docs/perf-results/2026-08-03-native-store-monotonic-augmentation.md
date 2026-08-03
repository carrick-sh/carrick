# Native translation-store monotonic augmentation: mechanism gate

**Date:** 2026-08-03. **Lane:** shipped-default Darwin/AArch64 native (DSR).
**Decision:** rejected and removed. The causal mechanism gate passed, but the
receipt-bound untraced ABBA gate found a statistically decisive regression.
The runtime candidate and its temporary controls were removed in `291359b4`.

## 1. Bound implementation and workload

All three mechanism captures used one signed release binary from a clean source
tree:

- source commit: `7eb761703d8e874eea250b37b8fe79f91a9d2dd0`;
- `target/release/carrick` SHA-256:
  `e3e68916eaf2b7560e4218c6882959848e257569e362a0d27fa10ae6a6b7d38a`;
- Mach-O UUID: `06E0A7E6-A3E8-33DB-837A-E8D6BD4EC834`;
- ad-hoc signature, verified by `codesign --verify --deep --strict`;
- `__DATA,__dof_carrick` present; and
- production unit reader SHA-256:
  `7fa369a8cd227f531794c8a28aa7ea65384cd5e2dde310cd512439038988d77b`.

The workload was the canonical cold Go build in
`localhost:5005/carrick-go-conformance:1.24`, resolved as arm64 image digest
`sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`.
It used the repository's fixed guest script: create a minimal program, compile
it with a unique empty `GOCACHE`, execute it, and require `ok` plus `BUILD_OK`.

## 2. One immutable sparse seed

The exact binary first ran the workload against an empty explicit store with
only `CARRICK_DSR_STORE_AUGMENTATION=0`. The production reader decoded every
resulting unit before the recognized `.unit-v1` files were copied into a
read-only seed which was never used as a live store.

| seed property | value |
|---|---:|
| tree SHA-256 | `db1225d3ac5c30d1067ef91749bd32415af97b025bb23a34b4f8bb63e51e3272` |
| units | 11 |
| blocks | 46,465 |
| bundle bytes | 43,750,260 |
| emitted-code bytes | 22,693,132 |
| hot/cold metadata bytes | 4,005,415 / 14,818,896 |
| PC-map entries | 5,673,283 |
| recovery entries/runs | 4,097,705 / 291,367 |

Before each matched arm, `restore_sparse_store_seed` copied this seed into the
same `active-store` pathname, fsynced every file and directory transition,
validated it twice through the production reader, and required exact entry and
tree-hash equality. Thus neither arm inherited the other's merges.

## 3. Matched control/candidate mechanism result

Both arms used NATIVEPERF v5 and the exact per-process translation census. The
profiles independently counted main-thread `(pid, exec_epoch)` incarnations;
that number was supplied to `carrick debug xlat-census` rather than inferred
from the census file count. The two semantic overlays were identical except
that the control set `CARRICK_DSR_STORE_AUGMENTATION=0` and the candidate left
the default enabled.

| measure | control | candidate | candidate/control | gate |
|---|---:|---:|---:|---|
| independently observed incarnations | 140 | 140 | 1.000 | complete |
| parsed census files | 140 | 140 | 1.000 | complete |
| private translations | 766,674 | 337,199 | **0.4398** | <= 0.50 |
| `segment-repeat` translations | 762,462 | 332,984 | **0.4367** | <= 0.50 |
| blocks replayed from attached units | 450,224 | 879,455 | 1.9534 | diagnostic |
| successful merges | 0 | 42 | - | > 0 |
| blocks added | 0 | 91,558 | - | > 0 |
| summed publication time | 0 ms | 3,788 ms | - | diagnostic |

Both arms had coverage 1.0, zero flush imbalance, zero missing reexec
successors, zero sequence anomalies, and identical 69 self-reexec plus 71
terminal-exit lineage. Both had zero file misses and zero typed load refusals.
The candidate additionally had zero claim errors, conflicts, repairs, capacity
or preflight refusals, I/O failures, validation failures, and post-rename sync
failures. Six empty candidate releases were benign races which published no
unit and are distinct from an error or refusal.

The production reader decoded all 11 post-candidate bundles. Every key's block
count was nondecreasing; six keys grew and five were unchanged:

| unit stem prefix | before | after | added |
|---|---:|---:|---:|
| `0bab84ef47c1` | 5,376 | 10,923 | 5,547 |
| `1413d1ee025d` | 910 | 964 | 54 |
| `40f2955b1c40` | 6,593 | 16,294 | 9,701 |
| `430b1a3b6529` | 149 | 149 | 0 |
| `47a04aba8a47` | 8,296 | 84,179 | 75,883 |
| `5bfe8dc9213d` | 186 | 186 | 0 |
| `d0235c87b995` | 2,268 | 2,376 | 108 |
| `de44c847b03e` | 20,154 | 20,419 | 265 |
| `e8c808a27b9a` | 851 | 851 | 0 |
| `ef6033bbae7f` | 851 | 851 | 0 |
| `faf198f1739f` | 831 | 831 | 0 |

The total rose from 46,465 to 138,023 blocks. The 91,558 delta exactly equals
the runtime's reconciled `shared_unit_blocks_added` counter.

## 4. Exact post-merge replay

The newly augmented 11-unit tree had SHA-256
`bd71fa2b58026103f1395af167cb9044dfd221dc317df5db3dc10bb6a308a502`.
After production decoding, it was copied to a read-only seed and atomically
restored before a fresh canonical build. That successor completed with exact
`ok` and `BUILD_OK` output and 142/142 independently observed incarnations.
It replayed 1,199,191 blocks and needed only 22,427 private translations,
including 18,202 `segment-repeat` translations. This is the direct replay proof
that a later process can execute the newly merged coverage without changing
guest-visible semantics.

## 5. Receipt-bound ABBA rejects the candidate

These captures enabled high-volume NATIVEPERF and census instrumentation and
are causal evidence only. They are not retention timing. Their diagnostics are
also adverse: control/candidate child CPU was 22.706/24.192 seconds and the
in-guest workload window was 8.763/11.424 seconds. The candidate paid 3.788
seconds of summed publication work while building the augmented units. The
untraced ABBA authority confirmed that this was a product cost, not merely
instrumentation tax.

The same signed binary was prepared from clean source commit
`e626b117b1e8142a11e2a73733ffbd566da30c01`; its SHA-256 and Mach-O UUID were
unchanged from the mechanism receipt. One immutable arm receipt was used for
both overlays, as required by the harness's same-binary mode. The campaign ran
two excluded warmups followed by eight complete A1/B1/B2/A2 quads: 32 measured
samples, no overlap, and a two-second cooldown between positions.

| metric | control median | candidate median | candidate/control | paired 95% interval | candidate wins |
|---|---:|---:|---:|---:|---:|
| **child CPU seconds** | 23.7104 | 25.5479 | **1.0728** | **[1.0653, 1.0806]** | 0/8 |
| child user CPU seconds | 17.0524 | 19.3396 | 1.1307 | [1.1276, 1.1385] | 0/8 |
| child system CPU seconds | 6.6736 | 6.2083 | 0.9278 | [0.9004, 0.9338] | 8/8 |
| workload wall milliseconds | 9,012.25 | 11,547.00 | **1.2786** | **[1.2495, 1.2928]** | 0/8 |
| process elapsed milliseconds | 9,512.00 | 12,120.75 | 1.2724 | [1.2448, 1.2857] | 0/8 |

The user/system split explains the negative result: replay removed enough
translation and kernel work to improve system CPU by about 7.2%, but eager
bundle construction and publication increased user CPU by about 13.1%. Net
child CPU became 7.3% worse and wall time became 27.9% worse. Every primary
quad lost; the stored exact sign-test probability was 1.0, failing its `<0.05`
gate, and the complete two-sided CPU interval lies above 1.0.

The campaign artifact is structurally accepted and complete, but its retention
decision is `retained=false`. All 34 executions returned zero and reported
`BUILD_OK`. Before every warmup and measured sample the production reader
decoded and atomically restored the same
`db1225d3ac5c30d1067ef91749bd32415af97b025bb23a34b4f8bb63e51e3272`
seed tree at the same active path. All nine quiet-box preflights reported no
foreign Carrick process, Docker oracle, load exclusion, or thermal/performance
warning. The host was on AC power, retained as metadata only.

The design's earlier estimate of roughly 4.5 child CPU-seconds, or 18%, was a
projection from translation-time opportunity. The measurements here establish
a 56% reduction in private translation count and a measured 7.3% CPU
regression, not an 18% CPU improvement. No official cold-build ratio changes:
the prior 10.44x shipped-default result remains authoritative.

## 6. Reproduction and receipts

Each arm used the same command shape after restoring the immutable seed:

```bash
python3 scripts/perf/native_go_dtrace_target.py \
  --variant default \
  --store-dir target/perf/native-store-augmentation/mechanism/active-store \
  --store-augmentation off \
  --mechanism-profile \
  --xlat-census-dir target/perf/native-store-augmentation/mechanism/control-census \
  --run-id native-store-augment-control-v1

python3 scripts/perf/native_go_dtrace_target.py \
  --variant default \
  --store-dir target/perf/native-store-augmentation/mechanism/active-store \
  --store-augmentation on \
  --mechanism-profile \
  --xlat-census-dir target/perf/native-store-augmentation/mechanism/candidate-census \
  --run-id native-store-augment-candidate-v1
```

The production aggregator was then run with the independent profile count:

```bash
target/release/carrick debug xlat-census <arm>-census \
  --processes-observed "$(jq -r .processes.incarnations <arm>-profile.json)"
```

The untraced authority used one receipt path for both same-binary arms:

```bash
python3 scripts/perf/native_go_build_abba.py run \
  --harness-repo "$PWD" \
  --control-receipt target/perf/native-store-augmentation/arms/control/arm.json \
  --candidate-receipt target/perf/native-store-augmentation/arms/control/arm.json \
  --control-overlay scripts/perf/overlays/native-store-augment-control.json \
  --candidate-overlay scripts/perf/overlays/native-store-augment-candidate.json \
  --store-seed-dir target/perf/native-store-augmentation/mechanism/seed \
  --active-store-dir target/perf/native-store-augmentation/abba/active-store \
  --quads 8 \
  --output target/perf/native-store-augmentation/abba/campaign.json
```

The compact, machine-readable decision receipt is
`target/perf/native-store-augmentation/mechanism/mechanism-decision.json`,
SHA-256
`2a8e7d809e08da9f7a761865ec03a033f0851224367b5519414f913156e118d3`.
Important bound artifact hashes are:

| artifact | SHA-256 |
|---|---|
| seed creation sample | `c368e026d503450a6cb844c466c3c64df71e08fc5b1fc105493eaab46aa16ac2` |
| seed tree receipt | `4c8f76e29384495c3563609aebb0c074efa8f0d104bcb451df41afc336a94d8e` |
| seed production census | `e6b94062eb8c4552f9a72da777ded3f55ba2b40023a39d30ad7cff3a3dab6d40` |
| control profile / summary | `ed3a362776d4e62963280dd377ed1fc66a15a5f779bb5e5713eb587ad84a4cd8` / `6ef04f4f10f0de6e3cefc02b81f2809fc340b9f7920b4a91b6274096b4fb8169` |
| candidate profile / summary | `6d4822270ed4c4f4ea9930d81bdce88f84598990052ae0ac9c9bb6362fc38b2f` / `19a9d93484bc5429e22320bf78f8b216166fb6c6d1530e9c6e4099da144bac3b` |
| post-candidate production census | `2564d7242f281aa2dde0b5df5146fb40fd027ef98d92c7bd929f93c90016ed55` |
| post-candidate store receipt | `4f171af6fb363645288f2a03da55929dd1fbacaa790e27c2613bf53252187a3d` |
| replay profile / summary | `ac87a7dd9f3892b7c358171df02a4fdabac1f3b4e2abf26d7c8ebfa75d5c6a11` / `8ca45e2ef2848058eb7149e6115a4b4de67c1f59b3101d15d7ece7d92564f091` |
| accepted ABBA campaign | `683f0b473271eec9c041627da80a1b45639bac92c6ae317e48acc7dd266a3105` |

The final decision is therefore **reject**. Per the approved plan, no
same-binary regression screens, hatch-removal-for-retention gate, or official
Carrick/Docker ratio refresh was run: those steps cannot rescue a candidate
which already fails its primary workload. The runtime, crash-export companion,
temporary hatch, seed-restoration campaign controls, and candidate overlays
were restored to their pre-candidate state. The approved design and this
negative evidence remain durable so the 56% mechanism win is not mistaken for
an end-to-end opportunity again.

The rejection cleanup is `291359b4`. Every candidate-owned runtime and harness
path is byte-for-byte identical to pre-candidate commit `6f3f0024`. The
restored tree passed 219/219 AArch64 DSR tests, 61/61 native-Darwin tests, 87/87
performance/DTrace harness tests, and the complete `RUST_TEST_THREADS=1 just
ci` gate. No augmentation control remains under `crates/` or `scripts/`.

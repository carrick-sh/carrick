# Native Performance M1: Untraced Authority Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land a receipt-bound, fail-closed A1/B1/B2/A2 runner whose paired
total-CPU result is the sole performance retention authority for the native
campaign.

**Architecture:** Keep `native_go_build.py` as the one workload/sample
implementation, but make the executed Carrick binary explicit. Put the exact
paired mathematics and deterministic resampling stream in one Python module
and mirror it in Rust against a shared golden fixture. A new ABBA driver owns
immutable arm preparation, schedule, partial publication, host preflight, and
acceptance; it never accepts an unreceipted executable.

**Tech Stack:** Python 3 standard library, Rust/serde, Mach-O `dwarfdump`,
`codesign`, `otool`, Git, Carrick's signed Darwin/AArch64 binary.

**Design authority:** `docs/superpowers/specs/2026-07-30-native-performance-evidence-control-plane-design.md`
sections 2, 5, 8, and 10.

## Global Constraints

- Scope is Darwin/AArch64 `--exec-backend native`.
- The primary metric is `RUSAGE_CHILDREN` total CPU from
  `native_go_build.run_sample`; it remains explicitly described as a floor.
- The primary workload and OCI image remain the cold-`GOCACHE` Go 1.24
  compile-and-run in `scripts/perf/native_go_build.py`.
- Carrick and the native-arm64 Docker oracle never run concurrently.
- An official campaign is serial: excluded `A, B` warm-ups, then at least eight
  complete `A1, B1, B2, A2` quads, with two seconds after every sample.
- A sample executes `receipt.binary_path`; neither the arm source tree nor the
  harness tree may silently supply another binary.
- `harness_repo`, `receipt.source_repo`, and `receipt.binary_path` are three
  separate identities in code and artifacts.
- Same-binary mode changes only complete, scrubbed environment overlays.
  Two-binary mode changes only receipts and uses identical overlays.
- Optimization candidates are normal behavior; controls opt out with
  `CARRICK_DISABLE_<HYPOTHESIS>=1`.
- Every partial result is atomically published with `complete=false` and
  `accepted=false`; an official run cannot resume.
- No performance claim comes from DTrace or from this milestone's
  control/control proof.
- Never kill a foreign run. Cleanup is scoped to the current
  `CARRICK_RUN_ID` through `scripts/sudo/kill.sh`.
- Do not read Linux kernel or other GPL implementation source.

---

## Task 1: Create the shared deterministic paired-statistics contract

**Files:**

- Create: `scripts/perf/paired_stats.py`
- Create: `scripts/perf/fixtures/paired-stats-v1.json`
- Create: `scripts/perf/test_paired_stats.py`
- Modify: `scripts/perf/native_go_build_screen.py`
- Modify: `scripts/perf/test_native_go_build_screen.py`

**Interfaces:**

```python
BOOTSTRAP_DRAWS = 100_000
BOOTSTRAP_SEED = 0x4341525249434B31
MASK64 = (1 << 64) - 1
PRNG_ID = "splitmix64-v1"
SAMPLER_ID = "u64-rejection-mod-v1"
MEDIAN_RULE = "sorted-binary64-middle-or-middle-mean-v1"
QUANTILE_RULE = "nearest-rank-v1"


@dataclasses.dataclass(frozen=True)
class BootstrapResult:
    prng_id: str
    sampler_id: str
    seed_hex: str
    draws: int
    median_rule: str
    quantile_rule: str
    two_sided_lower: float
    two_sided_upper: float
    one_sided_upper: float
    accepted_indices: int
    rejected_outputs: int
    first_indices: tuple[int, ...]
```

Required call signatures are
`splitmix64(state: int) -> tuple[int, int]`,
`rejection_index(state: int, population: int) -> tuple[int, int, int]`,
`median_binary64(values: Sequence[float]) -> float`,
`nearest_rank(values: Sequence[float], probability: float) -> float`,
`paired_bootstrap(ratios: Sequence[float], *, draws: int = 100_000,
seed: int = 0x4341525249434B31) -> BootstrapResult`,
`exact_one_sided_sign_probability(wins: int, trials: int) -> Fraction`, and
`exact_probability_json(value: Fraction) -> dict[str, int | float]`, and
`ratio_resolution(ratios: Sequence[float]) -> dict[str, float | int | str]`.

- [ ] **Step 1: Add red fixtures for every mathematical decision**

In `test_paired_stats.py`, assert:

```python
def test_splitmix64_contract_prefix(self):
    state = paired_stats.BOOTSTRAP_SEED
    actual = []
    for _ in range(8):
        state, value = paired_stats.splitmix64(state)
        actual.append(f"0x{value:016x}")
    self.assertEqual(actual, self.fixture["splitmix64_prefix"])

def test_golden_bootstrap_bits(self):
    result = paired_stats.paired_bootstrap(self.fixture["ratios"])
    self.assertEqual(result.first_indices, tuple(self.fixture["first_indices"]))
    self.assertEqual(
        [
            struct.pack(">d", value).hex()
            for value in (
                result.two_sided_lower,
                result.two_sided_upper,
                result.one_sided_upper,
            )
        ],
        self.fixture["bound_binary64_be"],
    )

def test_sign_test_removes_ties(self):
    self.assertEqual(
        paired_stats.exact_one_sided_sign_probability(7, 8),
        fractions.Fraction(9, 256),
    )

def test_resolution_preserves_controller_formula(self):
    result = paired_stats.ratio_resolution([0.91, 0.93, 0.94, 0.96])
    expected = 1.6448536269514722 * statistics.stdev(
        [0.91, 0.93, 0.94, 0.96]
    ) / math.sqrt(4)
    self.assertEqual(result["formula"], "normal-one-sided-ratio-sd-v1")
    self.assertEqual(result["resolution_fraction"], expected)
    self.assertEqual(result["smallest_resolvable_improvement_ratio"], 1 - expected)
```

Also cover empty populations, zero population size, even/odd medians,
nearest-rank endpoints, invalid probabilities, a seed outside unsigned 64-bit
range, and sign tests with `wins > trials` or `trials > 127`.

- [ ] **Step 2: Run the new test and prove red**

```bash
python3 -m unittest scripts/perf/test_paired_stats.py -v
```

Expected: import failure because `paired_stats.py` does not exist.

- [ ] **Step 3: Implement the exact SplitMix64 and unbiased index stream**

Use:

```python
def splitmix64(state: int) -> tuple[int, int]:
    state = (state + 0x9E3779B97F4A7C15) & MASK64
    value = state
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK64
    return state, (value ^ (value >> 31)) & MASK64


def rejection_index(state: int, population: int) -> tuple[int, int, int]:
    if population <= 0:
        raise ValueError("population must be positive")
    modulus = 1 << 64
    limit = modulus - modulus % population
    rejected = 0
    while True:
        state, value = splitmix64(state)
        if value < limit:
            return state, value % population, rejected
        rejected += 1
```

Keep one state across all 100,000 replicates. Each replicate consumes exactly
`n` accepted indices and takes the binary64 median of the sampled raw quad
ratios. Store the first 32 accepted indices in the golden fixture.

- [ ] **Step 4: Implement exact probability, quantiles, and resolution**

Use integer binomial arithmetic:

```python
def exact_one_sided_sign_probability(wins: int, trials: int) -> Fraction:
    if trials < 0 or wins < 0 or wins > trials:
        raise ValueError("sign-test counts are invalid")
    numerator = sum(math.comb(trials, k) for k in range(wins, trials + 1))
    return Fraction(numerator, 1 << trials)
```

Nearest rank is
`max(1, math.ceil(probability * len(sorted_values))) - 1`. Resolution uses
Bessel-corrected `statistics.stdev`, `z95=1.6448536269514722`, and the exact
field names in section 5.5 of the design. Do not round decision fields.

`BootstrapResult` carries the six algorithm-identity fields shown in the
interface. Its JSON object preserves those fields plus accepted/rejected
counts and the three binary64 bounds. Serialize an exact sign probability as:

```python
def exact_probability_json(value: Fraction) -> dict[str, int | float]:
    return {
        "numerator": value.numerator,
        "denominator": value.denominator,
        "probability": float(value),
    }
```

The rational fields are the authority; `probability` is a display/convenience
binary64 value. Reject `trials > 127` in both languages so the declared Rust
`u128` representation and Python artifact contract have identical bounds.

- [ ] **Step 5: Generate and freeze the cross-language fixture**

The fixture schema is `carrick.paired-stats-fixture.v1` and contains:

```json
{
  "schema": "carrick.paired-stats-fixture.v1",
  "seed": "0x4341525249434b31",
  "draws": 100000,
  "ratios": [0.91, 0.93, 0.94, 0.96, 0.98, 1.01, 1.02, 1.04],
  "splitmix64_prefix": [],
  "first_indices": [],
  "bound_binary64_be": []
}
```

Populate the three arrays once from the reviewed implementation. The tests
must then treat them as constants and compare bit encodings, not formatted
decimal strings.

- [ ] **Step 6: Make the old screen a compatibility consumer**

Remove its private PRNG/bootstrap code. Keep its public
`bootstrap_ratio(control, candidate, draws=100_000,
seed=0x4341525249434B31)` wrapper, but make it
construct paired ratios and call `paired_stats.paired_bootstrap`. Update its
tests to expect the new fixed seed and paired semantics.

- [ ] **Step 7: Run focused tests and commit**

```bash
python3 -m unittest \
  scripts/perf/test_paired_stats.py \
  scripts/perf/test_native_go_build_screen.py -v
git diff --check
git add scripts/perf/paired_stats.py \
  scripts/perf/fixtures/paired-stats-v1.json \
  scripts/perf/test_paired_stats.py \
  scripts/perf/native_go_build_screen.py \
  scripts/perf/test_native_go_build_screen.py
git commit -m "feat(perf): centralize paired performance statistics" -m \
"Make whole-quad paired resampling deterministic and shared by native
performance tools. Preserve the legacy screen as a compatibility consumer and
freeze exact index and binary64 outputs for independent implementations.

Verified with the paired-statistics and native screen unit suites.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 2: Mirror the paired-statistics stream in Rust

**Files:**

- Modify: `crates/carrick-cli/src/perf_stats.rs`
- Read fixture: `scripts/perf/fixtures/paired-stats-v1.json`

**Interfaces:**

```rust
pub const PAIRED_BOOTSTRAP_DRAWS: usize = 100_000;
pub const PAIRED_BOOTSTRAP_SEED: u64 = 0x4341_5252_4943_4b31;

#[derive(Debug, Clone, PartialEq)]
pub struct PairedBootstrap {
    pub two_sided_lower: f64,
    pub two_sided_upper: f64,
    pub one_sided_upper: f64,
    pub accepted_indices: u64,
    pub rejected_outputs: u64,
    pub first_indices: Vec<usize>,
}

pub fn paired_bootstrap(ratios: &[f64]) -> Result<PairedBootstrap>;
pub fn exact_one_sided_sign_probability(wins: u32, trials: u32) -> Result<(u128, u128)>;
```

- [ ] **Step 1: Add a red Rust golden test**

Deserialize the checked-in fixture with
`include_str!("../../../scripts/perf/fixtures/paired-stats-v1.json")`. Compare
the first indices and each confidence bound with `f64::to_bits()`. Add invalid
input tests and the `7/8 = 9/256` sign-test case.

- [ ] **Step 2: Run and prove red**

```bash
cargo test -p carrick-cli perf_stats::tests::paired -- --nocapture
```

Expected: compile failure because the paired API is absent.

- [ ] **Step 3: Implement wrapping SplitMix64 and `u128` rejection**

Use:

```rust
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn rejection_index(state: &mut u64, population: usize) -> Result<(usize, u64)> {
    anyhow::ensure!(population > 0, "population must be positive");
    let modulus = 1_u128 << 64;
    let limit = modulus - modulus % population as u128;
    let mut rejected = 0_u64;
    loop {
        let value = splitmix64(state);
        if (value as u128) < limit {
            return Ok(((value as usize) % population, rejected));
        }
        rejected = rejected.checked_add(1).context("rejection count overflow")?;
    }
}
```

Use checked counters and the same median/nearest-rank rules as Python. Keep the
existing independent-arm `bootstrap_median_ratio` API only for old artifact
readers; no new gate may call it. Reject `trials > 127` before shifting the
`u128` denominator.

- [ ] **Step 4: Run the cross-language gates and commit**

```bash
cargo test -p carrick-cli perf_stats::tests -- --nocapture
python3 -m unittest scripts/perf/test_paired_stats.py -v
just fmt
git diff --check
git add crates/carrick-cli/src/perf_stats.rs
git commit -m "test(perf): lock Rust and Python paired statistics" -m \
"Give the Rust evidence path the same SplitMix64 stream, rejection sampler,
whole-quad median bootstrap, and exact sign-test semantics as Python. Validate
the implementations against one checked-in bit-exact fixture.

Verified with focused Rust and Python paired-statistics tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 3: Make the sampled executable and rewritten-proctitle census explicit

**Files:**

- Modify: `scripts/perf/native_go_build.py`
- Modify: `scripts/perf/test_native_go_build.py`

**Interface:** Preserve the positional arguments and expose
`run_sample(harness_repo: pathlib.Path, engine: str, index: int,
timeout_seconds: int, captured_output: pathlib.Path | None = None,
environment_overlay: dict[str, str | None] | None = None, *,
binary: pathlib.Path | None = None, image: str = DEFAULT_IMAGE,
current_run_id: str | None = None,
known_receipt_binaries: tuple[pathlib.Path, ...] = ()) -> dict[str, object]`.

- [ ] **Step 1: Add red executable-identity tests**

Assert that an explicit `/immutable/A/carrick` appears in the executed command,
pre-provenance, post-provenance, and returned sample; patch the default
`target/release/carrick` to fail if opened. Assert that an image override flows
through command and provenance. Assert compatibility callers with no explicit
binary still use the harness target.

- [ ] **Step 2: Add red proctitle fixtures**

Use exact rows:

```python
rows = [
    (101, "carrick:native-go-build-carrick-old-1:go"),
    (102, "/tmp/carrick:native-go-build-carrick-old-2:compile"),
    (103, "carrick:run-c1: go"),
    (104, "carrick:run-c10: go"),
]
```

The first two and `run-c10` must be foreign when the current run is `run-c1`;
only the exact literal `carrick:run-c1:` is excluded. This matches
`scripts/sudo/kill.sh`'s `needle="carrick:$run_id:"` authority, including its
trailing-colon protection against prefix collisions. Add a copied receipt
binary such as `/var/tmp/native-m1/arm/carrick run ...` and require the census
to recognize it from the supplied receipt-binary set before its proctitle is
rewritten.

- [ ] **Step 3: Run both suites and prove red**

```bash
python3 -m unittest scripts/perf/test_native_go_build.py -v
```

- [ ] **Step 4: Thread explicit identity through the sample**

Call:

```python
run_id = current_run_id or generated_run_id
command = build_command(harness_repo, engine, run_id, binary=binary, image=image)
pre_provenance = sample_provenance(
    harness_repo,
    engine,
    normalized,
    binary_path=binary,
    image_ref=image,
    current_run_id=run_id,
    known_receipt_binaries=known_receipt_binaries,
)
```

Repeat the same arguments after cleanup. Strict git cleanliness applies to
`harness_repo` here; receipt source cleanliness is validated by the ABBA layer.
Include the resolved binary path and SHA-256 in every sample.

- [ ] **Step 5: Match the kill script's exact proctitle authority**

Change the census command to
`ps -axww -o pid= -o command=`. Recognize the known Carrick/performance
executable paths, every resolved receipt binary supplied by the ABBA runner,
plus any command containing an exact literal
`carrick:<nonempty-run-id>:` title. The title may appear after a path prefix;
this deliberately matches `kill.sh`'s substring authority rather than adding
a conflicting whitespace rule. Exclude current ancestry and the exact literal
`carrick:<current_run_id>:` only. Do not treat an arbitrary substring
containing the word `carrick` as authority and do not exclude prefix-related
IDs.
`scripts/sudo/kill.sh` remains unchanged and continues to perform the actual
scoped reap.

- [ ] **Step 6: Run focused tests and commit**

```bash
python3 -m unittest scripts/perf/test_native_go_build.py -v
git diff --check
git add scripts/perf/native_go_build.py \
  scripts/perf/test_native_go_build.py
git commit -m "fix(perf): bind samples to an explicit Carrick binary" -m \
"Prevent historical or same-binary campaigns from falling back to the
harness worktree executable. Use one delimited run-ID grammar for performance
preflight and scoped cleanup, including Carrick's rewritten process titles.

Verified with workload identity, provenance, census, and kill-list fixtures.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 4: Prepare immutable, verified arm receipts

**Files:**

- Create: `scripts/perf/native_go_build_abba.py`
- Create: `scripts/perf/test_native_go_build_abba.py`

**Interfaces:**

```python
ARM_SCHEMA = "carrick.native-perf-arm.v1"
CAMPAIGN_SCHEMA = "carrick.native-go-build-abba.v1"


@dataclasses.dataclass(frozen=True)
class ArmReceipt:
    path: pathlib.Path
    label: str
    role: str
    source_repo: pathlib.Path
    source_commit: str
    source_branch: str | None
    source_detached: bool
    binary_path: pathlib.Path
    binary_size: int
    binary_mode: int
    binary_sha256: str
    macho_uuid: str
    entitlement_sha256: str
    image_ref: str
    image_id: str
    image_repo_digests: tuple[str, ...]
```

Required call signatures are
`prepare_arm(source_repo: pathlib.Path, destination: pathlib.Path, *,
label: str, role: str, image_ref: str) -> dict[str, object]` and
`load_and_verify_arm(path: pathlib.Path) -> ArmReceipt`.

- [ ] **Step 1: Add red receipt-validation tests**

Use temporary fake command results to cover:

- dirty source before or after build;
- role other than `control`/`candidate`;
- failed `just build`;
- missing copied binary;
- changed size, mode, SHA-256, Mach-O UUID, signature, entitlement, or DOF;
- wrong host architecture or non-arm64 image;
- changed image ID/repo digests;
- empty image repo digests or an unknown receipt field;
- exact named-branch and detached-HEAD encodings;
- destination collision, including a dangling symlink; and
- atomic publication leaving no temporary neighbor.

- [ ] **Step 2: Run and prove red**

```bash
python3 -m unittest scripts/perf/test_native_go_build_abba.py -v
```

- [ ] **Step 3: Implement `prepare-arm`**

The command:

```text
native_go_build_abba.py prepare-arm
  --source-repo /tmp/carrick-native-campaign/control
  --destination /tmp/carrick-native-campaign/arms/control
  --label control
  --role control
  --image localhost:5005/carrick-go-conformance:1.24
```

runs `just build`, rechecks `git status --porcelain`, copies
`target/release/carrick` with `shutil.copy2`, removes write bits from the copy,
then records:

```python
branch = git_output(source_repo, "branch", "--show-current")
receipt = {
    "schema": ARM_SCHEMA,
    "label": label,
    "role": role,
    "source_repo": str(source_repo.resolve()),
    "source_commit": git_output(source_repo, "rev-parse", "HEAD"),
    "source_branch": branch or None,
    "source_detached": not bool(branch),
    "source_status": [],
    "binary_path": str(copied.resolve()),
    "binary_size": copied.stat().st_size,
    "binary_mode": stat.S_IMODE(copied.stat().st_mode),
    "binary_sha256": sha256_file(copied),
    "macho_uuid": macho_uuid(copied),
    "codesign_verified": True,
    "entitlement_sha256": entitlement_digest(copied),
    "has_dof_carrick": has_dof_carrick(copied),
    "rust_toolchain": rustc_version(source_repo),
    "build": build_receipt,
    "host": host_receipt(),
    "image_ref": image_ref,
    "image": native_go_build.docker_image_provenance(image_ref),
}
```

Use `codesign --verify --strict`, `codesign -d --entitlements :-`,
`dwarfdump --uuid`, and `otool -l`. Hash normalized entitlement bytes. Record
build start/end UTC timestamps and return status. Require a nonempty immutable
repo-digest set for the OCI image. Reserve a previously absent destination with
an exclusive `mkdir`, populate the copied binary, then create `arm.json` with
`os.open(..., os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)`, `flush`,
`os.fsync`, and directory `fsync`. The presence of `arm.json` is the publication
point; never use `os.replace` for a receipt that must not be overwritten.

- [ ] **Step 4: Implement re-verification**

`load_and_verify_arm` rejects every unknown field, requires exactly one of a
nonempty `source_branch` or `source_detached=true`, requires nonempty immutable
image repo digests, resolves no symlinks after receipt creation, and repeats
file metadata, SHA, UUID,
signature, entitlement, DOF, host, and image checks. It never rebuilds or
mutates the receipt directory.

- [ ] **Step 5: Run focused tests and commit**

```bash
python3 -m unittest scripts/perf/test_native_go_build_abba.py -v
git diff --check
git add scripts/perf/native_go_build_abba.py \
  scripts/perf/test_native_go_build_abba.py
git commit -m "feat(perf): prepare immutable native benchmark arms" -m \
"Make every official native-performance arm a clean-source, signed,
DOF-bearing, immutable binary receipt with exact image and build provenance.
Reject identity drift before a workload can run.

Verified with receipt creation, collision, atomicity, and tamper fixtures.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 5: Execute fail-closed ABBA campaigns

**Files:**

- Modify: `scripts/perf/native_go_build_abba.py`
- Modify: `scripts/perf/test_native_go_build_abba.py`
- Modify: `scripts/perf/native_go_build.py`
- Modify: `scripts/perf/test_native_go_build.py`
- Create: `scripts/perf/overlays/native-default.json`
- Create: `scripts/perf/overlays/native-shared.json`

**Interfaces:**

```python
@dataclasses.dataclass(frozen=True)
class ArmSpec:
    label: str
    receipt: ArmReceipt
    environment: tuple[tuple[str, str | None], ...]


@dataclasses.dataclass(frozen=True)
class Quad:
    index: int
    a1: dict[str, object]
    b1: dict[str, object]
    b2: dict[str, object]
    a2: dict[str, object]
```

Required call signatures are
`validate_arm_mode(control: ArmSpec, candidate: ArmSpec) -> str`,
`summarize_quads(quads: Sequence[Quad]) -> dict[str, object]`, and
`run_campaign(harness_repo: pathlib.Path, control: ArmSpec,
candidate: ArmSpec, output: pathlib.Path, *, quads: int = 8,
cooldown_seconds: float = 2.0, timeout_seconds: int = 900,
image_ref: str = native_go_build.DEFAULT_IMAGE) -> dict[str, object]`, and
`publish_accepted_artifact(source: pathlib.Path,
destination: pathlib.Path) -> dict[str, object]`.

- [ ] **Step 1: Add red schedule and arm-mode tests**

Assert exact calls:

```python
self.assertEqual(
    [(row["phase"], row["arm"]) for row in calls],
    [
        ("warmup", "A"), ("warmup", "B"),
        ("quad-1-a1", "A"), ("quad-1-b1", "B"),
        ("quad-1-b2", "B"), ("quad-1-a2", "A"),
    ],
)
```

Require at least eight official quads. Same-binary mode requires the same
resolved receipt path and equal SHA/UUID/image identity. Its complete overlays
may be equal for a null control/control proof or may differ for one declared
variant. Two-binary mode requires distinct receipt identities and
byte-for-byte equal overlays. Reject both dimensions changing, `candidate`
legacy variant use, unknown ambient `CARRICK_*`, and an opt-out key absent from
`PERFORMANCE_CONTROL_KEYS`.

- [ ] **Step 2: Add red quad-statistics tests**

For each of `cpu_s`, `cpu_user_s`, `cpu_sys_s`, `elapsed_ms`, and
`workload_ms`, assert:

```python
aq = (a1 + a2) / 2
bq = (b1 + b2) / 2
ratio = bq / aq
```

Ties remain in descriptive rows and are removed from sign-test trials. Require
the exact sign probability, paired bootstrap fields, arithmetic ratio SD, log
ratio SD, resolution fields, candidate win count, arm medians, and raw sample
membership. Total CPU is the primary decision.

- [ ] **Step 3: Add red failure-publication tests**

Inject failures after every position. Assert the artifact includes all
completed samples, has `complete=false`, `accepted=false`, one exact failure
reason, and cannot be passed to a `--resume` option. Publish that initial
partial artifact before the first preflight, so even a preflight failure leaves
durable evidence. After a sample has launched, include the current
`SampleEvidenceError.sample`; preflight failures explicitly store
`failure.sample=null`. Convert `subprocess.TimeoutExpired` into
`SampleEvidenceError` with run ID, command, elapsed/CPU deltas, captured
stdout/stderr, provenance, and cleanup evidence rather than re-raising the raw
exception. Cover receipt drift before a quad, marker failure, timeout, cleanup
failure, busy-host rejection, battery power,
thermal/power warning, high load, active compiler/spin, Docker oracle, foreign
rewritten proctitle, and pre/post provenance drift.

Test `publish_accepted_artifact` separately: it rejects incomplete or
unaccepted sources, source drift between verification and copy, destination
collision, truncated temp files, and a parent-directory sync failure. It
creates a same-directory random temp with `O_CREAT|O_EXCL`, copies and
`fsync`s the complete bytes, rehashes the temp, atomically hard-links it to the
absent destination, `fsync`s the parent, and unlinks the temp. It never uses
overwrite-capable rename/copy as the publication point.

- [ ] **Step 4: Run and prove red**

```bash
python3 -m unittest \
  scripts/perf/test_native_go_build_abba.py \
  scripts/perf/test_native_go_build.py -v
```

- [ ] **Step 5: Implement arm mode and controlled overlays**

Expose semantic `default` and `shared` overlays from `native_go_build.py`.
Do not use `VARIANT_CANDIDATE` for legacy sharing comparisons. For a new spike,
require a key matching `CARRICK_DISABLE_[A-Z0-9_]+`, present with value `1` only
in control and absent in candidate, and present in
`PERFORMANCE_CONTROL_KEYS`.

Check in complete JSON overlays whose key sets exactly equal
`PERFORMANCE_CONTROL_KEYS`. `native-default.json` nulls every key.
`native-shared.json` is identical except
`CARRICK_DSR_SHARED_TRANSLATION="1"` and
`CARRICK_DSR_DIRECT_BINDINGS="1"`; it explicitly keeps
`CARRICK_DSR_ARTIFACT_SPIKE=null`. Tests reject drift between these files and
the Python control-key tuple.

- [ ] **Step 6: Implement campaign execution and partial publication**

Before the campaign and before every quad, verify both receipts and image
identity, run the full contamination/power preflight, and reject any foreign
row. Resolve the complete binary set once as:

```python
known_receipt_binaries = tuple(
    sorted({
        control.receipt.binary_path.resolve(),
        candidate.receipt.binary_path.resolve(),
    })
)
```

Pass that same set to the campaign-level preflight, every provenance census,
and every sample, regardless of which arm is currently executing. This keeps a
stale pre-proctitle process from the other receipt visible. Execute excluded
warm-ups then quads serially. Invoke:

The Darwin power preflight runs `pmset -g batt` and requires
`Now drawing from 'AC Power'`. It runs `pmset -g therm` and requires
either the three explicit `No thermal warning`, `No performance warning`, and
`No CPU power status` lines or numeric
`CPU_Speed_Limit = 100`, `Scheduler_Limit = 100`, and
`CPU_Available = 1`. Any other reported limit/warning or unrecognized output
fails closed. The load, compiler/spin, Docker, and full-`ps -axww` checks
remain the other independent rejection reasons.

```python
native_go_build.run_sample(
    harness_repo,
    native_go_build.ENGINE_CARRICK,
    sample_index,
    timeout_seconds,
    environment_overlay=dict(arm.environment),
    binary=arm.receipt.binary_path,
    image=image_ref,
    current_run_id=sample_run_id,
    known_receipt_binaries=known_receipt_binaries,
)
```

Sleep only after cleanup and publication. The official artifact records
`cooldown_seconds=2.0`; a changed value becomes part of the campaign identity.
Atomically rewrite the partial artifact after every sample. There is no resume
subcommand.

- [ ] **Step 7: Separate accepted evidence from statistical eligibility**

Set `accepted=true` when the campaign is complete, all receipts/provenance and
sample invariants reconcile, and the statistical object is valid. Compute a
separate `decision.statistical_pass` field. It is true only when:

1. the artifact is complete and has at least eight quads;
2. total-CPU median quad ratio is below `1.0`;
3. total-CPU one-sided 95% upper bound is below `1.0`;
4. total-CPU one-sided sign-test probability is below `0.05`; and
5. no secondary metric has two-sided 95% lower bound above `1.0`.

The ABBA artifact always stores `decision.retained=false` because mechanism and
focused/end-to-end correctness authority live outside this runner. Store
`mechanism.status=external_gate_required` and
`correctness.status=external_gate_required`. A later hypothesis-retention
command may set a separate ledger row to `RETAIN` only when both receipts are
accepted and `statistical_pass=true`. Control/control must finish as accepted
evidence with `statistical_pass=false`, `retained=false`, and the reason
`total CPU statistical gates did not establish an improvement`.

- [ ] **Step 8: Run tests and commit**

```bash
python3 -m unittest \
  scripts/perf/test_native_go_build.py \
  scripts/perf/test_paired_stats.py \
  scripts/perf/test_native_go_build_abba.py \
  scripts/perf/test_native_go_build_screen.py -v
git diff --check
git add scripts/perf/native_go_build.py \
  scripts/perf/test_native_go_build.py \
  scripts/perf/native_go_build_abba.py \
  scripts/perf/test_native_go_build_abba.py \
  scripts/perf/overlays/native-default.json \
  scripts/perf/overlays/native-shared.json
git commit -m "feat(perf): make ABBA CPU the native retention authority" -m \
"Run immutable Carrick arms in excluded-warmup A1/B1/B2/A2 quads, publish
every partial result atomically, and fail closed on provenance, host-state, or
sample drift. Report paired CPU statistics without treating a control/control
run or traced timing as a win.

Verified with schedule, statistics, contamination, and failure-injection tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 6: Live-prove the authority without claiming a speedup

**Files:**

- Create: `scripts/perf/evidence/native-go-build-abba-control-control-v1.json`
- Modify: `scripts/perf/README.md`
- Modify: `docs/perf-results/2026-07-29-native-cpu-budget-evidence.md`
- Modify: `handoff.md`

- [ ] **Step 1: Run the complete static/focused gate**

```bash
just fmt-check
python3 -m unittest \
  scripts/perf/test_native_go_build.py \
  scripts/perf/test_paired_stats.py \
  scripts/perf/test_native_go_build_abba.py \
  scripts/perf/test_native_go_build_screen.py -v
cargo test -p carrick-cli perf_stats::tests -- --nocapture
```

- [ ] **Step 2: Build one signed arm and verify it**

From a clean worktree:

```bash
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo "$PWD" \
  --destination target/perf/native-m1-control \
  --label control-control \
  --role control \
  --image localhost:5005/carrick-go-conformance:1.24
```

Use the emitted receipt and the identical complete default overlay for both
arms. This is the allowed null form of same-binary mode. Do not add an inert
runtime switch merely to manufacture an environment difference.

- [ ] **Step 3: Run eight complete control/control quads**

```bash
python3 scripts/perf/native_go_build_abba.py run \
  --harness-repo "$PWD" \
  --control-receipt target/perf/native-m1-control/arm.json \
  --candidate-receipt target/perf/native-m1-control/arm.json \
  --control-overlay scripts/perf/overlays/native-default.json \
  --candidate-overlay scripts/perf/overlays/native-default.json \
  --quads 8 \
  --cooldown-seconds 2 \
  --output target/perf/native-go-build-abba-control-control-v1.json
```

Require `complete=true`, every receipt/sample hash equal, 34 total executions
(two excluded warm-ups plus 32 measured samples), `accepted=true`, and
`decision.statistical_pass=false` plus `decision.retained=false`.

- [ ] **Step 4: Run correctness and repository gates**

```bash
scripts/build-signed.sh
CARRICK_RUN_ID=native-m1-go-live \
  target/release/carrick run --exec-backend native \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c 'set -eu; cd /tmp; printf "package main\nfunc main(){println(\"ok\")}\n" > h.go; GOCACHE=/tmp/carrick-m1-gocache /usr/local/go/bin/go build -o h h.go; ./h; echo BUILD_OK'
scripts/sudo/kill.sh native-m1-go-live
just conformance-native smoke --workers 4
just ci
```

Do not run the Docker oracle concurrently with any Carrick command.

- [ ] **Step 5: Record the evidence and commit**

Document that the live run validates the instrument and estimates its floor;
it is not an optimization result and does not update `H0`. Record artifact
SHA-256, binary SHA-256, commit, host/OS build, quad count, primary ratio and
bounds, and all gate commands.

Only after every live gate finishes, publish the verified immutable artifact
out of ignored scratch through the Task 5 exclusive helper:

```bash
python3 scripts/perf/native_go_build_abba.py publish \
  --source target/perf/native-go-build-abba-control-control-v1.json \
  --destination scripts/perf/evidence/native-go-build-abba-control-control-v1.json
```

Keeping partial output under `target/perf` prevents the runner's own atomic
publication from dirtying `harness_repo` between samples.

```bash
git add scripts/perf/evidence/native-go-build-abba-control-control-v1.json \
  scripts/perf/README.md \
  docs/perf-results/2026-07-29-native-cpu-budget-evidence.md \
  handoff.md
git commit -m "diagnostics(perf): accept the native ABBA authority" -m \
"Live-prove immutable receipt execution, rewritten-proctitle preflight,
partial publication, and eight complete A1/B1/B2/A2 quads on the cold Go
workload. Record the control/control result strictly as instrument evidence.

Verified with the signed Go workload, native smoke, focused statistics tests,
and `just ci`.

Co-Authored-By: Codex <codex@openai.com>"
```

## M1 Completion Gate

M1 is complete only when:

- the Python/Rust golden fixture is bit-exact;
- official samples always execute a verified receipt binary;
- stale rewritten Carrick proctitles fail preflight;
- a corrupted or partial campaign cannot become accepted;
- the live control/control artifact contains eight complete quads and no false
  win;
- native smoke and `just ci` pass; and
- `handoff.md` points to the accepted evidence.

M1 does not authorize M2/M3 evidence claims or any runtime optimization.

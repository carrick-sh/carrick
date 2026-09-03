# Kernel Architecture and Public CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Carrick's active documentation describe the carrier kernel
architecture and split public hosted validation from trusted hardware guest
execution in GitHub Actions.

**Architecture:** Public pull requests use only GitHub-hosted compile, lint,
ABI, host-semantic, and feature-closure jobs. A separate trusted-event workflow
targets capability-labeled self-hosted Apple Silicon/HVF and Linux/KVM runners,
fails closed on missing hardware prerequisites, and distinguishes focused
runtime proof from the complete 2,127-suite closure gate.

**Tech Stack:** GitHub Actions YAML, Rust/Cargo `just` recipes, Markdown.

**Spec:**
[`docs/superpowers/specs/2026-08-28-kernel-architecture-and-public-ci-design.md`](../specs/2026-08-28-kernel-architecture-and-public-ci-design.md)

## Global Constraints

- Do not run project code: no Actions invocation, `just`, Cargo, tests,
  codesigning, Docker, guest execution, YAML execution, or formatting tools.
- Use read-only/static inspection only: `rg`, `sed`, `git diff`,
  `git diff --check`, and `git status`.
- Every commit in this plan must use `git commit --no-verify` so the repository's
  formatting hook does not violate the no-execution constraint.
- Do not edit Rust source, `justfile`, baselines, Docker oracle caches, the
  generated support matrix, `handoff.md`, or `hybrid.md`.
- Do not claim that hosted CI executes a guest, that a smoke/probe job closes
  the 2,127-suite denominator, or that any workflow added here has run.
- Preserve the current macOS/Apple Silicon/HVF/HVPatch lane as the reference
  runtime. Describe KVM, bhyve, and NVMM as active bring-up lanes unless current
  evidence explicitly says otherwise.
- Self-hosted runner jobs must have no `pull_request` or
  `pull_request_target` path.
- Hardware capability variables enable scheduling only; each enabled job must
  verify the capability it claims to use.

---

## File Structure

- Modify `.github/workflows/ci.yml`: hosted-only required validation.
- Create `.github/workflows/kernel-runtime.yml`: trusted hardware guest
  execution.
- Modify `README.md`: current kernel model, CI proof matrix, corrected lifecycle
  and scheduler prose.
- Replace `docs/architecture-overview.md`: current carrier/HVPatch deep dive.
- Modify `crates/README.md`: kernel, HAL, and VMM ownership map.
- Modify `crates/carrick-embed/README.md`: carrier and hardware requirements.
- Modify `crates/carrick-conformance-next/README.md`: in-process naming and
  cached-oracle/HVF boundary.
- Modify `docs/README.md`: architecture and CI navigation.
- Modify `docs/conformance-testing.md`: hosted-versus-hardware evidence and
  non-authoritative skip semantics.

---

### Task 1: Make the Existing CI Workflow Hosted-Only

**Files:**

- Modify: `.github/workflows/ci.yml:1-310`

**Interfaces:**

- Consumes: existing `just fmt-check`, `just clippy`, `just lint-domains`,
  `just deny`, `just check-matrix`, `just check`, `just check-fuzz`, `just doc`,
  `just test`, `just test-integration`, `just check-linux`,
  `just check-freebsd`, and `just check-netbsd` recipes.
- Produces: a pull-request-safe workflow containing only GitHub-hosted jobs and
  no guest-execution claim.

- [ ] **Step 1: Rename the workflow and correct its schedule comment**

Change the header to:

```yaml
name: Hosted CI

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:
  # Nightly catches moving @stable toolchain and hosted runner-image drift.
  schedule:
    - cron: "0 7 * * *"
```

Keep the existing `concurrency` and environment values.

- [ ] **Step 2: Rename the macOS job around its real proof surface**

Keep job id `check`, but replace its leading comment and display name with:

```yaml
  # Source, ABI, kernel-graph, and host-semantic validation on public hosted
  # Apple Silicon. These steps never launch a guest vCPU; they do not prove
  # HVPatch runtime or Linux behavioral conformance.
  check:
    name: hosted macOS · source + host-only tests
    runs-on: macos-14 # Apple Silicon
```

Do not change the existing commands or `RLIMIT_NOFILE` setup in this job.

- [ ] **Step 3: Remove all self-hosted jobs from `ci.yml`**

Delete the complete `kvm-smoke` job and its preceding R1 comment. Delete the
complete `hvf-conformance` job and its preceding comment. Replace the old
hosted-runner note above `cross-check-linux` with:

```yaml
  # Hosted runners intentionally stop at source, host-semantic, and target
  # closure evidence. Real guest execution lives in kernel-runtime.yml on
  # trusted, capability-labeled hardware; a skipped or unsupported nested-virt
  # attempt is never represented as a kernel pass here.
```

Leave `cross-check-linux`, `cross-check-freebsd`, `cross-check-netbsd`, and
`deny` otherwise unchanged.

- [ ] **Step 4: Perform static workflow review**

Run only these read-only checks:

```bash
rg -n "self-hosted|kvm-smoke|hvf-conformance|guest vCPU" .github/workflows/ci.yml
sed -n '1,340p' .github/workflows/ci.yml
git diff --check -- .github/workflows/ci.yml
```

Expected: no `self-hosted`, `kvm-smoke`, or `hvf-conformance`; the one guest-vCPU
mention states that hosted CI does not launch one; `git diff --check` is silent.

- [ ] **Step 5: Commit the hosted-only workflow**

```bash
git add .github/workflows/ci.yml
git commit --no-verify -m "ci: separate hosted validation from guest execution"
```

---

### Task 2: Add the Trusted Hardware Runtime Workflow

**Files:**

- Create: `.github/workflows/kernel-runtime.yml`

**Interfaces:**

- Consumes: repository variables `CARRICK_SELF_HOSTED` and
  `CARRICK_SELF_HOSTED_KVM`; new variable
  `CARRICK_SELF_HOSTED_FULL_CONFORMANCE`; runner labels `carrick-hvf` and
  `carrick-kvm`; existing signed/hardware `just` recipes.
- Produces: trusted-event HVF focused proof, nightly/manual strict closure, and
  nightly/manual KVM smoke jobs.

- [ ] **Step 1: Create the workflow trigger and global policy**

Create the file with this header:

```yaml
name: Kernel runtime · trusted hardware

on:
  push:
    branches: [main]
  workflow_dispatch:
  schedule:
    - cron: "0 9 * * *"

permissions:
  contents: read

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1
```

Do not add `pull_request` or `pull_request_target`.

- [ ] **Step 2: Add the focused Apple Silicon/HVF job**

Append this job. Reuse the same action versions as hosted CI; do not invent a
different toolchain policy.

```yaml
jobs:
  hvf-kernel:
    name: HVF · signed embed + cached probes
    if: ${{ vars.CARRICK_SELF_HOSTED == 'true' }}
    runs-on: [self-hosted, macos, arm64, carrick-hvf]
    timeout-minutes: 180
    concurrency:
      group: carrick-hvf-${{ github.repository }}
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@v4

      - name: Verify Apple Silicon host
        run: |
          test "$(uname -s)" = Darwin
          test "$(uname -m)" = arm64
          command -v codesign
          command -v otool

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - uses: Swatinem/rust-cache@v2

      - name: Install just and cargo-deny
        uses: taiki-e/install-action@v2
        with:
          tool: just,cargo-deny

      - name: Install Semgrep
        run: brew install semgrep || python3 -m pip install semgrep

      - name: Host-only source gate
        run: RUST_TEST_THREADS=1 just ci

      - name: Build and codesign HVPatch artifact
        run: just build

      - name: Verify entitlement and DTrace section
        run: |
          codesign -d --entitlements - target/release/carrick 2>&1 \
            | grep -q com.apple.security.hypervisor
          otool -l target/release/carrick | grep -q __dof_carrick

      - name: Signed embedded guest tests
        run: RUST_TEST_THREADS=1 just test-embed

      - name: Cached public probe gate
        run: RUST_TEST_THREADS=1 CARRICK_PROBE_WORKERS=1 just conformance-probes
```

The artifact check follows the repository's live `codesign` spelling. Do not
hardcode `__DATA` because the current binary's DOF section segment has varied;
the acceptance condition is the named `__dof_carrick` section.

- [ ] **Step 3: Add the strict full-closure job**

Append a separate job so the focused job is not mislabeled as full closure:

```yaml
  hvf-closure:
    name: HVF · strict 2,127-suite closure
    if: >-
      ${{ vars.CARRICK_SELF_HOSTED == 'true' &&
          vars.CARRICK_SELF_HOSTED_FULL_CONFORMANCE == 'true' &&
          (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') }}
    needs: hvf-kernel
    runs-on: [self-hosted, macos, arm64, carrick-hvf]
    timeout-minutes: 1440
    concurrency:
      group: carrick-hvf-${{ github.repository }}
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@v4

      - name: Verify canonical closure host
        run: |
          test "$(uname -s)" = Darwin
          test "$(uname -m)" = arm64
          command -v codesign
          command -v otool
          command -v docker
          docker version

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - uses: Swatinem/rust-cache@v2

      - name: Install just
        uses: taiki-e/install-action@v2
        with:
          tool: just

      - name: Build and verify frozen closure scope
        run: |
          just build
          just conformance-closure-scope

      - name: Strict 2,127-suite closure
        run: |
          just conformance full --closure --force
          # The recipe re-signs its build dependency, so verify scope again on
          # the exact post-gate artifact.
          just conformance-closure-scope
```

This command is baseline-free, rejects filters/retries/blessing, requires the
full HVF selection, and fails unless all 2,127 reports are accounted for as
MATCH. Do not add `--refresh-oracle`, `--bless`, `--allow-hang`, or a filter.
Do not add the separate probe-closure recipe here: the focused job already runs
the public probe gate, while this job's claim is the frozen 2,127-suite gate.

- [ ] **Step 4: Add the Linux/KVM smoke job**

Append:

```yaml
  kvm-smoke:
    name: KVM · real /dev/kvm smoke
    if: >-
      ${{ vars.CARRICK_SELF_HOSTED_KVM == 'true' &&
          (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') }}
    runs-on: [self-hosted, linux, kvm, carrick-kvm]
    timeout-minutes: 60
    concurrency:
      group: carrick-kvm-${{ github.repository }}
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@v4

      - name: Verify KVM host
        run: |
          test "$(uname -s)" = Linux
          test -c /dev/kvm
          test -r /dev/kvm
          test -w /dev/kvm

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - uses: Swatinem/rust-cache@v2

      - name: Install just
        uses: taiki-e/install-action@v2
        with:
          tool: just

      - name: KVM smoke fixture
        run: just kvm-smoke
```

- [ ] **Step 5: Perform a static security and proof-boundary review**

```bash
sed -n '1,360p' .github/workflows/kernel-runtime.yml
rg -n "pull_request|pull_request_target|self-hosted|--bless|--refresh-oracle|/dev/kvm|__dof_carrick" .github/workflows/kernel-runtime.yml
git diff --check -- .github/workflows/kernel-runtime.yml
```

Expected: no pull-request trigger, no blessing/refresh flag, dedicated runner
labels on both hardware families, explicit entitlement/DOF checks, explicit
usable `/dev/kvm` checks, and silent `git diff --check`.

- [ ] **Step 6: Commit the trusted hardware workflow**

```bash
git add .github/workflows/kernel-runtime.yml
git commit --no-verify -m "ci: add trusted hardware kernel gates"
```

---

### Task 3: Correct the Root README and Replace the Architecture Deep Dive

**Files:**

- Modify: `README.md:1-238`
- Replace: `docs/architecture-overview.md:1-329`

**Interfaces:**

- Consumes: `AGENTS.md` execution architecture, `hybrid.md` invariants,
  `handoff.md` current scope, and the workflow proof split from Tasks 1-2.
- Produces: a contradiction-free public explanation of Carrick's current
  kernel, HALs, maturity, and CI evidence.

- [ ] **Step 1: Replace the root README opening**

Use this opening before the existing name/status material:

```markdown
Carrick is an experimental Linux-compatible kernel that runs unmodified Linux
user-space binaries without a guest Linux kernel. On the reference
macOS/Apple Silicon path, one Carrick carrier process owns one
hardware-assisted VM and one kernel graph. Linux tasks, process identity,
address spaces, descriptors, waits, signals, namespaces, and lifecycle belong
to Carrick; guest `fork` and `clone` create kernel objects inside that carrier,
not Darwin child processes.

HVF, KVM, bhyve, and NVMM are hardware-execution and physical-memory backends.
Darwin, BSD, and Linux host facilities provide typed capabilities for storage,
events, sockets, timers, and memory. They are implementation mechanisms, not
the authority for Linux semantics.
```

Retain the backend/ISA bullets and preserved DSR/JIT paragraph, but title the
latter "Preserved optimization primitives" and state that they are not a
shipped execution backend.

- [ ] **Step 2: Replace the root Architecture section**

Use this ownership flow and accompanying bullets:

```markdown
## Architecture

```text
Linux ELF at guest EL0
  -> syscall or fault trap through the selected VMM
  -> Carrick kernel graph and subsystem dispatch
  -> typed host capabilities
```

- The carrier owns one VM and one kernel graph. Multiple Linux processes and
  namespace trees coexist inside that graph.
- `fork`, `clone`, `exec`, exit, wait, signals, credentials, file descriptions,
  and `/proc` state are Carrick kernel operations. Host process identity is not
  guest identity.
- Each logical guest thread has a host pthread, while a bounded, reclaimable
  set of vCPU leases is multiplexed across those threads. A blocking guest wait
  can release its lease for another runnable thread.
- Guest virtual addresses, stage-1 IPAs, reusable global-frame IPAs, and host
  owner generations are distinct memory domains authenticated through live
  translation and generation state.
- The runtime is BKL-free: independently locked subsystems coordinate through
  typed kernel objects and explicit lifecycle transactions.
```

Fix "What Works Today" so it contains no "one vCPU per guest thread" or "host
fork/wait4 mirroring" statement. Replace those bullets with bounded vCPU lease
multiplexing and Carrick-owned process lifecycle.

- [ ] **Step 3: Add the CI proof matrix to the root README**

Insert after Build Workflows:

```markdown
### Continuous integration

GitHub-hosted runners cannot provide an authoritative HVF/KVM guest-execution
gate. Carrick separates portable validation from hardware proof:

| Lane | Pull-request gate | What it proves |
| --- | --- | --- |
| Hosted macOS/Linux | Yes | Source, ABI, host-only kernel semantics, and target feature closure |
| Self-hosted Apple Silicon/HVF | Trusted events | Signed HVPatch embedded execution and cached probes |
| Self-hosted Apple Silicon/HVF closure | Trusted nightly/manual | Strict, baseline-free 2,127-suite accounting |
| Self-hosted Linux/KVM | Trusted nightly/manual | Real `/dev/kvm` smoke |
| FreeBSD/bhyve and NetBSD/NVMM | Cross-check only | Build and feature closure, not guest execution |

GitHub documents nested virtualization as unsupported on hosted macOS Arm64 and
experimental rather than guaranteed on hosted runners generally. A hosted
green check therefore never stands in for a signed hardware run. See
[the conformance guide](docs/conformance-testing.md) for the evidence boundary.
```

- [ ] **Step 4: Replace `docs/architecture-overview.md`**

Write the replacement using these exact top-level sections:

```markdown
# Carrick Kernel Architecture

## 1. One Carrier, One VM, One Kernel Graph
## 2. Guest Execution and the Trap Boundary
## 3. Kernel-Owned Identity and Lifecycle
## 4. Non-Identity Memory and Transactional Publication
## 5. Threads, Executors, and vCPU Leases
## 6. VFS, Networking, Events, and Host Capabilities
## 7. Platform HALs and Guest ISAs
## 8. Embedding and Conformance
## 9. Preserved Optimization Primitives
## See also
```

The opening must state:

```markdown
Carrick runs Linux user space above Carrick's own kernel graph. There is no
guest Linux kernel and no one-Darwin-process-per-Linux-process mapping. On the
reference macOS/Apple Silicon lane, one carrier owns one HVF VM; Linux
processes, threads, address spaces, namespaces, descriptors, waits, and signals
are objects and transactions inside Carrick.
```

Section 2 explains EL0 execution, EL1 shim/vector involvement, VM exits, and
Rust dispatch without claiming identity mapping. Section 3 distinguishes
`TaskKey`, `ThreadKey`, `MmId`, Linux numeric IDs, and unrelated host IDs;
`fork`/`clone`/`exec`/exit/wait are kernel transactions. Section 4 explicitly
names guest VA, stage-1 IPA, global-frame IPA, host address, and owner generation
as distinct domains and describes rollback-capable stage-1/stage-2/inventory
publication. Section 5 describes logical threads, persistent executors,
reclaimable leases, blocking-wait lease release, and fork admission ordering.
Section 6 makes host kqueue/epoll/filesystems/sockets wake or storage
capabilities rather than Linux authority. Section 7 describes HVF as reference
and the other VMMs as bring-up lanes. Section 8 distinguishes host-only tests,
signed embedded probes, Docker differential authority, and the strict closure
gate. Section 9 says DSR/JIT components are preserved for future optimization
and are not selectable shipped backends.

Do not retain any old sentence asserting native-host-process execution,
`libc::fork`, one VM per Linux process, stage-1 identity as the HVPatch model,
or lifetime vCPU ownership.

- [ ] **Step 5: Static contradiction scan**

```bash
rg -n -i "native macOS process|each Linux process is one Darwin process|libc::fork|one VM per process|guest pid.*host pid|one vCPU per guest thread|host fork|identity map" README.md docs/architecture-overview.md
git diff --check -- README.md docs/architecture-overview.md
git diff -- README.md docs/architecture-overview.md
```

Expected: no active retired-architecture claim. Legitimate negations such as
"not Darwin child processes" are acceptable and must be reviewed in context.

- [ ] **Step 6: Commit the public architecture rewrite**

```bash
git add README.md docs/architecture-overview.md
git commit --no-verify -m "docs: describe Carrick as a carrier kernel"
```

---

### Task 4: Align the Crate and Embedding READMEs

**Files:**

- Modify: `crates/README.md:1-99`
- Modify: `crates/carrick-embed/README.md:1-71`
- Modify: `crates/carrick-conformance-next/README.md:1-45`

**Interfaces:**

- Consumes: public architecture terminology from Task 3.
- Produces: crate-level ownership descriptions and unambiguous hardware
  requirements.

- [ ] **Step 1: Correct the crate map ownership statements**

Change the product/runtime rows to say:

```markdown
| `carrick-runtime` | Carrick kernel implementation: ELF execution, syscall dispatch, VFS/rootfs, kernel-owned process and memory models, namespaces, credentials, sockets, IPC, procfs/sysfs, scheduling integration, and platform-selected execution loops. |
```

Change the neutral-core row to:

```markdown
| `carrick-kernel` | Kernel-graph foundations: carrier/container objects, arenas, typed process/task/thread/mm identity, lifecycle transactions, and shared registries. |
```

Introduce the VMM table with:

```markdown
The VMM crates execute guest instructions and project Carrick's kernel state
onto host virtualization APIs. They do not own Linux process identity or
lifecycle semantics.
```

Change the HVF row to remove "fork/exec VM management" and use "stage-1/stage-2
projection, vCPU execution and coordination, fault/syscall exits, and
observability probes." Keep the remaining platform status accurate.

Change the conformance-next row's opening from "Self-hosted conformance
framework" to "In-process conformance framework".

- [ ] **Step 2: Add the embed carrier/hardware boundary**

After the first paragraph in `crates/carrick-embed/README.md`, add:

```markdown
An embedded workload enters the same carrier architecture as the CLI: one VM
and one Carrick kernel graph can contain multiple Linux process and namespace
trees. The embedding process does not become the Linux process, and guest
`fork`/`clone` remain Carrick kernel operations.
```

Extend the Entitlement section with:

```markdown
The entitlement authorizes HVF on a physical Apple Silicon host; it cannot add
nested-virtualization support to a hosted VM. Guest-running embed tests
therefore require a supported hardware runner in addition to signing. Ordinary
compile and host-only tests do not.
```

- [ ] **Step 3: Disambiguate conformance-next and cached oracles**

Change the title paragraph to:

```markdown
In-process conformance framework for Carrick built on `carrick-embed`.
```

After the authoring-policy cached-oracle paragraph, add:

```markdown
Committed Docker oracle results remove Docker from the ordinary feedback loop;
they do not remove the hardware virtualization requirement on the Carrick side.
On macOS, these tests still boot real HVF guests from signed test executables.
```

In Running Tests, state that `HV_DENIED`, a missing entitlement, or unsupported
nested virtualization is a failure on a configured hardware gate, never a
successful skip.

- [ ] **Step 4: Static README review**

```bash
rg -n -i "self-hosted|fork/exec VM management|Linux process|kernel graph|nested virtualization|HV_DENIED" crates/README.md crates/carrick-embed/README.md crates/carrick-conformance-next/README.md
git diff --check -- crates/README.md crates/carrick-embed/README.md crates/carrick-conformance-next/README.md
git diff -- crates/README.md crates/carrick-embed/README.md crates/carrick-conformance-next/README.md
```

Expected: "self-hosted" is absent as the framework's name; any occurrence is
specifically about a GitHub runner. Kernel versus VMM ownership is explicit.

- [ ] **Step 5: Commit the crate README updates**

```bash
git add crates/README.md crates/carrick-embed/README.md crates/carrick-conformance-next/README.md
git commit --no-verify -m "docs: align crate guides with the kernel model"
```

---

### Task 5: Document the CI Evidence Boundary in the Testing Guides

**Files:**

- Modify: `docs/README.md:1-50`
- Modify: `docs/conformance-testing.md:1-390`

**Interfaces:**

- Consumes: workflows from Tasks 1-2 and public terminology from Tasks 3-4.
- Produces: contributor-facing guidance that distinguishes hosted, focused
  hardware, and strict closure evidence.

- [ ] **Step 1: Update the documentation index descriptions**

Change the architecture overview entry to:

```markdown
- **[`architecture-overview.md`](architecture-overview.md)** — Current carrier-kernel architecture: kernel graph, HVPatch memory domains, task/executor model, host capabilities, and platform HALs.
```

Change the conformance entry to:

```markdown
- **[`conformance-testing.md`](conformance-testing.md)** — Host-only checks, signed hardware gates, differential Docker oracles, strict closure, and the evidence limits of public GitHub-hosted runners.
```

- [ ] **Step 2: Correct the conformance guide introduction**

Keep compile-time versus runtime conformance, but state that Carrick has one
shipped HVPatch kernel execution model projected through platform VMMs. Remove
language that treats `hvf`, `kvm-local`, `bhyve-local`, or `nvmm-local` as
different execution backends; they select target host/VMM/guest architecture.

Add after the introduction:

```markdown
## CI evidence boundary

Public pull requests run source, ABI, host-only kernel-semantic, and target
closure checks on GitHub-hosted machines. They do not execute a guest and must
not be cited as HVPatch/KVM runtime proof. GitHub documents nested
virtualization as unsupported on hosted macOS Arm64 and experimental rather
than guaranteed on hosted runners generally.

Real guest execution is isolated in `.github/workflows/kernel-runtime.yml` on
trusted, capability-labeled self-hosted hardware. The focused HVF job proves
signed embed/probe execution; the KVM job proves its named smoke fixture; only
the strict baseline-free closure invocation accounts for the frozen 2,127
suites. These claims are intentionally not interchangeable.
```

Link "unsupported" and "experimental" to the official GitHub runner references
already recorded in the design spec.

- [ ] **Step 3: Make skip semantics explicitly non-authoritative**

Rename `### Self-skip semantics` to
`### Developer convenience skips are not hardware evidence` and preserve its
historical description of legacy tests. Add:

```markdown
Those skips keep an ordinary developer test command usable, but a skipped case
proves nothing. Configured hardware jobs use signed recipes and strict modes
whose missing entitlement, VMM capability, binary, image, or oracle
prerequisite is a failure. Never cite a green skip-capable invocation as a
guest-execution receipt.
```

Update the old "Legacy differential probe suite" heading to "Retained
subprocess differential probes" and explain that new generic probes run
in-process through `carrick-conformance-next`; subprocess execution remains only
for the reviewed retained exceptions and CLI boundary contract.

- [ ] **Step 4: Document the strict closure command**

Add to the unified harness section:

```sh
just conformance full --closure --force
```

Explain that it requires the exact unfiltered HVF full selection, refuses
baseline excuses, skips, retries, blessing, and missing oracle rows, and
requires exactly 2,127 unique MATCH reports. Keep `just conformance-probes` as
the public probe gate and do not equate its narrower surface with suite closure.

- [ ] **Step 5: Static guide review**

```bash
rg -n -i "CI evidence boundary|skip|self-hosted|closure|2,127|legacy|exec-backend|native backend|vmm backend" docs/README.md docs/conformance-testing.md
git diff --check -- docs/README.md docs/conformance-testing.md
git diff -- docs/README.md docs/conformance-testing.md
```

Expected: the guide names each proof surface and its limits; no active prose
suggests that a skip-capable hosted run is runtime authority.

- [ ] **Step 6: Commit the testing documentation**

```bash
git add docs/README.md docs/conformance-testing.md
git commit --no-verify -m "docs: define hosted and hardware CI evidence"
```

---

### Task 6: Final Static Acceptance Review

**Files:**

- Review: `.github/workflows/ci.yml`
- Review: `.github/workflows/kernel-runtime.yml`
- Review: `README.md`
- Review: `docs/architecture-overview.md`
- Review: `crates/README.md`
- Review: `crates/carrick-embed/README.md`
- Review: `crates/carrick-conformance-next/README.md`
- Review: `docs/README.md`
- Review: `docs/conformance-testing.md`

**Interfaces:**

- Consumes: all preceding task commits.
- Produces: static-only handoff with no unsupported runtime claim.

- [ ] **Step 1: Verify workflow security boundaries by inspection**

```bash
rg -n "pull_request|pull_request_target|self-hosted" .github/workflows/*.yml
rg -n "CARRICK_SELF_HOSTED|runs-on:|concurrency:|/dev/kvm|com.apple.security.hypervisor|__dof_carrick" .github/workflows/kernel-runtime.yml
```

Expected: self-hosted occurs only in `kernel-runtime.yml`; that workflow has no
pull-request trigger; every hardware job has dedicated labels and capability
checks.

- [ ] **Step 2: Scan active public architecture prose for retired claims**

```bash
rg -n -i "runs.*as native host process|each Linux process is one|libc::fork|host fork.*mirror|one VM per.*process|guest pid.*host pid|one vCPU per guest thread|exec-backend (native|vmm)" README.md docs/README.md docs/architecture-overview.md docs/conformance-testing.md crates/README.md crates/carrick-embed/README.md crates/carrick-conformance-next/README.md
```

Expected: zero false affirmative claims. Review any negative or historical
mention in context; do not mechanically delete accurate history or explicit
"does not" statements.

- [ ] **Step 3: Review all changes and whitespace**

```bash
git diff --check 246133fc4..HEAD
git diff --stat 246133fc4..HEAD
git diff 246133fc4..HEAD -- .github/workflows README.md docs/architecture-overview.md docs/README.md docs/conformance-testing.md crates/README.md crates/carrick-embed/README.md crates/carrick-conformance-next/README.md
git status --short --branch
```

Expected: only the nine implementation files are changed by the five task
commits. This durable implementation plan is committed separately after the
static review. No controller, baseline, oracle, generated matrix, or Rust file
appears.

- [ ] **Step 4: Record the intentionally unexecuted validation**

The final handoff must say exactly:

```text
Validation was static only at the owner's request. No workflow, just recipe,
Cargo command, test, formatter, codesigning step, Docker command, or guest was
executed. The new hardware workflow is configuration awaiting its first trusted
runner execution; it is not yet runtime evidence.
```

- [ ] **Step 5: Present the final checkpoint without pushing**

Report the commit list, changed files, static inspection results, runner labels
and repository variables required to activate hardware lanes, and the first
recommended live validation commands. Do not push, change branch protection,
register runners, or enable repository variables unless separately requested.

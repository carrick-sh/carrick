# Kernel Architecture Documentation and Public CI Design

**Date:** 2026-08-28

**Status:** Design approved in chat; awaiting owner review of this written spec.

**Controller:** [`../../../handoff.md`](../../../handoff.md) remains the live
correctness and performance controller. This design changes documentation and
CI proof boundaries only; it does not redefine completion of the 2,127-suite
HVPatch campaign or the <=2x performance gate.

## Goal

Make Carrick's public documentation and GitHub Actions describe and test the
system that exists after retirement of the one-host-process-per-Linux-process
backends:

- Carrick is a user-space Linux-compatible kernel with one carrier process, one
  hardware-assisted VM, and one kernel graph per Carrick runtime instance.
- Linux task identity, process lifecycle, address spaces, waits, signals,
  descriptors, namespaces, and scheduling policy belong to Carrick.
- Guest `fork` and `clone` create Carrick kernel objects. They do not call host
  `fork` and do not create one VM per Linux process.
- HVF, KVM, bhyve, and NVMM are execution and physical-memory HALs, not sources
  of Linux semantics.
- Public GitHub-hosted validation must state what it proves without pretending
  that a runner lacking supported nested virtualization executed the kernel.

The change is documentation and workflow configuration only. It does not alter
Rust behavior, baselines, oracle data, support-matrix results, or controller
state.

## Current Problems

### Architecture prose

The root README begins with both the retired claim that Linux binaries run as
native host processes and the current HVPatch description. It later says guest
threads permanently own vCPUs and that process lifecycle mirrors host
`fork`/`wait4`. Those statements conflict with the carrier kernel graph,
Carrick-owned identity/lifecycle, and bounded reclaimable vCPU leases.

`docs/architecture-overview.md` is wholly organized around the retired model:
one Darwin process and one VM per Linux process, `libc::fork`, stage-1 identity
mapping, and one lifetime vCPU per guest thread. Editing a few paragraphs would
leave a plausible but false deep dive, so the page must be replaced rather than
patched incrementally.

The crate, embed, and conformance READMEs are closer to current reality but do
not cleanly distinguish kernel ownership, VMM responsibility, and the two
different meanings of "self-hosted" (an in-repository framework versus a
GitHub self-hosted runner).

### CI proof boundary

The existing workflow mixes hosted validation and dormant hardware jobs in one
file. Comments correctly acknowledge that hosted macOS cannot execute an HVF
guest, but the job names and README do not give contributors a compact proof
matrix. The dormant HVF job is also eligible on `pull_request` whenever its
repository variable is enabled, which would expose a persistent self-hosted
runner to untrusted fork code.

The HVF job runs bare `cargo test --workspace`, contrary to the repository's
serialized test recipes and signed-test rule. It can also pass through skips
when prerequisites are absent, which is not acceptable for a configured
hardware authority lane.

## External Runner Constraint

GitHub-hosted runners are already virtualized. GitHub documents nested
virtualization as unsupported on macOS Arm64 because of Apple's Virtualization
Framework limitation. GitHub's general hosted-runner documentation describes
nested VMs elsewhere as experimental and provides no stability, performance,
or compatibility guarantee. An incidental `/dev/kvm`, successful QEMU launch,
or current image behavior is therefore not a release contract.

Carrick will not use any of the following as a required correctness gate:

- an HVF attempt on a GitHub-hosted macOS runner;
- opportunistic KVM on a standard GitHub-hosted Linux runner;
- QEMU TCG standing in for HVF/KVM/bhyve/NVMM;
- a skipped guest test represented as a successful kernel test.

Software emulation is not a fallback for this change. It would exercise a
different execution boundary and would require a separately designed backend
or kernel test harness.

Authoritative runner references consulted for this decision:

- [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub-hosted runner concepts](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners)
- [Larger runners reference](https://docs.github.com/en/actions/reference/runners/larger-runners)

## CI Architecture

### Workflow 1: hosted validation

`.github/workflows/ci.yml` remains the required pull-request workflow and uses
only GitHub-hosted runners. Its scope is explicit:

1. macOS Arm64 formatting, clippy, typed-domain linting, support-matrix drift,
   compile checks, rustdoc, host unit tests, and host integration tests;
2. Linux-host unit tests for Linux host primitives;
3. cross-target feature-closure checks for Linux/KVM, FreeBSD/bhyve, and
   NetBSD/NVMM;
4. dependency license, source, and ban policy.

Job and step names use "hosted" or "host-only" where needed. Comments state
that these jobs exercise Carrick's kernel data structures and host semantics
but do not boot a Linux guest and do not prove HVPatch runtime conformance.

The hosted workflow contains no self-hosted jobs and never relies on a skip to
claim guest execution. Existing repository-approved `just` recipes remain the
source of truth; no bare workspace-wide test command is introduced.

### Workflow 2: trusted hardware execution

Create `.github/workflows/kernel-runtime.yml` for jobs that execute guest
vCPUs. It has only trusted triggers:

- push to `main`;
- nightly schedule;
- maintainer `workflow_dispatch`.

It has no `pull_request` or `pull_request_target` trigger. Repository variables
keep lanes dormant until suitable runners are registered, but enabling a lane
does not relax its fail-closed prerequisites.

#### Apple Silicon HVF lane

The runner labels are `[self-hosted, macos, arm64, carrick-hvf]`. A dedicated
label prevents unrelated generic self-hosted machines from accepting the job.
The lane:

1. checks out the exact workflow commit;
2. installs the pinned Rust/tool dependencies already used by Carrick;
3. runs host-only `just ci` through the safe repository recipe;
4. builds and signs through `just build`;
5. fails if the binary lacks the hypervisor entitlement or
   `__DATA,__dof_carrick`;
6. runs `just test-embed`, whose entitlement negative control must also pass;
7. runs the cached public probe gate with `just conformance-probes`.

This job proves a signed HVPatch artifact can execute the embedded/probe kernel
surface. It does not by itself prove the full 2,127-suite denominator or the
performance goal.

A separate full-conformance job is limited to nightly/manual events and a
second explicit repository variable. It runs only on a canonical runner with
the required local images/registries and Docker oracle prerequisites. Missing
images, Docker, entitlements, or oracle inputs are failures, not skips. Carrick
and Docker phases remain serialized by the harness. This job must not bless or
rewrite baselines automatically.

#### Linux KVM lane

The runner labels are `[self-hosted, linux, kvm, carrick-kvm]`. The job is
nightly/manual, gated by its existing repository variable, and fails before
building unless usable `/dev/kvm` is present. It runs the repository's
`just kvm-smoke` recipe. Its claim is limited to the KVM smoke fixture and must
not be presented as macOS/HVF conformance.

FreeBSD/bhyve and NetBSD/NVMM retain hosted cross-checks. Real execution for
those backends remains target-host work until corresponding trusted runners and
fail-closed recipes exist; the docs must say so directly.

### Security and concurrency

Self-hosted jobs never execute pull-request code. Each hardware family gets a
workflow concurrency group so scheduled, manual, and main-push runs cannot
compete for the same VMM or Docker resources. Hardware jobs use repository
variables only as enablement switches, never as evidence that a capability is
present. The job itself verifies every required capability.

## Documentation Architecture

### Root README

Rewrite the opening and architecture sections around this ownership chain:

```text
Linux ELF at guest EL0
  -> syscall/fault trap through the selected VMM
  -> Carrick kernel graph and subsystem dispatch
  -> typed host capabilities (Darwin/BSD/Linux primitives)
```

State plainly that there is no guest Linux kernel, no one-host-process mapping,
and no second Linux scheduler. Carrick owns Linux semantics; the host kernel
and hypervisor supply execution, memory, storage, event, and networking
primitives.

Correct the concurrency description to one host pthread per runnable logical
guest thread with a bounded, reclaimable set of vCPU leases. Correct lifecycle
prose to Carrick-owned fork/clone/exec/wait/signal state. Preserve the explicit
experimental/security warning and distinguish the release-quality macOS/HVF
reference lane from active non-macOS bring-up.

Add a short "Continuous integration" section containing a proof matrix:

| Lane | Public PR gate | What it proves |
| --- | --- | --- |
| Hosted macOS/Linux | Yes | Source, ABI, host-only kernel semantics, feature closure |
| Self-hosted Apple Silicon/HVF | Trusted events | Signed HVPatch guest execution and probes |
| Self-hosted Linux/KVM | Trusted nightly/manual | Real KVM smoke |
| FreeBSD/bhyve, NetBSD/NVMM | Cross-check only | Build/feature closure, not guest execution |

### Architecture overview

Replace `docs/architecture-overview.md` with a current, source-oriented deep
dive organized as:

1. carrier, VM, and kernel graph;
2. guest EL0 trap boundary and syscall dispatch;
3. kernel-owned process/task identity and lifecycle;
4. non-identity memory domains: guest VA, stage-1 IPA, global-frame IPA, and
   host-owner generation;
5. logical guest threads, persistent executors, and reclaimable vCPU leases;
6. VFS, file descriptions, sockets, event readiness, and host capabilities;
7. platform HAL split across HVF, KVM, bhyve, and NVMM;
8. conformance and evidence boundaries;
9. preserved DSR/JIT primitives as future optimization components, not a
   shipped execution backend.

The page must avoid volatile performance counts and completion claims. It may
link to the controller and durable evidence rather than duplicating them.

### Crate and specialized READMEs

- `crates/README.md`: describe `carrick-runtime` as the kernel implementation,
  `carrick-kernel` as shared kernel-graph foundations, and VMM crates as HAL
  execution backends. Remove VMM-owned process-lifecycle implications.
- `crates/carrick-embed/README.md`: say an embedded workload joins the same
  carrier kernel model and that guest-running tests require real supported
  virtualization; signing alone cannot create nested-virtualization support.
- `crates/carrick-conformance-next/README.md`: replace ambiguous "self-hosted"
  wording with "in-process" or "Carrick-hosted" and document that cached Docker
  oracles remove the routine Docker dependency but not the HVF requirement.
- `docs/README.md`: make the current architecture overview and CI/testing proof
  boundary discoverable.
- `docs/conformance-testing.md`: correct stale legacy/default-backend wording,
  explain hosted versus hardware CI, and make skips non-authoritative.

Historical evidence under `docs/perf-results/` and `docs/archive/` is not
rewritten. Historical statements remain valid as records of the artifact they
measured.

## Static Verification for This Change

The user explicitly requested that no code be run. Verification for the edit is
therefore limited to read-only/static review:

- inspect YAML structure and expressions manually;
- search active READMEs and the architecture overview for retired claims such
  as native-host-process execution, host `fork` mirroring, one VM per Linux
  process, identity-only HVPatch memory, or permanent one-vCPU ownership;
- inspect `git diff --check`, `git diff`, and repository status;
- do not invoke Actions, `just`, Cargo, tests, codesigning, Docker, guests, or
  YAML execution/validation tools.

The handoff must explicitly say that workflows were not executed. The next
authorized runtime validation is a trusted hardware run after review.

## Acceptance Criteria

1. A new contributor can identify Carrick as the Linux kernel authority and
   the VMM/host as HALs without encountering a contradictory active deep dive.
2. No public pull-request workflow can dispatch untrusted code to a Carrick
   self-hosted runner.
3. Required hosted checks make no guest-execution or conformance claim.
4. A configured hardware job fails when its virtualization, signing, image, or
   oracle prerequisites are absent.
5. Hardware job names and documentation distinguish focused probe/smoke proof
   from full correctness and performance closure.
6. Repository-approved serial/signing recipes replace bare workspace test
   commands.
7. No baseline, oracle, support matrix, controller, or runtime source changes
   are included.
8. The final report lists every changed file and states that validation was
   static only.

## Non-Goals

- Making nested virtualization supported on GitHub-hosted runners.
- Building a software VMM, TCG backend, or mock kernel executor.
- Registering or provisioning self-hosted hardware.
- Changing branch-protection settings or claiming a hardware job is required
  before the runner fleet exists.
- Refreshing conformance baselines, Docker oracle caches, support matrices, or
  performance results.
- Declaring HVPatch correctness or <=2x performance complete.

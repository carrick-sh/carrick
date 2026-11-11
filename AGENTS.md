# AGENTS.md

The rules every agent and human in **Carrick** follows. Keep it under 16 KiB:
tools truncate long files, and an unread rule doesn't bind. Depth lives in
`docs/`, `.agents/skills/` and the `justfile`. Owner decisions are logged on
#231; one that changes a rule here changes this file the same day.

## Non-negotiables

1. **Codesign before you run on macOS.** Build and run with `just build` or
   `just run`. A bare `cargo build` drops `com.apple.security.hypervisor`, and
   the run dies with `HV_DENIED` (`0xfae94007`). Rebuild `-p carrick-cli` after
   changing `carrick-runtime`. VM-booting tests run only through signed recipes
   (`just test-embed`, `scripts/test-signed.sh`). An `HV_DENIED` there is a
   failure, never a skip. → [Signing](docs/build-maintenance.md#signing).
2. **Never strip or trim debuginfo, and never link with `lld`.** `lld` drops
   `__DATA,__dof_carrick`, so `carrick trace` fires nothing. Keep Apple `ld64`;
   check with `otool -l target/release/carrick | grep dof`.
3. **Never `git stash`.** The stash is shared across worktrees. Never run
   `git add -A`, which commits the `conformance-probes/target` symlink. Never
   `git merge --ff-only` inside a worktree. Never use `--no-verify` without
   owner approval recorded on the PR. The standing exception is
   `worker salvage` pushes to `salvage/*` (owner, 2026-11-08).
4. **Clean room.** Never read GPL, LGPL or other copyleft source: Linux, QEMU,
   Wine. Use man pages, specs and the Docker oracle. Permissive prior art
   (FreeBSD linuxulator, gVisor, NetBSD compat, Go runtime) is fine: check its
   LICENSE first. Every brief that points at outside code states this.
5. **Never run carrick and Docker at the same time.** The VMs starve each other
   and the verdicts are wrong. carrick with carrick, or Docker with Docker, is
   fine.
6. **Be honest about status.** Carrick is experimental. Coverage is partial
   (`grep -c 'SupportLevel::BringUp' crates/carrick-abi/src/syscall.rs`), and
   there has been no adversarial security review. Never run untrusted code,
   and never say "complete" or "production-ready".
7. **Fix forward.** Never `git revert`, reset or force-push `main`.
8. **Reap by run id.** Stamp `CARRICK_RUN_ID` and reap with
   `scripts/sudo/kill.sh <run-id>`. Never `pkill -f carrick`. Never
   lldb-attach to a process descended from your own terminal session.
9. **Write gate and harness output to a durable file.** Never pipe it through
   `tail`, `grep` or `head`. Check both the exit status and the file. Chain a
   commit on its test with `&&`.
10. **Base on GitHub main** (`https://github.com/carrick-sh/carrick`), never a
    host mirror. Commit after each step: red witness, fix, proof.
11. **Flaky is a defect.** A verdict that changes between runs, or with load,
    gets a `flaky` issue with the run ids. Never retry until green, and never
    add it to `known_gaps`.
12. **Never shut down cloudmac;** it is shared with CI.

## What Carrick is

Carrick runs unmodified Linux binaries in one VM carrier per run, on a small
Carrick-owned guest kernel (ARM EL1 / x86 CPL0, one shared crate set). There is
no Linux kernel and no host big kernel lock. Under **HVPatch** (the default),
tasks, address spaces, waits and signals live in Carrick's kernel graph, and a
guest `fork` creates no host process. macOS HVF on AArch64 is the reference
lane; KVM, bhyve and NVMM are the other hosts. Crate map:
[`crates/README.md`](crates/README.md) (use `carrick-vmm-*` names). Subsystem
map: [`docs/architecture-overview.md`](docs/architecture-overview.md#where-key-subsystems-live).

## Priorities

In order: **red main**, then **landing approved work**, then the **Go, Python
and Node blockers**, then the **x86 single lane**, then **≤2x native-arm64
Docker** (owner, 2026-11-07: the perf gate starts once the language suites meet
their bar). A pathological ratio, such as 5x, 30x or 80x, is structurally wrong
work, so it counts as a correctness bug now. A row sitting on its timeout is a
hang. The ecosystem milestone is the languages' own test suites, against the
Docker oracle. The scoreboard is the fast smoke check.

## Engineering rules

- **Guest-visible change → conformance contract.** In Carrick,
  guest-visible correctness includes Linux semantics and non-pathological
  cost. Use
  [`carrick-conformance-contract`](.agents/skills/carrick-conformance-contract/SKILL.md)
  and add a red-first contract when none exists. A semantic pass cannot excuse
  a budget or ratio failure. Never weaken budgets, add retries or
  timeouts, poll, or serialize as a fix. → [`docs/conformance-contracts.md`](docs/conformance-contracts.md).
- **The compat zone is ours.** Guest AF_UNIX, ptys, pipes, futexes, pgrps and
  sessions, signals, identity, rlimits and the netns view live in Carrick's
  kernel. Host objects are used only for real crossings: host files, network,
  the CLI terminal, CPU and clock. There is no host readiness pipe for an
  in-zone object: enrol on its wait queue, then probe once.
  → [`docs/host-facility-boundary.md`](docs/host-facility-boundary.md).
- **Ring-first.** Every routed call is served exactly in ring, or left
  unrouted (a counted ENOSYS). A Forward-only arm is a second path.
  Personalities never Forward. Changes to the crossing allowlist
  (`carrick-personality-linux/src/crossing.rs`,
  `docs/design/arm-ring-first-flip.tsv`) are director-owned, and need an
  independent review and the signed gate.
- **One lane.** A fix lands for ARM and x86, and for HVF and KVM, in the same
  PR, through ISA-neutral crates. Per-arch code holds only ISA mechanics:
  register frames, trap and IRQ entry, page-table formats. A gap in neutral
  logic is a P0 for that PR. A true mechanic that can't follow yet becomes a
  `seam` issue with the reason (owner, 2026-10-27 and 2026-11-08).
- **Fix in shared layers; move code, never copy it.** Ring ports go through the
  shared `no_std` `*-core` crates. Search before writing: a second
  implementation drifts.
- **Contention is "not now", never fatal or an errno.** On `Busy`, keep the
  owned operation, release the lease, enrol on the holder's release, probe
  once, then rerun. Only a broken invariant (`Stale`, `Invalid`,
  `Quarantined`) is fatal. Witness "Busy once, then success".
- **A guest wait releases execution capacity.** Return an owned continuation
  that keeps its offset and completion authority. Test by exhausting the
  default pool.
- **Authority follows the execution lane.** Linux semantics key on
  `TaskKey`/generation, never on a host pid, timer or lock owner. Retirement
  and terminal decisions belong to the neutral owner; backends apply verdicts.
- **Types over comments.** Typed domains at every semantic boundary (`Fd`,
  `NsPid`, `GuestVa`, `LinuxErrno`, …; `just lint-domains`). A prose rule that
  failed twice becomes a type. ABI constants live in `carrick-abi`. Test
  storage for ABI records uses `TestEl1Region`.
- **Two live processes, or two live threads, beat any number of
  single-process cases.** Cover lifecycle exits: a non-last thread's raw
  `exit`, and `exit_group` with a running worker.
- **EL1 and CPL0 stacks are small.** No large by-value locals or returns:
  box or borrow. `crates/carrick-el1-image/frame_budget.rs` is the one checker.
- **HVPatch memory is non-identity.** Guest VA, IPA, global-frame IPA and
  owner generation are separate domains. → [`docs/architecture-overview.md`](docs/architecture-overview.md#hvpatch-memory).
- **On a contained fast path, only ENOENT is authoritative.** Fall back to the
  resolving path on any errno a Carrick-added flag could cause.
- **No shortcuts or second paths.** Fix root causes; no shims or V2 beside
  V3. New work is ON with an exact `=0` opt-out; delete what measures worse.
  No fake backends (doubles stay behind `cfg(test)`). New tooling is Rust: a
  `carrick trace` profile or `carrick debug` subcommand.
- **Authority debt** (`AuthorityDebtCeilings`, `just lint-domains`) may rise
  only through a recorded cohort admission. The admission states its reason
  and links the issue that retires it (owner, 2026-11-09). An unexplained rise
  is sent back. Range checks use `xtask authority-debt --base <merge-base>`.
- **No new line-pinned inventories or SHA-pinned receipts.** Retire them into
  types or counts.

## Evidence

- **Red-first, on the production entry point.** Show the witness failing on
  the pre-fix code and passing after, never on a test-only helper. A test that
  passes immediately proves nothing.
- **Run `just test`, never a bare `cargo test --workspace --lib`.** Workers
  run `just test-touched <main-sha>`, `just check-contract-change <main-sha> HEAD`
  (for files added or moved under `crates/`) and
  `just xtask authority-debt --source-only`, plus:
  `just cross-check-macos` for macOS or HVF code; `just check-linux` and
  `cargo check -p carrick-vmm-kvm` for KVM, HAL or host-linux code; and
  `just build-cpl0` for shared personality, lifecycle or guest-copy code.
- **macOS-only diffs run on a Mac** (`cargo test -p <crate> --lib`, or a
  green `carrick-macos-ci` unit shard on the exact head) before their review
  counts.
- **Done means live-verified:** a clean build, the tests, and a runtime demo
  on the exact binary. Rebuild after every merge you claim.
- **One signed result belongs to one artifact.** Record HEAD, SHA-256,
  CDHash, LC_UUID, the entitlement and `__dof_carrick`. Run
  `just smoke-signed` and attach its receipt before you report signed work.
  Compare populations (tests started, binaries finished), not failure names.
- **Pre-existing means it fails on current GitHub main**, not on the PR's base.
- **Gate and test tooling passes a known-answer run** before anything relies
  on it. A workflow change records `Known-answer run: <id>` on its PR.
- **Correctness holds under load.** Never wait for a quiet box to get a
  verdict. Quietness is only for performance measurement. Perf claims need a
  paired, interleaved A/B on one host; otherwise write "suggests".
- **Oracle and probe rules** (native arm64 oracle only, both streams, oracle
  cache, `carrick-conformance-next`, errno numbers, bounded waits):
  → [`docs/conformance-testing.md`](docs/conformance-testing.md#rules-for-agents),
  skill `ltp-conformance`.

## Debugging

Use real debuggers, never `eprintln!`. `carrick trace` is the tracer: extend
it, and keep `scripts/dtrace/` scripts. Zero events means the probe didn't
fire. Logging perturbs races; USDT doesn't. Deadlock: a real core and
`bt all`. Heisenbug: the event ring via `carrick-lldb` on the **carrier**.
After `carrick_fatal!`, read `CARRICK_LAST_FATAL`. A diagnosis is a hypothesis
until you read real values. → [`docs/diagnostics-and-debugging.md`](docs/diagnostics-and-debugging.md),
skills `carrick-trace` and `carrick-lldb`.

## Shared machines and leases

- `just accept` holds the host lease in exclusive `gate` mode, and
  `scripts/test-signed.sh` holds shared `carrick` mode. Deliberate load needs
  `CARRICK_ALLOW_LOAD=1` and cleans up after itself, and every `dtrace -Z`
  session is bounded.
- Lock order: remote checkout lock, then host lease, then work. Never upgrade
  a shared lease, and never unlink a live lock file.
- Proxmox worker VMs take their in-VM lease, never the physical host (#639).
- Admitted checkouts key on device and inode: remove and re-add, never copy.
  → `docs/host-lease-containment-follow-up.md`, `docs/ci/mac-hvf-runner.md`.

## Workflow

- **GitHub is the system of record.** Issue first, with a plan and acceptance;
  a draft PR from the first code commit, with `Closes #N`; progress and
  evidence as PR comments; facts as labelled issues, searched before filing.
  Agent memory is not a rulebook: a rule every agent must follow goes here.
- **Write for people.** Lead with what happened and what it means. Raw data
  goes in `<details>`.
- **One PR per issue, opened against `main`.** Only a deliberate `gh stack`
  bases on another branch. A stack lands collapsed as one
  PR, never with a merge commit. → [`carrick-stacked-prs`](.agents/skills/carrick-stacked-prs/SKILL.md).
- **One owner per syscall family and mechanism.** Before starting, search open
  PRs, issues and the ring-coverage registry (#1906). Two open PRs changing
  the same production function overlap: reuse, stack or close one.
- **Size by coherent landables, not line counts** (owner, 2026-11-02, and
  2026-11-08 for ring-first porting). The ~4k-line cap is retired.
- **Commits:** `type(scope): subject`, imperative, lowercase, no period, about
  72 characters. Types are `feat`, `fix`, `refactor`, `docs`, `test`,
  `diagnostics`, `chore`, `ci`. Always write a
  body covering why, what and how it was verified. Add one
  `Co-Authored-By: <agent name> <vendor noreply>` line per agent:
  `noreply@anthropic.com`, `noreply@openai.com` or `noreply@google.com`.
  Preserve another agent's authorship. The SHA map for the 2026-10-14 history
  rewrite is on `history/coauthor-rewrite-2026-10-14`.
- **Hooks:** pre-commit runs `fmt-check` and pre-push runs `clippy`. Fix with
  `just fmt` or `just clippy`. Unrelated fmt churn is toolchain skew: check it
  out. Run **`just ci`** in full before pushing; it stops at the first red.

## Review and landing

- **A worker's result is a claim.** Re-verify it from the PR's diff and
  evidence, and grep the diff for out-of-fence changes. A verdict counts only
  as a published review on the current head.
- **Large or shared-kernel PRs get a published independent review** before
  landing, and every fix round gets a confirming re-review. A zero-finding
  review of a large change finished in minutes counts as unreviewed until a
  second vendor confirms it. Designs carry an existing-mechanism inventory.
- **Only P0s block** (owner, 2026-11-08). A P0 is a wrong guest-visible
  result, a crash or hang, data loss, a security hole, a broken invariant, or
  a missing witness for the PR's own claim. P1s and P2s become linked
  `follow-up` issues. A P1 escalates only on evidence that it blocks landing.
- **Flaky or crash fixes land on population evidence:** 10 runs, base vs head,
  one signed artifact each, plus a signed A/B showing the crash gone.
- **Land through the merge queue.** The required checks are `ci-ok` and
  **Signed queue gate** (it runs on the merge group, #1750). A NEW failure the
  group introduces ejects it; other NEW failures are advisory. An incomplete
  base is advisory; a candidate-side gap blocks (#2035, #2045). Signed-fixture
  input changes take the owner-exception route.
  → [`docs/ci/signed-gate.md`](docs/ci/signed-gate.md).
- **Admin merges** need a published review, a green `ci-ok` on the exact head
  rebased on main, and an announcement on #231 naming the lanes to watch.
  They happen between merge groups only. Main's next kernel-runtime run is the
  after-evidence. Never use one for a flaky or crash fix. Standing cases (owner,
  2026-11-04 and 2026-11-08): docs- and workflow-only PRs; calculated bets to
  keep landings flowing; owner-directed x86, KVM, HAL or CPL0 landings.
- **WIP limit: 20 open PRs** (owner, 2026-11-07; enforced by `worker start`).
  Above it, only finishing work starts. An agent may override it to fix the
  project, rarely, with a logged reason (owner, 2026-11-11).
- **Personality split:** the shared kernel is personality-neutral. Nothing
  here names an out-of-tree personality. Neutral crates must not depend on
  `carrick-personality-linux`; `carrick-el1`, `carrick-el1-abi`, `carrick-hal`
  and `carrick-mem` still do, `carrick-core` only as a dev-dependency (#366,
  #237, #2075). Seam PRs follow the lighter gate in
  [`docs/director-playbook.md`](docs/director-playbook.md#seams).

## Where to look next

- Commands: [`justfile`](justfile) (signing recipes are marked).
- Director operations (workers, routing, sessions, runners):
  [`docs/director-playbook.md`](docs/director-playbook.md).
- Architecture: `docs/architecture-overview.md`, `docs/hal.md`,
  `docs/syscalls-emulation-map.md`.
- Gates and runners: `docs/ci/signed-gate.md`, `docs/ci/mac-hvf-runner.md`,
  `docs/build-maintenance.md`.

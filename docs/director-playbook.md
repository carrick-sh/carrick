# Director playbook

Director-only operating rules, moved out of `AGENTS.md` (#2118) so the
rulebook every agent reads stays short. Workers do not act on most of this;
the director does. The binding rules every agent follows stay in
[`AGENTS.md`](../AGENTS.md). Text below is copied from the previous
`AGENTS.md`, tightened only where a decision has since retired the subject.

## Directing workers is reviewing diffs, not reading reports

Workers code in worker VMs; the director owns runtime fixes, live
verification, the signed evidence and landing.


- **The director starts workers as VMs** (owner, 2026-11-07): the
  director's `worker [--host hz] start` (wrapping `conductor worker
  start --template 9001`) creates one through the host's Proxmox API, or a
  `worker-shepherd` subagent of the `carrick-conductor` Claude plugin runs
  one (both in carrick-sh/agy-director). Each worker
  works one issue from GitHub main and opens a draft PR for it. The GitHub
  Actions dispatch path (`/agent` rounds, the reactor) is retired.

  (`ctb` was retired on 2026-11-09, so only `hz` remains.)

- **One owner per syscall family and mechanism; check before starting a
  lane** (a lane is one worker's assigned issue). This puts "Search before
  writing" into practice. Duplicated lanes come from starting work on fresh
  evidence without seeing an open draft that already owns it: PR #1836's ARM
  `nanosleep` port was nearly rebuilt by a timer lane on 2026-11-08.
  - **Check:** before briefing a worker, search open PRs (title, body and
    the functions their diffs touch) and issues for the syscalls, functions
    and paths involved, and read the ring-coverage registry (pinned issue
    #1906, one owning issue per family). A hit means the brief names that PR
    or issue and builds on it, or the lane doesn't start. New evidence for an
    owned family goes to its owner.
  - **Overlap:** two open PRs changing the same production function is
    overlap. Reuse, stack or close one.
  - **Idle drafts:** a draft idle for more than 24 hours with no named
    blocker is finished or closed, with the reason on its issue. A blocked
    draft names its blocker there.
  - **Inventory:** a brief or review that adds a type, lock, queue,
    publisher or owner includes an existing-mechanism inventory: the nearest
    existing one, with file:line, and why it is reused or can't be.

- **Commit after each step (red witness, fix, signed proof), and require it in
  worker briefs.** Long turns hit time limits — two hit the three-hour cap in
  one day, one stranding 1,749 uncommitted lines (#1560).
- **Transport-timeout deaths may leave clean diffs** — run `cargo check` and
  tests, then commit with the worker's trailer. Brief narrowly and start fresh
  conversations on the same worktree.
- **After rebasing a fix stack across a code move**, list each fix as kept,
  ported or dropped and re-prove its red witness before any signed gate.
- **After merging a fast-forward from main**, run `just lint-domains` on
  the merged tree. (Rebase in the worktree; never `git merge --ff-only` there,
  see `AGENTS.md` non-negotiable 3.)
- **A diff touching macOS-only code is tested on a Mac before its review
  counts.** The incident that made this a rule: a worker's accidental global
  substitution in `carrick-vmm-hvf/src/trap.rs` replaced X19 with X21 in the
  production `GPR_TABLE`. It compiled, so vCPU snapshot and restore silently
  lost a callee-saved register while every Linux gate passed (#887, #1560).
  Reviewers grep such diffs for unrelated edits.

- **Workers prove their slice; CI and the director gate the rest** (owner,
  2026-10-30, #231 items 4 and 5). Workers run
  `just test-touched <main-sha>` (changed crates and reverse dependencies,
  using `just test` features and serial partitions),
  `just check-contract-change <main-sha> HEAD`,
  `just xtask authority-debt --source-only` and the pre-push clippy hook,
  plus the checks their change calls for:
  - `just cross-check-macos` for `cfg(target_os = "macos")` or HVF-adjacent code;
  - `just check-linux` (aarch64-Linux KVM crates) and
    `cargo check -p carrick-vmm-kvm` for KVM, HAL or host-linux code;
  - a red-first witness that drives the production entry point, never a
    test-only inner helper;
  - scoped signed witnesses when they have HVF.

  Whole-workspace `just lint-domains` and `just test-kernel` are left to CI.
  Workers post the results on the PR. **Code first by default** (owner,
  2026-11-03, #231): a shared-kernel change starts as a draft PR whose body
  carries a short design note, and the independent review covers the code
  and the approach together; iterate from there. A separate design pass,
  reviewed before code, is kept only for ABI or wire-protocol layouts,
  lock orders that span crates, and multi-slice stacks whose workers need
  a shared interface first. The director
  runs `just accept --profile linux-portable` once per stack or batch in a
  dedicated detached worktree. Signed acceptance runs on the merge group;
  optional diagnostic runs use a detached worktree, never a worker's live one.

- **Run `just build-cpl0` (`carrick-x86-cpl0 --target x86_64-unknown-none`)
  for shared personality, lifecycle or guest-copy changes before claiming x86
  is green.** `carrick-vmm-kvm`'s build script builds the freestanding x86
  CPL0 image only on Linux x86_64, so `cargo check -p carrick-vmm-kvm`
  elsewhere skips it — twice a worker reported x86 green while the image
  didn't compile (#1691, #1697).

## Routing

- **Routing:** a strong design-capable worker for shared-kernel, mm, fork,
  signal, carrier and seam work; a fast instruction-following worker for
  precisely specified mechanical work. A lane refused by one provider's
  content filter restarts fresh on the same worktree (WIP committed first)
  with a provider tier suited to systems work, never by rewording the retry.

The current routing table is the output of `worker quota .route`; treat this
paragraph as the principle and that command as the source.

## Board status

- **Board status follows every transition** on org project 1 ("Carrick shared
  kernel", which spans carrick and carrick-nt): Todo → In progress (started)
  → In review (PR ready) → Done (merged or closed). Blocked names its blocker.
  Every new issue and PR goes on the board.

(The board reconciler now automates most transitions; a Blocked card still
names its blocker.)

## Landing mechanics

- **Cancel PR runs that won't land before enqueueing** (`cancel-wasted-runs.sh`);
  hosted macOS capacity is scarce.

## Seams

- **Seams:** a seam is a carrick issue labelled `seam`, in neutral
  vocabulary. Additive personality-API seams (new types and traits, no
  guest-visible behaviour change, Linux dispatch/mm/fork/signal untouched)
  take the lighter gate: kernel-semantics, KVM/CPL0 builds and a signed
  smoke. Anything touching Linux paths keeps the full signed gate.

## Multiple director sessions

When more than one director session runs at once, each one can break the
others through shared state they never see change. On 2026-10-21 that cost
a signed gate, nine hours of merge queue and a red `main` (#753).

- **Hosts are owned.** Each session uses only the hosts listed for it in
  the "Director lanes" comment on #231. Borrowing another session's host
  means asking first, and every gate still takes that host's lease.
- **Announce shared changes before and after.** This covers repository
  settings and rulesets, workflows and CI configuration, merges to `main`,
  the merge queue, Proxmox templates and the controller, and host-lease
  configuration. Send one message before and one after. The "after" message
  says how the other session would notice breakage. Test a ruleset against
  the merge queue itself, not only against human and App pushes.
- **A merge to `main` is announced at enqueue and at landing.** Name the
  PR, the merge SHA and the lanes to watch (signed EL1 for ARM work, KVM
  for x86). Announce a native stack layer by layer.
- **A main defect you cause is yours to announce.** File a `main-defect`
  issue and notify the other session immediately, so its red CI isn't
  misread as its own regression.
- **The record is on GitHub.** Session-to-session messages are
  notifications. The #231 "Director lanes" comment (owner, hosts, active
  PRs, in-flight shared changes) is the record, and each session updates
  its own section when its lane changes.

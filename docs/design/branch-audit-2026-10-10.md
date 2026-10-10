# Branch and worktree audit, 2026-10-10

Read-only audit of Carrick branches, worktrees, worker mailboxes and build
directories across the local Mac, carrick-vm, cloudmac and GitHub. Nothing was
deleted, moved, rebased, committed or pushed. The only side effects were
`git fetch` of remote-tracking refs on the local Mac, and objects written by
`git merge-tree --write-tree` (no refs touched).

Reference main: GitHub `main` = `4e63042fe` (PR #136 landed 16:41Z during the
audit; most numbers were computed against `c9c603b9c`, one commit earlier).

## Method and caveats

- **Ahead count:** `git rev-list --count origin/main..X`.
- **Patch landed:** `git cherry origin/main X` (patch-id).
- **Subject-unique:** a `git cherry` "+" commit whose subject does not appear
  anywhere in `git log --format=%s origin/main`. The merge queue lands PRs
  by rebase, so subjects survive. Patch-ids do not survive when conflict
  resolution changed the patch. Subject-unique is therefore the better
  "really not landed" signal. It is still a heuristic in two directions:
  - a ported fix with a new subject still counts as unique (example: n1-cm
    `0565ec758` and `bbf545fd4` were ported to main as `6f0db0dc4`, PR #128);
  - a rebase residue with the same subject counts as landed.
- **Content landed:** `git merge-tree --write-tree origin/main X`. If the
  result tree equals main's tree, the content is in main. Most stale branches
  conflict, mainly on line-pinned inventory JSON, so this test was decisive
  for only a few branches.
- **Running workers:** for local and carrick-vm workers, checked with
  `kill -0` on the agy-director `*.pid` files. Ownership comes from
  `*.meta.json`. Facts come from `mail/*.out.jsonl` and `*.in.jsonl`, which
  were read as data.
- **Uncertain** marks a judgement I could not prove mechanically.

## Executive summary

1. **Two lanes are restructuring the same fork-stock/HAL code from one
   56-commit base, on different hosts.**
   - Local `work/arm-adopt-step5` (`63a7f7666`, 78 commits, codex sol2):
     **blocked**, waiting on a director decision about FrameOwner transfer
     services.
   - carrick-vm `x86-fork-land` (agy, **running**): porting the x86 parts of
     `review/fork-retire-on-26e3` (91 commits).
   - Both branches contain the same 56 ARM-adoption commits. fork-retire
     adds 35 that **unify** child retirement across ISAs; arm-step5 adds 22
     ARM-only commits that keep a separate ARM retire path.
   - Whichever lands second gets the conflict: 21 non-inventory files
     conflict pairwise.
2. **The same bug has been fixed twice, in different code, in several areas.**
   Detail in section 2.2.
3. **Active PRs carry stale duplicates of landed work.**
   - **PR #137** (`work/ring-ipc`) is based on `dfc9100e2`. It carries 12
     pre-rebase identity commits that landed via PR #130, and a **4 MiB** CPL0
     extent (`999c6cdaf`). PR #136 found that 4 MiB overlaps the fixture
     tables at 0x30_0000 and landed 2 MiB instead. Only 4 commits in #137 are
     real IPC work.
   - **PR #131**'s GitHub head (`73cd4e5b9`) is stale: 45 of its 106 subjects
     are already on main. The rebased head `765f0ab08` (76 commits on
     `c9c603b9c`) exists **only on carrick-vm**. The push was blocked by the
     extent limit, which #136 has now removed.
4. **Unpushed sole copies.**
   - arm-step5 tip commits `bd49c09e3`, `535806136` and `63a7f7666` exist
     only on the local Mac.
   - The rebased ring-signals branch exists only on carrick-vm.
   - The 186 subject-unique commits on `work/n1-cm` are on GitHub but in a
     parked draft, and only partly salvaged.
5. **Knowledge has split between workers.**
   - The director told arm-step5 that the KVM `wait4_*rusage*` failures are a
     "pre-existing main defect, tracked separately".
   - ring-signals-sol later proved that the EFAULT-rusage fixture is
     **false on Linux**: the native run also exits 9. The full-rusage overlap
     fixture is also false.
   - None of this is in the repo.
6. **The carrick-vm mirror is out of date.**
   - The bare repo `~/dev/carrick.git` has `main` at `39fbcacb3`, 110 commits
     behind (`gh-main` = `c9c603b9c`, also one behind now).
   - Workers repeatedly reported that `CARRICK_AUTHORITY_BASE=origin/main`
     gated against the wrong base.
   - There are two repos on the VM: worktrees hang off the non-bare
     `~/dev/carrick` clone, whose own `main` is `652e0dcde` (Oct 4,
     996 behind).
7. **Hygiene.**
   - Local: 461 branches, 27 worktrees; about 115 GB is reclaimable in
     landed or disposable worktrees, plus a 74 GB root `target/`.
   - GitHub: 125 branches, 72 of them with merged or closed PRs.
   - carrick-vm: about 25 landed worktrees (~6 GB) plus `wt-cpl0-extent`
     (12 GB, landed).
   - cloudmac: 4 landed `signed-pr*` worktrees plus 8 stale `wt-*` from
     Oct 4-5.

## 1. Inventory

Columns:
- **ahead:** commits ahead of main.
- **subj-uniq:** subject-unique count (see Method).
- **date:** date of the last commit.

### 1.1 Local Mac (`/Volumes/CaseSensitive/carrick`, 27 worktrees)

No agy or codex worker process is running locally: every `*.pid` under
`.../agy-director/local/` is dead. The most recent local worker is
`arm-step5-sol2`, last message 09:14Z. It is blocked on a FrameOwner transfer
decision.

| worktree | branch | head | ahead | subj-uniq | date | owner (meta.json) | size | status |
|---|---|---|---|---|---|---|---|---|
| (root) | main | 0250e7f2a | 0 | 0 | 10-04 | director | target 74G, .sccache 10G | local `main` ref is **1047 behind** origin/main |
| ab-n1cm | work/n1-cm | bbf545fd4 | 517 | 186 | 10-08 | n1-cm-sol/n1-db2..4/n1-g1/g2 | 695M | PARKED (PR #59 draft); ORPHANED-UNIQUE fixes (see 2.1) |
| ab-n1cm-main-baseline | detached | 3de24ed69 | 0 | 0 | 10-08 | - | 231M | LANDED (A/B baseline) |
| ab-n1cm-panic | detached | a6d5d07e5 | 479 | 156 | 10-07 | - | 613M | SUPERSEDED by work/n1-cm (474/474 subjects in n1-cm) |
| arm-flip | docs/arm-ring-first-flip | 94f487d46 | 1 | 0 | 10-08 | arm-flip | 232M | LANDED |
| arm-step5 | work/arm-adopt-step5 | 63a7f7666 | 78 | 77 | 10-10 | arm-step5 / -sol / -sol2 | 57G (56G target) | ACTIVE (blocked on director); 3 tip commits only here |
| arm-step5-first-error | detached | b0052e4fe | 17 | 17 | 10-09 | - | 16G | SUPERSEDED by arm-step5 (all 17 subjects in arm-step5) |
| arm-step5-main-baseline | detached | dfc9100e2 | 0 | 0 | 10-09 | - | 18G | LANDED (A/B baseline) |
| bisect-df605a239 | detached | df605a239 | 356 | 43 | 10-06 | - | 614M | SUPERSEDED (X1-era CPL0 admission, 14 unique subjects, replaced by shared-kernel inversion #104-108; uncertain per commit) |
| el1-inotify | agy/el1-inotify | 7eb9a6853 | 4 | 2 | 09-23 | - | 199M, 1 uncommitted file | SUPERSEDED (delegate/recall design abandoned 09-24) |
| fix-freebsd | fix/freebsd-process-exit-claim | 75187008c | 1 | 0 | 10-07 | - | 231M | LANDED via #110 |
| fixture-lock | fix/fixture-lock-reviewed-versions | 095661042 | 1 | 0 | 10-08 | - | 352M | LANDED (#117) |
| fork-shared-retire | review/fork-retire-on-9d6 | 042cfa479 | 91 | 90 | 10-09 | - | 14G | ACTIVE-PORT source (same SHA as GitHub `review/fork-retire-on-26e3`; being ported on carrick-vm) |
| land-pr62 | detached | 69db26365 | 1 | 0 | 10-05 | - | 228M | LANDED |
| land-x86-fixes | land/x86-standalone-fixes | ed913968e | 3 | 0 | 10-09 | - | 2.1G | LANDED (#133) |
| lease-order | fix/lease-release-ordering | 0c8943ebf | 2 | 0 | 10-08 | lease-sol | 231M | LANDED (#116) |
| lease-zombie | fix/host-lease-zombie-liveness | 68b733a03 | 1 | 0 | 10-07 | lease-gem | 231M | LANDED (#111) |
| n1-bisect | detached | 6607b0281 | 358 | 40 | 10-05 | - | 611M | SUPERSEDED by work/n1-cm |
| n1-files | wip/n1-files-g2-diag-0307 | ce5975e46 | 431 | 110 | 10-07 | n1-files-g2 | 624M | SUPERSEDED by work/n1-cm except one `wip(n1-files)` diagnostic checkpoint |
| ring-switch | work/ring-switch | 21c30ac3d | 42 | 0 | 10-09 | ring-switch / -sol | 44G | LANDED (#132) |
| ring-switch-main-ab-20261009 | detached | 10e41549e | 1 | 1 | 10-09 | - | 20G | disposable A/B control (`test(conformance): add unchanged-main glibc fork control`) |
| rl-shared-kernel | work/shared-kernel | 02c209cea | 476 | 0 | 10-07 | - | 231M | LANDED (#104-108) |
| rl-x86-legacy-retire | work/x86-legacy-retire | c1c2f2f1b | 22 | 19 | 10-08 | - | 231M | SUPERSEDED by GitHub PR #86 head a344ea49a (same subjects, newer rebase) |
| spawn-regress-fixed-pb | detached | 0661cbe3b | 1 | 0 | 10-04 | - | 224M | LANDED |
| wt-remote-gate | work/remote-gate | 935d47a21 | 3 | 0 | 10-03 | - | 223M | LANDED |
| x86-user-ceiling | work/x86-user-ceiling | 34e8d8187 | 2 | 2 | 10-06 | - | 226M | SUPERSEDED: second implementation of the mmap user-VA ceiling. Main landed `a0177ecac` instead. |
| xtask-macos | fix/xtask-macos-tests | 47f24cf70 | 2 | 0 | 10-07 | xtask-gem | 231M | LANDED (#110) |

Local branches: **461**.
- 35 are fully merged (`git branch --merged origin/main`).
- 201 are unmerged but have 0 subject-unique commits: landed by
  patch or subject.
- 225 have at least one subject-unique commit. By last-commit month:
  May 50, Jun 30, Jul 7, Aug 16, Sep 59, Oct 63.
- By prefix: work/* 99, agy/* 93, codex/* 39, preserved-stash/* 16,
  backup/* 13, fix/* 14, feat/* 14, opus/* 8, others.
- The October unique set is listed in section 3.

### 1.2 carrick-vm (`carrick@10.14.14.66`)

The VM has two repos:
- `~/dev/carrick.git`: bare. Its `origin` remote points at itself. It has
  110 branches, 70 of them `fixpub/<sha>` bundle-publication refs.
- `~/dev/carrick`: non-bare clone with 125 branches. **All `~/dev/wt-*`
  worktrees belong to this clone.** Its `main` is `652e0dcde` (Oct 4,
  996 behind) and its `origin/main` is `39fbcacb3`.

Running workers:
- `ring-signals-sol`, pid 682464, in `wt-ring-signals`.
- `x86-fork-land`, pid 650774, in `wt-x86-fork-land`.

Disk: 174G of 246G used, 63G free.

| worktree | branch | head | subj-uniq | date | owner | size | status |
|---|---|---|---|---|---|---|---|
| wt-ring-signals | work/ring-signals | 765f0ab08 | 74 | 10-10 | ring-signals-sol (RUNNING) | 63G | ACTIVE; rebased on c9c603b9c; **not on GitHub** (PR #131 head stale) |
| wt-x86-fork-land | work/x86-fork-land | c9c603b9c (+ uncommitted port) | 0 | 10-10 | x86-fork-land (RUNNING) | 5.9G | ACTIVE: porting fork-retire x86 parts onto 4e63042fe |
| wt-ring-ipc | work/ring-ipc | 70badb62d | 5 | 10-10 | ring-ipc | 30G | ACTIVE (PR #137), needs rebase/cleanup |
| wt-cpl0-extent | work/cpl0-image-extent | facdbfd20 | 1 | 10-10 | cpl0-extent | 12G | LANDED (#136) |
| wt-fdtable | work/shared-fd-table | 84060af42 | 0 | 10-10 | x86-fdtable(-sol) | 238M | LANDED (#135) |
| wt-ring-identity | work/ring-identity | b8730fee3 | 0 | 10-10 | ring-identity(-sol) | 237M | LANDED (#130) |
| wt-ring-sched | work/ring-sched | 4d1d06921 | 0 | 10-10 | ring-sched(-sol) | 237M | LANDED (#134) |
| wt-land-x86 | detached | be9c604f2 | 0 | 10-09 | - | 236M | LANDED (#133) |
| wt-review-switch | detached | bad35bc69 | 0 | 10-09 | - | 236M | LANDED (#132) |
| wt-main-ab | detached | dfc9100e2 | 0 | 10-09 | - | 236M | disposable baseline |
| wt-x86-diag | work/x86-n1-diag | 015a9bb84 | 247 | 10-08 | x86-diag | 628M | PARKED (PR #119 draft) |
| wt-x86-anon | work/x86-process-owner-resume | e9eb22e1f | 228 | 10-08 | x86-anon-sol2/x86-fork-2/x86-fork-sol | 237M | PARKED (= GitHub work/x86-process-owner) |
| wt-x86-legacy | work/x86-legacy-retire | a344ea49a | 19 | 10-08 | x86-retire-final | 235M | ACTIVE (PR #86) |
| wt-x86-entry | work/x86-entry-unify | 18d8cec53 | 0 | 10-08 | x86-entry-gem | 236M | LANDED |
| wt-x86-shared-fixes | work/shared-x86-fork-fixes | 7cab20c99 | 0 | 10-08 | - | 235M | LANDED (#120) |
| wt-process-owner-main | work/shared-process-owner | 344812665 | 0 | 10-08 | - | 236M | LANDED (#121) |
| wt-review121-{ci-lint,ci-runtime,exit-effects,isa,kvm-boundary,wait} | work/review121-* | various | 0-1 | 10-08 | rev121 | 6 x 236M | LANDED via #121 (`wt-review121-wait` has 1 uncommitted file; `review121-exit-effects` has 1 unique subject, check) |
| wt-x86-anon-main-classify | detached | 048c2b6c1 | 0 | 10-08 | - | 235M | disposable baseline |
| wt-buildcode | fix/fixture-lock-reviewed-versions | 773d23573 | 0 | 10-08 | buildcode-sol | 235M | LANDED (#117) |
| wt-buildrs | fix/vmm-kvm-build-no-nested-cargo | f6322220b | 0 | 10-08 | buildrs-sol | 236M | LANDED (#118) |
| wt-mem-race | fix/mem-snapshot-deadline-race | 5c1de8dc7 | 0 | 10-08 | memrace-gem | 235M | LANDED (#115) |
| wt-resv | work/resv-double-free | db716c74e | 0 | 10-08 | resv-* | 235M | LANDED (#112) |
| wt-inv | work/inv-pr1 | c10d9bfb3 | 0 | 10-08 | inv-sol | 235M | LANDED |
| wt-inv-review | detached | b476c25c1 | ? | 10-08 | review-51(b) | 234M | review scratch |
| wt-merge-queue | work/merge-queue | 43bc3bd87 | 3 | 10-04 | - | 229M | SUPERSEDED (merge queue live) |
| wt-n2b-core | work/n2b-core | 5687724d7 | 0 | 10-04 | - | 226M | LANDED |
| wt-x86-x1a | work/x86-x1a | 1bbc39005 | 55 | 10-06 | - | 289M, 3 dirty files | SUPERSEDED (PR #64 closed; X1 wave inverted) |
| wt-m2-kvm | (no .git) | - | - | - | - | 114M | ORPHAN directory |
| wt-lease-leak-review (bare repo wt) | detached | 9ae96f130 | - | 10-04 | - | - | prunable |

The VM also has 10-04 to 10-08 bundles and briefs in `~/dev`
(`x86-anon-wip.bundle`, `*.md`, `*-evidence/`). `/tmp` holds `inv-*sysroot`
(~0.9G) and `sk-verify-target` (1.1G).

### 1.3 cloudmac (`rentamac@cloudmac`)

Two repos: `/Volumes/carrick/dev/carrick.git` (bare; `main` `8b6cf9031`
10-04, `github/main` fetched 10-08; 137 branches, 116 of them `gate/*`) and
`/Volumes/carrick/dev/carrick` (clone; `main` 10-03, `github/main` 10-07).
The SSD `/Volumes/carrick-build` is 53% used.

| worktree | head | date | size | status |
|---|---|---|---|---|
| gate-worktree | 8d615fac4 | 10-10 | 1.6G | LANDED (= main 476c73a65 by subject); live gate scratch |
| signed-main | cb835a712 | 10-10 | 627M | stale main checkout |
| signed-pr130 / pr134 / pr135 / pr136 | b8730fee3 / 4d1d06921 / 84060af42 / facdbfd20 | 10-10 | 628M each | LANDED, deletable |
| wt-attrib-main | f0e9a3265 | 10-05 | 656M | stale |
| wt-build-cache-proof | 53dc33549 | 10-05 | 225M | stale |
| wt-elf-fix | c98fd647f (work/elf-fix) | 10-04 | 226M | PR #35 closed; 0 unique |
| wt-fes-load | bedfd58cd | 10-04 | 1.4G | PR #20 closed; 0 unique |
| wt-hosted-mac | d196e752d | 10-04 | 227M | PR #42 closed; 0 unique |
| wt-n1-p4 | a0ead6ea5 | 10-04 | 227M | PR #21 draft (stale N1 p4) |
| wt-pool-guard | f6870ea6a | 10-04 | 226M | PR #37 closed; 0 unique |
| wt-storm | dd75266a3 | 10-05 | 618M | PR #49 closed |

Other cloudmac data: `evidence` 12G, `sccache` 14G, `home` 13G,
`fixtures` 1G. Unique refs on cloudmac only:
- `n1-cm-before-order4-ee105fb96`: missing locally; an older N1 snapshot.
- `work/n1-cm` `cad5ae1f8`: an older copy of GitHub `work/n1-cm`.

### 1.4 GitHub (`carrick-sh/carrick`, 125 branches)

Open PRs:
- Active: #137, #131, #86.
- Drafts: #119, #90, #66, #59, #52, #44, #31, #29, #28, #27, #21, #16,
  #14, #11.
- #11, #14, #16 and #21 are CONFLICTING.

Remote branches by PR state: 60 CLOSED, 12 MERGED, 17 OPEN, 34 without a PR.
The local clone also has 64 stale remote-tracking refs
(189 tracked vs 125 live).

| branch | head | ahead | subj-uniq | date | PR | status |
|---|---|---|---|---|---|---|
| fix/el1-grant-handback | 6569af7b6 | 0 | 0 | 2026-09-27 | - | LANDED |
| wip-2.3-fix | 31ca9d8e9 | 4 | 4 | 2026-09-27 | - | SUPERSEDED/CHECK |
| wip/el1-anon-mmap-2.3 | 8a5553abe | 1 | 1 | 2026-09-27 | - | SUPERSEDED/CHECK |
| work/futex-per-kernel | b5cbc4096 | 6 | 0 | 2026-10-04 | CLOSED#17 | LANDED |
| work/batch4-linux-reconcile | 11a2e045c | 1 | 0 | 2026-10-04 | - | LANDED |
| work/spawn-regress | 2e92bc045 | 6 | 0 | 2026-10-04 | CLOSED#8 | LANDED |
| work/fes-load | bedfd58cd | 7 | 0 | 2026-10-04 | CLOSED#20 | LANDED |
| work/willow-pilot | df0ca8195 | 24 | 0 | 2026-10-04 | CLOSED#18 | LANDED |
| work/flash-persona | 4c11d300d | 2 | 0 | 2026-10-04 | CLOSED#15 | LANDED |
| work/n1-p2 | 41fe977bc | 159 | 12 | 2026-10-04 | OPEN#11 | ACTIVE (draft, stale) |
| work/flash-x86parity | 93d44690e | 2 | 0 | 2026-10-04 | CLOSED#13 | LANDED |
| work/x86-m3 | 786f6f4b3 | 155 | 8 | 2026-10-04 | CLOSED#7 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/n1-p1 | 09cf6a56b | 159 | 12 | 2026-10-04 | OPEN#14 | ACTIVE (draft, stale) |
| work/n2-audit | 94567dd6f | 2 | 2 | 2026-10-04 | CLOSED#25 | ORPHANED-UNIQUE (n2 readiness plan doc) |
| work/abi-meta | d51757343 | 1 | 0 | 2026-10-04 | CLOSED#33 | LANDED |
| work/fixtures-nodocker | e9c1e032f | 9 | 0 | 2026-10-04 | CLOSED#10 | LANDED |
| land/batch5 | 51bfe67f4 | 0 | 0 | 2026-10-04 | MERGED#40 | LANDED |
| work/merge-queue | 0410065d0 | 2 | 2 | 2026-10-04 | CLOSED#2 | SUPERSEDED (merge queue live on main) |
| work/n1-p3 | 3db84db7c | 159 | 12 | 2026-10-04 | OPEN#16 | ACTIVE (draft, stale) |
| work/batch4-futex-replay | 16516bf7c | 1 | 0 | 2026-10-04 | - | LANDED |
| work/elf-fix | c98fd647f | 6 | 0 | 2026-10-04 | CLOSED#35 | LANDED |
| work/pool-guard | f6870ea6a | 1 | 0 | 2026-10-04 | CLOSED#37 | LANDED |
| work/hosted-mac | 5e996d351 | 41 | 0 | 2026-10-04 | CLOSED#39 | LANDED |
| work/hosted-mac-jit | d196e752d | 2 | 0 | 2026-10-04 | CLOSED#42 | LANDED |
| work/n2-l2 | ac995a3f7 | 1 | 1 | 2026-10-04 | OPEN#31 | ACTIVE draft, stale; ORPHANED-UNIQUE N2 red witnesses |
| work/n2-l5 | c6e85d291 | 1 | 0 | 2026-10-04 | CLOSED#32 | LANDED |
| work/n2-l1 | 46abf774e | 1 | 1 | 2026-10-04 | OPEN#29 | ACTIVE draft, stale; ORPHANED-UNIQUE N2 red witnesses |
| work/n2-l3 | 89e183f42 | 1 | 1 | 2026-10-04 | OPEN#28 | ACTIVE draft, stale; ORPHANED-UNIQUE N2 red witnesses |
| work/n2-l4 | 2e6abf504 | 1 | 1 | 2026-10-04 | OPEN#27 | ACTIVE draft, stale; ORPHANED-UNIQUE N2 red witnesses |
| work/n1-p4 | a0ead6ea5 | 154 | 7 | 2026-10-04 | OPEN#21 | ACTIVE (draft, stale) |
| work/lease-leak | 9ae96f130 | 19 | 0 | 2026-10-04 | CLOSED#6 | LANDED |
| work/flash-ns-seed | 80f362b32 | 1 | 1 | 2026-10-04 | CLOSED#23 | ORPHANED-UNIQUE (flake evidence README + seed sweep) |
| work/flash-futex-seed | 391fae5ea | 1 | 1 | 2026-10-04 | CLOSED#22 | ORPHANED-UNIQUE (flake evidence README + seed sweep) |
| work/willow-pilot-workflow | 02d0500a6 | 1 | 0 | 2026-10-04 | MERGED#12 | LANDED |
| work/vmfree-m2 | dd5808a2e | 24 | 0 | 2026-10-04 | CLOSED#1 | LANDED |
| work/x86-i1 | 681f35571 | 1 | 0 | 2026-10-04 | CLOSED#26 | LANDED |
| work/x86-i2 | d08aad46b | 1 | 0 | 2026-10-04 | CLOSED#30 | LANDED |
| work/x1-arm-regress | 0feb7c7b0 | 369 | 51 | 2026-10-05 | CLOSED#70 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/x86-wave2-plan-main | 289e8d797 | 3 | 3 | 2026-10-05 | CLOSED#67 | ORPHANED-UNIQUE doc (wave2 plan, inverted 10-06) |
| work/elastic-design | a98b655f5 | 4 | 0 | 2026-10-05 | CLOSED#4 | LANDED |
| work/affinity-migration | dd75266a3 | 10 | 2 | 2026-10-05 | CLOSED#49 | SUPERSEDED/CHECK |
| work/x86-audit | a9a39db0c | 2 | 2 | 2026-10-05 | CLOSED#24 | ORPHANED-UNIQUE doc, superseded by inversion plan |
| land/batch8 | 87aeb82d3 | 6 | 0 | 2026-10-05 | MERGED#58 | LANDED |
| work/persona-design | 486394ebf | 2 | 0 | 2026-10-05 | CLOSED#19 | LANDED |
| work/x86-a-imagedeps | 9bc49cadf | 318 | 23 | 2026-10-05 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/n1-fork | df282f8bd | 222 | 10 | 2026-10-05 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/fixture-scope | 805eada21 | 2 | 0 | 2026-10-05 | CLOSED#43 | LANDED |
| work/inv-pr5 | 9847585b7 | 4 | 0 | 2026-10-05 | CLOSED#45 | LANDED |
| work/inv-pr34 | 4d5915953 | 3 | 0 | 2026-10-05 | CLOSED#47 | LANDED |
| work/tlb-ack-terminal | 111d92ecf | 2 | 0 | 2026-10-05 | CLOSED#55 | LANDED |
| work/remote-bundle | 564b0c996 | 4 | 0 | 2026-10-05 | CLOSED#54 | LANDED |
| work/x86-b | 804018d23 | 262 | 12 | 2026-10-05 | CLOSED#60 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/ci-green | bcd1f5df7 | 37 | 0 | 2026-10-05 | CLOSED#3 | LANDED |
| work/build-cache | e9f37be53 | 18 | 0 | 2026-10-05 | MERGED#5 | LANDED |
| work/m2-kvm | 11fac0d7b | 4 | 0 | 2026-10-05 | CLOSED#34 | LANDED |
| work/socket-dispatch | 4282a08a4 | 1 | 0 | 2026-10-05 | CLOSED#50 | LANDED |
| work/x86-a-faultfix | c4e7eba4d | 295 | 20 | 2026-10-05 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/x86-a-cowfix2 | e6e6eb7c1 | 295 | 20 | 2026-10-05 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| land/batch6 | b2e77e2ff | 0 | 0 | 2026-10-05 | MERGED#53 | LANDED |
| work/n1-filemap-wip | 3c5113bda | 348 | 30 | 2026-10-05 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/ci-unit-shard | a3f9b2d5b | 1 | 1 | 2026-10-05 | OPEN#44 | ACTIVE (PR44 draft, stale) |
| work/inv-pr2 | 35e803b1b | 1 | 0 | 2026-10-05 | CLOSED#46 | LANDED |
| work/x86-a | 26b1548d9 | 334 | 26 | 2026-10-05 | CLOSED#61 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/n1 | 56bf8c0ca | 347 | 29 | 2026-10-05 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| land/batch7 | 80bc107de | 0 | 0 | 2026-10-05 | MERGED#57 | LANDED |
| work/ci-restructure | 48c1d9c41 | 0 | 0 | 2026-10-05 | MERGED#41 | LANDED |
| work/affinity-el1-zone | 31c830e39 | 10 | 3 | 2026-10-05 | OPEN#52 | ACTIVE (PR52 draft, stale) |
| work/vfork-hook-scope | 0310780a5 | 2 | 0 | 2026-10-05 | CLOSED#56 | LANDED |
| work/wallclock-sweep | 4ab04bfd0 | 4 | 0 | 2026-10-05 | CLOSED#48 | LANDED |
| work/x86-i4 | ec5aaaf7d | 1 | 0 | 2026-10-05 | CLOSED#38 | LANDED |
| work/x86-i3 | ced34acc4 | 1 | 0 | 2026-10-05 | CLOSED#36 | LANDED |
| land/pr87 | 06607ada3 | 7 | 0 | 2026-10-06 | - | LANDED |
| work/proc-uptime-host-bound | 65bcb1539 | 2 | 0 | 2026-10-06 | MERGED#84 | LANDED |
| work/launch-trace-flag | f73f9e189 | 3 | 2 | 2026-10-06 | OPEN#90 | ACTIVE (PR90 draft, stale) |
| work/shared-kernel-inversion-plan | e42dc0a4d | 3 | 3 | 2026-10-06 | CLOSED#72 | ORPHANED-UNIQUE doc + census tool (plan executed via #104-108) |
| work/x86-wave2-plan | 3f91c9bc5 | 149 | 7 | 2026-10-06 | CLOSED#65 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/sk-mmu | 6acc625ed | 415 | 32 | 2026-10-06 | CLOSED#76 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/x86-x1a | 1bbc39005 | 373 | 55 | 2026-10-06 | CLOSED#64 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/layout-tools | 23de5c610 | 364 | 29 | 2026-10-06 | CLOSED#73 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/x86-ord5 | 926ccbd46 | 366 | 30 | 2026-10-06 | CLOSED#68 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/x86-ord6 | 904fd644b | 374 | 31 | 2026-10-06 | CLOSED#71 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/mm-pub-v2 | 9bf9d2241 | 500 | 37 | 2026-10-06 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/x86-ord4 | 246038022 | 345 | 29 | 2026-10-06 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/cpl0-dep | 0d6f1bba5 | 1 | 0 | 2026-10-06 | MERGED#62 | LANDED |
| work/accept-deps | f79cbb361 | 1 | 0 | 2026-10-06 | MERGED#88 | LANDED |
| work/ci-sccache | f922e70b5 | 2 | 0 | 2026-10-06 | MERGED#63 | LANDED |
| work/gate-hygiene | 0903c836a | 2 | 2 | 2026-10-06 | OPEN#66 | ACTIVE (PR66 draft, stale) |
| work/n1-sigframe-draft | e8cbf3744 | 386 | 67 | 2026-10-06 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/sk-user | 63edab813 | 372 | 29 | 2026-10-06 | CLOSED#74 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/x86-va-ceiling | 59e01e072 | 375 | 31 | 2026-10-06 | CLOSED#77 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/syscall-abi-crate | 97fa80542 | 466 | 36 | 2026-10-06 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/anon-generic | 261f5721a | 482 | 51 | 2026-10-06 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/sk-mmu-fork | 519c1fe36 | 420 | 32 | 2026-10-06 | CLOSED#78 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/backend-target-select | 48c73b1c3 | 4 | 4 | 2026-10-06 | - | ORPHANED-UNIQUE (no PR; BSD lanes via syscall shim) |
| work/x86-fork-e2e | f114c0777 | 489 | 59 | 2026-10-06 | CLOSED#82 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/x86-mm-owner | e3672b6b4 | 431 | 33 | 2026-10-06 | CLOSED#80 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/futex-halt-poll-determinism | 52b203dd6 | 2 | 0 | 2026-10-06 | MERGED#69 | LANDED |
| work/sk-gates | 735a08c59 | 485 | 37 | 2026-10-06 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/sk-mmu-legacy | 15a685fb1 | 421 | 32 | 2026-10-06 | CLOSED#79 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| wip/n1-cm-codex-stop | 8a2d52df7 | 400 | 81 | 2026-10-06 | - | SUPERSEDED by work/n1-cm |
| work/x86-run | 7e77db9fd | 524 | 70 | 2026-10-07 | CLOSED#81 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/shared-kernel | 02c209cea | 476 | 0 | 2026-10-07 | CLOSED#75 | LANDED |
| work/x86-entry-unify2 | b745f87f1 | 509 | 23 | 2026-10-07 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/n1-cm-panic-diag | a6d5d07e5 | 479 | 156 | 2026-10-07 | - | SUPERSEDED by work/n1-cm (subject subset) |
| fix/freebsd-process-exit-claim | 75187008c | 1 | 0 | 2026-10-07 | CLOSED#109 | LANDED |
| work/x86-anon-cpl0 | 83364467d | 580 | 105 | 2026-10-07 | CLOSED#102 | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| archive/shared-kernel-pre-land-d355743b2 | d355743b2 | 482 | 10 | 2026-10-07 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/shared-kernel-scorecard | 6261fd7e3 | 484 | 12 | 2026-10-07 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/x86-cpl0-input-authorities | d1cdac6bf | 508 | 54 | 2026-10-07 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| archive/x86-entry-unify-pre-rebase-ccb413b96 | ccb413b96 | 505 | 39 | 2026-10-07 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| wip/shared-kernel-codex-stop | 577e01fc8 | 498 | 38 | 2026-10-07 | - | SUPERSEDED (pre-inversion x86/N1 wave; content re-landed via #104-108/#120/#121 or parked in n1-cm) |
| work/x86-legacy-retire | a344ea49a | 21 | 19 | 2026-10-08 | OPEN#86 | ACTIVE (PR86, green CI, 269 behind) - ORPHANED-UNIQUE TLS/arch_prctl |
| docs/arm-shared-owner-adoption | c770fc91d | 1 | 0 | 2026-10-08 | - | LANDED |
| work/x86-process-owner | e9eb22e1f | 1652 | 228 | 2026-10-08 | - | PARKED - shared fixes extracted to PR120/121 |
| work/x86-n1-diag | 015a9bb84 | 1672 | 247 | 2026-10-08 | OPEN#119 | PARKED (PR119 draft) - merge-based lane, some ORPHANED-UNIQUE |
| fix/fixture-lock-reviewed-versions | 773d23573 | 2 | 0 | 2026-10-08 | - | LANDED |
| work/n1-cm | bbf545fd4 | 517 | 186 | 2026-10-08 | OPEN#59 | PARKED (PR59 draft) - holds ORPHANED-UNIQUE fixes |
| work/arm-step5-review | 9d62964fd | 56 | 55 | 2026-10-09 | - | SUPERSEDED by local work/arm-adopt-step5 (56/56 subjects; local has 22 more) |
| review/fork-retire-on-26e3 | 042cfa479 | 91 | 90 | 2026-10-09 | - | ACTIVE-PORT (being ported by carrick-vm x86-fork-land) |
| work/fork-shared-retire | edeb17b82 | 60 | 59 | 2026-10-09 | - | SUPERSEDED by review/fork-retire-on-26e3 |
| gh-readonly-queue/main/pr-136-c9c603b9cf5755c256b87dae257d3546281ce5aa | 4e63042fe | 1 | 1 | 2026-10-10 | - | LANDED (queue ref, auto-deleted) |
| work/cpl0-image-extent | facdbfd20 | 1 | 1 | 2026-10-10 | MERGED#136 | LANDED (PR136 = 4e63042fe) |
| work/ring-signals | 73cd4e5b9 | 107 | 61 | 2026-10-10 | OPEN#131 | ACTIVE (PR131; GitHub head STALE, newer 765f0ab08 on carrick-vm only) |
| work/ring-ipc | 70badb62d | 19 | 5 | 2026-10-10 | OPEN#137 | ACTIVE (PR137; carries 12 stale identity commits + 4 MiB extent 999c6cdaf) |
| main | c9c603b9c | 0 | 0 | 2026-10-10 | - | main |

## 2. Unshared or duplicated knowledge

### 2.1 ORPHANED-UNIQUE commits worth keeping

**A. `work/arm-adopt-step5` (local only for the tip).**
- `bd49c09e3` fix(runtime): authenticate grant crossings with parked address
  identity.
- `535806136` fix(abi): refresh x86 pin for the shared fd table layout.
- `63a7f7666` fix(hal): separate native frame custody in the shared
  inventory. This introduces `HostMm` vs `GuestMm(native_mm,
  root_generation)` rows in one inventory.

These are the current ARM shared-owner frontier. Push them to a GitHub
branch now: their only other copy is the VM `fixpub/*` refs, which stop at
`1adf07e0c`.

**B. `work/ring-signals` `765f0ab08` (carrick-vm only).** 76 commits rebased
on `c9c603b9c`; the worker reports it review-ready. Only-here commits
include:
- fix(x86): retain fixture xstate through task switches
- fix(x86): require process admission before timer expiry
- fix(kvm): preserve typed signal status through root exit custody
- fix(arch): admit carrier-owned arm signal crossings
- test(kvm): require in-ring default sigsegv termination

The GitHub PR #131 head does not contain these.

**C. `work/x86-legacy-retire` (PR #86, a344ea49a, CI green, 269 behind).**
- `f746caeb3` fix(x86): serve task tls and clear-tid registration in cpl0.
- `a69ebe08b` fix(x86): admit native tls calls and gate retired lane
  coverage.
- `47f918253` refactor(x86): keep linux tls policy in the personality.
- The deletion of `kvm_x86_engine.rs`, `run_elf_x86.rs` and
  `guest_setup_x86.rs` (still present on main).
- `docs/retirements/x86-kvm-run-elf.md` and
  `docs/retirements/x86-legacy-syscall-audit.md`.

Main lanes still list `arch_prctl` as a **main failure** (x86-fork-land
baseline on 4e63042fe: `x86_kvm_run` fails arch_prctl, elf_matches,
adjacent_anonymous). PR #86 serves `arch_prctl`. Its clear-tid half is now a
duplicate (see 2.2).

**D. `work/n1-cm` (PR #59 draft, 186 subject-unique).** EL1 delegated-MM
(N1) fixes with no subject or keyword match on main (checked with keyword
greps for MAP_STACK, getdents, pathname, producer revision, grant slot,
read prefix):
- `b5980416d` fix(runtime): serve advisory MAP_STACK reservations in EL1.
  x86-n1-diag also relies on "N1 advisory MAP_STACK admission".
- Owner-wait copyout retention:
  - `919bb7e23` getdents/readlink
  - `3df4a205f` stat
  - `770860e4b` signal frames
  - `07081da64` pathname resolution
  - `807f5f858` guest input copies
  - `d559ef7b4` pipe creation
  - `445b522e6` vector ipc
  - `a47d49346` ipc copyout
- `f0059acd1` fix(runtime): preserve ipc read prefixes when a peer reaches
  eof.
- Scheduler wakes:
  - `cad5ae1f8` unlock resource before advancing producer revision
  - `d221b3d49`, `751b0ec63`, `3f0762f65`: completion handback drain/dedupe
  - `b05cc4214` recheck active editor before parking
  - `8f7cbc1a0` wake owner metadata waiters
- Grant slots and mailbox:
  - `025c4a558` fail-closed grant slots and exact mailbox cancellation
  - `7a0fce9a2` reclaim stale grant slot/mailbox requests
  - `017234a38` park busy owner faults and retire stale grant slots
- Fork, owner and COW (`99ce82217`, `1e746c2c4`, `b9288897b`, `f6d731f37`,
  `ad16fe6bf`, `8bd4d45a7`, `bd6fe3285`, `b047c48ed`, `853534225`,
  `181bf50fd`, `62e279cf4`).
- Docs:
  - `docs/diagnostics/n1-ipc-ebusy.md`
  - eleven `docs/perf-results/2026-10-0[56]-n1-*.md` handoffs

Status of these: **uncertain per commit.** Some may be obsolete after the
ring-first and shared-owner direction. `0565ec758` and `bbf545fd4` were
already salvaged as PR #128 `6f0db0dc4`. None of the rest has a home.

**E. `work/x86-n1-diag` / `work/x86-process-owner` (parked,
merge-structured, 247 / 228 subject-unique).** Mostly pre-inversion history
merged rather than rebased. The parts not on main:
- `docs/diagnostics/x86-native-signal-startup.md` (8 signal-startup
  dependencies closed natively)
- `docs/diagnostics/x86-native-stdio-poll-design.md` (FileTableId/poll
  design, deferred until fork-stock landed)
- `docs/diagnostics/x86-n1-fork-stock.md`
- `docs/x86-anon-cpl0-handoff.md` (process-owner extraction design)

Code beyond what #120/#121 extracted is **uncertain**.

**F. Evidence and plans on closed or abandoned PRs.**
- `work/flash-futex-seed` (README 388 lines, futex wake flake) and
  `work/flash-ns-seed` (README 117 lines, namespace lower copy-up flake).
  AGENTS.md calls flakes architectural flaws. If these flakes are not
  fixed, the evidence is the only record. Uncertain whether #69 and
  `work/flaky-sched` closed both.
- `work/n2-l1..l4` (PRs #27-31): about 2,400 lines of N2 red witnesses.
- `work/n2-audit`: N2 readiness plan.
- `work/x86-wave2-plan-main`: wave-2 plan, 808 lines.
- `work/shared-kernel-inversion-plan`: inversion plan and census tool,
  1,988 lines.
- `work/backend-target-select`: BSD lanes via syscall shim; no PR.
- Local `.worktrees/EL1-HANDOFF-2026-09-29.md` and
  `.worktrees/lease-leak-review2.md`: untracked, Mac only.

### 2.2 Fixes implemented twice

| problem | implementation 1 | implementation 2 | state |
|---|---|---|---|
| Committed child exit fails with NativeBusy while parent wait holds the channel bucket (`native_process_runtime.rs`, publish_channel/wake path) | main `e3ddd4d91` fix(runtime): complete committed parent wakes under contention (ring-identity lane, 13:28Z, PR #130) | carrick-vm ring-signals `396312aa3` fix(portable): retain process wake publication under contention (14:08Z). It was written **after** rebasing onto a main that already contained e3ddd4d91; it advances the channel generation unconditionally. | Both now stack on the same function. Review whether 396312aa3 is still needed or now redundant (uncertain). |
| Retire child space entries after the final MM exit | arm-step5 `ed6966683` (ARM, `aarch64_process.rs`, +162) | fork-retire `edeb17b82`/`b64e5eb3e` (x86, `carrick-x86-cpl0/native_process.rs`, +56), later unified by `refactor(portable): share one retired child space queue across isas` on fork-retire | arm-step5 keeps the ARM-only version; fork-retire has the unified one. x86-fork-land is porting the unified one. |
| CPL0 clear-tid / `set_tid_address` registration | PR #86 `f746caeb3` + `d24b7b625` (10-08) | main `a195bacc6` fix(identity): serve cpl0 clear-tid registration for libc startup (10-10) | Main version landed; PR #86 must drop its copy on rebase. |
| CPL0 supervisor image too small | main `a0a1b1ce5a` raises the cap 1 MiB to 0x120000 (signals fixture lane, via #130); main `436bdfa8b` (cherry-picked `99215dbcf`) derives the fixture table start | PR #136 `4e63042fe` raises it to 2 MiB with one typed authority (landed) | ring-ipc `999c6cdaf` sets **4 MiB**, which #136 showed overlaps 0x30_0000. It is a third implementation and a latent layout bug if rebased naively. |
| mmap placement bounded by the per-ISA user VA ceiling | main `a0177ecac` fix(x86): use the guest user limit for mmap placement | local `x86-user-ceiling` `a84c3b633` (carrick-abi / dispatch mem.rs, +195 tests) | Main version landed; the local one is superseded. |
| Transient root contention (Busy) aborting the carrier | n1-cm `0565ec758`, `bbf545fd4` | main `6f0db0dc4` (PR #128, busy-fwd port) | Salvaged correctly. Example of a fix that is invisible to `git cherry`. |
| NativeRunFailure transport | ring-signals `1f1e4f0a4` (transport bundled with signal runtime) | landed via identity as `3f36d3c2c` feat(x86): transport authenticated native run failures | Signals must drop its copy; ring-identity-sol noted "Signals can drop its counter commit on rebase". |
| Task submission directory generic | main `ed4862484` | arm-step5 `c9357476b` (same subject, 8-line rebase residue) | Rebase artifact; drop or squash. |

### 2.3 Lanes that will conflict when landed

Pairwise `git merge-tree` on the current heads. Counts are conflicting
files excluding inventory JSON.

| pair | conflicting files | hotspots |
|---|---|---|
| arm-step5 x fork-retire | 21 | `carrick-el1-abi/src/fork_stock.rs`, `lib.rs`, `aarch64_process.rs` (+tests), `personality/dispatch.rs`, `personality/mod.rs` |
| arm-step5 x ring-signals (VM head) | 5 | `carrick-core/src/wait.rs`, `carrick-el1-abi/src/lib.rs`, `native_process_runtime.rs`, `sched-core/src/tests.rs`, `x86-cpl0/src/native_execution.rs` |
| arm-step5 x ring-ipc | 22 | `dispatch.rs`, `lifecycle.rs`, `native_process_runtime.rs`, `process_owner.rs`, `x86_kvm_run.rs`, `surfaces.toml` |
| ring-ipc x ring-signals (VM) | 26 | same; plus x86 identity fixtures, because ring-ipc carries the pre-rebase identity commits |
| fork-retire x ring-signals (VM) | 15 | `wait.rs`, `fork_stock.rs`, `native_process_runtime.rs`, `process_owner.rs` |
| x86-legacy-retire (PR #86) x every active lane | 10-13 | `personality-linux/{dispatch,entry,lifecycle}.rs`, `cpl0_boot.rs`, `x86-cpl0/src/entry.rs`, `syscall-abi/src/lib.rs` |
| n1-cm x anything | 17-24 | `core-abi/mm/grant_slot.rs`, `reservation/root.rs`, `mm_portal/fork.rs`, `dispatch/fs/rw.rs` (not landable as is) |

Semantic conflicts (no textual overlap required):
- **CPL0 carrier port 0xd5.** On fork-retire, `NATIVE_CHILD_RETIRE_PORT` is
  0xd5. Main took 0xd5 for `NATIVE_RUN_FAILURE_PORT` (`3f36d3c2c`).
  x86-fork-land noticed and moved to 0xd6.
  - Main **also** defines `X86_INITIAL_RUNNER_READY_PORT = 0xd5` (from
    `fc84cd9cc`). The two are consumed in different phases (boot handshake
    vs run), so this is probably not a live bug.
  - Main has no pairwise-distinct port check. That check exists only in
    fork-retire (`fix(kvm): check every cpl0 carrier port pairwise at
    compile time`).
  - **Uncertain** whether the runner-ready reuse is intended.
- **ARM signal routing.** arm-step5 has `057ae8844` (retain rt_sigaction
  kernel fallback on arm) and `a9c3a5773` (scope arm signal opt-out to fork
  witness). ring-signals has "admit carrier-owned arm signal crossings" and
  "preserve main arm signal lifecycle routes". Both edit ARM signal
  dispatch policy in `personality/dispatch.rs`, in opposite directions.
- **Identity obligation on ARM.** The director told arm-step5-sol2: when the
  ARM scheduler resumes a parked lifecycle it must call
  `resume_pending_lifecycle()` and route `take_run_failure()` to
  `complete_native_run_failure`. This lives only in a mailbox.
- **EL1 ABI layout hashes and line-pinned inventories.** Every lane
  refreshes them, which guarantees conflicts in `carrick-el1-abi/src/lib.rs`
  and the inventory JSON. 86 of 1,241 main commits since 10-03 (7%) are
  inventory, position or recapture churn.

### 2.4 Facts one worker found that others lack

All found in mailboxes; none appears in the repo.

1. **False fixtures.**
   - ring-signals-sol: the EFAULT `wait4` rusage fixture is false on Linux
     ("native exits9 too"), and so is the full-rusage buffer overlap. These
     are `cpl0_fork_e2e::wait4_rejects_unwritable_rusage_without_writing_status`
     and `wait4_zeroes_the_full_rusage_record`.
   - The director had told arm-step5 these are "a pre-existing main defect,
     tracked separately".
   - x86-fork-land's baseline still counts `cpl0_fork_e2e 2` failures on
     4e63042fe.
2. **False green.** x86-fdtable-sol: the "KVM stdout poll fixture 1/1 remains
   a known false green".
3. **Main KVM baselines.** Workers recorded different sets without a ledger:
   - ring-signals-sol on c9c603b9c: 5 named x86_kvm_run failures
     (guest_owned_calls_refuse, poll_stdio, arch_prctl,
     elf_matches_native_anonymous_memory, adjacent_anonymous_memory).
   - x86-fork-land on 4e63042fe: carrick-vmm-kvm cpl0_entry 3,
     cpl0_fork_e2e 2, cpl0_lifecycle 1, live_vcpu_x86 1; x86_kvm_run 3.
   - x86-fdtable-sol: 3 failures (anonymous leaf, TLS bases, anonymous
     memory).
4. **Pre-existing lint debt** that each worker rediscovered:
   - five native asm review sites in `context_resume.rs`,
     `native_execution.rs`, `native_process.rs` fail `lint-domains`
     (x86-diag);
   - `probes.rs` HA-000466 host-authority drift (resv-pr-gem);
   - `cargo clippy -p carrick-runtime --features platform-linux` reports
     117 dead-code errors, and the default runtime clippy cannot build on
     Linux (x86-fork-final);
   - a `nonminimal_bool` in `carrick-kernel/src/kernel/objects/thread.rs`,
     fixed only on ring-signals (`a84eb60bf`).
5. **Mirror lag.** ring-identity-sol, three times: "local origin mirror
   main still advertises dfc9100e2 / 482e5ea89", so
   `CARRICK_AUTHORITY_BASE=origin/main` gated against a stale base. It is
   still true: bare `main` 39fbcacb3 vs GitHub 4e63042fe.
6. **Test-isolation defect.** arm-step5-sol: the carrier-global test
   `holds_and_rolls_back_the_exact_carrier_lease` sees registered
   containers 1 vs 0 under parallel tests and passes serially. Recorded as a
   pre-existing follow-up; no owner.
7. **Unowned follow-ups.**
   - x86 idle-peer host SyscallTrap handback: main `wait_in_guest` rejects
     SyscallTrap on a production idle-peer slot. Named for the x86 in-kernel
     fork lane.
   - x86 x5 upper-word-zero identical on main (ring-identity-sol).
   - Prefork A/B 6/50 vs 5/50 (x86-anon-sol2).
8. **Root-cause notes in diagnosis lanes.**
   - n1-cm-db: duplicate `free_node` at `root_prepared.rs:184`, and invalid
     active-free-head assertions corrected by tagged-head CAS (`9b06b4184`).
   - n1-db3: a live-vs-manager COW classification divergence hypothesis.
   - Neither is in `docs/` on main.
9. **Fixture build-code gap.** n1-db3: main's reviewed-build-code lacked the
   serde_derive and zerocopy versions. Fixed by #117, but other lanes
   rediscovered it.


## 3. Hygiene

### 3.1 Worktrees and build directories (sizes from read-only `du -sh`)

**Local Mac** (`/Volumes/CaseSensitive`, 1.8T, 68% used).
- Root `target/`: 74G. `.sccache`: 10G.
- Landed or disposable worktrees, about 115G in total:

| worktree | size | why it can go |
|---|---|---|
| ring-switch | 44G | #132 landed |
| ring-switch-main-ab-20261009 | 20G | A/B control |
| arm-step5-main-baseline | 18G | baseline |
| arm-step5-first-error | 16G | subset of arm-step5 |
| land-x86-fixes | 2.1G | #133 landed |
| ab-n1cm-main-baseline, ab-n1cm-panic, n1-bisect, n1-files, bisect-df605a239 | 0.2-0.6G each | superseded |
| arm-flip, fix-freebsd, fixture-lock, land-pr62, lease-order, lease-zombie, rl-shared-kernel, rl-x86-legacy-retire, spawn-regress-fixed-pb, wt-remote-gate, x86-user-ceiling, xtask-macos | 0.2-0.4G each | landed or superseded |
| el1-inotify | 0.2G | superseded; has 1 uncommitted file in `carrick-kernel/src/el1_delegation.rs` |

- **fork-shared-retire** (14G): keep until x86-fork-land's port lands.
- **arm-step5** (57G): active.
- **.worktrees/target** (228M) and **gate-worktree.lock**: leftovers.

**carrick-vm** (63G free of 246G).
- Delete `wt-cpl0-extent` (12G, landed).
- Delete the landed 236M worktrees (about 6G): fdtable, ring-identity,
  ring-sched, land-x86, review-switch, main-ab, x86-entry, x86-shared-fixes,
  process-owner-main, review121-* x6, x86-anon-main-classify, buildcode,
  buildrs, mem-race, resv, inv, inv-review, merge-queue, n2b-core.
- Delete `wt-m2-kvm` (no .git) and the `wt-lease-leak-review` prunable
  entry.
- Keep `wt-ring-signals` (63G) and `wt-ring-ipc` (30G) while active.
  Clean their `target/` after landing.

**cloudmac.**
- Delete `signed-pr130/134/135/136` (4 x 628M, landed).
- Delete the eight `wt-*` from 10-04 and 10-05 (about 4.4G): attrib-main,
  build-cache-proof, elf-fix, fes-load, hosted-mac, n1-p4, pool-guard,
  storm.
- Prune `gate/*` refs older than the queue window (116 refs).

### 3.2 Branches safe to delete

Tag before deleting anything uncertain, for example
`archive/2026-10-10/<name>` as a lightweight tag in the GitHub repo.

**GitHub.**
- The 12 branches with MERGED PRs.
- The 53 CLOSED-PR branches marked LANDED (34) or SUPERSEDED (19) in 1.4. They are
  mostly superseded by the inversion.
- `land/batch5-8`, `work/arm-step5-review` (superseded by the local
  branch once that is pushed), `work/fork-shared-retire` (superseded by
  `review/fork-retire-on-26e3`), `work/n1-cm-panic-diag`,
  `wip/*-codex-stop`, `archive/*` (convert to tags).
- Keep until salvaged: the ORPHANED-UNIQUE rows in 1.4.

**Local Mac.**
- 35 merged branches plus 201 unmerged branches with 0 subject-unique
  commits (68 agy/*, 43 work/*, 17 codex/*, 9 fix/*, 5 preserved-stash/*,
  others). Candidates for `git branch -D` after a last spot check;
  subject matching is heuristic.
- 132 branches from May-Aug with unique subjects predate the current
  architecture. Tag-and-delete them as a batch rather than triaging each.
- Triage the October subject-unique set individually. Most are N1, X1 and
  S3 snapshots superseded by `work/n1-cm` or the inversion:

backup/el1-tlbi-pre-squash (6066c5947, 2026-10-01, subj-unique=3) backup/n1-before-pr46-47d111828 (47d111828, 2026-10-05, subj-unique=10) backup/n1-help-snapshot-715c5c35f (715c5c35f, 2026-10-04, subj-unique=9) backup/n1-pre-main-merge (02a0a437c, 2026-10-07, subj-unique=144) backup/n1-prebatch5-75debee90 (75debee90, 2026-10-04, subj-unique=6) backup/n1g2-before-batch6-12a028af2 (12a028af2, 2026-10-05, subj-unique=9) backup/s3-t2-pre-rebase (43ad636ad, 2026-10-01, subj-unique=1) backup/s3-t3b-pre-rebase (808b0bc37, 2026-10-01, subj-unique=5) checkpoint/s3t3-before-main-839f92126 (8f0e14faf, 2026-10-02, subj-unique=17) checkpoint/s3t3-rebased-839f92126 (6550c4f49, 2026-10-02, subj-unique=12) land/phase-b (de28644d6, 2026-10-03, subj-unique=2) pr11 (41fe977bc, 2026-10-04, subj-unique=12) pr14 (09cf6a56b, 2026-10-04, subj-unique=12) pr16 (3db84db7c, 2026-10-04, subj-unique=12) pr21 (a0ead6ea5, 2026-10-04, subj-unique=7) recap/ord6 (6bb08a88d, 2026-10-06, subj-unique=31) review/fork-retire-on-26e3 (3d5034278, 2026-10-09, subj-unique=75) review/fork-retire-on-9d6 (042cfa479, 2026-10-09, subj-unique=90) tmp/phaseb-full (94af9e82b, 2026-10-03, subj-unique=3) wip/n1-files-g2-diag-0307 (ce5975e46, 2026-10-07, subj-unique=110) work/agy-grpstop (970504845, 2026-10-01, subj-unique=1) work/agy-relaysig (1f861543f, 2026-10-01, subj-unique=6) work/anon-generic (261f5721a, 2026-10-06, subj-unique=51) work/arm-adopt-step5 (63a7f7666, 2026-10-10, subj-unique=77) work/backend-target-select (48c73b1c3, 2026-10-06, subj-unique=4) work/brk-heap (a62ece325, 2026-10-01, subj-unique=1) work/cow-cost (fdf7f38c5, 2026-10-01, subj-unique=1) work/el1-tlbi (1dd4fea9d, 2026-10-01, subj-unique=2) work/fork-shared-retire-pre-rebase2 (3260e0828, 2026-10-09, subj-unique=57) work/fork-shared-retire-pre-rebase (e1f13729e, 2026-10-09, subj-unique=54) work/fork-shared-retire (21c124404, 2026-10-09, subj-unique=70) work/forkexit (f07a26147, 2026-10-02, subj-unique=2) work/grpstop-zone (ced5b11c6, 2026-10-01, subj-unique=3) work/isolation-on-i (5914a5001, 2026-10-01, subj-unique=2) work/lane-maint (cb16f5c89, 2026-10-01, subj-unique=1) work/launch-trace-flag (f73f9e189, 2026-10-06, subj-unique=2) work/lifecycle-phase-b (fa5f7d95c, 2026-10-03, subj-unique=14) work/mm-pub-v2 (9bf9d2241, 2026-10-06, subj-unique=37) work/munmap-release (45bccc551, 2026-10-01, subj-unique=2) work/n0 (f83548642, 2026-10-02, subj-unique=15) work/n1-cm (bbf545fd4, 2026-10-08, subj-unique=186) work/n1-filemap-wip (3c5113bda, 2026-10-05, subj-unique=30) work/n1-files (623e3693d, 2026-10-07, subj-unique=109) work/n1-p1 (09cf6a56b, 2026-10-04, subj-unique=12) work/n1-p2 (41fe977bc, 2026-10-04, subj-unique=12) work/n1-p3 (3db84db7c, 2026-10-04, subj-unique=12) work/n1-pre-rebase (6c5e28e69, 2026-10-04, subj-unique=23) work/n1-sigframe-draft (e8cbf3744, 2026-10-06, subj-unique=67) work/n1 (56bf8c0ca, 2026-10-05, subj-unique=29) work/pb-exec (b5f739d5d, 2026-10-03, subj-unique=2) work/preempt-hang (cd9158bfb, 2026-10-01, subj-unique=1) work/read-pin (0d2e57343, 2026-10-01, subj-unique=1) work/s3-t2 (8abb0a722, 2026-10-01, subj-unique=1) work/s3-t3b (1cf7568e1, 2026-10-02, subj-unique=14) work/sched-diag (41281af8f, 2026-10-01, subj-unique=1) work/sk-gates (735a08c59, 2026-10-06, subj-unique=37) work/step2-prep (f6e90773f, 2026-10-02, subj-unique=29) work/vfs-deadline (5a71b22eb, 2026-10-03, subj-unique=1) work/x1-arm-regress (0feb7c7b0, 2026-10-05, subj-unique=51) work/x86-legacy-retire (c1c2f2f1b, 2026-10-08, subj-unique=19) work/x86-user-ceiling (34e8d8187, 2026-10-06, subj-unique=2) work/x86-wave2-plan-main (289e8d797, 2026-10-05, subj-unique=3) work/zone-wake (a754e946d, 2026-10-01, subj-unique=3) 

**carrick-vm.**
- The bare repo's 70 `fixpub/<sha>` refs: delete them once their PRs
  land. They are bundle-publication scratch.
- The clone's `backup/*`, `batch8-*`, `inv-before-*`, `ci-green-before-*`
  and `work/x86-*-checkpoint` branches: all have 0-3 unique subjects or are
  superseded.

### 3.3 carrick-vm mirror staleness

| ref | value | relation to GitHub main 4e63042fe |
|---|---|---|
| bare `~/dev/carrick.git` `main` | 39fbcacb3 (PR #134 merge) | 111 behind |
| bare `gh-main` | c9c603b9c | 1 behind |
| clone `~/dev/carrick` `origin/main` | 39fbcacb3 | 111 behind |
| clone `main` | 652e0dcde (10-04) | about 1,000 behind |
| cloudmac bare `main` / `github/main` | 8b6cf9031 (10-04) / 8f6e6bc08 (10-08) | stale; gates use explicit SHAs, so no harm yet |

Workers on carrick-vm gate with `CARRICK_AUTHORITY_BASE=origin/main`. On
the VM that resolves to the bare mirror's `main`, not GitHub. ring-identity
and ring-signals had to rebase onto `github/main` by hand and then ask the
director to refresh the mirror.

## 4. Prioritized recommendations

### Now (today)

1. **Make every sole copy durable.**
   - Push local `work/arm-adopt-step5` (`63a7f7666`) to GitHub, replacing
     `work/arm-step5-review`.
   - Have ring-signals-sol push `765f0ab08` (or its successor) to
     `work/ring-signals` now that #136 has removed the extent blocker.
2. **Choose one owner for fork-stock and child retirement.**
   - Land x86-fork-land's port of the unified retire
     (`share one retired child space queue across isas`,
     `share fork stock loans and child quarantine across isas`) first.
   - Then rebase arm-step5 onto it and drop arm-step5's ARM-only
     `ed6966683` in favor of the shared queue.
   - Doing it in the other order makes the shared refactor fight 78 ARM
     commits.
   - Have x86-fork-land port the pairwise CPL0 port check, and decide
     whether `X86_INITIAL_RUNNER_READY_PORT == NATIVE_RUN_FAILURE_PORT == 0xd5`
     on main is intended.
3. **Clean PR #137 before review.** Rebase ring-ipc onto 4e63042fe keeping
   only the 4 IPC commits (`c1d2241c6`, `b63ca3ca6`, `ffe298c9c`,
   `70badb62d`). Drop:
   - the 12 identity commits (landed in #130)
   - the XSAVE commit `1ae57533a` (landed as `6207de63f`)
   - the ARM flip doc
   - the 4 MiB extent `999c6cdaf` (it contradicts #136's layout proof)
4. **Settle the false-fixture question in the repo.** Mark the two
   `cpl0_fork_e2e` wait4 rusage tests as false fixtures, fix them, or record
   the oracle evidence. Correct the "pre-existing main defect" instruction
   that went to arm-step5.

### This week

5. **Order the landings:**
   1. ring-signals (rebased; it carries the run-failure and xstate work)
   2. x86-fork-land port
   3. ring-ipc (cleaned)
   4. arm-step5
   5. PR #86 rebased. Drop its clear-tid copy (main `a195bacc6`) and keep
      TLS/`arch_prctl` and the standalone-lane deletion. That removes an
      `arch_prctl` "main failure" every lane currently subtracts.
6. **Salvage n1-cm deliberately rather than by accident.**
   - Open one triage task with the list in 2.1 D.
   - For each commit, decide whether it still applies to the ring-first,
     shared-owner model: port it (as #128 did), record it as obsolete, or
     turn it into a red witness on main.
   - Then close PR #59 and N1 drafts #11/#14/#16/#21.
   - Move `docs/diagnostics/n1-ipc-ebusy.md` and the n1 perf-results
     handoffs to main either way.
7. **Salvage the evidence-only branches as docs on main:**
   - x86 signal-startup, stdio-poll and fork-stock diagnostics from
     x86-n1-diag
   - `x86-anon-cpl0-handoff.md`
   - futex and namespace flake READMEs, unless both flakes are confirmed
     fixed
   - N2 witnesses: land them as `#[ignore]`-free red contracts or close them
8. **Delete per section 3.** About 115G local, about 18G VM, about 7G
   cloudmac. Start with the landed GitHub branches and `git fetch --prune`.

### Process changes

9. **One shared facts ledger in the repo.**
   - For example `docs/ledger/main-facts.toml`, edited only through
     reviewed PRs and read by workers at dispatch.
   - Each entry: id, kind (`main-defect | false-fixture | false-green |
     lint-debt | follow-up | test-isolation`), exact test/path, the main SHA
     where it was observed, evidence (receipt path or native-oracle result),
     owner, and status.
   - Seed it from 2.4. Workers cite ids instead of re-deriving "5 main
     failures" from their own baseline runs.
   - Add a CI check that every `#[ignore]` or named main failure in a PR
     body references a ledger id.
10. **A main KVM/signed baseline as a published artifact.**
    - After each merge-queue landing, have the CI/gate box publish the exact
      failing-test set for `x86_kvm_run`, carrick-vmm-kvm and the signed
      `el1_` filter, keyed by main SHA.
    - Workers then diff against that set instead of measuring their own
      baseline. Today three workers recorded three different main sets.
11. **Base on GitHub main only.**
    - On carrick-vm, delete the self-referential bare-repo `main` (or make
      it a fetch-mirror refreshed by a post-merge hook) and point the clone's
      `origin` at GitHub.
    - Set `CARRICK_AUTHORITY_BASE=github/main` in worker env. Rule: a worker
      rebases onto `github/main` at dispatch and before review-ready, never
      onto a mirror.
    - Retire the second VM repo so there is one object store.
12. **Port before you parallelize.**
    - When two lanes touch `native_process_runtime.rs`, `process_owner.rs`,
      `personality/dispatch.rs`, `carrick-el1-abi/src/lib.rs` or
      `fork_stock.rs`, the director names one integration owner and the
      other lane stacks on it.
    - When one lane needs another lane's mechanism (identity needed the
      NativeRunFailure transport from signals), extract a standalone commit
      to main first rather than carrying copies.
    - Allocate CPL0 ports and ABI layout slots in one registry file
      reviewed per PR.
13. **Make shared-concept fixes ISA-neutral by default.**
    - The child-retire and parent-wake duplicates were the same rule written
      separately for x86 and ARM.
    - Briefs should require a fix in shared `personality/`, `core` or `hal`
      code, with per-ISA adapters only. An ISA-only implementation of a
      shared-kernel rule needs director sign-off.
14. **Reduce inventory churn.** 7% of main commits are position
    reconciliation, and every lane conflicts on the JSON. Finishing the
    planned retirement of line-pinned inventories (memory: inventory
    retirement plan, #51) is the biggest single conflict reducer.
15. **Worktree lifecycle.**
    - Delete a worker's worktree and `target/` when its PR merges. The
      director's landing checklist should include
      `git worktree remove` on every host plus branch delete.
    - A/B baseline worktrees should use a shared target dir or be removed
      the same day. The three baselines here hold 54G.

## Appendix: commands run (all read-only)

```
git fetch origin main; git fetch origin '+refs/heads/*:refs/remotes/origin/*'
git worktree list --porcelain; git rev-list --count origin/main..X; git cherry origin/main X
git log --format=%s origin/main | sort -u   # subject set for subject-unique test
git merge-tree --write-tree --name-only origin/main X   # and pairwise between active heads
git diff --name-only $(git merge-base origin/main X) X
gh pr list --state {open,merged,closed,all} --json ...
ssh carrick@10.14.14.66 'git -C ~/dev/carrick{,.git} for-each-ref ...; git cherry github/main ...; du -sh ~/dev/wt-*'
ssh rentamac@cloudmac 'git -C /Volumes/carrick/dev/carrick{,.git} for-each-ref ...; du -sh /Volumes/carrick-build/wt/*'
python3 scans of agy-director mail/*.out.jsonl and *.in.jsonl (local and /tmp/agy-director/willow)
du -sh /Volumes/CaseSensitive/carrick/.worktrees/* /Volumes/CaseSensitive/carrick/target
```

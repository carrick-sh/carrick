# Strategy assessment — where we are and what to do next

**Date:** 2026-07-25 · **HEAD:** `cb236874` (clean) · **Method:** five evidence-grounded
ground-truth reports, each put through an adversarial challenge. Where a challenger found a
claim overstated or refuted, this paper plans on the corrected version.

Every claim below is marked **[V]** verified (I or a reviewer read the code/artifact),
**[I]** inferred (reasoned from evidence), or **[U]** unknown (would need work to settle).
Read the marks — the resourcing decision turns on which is which.

---

## 1. Where we actually are

Carrick genuinely runs two major Linux ecosystems on the macOS/AArch64 **VMM** lane —
418/425 CPython suites and 187/192 Go suites of what the Docker oracle itself can run
**[V]**, which is a real, non-trivial product result and the strongest thing the project
has. Syscall coverage is not the limiter: the aarch64 table is 225 BringUp / 112 Deferred /
2 Planned **[V]** (`crates/carrick-abi/src/syscall.rs`), more than AGENTS.md's "~210/~130"
claims. The strategic pivot the maintainer describes as "on the path to" has largely already
happened in the code — the last 200 commits are 56% native/DSR and 4% VMM **[V]**, the
native/DSR crates are now the larger investment (~49.6k lines of dedicated crates vs ~39.1k
VMM), and `--exec-backend` has defaulted to `native` in all three CLI subcommands since
`e4741435` (2026-07-13) **[V]** (`crates/carrick-cli/src/args.rs:178,360,470`). But almost
nothing downstream of that flag followed it: the conformance harness still defaults to
`--lane hvf` (`lane.rs:343`), which explicitly injects `--exec-backend vmm` (`lane.rs:168`)
**[V]**, and `bless_target()` hard-codes that only the `hvf` lane may rewrite
`baseline.jsonl` and `docs/support-matrix.md` — native is architecturally a subordinate
lane that can write only its own overlay, which is committed as **1 byte** **[V]**. So the
project's flagship gate certifies the backend being retired, against a baseline last blessed
`9e7ffdf6` on **2026-06-20, 1,435 commits ago** **[V]**; `just check-matrix` inside `just ci`
only asserts the matrix equals a render of that same stale file, which is internal
consistency, not freshness **[V]**.

The single most decision-relevant number is one no prior summary surfaced: the last recorded
run of the **native** backend against the project's own 23-case pre-merge smoke tier
(`target/conformance/native-default-goal-smoke-20260713.jsonl`, 2026-07-13) is **15 match /
4 regression / 3 timeout / 1 carrick_crash, with all eight non-matches `gating: true`** —
`ltp-eventfd01`, `go-build`, `go-runtime`, `go-sync`, `node-app-smoke`, `node-v8-smoke`,
`cpython-subprocess`, `cpython-threading` **[V]**. The shipped default backend has never been
demonstrated to pass the project's own fast gate. The native bless checklist is **2 of 14**
items checked, and its "Current next action" reads *"Stop correctness laddering on the
measured Go compiler/import performance blocker"* **[V]**. Nothing automated observes a
guest anywhere: `just ci` runs no guest, and both CI jobs that would (`hvf-conformance`,
`kvm-smoke`) are dormant behind unset repo variables **[V]** — so CI executes **zero** guest
instructions on any lane.

Breadth is thinner than the crate list implies. The native capability table
(`page_profile.rs:124-138`) admits exactly **three** (host OS, host ISA) pairs — macOS/aarch64,
FreeBSD/amd64, NetBSD/amd64 — with everything else an explicit `Unsupported` arm **[V]**;
notably there is **no Linux arm**, so on a `platform-linux` build the shipped default backend
refuses out of the box **[V]**. The two aarch64-BSD lanes do not exist as executable lanes at
all: the AArch64 DSR gateway is assembled only on macOS+aarch64 (`carrick-dsr-aarch64/build.rs`),
there is no run loop, and `bsdvm` stage2/stage3 are hard-coded `available=False` while stage1
is `report_only=True` and cannot fail the ladder **[V]** — `just bsdvm-acceptance` means unit
tests on four support crates plus a compile. Depth on the three real lanes is wildly uneven:
Darwin/aarch64 runs containers and full ecosystems; FreeBSD/amd64 has 43 acceptance tests and
a 25-case curated LTP gate; NetBSD/amd64 has four single-threaded, fork-free, signal-free ELF
fixtures, and its own evidence doc states the fsbase-swap seam's correctness under mid-guest
signal delivery *"is box-grounded but has never been run"* **[V]** — the one item where a wrong
analysis produces host-side memory corruption rather than a clean failure.

Finally, cross-ISA is structurally VMM-only forever (`page_profile.rs:110-121`) **[V]**, so
the honest end-state is *demote VMM to the cross-ISA/Rosetta backend*, not *delete VMM*.

### Corrections the challengers forced (things we believed that are not true)

1. **"0 gating (VMM) vs 90 regressions (native) is the cost of the pivot."** Not a valid
   comparison. The VMM baseline's zero gating rows are an artifact of blessing — a blessed
   baseline is by construction a state in which nothing can fail — and it carries 869
   `known_diffs` excusing its 43 DIFF rows. The corpora differ (1,429 LTP rows vs 1,492), and
   227 of native's 1,331 "MATCH" rows are rows where **neither side asserted anything**, from
   an uncommitted artifact 550 commits old **[V]**. Do not quote this comparison to anyone.
2. **"The native perf blocker was abandoned for ten days."** Refuted. Eight named `perf(...)`
   commits land between 2026-07-16 and 07-20 (direct-branch chaining, translation-cache
   hashing, FPU save/restore elision, gateway hot-path allocation) **[V]**. The *campaign
   ledger* went stale, not the work — a far cheaper problem.
3. **"New-host bring-up yields nothing for the mature lane."** Refuted. Of 41
   `fix(native-x86)` commits in 2026-07-14..21, **20 touch shared code** — including
   `bef766ef`, a guest-reachable host core-dump fixed in shared `dispatch/proc.rs`, and
   `2c476bb2`, a published-relay half-close fix in the very file the determinism sweep is
   credited for **[V]**. Breadth has real cross-lane debugging value.
4. **"Spawn cost is the single root cause of native slowness."** Refuted by the project's own
   Task-3 measurements: a frozen compile is 16.00x with 57–77% of CPU **unattributed**, and a
   prior attribution was formally **retracted** **[V]**. Native compute performance is an open
   research problem, not one decision away from resolution.
5. **"The VMM fork-child network bug is a one-line fix."** Wrong on both scope and severity.
   There are **two** VMM fork-child arms — `runtime.rs:1100-1132` and the multi-threaded
   `vcpu_loop/quiesce.rs:683-805` that every real container takes — and the quiesce site omits
   **both** `network_after_fork_child` *and* `mem_after_fork_child` **[V]**. Severity is also
   differently shaped than assumed: forked children `_exit()` (`exec_helpers.rs:321`), so
   `Drop`/`destroy_namespace` never runs on normal exit — the record-deletion path is an
   error-path bug, while the *unconditional* harm is inherited relay fds keeping a published
   host port bound and unserviced **[V/I]**.
6. **"Conformance is not being maintained."** Too strong. `oracle-cache.jsonl` was last
   committed 2026-07-15 **[V]** — runs happen; **results are never blessed back**.

### Where project docs currently overstate reality (these are doc bugs)

The project's own principle is honest status framing, so each of these is a defect:

| Doc | Claim | Reality |
|---|---|---|
| `AGENTS.md:17,27` | "The mature default path is macOS / Apple Silicon with HVF"; "release-quality reference lane" | The shipped CLI default has been `native` since 2026-07-13. `README.md:70` gets this right; AGENTS.md contradicts it — and AGENTS.md is the file agents read first. |
| `AGENTS.md:36-41` | Rule 0: "every `carrick run` dies with HV_DENIED" without codesigning | False for the default backend; native uses no HVF. Sends every agent through a ceremony the default path does not need. |
| `AGENTS.md` "What Carrick is" / subsystem map | Describes only the VMM model; lists `carrick-vmm-hvf/src/trap.rs` as the trap loop | The default execution path (`native_darwin.rs`, 12,985 lines) is never named as a key subsystem. |
| `AGENTS.md:31` | "~210 emulated, ~130 deferred" | 225 BringUp / 112 Deferred / 2 Planned **[V]**. Also `docs/syscalls-emulation-map.md:31` says ~216/121. |
| `AGENTS.md:110-119` | "The **two** native (DSR) drivers"; resolves to `DarwinAarch64Lane` or `FreebsdX8664Lane`; "Phase 2 merges the two drivers' thread loops" | There are **three** lanes (`NetbsdX8664Lane`, `native/mod.rs:95`), and the loop merge was explicitly **SKIPPED** (`f902c26e`, `8c65d42d`). `native/mod.rs:82-84` even says "there is no third lane yet" ten lines above the third lane. |
| `AGENTS.md:73` | `just test` = `cargo test --workspace --lib` | The real recipe splits `carrick-runtime` to `RUST_TEST_THREADS=1` because parallel harness threads corrupt each other. The doc prints the exact command the project warns against. |
| `AGENTS.md` conformance section | Presents `just conformance` as the live correctness authority | It defaults to the VMM lane and gates against a 1,435-commit-old baseline. Never discloses either. The `macos-native-dsr` lane is never mentioned. |
| `docs/support-matrix.md` | "Auto-generated carrick-vs-Docker verdict table" | It is an HVF/`--exec-backend vmm` render, unlabelled, five weeks stale, and `just check-matrix` in `just ci` actively enforces that it stays checked in. |
| `README.md:153-155`, `docs/hal.md:31` | "platform-netbsd wires NetBSD/NVMM … blocked by nested-NVMM host behavior" | NetBSD's *working* path is native (no VMM), acceptance achieved 2026-07-24. The docs describe the blocked lane and omit the unblocked one. `docs/hal.md`'s platform matrix has no native rows at all. |
| `justfile` `bsdvm-acceptance` | Named "acceptance" | Runs stage0 (unit tests on 4 support crates) + stage1 (a compile that is `report_only` and cannot go red). No guest, no ELF. |
| `native_freebsd.rs:19-25` | "Scope: a SINGLE-THREADED static binary. Threads, fork/clone … are the next rungs" | The file now contains fork/vfork/clone/exec/xstate/kick machinery and is the **shared BSD run loop**. Badly stale. |
| `crates/carrick-abi/src/syscall.rs:158-159` | Attributes the aarch64 table to kernel `include/uapi/asm-generic/unistd.h` (v6.12) | Contradicts AGENTS.md's non-negotiable clean-room rule; the x86 sibling file explicitly disclaims kernel/glibc source. Either the comment is an inaccurate provenance record or the rule was broken. Resolve before external scrutiny. |

---

## 2. The strategic fork

Five directions are on the table. They are not equally distinct — B and C are entangled, and
D is a subset of B in practice — but stating them separately makes the trade visible.

### Option A — Breadth: finish the aarch64-BSD lanes

**Buys.** Two more (host, ISA) pairs; a "carrick runs on four operating systems" story; the
demonstrated cross-lane bug-finding effect (FSGSBASE, the >PATH_MAX gap, and 20-of-41 shared-code
fixes came out of x86 BSD bring-up **[V]**).

**Costs.** Larger than the seam thesis suggests. The scout sizes the remaining work at 13 open
tasks with the dominant term (T9, the trap/kick host shim) at **L, needed twice** **[I]**,
because unlike the x86 BSD lane the aarch64 host shim has no trait seam — there is a 675-line
C shim behind a raw `extern "C"` block at `native_darwin.rs:545-568` **[V]**. Add: NetBSD/aarch64
GENERIC64 ships **PaX MPROTECT on by default** with `maxprot` pinned at map time, a direct
constraint on JIT/code-cache design **[V]**; USDT can *never* fire on freebsd-arm64
(`fasttrap.ko` absent — a kernel reason) and NetBSD GENERIC64 has DTrace disabled **[V]**, so
`carrick trace` — which AGENTS.md calls THE tracer — does not exist on either new lane;
`run_oci` is a hard `Unsupported` there, so containers do not work without T5 **[V]**.

**Risks.** The "host glue only, no dispatcher change" cost model was **already violated once**:
NetBSD required four `#[cfg(not(target_os = "netbsd"))]` gates in the shared
`dispatch/net/support.rs` for three real feature gaps **[V]**, and it left the shared BSD run
loop's ~118 inline tests entirely disabled on NetBSD because some SIGSEGV there **[V]** — a
plausible real bug in a shared path, silenced rather than root-caused. Both are in tension with
"no pragmatic shortcuts."

**Unblocks.** Nothing on the product path. It unblocks more breadth.

**Wrong if.** The goal is a working product on the lane that has users. Also wrong if you value
`carrick trace` — you are shipping two lanes where the documented primary debugging tool cannot
run.

**Right if.** Portability *is* the product (a research/portability thesis rather than a runtime
people use), or if the cross-lane bug-finding effect is judged the cheapest way to harden shared
code — which the evidence does partly support.

### Option B — Depth: close the native-vs-VMM gap on the mature lane

**Buys.** The shipped default backend actually working: the eight gating smoke failures, the
`clone(CLONE_THREAD)`-in-a-fork-child `EOPNOTSUPP` guard and its six failing probes, the
90-ish LTP regressions, and real-workload parity.

**Costs.** Genuinely uncertain. The campaign's own P0 (Go compiler/import at 516x) is open with
an explicit "do not restart laddering" instruction, and the compute-side attribution is a
research problem with a retracted prior diagnosis **[V]**. The libdispatch post-fork guard and
the ~7 ms/exec PID-preserving self-reexec are the same root cause and the hardest thing in the
native design **[V]**.

**Risks.** Open-ended. Also: you cannot currently *measure* progress, because the gate points at
the other backend.

**Unblocks.** Every honest claim that native has replaced VMM. Also the only path to retiring the
dual-backend mental-model tax (the code tax is modest — ~19.3k VMM lines in the macOS closure vs
~89k native **[V]** — so deletion is not the motive; coherence is).

**Wrong if.** You would rather have a broad experimental substrate than a deep one, or if the
native pivot's premise turns out to be false (see §4).

### Option C — Measurement: make the gate test the shipped default, and make it able to fail

**Buys.** Cheap decisions. Today no artifact in the repo describes the default backend at HEAD,
so every ranking argument is unarguable. Beyond re-pointing the lane, the gate has four
structural holes that would let a green run hide real divergence: **NEW rows are non-gating**
(so `go-syscall`'s 12 failures sit forever), **DIFF rows are also non-gating** once blessed,
**66 LTP suites carry a blanket `known_gaps=["summary"]`** on the only token an LTP suite emits
— structurally unfailable no matter what carrick does — and **72 suites have no baseline row at
all**, classifying NEW and therefore non-gating **[V]**.

**Costs.** The bless-guard inversion is ~1 file. The gate-semantics repair is S–M. The *full
re-bless* is the expensive part and is currently **blocked** by the native campaign's own
checklist (2/14) and two open P0s — presenting it as bounded work would be exactly the
"counting work as done that was never live-verified" failure the project warns about.

**Risks.** Spending a campaign building instruments instead of product. Mitigated by scoping to
the 23-case smoke tier first, which is hours of machine time, not a campaign.

**Unblocks.** A, B, D and E all become rankable instead of argued.

**Wrong if.** You already know what you want to build and do not need the number. (You don't —
the 8/23 red smoke result is twelve days old and several of those suites have individual fixes
recorded since, so the current state is genuinely **[U]**.)

### Option D — Attack the correctness/debt ledger

**Buys.** Retires shipped, user-visible bugs. The top items are cheap and two of them are on the
lane AGENTS.md calls "release-quality."

**Costs.** Individually XS–S. The real cost is that the ledger is **invisible**: there are 5
TODO/FIXME comments in all of `crates/` **[V]**, so the entire known-issue list lives in design-spec
"what this does NOT fix" sections, red lists, and commit bodies that no tool enumerates.

**Risks.** Without measurement you cannot tell when you are done, and you will re-find the same
class of bug from a different direction.

**Unblocks.** Makes the VMM→native migration strictly safer (the legacy path is currently the
buggier one on fork/network). Makes the NetBSD lane trustworthy.

**Wrong if.** The items are truly narrow — but two are not (see §3's first three).

### Option E — Performance

**Buys.** Viability for real Linux software, which is fork/exec-heavy.

**Costs/risks.** Open-ended research with a retracted prior attribution and 57–77% of CPU
unaccounted for. Also unprotected: ~33 perf commits produced the native win, ~880 `.rs`-touching
commits have landed since, and there is no perf gate — two of that campaign's own commits were
reverted for being net-negative **[V]**.

**Wrong if.** Pursued before you know whether native is even *faster than the VMM it replaces*
on fork/exec — which is currently **[U]** and possibly no (native deliberately regressed 5.7 ms
→ 12.1 ms to buy libdispatch safety **[V]**).

---

## 3. Recommendation

**Primary: Option C-scoped fused with B — make the shipped default backend pass the project's
own fast gate, and make the gate test it by default.**

**Secondary: Option D's top three correctness items**, which are XS–S and two of which are
shipped bugs on the reference lane.

**Defer Option A**, explicitly and with a written status — but pay the hours to stop its
~20 landed prerequisite commits from rotting (a cross-compile gate).

### Reasoning

The strongest single justification: **the project has already made the direction call and shipped
it, and does not know whether it works.** `--exec-backend` defaults to `native`; the flagship gate
tests `vmm`; the only artifact describing native against the pre-merge gate is twelve days old and
shows **8 of 23 suites gating**. Every other option — breadth, depth, perf, debt — is a bet placed
without the number that ranks the bets. Getting that number is *hours of machine time*, because the
harness, the lane, the oracle cache and the suite definitions all already exist. This is not
"invest in measurement" in the abstract; it is running a 23-case suite against the backend users
actually get.

The second justification is honesty: the project's own principle is honest status framing, and
right now `docs/support-matrix.md` publishes numbers the project privately disowned in its own
2026-07-05 audit (1,128 of 1,977 "MATCH" rows are broken/broken **[V]**), while AGENTS.md tells
every agent the wrong backend is the default. Those are cheap to fix and they compound: as of
`d763a98e` (yesterday) AGENTS.md finally loads in Claude Code, so every wrong claim in it is now
amplified across ~41–56% of the fleet instead of ignored.

I am **not** recommending "invert the bless authority and re-bless" as a bounded task — the
challenger is right that the native campaign's own checklist (2/14, two open P0s, an explicit
"do not restart laddering") says a full native bless is blocked. The recommendation is the
bounded prefix of that work, ordered so each step's result informs the next.

### First work items, sized, in order

| # | Item | Size | Why it is first |
|---|---|---|---|
| 1 | **Re-run the 23-case smoke tier on `--lane macos-native-dsr` at HEAD.** Two-phase (carrick then Docker, cached oracle), scoped `CARRICK_RUN_ID`, reap with `scripts/sudo/kill.sh`. | XS — hours of machine time, no code | Replaces a twelve-day-old red number with a current one. This single result is the gating input to items 4–5 and to §4's first two triggers. |
| 2 | **Truth-up `AGENTS.md`** (default backend, Rule 0's scope, `just test`'s real recipe, the three lanes, the skipped loop merge, syscall counts, an oracle-freshness note, no-USDT-on-aarch64-BSD) **and add a `just conformance-native` recipe** — there is currently no `just` recipe for the default backend's own lane at all **[V]**. Resolve the `syscall.rs` UAPI provenance comment while in there. | XS — under a day | CLAUDE.md landed yesterday; that fix only pays off if what loads is true. The missing recipe is why nobody runs the native lane. |
| 3 | **Fix the two VMM fork-child sites and the missing `fork_gate`.** Route both `ForkOutcome::Child` arms (`runtime.rs:1100-1132` *and* `vcpu_loop/quiesce.rs:683-805`) through the shared `AFTER_FORK_CHILD_STEPS` list so they cannot diverge again; adjudicate the quiesce site's missing `mem_after_fork_child` **[U]**; take `fork_gate` around `carrick-aarch64/src/engine.rs:1138`. Red-first regression test: fork a guest under `carrick run -p`, assert the published port still serves. | S — ~1 day | The highest-severity shipped correctness bugs, on the lane the docs call release-quality, and the native lanes already get both right. Makes the migration strictly safer. |
| 4 | **Gate-semantics repair.** Make DIFF and NEW rows either gating or force-triaged before a bless; fail on suites with no baseline row (72 today); audit the 66 blanket `known_gaps=["summary"]` LTP suites; add published-port (`-p`) suites to `carrick-conformance` — the flagship demo has **zero** coverage today (`grep publish crates/carrick-conformance/` = one unrelated comment **[V]**) despite four real bugs landing there in two days. | S–M — days | Without this, a green gate does not mean "no known divergence," so item 5's output would be worth less than it looks. |
| 5 | **Drive the smoke-tier gating list to zero, then invert the bless guard and bless a native baseline.** Only after item 1 tells you how big the list actually is. | M–L — one campaign, scope set by item 1 | This is what makes "native is the primary backend" a statement of fact rather than of intent. |

**Parallel, XS, independent of the above:** add `just check-freebsd-arm64` /
`just check-netbsd-arm64` and extend `check-netbsd` from `-p carrick-vmm-nvmm` to the native
closure (`-p carrick-cli -p carrick-runtime --features platform-netbsd`) **[V: neither exists
today]**. Roughly ten of the last twenty-two commits are pure portability tax of a class a
`cargo check` finds in minutes without booting a VM. This is the cheapest way to defer Option A
without paying re-fix cost later, and it also stops the just-landed NetBSD **native** lane —
which has no CI protection at all — from silently breaking.

**Also worth an explicit ruling, not work:** write down that VMM survives on macOS as the
cross-ISA (Rosetta `linux/amd64`) backend and nothing else. "Replace VMM" is unachievable while
amd64 images are supported (`page_profile.rs:110-121`); "demote VMM to cross-ISA-only" is, and
it is a much smaller, finite target. Park KVM/bhyve/NVMM with a documented status rather than
letting them rot implicitly (no VMM feature work in days, `baseline.nvmm.jsonl` and
`baseline.kvm-arm64.jsonl` both **0 bytes**, and the bhyve/NVMM live tests **skip silently**
rather than fail when fixtures are unset **[V]**).

---

## 4. What would change this recommendation

This section matters more than the recommendation. Each item is a specific, cheap observation
that should flip the call.

1. **Item 1 comes back green or near-green (≤2 gating).** Then native depth is much further
   along than the ledger implies, item 5 collapses to a bless run, and **Option A becomes
   reasonable immediately**. This is the highest-value observation in the paper and it costs
   hours.

2. **A same-run native-vs-HVF fork/exec A/B shows native SLOWER than HVF.** Currently **[U]**:
   native's provable fork+exec p50 is 5,735 µs (2026-07-11) and it deliberately regressed to
   ~12.1 ms to buy libdispatch correctness, while the 6,535 µs comparison row is unattributed
   and probably HVF **[I]**. If native is slower than the backend it is replacing on the single
   most workload-critical primitive, **the pivot's premise needs re-litigating before any further
   investment in either direction** — that is a bigger decision than this paper's. One A/B run
   settles it.

3. **The goal is portability-as-product rather than a working macOS runtime.** If carrick's
   thesis is "Linux binaries run natively on *any* Unix," then breadth is the product and
   Option A is correct despite everything above — but then the aarch64-BSD campaign should be
   scoped honestly as *at least* one L-sized host shim per lane, with a JIT design that respects
   NetBSD PaX MPROTECT and no `carrick trace`, and the Darwin C shim should be seamed behind a
   trait first (M–L, shared across both lanes, and it improves Darwin's testability regardless).

4. **The NetBSD mid-guest-signal fixture shows corruption.** If the fsbase-swap analysis is
   wrong, the failure is host-side memory corruption, the NetBSD lane is not trustworthy, and
   every aarch64-BSD estimate that assumes the same seam shape gets much more expensive. Cost to
   find out: one fixture (S). This should happen regardless of which option wins.

5. **The Codex fleet returns.** It authored ~52–56% of July commits and has been effectively dark
   since 2026-07-22 **[V]**; last-week throughput (24–43/day vs ~60) is explained by that, not by
   the work getting harder. Any plan sized against recent velocity is sized against roughly half
   the historical capacity. With it back, primary + secondary + a scoped Option A are all
   affordable in parallel.

6. **Someone actually needs `--platform linux/amd64` in production.** Then VMM is permanent, not
   transitional, and it deserves maintenance investment (its baselines are empty and its live
   tests skip silently) rather than the parking this paper recommends.

7. **A user-facing deadline exists for a specific workload.** Rank by that workload, not by LTP
   counts. The project's own guidance is right here: LTP parity is not workload coverage — no
   LTP case pushes `brk` past 4 MiB, which is how a bhyve bug that crashed 100% of CPython hid
   behind a healthy ~70% LTP score for weeks.

---

## 5. Recurring process costs and their durable fixes

Each of these has cost real hours more than once. Each has a specific, cheap, mechanical fix.

| Recurring cost | Evidence | Durable fix |
|---|---|---|
| **The operating manual reached ~half the fleet, and is wrong where it lands.** AGENTS.md had 18 commits of investment and loaded in **zero** Claude Code sessions until `d763a98e` (2026-07-25) added CLAUDE.md. ~41–56% of recent commits were authored by agents that never saw the rules on codesigning, test invocations, honest framing, or clean-room. | `git log --diff-filter=A -- CLAUDE.md` → one commit, yesterday **[V]** | CLAUDE.md is landed; **follow through by fixing the false claims in AGENTS.md** (§1 table). A wrong manual amplified across the fleet is worse than no manual. Item 2 above. |
| **No aarch64-BSD cross-compile gate**, so trivial compile blockers are found by booting VMs. | `rg 'aarch64-unknown-(freebsd\|netbsd)' justfile .github/ scripts/` → **zero hits** **[V]**; ~10 of the last 22 commits are this class of tax | Add `just check-freebsd-arm64` / `check-netbsd-arm64`; extend `check-netbsd` past `-p carrick-vmm-nvmm` to the native closure. Hours. |
| **"Gate-to-hide": failing tests gated as environmental.** `38f30a20` gated 3 tests; `c5a1cee9` proved **0 of 3** were environmental — both failed pre-existingly on the merge base, and several were testing the wrong contract outright. The correction cost a full extra round. | `c5a1cee9`, `7f37bdf1`, `786c5bf3` **[V]** | A semgrep rule alongside `.semgrep/typed-domains.yml` rejecting a new `#[cfg(not(target_os = ...))]` or `#[ignore]` on a test without a linked root-cause reference. The enforcement mechanism (`just lint-domains` in `just ci`) already exists. |
| **Gates that measure nothing and report green.** `bsdvm` stage1 was `cargo build --workspace`, structurally incapable of going green for days (`d736a69b`); stage1 is `report_only` so a red stage prints PASS; the probe gate SKIPs everything and reports `ok` in 0.04s from the wrong cwd; bhyve/NVMM live tests `eprintln!("skip")` and return when fixtures are unset; `just check-matrix` gates a render of a five-week-old file. | All **[V]** | Make **red-first proof a requirement for every new gate** — the habit `9c421058` already established ("verify what refresh-golden publishes instead of assuming it"). A gate that has never been observed red gated nothing. |
| **Scout/report overstatement, caught late.** ~20 commits since 2026-07-01 exist purely to correct an earlier claim (`db9796cb`, `b88f9e80`, `dd5e2552`, `00c87354`, `8c65d42d`, `9210dc97`, `786c5bf3`, `bd42be44`…). | **[V]** | The VERIFIED/INFERRED/UNKNOWN tagging plus an adversarial verifier pass — the pattern that produced *this* paper and demonstrably caught five wrong claims — should be the **required template** for scouts and campaign reports, not an occasional practice. |
| **Results are produced and never blessed back.** `oracle-cache.jsonl` fresh at 2026-07-15; `baseline.jsonl` last blessed 2026-06-20. Conformance runs happen; nothing writes the verdict down. | **[V]** | Make "bless or record why not" part of a campaign's definition of done, and **stamp `docs/support-matrix.md` with the lane, backend, commit and date it was rendered from** — today it names none of them. |
| **Nothing reclaims what it creates.** 24,219 leaked endpoint files (99.8% dead-owner, fixed in `f0ac2327`); 46 GB across 16 stale agent worktrees, several holding *stale copies of `baseline.jsonl`* that a grepping agent can mistake for the real one. | `du -sh .worktrees .claude/worktrees` → 31G + 15G **[V]** | Reap the worktrees now; script a reaper. The wrong-file-edit risk from stale repo copies is the real cost, not the disk. |
| **The debt ledger is invisible.** 5 TODO/FIXME comments in all of `crates/`; ~30 open red-list items live in five long design docs and a month of commit bodies, in at least three separate unlinked lists. | **[V]** | Promote them into one tracked in-repo ledger keyed by severity and lane, linked from AGENTS.md. This paper is most of the content. Items **will** be lost as campaign context rolls over. |
| **A dormant CI job is pre-loaded with a known footgun.** `.github/workflows/ci.yml:288` runs `cargo test --workspace` in `hvf-conformance`, and `#[ignore]`d tests — which *are* the guest-execution coverage — would not run even if it were enabled. | **[V]** | Point it at `just test` + `just test-integration`, and add an explicit `--ignored` step for the guest-booting tests, **before** anyone registers a runner. |

---

## Appendix — the three highest-severity open correctness items

1. **VMM fork-child network cleanup, two sites.** `network_after_fork_child` has zero callers
   outside `native/fork_child.rs` **[V]**. Both VMM `ForkOutcome::Child` arms omit it, and the
   multi-threaded `vcpu_loop/quiesce.rs` arm — the one every real container takes — also omits
   `mem_after_fork_child`. Unconditional harm: a forked child holds copies of the parent's relay
   and publication sockets for its whole lifetime, so if it outlives the parent the published
   host port stays bound with nothing servicing it (hang class). Conditional harm (error paths
   only, since children `_exit`): the child's provider `Drop` can delete the parent's live
   published-port records. On the lane AGENTS.md calls release-quality; the native lanes get it
   right. Fix: S.

2. **NetBSD fsbase-swap seam is unmeasured.** Mid-guest signal delivery + resume, async kick,
   multi-threaded clone capture, and fork rebuild are all **analysis, never executed** — the
   lane's own evidence doc says so, ordered by priority **[V]**. All four acceptance fixtures are
   single-threaded, fork-free and signal-free. If the mcontext `_mc_tlsbase` round-trip argument
   is wrong, host code resumes with the **guest** FS base installed: silent host-side memory
   corruption, not a clean crash. Highest severity-if-wrong item in the tree. Fix: one fixture, S.

3. **Published-port subsystem, partially closed.** Four real bugs landed here in two days
   (EAGAIN-as-EOF breaking keep-alive on every BSD host; cross-instance misroute serving one
   container's traffic to another; 24,219 leaked records; relay scoping) **[V]**, and the
   subsystem has **zero** conformance coverage. Remaining documented residuals: a connect TOCTOU
   that can hand a guest's bridge connection to an unrelated host process that rebound the port
   (security-relevant, closable only with SCM_RIGHTS fd passing), pid-reuse false-live, duplicate
   `--name` aliasing, and ~50% name-hash collision around 300 concurrent named containers. Fix:
   S for coverage; M–L for IPAM and fd passing.

**Standing caveat, per the project's own rule:** carrick remains experimental. Syscall coverage
is partial, guest behaviour is incomplete, there has been **no adversarial security review**, and
a guest is not a hardened trust boundary. Nothing in this paper changes that, and "unreviewed
security posture" belongs on the risk ledger as a line item rather than as ambient context.

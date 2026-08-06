# Category budgets: the Move-0 policy artifact

**Date:** 2026-08-05. **Scope:** Darwin/aarch64 native backend
(`--exec-backend native`, the shipped default), cold `go build` as the
canonical workload. Instantiates Move 0 of
[`2026-08-05-category-collapse-strategy-design.md`](../superpowers/specs/2026-08-05-category-collapse-strategy-design.md)
(§3, "Move 0 — category budgets, with Docker-side denominators"): it joins the
fresh Docker in-container CPU split to the v5 carrick category shares and the
official total-CPU median, and produces the per-category CPU-second budget
table every subsequent perf work item on this campaign is ranked against.

No new measurement was taken for this document — it is pure arithmetic over
already-measured inputs, with derived figures marked as such.

---

## 1. Inputs

| input | value | source |
|---|---|---|
| carrick total CPU, median (n=5) | **20.167694 s** | [`2026-08-04-current-default-wall-refresh.md`](2026-08-04-current-default-wall-refresh.md), Carrick sample 5 of 5 ("current median Carrick CPU is 20.167694 s") |
| carrick total CPU, used for arithmetic below | 20.168 s (rounded per the task brief) | *derived* — rounds the row above to 3 decimals |
| Docker `build-cold` `user_s` median (n=5) | **2.010 s** | [`2026-08-05-docker-cpu-split.md`](2026-08-05-docker-cpu-split.md), medians table |
| Docker `build-cold` `sys_s` median (n=5) | **0.150 s** | [`2026-08-05-docker-cpu-split.md`](2026-08-05-docker-cpu-split.md), medians table |
| Docker `build-cold` `cpu_total_s` median (n=5) | **2.160 s** | [`2026-08-05-docker-cpu-split.md`](2026-08-05-docker-cpu-split.md), medians table (= `user_s` + `sys_s`) |
| carrick avg cores busy on this build | **~2.5** | [`2026-08-03-build-serialization-attribution.md`](2026-08-03-build-serialization-attribution.md) §1 ("carrick … avg cores busy **2.5**") |
| Docker avg cores busy on this build | **~2.8** | [`2026-08-03-build-serialization-attribution.md`](2026-08-03-build-serialization-attribution.md) §1 ("docker … avg cores busy **2.8**") |

### v5 category shares (carrick-side, % of all sampled CPU)

| category | capture A | capture B | midpoint (used below) |
|---|---:|---:|---:|
| Darwin kernel (total) | 48.0232% | 48.7901% | **48.4067%** |
| — named-syscall | 27.7520% | 28.8889% | **28.3205%** |
| — non-syscall (faults, VM) | 20.2712% | 19.9012% | **20.0862%** |
| translated guest | 25.8818% | 25.3278% | **25.6048%** |
| Darwin userspace (libs) | 10.0290% | 9.9863% | **10.0077%** |
| other Carrick host code | 8.3174% | 8.5377% | **8.4276%** |
| translation | 6.0589% | 5.9643% | **6.0116%** |

Midpoint = (A+B)/2, per the task brief's instruction to use the midpoint of
each A/B pair. Named-syscall + non-syscall midpoints sum to 48.40650%, which
matches the kernel-total midpoint (48.40665%) to within rounding — the split
is internally consistent.

**Source note (read this before citing the shares elsewhere).** The brief
names [`2026-08-04-current-default-broad-cpu-attribution.md`](2026-08-04-current-default-broad-cpu-attribution.md)
"as restated in `handoff.md`" as the source. That phrasing matters: the
percentages above are copied verbatim from `handoff.md` lines 327-331 ("Task
12", commit range `8214c136`, signed binary SHA-256 `74a1c9be…`). They are
**not** the numbers currently written in the body of
`2026-08-04-current-default-broad-cpu-attribution.md` itself — that file's
"Broad result" table records an earlier, differently-provenanced capture
(run ids `dsr-20260804T092759…`/`dsr-20260804T093221…`, kernel
50.6261%/50.8335%, translated guest 22.8261%/22.7193%, translation
7.1875%/5.9728%, etc.), which the file's own text says was later superseded
by the wall-refresh doc for *timing* but whose *shares* were themselves
superseded again by the later Task 12 capture — a supersession recorded only
in `handoff.md`'s prose, never written back into the dated doc file. This
document uses the more recent, more-tested Task 12 numbers (matching the
brief's literal instruction) and flags the discrepancy so a future reader who
opens the dated doc directly isn't misled by the older table there.

---

## 2. Today's CPU-seconds per category

Midpoint share × 20.168 s, one row per category. Kernel's two sub-rows
(named-syscall, non-syscall) are shown for reference but are **not** added
into the sum separately — they already compose the kernel-total row above
them.

| category | midpoint share | CPU-s today |
|---|---:|---:|
| Darwin kernel (total) | 48.4067% | **9.763** s |
| — named-syscall | 28.3205% | 5.712 s |
| — non-syscall | 20.0862% | 4.051 s |
| translated guest | 25.6048% | **5.164** s |
| Darwin userspace | 10.0077% | **2.018** s |
| other Carrick host code | 8.4276% | **1.700** s |
| translation | 6.0116% | **1.212** s |
| **residual (unattributed sampling remainder)** | 1.5418% | **0.311** s |
| **Sum (top-level rows only: kernel + translated guest + Darwin userspace + other Carrick + translation + residual)** | 100.0000% | **20.168** s |

The residual is real, not rounding noise at the row level: the seven named
top-level categories' midpoints sum to 98.4583% of all sampled CPU (they
never claimed 100% — `process setup`, `gateway`, `dispatch`, and
`unresolved` from the underlying attribution's finer table, plus normal
sampling variance between captures A and B, account for the remainder). It is
listed as its own row rather than folded silently into any named category.

---

## 3. The 3x target

The campaign goal (spec §"Goal") is cold `go build` **within 3x of
native-arm64 Docker**, with the 2x product bar as the horizon. That ratio is
stated on **wall-clock time**; converting it into a **CPU-second** budget
requires an assumption about parallelism, because CPU-seconds = wall ×
average cores busy.

**Equal-parallelism assumption.** [`2026-08-03-build-serialization-attribution.md`](2026-08-03-build-serialization-attribution.md)
measured carrick at **~2.5** average cores busy on this build and Docker at
**~2.8** — close enough that a 3x reduction in wall-clock time, at
unchanged parallelism, corresponds approximately to a 3x reduction in total
CPU-seconds. Under that assumption the CPU-second target can be set directly
from Docker's own measured total CPU rather than re-deriving it from a wall
target and an assumed core count:

```
target total carrick CPU = 3 × Docker cpu_total_s = 3 × 2.160 s = 6.480 CPU-s
```

**2x product bar** (*derived*, same method):

```
2 × Docker cpu_total_s = 2 × 2.160 s = 4.320 CPU-s
```

Both are *derived* figures — they inherit whatever error is in the
equal-parallelism assumption, which is not re-verified here.

---

## 4. Budgets per category

Instantiating the spec's Move-0 shape (§3) with the real numbers above:

### 4a. translation + translation-lock + translation-metadata: ≈ 0 (amortized)

Budget: **0.000 CPU-s**. Per Move 1 of the spec, the live arena's whole
purpose is translate-once/attach-many; once it lands runtime-on, this
category (and the parts of "other Carrick" and kernel non-syscall it
subsumes — the published-block lock, publication-recovery allocation, and
PC-map/recovery metadata zfod) is expected to amortize toward zero rather
than being individually budgeted. This is the spec's own framing, not a new
derivation.

### 4b. translated guest: ≤ 1.3 × Docker `user_s`

```
1.3 × 2.010 s = 2.613 CPU-s
```

Budget: **≤ 2.613 CPU-s**.

### 4c. Darwin kernel: ≤ 2 × Docker `sys_s` — implausible; fallback applies

```
2 × 0.150 s = 0.300 CPU-s
```

**This is implausibly small.** Today's carrick kernel CPU is **9.763
CPU-s** (§2) — about **32.5x** larger than 0.300 CPU-s. Treating 0.300 CPU-s
as a literal near-term kernel budget would require a 96.9% cut in kernel CPU
achieved by Move 3 alone, which no ledger entry in the spec projects. Per the
brief, the fallback applies instead:

```
kernel budget = target total − (translation + translated guest + carrick-host/Darwin-userspace)
```

(worked in §4e below).

**Verdict on the spec's §6 third invalidation condition.** §6 asks: *"Docker-
side measurement shows the kernel budget is already near 2x Docker sys"* —
i.e., is today's measured kernel CPU already close to the 2x-`sys_s` figure,
implying the kernel bucket is mostly an artifact induced by translation/guest
amplification rather than an independent tax, so Move 3 could shrink to the
named entries only?

**Verdict: the condition does NOT hold — carrick kernel CPU (9.763 CPU-s) is
far above, not near, 2x Docker sys (0.300 CPU-s), by roughly 32.5x.**
Consequence for the spec's §6 Move 3 scope: this invalidation condition is
**not triggered**, so Move 3 does **not** shrink to the named entries only —
the full standing amplification ledger (spec §3 Move 3: "top ~20 guest
operations on the build") remains in scope. This is reinforced by a detail
the aggregate comparison alone doesn't show: named-syscall CPU alone (5.712
CPU-s, §2) already exceeds the fallback kernel budget derived below (§4e),
and named-syscall work is largely outside Move 1's translation-amortization
attack surface (Move 1's table in spec §3 only claims the non-syscall/fault
portion of kernel, via metadata zfod and lock wait). So even a fully
successful Move 1 would not, by itself, bring kernel CPU near the naive
2x-`sys_s` figure — Move 3's per-operation ledger against named syscalls
(mmap, fs-walk, exec chain) is doing real, unshared work in this budget, not
redundant work that translation fixes would have covered anyway.

### 4d. carrick host + Darwin userspace combined: ≤ ~1 CPU-s

Per the spec's Move-0 shape (§3, stated directly, not derived here):

Budget: **≤ 1.000 CPU-s** combined for "other Carrick host code" (today
1.700 CPU-s) + "Darwin userspace" (today 2.018 CPU-s) — a combined *today*
figure of 3.718 CPU-s that must fall to ≤1.000 CPU-s combined, partly as a
side effect of Moves 1-2 (the spec notes the named allocation owners inside
these buckets are translation-linked).

### 4e. Kernel budget, fallback arithmetic, and the full budget table

```
kernel budget (exact residual) = 6.480 − (0.000 + 2.613 + 1.000)
                                = 6.480 − 3.613
                                = 2.867 CPU-s
```

Setting the kernel budget to that exact residual would make the budget sum
equal the target with **zero** slack. To keep the "≤" honest against
measurement/rounding noise in the inputs above (each of which is itself a
median with sample-to-sample variance), the kernel budget below is rounded
**down** to 2.800 CPU-s, deliberately reserving the difference as explicit
slack rather than spending it:

| category | budget | today's CPU-s (§2) | required change |
|---|---:|---:|---:|
| translation + lock + metadata | ≤ 0.000 s | 1.212 s (translation only; lock/metadata are inside kernel/other today) | amortize toward 0 |
| translated guest | ≤ 2.613 s | 5.164 s | −2.551 s (−49.4%) |
| Darwin kernel | ≤ 2.800 s | 9.763 s | −6.963 s (−71.3%) |
| carrick host + Darwin userspace (combined) | ≤ 1.000 s | 3.718 s | −2.718 s (−73.1%) |
| **Budgeted sum** | **6.413 s** | — | — |
| **3x target** | **6.480 s** | — | — |
| **Slack (target − budgeted sum)** | **0.067 s (1.03% of target)** | — | — |

Budgets sum to **6.413 CPU-s ≤ 6.480 CPU-s target**, with **0.067 CPU-s**
(~1.03%) of explicit slack. The kernel row carries the largest single
reduction in both absolute (−6.963 s) and relative (−71.3%) terms — consistent
with the spec's own §4 characterization of the kernel move as "the hardest
ask" (spec: kernel "≈10 CPU-s → ≈4", broadly the same order of magnitude and
direction as the 9.763 → 2.800 figures resolved here with the fresher Task 12
shares).

---

## 5. The ranking rule

Work items on this campaign are ranked by **category-budget movement** against
the table in §4e, not by raw mechanism percentage: a change is prioritized by
how far it moves its category's measured CPU-seconds toward that category's
budget, not by whether it individually clears any fixed threshold. ABBA
retention discipline is unchanged — a candidate is only retained if it wins
its ABBA (paired, same-instrument, both arms held constant except the one
variable), regardless of how much category-budget movement it projects to
before being measured. The ≥10% gate that governed the prior sequential
mechanism-at-a-time policy remains in force as an **attribution filter** (it
still decides whether a mechanism is worth measuring at all) but is no longer
a **veto**: a family of related, source-distinct mechanisms that are
individually below 10% but addressable by **one** mechanism — one compiler
pass, one shared mapping, one lowering — is judged as a single candidate
against its combined share, exactly as the spec's worked example treats the
16.07-16.17%-of-CPU context-traffic family (ctx-load64 + ctx-store64) as one
candidate rather than two sub-10% rejects. See
[`2026-08-05-category-collapse-strategy-design.md`](../superpowers/specs/2026-08-05-category-collapse-strategy-design.md)
§3 ("Move 0") and §2 for the full policy this restates.

---

## Verification

Recomputed by hand (Step 2 of the task brief):

- **Kernel:** midpoint 48.4067% × 20.168 s = 9.7627 s → rounds to **9.763 s**,
  matching the table in §2.
- **Translated guest:** midpoint 25.6048% × 20.168 s = 5.1640 s → rounds to
  **5.164 s**, matching the table in §2.
- **Category sum:** 9.763 + 5.164 + 2.018 + 1.700 + 1.212 + 0.311 =
  **20.168 s**, matching the carrick total CPU input to the last digit used.
- **Budget sum:** 0.000 + 2.613 + 2.800 + 1.000 = **6.413 s ≤ 6.480 s**
  target, slack **0.067 s**.

All rows checked; sums close to the stated precision.

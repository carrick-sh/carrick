# Overhead campaign narrative (moved from AGENTS.md on 2026-09-06)

The measurements, corrections and per-operation ledgers that used to live in
`AGENTS.md`'s Engineering standards. Every number here is dated; treat undated
claims as hypotheses. The rulebook keeps only the bar and the ranking rule.

## Original text

**The two gates. Nothing else matters if these fail: correctness, and
"zero"-overhead.** Carrick's whole premise is running Linux binaries at
host-native cost. A correct-but-slow runtime and a fast-but-wrong one are both
dead ends, so every change is judged against those two first and against
elegance, generality or effort saved second. Overhead is not a "later"
concern — it is half the product.

**The two gates are ORDERED, and pathology is a correctness signal.** The
owner's ranking is explicit: reach 100% conformance first, then get within 2x of
Docker; going sub-1x is welcome but is never the thing to chase first. The
corollary is the useful part — **a pathological ratio is evidence of an INCORRECT
implementation, not merely a slow one.** When a suite runs 30-50x the oracle,
look for the wrong algorithm, not a tuning knob: `ltp-munmap04` at 47x and
`ltp-mmap18` at 34x COMPLETE, so they are not hangs — carrick is doing
structurally wrong work per operation. Treat that as a bug hunt with a
correctness fix at the end of it.

**Read a conformance perf ratio with the timeout budget in hand.** A hung suite
reports as spectacularly "slow" because it sits on its deadline: on the
2026-08-16 run the ten worst ratios (cpython-mmap 490x, context 297x,
tracemalloc 212x, ...) were all exactly 300.3 s — the suite budget — and a second
tier at exactly 30.5 s was LTP's own internal timeout. Excluding timeouts moved
the picture from a misleading 2.53x MEAN to a 0.94x MEDIAN, with 88.3% of suites
inside the 2x bar and LTP aggregating at 1.11x. So: fixing a hang removes a
"490x" row, and quoting the raw ratio of a timed-out suite as a performance
number is simply wrong. (That whole dataset also ran 8 workers on a 10-core
host, which makes every number contention-inflated and therefore a hypothesis,
never a controlled measurement.)

- **The overhead bar is WITHIN 2x of native-arm64 Docker** on the same workload.
  That is the number to rank against. As of 2026-08-01 the native lane was
  **~14.5x** on the cold go-build; **as of 2026-08-07** (the Move-3 campaign's
  closing refresh, after the anon-reuse-remap and stat-cache-interning fixes)
  the official shipped-default ratio is **10.1806x**
  ([`docs/perf-results/2026-08-07-post-move3-default-refresh.md`](docs/perf-results/2026-08-07-post-move3-default-refresh.md)),
  so reaching the 2x bar still means removing **80.36%** of current Carrick
  wall — every overhead bucket, not one of them. Rank work by whether it can
  plausibly be a multiple, and be honest that a 3-15% improvement does not
  move a double-digit ratio. Original evidence:
  [`docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md`](docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md).
- **The build-lane CPU split, with the correction that supersedes it.** An
  earlier reading of the budget put carrick's own host userspace at 36.9% of CPU
  and inserted codegen at 18.6%, and that ranking was quoted here for months. It
  is WRONG and was corrected in place by
  `CORRECTION-user-module-split-codegen-IS-the-biggest-bucket` (`e63975d3`,
  `docs/perf-results/native-dsr-shape-census.jsonl`): 58% of user PCs matched no
  per-process JIT snapshot and were read as host code, when they were mostly
  JIT. Measuring instead with `umod(uregs[R_PC])` — any PC in no Mach-O image IS
  the `MAP_JIT` cache, so no snapshot join and no unwind is needed — gives
  **JIT 52.9% of total CPU, inserted codegen ~36.4%, carrick's own host text
  11.5% (+6.1% dylibs), kernel 29.5%, guest-shaped JIT words 16.5%.**
  So **emitted code is the largest bucket on the build**, and "carrick's own
  userspace has never been attacked" is worth about a third of what that reading
  implied.
- **Re-measured 2026-08-02 (supersedes the split above).** Sampling with the
  tracer's own pid excluded — `native-cpu-attribution.d` screened on
  `execname == "carrick"` and `carrick trace` runs libdtrace IN-PROCESS, so 54%
  of the old profile was the profiler — gives **user 67.6% / kernel 32.4%**, and
  within user **66.4% unsymbolized (the JIT cache), 13.3% carrick's Rust, 8.7%
  memcpy/memset, 7.8% malloc**. Emitted-code execution is **~45% of all build
  CPU**. The historical shape census put the DSR-overhead floor at **52.4% of
  executed emitted instructions, down from 81.3%**; current attribution uses
  the authenticated `carrick debug jit-shape-census` tooling. The historical
  residue was concentrated in ONE thing: slot 1128 is the
  guest's virtualized **x17** (physical x17 is the DSR edge register, borrowed to
  hold virtual branch conditions), and every such edge publishes it
  (`str x17,[x28,#1128]`) and restores it (`ldr x17,[x28,#1128]`). The general
  shape is `ctx-load64` 25.0% + `ctx-store64` 8.7% = **33.7% of executed emitted
  instructions ≈ 15% of total build CPU**. Histogrammed by (slot, register),
  that traffic is NOT general guest-register spilling — carrick keeps guest
  registers in host registers — it is carrick saving and restoring the four
  physical registers it BORROWS: **x17 ~21%, x19 ~9%, x15 ~3.3%, x16 ~0.2%**.
  There is no register-allocation problem; there is a stolen-register problem,
  and the borrow is gated on the emitter's own needs rather than on whether the
  guest value is LIVE. Note the ceiling:
  even PERFECT codegen leaves the build near 5x Docker, so the 2x bar needs the
  kernel and host-userspace buckets too.
- **The overhead workstream is still one thing: "utilize Darwin in the most
  efficient way to emulate Linux."** Carrick's host-side work and the kernel work
  it induces are not separate problems — they are the cost of LOWERING one Linux
  operation onto Darwin primitives, measured on the two sides of the syscall
  boundary. Rank by the **amplification factor
  of a single guest operation**, which is concrete and directly attackable
  where a CPU percentage is not:
  - guest `open` → **8.69 host opens** in-service-window on the **cold
    go-build** at HEAD (was 19.68 on 2026-07-28, before the trusted-dirfd
    lanes; total `openat`-window amplification 27.6x counting the
    resolution/mode tail, ~105 µs host kernel CPU per guest open). On the
    **fs-walk** fixture the same in-window figure is **2.37** (4.61
    counting every host `openat` in the run). Those are DIFFERENT WORKLOADS —
    pair like with like and do not read a ratio between them as progress.
    Full per-op ledgers:
    [`docs/perf-results/2026-08-06-build-lane-amplification-ledger.md`](docs/perf-results/2026-08-06-build-lane-amplification-ledger.md) (build),
    [`docs/perf-results/2026-08-05-fswalk-amplification-ledger.md`](docs/perf-results/2026-08-05-fswalk-amplification-ledger.md) (fs-walk);
    On fs-walk: whole fixture **2.05x** host per guest syscall (49,623/24,201,
    excluding 3,182 probable-tracer `kdebug_trace*`), 1.71x inside service
    windows. Still to drive toward 1: guest `openat` **5.91** host calls,
    `getdents64` **4.01** (of which six per directory are pure
    `fdopendir`/`closedir` preamble), `newfstatat` **2.86** — note the older
    "roughly one host call per guest stat" claim is true only of `fstatat64`
    itself. `close` (0.27) and `fcntl` (0.0009) are already below 1, so sub-1
    is reachable. **Open regression:** `carrick-only` `fstatat64` on this
    fixture went 32 (2026-08-02) → 5,802 (HEAD) with every guest-joined column
    flat — bisect that before starting a new fs lever;
  - guest `mmap(MAP_PRIVATE, fd)` → **lowered 2026-08-07** to a host
    `MAP_PRIVATE|MAP_FIXED` file mmap (was a `pread` of the FULL mapping
    length into fresh anon at `dispatch/mem.rs:2517`), default ON, hatch
    `CARRICK_MMAP_FILE_BACKED=0` (the sibling of `CARRICK_DSR_ZERO_REMAP`
    below). Fixes a real Linux divergence (private beyond-EOF SIGBUS), but
    its build-lane population is only 18 calls / 3.8 MiB/build — not the
    kernel-CPU lever this bullet originally named; see the fault-term
    correction below;
  - guest `execve` → WAS 4 full ELF materializations + 3 SHA-256 passes; the
    2026-08-02 exec lanes removed the payload hashing (metadata-only
    `ArtifactDigestCoverage`, hatch `CARRICK_EXEC_FAST=0`) and map eligible
    PT_LOADs `MAP_PRIVATE` from the executable's own host file (hatch
    `CARRICK_EXEC_FILE_BACKED=0`). What remains: the host self-re-exec's
    ~8.5 ms fixed chain, mostly Darwin's own exec floor
    (`docs/perf-results/2026-08-03-native-exec-fixed-cost-decomposition.md`),
    and ONE remaining full read of the executable for loader planning.
    (Two prior claims here were stale and are corrected: `MAP_FIXED|
    MAP_ANONYMOUS` is already a single host mmap on the identity backend, and
    `map_prepared_for_plan` was live, not `dead_code`.)
  Drive each toward 1. **The fault term is dominated by CARRICK'S OWN host
  allocations, not the guest's memory.** The birth-keyed page census puts
  host-other at 63.2%/62.7% of sampled zfod (2026-08-03,
  [`docs/perf-results/2026-08-03-current-native-fault-ownership.md`](docs/perf-results/2026-08-03-current-native-fault-ownership.md)),
  re-confirmed at HEAD (63.26%/63.30%, the 2026-08-06 build-lane ledger —
  which also places 36% of all zfod inside guest `mmap` service windows).
  That in-window mass was 99.4% carrick's own **whole-range anonymous-reuse
  scrub** memsetting the ops' biased host backing — 98% of it serving
  hint-less `PROT_NONE` reserves that are provably zero already; it is NOT
  the guest touching its memory and NOT the eager `MAP_PRIVATE` file
  materialization (refuted 2026-08-06 by Task 5's population census: 18
  calls / 3.8 MiB per build)
  ([`docs/perf-results/2026-08-07-build-lane-fault-partition.md`](docs/perf-results/2026-08-07-build-lane-fault-partition.md)).
  **That scrub was replaced kernel-side on 2026-08-07** (`52342762`, hatch
  `CARRICK_DSR_ZERO_REMAP=0`): a fresh `MAP_FIXED|MAP_ANON` mapping now
  delivers the zeroed pages, collapsing in-window zfod 553k → ~723 and total
  build zfod by ~520k, retained on a −0.66 CPU-s (−3.2%) cold-build ABBA
  ([`docs/perf-results/2026-08-07-anon-reuse-remap.md`](docs/perf-results/2026-08-07-anon-reuse-remap.md)).
  The narrow 2026-07-29 claims
  survive (JIT first-touch 2.08% of zfod, inserted code 1.48%); that census's
  guest-dominates conclusion does NOT — it was superseded by the 2026-08-01
  audit and has been twice re-confirmed since. The remaining levers are
  allocation-side — buffer reuse / `MADV_FREE_REUSABLE` for the repeated
  ≥128 KiB buffers (the out-of-window 63% host-other mass) — as well as
  per-page cost.
- **Use Go's runtime as a DUAL-PORT ORACLE for "what should this lower to on
  Darwin?"** Go implements the same allocator abstractions (`sysAlloc`,
  `sysReserve`, `sysMap`, `sysUnused`, `sysUsed`, `sysFault`, `sysFree`)
  separately for `linux/arm64` and `darwin/arm64`, so diffing
  `$GOROOT/src/runtime/mem_linux.go` against `mem_darwin.go` shows exactly how
  one intent is expressed idiomatically on each OS. It is BSD-licensed — reading
  it is explicitly fine, unlike the Linux kernel side. Other subsystems
  (`os_darwin.go`, `sys_darwin.go`, signal and thread handling) serve the same
  purpose.
  - Worked example: **Go's Darwin port uses NO `mprotect` at all** for heap
    management. Its whole vocabulary is `mmap(MAP_ANON|MAP_PRIVATE)` to
    allocate, `mmap(PROT_NONE, …|MAP_FIXED)` to protect/fault,
    `mmap(PROT_READ|WRITE, …|MAP_FIXED)` to commit, and the
    **`MADV_FREE_REUSABLE` / `MADV_FREE_REUSE` pair** to decommit/recommit
    (leaving the VM entry intact). `mem_linux.go` DOES use `mprotect`. Same
    allocator, same intent, different primitive — because on Darwin `mprotect`
    is the expensive way.
  - The lesson generalizes: **translate the guest's INTENT, not its mechanism.**
    A guest `mprotect(PROT_NONE)` on heap means "decommit"; faithfully
    re-issuing a host `mprotect` reproduces a Linux idiom on the OS where it is
    the wrong one. Ask what a native Darwin program wanting that semantic
    actually calls, and lower to that.
- **Correctness is not tradeable for overhead.** A guest-visible ABI guarantee
  (e.g. anonymous `mmap` returning zeroed pages) is immovable — do not weaken
  one behind a "provably safe" fast path. Find a lever that removes the work
  instead of removing the guarantee. Note this usually costs nothing: mapping an
  image file-backed, or letting Darwin's zero-fill deliver a pre-zeroed page
  instead of memsetting it yourself, removes work AND keeps the guarantee.
- **A perf claim is a HYPOTHESIS until it comes from a controlled,
  single-variable experiment.** One knob at a time, everything else held —
  including the core class. On Apple Silicon `hw.logicalcpu` is NOT homogeneous
  (this host is 4 Performance + 6 Efficiency), so a concurrency sweep silently
  changes which cores run the work and is never a clean variable. Anything less
  than a controlled experiment is written as "suggests", never "confirmed".

**No backward compatibility. We are our own ecosystem.** There is no external
consumer to keep working, so do NOT carry a legacy path, a V2 beside a V3, a
compatibility shim, or a deprecated spelling. Replace it and delete the old one.
The cost of a second path is not the code — it is that every future measurement,
test and reader now has two answers to reconcile.

**Rust first, and extend OURSELVES rather than growing a tool zoo.** The first
language you reach for is Rust, and the first home for a new capability is our
own binary — a `carrick trace` profile or a `carrick debug` subcommand — not a
new standalone script.

- **D scripts** are for what only D can do, and they belong to a Rust profile
  rather than standing alone: `carrick trace` hashes a profile's D program into
  its output header (`program_sha256`), so the script becomes an authenticated
  input with a Rust parser and validator around it. A new `.d` should arrive as
  a new `TraceProfileKind`, not as a file someone runs by hand.
- **Python** is for driving lldb, where it is the only in-process option.
- Everything else — capture orchestration, parsing, validation, statistics,
  report generation — is Rust in our own crates, where the type system, `just
  ci`, and `-D warnings` apply. Ad-hoc shell/Python harnesses are untyped,
  untested, ungated, and drift from the runtime they measure.
- Rust owns the truth; the D script consumes it. `carrick debug
  native-x86-layout` exists precisely so offsets are read from the running
  binary instead of hardcoded into a `.d` — follow that pattern.

**Look for what already exists before writing anything new.** This tree is large
and has usually already solved the adjacent problem. Grep for the mechanism, the
probe, the helper, the harness — and read it — before adding a parallel one. A
second implementation is worse than a slightly-wrong first one, because now both
drift. (Worked example: a fault-address census, its parser, and its test already
existed as `scripts/dtrace/native-fault-attribution.d` +
`scripts/perf/native_fault_directional.py` while a campaign doc was still
recording the fault term as "blocked on instrumentation.")

**Opt-OUT, not opt-in — a default-off mechanism is not shipped, it is
abandoned.** This project has repeatedly built a mechanism, gated it behind
`FEATURE=1`, and then left it dead for months: the whole container-lifetime
shared-translation lane, the H004 direct-binding sidecar, and the artifact spike
are all in the tree, compiled, tested and unreachable. That pattern hides
regressions (nobody runs the arm), rots the code (it drifts from the default
path), and lets a "landed" change never actually land.

- New work defaults **ON**, with an exact `=0` escape hatch for bisection.
- If it cannot be defaulted on, it is not finished — say so plainly rather than
  merging it dark.
- When a mechanism is MEASURED WORSE, **delete it**; do not park it behind a
  flag. `git` is the version control — the code is recoverable, and a commit
  message pointing at the measurement is worth more than dead code carrying an
  implication that it might still be a good idea.
- The same applies to tests: a test that no gate executes is not a test. Check
  that a new suite actually runs (`carrick-cli` has no lib target, so its
  in-file `mod tests` and integration suites are compiled by clippy and never
  run by `just test`/`just test-integration`).

- **Ask Darwin only for what Darwin owns.** Carrick has its own kernel now, so
  the host is the authority for real I/O and real hardware — files, sockets,
  memory, the time source, the CPU — and for nothing else. Identity (pid/tid/
  uid/gid/capabilities), process relationships, resource limits, the network
  NAMESPACE view, and signal delivery between guest processes are guest state and
  must be answered from the kernel graph keyed by the exact task. Delegating one
  of those does not return an approximate answer, it returns the HOST'S answer:
  `SCM_CREDENTIALS` handed guests the Mac user's uid/gid, the interface list
  handed them the Mac's `en0` IPv6, and guest DNS through host `getaddrinfo`
  dragged in fork-unsafe ObjC that aborted every forked child. Standing audit and
  the ranked fix list: [`docs/host-facility-boundary.md`](docs/host-facility-boundary.md).
- **NEVER read Linux kernel or other GPL source when implementing carrick.**
  Clean-room only: derive ABIs from man-pages/specs and the differential Docker
  oracle (`bpftrace`/observe behaviour, diff verdicts). This is
  non-negotiable.
  (Reading LTP *test* source — the oracle itself — is a separate, grayer matter.)
- **Typed domain values are the baseline — bare `u64`/`i32` never crosses a
  semantic boundary.** Three shipped bugs (the `!wait_set` polarity hang, the
  `alarm`↔`epoll_create` private-number collision, the poll int-vs-timespec
  timeout) all reduce to "two domains shared one integer type". The rules,
  ranked audit, and staged plan live in
  [`docs/typed-interfaces-audit.md`](docs/typed-interfaces-audit.md):
- **That migration typed SCALARS and stopped there — the four domains it does
  NOT cover are where the HVPatch bugs live.** Populations (`kicker.count()` vs
  `task().threads().len()` are both `usize`, and there are EIGHT such sets),
  thread lifecycle ("alive" vs "can reach a safe point", which must be asked
  per-purpose), address-space ownership ("which mm" is not a value, it is
  `self`), and scope (a `static` carries no mark saying whether it describes the
  carrier or one Linux process). All four were TRUE statements under the retired
  one-process-per-guest model, so the code that relies on them still compiles,
  still passes, and still explains itself in terms of a model that no longer
  exists — three defects carry doc comments actively justifying the wrong
  behaviour. Critically, **every instance is correct while exactly one Linux
  process exists and wrong the instant a second appears**, and the smoke lane is
  a single `run-elf` process where carrier pid, root task id and `getpid()`
  coincide numerically — so the gate structurally cannot see this class, and a
  case exercising TWO live guest processes is worth more than any number of
  single-process cases. Evidence, the 42 audited sites, and the proposed
  architecture:
  [`docs/identity-and-scope-domains.md`](docs/identity-and-scope-domains.md).
  - Use the existing types; don't re-raw them: `Fd`/`HostFd` (guest vs host
    descriptors), `NsPid`/`HostPid` (translate, never wrap the wrong domain),
    `Signal`, `GuestPtr`/`GuestLen`, `SigSet`/`SigBlockMask`/`WaitSigMask`
    (set vs park-mask polarity), `CanonicalNr`/`NativeNr` (syscall numbering),
    `GuestVa`/`Gpa`/`HostVa` (address spaces), `LinuxErrno`
    (`guest_retval()` is THE negation point), and the `bitflags` types.
  - New number/flag tables derive from an ordinal enum or `bitflags!` — never
    hand-numbered constants (add a compile-time uniqueness assert when a table
    can't be an enum).
  - Where polarity or direction matters, the type has NO general `from_raw`:
    construction goes through a NAMED semantic constructor
    (`SigBlockMask::for_signal_wait`, `WaitSigMask::Additive/Replace`). Raw
    escapes only at libc/wire/atomic boundaries via explicit `.raw()`/`.get()`.
  - Enforcement is mechanical, not aspirational: workspace-`deny`ed
    `unreachable_patterns` + `bindings_with_variant_name` (the unimported-const
    match-arm catch-all is a build failure), and **`just lint-domains`** — the
    semgrep gate ([`.semgrep/typed-domains.yml`](.semgrep/typed-domains.yml))
    that blocks the shipped bug shapes (raw wait-set complements, bit=`signum`
    masks, host pids in `NsPid`, hand-numbered private numbers, function-local
    `LINUX_*` consts, inline errno negation). It runs inside `just ci`.
  - Mechanical migrations go through
    [`scripts/migrate/rewrite.py`](scripts/migrate/rewrite.py) (count-asserted,
    all-or-nothing rewrite specs) so a repeated-shape pass is a reviewable
    artifact, not a pile of hand edits.
- **No pragmatic shortcuts — fix the root cause.** If a backend has a bug, fix the
  backend; don't gate it with a shell hack, swap a real implementation for a
  cheaper approximation, or paper over it. If you catch yourself reaching for a
  workaround, stop and do it properly.
- **Definition of Done = live-verified end-to-end, not "it compiles."** Don't
  report a goal complete until you have a clean build, passing tests, **and** an
  actual runtime demo of the behaviour. If something compiles but fails at
  runtime, it isn't done.
- **Prefer Darwin-native kernel mechanisms** over hand-rolled userspace
  (`sendfile(2)`, `kqueue`/`EVFILT_*` for epoll, `__ulock` for futex, macOS ptys).
  Userspace reimplementations tend to deadlock the vCPU or mishandle
  EAGAIN/backpressure.
- **Choose state authority by execution lane, not by host-process accident.**
  Native/VMM paths can fork real host processes, so state that must cross those
  forks cannot live only in a private `HashMap`; use durable/fork-coherent
  authorities such as xattrs, inherited fds or host-kernel bookkeeping. HVPatch
  guest `fork` stays inside one carrier, but the inverse trap applies: Darwin
  PID/process-owned state represents the carrier, not a logical Linux process.
  Put Linux process semantics in the kernel graph keyed by exact
  `TaskKey`/generation (or an explicitly shared description/namespace), never a
  process-global host PID, timer, ptrace session, classic lock owner or similar
  surrogate. Shared cross-lane code needs a typed backend authority rather than
  silently choosing either model.
- **Use the `libc` crate, not ad-hoc `extern "C"` blocks** (`libc::fork`,
  `waitpid`, `pipe`, `ioctl`, …). Exception: `applevisor-sys` raw `hv_*` bindings.

---


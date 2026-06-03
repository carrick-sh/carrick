# `go build` under carrick: the multithreaded-toolchain syscall-boundary fault

**Status:** tracked carrick runtime gap (not yet fixed). Surfaced by the unified
conformance harness (the Go suites) running under `--fs host`. First diagnosed
2026-06-03, then **re-diagnosed 2026-06-03** when the original "post-fork
`MAP_SHARED` stage-2 coherence" root cause was empirically **refuted** (see
"Correction" below). The earlier filename/title is kept for continuity; the
real gap is a carrick **trap-path** fault, not file-mapping coherence.

## Symptom

`go build` of *any* program (even a trivial `package main`) crashes under
carrick `--fs host`:

```
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x1c370]
...
cmd/vendor/golang.org/x/telemetry/internal/counter.(*file).newCounter1
```

The same build succeeds under **docker** (`linux/arm64`), so the container is
conformant — the gap is carrick's. The Go *runtime* is fine; only the parts of
the Go **toolchain** that run `go build` (and the `runtime` package's own
build-dependent tests, e.g. `TestCoroLockOSThread`, `TestAtomicAlignment`) hit
it.

## Correction: the original diagnosis was wrong

The first writeup blamed a **forked-child post-`hv_vm_map` stage-2 TLB
incoherence** of the telemetry counter's `MAP_SHARED` file mapping (`forked=1`).
That is **refuted**. Fresh traces with the current binary show:

```
HVMAP pid=… va=0x10000000000 ipa=0x1800000000 size=0x4000 rc=0 forked=0
PTWALK rc=0
… (5 distinct guest pids, distinct monotonic IPAs 0x1800000000/0x1800200000/…)
```

- **`forked=0`**, not 1: `go` is fork+**exec**'d from `sh`, so it runs in a fresh
  exec'd VM (a new vCPU), not a forked child. The original trace was stale
  (pre-`forked_no_exec`).
- The alias IPAs are **distinct** (a separate fork-shared monotonic allocator now
  guarantees this — a real latent fix, but unrelated; see below), `hv_vm_map`
  returns **rc=0**, and the stage-1 page-table walk is clean.
- With `GODEBUG=countertrace=1`, the **`go` parent maps its telemetry counter and
  increments EVERY counter coherently** (`go/invocations`, `go/goroot`,
  `go/subcommand:build`, …, all reading/writing `0x10000000xxx` correctly). The
  file mapping is **not** incoherent.
- **Every isolated probe PASSES** under carrick `--fs host`: plain `MAP_SHARED`
  store/read-back (`mmapfile`), cross-vCPU read of a freshly-mapped alias with
  pre-spawned sibling threads (`mmapfileshare_mt`, `readers_match 4/4`), and a
  **faithful replica of the telemetry `mappedFile` layout** — short header write,
  sparse 16 KiB extend, hash-table reads, record `writeEntryAt`, cross-vCPU
  `lookup`, file coherence (`telemetrymap`, all `true`) — run both via `run-elf`
  AND fork+exec'd from `sh` inside the go image. None reproduce the crash.

So the alias mapping mechanism works; the telemetry counter pattern works. The
gap is something the multithreaded `go` toolchain does that the probes do not.

## Actual root cause (trace-confirmed)

It is a **guest nil-pointer dereference that carrick faithfully delivers as
SIGSEGV** — the *cause* of the nil deref is a carrick trap-path bug, surfaced at
a **syscall boundary**, in the multithreaded toolchain.

Evidence from `carrick trace` (`scripts/dtrace/trace-go-fault.d`,
`trace-go-sigsegv.d`) + Go's `GOTRACEBACK=crash` full traceback:

```
FAULT  pid=… esr=0x93854005 elr=0x1c370 far=0          ← real EL0 data abort (HVF exit)
INJECT pid=… signum=11 saved_pc=0x1c370 handler=0x8dd40 ← carrick delivers SIGSEGV to Go
```

- ESR `0x93854005` decodes to **EC=0x24** (data abort from EL0), **DFSC=0x05**
  (translation fault, level 1), **WnR=0** (read), `far=0` — a genuine guest read
  of VA 0. It enters carrick at `trap.rs:2228` (`is_aarch64_el0_abort_exception`)
  and is delivered as the correct Linux signal (SIGSEGV). carrick is doing the
  right thing *with* the fault.
- **But the reported PC is bogus.** `pc=elr=0x1c370` disassembles (in the Go
  binary) to `CMN $4095, R0` — the return-value check **immediately after the
  `svc` at `0x1c36c`** in `internal/runtime/syscall.Syscall6`. A `CMN` performs
  **no memory access** and cannot raise a data abort. So the captured ELR does
  not point at the faulting instruction; the fault is bound to the **syscall
  boundary** (`svc`), and the precise faulting site is obscured.
- The Go traceback therefore *looks* like the crash is in
  `telemetry…newCounter1 → Syscall6`, but that symbolization is an artifact of
  the bad `saved_pc` carrick put in the signal frame.

It is a **Heisenbug whose victim shifts by timing**:

- Plain run → the **`go` parent** dies in its telemetry registration.
- `GODEBUG=countertrace=1` (adds debug I/O) → the parent survives and the
  **`go tool compile` child** dies instead (`go: error obtaining buildID for go
  tool compile: signal: segmentation fault (core dumped)`).

Ruled out:

- **Async preemption (SIGURG).** `GODEBUG=asyncpreemptoff=1` does **not** fix it
  (identical crash, same `pc=0x1c370`). Not a preemption-signal-during-syscall
  bug.
- **Cross-process / published signal.** The SIGSEGV has **no `signal-publish`**
  source — it originates from carrick's own `vcpu-fault` path, i.e. a real guest
  EL0 abort, not a routed/mis-delivered signal.
- **MAP_SHARED alias coherence / IPA reuse** (see Correction).

Working hypothesis: under the multithreaded toolchain's concurrent svc traffic
(fork+exec, futex, file I/O across several vCPUs), carrick's **per-vCPU syscall
trampoline mis-manages a register or the resume PC/ELR around the `svc`
boundary**, leaving the guest to resume with a corrupted pointer → it derefs
VA 0. This is adjacent to the historical SIMD/FP register-restore bug
(`project_simd_fp_abi_bug`) and the cross-process signal work, and lives in
`crates/carrick-hvf/src/trap.rs` (the `run_until_syscall` / EL1-vector
save-restore path), **not** in memory/alias code.

## The fork-shared alias-IPA allocator (landed, but a *different* fix)

While chasing the (wrong) coherence theory, a real latent bug was found and
fixed: the alias-IPA bump cursor lived in a per-process `MemState` field copied
on fork, so host-forked guests could reuse the same IPA in the one shared,
unflushable stage-2 `hv_vm`. It is now a fork-shared (`MAP_SHARED`) monotonic
counter (`crate::memory::alloc_alias_ipa`). Keep it — it is correct — but note
it does **not** fix `go build`.

## Reproduce

```sh
export CARRICK_INSECURE_REGISTRIES=localhost:5005
B='cd /tmp && printf "package main\nfunc main(){}\n">h.go && \
   GOCACHE=/tmp/gc /usr/local/go/bin/go build -o /tmp/h ./h.go && echo BUILD_OK'
./target/release/carrick run --raw --fs host localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c "$B"
# carrick: SIGSEGV addr=0x0 pc=0x1c370. docker (same image+cmd): BUILD_OK.

# Full Go traceback (all goroutines + the signal frame):
./target/release/carrick run --raw --fs host -e GOTRACEBACK=crash \
  localhost:5005/carrick-go-conformance:1.24 /bin/sh -c "$B"

# Show which process dies + that the parent's counters all succeed:
./target/release/carrick run --raw --fs host -e GODEBUG=countertrace=1 \
  localhost:5005/carrick-go-conformance:1.24 /bin/sh -c "$B"

# Post-mortem fault capture (far/esr/elr + the injected SIGSEGV):
./target/release/carrick trace -s scripts/dtrace/trace-go-sigsegv.d \
  --forward-env CARRICK_INSECURE_REGISTRIES=localhost:5005 \
  run --raw --fs host localhost:5005/carrick-go-conformance:1.24 /bin/sh -c "$B"
```

## Next steps

1. Recover the **true** faulting PC (the ELR is the post-`svc` value): on the
   EL0-abort path, read guest bytes around the real fault, or instrument the
   per-vCPU svc trampoline save/restore to dump the full GPR set at the fault
   (a register holding 0 that should be a valid pointer is the smoking gun).
2. Minimize: vary OS-thread count / `GOMAXPROCS` and fork depth to find the
   smallest multithreaded svc+fork interleaving that reproduces, then reduce to
   a deterministic probe (the discipline that nailed prior trap bugs).
3. Fix in `trap.rs` (syscall trampoline register/PC management under concurrent
   vCPUs), not in memory/alias code.

## Impact on conformance

The Go conformance suites (`scripts/conformance/suites.toml`) run under
`--fs host` and correctly **surface** this: `runtime`'s build-dependent subtests
fail (the rest pass), so the suite shows a DIFF against the all-passing docker
oracle. That is the harness doing its job — the gap is real and now precisely
characterized, not hidden behind a workaround.

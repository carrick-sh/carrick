# `go build` under carrick: fork-dropped `MAP_SHARED` alias (RESOLVED)

**Status:** **RESOLVED** 2026-06-03. `go build` now compiles AND runs a program
under carrick `--fs host` (8/8 stable; was a hard SIGSEGV on most runs). The fix
is commit `2f06c72` (fork-dropped guest_shared-alias survival), built on the
fault-reporting fix `f519cda`. History of two superseded misdiagnoses is kept
below because each was instructive.

## Symptom (historical)

`go build` of *any* program crashed under carrick `--fs host`:

```
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: ... addr=0x0 pc=0x1c370]
cmd/vendor/golang.org/x/telemetry/internal/counter.(*file).newCounter1
```

docker (`linux/arm64`) built fine, so the container was conformant — the gap was
carrick's.

## Two misdiagnoses, then the real cause

1. **"post-fork MAP_SHARED stage-2 coherence"** (first writeup) — refuted: the
   failing mapping is `forked=0`, distinct IPA, `hv_vm_map rc=0`; the `go` parent
   maps its counter and reads every counter coherently; all isolated probes pass.
2. **"trap-path syscall-boundary nil-deref"** (second writeup) — half right. The
   reported `addr=0x0 pc=0x1c370` was an artifact: on a direct EL0-abort exit the
   guest's EL1 vector never runs, so carrick read STALE `ELR_EL1`/`FAR_EL1` (the
   prior `svc`'s residue) into the SIGSEGV frame. Fixed in `f519cda` by using
   HVF's authoritative `exception.virtual_address` + `Reg::PC` (and filling
   `sigcontext.fault_address`). With correct reporting, the true fault appeared:
   `addr=0x100000001a4 pc=<LDAR>` — a **stage-2 translation fault on the telemetry
   counter's MAP_SHARED alias**, hit by an atomic `LDAR`, NOT a nil deref.

## Real root cause (trace-confirmed, fixed)

Guest threads share ONE `hv_vm`; per-thread `mappings` are just local metadata
("stage-2 entries live on the shared HVF VM", `trap.rs`). But `HvfInner::fork`
tears the shared VM down (`hv_vm_destroy`) and rebuilds it (`hv_vm_create`)
replaying **only the forking thread's `self.mappings`**. A `guest_shared`
(MAP_SHARED-file) alias mapped by a **sibling thread** is therefore **dropped**
from the rebuilt shared VM. arm64 HVF has no stage-2 TLB shootdown, so it never
self-heals.

The go toolchain's telemetry counter is `mmap(MAP_SHARED)`'d on one thread and
read via an atomic `LDAR` on another. When `go` forks `go tool compile`, the VM
rebuild drops the counter alias; the next `LDAR` stage-2-faults. The decisive
diagnostic (`CARRICK_TRACE_FAULT`): `exit_va=0x100000001a4 exit_pa=0x18000001a4`
(the alias IPA), `forked_child=false`, `mapped_here=false` (this process's VM
lost it). A plain retry never resolves it (the mapping is genuinely absent), and
only **1** lazy re-map fires per dropped alias — it is not a fault storm.

## The fix (`2f06c72`)

A process-global registry records `guest_shared` aliases. On a direct EL0 abort
against a high-VA alias the current VM is missing, carrick lazily re-`hv_vm_map`s
the SAME (still-live MAP_SHARED) host backing into this shared VM and re-runs the
instruction — restoring the stage-2 entry for every thread. Only registered
aliases are touched (a genuine bad access still faults); bounded as a backstop.
The host backing is a MAP_SHARED mmap valid across threads + fork, so the re-map
is coherent.

## Verification

- `go build` of a `package main` that prints: compiles + runs + `BUILD_OK`, 8/8.
- go-runtime pass count 835 → 837, **no new crashes**.
- conformance smoke: cpython/node/ltp unaffected.
- `faultaddr` probe (new): `si_addr` + `fault_address` match the faulting VA,
  line-exact vs docker.
- New smoke suites: `go-build` (shell verdict, exit-code regression guard) and a
  curated pure-runtime `go-runtime` subset.

## Newly-exposed gap (separate): cgo + nested toolchain

Because `go build` now WORKS, runtime subtests that build+run helper programs
proceed past their previously-crashing telemetry access and then **hang on
unsupported cgo nested builds** (`TestCgo*`, `TestSegv/*InCgo`,
`TestCoroCgoCallback`, …). That is why the full `runtime.test -test.run Test`
set is no longer a viable fast gate; the smoke `go-runtime` suite was reduced to
a curated pure-runtime subset. cgo bring-up + nested-toolchain robustness under
heavy concurrency is a separate tracked gap.

## Reproduce

```sh
export CARRICK_INSECURE_REGISTRIES=localhost:5005
B='cd /tmp && printf "package main\nfunc main(){println(\"ok\")}\n">h.go && \
   GOCACHE=/tmp/gc /usr/local/go/bin/go build -o /tmp/h ./h.go && /tmp/h && echo BUILD_OK'
./target/release/carrick run --raw --fs host localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c "$B"   # => ok / BUILD_OK

# Inspect the (now-fixed) fault path: CARRICK_TRACE_FAULT=1 dumps exit_va/pc/GPRs
# + forked/mapped_here; CARRICK_REMAP_STATS=1 logs lazy re-maps.
```

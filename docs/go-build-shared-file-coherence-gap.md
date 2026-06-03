# `go build` under carrick: the post-fork `MAP_SHARED`-file coherence gap

**Status:** tracked carrick runtime gap (not yet fixed). Surfaced by the unified
conformance harness (the Go suites) running under `--fs host`. Diagnosed
2026-06-03; this is a specific manifestation of the known **SHARED_FILE stage-2
coherence wall** (`golang-bringup-handoff.md`, the `project_shared_file_coherence`
memory).

## Symptom

`go build` of *any* program (even a trivial `package main`) crashes inside the
`go` command under carrick `--fs host`:

```
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x...]
...
cmd/vendor/golang.org/x/telemetry/internal/counter.(*file).newCounter1
```

The same build succeeds under **docker** (`linux/arm64`), so the container is
conformant — the gap is carrick's. The Go *runtime* is fine; only the parts of
the Go **toolchain** that run `go build` (and the `runtime` package's own
build-dependent tests, e.g. `TestCoroLockOSThread`, `TestAtomicAlignment`) hit
it.

## Root cause (trace-confirmed)

Go's toolchain telemetry counter `mmap`s a counter file `MAP_SHARED` and reads
it back:

```
mmap(addr=0, len=16384, prot=PROT_READ|PROT_WRITE, flags=MAP_SHARED, fd=<counter file>, off=0)
```

carrick backs a `MAP_SHARED`-file mmap with a high-VA `hv_vm_map` **alias**
(`dispatch/mem.rs` → `DispatchOutcome::MapHostAlias` → `trap.rs::map_host_alias`,
VA `0x10000000000`). `carrick trace` on the `hv-vm-map-alias` / `pt-alias-walk`
USDT probes during the failing build shows the mapping **succeeds**:

```
HVMAP va=0x10000000000 ipa=0x1800000000 size=0x4000 rc=0 forked=1   ← hv_vm_map OK
PTWALK rc=0                                                         ← stage-1 page tables OK
→ guest still: SIGSEGV addr=0x0
```

The load-bearing flag is **`forked=1`**: the mapping is established in a
**forked-child** guest. On arm64 HVF there is **no stage-2 TLB flush** (it is an
EL2-only operation), so a *post-fork* `hv_vm_map` of a brand-new `MAP_SHARED`
window reports `rc=0` but the forked child's vCPU never sees a coherent mapping.
Go reads a null/garbage pointer out of the "mapped" counter file and `nil`-derefs
at `addr=0x0`.

This is why nearly everything else works: apt, language servers, http servers,
etc. use **anonymous / arena** mappings, which come from the boot-mapped shared
aperture (no post-fork `hv_vm_map`). Only a program that maps a **shared file
after fork** and then reads it trips the wall. Go's toolchain telemetry is the
first real workload that does.

## Ruled out (each isolated and verified to PASS under carrick `--fs host`)

The constituent operations all work in isolation — the gap is specifically the
forked-child post-`hv_vm_map` coherence, not any of these:

- plain `MAP_SHARED` file mmap + store + read-back (`conformance-probes/mmapfile.rs`);
- atomic `fetch_add` / `compare_exchange` (LDADD / LDXR-STXR) on a file-backed mapping;
- multi-page mappings (1–16 pages);
- grow-then-remap (the counter-extend pattern);
- sparse extend via `pwrite`-at-offset + fd-write→mmap-read coherence (the exact
  `openMapped` sequence: header `pwrite`, sparse extend to 16 KiB, `mmap`,
  `bytes.HasPrefix`);
- `GOMAXPROCS=1` (single vCPU — still crashes, so it is **not** multi-vCPU contention).

Telemetry is definitively the trigger: setting the telemetry mode to `off`
(`$HOME/.config/go/telemetry/mode`) lets `go build` complete under `--fs host`
(`BUILD_OK`). That is a *diagnostic*, not the fix — the goal is conformance, so
carrick must run the `MAP_SHARED`-file mmap correctly, not disable the workload.

## Reproduce

```sh
export CARRICK_INSECURE_REGISTRIES=localhost:5005
./target/release/carrick run --raw --fs host localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c 'cd /tmp && printf "package main\nfunc main(){}\n">h.go && \
    GOCACHE=/tmp/gc /usr/local/go/bin/go build -o /tmp/h ./h.go && echo BUILD_OK'
# carrick: SIGSEGV in x/telemetry counter.  docker (same image+cmd): BUILD_OK.

# Trace the alias mapping (auto-sudos via the NOPASSWD carrick binary):
./target/release/carrick trace -s scripts/dtrace/trace-alias-rc.d \
  --forward-env CARRICK_INSECURE_REGISTRIES=localhost:5005 \
  run --raw --fs host localhost:5005/carrick-go-conformance:1.24 /bin/sh -c '<build>'
```

## The fix (not yet done — known hard)

The recommended fix in the handoff is to **recreate the faulting vCPU to get a
fresh stage-2 TLB**, applied at the right point. Five other approaches were ruled
out historically (TLBI broadcast, pre-establishing the tables, retry, MAP_FIXED
overlay, status-quo).

A sharper sub-question to investigate first: the `go` process is a fork+**exec**
(`sh -c "go build"`), yet the alias mapping is flagged `forked=1`. If `execve`
*should* recreate the vCPU (an exec'd process has a fresh address space → it
deserves a fresh stage-2 TLB) and currently does not, then **"recreate the vCPU
on exec"** may be both the correct semantics and the most tractable fix — more
contained than a general post-fork-fault vCPU recreation. Verify whether carrick
recreates the vCPU on `execve` before committing to the broader machinery.

## Impact on conformance

The Go conformance suites (`scripts/conformance/suites.toml`) run under
`--fs host` and correctly **surface** this: `runtime`'s build-dependent subtests
fail (the rest pass), so the suite shows a DIFF against the all-passing docker
oracle. That is the harness doing its job — the gap is real and now precisely
characterized, not hidden behind a workaround.

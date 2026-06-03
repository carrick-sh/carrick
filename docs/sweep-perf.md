# Per-run overhead & sweep cycle time (banked 2026-05-29)

Investigation into carrick's per-`run` overhead (it should be ~a few ms over a
native fork in a Linux VM; it was not) and how to speed up the LTP sweep.

## Measured per-run lifecycle (`carrick run … --fs host /bin/sh -c /bin/true`)

Instrumented with the new `carrick:::lifecycle(phase)` USDT probe (commit
2b695b3) + the existing `fork-pre`/`fork-post`/`guest-exit` probes, traced via
`scripts/dtrace/trace-bootfork.d`. Anchor = first host syscall:

| phase | cost | what |
|---|---|---|
| **first-boot** (→ FIRST_VCPU_RUN) | **~90 ms** | OCI image load + `hv_vm_create` + 32 GiB `hv_vm_map` + guest mem/page-tables + ELF load |
| **fork** (fork-pre → fork-post) | **~5.7 ms** | HVF context rebuild + snapshot restore in the child; **no image reload** |
| forked-child teardown | **~7 µs** | child process exit is ~free |
| **initial-process teardown** | **~175 ms** | the process holding the original 32 GiB VM + async runtime + image/scratch handles; on a clean exit the VM is `ManuallyDrop`'d so this is the kernel reclaiming the VM at process exit (no explicit `hv_vm_destroy`, no big `munmap` fires) |

So today **each `carrick run` ≈ 90 ms boot + 175 ms teardown ≈ 265 ms**, with
the guest itself running in ~2 ms. Fork is ~16× cheaper than boot, and the
175 ms teardown is **initial-process-only** — forked children don't pay it.

`--fs memory` is 15× SLOWER (~3.5 s) for this image because it materializes the
whole 1.9 GB rootfs into guest RAM each run — the sweep correctly uses
`--fs host` (cap-std over the host layers, no full-image load).

## Speedups

1. **Docker-oracle cache — DONE (commit 1cfc76b).** Docker's verdict is stable
   per image; the harness now caches it (`docs/ltp-baseline/docker-oracle.jsonl`,
   seeded from prior results) and re-runs only carrick. `--refresh-oracle` for an
   image change. ~halves re-sweep cycle time.

2. **Zygote / `docker run -d` + `docker exec` — DESIGNED, not built.** Keep ONE
   detached carrick guest alive (boot once; an init/pid1 keeps the VM up), and
   run each test as a `carrick exec` that injects a process INTO that guest
   instead of a fresh `carrick run`. Boot (90 ms) and teardown (175 ms) collapse
   to one-time costs; each test is a guest `fork` (~5.7 ms) whose child tears
   down in ~7 µs. ~470 tests → **~125 s of boot+teardown erased per sweep**, on
   top of the cache.
   - **Primitives already exist**: a guest `fork`/`clone` becomes a carrick
     child (fork-pre/post), and `execve_into` (trap.rs ~2865) re-execs the guest
     into a fresh AddressSpace WITHOUT a new process/boot. There is already a
     docker-compatible `run` frontend (spec/image/runtime/engine/cli; `-e/-w/-v/
     --entrypoint`) — `exec` extends it.
   - **New work (daemon shape, like dockerd)**: `carrick run -d <image> <init>`
     (boot once, run a waiting init, print a guest id, stay resident) +
     `carrick exec <id> <cmd>` (thin client → unix-socket IPC to the resident
     carrick → guest init `fork`+`execve_into`s `<cmd>`, relays stdio/exit). The
     kill/timeout model moves from global `pkill carrick` to per-exec child kill.
   - **Caveat — isolation**: tests share one guest's kernel state (pids, /tmp,
     mounts); the harness needs per-exec cwd/tmpdir hygiene (LTP mostly uses
     `tst_tmpdir`, which helps).
   - **Lighter interim (`run --batch`)**: feed one resident guest a list of test
     commands, fork+exec each sequentially — one boot+teardown, N forks; smaller
     change, sweep-specific, less general than `exec`.

3. Other levers (smaller): tier the carrick timeout (short first, re-run hangs at
   45 s); parallelize carrick runs (replace global `pkill` with per-guest pid
   kill — each `carrick run` is its own HVF VM, so concurrent VMs are feasible,
   watch HV_BUSY); cut the 32 GiB arena to a smaller/lazy mapping (cuts both the
   boot-side stage-2 map and the teardown).

## Instruments (durable)
- `carrick:::lifecycle(phase)` USDT — phase 4 = FIRST_VCPU_RUN (initial boot
  done; once-per-process, NOT re-fired across no-exec fork → cleanly "first
  boot"). Constants in `carrick_hvf::probes::phase`.
- `scripts/dtrace/trace-bootfork.d` — first-boot vs fork vs teardown.
- `scripts/dtrace/trace-lifecycle.d` — boot/guest/teardown + mmap accounting.
- Note: `carrick trace --trace-out <file>` is broken (writes nothing) — use
  stdout + grep for non-interactive traces. See project_carrick_trace_traceout_bug.

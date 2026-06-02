# Session handoff — 2026-06-02 (pre-Rosetta-memory-merge)

State checkpoint before merging the Rosetta memory fixes. Branch:
`fix/apt-forkstorm-and-integration-green` (NOT merged to `main`).

## Committed this session (on the branch)

| Commit | What |
|---|---|
| `6254c0d` | io_wait: poll-fallback a dead per-thread kqueue — **fixes the apt-get-install fork-storm hang** (EBADF busy-spin → bounded `waitid` poll). apt install 6/6 (was ~1/6). |
| `ef95e6a` | Restore the integration suite to green (5 drifted failures): capset structural validation, `unshare`(97) classifier, `io_blocking_guard` token markers, capget docker-default expectation, `/proc/sys/kernel/hostname` `guest_hostname()`. Serialized the caps tests (process-global state). |
| `8b7b5c4` | fs: map `/dev/fd/N` + `/dev/std{in,out,err}` → `/proc/self/fd` — **fixes bash process substitution** (`cat <(...)`, `tee >(...)`) + the libuv harness's carrick runner. |
| `357dbdf` | docs: the 2026-06-02 language-runtime conformance snapshot (in `docs/conformance-coverage.md`). |

All gate-verified at commit time: integration 244/244, conformance gate 4/4, apt 6/6,
carrick-runtime lib 286, carrick-hvf lib 56.

## Uncommitted at checkpoint — the multiprocessing SIGSEGV fix (about to be committed)

**Root cause (definitively proven).** CPython `test_multiprocessing_*.test_processes`
died deterministically with a guest SIGSEGV at test 54 `test_async_timeout` (`p =
self.Pool(3)`). Fault: `far=0x5858585858585850`, `x19=0x5858...5848` (`0x58 = 'X'`),
`LDR x1,[x19,#8]` — a guest pointer overwritten with `'X'` bytes from a freed 16 MiB
`latin('X')*` Connection message. Same CLASS as the prior mmap-zerofill SEGV.

The reused-region zero-fill in `dispatch/mem.rs` (`if reused && !is_high_va`) used
`memory.write_bytes()` — the **permission-checked** path (`write_guest_bytes_checked`).
A region just reclaimed from `munmap` is stage-1-invalidated (no-access), and a
`PROT_NONE` mmap is not writable, so the checked write **silently faults** (the result
was `let _ =`-ignored) and the stale `'X'` survived. The guest then `mprotect`'d the
region to RW and read `'X'` as a pointer → SIGSEGV. Proven with a gated probe:
`[ZFILL] addr=0x6010810000 len=134217728 prot=0x0 write_err=true Xafter/4k=4096`.

**Fix.** New `GuestMemory::zero_backing(addr, len)` that scrubs the PHYSICAL backing
raw, bypassing `range_no_access` + writability (the arena backing is always mapped —
munmap only stage-1-invalidates). Files:
- `crates/carrick-guest-mem/src/lib.rs` — trait method (default = checked `write_bytes`, for the in-memory backend).
- `crates/carrick-hvf/src/trap.rs` — inner `zero_guest_backing` (raw `ptr::write_bytes(0)` via `mapping_for_range_mut`) + `HvfTrapEngine::zero_backing` override.
- `crates/carrick-runtime/src/runtime.rs` — `SplitView::zero_backing` delegate.
- `crates/carrick-runtime/src/dispatch/mem.rs` — call site (483) now uses `zero_backing`.

**Verified:** `test_async_timeout ... ok` (was SIGSEGV). This is a broad memory-safety
fix — ANY guest mmap'ing over a freed/dirtied no-access region was at risk.

## OPEN — the next multiprocessing blocker (after the SIGSEGV fix)

`test_processes` now progresses past the SIGSEGV but hits:
`carrick: trap engine failed: ... alias page-table build failed: stage-1 page-table
pool exhausted`. The 128 MiB+ anon arena reservations exhaust the stage-1 PT pool —
sibling of the test_mmap fix `82911cb` (map large aliases as L2 BLOCKs, not per-2 MiB
page tables), but for the ANON large-mmap path. This is the next thing to chase for the
multiprocessing cluster (8 of the 18 CPython DIFFs).

## WIP — regression probe (untracked, NOT committed)

`conformance-probes/src/bin/mmapprotnonereuse.rs` exists but **does not yet reproduce**
the bug: a simple `mmap(RW,'X')→munmap→mmap(PROT_NONE)→mprotect→read` MATCHes because
freeing the TOP region leaves it writable (no `range_no_access`). To make it a real RED
guard it needs the **A/B/C pattern**: map A, then a small guard B *after* A (so A is not
the top), fill A with `'X'`, `munmap(A)` (→ free list + no-access), then `mmap(PROT_NONE)`
the same size as A (reuses A's no-access region), `mprotect(RW)`, assert all-zero.
Finish + verify RED (revert `zero_backing`→`write_bytes`) → GREEN post-merge.

## Conformance snapshot (2026-06-02, carrick vs Docker linux/arm64 oracle)

- **Go**: ~876/880, 4 known/env-gated (TestExplicitPWD; net raw-IP ×3).
- **Node node-core**: 5301/5304 (3 cosmetic stderr-snapshot).
- **libuv**: 498/507 solo; 9 carrick-only gaps (`kill`, `spawn_exercise_sigchld_issue`, `tcp_reuseport`/`udp_reuseport`, `udp_multicast_interface6`, `udp_recvmsg_unreachable_error`(+6), `tty_pty_partial`, `platform_output`).
- **CPython 3.12.13**: 425/492 MATCH (86.4%). DIFFs: multiprocessing (SIGSEGV fixed → now PT-pool blocker), asyncio, test_socket (40 SCTP skips, out of scope), small punch-list gaps (posix/shutil/zipfile/subprocess/cmd_line/ssl).

## Other carrick gaps found (not yet fixed)

- `diff <(...)` aborts inside GNU diff: carrick reports `st_size=0` for the `/proc/self/fd/N` magic symlink vs Linux's readlink-target length.
- `--user <name>` resolution unsupported (numeric uid only); `setpriv` capability-prctl EINVAL.

## RUN-OPS gotchas (proven this session)

- Run heavy suites **SOLO** — concurrent node-core/libuv/python starve each other (false TIMEOUT/n=0; libuv 220/507 contended vs 498/507 solo).
- `cpython-parity.py --jsonl` **appends** → dedupe last-wins per module.
- carrick needs the **registry** ref `localhost:5050/cpython-test:3.12.13`; a bare `cpython-test:3.12.13` (docker-daemon) ref → carrick can't pull → every module `n=0` (looks like a mass regression, isn't).
- Fault diagnostics: gated `eprintln` at the `vcpu_fault` site in `trap.rs` (`far`/`elr`/`insn`/`x19`) beats `carrick trace` here (auto-sudo can mask load-sensitive crashes). `CARRICK_XMMAP` mmap-return scan localizes stale-page reuse.

## Post-Rosetta-merge retest checklist

1. Rebuild signed (`./scripts/build-signed.sh`).
2. Re-verify the SIGSEGV fix survived the merge: `test_async_timeout ... ok` under `carrick run localhost:5050/cpython-test:3.12.13 ... python3 -m test -v test.test_multiprocessing_fork.test_processes`.
3. Conformance gate (`cargo test -p carrick-cli --test conformance`) + integration 244/244 + lib tests.
4. apt-get install ×N still 6/6.
5. Finish + verify the `mmapprotnonereuse` probe (RED→GREEN).
6. Then chase the stage-1 page-table-pool exhaustion (large anon mmap → BLOCK mapping).

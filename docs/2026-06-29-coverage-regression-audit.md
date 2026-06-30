# Carrick Portability-Lane Regression-Guard Audit — Synthesis Report

## 1. Bottom line

The portability work is, structurally, in better shape than the guard coverage suggests: the neutral seams (`carrick-hal` futex/fork/signal traits, `carrick-x86`/`carrick-aarch64` engine cores, `carrick-runtime/dispatch`) are mostly the right shape, and the macOS/HVF reference lane is genuinely well-gated. The exposure is almost entirely **cross-lane and CI-shaped**, and it stacks from one root fact: **no lane runs a guest vCPU in CI** (the `hvf-conformance` job is dormant behind an unset repo var; all cross-checks are `cargo check`). On top of that root multiplier sit three recurring failure modes: (a) **the entire x86 probe lane is `gating:false`** (`conformance.rs:194/199`), so every KVM/bhyve/NVMM runtime fix is report-only — a DIFF prints but nothing fails; (b) **host-neutral logic is needlessly trapped behind platform `cfg`s** (bhyve `RamInner`, `bsd_extattr_ns` tag mapping, FreeBSD `sendfile` partial-count, x86 reclaim XSAVE serialization, the clone3 init blob), so its ready-to-run unit tests execute on zero CI lanes while a macOS-runnable copy would guard every lane; and (c) **fixes landed on HVF but never reached the BSD/x86 twins** (the FUTEX_WAIT errno clamp, the vDSO/syscall realtime-coherence seam, the aarch64 sigframe restore-fault test).

The audit also surfaced **one live correctness bug, not just a coverage hole**: `seccomp_precheck` hardcodes `seccomp_data.arch = AUDIT_ARCH_AARCH64` and feeds the already-normalized canonical syscall number, so on every x86 lane (KVM/bhyve/NVMM + Rosetta) a guest installing the standard Docker/libseccomp profile is killed on its first post-install syscall. After the verdict pass corrected severities, only two findings are truly **high** (no-guest-in-CI, seccomp); the bulk are **medium/low** and most are closable with cheap, host-runnable unit tests that already have a fixture one block away.

## 2. Top recommendations, ranked by leverage

Ranked by durability × silent-regression-likelihood × blast-radius. The first four are structural and each collapses several individual findings.

### R1 — Stand up one CI lane that actually runs a guest *(fixes #no-guest-runs-in-ci; unblocks ~all runtime findings)*
Add a scheduled (nightly) job on a **self-hosted Linux runner with `/dev/kvm`** (the willow/Proxmox nested-virt fleet already exists) running `just kvm-smoke` — it does `run-elf` of a freestanding aarch64 ELF on real KVM with **zero Docker dependency**, so it gates the shared `carrick-x86` + `carrick-aarch64` engine bring-up. Separately, register the Apple-Silicon runner and set `CARRICK_SELF_HOSTED=true` to un-dorm the existing `hvf-conformance` job (`ci.yml:198`), which self-skips safely if Docker is absent. Do **not** assume GitHub-hosted Ubuntu provides `/dev/kvm` — nested virt is not guaranteed. **Protects:** every lane gains its first automated guest-execution smoke; today a broken syscall translation, a reclaim deadlock, or an x86 engine fault is invisible until a human runs a manual gate.

### R2 — Fix the seccomp ISA hardcode (live guest-fatal bug) *(fixes #seccomp-arch-hardcoded)*
`dispatch/mod.rs:2170-2174` builds `seccomp_data` with `arch = AUDIT_ARCH_AARCH64` and `nr = request.number` (the *canonical* number). Source `arch` from `GuestReportedArch` (add `AUDIT_ARCH_X86_64 = 0xC000003E` to `seccomp.rs`) and feed the **raw pre-normalization** guest syscall number (carry it on `SyscallRequest`). Add a `seccompdefaultprofile.rs` probe (install an arch-gated filter; assert allow succeeds and deny returns the filter errno) gated on hvf **and** the x86 lanes, plus a `seccomp.rs` unit test asserting an x86_64-arch filter KILLs against an aarch64 `SeccompData` and allows against an x86 one. **Protects:** kvm/bhyve/nvmm + Rosetta. **Prevents:** the standard Docker/systemd/browser-sandbox seccomp profile silently killing the guest on its first syscall — currently undetected because the x86 lane is report-only and CI runs no guest.

### R3 — Make the BSD/Linux backend crates and host-neutral logic CI-visible *(fixes #amd64-probe-lane-report-only-no-native-epoll-guard, #bhyve-nvmm-backends-untested-in-ci, #bhyve-demand-paging-guards-never-run-in-ci)*
Three near-zero-effort moves on existing runners:
- Add `cargo test -p carrick-host-linux` to the existing `cross-check-linux` ubuntu job (and add the crate to `just check-linux`'s compile closure — today it is not even compile-checked, `justfile:226`). The `epoll_mux.rs` EV_EOF→EPOLLHUP / IN_IGNORED edge tests need only host pipe/eventfd/timerfd/inotify primitives — no `/dev/kvm`, no guest.
- Add a **NetBSD cross-check** mirroring `check-freebsd` so `carrick-vmm-nvmm` is at least type-checked (today an nvmm trait-signature break is invisible to CI).
- Upgrade both BSD cross-checks from `cargo check` to `cargo check --all-targets` so the `#[test]` modules compile.

**Protects:** the native-epoll backend (kvm-local host layer, currently zero compile-or-test coverage) and bhyve/nvmm compile health.

### R4 — Hoist diverged host-neutral logic into shared crates and move its tests there *(structurally fixes #bhyve-demand-paging, #bsd-xattr-namespace, #freebsd-sendfile-partial-eagain, #reclaim-fp-avx + #bhyve-xsave-error-swallowed, #clone3-child-register-inheritance, #ipcset-no-shared-seam/#sysv-ipc-ctl-macos-only-fill)*
This single pattern closes the largest cluster. `carrick-x86` and `carrick-portable` are **not** crate-`cfg`-gated and DO compile+test on the macOS CI host. Move the host-neutral cores out of the per-backend crates and run their tests in `cargo test --workspace`:
- **Demand-paging:** unify bhyve `RamInner` (reservation/writability/window-prune) and nvmm `WindowRegion` into one `carrick-x86` module; move `reservation_writability_is_preserved_through_commit` / `remove_windows_lets_reused_va_recommit_fresh` there. Kills the bhyve-vs-nvmm divergence *and* the SEGV_ACCERR/heap-corruption guard's CI invisibility at once.
- **x86 reclaim XSAVE:** one `carrick-x86` serializer over `X86VcpuSnapshot` consumed by both KVM and bhyve (today KVM hand-rolls `serialize_x86_snapshot`, bhyve hand-rolls a different byte layout at `bhyve_x86_engine.rs:1773`). Add a round-trip unit test with a non-zero YMM region. Make bhyve fail **loud** (`bhyve_x86_engine.rs:1784` `get_xsave().ok().flatten()` and the `let _ = set_xsave`) to match KVM's documented "reclaim failure is fatal, never silent corruption" contract.
- **clone3 init blob:** complete the documented Stage-4 — give `carrick-x86/src/bringup.rs::msr_init_blob` the `entry_rdx/entry_rcx` params and re-point bhyve at it, deleting the duplicate in `guest_setup_x86.rs`. The shared copy is **currently missing the 6837b3bd RDX/RCX restore fix** — re-pointing bhyve at it today would re-introduce the RIP=0 SIGSEGV. Move the `msr_init_blob_restores_entry_rdx_rcx_before_iretq` assertion into `carrick-x86` so it runs in macOS CI.
- **BSD xattr tags:** extract `linux_name_to_bsd_tag`/`bsd_tag_to_linux_name` as pure enum-returning helpers (no `libc::EXTATTR_NAMESPACE_*` dep) so a non-`cfg`-gated unit test covers the `system.`/`trusted.`/`security.` round-trip (the exact 0660b721 regression) on macOS/Linux CI.
- **`sendfile` partial-count:** extract `resolve_sendfile_result(rc, bytes_sent, errno) -> isize` and call it from both the macOS and FreeBSD arms; table-drive a host-agnostic unit test. Kills the duplicated decision logic and covers the untested FreeBSD `*sbytes` branch.
- **SysV `ipc_perm` fill:** add `carrick-portable` `read_sem_perm`/`apply_ipc_set_mode` so the `cfg(not(macos))` zeroed stub is replaced by a real host-truth fill across all four lanes.

### R5 — Enforced forward "every assigned x86_64 syscall number is declared" guard *(fixes #x86-no-reverse-shim-coverage-guard)*
Add a `carrick-abi` `#[test]` that, for every assigned x86_64 number in `0..=max(X86_64_SYSCALLS)`, asserts it is present in the table (`Direct`/`Native`) **or** matched by an explicit `normalize_syscall` shim arm **or** in a single commented `const DEFERRED_X86_SHIMS` allowlist (`utime=132`, `utimes=235`, `futimesat=261`, …). This converts the recurring manual "gnu-only probe gap" archaeology (318c5688/ef831d2c/e675974f/f80cab5f) into a CI gate. **Note:** frame it as *forward* completeness — the originally-proposed reverse-over-canonicals form false-positives on every aarch64-only canonical and would not even catch its own motivating example (`utimensat` is reachable on x86 via `280 → Direct(88)`).

### R6 — Per-lane baseline overlays + a gating x86 probe subset *(fixes #no-bhyve-nvmm-baseline, #x86-fork-coherence-probes-report-only, #x86-probe-gate-report-only-for-nspid-dac, #ofd-bsd-downgrade, #semctl-* , #afunix-backpressure)*
Make `--baseline-overlay` lane-derived (`baseline.{kvm,bhyve,nvmm}.jsonl` chosen by `--lane`), commit empty seeds, and extend the `--bless` guard (`main.rs:603-608`) to permit `--bless --lane bhyve|nvmm` writing **only** that lane's overlay. Then carve a **per-probe gating allowlist** so a curated subset (`forkcow/forkshared/mapfixed`, `setpgidparentgroup/fcntlgetlk/dirdac/mkdirsetgid`, `sysvsemstat/semctlsetmode`, `afunixbackpressure`, `fcntlofdlock` with a documented BSD excuse) fails red on the x86 fleet while the remaining ~34 bring-up gaps stay report-only. This gives the bring-up lanes a real gate and a sanctioned excuse home, and lets deliberate BSD divergences (OFD→process-lock downgrade) be *tracked* rather than buried in report-only noise. **Correction to fold in:** the empty `baseline.kvm.jsonl` already fails-closed for suite verdicts, so this is excuse-granularity + probe-gating, not "regressions are currently silent" for the suite layer.

### R7 — Restore real futex coverage on x86 and propagate the FUTEX_WAIT errno clamp *(fixes #futex-probes-aarch64-syscall-on-x86, #futex-wait-errno-clamp-hvf-only)*
Replace `const SYS_FUTEX = 98 // aarch64` with `libc::SYS_futex` in `futexshare/futexwakecount/futexsharedalias/futexrequeue` (today they silently run **getrusage** on x86_64 and false-MATCH); add a lint grep over `conformance-probes/src/bin` rejecting raw aarch64 syscall constants. Separately, hoist the FUTEX_WAIT errno-ABI clamp (HVF's `wait_one_slice` folds unexpected errno → `Woken`, e16cd752) into the shared `carrick-hal/src/futex.rs` `shared_wait_sliced` seam so bhyve/nvmm stop returning a **raw FreeBSD/NetBSD errno** that can fatally abort glibc nptl. Add a host-runnable unit test driving a fabricated non-`{EAGAIN,EINTR,ETIMEDOUT}` errno. (KVM already returns Linux-native errnos — leave its passthrough.)

## 3. Findings by category

Severities are the verdict-corrected values. Duplicates across themes are merged.

### cross_lane_coverage

| Gap | Sev | Lanes | Evidence | Fix |
|---|---|---|---|---|
| Reclaim path never exceeds HVF(~60)/KVM(~512) budget at probe N=14 → reclaim save/restore unexercised on 2 of 3 reclaiming lanes | med | hvf, kvm | `threadbarrier.rs` N=14; `kvm_x86_engine.rs:206`; `hvf_*:306`; `CARRICK_KVM_BUDGET` set by no script | `CARRICK_KVM_BUDGET=4` in kvm lane env; add `CARRICK_HVF_BUDGET` override; `reclaimfpregs` probe; KVM unit tests for the a340ce58 sync-regs/PIO resume bugs |
| bhyve/nvmm/kvm-aarch64 backends compile-only (nvmm not even compiled) → 27 bhyve + 6 nvmm unit tests run on zero CI lanes | med | bhyve, nvmm | `lib.rs:19` cfg-freebsd; `justfile:237/225` cargo check; no NetBSD job | R3 + hoist `guest_setup_x86` to `carrick-x86` |
| KvmAarch64Vmm (2nd consumer of `Aarch64EngineCore`) is compile-only in CI, manual-only in conformance; all aarch64 regression evidence is HVF-derived | med | kvm, hvf | `carrick-vmm-kvm/Cargo.toml:29-32`; `lane.rs:69-75`; `ci.yml:85-112` | Shared `Aarch64EngineCore`-level reg/FP/sigframe round-trip unit tests; aarch64 conformance lane on nested-KVM box |
| inotify dispatch synthesis not authoritative on Linux → double-emit alongside native kernel inotify fd for host-backed fds | med | kvm | `inotify.rs:804-813` (no-op on linux), `:403-456`, `fd_helpers.rs:255-379` | Per-watch capability-driven source ownership (native owns → suppress dispatch synthesis); deterministic inotify probe on hvf + kvm overlay |
| WIFSIGNALED reconstruction for BSD-default-ignore signals (SIGPOLL/SIGSTKFLT) unguarded; `signalexit` only tests SIGTERM/SIGKILL (never hit marker path) | med | hvf, bhyve, nvmm | `proc.rs:2491`, `exec_helpers.rs:256-275`, ddd3040c | `sigexitignmap.rs` probe (signal 29/16 → WIFSIGNALED); unit tests for `translate_child_wait_status`/`consume_sigdeath_marker` |
| AF_UNIX write+sendfile ENOBUFS→EAGAIN backpressure (BSD-only) unguarded on bhyve/nvmm | med | hvf, bhyve, nvmm | `mod.rs:4944`, `fs.rs:6680`, 6c8e8c88 | `afunixbackpressure.rs` (DGRAM ENOBUFS + sendfile-to-AF_UNIX EINVAL) seeded on bhyve+nvmm |
| semctl IPC_STAT host-truth fill macOS-only; x86 lanes return zeroed `semid_ds`; `sysvsemstat` absent from amd64 probe-oracle (skipped on Docker-less boxes) | med | kvm, bhyve, nvmm | `sysv.rs:1321-1342`, `sysvsemstat.rs` | `carrick-portable` `read_sem_perm`; bless `sysvsemstat` into `amd64-{gnu,musl}` probe-oracle |
| vDSO-vs-syscall realtime/boottime coherence seam published only by HVF; bhyve/nvmm fall back to live `SystemTime::now()` | low | bhyve, nvmm | `dispatch/mod.rs:3470`, `trap.rs:2384` (only caller), `carrick-x86/src/vdso.rs:143` | Publish `set_realtime_off_ns` from `carrick-x86::populate_vdso_vvar`, computed vs `CLOCK_UPTIME_RAW`; `clockcoherence.rs` probe. Drop kvm (target_os=linux short-circuits) and hvf (already wired) |
| F_GETLK l_pid / DAC search-deny / setgid-dir inheritance: neutral fixes guarded only by report-only x86 probes + non-CI LTP | med | kvm, bhyve, nvmm | `conformance.rs:194/199`; 03d0813f, 19bcf4b4, 1e7d0f6f | Host-native unit tests (extract pure fns for record-lock holder-pid xlate, `check_search_access`, `create_uid/gid`) — run in `cargo test` on all lanes |
| FreeBSD `sendfile` partial-EAGAIN `*sbytes` branch untested (macOS twin is tested) + duplicated decision logic | low | bhyve | `lib.rs:1129` (happy-path only), f52046d5 | Extract `resolve_sendfile_result` + host-agnostic table test (R4) |
| Four arch-pinned futex probes run getrusage on x86 (false MATCH); requeue + cross-VA alias variants untested on x86 | med | kvm, bhyve, nvmm | `futexshare.rs:14` etc. (`=98`) | R7 |
| BSD-poll one-way-pipe POLLOUT suppression (4a4389a3) gated only by macOS probes where it's a no-op | low | bhyve, nvmm | `net.rs:644-656`, `host_fd_is_oneway_pipe_read_end` | Host-poll-independent unit test in `net.rs` asserting EPOLLOUT dropped for one-way read-end. (dfaf5716/EPOLLPRI half **refuted** — Darwin-specific, already gated) |
| No deterministic child→parent MAP_SHARED\|MAP_ANON cross-fork probe | low | all | `forkshared.rs` (file-backed); `futexwakeexact.rs` already covers parent→child | Optional: add anon mapping + boolean assert to `forkshared.rs`. Low value (anon aliasing is symmetric) |
| NVMM has no M:N admission/reclaim → `NoopScheduler`; >max_vcpus (~256) lifetime threads will fail vCPU create | low | nvmm | no `vcpu_budget`/`reclaims` override; `vmm.rs:513-516`; 1f6524c2 | Override `vcpu_budget()` to queried `max_vcpus`; recycle cpuid slot; unit test asserting `vcpu_budget() != usize::MAX` |

### missing_abstraction

| Gap | Sev | Lanes | Evidence | Fix |
|---|---|---|---|---|
| FUTEX_WAIT errno clamp re-implemented per backend; bhyve/nvmm diverge and leak raw host errno | med | bhyve, nvmm | `threaded_impl.rs:89` (clamp) vs `bhyve_futex.rs:34`/`nvmm_futex.rs:28` (`Error(r)`) | Hoist clamp into `carrick-hal/src/futex.rs` shared seam (R7) |
| bhyve `RamInner` vs nvmm `WindowRegion` — two diverged demand-paging models, no shared seam | med | bhyve, nvmm | `guest_setup_x86.rs` vs `nvmm_x86_engine.rs:265-478` | Unify in `carrick-x86` (R4) |
| x86 reclaim XSAVE serialization hand-rolled differently in KVM vs bhyve | med | bhyve, kvm | `kvm_x86_engine.rs:1342` vs `bhyve_x86_engine.rs:1773` | One `carrick-x86` serializer (R4) |
| `guest_setup_x86` clone3 init blob duplicated kvm/bhyve; shared `carrick-x86` copy missing the 6837b3bd fix | low | bhyve | `bringup.rs::msr_init_blob` (old 7-arg sig) | Complete Stage-4 unification (R4) |
| SysV IPC_SET implemented 3 inconsistent ways; **shmctl IPC_SET is a universal no-op** (mode change silently dropped, all lanes) | low | all | `sysv.rs:549` | `ipcsetperm` probe; store mode in carrick-owned `ShmSegment`; shared `IpcPerm` seam |
| `restore_user_segments` "no-op set_segment ⇒ must override" contract implicit/unenforced | low | bhyve, nvmm, kvm | `vmm.rs:663-685` doc-only | `carrick-x86` mock-vcpu unit test asserting default emits CS at DPL3; optional capability flag. (Runtime path already guarded by `mprotectexec`/`mremapshrink` on kvm+bhyve) |
| `Reg`/`SysReg`/`X86Reg` three-way split forces `reg_to_x86()` bridge + `unreachable!()` arms (audit T1 unlanded); false "compile error" doc | low | all | `error.rs:93/108-109`, `kvm.rs:465/481`, `engine.rs:601` | Fix the false doc comment now; land associated-`Reg`-type refactor. (Mapping already behaviorally guarded — `reg_to_x86` is on the hot syscall path) |
| Single `baseline.kvm.jsonl` overlay shared by kvm/bhyve/nvmm — can't express per-lane excuse | low | kvm, bhyve, nvmm | `main.rs:96`, `verdict.rs:99` | Lane-derived overlay (R6). Latent only — empty overlay fails-closed today |

### missing_regression_guard

| Gap | Sev | Lanes | Evidence | Fix |
|---|---|---|---|---|
| **No lane runs a guest in CI** — every runtime conformance gate is manual | **high** | all | `ci.yml:198-200` (dormant), cross-checks compile-only | R1 |
| x86 fork-coherence (`forkcow/forkshared/mapfixed`) report-only on x86; bhyve refresh/flush seam has no unit test | med | kvm, bhyve, nvmm | `conformance.rs:348-358`, 091b3f12 (no test) | bhyve shm-alias round-trip unit test + carve gating subset (R6) |
| bhyve/nvmm demand-paging guards (SEGV_ACCERR, stale-window prune) compile to nothing on macOS CI | med | bhyve, nvmm | `lib.rs:19`, `guest_setup_x86.rs:2875+` | Hoist `RamInner` + tests to `carrick-x86` (R4) |
| Sole-vCPU PT-reclaim off-by-one (strong_count BEFORE clone) has no unit test | med | hvf, kvm-aarch64 | `carrick-aarch64/src/engine.rs:307`, 35db00b6 | `carrick-aarch64` engine test w/ mock VMM asserting `set_multi_vcpu(false)` for sole vCPU. **Correct lanes: drop kvm-local (x86, uses `carrick-x86`)** |
| aarch64 sigframe restore bad-SP/non-EL0 fault (SignalDeliveryFault) untested; x86 twin is | med | hvf, kvm, bhyve, nvmm | `sigframe.rs:370/392` vs `x8664_arch.rs:2237`, 4258c237 | aarch64 codec unit tests in `sigframe.rs` (host-neutral → runs in CI) |
| Non-canonical-RIP / non-EL0-PSTATE **validation/rejection** arm untested on both ISAs | med | all | `x8664_arch.rs:627`, `sigframe.rs:388` | Two pure `carrick-hal` tests forging a readable-but-invalid RIP/PSTATE → assert SignalDeliveryFault |
| CPU-clock POSIX-timer firing (`run_fallback_cpu`/`is_cpu_clock`) — headline of 6d893c1e — no probe, no unit test | med | all | `posix.rs:178/226`; `posixtimers.rs` (MONOTONIC only) | `carrick-timer-core` unit test mirroring `itimer.rs:493` (drives `guest_cpu` accessor) |
| `{0,0}` zero-timeout immediate-ETIMEDOUT fix (519dd40f) no guard | med | all | `proc.rs:1555-1574`; LTP futex_wait broken/broken | In-process test in `concurrency_contracts.rs` asserting `FutexWait{timeout:Some(ZERO)}` + wall-bounded probe |
| `connect(0.0.0.0)→loopback` rewrite no probe/unit test | med | hvf, bhyve, nvmm | `net.rs:148`, 55e1dbf5 | `cfg(not(linux))` byte-transform unit test in `net.rs` + `connectunspec` probe |
| semctl IPC_SET mode-apply no-op off macOS, no probe on any lane | med | all | `sysv.rs:1242-1269`, f1673bfc | `semctlsetmode` probe + overlay excuses on bring-up lanes |
| Rosetta x86_64 path (only x86 on macOS reference) — no probe/baseline | med | hvf | `runtime.rs:446-522` | macOS Rosetta suite (musl/glibc dynamic; assert AT_BASE present, `/proc/self/exe` resolves) + `with_auxv_base` unit test |
| `carrick-host-linux` native-epoll backend tests run on no CI lane; crate not compile-checked | med | kvm | `epoll_mux.rs:652+`, `justfile:226` | R3 |
| FP/AVX-save-across-reclaim no probe on x86; bhyve/kvm XSAVE serialization unguarded | med | bhyve, kvm | `bhyve_x86_engine.rs:1773`, eb9d83f3; `threadbarrier.rs` counts only | Shared serializer + round-trip unit test + `reclaimfpregs` probe (R4). HVF transitively guarded by `forkfpregs` |
| sockopt EBADF/ENOTSOCK errno fix no line-exact probe; LTP backstop is broken/broken | low | all | `net.rs` sockopt handlers, 199d1712 | `sockopterrno` probe (closed-fd→EBADF, regular-file→ENOTSOCK, socket→ok) |
| Shared mmap errno fixes (MAP_SHARED_VALIDATE→EOPNOTSUPP, select nfds `as i32` truncation) untested | low | all | `mem.rs:402-413`, `net.rs:452`, 5b6c465b | `mem.rs` unit test for the two errno arms; harden `selectnfds.rs` for the zero-extension form. (/dev/zero leg already covered by `mmapdevzero.rs`) |
| Trap-watchdog wall-window decision untested, bypassed by gate (`--max-traps usize::MAX`) | low | all | `vcpu_loop/mod.rs:984-1012`, d24310bc/dfb55db6 | Extract pure `watchdog_trip(...)` + unit tests |
| `names_self(0)==false` arm not isolated by any probe; no CI-runnable guard | low | all | `abi_args.rs`, ba19bd2f | Pure-fn refactor + unit test. (Drifted arms already guarded by `killtarget`/`pidnsinitsig` on all lanes) |
| `ForkRamStrategy` engine branch wiring no fast CI guard | low | all | `carrick-x86/engine.rs:1131`, 950a34e4 | `TestVmm` freeze-counter unit test. (Behaviorally guarded by `forkcow.rs` on every lane, manual) |
| ABI wire-struct value pack/unpack (signedness/endianness/per-ISA variants) — only size/offset asserts | low | all | `sysv.rs:162`; no proptest in workspace | proptest round-trip layer in `carrick-abi` + one differential `fstat`-bytes test per ISA |
| Reverse x86-shim reachability — no enforced guard (recurring manual gnu-gap hunts) | med | kvm, bhyve, nvmm | `syscall_x86_64.rs:1012` (forward only) | R5 (forward completeness allowlist) |
| Fuzz target (ELF only) in excluded sub-workspace CI never compiles; ABI decoders unfuzzed | low | all | `fuzz/`, `Cargo.toml:3-7` | CI `cargo build --manifest-path fuzz/Cargo.toml`; later add sockaddr/msghdr/cmsg/clone_args targets. (Runtime-contained by `dispatch_with_panic_backstop` + `overflow-checks`) |
| `kvm_xsig.rs` dead-forwarder residue (4/5 vestigial) + stale `CrossProcessFutex` doc | low | — | `kvm_xsig.rs:1`, `carrick-hal/lib.rs:6` | Cosmetic: delete dead forwarders; fix doc |

### silent_failure_risk

| Gap | Sev | Lanes | Evidence | Fix |
|---|---|---|---|---|
| **seccomp arch/nr hardcoded aarch64** → Docker default profile guest-fatal on every x86 lane | **high** | kvm, bhyve, nvmm, (Rosetta) | `dispatch/mod.rs:2170-2174`, `seccomp.rs:73-75` | R2 |
| bhyve reclaim drops FP state on `get_xsave`/`set_xsave` error (`.ok().flatten()`, `let _`) → silent SSE/AVX corruption | med | bhyve | `bhyve_x86_engine.rs:1784`, eb9d83f3 | Fail-loud like KVM + shared seam + `reclaimfpregs` probe (R4) |
| fasync SIGIO `ns_to_host_or_self(ns).unwrap_or(ns)` sends signal to raw ns value as host pid on translation miss | med | all | `fs.rs:2397-2405`, 6b24b1a1 | Drop-on-miss (match kill-path ESRCH intent); `fasynciodeliver` probe; re-bless `fcntl31` to MATCH; unit test. (mq_notify **refuted** — stores host pid) |
| F_OFD_*→regular-lock downgrade on BSD silently changes OFD semantics; probe report-only, no excuse | low | bhyve, nvmm | `carrick-portable/lib.rs:97-108`, `fcntlofdlock.rs:52-77` | `baseline.bsd.jsonl` excuse + `compat-report` entry on F_OFD_* over downgraded host |
| BSD `bsd_extattr_ns` tag round-trip (system/trusted/security) — regressed once (0660b721) — no CI guard | med | bhyve, nvmm | `lib.rs:390-426/1222`; freebsd-cfg test covers user.* only | Extract pure tag helpers + non-cfg-gated unit test (R4) |
| `refresh_shared_after_wait` trigger uses bare `Some(260)|Some(95)` literals decoupled from `carrick-abi`; no macOS-CI test | low | bhyve | `carrick-x86/engine.rs:968` | Use abi constants + `TestVmm` invocation test. (End-to-end guarded by `forkshared`/`ltpcheckpoint` on bhyve) |
| mincore residency-vec DoS bound (guest-reachable host abort) — ENOMEM/overflow arms untested | low | all | `mem.rs:963-969`, ae195376 | Extend `syscall_mem.rs:364` (success path already covered) with unmapped-end + overflow ENOMEM asserts |
| sigdeath marker write best-effort + pid-keyed (stale-pid false WIFSIGNALED) | low | hvf, bhyve, nvmm | `exec_helpers.rs:316/266` | O_EXCL + per-run token + unit tests. (Happy path guarded by LTP waitpid01) |
| msgctl IPC_SET `msg_qbytes` round-trip + NetBSD reuse of macOS msqid_ds offsets — no probe/assert | low | hvf, nvmm | `sysv.rs:82-105`, 73524767 | Extend `sysvmsg.rs` (qbytes via IPC_SET) + compile-time offset guard. (qnum offset already differentially verified on hvf) |
| Oracle-cache determinant key has no golden-key/version guard → schema drift silently triggers full Docker re-pass | low | all | `oracle.rs:28-41/97-99` | Golden-key string test; count+warn on skipped records. (Self-healing; semantic key tests exist) |
| Name-keyed probe excuses Xfail for ANY diff → excused probe masks a NEW real regression | low | amd64/kvm, hvf | `conformance.rs:1377-1382/1347-1363` | Fingerprint the excused **carrick-side** output; mismatch → Fail; pure-fn unit test |

## 4. What is already well-covered (don't spend effort here)

- **Compile-time meta-guards**: the exactly-one-platform `compile_error!` (`main.rs:96-117`) and `build.rs` platform↔`target_os` assert are airtight; `carrick-abi` size/offset/uniqueness asserts and the `X86_64_SYSCALLS` sortedness + cross-aarch64 name check are solid (theme items "ABI asserts" and "platform guards" are NOT gaps).
- **macOS/HVF reference lane runtime behavior**: forkcow/forkshared/mapfixed gate on arm64; HVF COW has CI host-level tests (`mach_cow_probe`/`minherit_probe`); the x86 PROT_NONE/EFAULT gate is unit-tested in CI (`x86_set_no_access_records_and_default_gate_efaults`); `forkfpregs` transitively guards HVF reclaim FP; `killtarget`/`pidnsinitsig` guard the historically-drifted `names_self` arms on all lanes.
- **The shared-engine/structural-leverage work (F1–F9)**: HVF is genuinely folded onto the shared seams (HvfFutex = `FutexTableFutex<HvfShared>`, `Aarch64EngineCore<HvfAarch64Vmm>`, generic `run_threaded_loop`); `shared_futex_uses_mirror()` is a clean trait hook, not a re-forked seam. No new HVF-holdout reimplementation found.
- **The syscall **translation table** half of x86 bring-up**: `x8664_arch::normalize_syscall` + `carrick-abi::syscall_x86_64` have ~40 unit-test cases running in macOS CI (fork/vfork/clone3 desugaring, stat-family/poll/select/dup2/alarm normalization, ISA reporting). The runtime *engine* half (MAP_FIXED aperture) is the gap, not the table.
- **POSIX mqueue**: fully neutral host-file-backed, zero `cfg`, guarded by LTP + `mqueue.rs` probe. (SysV IPC is the opposite — see findings.)
- **The neutral M:N admission layer** (`carrick-hal/src/vcpu_sched.rs`, 6 tests) and the **`BackendCapabilities`/`HostOs` table** (8932e94b) have real exhaustive unit tests. The reclaim **mechanics** are the gap, not admission.
- **The host-signal disposition/xsig/fork-coordinator machinery** (7676c89e..6517fc82) is single-sourced and unit-tested; the sigframe **codec** is single-sourced per ISA. Only the sigframe **guards** are thin.

## 5. Suggested sequencing (regression-protection per unit of effort)

**Phase 0 — the one live bug + the root multiplier (do immediately):**
1. **R2 seccomp ISA fix** — it is guest-fatal on every x86 lane today, not a coverage gap. Ship the fix + probe + unit test.
2. **R1 CI guest lane** — nightly `just kvm-smoke` on the self-hosted KVM box + un-dorm `hvf-conformance`. Everything below becomes meaningfully enforceable once a guest runs.

**Phase 1 — cheap CI-visibility wins (hours, existing runners, no guest needed):**
3. **R3**: `cargo test -p carrick-host-linux`, NetBSD cross-check, `--all-targets` on BSD checks.
4. **R5**: forward x86-syscall-completeness `carrick-abi` test (kills recurring manual gnu-gap hunts).
5. The host-neutral unit tests that need no refactor: sigframe aarch64 codec + validation-arm tests (`carrick-hal`, runs everywhere); `run_fallback_cpu` timer test; `{0,0}` futex `concurrency_contracts.rs` test; `connect(0.0.0.0)` byte-transform test; mincore ENOMEM/overflow asserts; watchdog `watchdog_trip` test; `translate_child_wait_status`/`consume_sigdeath_marker` tests.

**Phase 2 — the structural seam consolidation (R4), highest durability:**
6. Hoist demand-paging `RamInner`, x86 reclaim XSAVE serializer, the clone3 init blob, BSD xattr tag helpers, `sendfile` partial-count, and SysV `ipc_perm` fill into `carrick-x86`/`carrick-portable` with their tests. Each move both kills a backend divergence and converts a zero-CI-coverage test into a `cargo test --workspace` test. Fold in the bhyve XSAVE fail-loud fix here.

**Phase 3 — gating + per-lane infrastructure (R6, R7) + new probes:**
7. **R7**: fix the four `=98` futex probes + lint grep; hoist the FUTEX_WAIT errno clamp.
8. **R6**: lane-derived overlays, `--bless --lane`, and a per-probe gating allowlist; bless the curated x86 subset + new probes (`afunixbackpressure`, `semctlsetmode`, `sockopterrno`, `connectunspec`, `clockcoherence`, `reclaimfpregs`, `seccompdefaultprofile`, Rosetta suite) once they pass on the fleet.

**Phase 4 — long-tail hardening:** Reg-enum T1 refactor + false-doc fix; OFD `baseline.bsd.jsonl` excuse + compat-report; inotify capability-driven source ownership; oracle golden-key test; excuse-fingerprinting; fuzz crate CI build + ABI decode targets; NVMM `vcpu_budget` override; `kvm_xsig` cleanup.

Phases 0–1 deliver the bulk of the regression protection for the least effort; Phase 2 is where the *durable* structural payoff (one seam, one test, no divergence) is concentrated and should not be skipped in favor of per-case probes.
---

## Appendix — independent verification (spot-checks of the headline claims)

This report was produced by a 72-agent find→adversarial-verify→synthesize sweep
over the last ~260 commits. Each gap (except the four critic-added ones) survived
a skeptic told to refute it. The four highest-impact / most surprising claims were
then re-checked by hand against the live source:

- **R2 seccomp arch hardcode (HIGH, live bug) — CONFIRMED.**
  `crates/carrick-runtime/src/dispatch/mod.rs:2170-2174` builds `SeccompData` with
  `arch: AUDIT_ARCH_AARCH64` and `nr: request.number` (the canonical/normalized
  number). `crates/carrick-runtime/src/seccomp.rs` defines only
  `AUDIT_ARCH_AARCH64 = 0xC000_00B7` — no x86_64 constant. An x86 guest installing
  any `arch != AUDIT_ARCH_X86_64 → KILL` filter (the Docker/libseccomp default
  prologue) is killed. This finding was added by the completeness critic and so did
  NOT pass the per-gap skeptic stage — it is hand-verified here instead.
- **x86 probe lane report-only (root multiplier) — CONFIRMED.** Both AMD64 probe
  sets (musl + gnu) are `gating: false` in
  `crates/carrick-cli/tests/conformance.rs:194,199`; the comment says to flip to
  `gating: true` "once carrick-x86 reaches probe parity." (The report cited
  `conformance.rs:194/199` without the `crates/carrick-cli/tests/` prefix — line
  numbers exact, path prefix dropped. The same imprecision affects other
  `conformance.rs:NNN` citations in this doc; resolve them under that path.)
- **Four `=98` futex probes false-MATCH on x86 — CONFIRMED.**
  `conformance-probes/src/bin/{futexshare,futexwakecount,futexsharedalias,futexrequeue}.rs`
  each declare `const SYS_FUTEX: libc::c_long = 98; // aarch64` and call
  `libc::syscall(SYS_FUTEX, …)`. Syscall 98 on x86_64 is `getrusage`, so these run
  the wrong syscall (and pass) on every x86 lane.
- **No per-lane baseline for bhyve/nvmm — CONFIRMED.** Only
  `scripts/conformance/baseline.jsonl` (8.6 MB) and an empty
  `scripts/conformance/baseline.kvm.jsonl` (0 bytes) exist.

Trust level: high. The one caveat is citation-path precision (the `conformance.rs`
prefix above); line numbers and substance held everywhere checked.

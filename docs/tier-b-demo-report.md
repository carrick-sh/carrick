# Tier B demo report — `busybox echo hello` against Alpine

## Environment

- Date: 2026-05-18
- macOS: `Darwin Timothys-MacBook-Air-2.local 25.5.0 Darwin Kernel Version 25.5.0: Mon Apr 27 20:41:26 PDT 2026; root:xnu-12377.121.6~2/RELEASE_ARM64_T8132 arm64` (macOS 26 / Tahoe, Apple Silicon)
- Carrick worktree: `/Volumes/CaseSensitive/carrick/.claude/worktrees/agent-ab27f527132522b0f`, branch `main` @ `02eddd3` (clean before this report)
- Release build: `cargo build --release --bin carrick` succeeded in 25.8s, no warnings of note.
- HVF capabilities (`./target/release/carrick trap-capabilities`):

```json
{
  "backend": "hypervisor_framework",
  "available_on_this_host": true,
  "implemented": true
}
```

## Pull attempt

### First attempt — tag reference

Command:

```
./target/release/carrick pull docker.io/library/alpine:latest
```

Outcome: **Registry rejected by client-side platform resolver.** Exact error:

```
Error: OCI registry operation failed: Image manifest not found:
  no entry found in image index manifest matching client's default platform
```

Root cause: `src/oci.rs::pull_image` constructs `oci_distribution::Client::default()`. The default `ClientConfig` ships `platform_resolver = Some(current_platform_resolver)`, which matches manifests where `os == go_os()` AND `architecture == go_arch()`. On this host that evaluates to `os == "darwin" && architecture == "arm64"`, but `docker.io/library/alpine`'s OCI image index advertises only `linux/{amd64,arm/v6,arm/v7,arm64,386,ppc64le,s390x,riscv64}`. No entry matches `darwin/arm64`, so the resolver returns `None` and `oci-distribution` bails with the error above. The registry itself was reachable (HTTPS token endpoint and `/v2/library/alpine/manifests/latest` responded with the full index when probed directly via `curl`).

### Workaround — digest-pinned pull

Bypassed the resolver by fetching the `linux/arm64` manifest digest out-of-band and pulling it directly. The bootstrap accepts `@sha256:...` references and short-circuits the index-resolution path (digest references are fetched as concrete manifests).

```
TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json" \
  "https://registry-1.docker.io/v2/library/alpine/manifests/latest" \
  | python3 -c "import json,sys
m=json.load(sys.stdin)
for x in m['manifests']:
    p=x.get('platform',{})
    if p.get('architecture')=='arm64' and p.get('os')=='linux':
        print(x['digest'])"
# -> sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0

./target/release/carrick pull \
  docker.io/library/alpine@sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0
```

Outcome: **success.** Result:

- Manifest digest: `sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0`
- Image dir: `/Users/tjfontaine/.carrick/images/docker.io/library/alpine/sha256/378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0`
- Config size: 627 bytes
- Layers: 1
  - Layer digest: `sha256:d17f077ada118cc762df373ff803592abf2dfa3ddafaa7381e364dd27a88fca7`
  - Media type: `application/vnd.oci.image.layer.v1.tar+gzip`
  - Size: 4,199,870 bytes (~4.0 MiB)
  - Path: `/Users/tjfontaine/.carrick/blobs/sha256/d17f077ada118cc762df373ff803592abf2dfa3ddafaa7381e364dd27a88fca7`

## Run attempt

Command (using the digest-pinned reference from the successful pull):

```
./target/release/carrick run \
  docker.io/library/alpine@sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0 \
  /bin/busybox echo hello
```

(Note: `Commands::Run` in `src/main.rs` does not expose `--max-traps` or `--compat-report`; it always uses `DEFAULT_MAX_TRAPS = 1_000_000` and prints the report inline. So `--max-traps 4096` from the brief is not accepted here.)

Outcome: **Failed before HVF was even constructed.** Exit code 1. No traps executed (the run never reached the dispatcher / HVF loop). Stderr (122 bytes, full):

```
Error: failed to compose image rootfs layers

Caused by:
    layer contains a path outside the rootfs: etc/../proc/mounts
```

Stdout was empty.

- Trap count reached: 0 (rootfs composition failed before any guest code was loaded; `LinuxAbi`, the dispatcher, `AddressSpace`, and HVF were never instantiated).
- First three unhandled syscalls: **N/A** — never started executing the guest.
- First three unhandled ioctls: **N/A**.
- First three unimplemented `/proc` reads: **N/A**.
- First three unimplemented `/sys` reads: **N/A**.
- Exit code (Linux guest sense): **N/A** — host process exited 1 with the error above.
- Captured stdout/stderr: see above (stdout empty, stderr 122 bytes shown verbatim).

### Why the rootfs composer rejected the layer

`src/rootfs.rs::normalize_path` flatly rejects any `Component::ParentDir` (`..`), and `normalize_symlink_target` reaches it via:

```rust
fn normalize_symlink_target(link_path: &Path, target: &Path) -> Result<PathBuf, RootFsError> {
    if target.is_absolute() {
        return normalize_rootfs_path(target);
    }
    let parent = link_path.parent().unwrap_or_else(|| Path::new(""));
    normalize_path(&parent.join(target), false)   // <- contains ".."
}
```

The Alpine layer carries perfectly ordinary POSIX relative symlinks whose textual targets contain `..`. Confirmed via `tar -tzvf` on the cached layer:

```
lrwxrwxrwx 0 0 0 0 Apr 14 21:51 etc/mtab -> ../proc/mounts
lrwxrwxrwx 0 0 0 0 Apr 14 21:51 etc/os-release -> ../usr/lib/os-release
lrwxrwxrwx 0 0 0 0 Apr 14 21:51 usr/share/apk/keys/aarch64/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub -> ../alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub
...
```

`/etc/mtab -> ../proc/mounts` is well-formed: `etc/` + `../proc/mounts` reduces to `proc/mounts`, which is in-rootfs. The composer is throwing on a legitimate symlink layout that any container runtime accepts. The first failing entry happens to be `etc/mtab` (the first symlink-with-`..`-target in the tar order); subsequent ones (`etc/os-release`, the many `usr/share/apk/keys/<arch>/...` entries) would also trip the same path.

`normalize_path` should reduce `..` components against the accumulated path (popping the previous `Normal` component) and only reject when the path would escape *above* the rootfs root (i.e., the stack would underflow). That's what `path-clean`-style canonicalization does, and it's what `tar`/OCI extractors do.

## Diagnosis

The Tier B demo is currently blocked on two cliffs *before* any guest instruction executes. Both are squarely in host-side bootstrap code; neither requires touching the HVF trap loop or syscall dispatch surface.

1. **Symlink-target path normalization in `RootFs` (`src/rootfs.rs`).** Blocking. Classification: **bootstrap-stub-extension** (small, well-scoped change to existing host code).
   - `normalize_path` (called from `normalize_symlink_target` and `normalize_layer_path` with `allow_absolute=false`) rejects every `Component::ParentDir`. Replace the blanket `Err(UnsafePath)` for `ParentDir` with: pop the last `Normal` component from `out`; if `out` is empty (would escape root), *then* return `UnsafePath`. Apply only to relative-target reduction; the absolute-target path (`normalize_rootfs_path(target)`) is already independently safe since it walks from the synthetic root.
   - This alone unblocks layer composition for Alpine. No new dependencies. ~10 lines of code plus tests covering `etc/mtab -> ../proc/mounts`, `a/b/c -> ../../x`, and an actual escape (`a -> ../../../etc/passwd` must still error).

2. **Pull-by-tag for Linux images on a macOS host (`src/oci.rs::pull_image`).** Blocking only if you want a friendlier UX than the digest workaround; *not* blocking Tier B itself once you accept the digest pin. Classification: **bootstrap-stub-extension**.
   - The `oci-distribution` client defaults to host-OS resolution, so on macOS it asks for `darwin/arm64` and finds nothing in a `linux/*` index. Build a `ClientConfig` with `platform_resolver: Some(Box::new(|m| /* pick linux/arm64, then linux/amd64 as a deliberate fallback or just linux/arm64 */))`. Equivalently, the Tier B demo can be reproduced today by pre-resolving the digest as shown above.

There is no evidence of any missing-syscall or missing-`/proc` work being required for Tier B — that question is unanswerable from this run because we never reached the dispatcher. Once issue (1) is fixed, the next failure mode to expect (from reading `dispatch.rs`, `linux_abi.rs`, the existing fixture suite under `fixtures/linux-aarch64-hello/src/`, and the v0.1 plan in `plan.md`) is dynamic-loader-driven syscalls in `/bin/busybox` (musl ldso-bootstrap: `mmap`, `mprotect`, `read`, `pread64`, `openat`, `readlinkat`, `set_tid_address`, `set_robust_list`, `rseq`, `prlimit64`, `getrandom`, `brk`, `arch_specific_register_setup`). That follow-on investigation is out of scope for this report; this report's job was to find the first wall, and the first wall is rootfs composition.

### Smallest path forward

- Patch `normalize_path` to collapse `..` rather than reject. **Required.**
- (Optional, quality-of-life) Add a Linux/arm64 platform resolver to `pull_image` so `carrick pull docker.io/library/alpine:latest` works without an external digest lookup.
- Re-run `./target/release/carrick run docker.io/library/alpine@sha256:378c4...d1481a0 /bin/busybox echo hello`, capture the embedded `report` field from the JSON output, and iterate on whatever the first unhandled syscall / ioctl / proc-read is.

## Reproduction

A future engineer can replay this exact investigation against the same Alpine bits as follows. (The digest is pinned, so the demo is stable against future Alpine pushes.)

```bash
# From the repo root.
cargo build --release --bin carrick

./target/release/carrick trap-capabilities

# Tag pull (fails today on this host platform).
./target/release/carrick pull docker.io/library/alpine:latest

# Digest pull (works).
./target/release/carrick pull \
  docker.io/library/alpine@sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0

# Run (fails today during rootfs composition).
./target/release/carrick run \
  docker.io/library/alpine@sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0 \
  /bin/busybox echo hello

# Confirm the offending symlinks in the cached layer.
tar -tzvf ~/.carrick/blobs/sha256/d17f077ada118cc762df373ff803592abf2dfa3ddafaa7381e364dd27a88fca7 \
  | awk '$NF ~ /\.\./ || $(NF-1) ~ /\.\./' | head
```

The cached image lives under `$HOME/.carrick/` by default (or `$CARRICK_HOME` if set). Removing that directory between runs forces a fresh pull.

## Second attempt — EL0 entry trampoline added

Date: 2026-05-18, after landing the `with_el0_trampoline()` builder in `src/memory.rs` and the matching `el0_trampoline_entry` handling in `src/trap.rs`.

Setup: vCPU starts at the trampoline page (guest PA `LINUX_EL0_TRAMPOLINE_BASE = 0x10000`), executes a single `eret` at offset 0, and drops to EL0t with `PC = plan.entry`, `PSTATE = 0x3c0` (EL0t, DAIF masked). SPSR_EL1 and ELR_EL1 are staged before the run, CPSR remains EL1h, and SCTLR_EL1 stays `0` (stage-1 MMU off).

Command (after `cargo build --release` + `codesign --force --sign - --entitlements scripts/entitlements.plist target/release/carrick`):

```
./target/release/carrick run-elf \
  fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello \
  --max-traps 8
```

Outcome: **new wall.** Exit code 1. Exact stderr:

```
Error: failed to run static ELF fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello

Caused by:
    0: trap engine failed: guest exception is not an AArch64 SVC trap: syndrome=0x82000007, virtual_address=0x400, physical_address=0x400
    1: guest exception is not an AArch64 SVC trap: syndrome=0x82000007, virtual_address=0x400, physical_address=0x400
```

### Interpretation

Comparing against the first-attempt symptom (same shape, but `virtual_address=0x200`):

- First attempt vectored to PA `0x200` — the AArch64 "current EL with SPx, synchronous" vector entry. That happens when the vCPU is still at EL1 and takes a synchronous exception (the SVC instruction itself, or a fault from running user code in EL1h). Indicates the vCPU never reached EL0.
- Second attempt vectors to PA `0x400` — the "lower EL using AArch64, synchronous" vector entry. That entry is **only** taken when the source EL is strictly lower than the current EL, i.e., EL0 → EL1.

So the trampoline `eret` did fire, PSTATE flipped to EL0t, ELR_EL1 loaded into PC, the guest executed at least one user-mode instruction, and the first `svc #0` correctly raised "synchronous from lower EL using AArch64." The exception then vectored to `VBAR_EL1 + 0x400`. `VBAR_EL1 = 0`, stage-1 MMU is disabled, and stage-2 has no region mapped at `0x400`, so HVF reports an Instruction Abort from a lower EL (EC=`0x20`, IFSC=`0x07` — translation fault, level 3) at IPA `0x400`.

This is success-shaped progress: Tier B is no longer blocked on getting to EL0, it is now blocked on the EL0 → EL1 exception path.

### Next wall: routing the EL0 SVC to HVF

`svc #0` from EL0 vectors to EL1 (the guest's own VBAR_EL1) by default. To surface it to the host (HVF) we need one of:

1. **`HCR_EL2.TGE = 1`.** This is the canonical fix — TGE routes synchronous EL0 exceptions to EL2 (HVF) instead of EL1. *Not available on standard HVF.* `applevisor-sys` gates `HCR_EL2` behind the `macos-15-0` feature *and* "EL2 was enabled in the VM configuration." Plain HVF guests on Apple Silicon run with the host at EL2; the guest cannot directly program HCR_EL2. (Verified: `cargo build` with `SysReg::HCR_EL2` fails — the variant is not in the public enum on the current feature set.)
2. **EL1 vector stub that re-traps to HVF via `hvc #0`.** Install a VBAR_EL1-aligned page (`0x800` boundary; the existing trampoline base `0x10000` qualifies) and put `hvc #0; eret` at offset `0x400`. `hvc` from EL1 unconditionally traps to EL2, which HVF surfaces as an `EXCEPTION` exit with `EC = 0x16` (HVC). The host dispatches the syscall, sets `X0`, resumes the vCPU; the vCPU continues at the `eret` two instructions later, which restores SPSR_EL1/ELR_EL1 (still holding the user's saved PSTATE and return PC) and drops back to EL0. The trap engine would need to accept `EC = 0x16` in addition to `EC = 0x15` — or treat HVC as the canonical syscall trap and stop expecting SVC at all.
3. **Same vector stub, but the stub itself reads X8/X0..X5 and emits an `hvc` so the host knows it's a syscall.** Equivalent to (2) — `hvc #0` does not require a special encoding to convey syscall arguments; the X registers are preserved across the EL0 → EL1 transition.

Option (2) is the smallest delta: one extra 16 KiB region, four extra bytes of trampoline (`hvc #0` at `0x10400`, `eret` immediately after), a `VBAR_EL1 = 0x10000` write in `map_plan`, and a single-line widening of `is_aarch64_svc_exception` to also accept `EC = 0x16`. The existing `Aarch64SyscallFrame` extraction works unchanged because X0–X5 and X8 are preserved across the EL0 → EL1 transition. Returning to user space is automatic: the `eret` immediately after `hvc` restores the hardware-saved SPSR_EL1 (= user PSTATE) and ELR_EL1 (= user PC after SVC). No host-side PC fix-up needed beyond writing X0.

### What this change did (and didn't) move

- **Did:** Wire the vCPU through one round-trip across EL1 → EL0. `_start` of the static musl-hello binary now executes in EL0.
- **Did:** Confirm the trampoline `eret`, SPSR_EL1 staging, and ELR_EL1 staging are all functional under HVF.
- **Didn't:** Surface the SVC to the dispatcher. We have moved the wall from "vCPU never leaves EL1" to "EL1 has no vector handler." Tier B is still gated on the EL1 vector stub described above.

### Reproduction

```bash
cargo build --release --bin carrick
codesign --force --sign - --entitlements scripts/entitlements.plist target/release/carrick
./target/release/carrick run-elf \
  fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello \
  --max-traps 8
# expected: syndrome=0x82000007, virtual_address=0x400 (EL0 SVC vectored to unmapped VBAR_EL1+0x400)
```

## Third attempt — stage-2 RW-without-X stack/data fault, and the macOS 26 HVF workaround

Date: 2026-05-18, after landing the EL1 vector forwarding stub and chasing the next wall.

### Symptom

Running `./target/release/carrick run docker.io/library/alpine@sha256:378c4...d1481a0 /bin/busybox echo hello` produced:

```
trap engine failed: guest exception is not an AArch64 SVC trap:
syndrome=0x92000005, virtual_address=0xfffffeff40, physical_address=0xfffffeff40
```

Decode: `EC = 0x24` (Data Abort from a lower EL), `WnR = 0` (read), `DFSC = 0b000101` (translation fault, level 1). The faulting VA `0xff_fffe_ff40` lies inside the configured stack region `LINUX_STACK_TOP - LINUX_STACK_SIZE .. LINUX_STACK_TOP` (i.e. `0xff_ffef_0000 .. 0xff_ffff_0000`) and is exactly the initial SP that `with_linux_initial_stack` plants for `argc/argv/envp/auxv`.

### Diagnosis (root cause)

This is not a missing-mapping bug. With ad-hoc tracing in `GuestMappingPlan::from_address_space` and `map_plan`, we confirmed that:

1. The stack region IS in the `AddressSpace` for the OCI/rootfs path (the rootfs `run_rootfs_elf_with_hvf_args` builder already chains `.with_linux_initial_stack(argv, env)`).
2. The corresponding `GuestMapping` IS emitted with `guest_start=0xffffef0000`, `mapped_size=0x100000`, `payload_size=0x100000`, perms `RW`.
3. `hv_vm_map` for that range succeeds with no error.
4. A host-side `Memory::read(stack_pointer, &mut [u8; 16])` immediately after the map returns the expected `argc=3` plus the first `argv` pointer — i.e. the host allocation is correctly written and addressable.
5. From the guest side, after the EL0 trampoline `eret`, `_dlstart` (musl ld's entry) executes correctly up to and including `mov x0, sp; and sp, x0, #~15; sub sp, sp, #0x230; mov x3, x0` (verified by reading PC=0x800006953c+0x24=0x800006953c+9·4=0x...69560 and SP_EL0=0xfffffefd10 at the fault, which is the original SP minus 0x230). The very next instruction, `ldr x2, [x3], #0x8` at `_dlstart+0x24`, then takes the stage-2 fault on the read from x3 (= original SP).

The fault virtual address equals the host-readable IPA inside our registered mapping. ARMv8's stage-2 attribute model has no per-EL data-access bit, so this is not architectural. The mapping exists, is addressable from the host, but the guest's stage-2 walk for an EL0 data access into it returns "translation fault, level 1".

To narrow it further we ran the static-PIE fixture `carrick-linux-aarch64-pie-hello` (also at `LINUX_STACK_TOP=0xff_ffff_0000`, same RW stack region). It runs to completion in 2 traps. The difference: that fixture's `_start` writes "hello from carrick pie\n" and exits *without ever touching the stack*. As soon as we ran `carrick-linux-aarch64-argv-echo` (a static fixture that DOES `ldr x0, [sp]`), it reproduced the same `syndrome=0x93c08005` / `DFSC=0x05` fault at `virtual_address=stack_pointer`.

Targeted permutation testing then isolated the bug:

| Stack region perms (HVF `MemPerms`) | Outcome |
|---|---|
| `ReadWrite`   | Stage-2 translation fault, level 1, on EL0 data read |
| `Read`        | Works (no write, no execute — fault clears) |
| `ReadWriteExec` | Works |

So the failure is specifically `HV_MEMORY_READ | HV_MEMORY_WRITE` *without* `HV_MEMORY_EXEC` on macOS 26 (Tahoe) HVF: that stage-2 attribute combination apparently does not produce a valid stage-2 table entry for EL0 data accesses, even though `hv_vm_map` returns success and host-side reads/writes via the same `Memory` handle work. This is HVF-specific behaviour, not ARMv8 architectural. We have not seen it reported elsewhere; it may be specific to macOS 26 + the `macos-13-0` feature set of `applevisor` (default IPA granule 4 KiB while host pages are 16 KiB), but isolating that is out of scope here.

### The fix

`src/trap.rs::hvf_perms` now escalates any `Write`-capable mapping to also carry `Exec`. Concretely:

```rust
let escalated_perms = SegmentPerms {
    read: perms.read,
    write: perms.write,
    execute: perms.execute || perms.write,
};
```

The escalation is gated on `write`, so `Read`-only and `Exec`-only mappings still translate the original perms (those work as-is and don't trip the quirk). With stage-1 disabled (`SCTLR_EL1.M = 0`) and the host process single-tenant, the extra stage-2 `X` bit on writable data/stack regions doesn't introduce a meaningful new attack surface — the guest could already execute anywhere, since stage-1 isn't enforcing it.

The change is 10 lines of code (plus a long explanatory comment) entirely inside `hvf_perms`. No address-space layout changes, no new HVF feature, no syscall-dispatch changes. All 215 pre-existing tests still pass.

### What the fix moved (and what it didn't)

- **Did:** The Tier B stack stage-2 fault on the first `ldr` is gone. musl ld's `_dlstart` now successfully reads `argc`, `argv`, and the auxv.
- **Did:** The very first syscall reaches our dispatcher. With debug tracing we observed `trap#1: EC=0x16 (HVC route), x8=96 (set_tid_address), x0=stack_arg, x1=1, x2=8`, returning `3407` (our synthetic TID). This is the first concrete evidence Tier B's user code is actually running under the dispatcher.
- **Didn't:** Get past the *second* syscall. See below.

### New wall: PC fails to advance past the EL1 vector's HVC re-trap on the second SVC

After the fix, `carrick run … /bin/busybox echo hello` either exits with `RuntimeError::TrapLimitExceeded { max_traps: 1_000_000 }` or with HVF returning `0xfae94007` (`HV_DENIED`) part-way through, depending on timing — both stem from the same underlying loop.

With per-trap tracing (`eprintln!` in `runtime.rs` + `run_until_syscall`) the loop shape is:

```
trap#1: EC=0x16 pc=0x20404 elr_el1=0x800001fcac spsr_el1=0x800003c0  x8=96  -> Returned(3407)
trap#2: EC=0x16 pc=0x20404 elr_el1=0x8000018420 spsr_el1=0x200003c0  x8=1685382482 (=0x6473_5f4d)  -> Errno(38)
trap#3..N: EC=0x16 pc=0x20404 elr_el1=0x8000018420 spsr_el1=0x200003c0  x8=1685382482  -> Errno(38)
… repeats until trap budget exhausted or HVF returns HV_DENIED …
```

So:

- Trap #1 dispatches cleanly. `set_tid_address` returns 3407. The EL1 vector's `eret` fires and user code keeps running.
- Trap #2 fires from a different user PC (`ELR_EL1` jumps from `0x800001fcac` to `0x8000018420`), so user code DID execute between traps. But `X8 = 0x6473_5f4d` — which is ASCII "M_sd" as bytes — is not a valid Linux/aarch64 syscall number (max is < 500). The disassembly at `ELR_EL1 - 4 = 0x800001841c` shows `nop`, not `svc`. So whatever raised this exception, it wasn't a plain user-mode `svc #0` at `0x800001841c`.
- From trap #2 onwards, `pc` (the HVC instruction at vector slot `0x20400 + 4 = 0x20404`), `ELR_EL1`, `SPSR_EL1`, and `X8` are all identical on every trap. The vCPU is **stuck** re-executing the same EL1 vector's `hvc #0` in a loop. Our `complete_syscall` only writes `X0`; it does not advance PC or eret, and apparently the `eret` two instructions later either never fires or fires back into a state that immediately re-traps to HVF with the same syndrome.
- After ~1M of these traps HVF refuses with `HV_DENIED (0xfae94007)` instead of letting us keep running the vCPU. The application-visible error therefore flips between `guest did not exit after 1000000 traps` and `HV_DENIED` depending on how quickly the loop saturates.

Interpretation: the EL1 vector stub `hvc #0; eret` at offset `0x400` is not actually returning to the EL0 caller after the second HVC. The `X8 = 0x6473_5f4d` value strongly suggests user code is *not* the source of the second trap — either:

1. The `eret` is re-entering EL0 but at a stale PC where neighbouring memory happens to encode an `svc #0` (or another HVC); the user "PC" we see in ELR_EL1 reflects a runaway, not the originally intended return.
2. The HVF round-trip through HVC is clobbering some sysreg (`SPSR_EL1`, `ELR_EL1`, or `SP_EL0/EL1`) that the `eret` then consumes, so we never reach EL0 at all on the second iteration and instead loop inside EL1.
3. PC needs to be explicitly advanced past the `hvc #0` instruction on resume (i.e. `vcpu.set_reg(Reg::PC, pc + 4)` in `complete_syscall` when the trap class is `EC = 0x16`), because HVF surfaces HVC without auto-skipping it. Then the existing `eret` would actually run on resume.

Hypothesis (3) is the most concrete and most likely. The trace shows `pc=0x20404` consistently, which is *exactly* one instruction past `0x20400` (the HVC). If HVF surfaces HVC with PC pointing AT the HVC, our resume should fall through to PC+4 = `0x20404` = `eret`. If HVF instead surfaces with PC already at `0x20404` (post-HVC), then resuming runs the `eret`, which uses `SPSR_EL1`/`ELR_EL1` — and those still hold the values the EL0→EL1 SVC trap saved. But if the resume actually re-runs PC=0x20404 as the HVC (because HVF expects us to advance), we'd loop. The empirics fit pattern (3): we need to advance PC past the HVC on resume when the trap class is HVC.

### Next wall (predicted next move)

The smallest correct delta to unblock the next layer is:

- In `HvfTrapEngine::complete_syscall` (or in a new helper invoked from there), when the most recent exit was `EC = 0x16` (HVC, i.e. our EL1-vector route), advance `PC` by 4 before returning so the resumed vCPU executes the `eret` at vector offset `0x404`, not the `hvc #0` at `0x400` again. The direct EL0-SVC path (`EC = 0x15`) likely already has HVF auto-advance PC, which is why the existing tests pass. Track the most recent EC from `run_until_syscall` into the engine so `complete_syscall` can branch on it.

Once that lands, expect to immediately surface the *real* second syscall musl ld issues (likely `set_robust_list` (#99), `prlimit64` (#261), `mprotect` (#226), `mmap` (#222), `openat` (#56), `read` (#63), `getrandom` (#278), or `brk` (#214) depending on the musl version). That's compat-report territory, not bootstrap-cliff territory, and is what Tier B was originally supposed to be measuring.

### Reproduction

```bash
cargo build --release --bin carrick
codesign --force --sign - --entitlements scripts/entitlements.plist target/release/carrick
./target/release/carrick run \
  docker.io/library/alpine@sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0 \
  /bin/busybox echo hello
# expected today: "guest did not exit after 1000000 traps" (or HV_DENIED 0xfae94007 on faster machines)
# previously (before the hvf_perms fix): "guest exception is not an AArch64 SVC trap: syndrome=0x92000005, virtual_address=0xfffffeff40"
```

## Fourth attempt — musl startup loop (post HVC-PC-advance fix)

Date: 2026-05-18, after `src/trap.rs::HvfTrapEngine::complete_syscall` was already
extended to advance `PC` by 4 when the last exit class was `EC = 0x16` (HVC), and
after `RuntimeError::TrapLimitExceeded` was demoted from an `Err` into an
`Ok(RunResult { trap_limit_hit: true, .. })` so the compat report survives a
trap-budget cut-off.

### Setup

- `Commands::Run` now accepts `--max-traps` (it must precede the image/command,
  because the trailing-vararg `command: Vec<String>` would otherwise swallow
  `--max-traps 200`). Reproduce with:

  ```bash
  cargo build --release --bin carrick
  codesign --force --sign - --entitlements scripts/entitlements.plist \
    target/release/carrick
  CARRICK_TRACE_TRAPS=1 ./target/release/carrick run --max-traps 200 \
    docker.io/library/alpine@sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0 \
    /bin/busybox echo hello \
    > /tmp/busybox-200.json 2> /tmp/busybox-200.trace
  ```

- A one-line `eprintln!` in `run_combined_syscall_loop_with_dispatcher`
  (gated on the `CARRICK_TRACE_TRAPS` env var) records every syscall frame
  as it is observed by the dispatcher. Output goes to stderr; the JSON
  result still lands on stdout.

### What the JSON says (compat report, 200-trap budget)

```json
"summary": {
  "syscall_invocations": 200,
  "syscall_returns_ok": 1,
  "syscall_returns_errno": 199,
  "distinct_unhandled_syscalls": 1,
  "unhandled_syscall_invocations": 199,
  ...
},
"unhandled_syscalls": [
  { "count": 199, "name": "unknown", "number": 1685382482 }
],
"proc_read_unimplemented": [],
"sys_read_unimplemented": [],
"unhandled_ioctls": [],
"trap_limit_hit": true,
"traps": 200,
"exit_code": -1
```

Only **one** unhandled syscall number is observed (199 times). No
`/proc` / `/sys` reads, no ioctls, no partial syscalls. The CompatReport
is therefore not the diagnostic surface here — the trace is.

### What the trace says (first five distinct calls + loop body)

The trace has **exactly two** distinct events. Trap #1 is real, traps #2..#200
are byte-identical:

```
trap#1:   x8=96         (set_tid_address) x0=0x80000c2e80 x1=0x1     x2=0x8 x3=0x800009fb50 x4=0x0     x5=0x8000004554
trap#2:   x8=1685382482 (<unknown>)       x0=0x1000e0b10  x1=0x0     x2=0x4f0 x3=0xe0b10      x4=0xdc000 x5=0xfffffffffffff000
trap#3:   x8=1685382482 (<unknown>)       x0=0xffffffffffffffda x1=0x0 x2=0x4f0 x3=0xe0b10    x4=0xdc000 x5=0xfffffffffffff000
trap#4..#200: identical to trap#3.
```

Decoding `x8 = 1685382482 = 0x6473_5f4d`: that is ASCII `"M_sd"` in
little-endian bytes (`4d 5f 73 64`). It is not a Linux/aarch64 syscall
number (the largest valid one is < 500). So trap #2 onward is not a real
syscall: the guest's `X8` at the moment we observe it is a snapshot of
musl-`ldso` *data* (a half-word fragment of an ELF/auxv string or a
relocation slot), not a syscall number.

The key signal is `x0` between trap #2 and trap #3:

- **trap #2**: `x0 = 0x1_000e_0b10` (whatever musl had in `x0` at the
  faulting instruction).
- **trap #3..#200**: `x0 = 0xffff_ffff_ffff_ffda`, i.e. `(i64)-38`, which
  is exactly the value `complete_syscall` just wrote in response to
  `Errno { errno: ENOSYS (38) }`.

So between trap #2 and trap #3 the only thing that demonstrably changed in
the guest is the value we wrote into `X0`. `x1..x5, x8`, and the trap class
are all bit-for-bit identical. The vCPU is **not** advancing past whatever
instruction produced trap #2 — it re-enters with the same architectural
state we last saw, plus our return value clobbered into `X0`.

The loop is first detectable at **trap #2** (i.e. one trap after the first
real syscall). The compat report's 199 identical "unknown" entries are
just N copies of the same stuck instruction; they are not 199 distinct
musl decisions.

### Best guess at root cause

This is exactly the failure mode predicted in the "Third attempt — next
wall" section, but the predicted fix is *already* present in
`src/trap.rs::HvfTrapEngine::complete_syscall` (it advances `PC += 4`
when `last_exit_class == AARCH64_HVC_EXCEPTION_CLASS`). The loop persists
despite that, so the PC-advance is either being applied to the wrong
program counter or being applied at the wrong instant. Three concrete
hypotheses, in declining order of likelihood:

1. **HVF already auto-advances `PC` past `HVC`, so our `+4` skips the
   `eret` and lands in the per-slot `nop` fill.** The Third-attempt
   trace recorded `pc=0x20404` at HVC entry — that is `vector_base +
   0x400 + 4`, i.e. one instruction past the `hvc #0` at `0x20400`,
   which is the address of the `eret`. If HVF surfaces that PC because
   it has already retired the HVC, then `complete_syscall` adds another
   `4` → `0x20408`, which is inside the `nop` pad that `el1_vectors_bytes`
   writes after `eret`. The vCPU then runs `nop`s until it reaches the
   next vector slot (`0x20480` = "Lower EL using AArch64, IRQ"), which
   is a bare `eret`. That `eret` consumes the **stale** `SPSR_EL1` /
   `ELR_EL1` from the original `set_tid_address` SVC (they were never
   updated, because no real EL0→EL1 transition occurred on the runaway
   path), drops back into EL0 at a stale PC, and the user code at that
   stale PC happens to re-trigger the same trampoline path on its next
   instruction — re-presenting the SAME `X8`/`X1..X5`. This is
   consistent with `x1..x5,x8` being byte-identical across iterations.

2. **`set_reg(PC, …)` is writing the wrong register from HVF's point
   of view.** On Apple HVF, the vCPU has both an `EL0_PC` (the saved
   user PC) and the current EL1 PC; `Reg::PC` may select the EL1 PC at
   the point of trap, which is unrelated to the EL0 user PC. Advancing
   it has no observable effect on the `eret`. The frozen `x1..x5,x8`
   then come from a runaway EL0 that's re-issuing the same syscall path.

3. **`last_exit_class` is being set from the wrong syndrome.** Looking
   at `run_until_syscall`, `last_exit_class` is updated from the
   exception that just arrived. If the first SVC arrives as `EC = 0x16`
   (because the EL1 vector stub re-traps via `hvc #0`), then the
   PC-advance path *is* exercised on trap #1. But if the very first
   exception that HVF reports is in fact `EC = 0x15` (direct SVC, with
   HVF auto-advance), `last_exit_class` would be `0x15`, and
   `complete_syscall` would skip the advance, leaving us re-entering at
   PC=PC-of-HVC and looping. The brief's existing description of trap #1
   ("EC=0x16 pc=0x20404") makes (1) more likely than (3), but both are
   worth ruling out before touching the vector stub.

Hypothesis (1) fits the data best: the `+4` is being applied on top of
an already-advanced PC. The simplest empirical test is to either drop
the `+4` (and see whether things instead get stuck *at* the HVC),
or to read `PC` from HVF after the trap and compare to the known HVC
address `LINUX_EL1_VECTORS_BASE + AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET`
(`0x20400`) — if HVF reports `0x20404`, hypothesis (1) is confirmed
and the right fix is *not* to advance PC at all on `EC = 0x16`.

### Smallest concrete fix that would advance the demo

Before changing any code: **add one more piece of evidence**. Extend
the existing trace `eprintln!` (or add a sibling print inside
`HvfInner::run_until_syscall`) to also log `pc`, `elr_el1`, and
`spsr_el1` on every trap. Re-run with `--max-traps 4`. Then:

- If `pc` on trap entry is `0x20404` (one past the HVC), **remove
  the `PC += 4` advance from `complete_syscall`** — HVF is
  already advancing it, and our extra `+4` skips the `eret`. (Smallest
  delta: gate the advance behind an explicit "HVF did not advance"
  detection, or just drop the conditional entirely if the assumption
  holds across all trap classes on this HVF version.)

- If `pc` is `0x20400` (at the HVC) and `elr_el1` / `spsr_el1` are
  frozen across iterations, the `eret` itself isn't running — most
  likely because the user-side PSTATE in `SPSR_EL1` is corrupt
  (e.g. EL1h instead of EL0t). Fix by checking `SPSR_EL1` in
  `complete_syscall` and forcing the user-mode bits if they got
  clobbered, OR by switching the vector stub from `hvc #0; eret` to
  an explicit "restore SPSR/ELR/SP_EL0 from per-thread save area, then
  eret" sequence (which is what real kernels do, and what `ldso`
  expects on syscall return).

- If `elr_el1` changes per iteration but `x1..x5,x8` don't, the user
  is running but not making progress because the syscall return path
  is leaving the call site unchanged — most likely because we're
  failing to update `SP_EL0` or the user-side return PC after our
  HVC trap. This would point at adding `SP_EL0` / `ELR_EL1` plumbing
  to `complete_syscall`.

The minimum-viable fix is therefore: **add a four-line diagnostic dump
of (`pc`, `elr_el1`, `spsr_el1`, `sp_el0`) at trap entry**, run
`--max-traps 4` once, then pick exactly one of the three branches
above. Each branch is a five-to-ten-line edit in `src/trap.rs`; none
require new dependencies, new mappings, or syscall-dispatch changes.

Once the loop breaks, expect to immediately surface a real second
syscall from `_dlstart` — almost certainly one of
`set_robust_list` (#99), `rseq` (#293), `prlimit64` (#261),
`mprotect` (#226), `mmap` (#222), `openat` (#56), or `getrandom`
(#278). At that point the compat report becomes the right diagnostic
surface and Tier B has reached "running musl, missing syscall X."

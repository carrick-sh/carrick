# Carrick × Rosetta 2: x86_64 Container Support

Running an unmodified `linux/amd64` container on Apple Silicon via carrick, using Apple's
Rosetta 2 translation layer as a guest-space JIT — with no Linux VM, no FUSE daemon, and
no binfmt_misc kernel module.

---

## Implementation status (2026-05-26, branch `feat/rosetta-amd64`)

The full plan below is **implemented**, plus the MMU/procfs/vDSO groundwork the plan did
not anticipate. Under carrick, Apple's Rosetta interpreter now **loads and runs its entire
initialisation** for `carrick run --platform linux/amd64 …`: it passes the licensing `ioctl`
handshake, enables hardware TSO, opens `/proc/self/exe`, parses the vDSO, reads
`mmap_min_addr`, and executes ~13 syscalls successfully before the one remaining gap.

**Corrections to the plan, verified against the real binary/crate (the plan's guesses were wrong):**
- `ACTLR_EL1 = 0xc081` (not `0x6021`), gated behind applevisor feature `macos-15-0` (bumped from `macos-13-0`).
- The TSO enable bit is `ACTLR_EL1.EnTSO` = **bit 1**, not bit 0.
- `prctl PR_SET_MEM_MODEL = 0x4d4d444c` / `PR_GET_MEM_MODEL = 0x6d4d444c` (the Asahi/Apple
  "MMDL" magic values — *not* 70/71, which collide with upstream `PR_RISCV_V_*`). Confirmed by
  disassembling rosetta (`mov w0,#0x444c; movk w0,#0x4d4d`).
- Handshake `ioctl`s observed: `0x80456125` (licence, size 69) and `0x80806123` (info, size 128).
  The licence response is the verification blob Rosetta `memcmp`s against its **own embedded
  copy**, so carrick reads it **live from the installed Rosetta binary** rather than embedding
  Apple's string. The info ioctl just needs a non-negative return.
- Image cache is now **per-platform** (arm64/amd64 no longer collide in the store).

**Additional groundwork (not in the plan):**
- HVF max IPA on M-series is **40 bits**, but Rosetta is a non-relocatable `ET_EXEC` fixed-linked
  at **2^47**. Widened guest VA to 48-bit (`TCR_EL1.T0SZ` 24→16) and added a **non-identity
  page-table alias** that maps Rosetta's 2 MiB image window down to a low IPA (the IPA output
  stays within 40 bits — mirrors how Apple's own Virtualization.framework uses the guest
  kernel's page tables). `MemoryRegion`/`GuestMapping`/`HvfMappedRegion`/`ForkMappingDesc` now
  carry a distinct `ipa` (identity for every region except this alias).
- vDSO now emits a real section-header table (`SHT_DYNSYM`) so strict parsers like Rosetta
  resolve it (glibc/Go use `PT_DYNAMIC` and never needed sections). Generic improvement.
- `open("/proc/self/exe")` (+ thread-self/curproc aliases) now resolves to the executable —
  generic for every guest. `/proc/sys/vm/mmap_min_addr` synthesised.

**Licensing safeguards:** opt-in (`--platform`), zero Apple bytes bundled (everything is read
from the user's own install at runtime), `CARRICK_ACCEPT_ROSETTA_TERMS=1` accepts the macOS SLA
responsibility and silences the per-run notice.

### The general VA split — DONE

The general high-VA→low-IPA mmap subsystem is implemented (it was the deferred follow-up).
A guest `mmap` at a VA ≥ 1 TiB (HVF's IPA ceiling) is routed to a low alias arena via
`DispatchOutcome::MapHostAlias` → `HvfTrapEngine::map_host_alias`, which `hv_vm_map`s anon
memory at the reserved IPA, builds a fresh VA→IPA stage-1 path
(`PageTableManager::map_aliased`, 2 MiB blocks or 4 KiB pages), copies in the file payload for
file-backed maps, and registers the region (VA-keyed for syscall access). Only high-VA mmaps
take this path, so normal guests are unaffected. With it, Rosetta's 256 MiB anonymous
translation arena at 240 TiB **and** its file-backed maps are all backed.

### Current frontier — TTBR1 / x86-64 high-half addresses

`carrick run --platform linux/amd64 --fs host alpine:latest /bin/uname -m` now runs **~30
Rosetta init syscalls**: licence handshake, hardware TSO, both high-VA reservations (incl. the
256 MiB arena at 240 TiB), AOT cache-dir creation, ELF-header reads, `/proc/self/{exe,fd,maps}`,
`/proc/sys/vm/mmap_min_addr`, signal setup. It opens the real busybox ELF (Alpine's `/bin/uname`
→ `/bin/busybox`, now that `openat` follows symlinks), `fstat`s it, then:

> `mmap(0xfffffffffff3a000, 0xc4708, PROT_READ, MAP_PRIVATE|MAP_FIXED_NOREPLACE, busybox_fd)`

`0xfffffffffff3a000` is `-0xc6000` — an **x86-64-canonical *high-half* (negative) address**
(bits 63:48 all set). Rosetta maps the translated binary into the upper VA half, as x86-64
kernels lay out the negative address space. carrick's guest is configured **TTBR0-only**
(`TCR_EL1.EPD1 = 1`, lower 48-bit half), so there is no upper-half translation and the address
is untranslatable. carrick returns EEXIST for the `MAP_FIXED_NOREPLACE`; Rosetta then aborts
with `unable to mmap ELF: 17`.

**Next architectural step: TTBR1 / upper-half support.** Enable `TTBR1_EL1` (`EPD1 = 0`,
`T1SZ`), give it a stage-1 table root, and alias upper-half guest VAs (`0xffff_…`) down to the
low IPA arena (the same `MapHostAlias` mechanism, but driven from the TTBR1 walk). Then the
guest-fault and software-access paths must accept upper-half VAs. After that comes the AOT
cache round-trip and the actual x86→AArch64 JIT execution (the first real translated
instructions + the final `write(1, "x86_64\n")`).

Reproduce: `CARRICK_ACCEPT_ROSETTA_TERMS=1 carrick run --platform linux/amd64 --fs host alpine:latest /bin/uname -m`
(trace with `carrick trace --script scripts/rosetta-open.d -- run --platform linux/amd64 …`, or
`CARRICK_TRACE_TRAPS=1` for the raw per-syscall stream).

---

## Background and Execution Model

Carrick executes Linux user-space binaries as native macOS threads. The guest runs at EL0
inside a Hypervisor.framework vCPU; system calls are trapped at EL1 and serviced by carrick's
syscall dispatcher (`SyscallDispatcher`). The dispatcher never touches the host kernel's ABI —
it is pure user-space emulation of the Linux syscall interface.

Apple's Rosetta 2 ships an AArch64 binary,
`/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta`, that is purpose-built for exactly this
environment. It operates as a Linux ELF interpreter: when launched with an x86_64 binary as
its argument, it JIT-compiles x86_64 instructions to AArch64 and emulates the x86_64 user-space
ABI entirely in guest space. Crucially:

- **Syscalls** are translated by Rosetta's JIT before they reach the guest EL1 boundary.
  x86_64 syscall numbers are rewritten to their AArch64 equivalents in the emitted AArch64
  code. Carrick's dispatcher always sees AArch64 syscall numbers — it never needs to know or
  care that the original application was x86_64.
- **Memory ordering** — x86_64 uses TSO (Total Store Ordering); AArch64 uses a relaxed model.
  Rosetta requests hardware TSO emulation via `prctl(PR_SET_MEM_MODEL, PR_SET_MEM_MODEL_TSO)`.
  On M-series Apple Silicon, bit 0 of the per-vCPU `ACTLR_EL1` register enables hardware-
  accelerated x86_64 memory ordering.
- **Verification** — Rosetta performs a one-time licensing check by issuing specific `ioctl`
  codes on `/proc/self/exe`. The kernel (or, in our case, carrick's dispatcher) must respond
  with a specific byte string for Rosetta to proceed.

The integration therefore has five discrete concerns:

1. Propagating the `--platform linux/amd64` intent from CLI → image pull → runtime
2. Redirecting the **initial** ELF load to Rosetta instead of failing on EM_X86_64
3. Redirecting **mid-guest `execve`** calls that load further x86_64 binaries
4. Servicing Rosetta's licensing `ioctl` handshake
5. Servicing Rosetta's `prctl` memory-model request by toggling `ACTLR_EL1`

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  macOS host (Apple Silicon)                                  │
│                                                              │
│  carrick-cli                                                 │
│    --platform linux/amd64  ──►  CliRunRequest.platform       │
│                                        │                     │
│  carrick-engine                        ▼                     │
│    ImageStore::resolve(amd64) ──► amd64 OCI layers           │
│    resolve_run_spec()         ──► RunSpec { platform: Amd64 }│
│                                        │                     │
│  carrick-runtime / execute.rs          ▼                     │
│    extract layers                                            │
│    install Rosetta bind mounts  ◄── platform == Amd64        │
│    run_elf_from_dispatcher_debug()                           │
│          │                                                   │
│          │  bytes = read(entrypoint)  ← e.g. /bin/sh        │
│          │  inspect_elf_bytes() → Machine::X86_64            │
│          │  rosetta_redirect()  ──► load Rosetta AArch64     │
│          ▼                          rewrite argv             │
│  ┌──────────────────────────────────────────────────┐        │
│  │  HVF vCPU (EL0)                                  │        │
│  │                                                  │        │
│  │  Rosetta AArch64 JIT                             │        │
│  │    ioctl(fd, 0x80456125, ...) ──► dispatcher     │        │
│  │        ◄── "Our hard work..." haiku              │        │
│  │    prctl(71, 1) ──► dispatcher                   │        │
│  │        ◄── SetMemoryModel{tso:true}              │        │
│  │                   │                              │        │
│  │                   ▼                              │        │
│  │  HvfTrapEngine::enable_hardware_tso()            │        │
│  │    ACTLR_EL1 |= 1                               │        │
│  │                                                  │        │
│  │  x86_64 guest binary (JIT translated)            │        │
│  │    syscall (x86_64) ──► Rosetta rewrites ──►    │        │
│  │    svc #0 (AArch64) ──► carrick dispatcher       │        │
│  └──────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

---

## Component-by-Component Implementation

### 1. carrick-spec: `Platform` type

A new shared enum needs to be the canonical representation of the target architecture. It
belongs in `carrick-spec` alongside `RunSpec`, `FsBackendKind`, etc., so every crate in the
workspace shares the same definition.

#### [NEW] `Platform` enum

```rust
/// The instruction-set architecture of the Linux container to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// AArch64 / arm64 — native on Apple Silicon. Default.
    #[default]
    Aarch64,
    /// x86_64 / amd64 — translated via Apple Rosetta 2.
    Amd64,
}

impl Platform {
    /// Parse from OCI platform strings: "linux/amd64", "linux/arm64", etc.
    pub fn from_oci_str(s: &str) -> Option<Self> {
        match s {
            "linux/amd64" | "linux/x86_64" => Some(Self::Amd64),
            "linux/arm64" | "linux/aarch64" => Some(Self::Aarch64),
            _ => None,
        }
    }
}
```

#### [MODIFY] `RunSpec`

Add `pub platform: Platform` (defaults to `Platform::Aarch64`). `RunSpec` is the boundary
object between engine and runtime — everything downstream reads it from here.

---

### 2. carrick-cli: `--platform` flag

#### [MODIFY] [args.rs](file:///Volumes/CaseSensitive/carrick/crates/carrick-cli/src/args.rs)

Add `--platform` to the `Run`, `Shell`, and `Pull` subcommands:

```diff
 Run {
     image: String,
+    /// Target platform, e.g. linux/amd64 or linux/arm64.
+    /// Selects the OCI manifest entry and enables Rosetta translation for amd64.
+    #[arg(long, value_name = "OS/ARCH")]
+    platform: Option<String>,
     #[arg(long, default_value_t = DEFAULT_MAX_TRAPS)]
     max_traps: usize,
```

#### [MODIFY] [commands.rs](file:///Volumes/CaseSensitive/carrick/crates/carrick-cli/src/commands.rs)

Pass `platform` into `CliRunRequest` directly. Do **not** use `std::env::set_var` — that is
process-global, not thread-safe, and deprecated in Rust 2024:

```rust
Commands::Run { image, platform, max_traps, .. } => {
    let req = CliRunRequest {
        image_ref: image.clone(),
        platform: platform.clone(),
        // ... rest of fields
    };
    engine.run(req).await
}
```

---

### 3. carrick-engine: Platform threading

#### [MODIFY] `CliRunRequest`

```diff
 pub struct CliRunRequest {
     pub image_ref: String,
+    pub platform: Option<String>,   // raw OCI string from CLI
     pub args: Vec<String>,
     // ...
 }
```

#### [MODIFY] [lib.rs — `resolve_run_spec`](file:///Volumes/CaseSensitive/carrick/crates/carrick-engine/src/lib.rs#L31-L135)

Parse and propagate the platform:

```rust
let platform = req.platform
    .as_deref()
    .and_then(Platform::from_oci_str)
    .unwrap_or_default();

// Pass to image resolution (selects correct OCI manifest)
let image_ref = carrick_spec::ImageReference::parse_with_platform(
    &req.image_ref, platform
)?;

// ... (rest of resolve_run_spec) ...

RunSpec {
    platform,
    // ... other fields
}
```

> [!IMPORTANT]
> **Open Question:** How does `carrick-image`'s `ImageStore::resolve()` currently handle
> multi-arch OCI image indexes? Does it select the host-native manifest automatically? We need
> to confirm it accepts a platform hint to pull the `linux/amd64` variant of a multi-arch image,
> and extend the API if it does not.

---

### 4. carrick-runtime/execute.rs: Rosetta bind mounts

When the platform is `Amd64`, Rosetta needs its host runtime files visible inside the guest
VFS. These files live on the host Mac, not in the OCI image layers. Both filesystem backend
paths in [execute.rs](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/execute.rs#L19) need this:

#### [MODIFY] execute.rs — after layer extraction, before `run_elf_from_dispatcher_debug`

```rust
// For amd64 containers, bind-mount the Rosetta runtime into the guest VFS.
// Rosetta opens these paths at startup to load its AOT cache and runtime
// support libraries. They do not exist in the OCI image.
if spec.platform == Platform::Amd64 {
    dispatcher.install_bind_mount(
        "/Library/Apple/usr/libexec/oah",  // host source
        "/Library/Apple/usr/libexec/oah",  // same path in guest
        true,                              // read-only
    );
    // Rosetta may write JIT caches here; must be writable.
    dispatcher.install_bind_mount(
        "/var/db/oah",
        "/var/db/oah",
        false,
    );
}
```

Apply this to **both** the `FsBackendKind::Host` branch (around line 38) and the
`FsBackendKind::Memory` branch (around line 120).

---

### 5. carrick-runtime/runtime.rs: Rosetta ELF redirection

This is the heart of the integration. There are **three distinct call sites** where an ELF
binary is loaded, and all three must redirect x86_64 binaries to Rosetta.

#### The shared helper

```rust
/// Inspects raw ELF bytes. If they describe an x86_64 binary, rewrites the
/// load as: load Rosetta, with argv = ["rosetta", "<target>", original_args...].
///
/// Returns:
///   None        — binary is AArch64 (or unknown); caller proceeds normally.
///   Some(Ok(_)) — binary is x86_64; returns (rosetta_bytes, new_argv).
///   Some(Err(e))— binary is x86_64 but Rosetta binary not readable; errno.
fn maybe_redirect_to_rosetta(
    target_path: &str,
    target_bytes: &[u8],
    argv: Vec<String>,
) -> Option<Result<(Vec<u8>, Vec<String>), i32>> {
    use crate::elf::{inspect_elf_bytes, Machine};
    use crate::linux_abi::LINUX_ENOENT;

    let meta = inspect_elf_bytes(target_bytes).ok()?;
    if meta.machine != Machine::X86_64 {
        return None;
    }

    const ROSETTA: &str = "/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta";
    let rosetta_bytes = match std::fs::read(ROSETTA) {
        Ok(b) => b,
        Err(_) => return Some(Err(LINUX_ENOENT)),
    };

    // Rewrite argv to match the Linux binfmt_misc interpreter calling convention:
    //   argv[0] = path to interpreter (Rosetta)
    //   argv[1] = path to x86_64 binary (the original target)
    //   argv[2..] = original arguments (skip original argv[0])
    let mut new_argv = Vec::with_capacity(argv.len() + 1);
    new_argv.push(ROSETTA.to_string());
    new_argv.push(target_path.to_string());
    new_argv.extend(argv.into_iter().skip(1));

    Some(Ok((rosetta_bytes, new_argv)))
}
```

#### Call site 1: Initial load — Host FS backend

[`run_elf_from_dispatcher_debug`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L356-L388)
currently reads the binary via `dispatcher.read_exec_file(path)` and immediately passes it
to `AddressSpace::load_elf_bytes_with_reader`, which calls `plan_elf_load_bytes` and rejects
non-AArch64. Insert the check before that call:

```rust
pub fn run_elf_from_dispatcher_debug<A, E>(
    path: &str,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let argv: Vec<String> = argv.into_iter().collect();
    let env: Vec<String> = env.into_iter().collect();

    let bytes = dispatcher.read_exec_file(path)
        .ok_or_else(|| RuntimeError::io("executable not found"))?;

    // Redirect x86_64 binaries through Rosetta.
    let (load_bytes, argv) = match maybe_redirect_to_rosetta(path, &bytes, argv) {
        None => (bytes, argv),
        Some(Ok((rosetta_bytes, new_argv))) => (rosetta_bytes, new_argv),
        Some(Err(errno)) => return Err(RuntimeError::from_errno(errno)),
    };

    // Rosetta is an AArch64 binary; this now succeeds.
    let image = AddressSpace::load_elf_bytes_with_reader(&load_bytes, &|p| {
        dispatcher.read_exec_file(p)
    })?;
    // ... (rest of function: with_el0_trampoline, stack, etc.)
}
```

#### Call site 2: Initial load — Memory FS backend

[`run_rootfs_elf_with_hvf_args_and_dispatcher_debug`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L322-L349)
uses `AddressSpace::load_elf_from_rootfs(path, rootfs)`. Same pattern:

```rust
let bytes = rootfs.read_file(path)
    .ok_or_else(|| RuntimeError::io("executable not found"))?;

let (load_bytes, argv) = match maybe_redirect_to_rosetta(path, &bytes, argv) {
    None => (bytes, argv),
    Some(Ok((rosetta_bytes, new_argv))) => (rosetta_bytes, new_argv),
    Some(Err(errno)) => return Err(RuntimeError::from_errno(errno)),
};

// Rosetta is an AArch64 binary; read its interpreter from the host.
let image = AddressSpace::load_elf_bytes_with_reader(&load_bytes, &|p| {
    // Rosetta's PT_INTERP (if any) comes from the host, not the rootfs.
    std::fs::read(p).ok()
})?;
```

#### Call site 3: Mid-guest `execve`

[`load_execve_image`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L2008-L2070)
handles shebang resolution then loads the final ELF via `dispatcher.read_exec_file`. Insert
after shebang resolution, before the `AddressSpace::load_elf_bytes_with_reader` call:

```rust
let raw_bytes = dispatcher.read_exec_file(&path).ok_or(LINUX_ENOENT)?;

let (load_bytes, argv) = match maybe_redirect_to_rosetta(&path, &raw_bytes, argv) {
    None => (raw_bytes, argv),
    Some(Ok((rosetta_bytes, new_argv))) => (rosetta_bytes, new_argv),
    Some(Err(errno)) => return Err(errno),
};

let raw = AddressSpace::load_elf_bytes_with_reader(&load_bytes, &|p| {
    dispatcher.read_exec_file(p)
}).map_err(|_| LINUX_ENOENT)?;
```

---

### 6. dispatch/fs.rs: Rosetta ioctl handshake

Rosetta performs a one-time licensing verification by calling `ioctl` on its own file
descriptor (typically the fd for `/proc/self/exe`) with one of three specific request codes.
The kernel (or here, carrick's dispatcher) must write a specific string into the caller's
buffer.

The [ioctl handler](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/fs.rs#L2220)
starts with an fd validity check, then enters PTY handling. The Rosetta intercept goes
**between** those two:

#### [MODIFY] fs.rs — inside `fn ioctl`

```rust
fn ioctl(this, cx, fd: Fd, request: u64, arg: u64) {
    let fd: Fd = fd;
    let ioctl_request = request;
    let arg = arg;

    if !this.fd_is_valid(fd.0) {
        return Ok(LINUX_EBADF.into());
    }

    // ── Rosetta 2 Virtualization Handshake ────────────────────────────────
    // Rosetta issues one of these ioctl codes on /proc/self/exe during startup
    // to verify it is running inside an Apple virtualisation environment.
    // The ioctl code encodes the size of the expected response in bits [29:16].
    // We must write Apple's verification string to the guest buffer at `arg`.
    const ROSETTA_IOCTLS: [u64; 3] = [0x80456122, 0x80456125, 0x80806123];
    if ROSETTA_IOCTLS.contains(&ioctl_request) {
        const HAIKU: &[u8] = b"Our hard work by these words guarded, \
            please don't steal (c) Apple Computer Inc\0";
        // The size field in the ioctl number tells us how many bytes the guest
        // expects; honour it to avoid overrunning the caller's buffer.
        let expected_size = ((ioctl_request >> 16) & 0x3fff) as usize;
        let payload = if expected_size > 0 && expected_size < HAIKU.len() {
            &HAIKU[..expected_size]
        } else {
            HAIKU
        };
        if cx.memory.write_bytes(arg, payload).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
        return Ok(DispatchOutcome::Returned { value: 0 });
    }

    // ── PTY ioctls ───────────────────────────────────────────────────────
    if let Some((role, host_fd)) = this.pty_info(fd.0) {
        // ... existing PTY code unchanged ...
```

---

### 7. dispatch/mod.rs: New `DispatchOutcome` variant

The syscall dispatcher communicates back to the runtime loop exclusively through the
`DispatchOutcome` return value. The dispatcher has no access to the `HvfTrapEngine` or any
vCPU register — that is by design. To trigger a system register write from a `prctl` handler,
we need a new outcome variant:

#### [MODIFY] [dispatch/mod.rs](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/mod.rs#L486)

```diff
+    /// Request the runtime to toggle hardware x86_64 memory ordering (TSO)
+    /// on the active vCPU via ACTLR_EL1. The prctl return value is always 0.
+    SetMemoryModel { tso: bool },
```

This is safe to add alongside the existing variants (`Fork`, `Execve`, `SigReturn`, etc.).

---

### 8. dispatch/proc.rs: `prctl` — memory model arms

#### [MODIFY] `ProcState`

Add TSO tracking so `PR_GET_MEM_MODEL` (prctl 70) can return the correct current value:

```diff
 pub(super) struct ProcState {
     pub executable: String,
     pub personality: u64,
     pub dumpable: u8,
     pub comm: [u8; 16],
     pub pdeathsig: u64,
+    /// Whether hardware TSO (x86_64 memory ordering) is active for this vCPU.
+    pub tso_enabled: bool,
 }
```

#### [MODIFY] [proc.rs — `prctl` handler](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/proc.rs#L319)

Add two new match arms before the `_ => LINUX_EINVAL` fallthrough:

```rust
// PR_GET_MEM_MODEL — query current memory ordering mode
// 0 = default (relaxed AArch64), 1 = TSO (x86_64 compatible)
70 => {
    let model = if this.proc.lock().tso_enabled { 1i64 } else { 0i64 };
    DispatchOutcome::Returned { value: model }
}

// PR_SET_MEM_MODEL — request a memory ordering mode change.
// We return SetMemoryModel; the runtime loop writes ACTLR_EL1 on the active
// vCPU thread. The dispatcher itself cannot reach the vCPU.
71 => match arg2 {
    0 => { // PR_SET_MEM_MODEL_DEFAULT
        this.proc.lock().tso_enabled = false;
        DispatchOutcome::SetMemoryModel { tso: false }
    }
    1 => { // PR_SET_MEM_MODEL_TSO
        this.proc.lock().tso_enabled = true;
        DispatchOutcome::SetMemoryModel { tso: true }
    }
    _ => DispatchOutcome::errno(LINUX_EINVAL),
},
```

---

### 9. trap.rs: `enable_hardware_tso` / `disable_hardware_tso`

`ACTLR_EL1` is a per-vCPU implementation-defined register. On Apple Silicon M-series chips,
bit 0 (TSOEN) enables x86_64 TSO memory ordering. This must be toggled on the **active vCPU
thread** at the moment the prctl fires, not at vCPU initialisation time.

> [!IMPORTANT]
> **Pre-implementation check required:** Confirm whether `applevisor::SysReg::ACTLR_EL1`
> exists in the crate at the project-pinned version. If not, use the raw FFI path already
> established in trap.rs (L277) for `CNTKCTL_EL1` as a precedent:
> `applevisor_sys::hv_vcpu_set_sys_reg(handle, hv_sys_reg_t::HV_SYS_REG_ACTLR_EL1, val)`

#### [MODIFY] [trap.rs](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/trap.rs)

```rust
impl HvfTrapEngine {
    /// Enable hardware x86_64 TSO memory ordering on this vCPU.
    /// Sets ACTLR_EL1[0] (TSOEN = 1).
    pub fn enable_hardware_tso(&mut self) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        let actlr = self.inner.vcpu
            .get_sys_reg(SysReg::ACTLR_EL1)
            .map_err(hvf_error)?;
        self.inner.vcpu
            .set_sys_reg(SysReg::ACTLR_EL1, actlr | 1)
            .map_err(hvf_error)?;
        Ok(())
    }

    /// Restore default AArch64 relaxed memory ordering on this vCPU.
    /// Clears ACTLR_EL1[0] (TSOEN = 0).
    pub fn disable_hardware_tso(&mut self) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        let actlr = self.inner.vcpu
            .get_sys_reg(SysReg::ACTLR_EL1)
            .map_err(hvf_error)?;
        self.inner.vcpu
            .set_sys_reg(SysReg::ACTLR_EL1, actlr & !1)
            .map_err(hvf_error)?;
        Ok(())
    }
}
```

---

### 10. runtime.rs: Handle `SetMemoryModel` in every runtime loop

There are three runtime dispatch loops that match on `DispatchOutcome`:

- Single-threaded combined loop (~L561, `run_combined_syscall_loop`)
- Split loop (~L2273, `run_split_loop`)
- Multi-threaded loop (~L1203, `ThreadRuntimeState::handle_execve`)

Each must gain a `SetMemoryModel` arm. The pattern is identical in all three:

```rust
DispatchOutcome::SetMemoryModel { tso } => {
    if tso {
        trap.enable_hardware_tso()?;
    } else {
        trap.disable_hardware_tso()?;
    }
    trap.complete_syscall(0)?;
}
```

---

## Data Flow Summary

```
carrick-cli
  --platform linux/amd64
       │
       ▼ CliRunRequest { platform: Some("linux/amd64") }
carrick-engine / lib.rs
  Platform::from_oci_str("linux/amd64") → Platform::Amd64
  ImageStore::resolve(image_ref, amd64)  ← pulls amd64 manifest
       │
       ▼ RunSpec { platform: Platform::Amd64, rootfs_layers: [...] }
carrick-runtime / execute.rs
  extract layers
  install Rosetta bind mounts  ← /Library/Apple/usr/libexec/oah, /var/db/oah
  run_elf_from_dispatcher_debug("/bin/sh", ...)
       │
       │ read("/bin/sh") → bytes
       │ inspect_elf_bytes → Machine::X86_64
       │ maybe_redirect_to_rosetta
       │   → load_bytes = rosetta AArch64 binary
       │   → new_argv = ["rosetta", "/bin/sh", ...]
       ▼
  AddressSpace::load_elf_bytes_with_reader(rosetta_bytes)  ← AArch64, succeeds
  run_address_space_with_hvf_and_dispatcher
  run_threaded_hvf_loop
       │
       │  [guest runs: Rosetta AArch64 code]
       │
       │  ioctl(fd, 0x80456125, buf_ptr)
       ▼
  dispatcher.dispatch → ioctl handler
    ROSETTA_IOCTLS match → write haiku to buf_ptr
    → DispatchOutcome::Returned { value: 0 }
       │
       │  prctl(71, 1)  [PR_SET_MEM_MODEL_TSO]
       ▼
  dispatcher.dispatch → prctl handler
    arm 71 → tso_enabled = true
    → DispatchOutcome::SetMemoryModel { tso: true }
       │
       ▼
  runtime loop matches SetMemoryModel
    trap.enable_hardware_tso()  → ACTLR_EL1 |= 1
    trap.complete_syscall(0)
       │
       │  [Rosetta JIT-compiles x86_64 binary, emits AArch64]
       │  [x86_64 syscall → Rosetta rewrites to AArch64 number]
       │  svc #0 (AArch64 syscall)
       ▼
  dispatcher.dispatch → normal AArch64 syscall handler
```

---

## Open Questions

> [!IMPORTANT]
> **Q1: `applevisor` crate ACTLR_EL1 support.**
> Run `cargo doc -p applevisor -p applevisor_sys` and check whether `SysReg::ACTLR_EL1` or
> `hv_sys_reg_t::HV_SYS_REG_ACTLR_EL1` is present. If neither exists at the crate's current
> version, we either add the raw `u32` constant (`0x6021`, the encoding for ACTLR_EL1 in
> Apple's HV framework) or bump the crate version.

> [!IMPORTANT]
> **Q2: `/proc/self/exe` in carrick's procfs emulation.**
> Rosetta opens `/proc/self/exe` to obtain the fd on which it calls the handshake ioctl. What
> does carrick's dispatcher currently return for this path? It should return a readable fd whose
> identity is the **Rosetta binary** (since that is what is actually loaded). If it returns the
> original x86_64 binary path, the ioctl will arrive on a different fd than Rosetta expects.
> This needs to be confirmed before implementing the ioctl intercept.

> [!IMPORTANT]
> **Q3: `carrick-image` multi-arch support.**
> Does `ImageStore::resolve()` today select the native-arch manifest from an OCI image index?
> Can it accept a platform override to pull `linux/amd64`? The engine integration in Phase 3
> depends entirely on this API, and it may require changes to `carrick-image` as well.

> [!NOTE]
> **Q4: Rosetta static vs dynamic linking.**
> Confirm that `/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta` has no `PT_INTERP`
> (i.e. it is statically linked or self-contained). If it has an interpreter, we need to
> ensure that interpreter path also exists on the host and is accessible via `read_exec_file`.
> Run: `file /Library/Apple/usr/libexec/oah/RosettaLinux/rosetta`

---

## Implementation Phases and Order

| Phase | Scope | Dependency |
|-------|-------|------------|
| 0 | Confirm prerequisites (Q1–Q4 above) | None |
| 1 | `carrick-spec`: Add `Platform` enum + `RunSpec.platform` | None |
| 2 | `carrick-cli`: Add `--platform` flag | Phase 1 |
| 3 | `carrick-engine`: Thread `platform` through `resolve_run_spec` | Phase 1, Q3 |
| 4 | `carrick-runtime/execute.rs`: Rosetta bind mounts | Phase 1 |
| 5 | `carrick-runtime/runtime.rs`: `maybe_redirect_to_rosetta` + 3 call sites | Phase 1 |
| 6 | `dispatch/fs.rs`: ioctl handshake | Q2 |
| 7 | `dispatch/mod.rs`: `SetMemoryModel` variant | None |
| 8 | `dispatch/proc.rs`: prctl arms 70/71 | Phase 7 |
| 9 | `trap.rs`: `enable_hardware_tso` / `disable_hardware_tso` | Q1 |
| 10 | `runtime.rs`: `SetMemoryModel` arm in all 3 loops | Phase 7, 9 |

Phases 1–6 can proceed in parallel with phases 7–10. Phase 0 must complete first.

---

## Verification

### Unit Tests

| Test | What it validates |
|------|-------------------|
| `inspect_elf_bytes` on a real x86_64 ELF → `Machine::X86_64` | ELF detection |
| `maybe_redirect_to_rosetta` on AArch64 → `None` | No false redirects |
| `maybe_redirect_to_rosetta` on x86_64 → `Some(Ok(...))`, argv rewritten | Redirect logic |
| ioctl handler returns haiku for all 3 Rosetta codes, truncated to correct size | Handshake |
| prctl 70 returns 0 before prctl 71, returns 1 after | Memory model tracking |
| prctl 71 with arg2=1 returns `SetMemoryModel { tso: true }` | Outcome routing |

### Integration Test

```bash
carrick run --platform linux/amd64 alpine:latest uname -m
# Expected: x86_64

carrick run --platform linux/amd64 ubuntu:24.04 dpkg --print-architecture
# Expected: amd64
```

### Trace Verification

Use `carrick trace` during an amd64 container run. All syscalls should appear as standard
AArch64 syscalls (Rosetta's JIT rewrites x86_64 syscall numbers before the `svc #0`
instruction). Verify that `ioctl` and `prctl` appear in the trace with the expected arguments.

# No-VMM Native Feasibility Probes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Build and run standalone Darwin host probes that prove or refute the Phase 0 feasibility gates for the approved no-VMM direct-execution design in `docs/superpowers/specs/2026-07-09-no-vmm-direct-execution-design.md`.

**Architecture:** Keep all experiments in the excluded `bench-native` crate. Add one probe binary, `native_exec_probe`, with deterministic subcommands and `key=value` output. The probes exercise Darwin-native execution vehicles only: host page geometry, fixed address mapping in a child process, executable memory, patchable AArch64 branch islands, signal/ucontext trap delivery, and a guest-vs-host fault discriminator. Do not touch `carrick-runtime`, `carrick-vmm-hvf`, `carrick-hal`, or production backend selection in this plan.

**Tech Stack:** Rust 2021 in `bench-native`, `libc` 0.2 Darwin APIs, a probe-local C shim compiled by `cc` only for public Darwin `ucontext_t` register extraction, macOS/Apple Silicon, same-ISA `linux/arm64` assumptions.

**Stop Condition:** The plan is complete when `native_exec_probe all` runs on the local Darwin host, `docs/2026-07-09-no-vmm-native-feasibility-evidence.md` records exact outputs, and the evidence doc states either `verdict: proceed-to-prototype` or `verdict: blocked`.

## Constraints

- Preserve the approved invariant: one Linux process maps to one macOS process.
- Keep HVF as the release-quality default and reference path.
- Treat the native direct-execution lane as trusted-code-only. Do not describe it as a security boundary.
- Keep this phase out of production crates; it is a feasibility gate, not a backend.
- Do not read Linux kernel or other GPL source.
- Use the `libc` crate for Darwin APIs in Rust. The C shim is restricted to public Darwin `ucontext_t` field extraction for the probe.
- Run destructive fixed-address mapping checks only in a forked child.
- Do not stage or commit unrelated dirty files.

## File Structure

Create and modify these files only:

```text
bench-native/Cargo.toml
bench-native/Cargo.lock
bench-native/build.rs
bench-native/native_exec_probe/ucontext_arm64.c
bench-native/src/bin/native_exec_probe.rs
bench-native/src/native_exec_probe/mod.rs
bench-native/src/native_exec_probe/report.rs
bench-native/src/native_exec_probe/mapping.rs
bench-native/src/native_exec_probe/execmem.rs
bench-native/src/native_exec_probe/trap.rs
bench-native/src/native_exec_probe/fault.rs
docs/2026-07-09-no-vmm-native-feasibility-evidence.md
```

## Task 1: Add The Probe Binary Harness

**Files:**
- Modify `bench-native/Cargo.toml`
- Create `bench-native/src/bin/native_exec_probe.rs`
- Create `bench-native/src/native_exec_probe/mod.rs`
- Create `bench-native/src/native_exec_probe/report.rs`

**Modify `bench-native/Cargo.toml`:**

Add the new binary. Leave existing perf probe binaries unchanged.

```toml
[[bin]]
name = "native_exec_probe"
path = "src/bin/native_exec_probe.rs"
```

Do not replace the existing package metadata or `[dependencies]` table; append only the new `[[bin]]` block.

**Create `bench-native/src/bin/native_exec_probe.rs`:**

```rust
#[path = "../native_exec_probe/mod.rs"]
mod native_exec_probe;

fn main() {
    let code = match native_exec_probe::run_from_env() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("native_exec_probe: {err}");
            2
        }
    };
    std::process::exit(code);
}
```

**Create `bench-native/src/native_exec_probe/report.rs`:**

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }
}

#[derive(Debug)]
pub struct ProbeReport {
    name: &'static str,
    status: Status,
    fields: Vec<(&'static str, String)>,
}

impl ProbeReport {
    pub fn new(name: &'static str, status: Status) -> Self {
        Self {
            name,
            status,
            fields: Vec::new(),
        }
    }

    pub fn field(mut self, key: &'static str, value: impl ToString) -> Self {
        self.fields.push((key, value.to_string()));
        self
    }

    pub fn print(&self) {
        print!("probe={} status={}", self.name, self.status.as_str());
        for (key, value) in &self.fields {
            print!(" {key}={}", shell_escape(value));
        }
        println!();
    }

    pub fn status(&self) -> Status {
        self.status
    }
}

fn shell_escape(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/' | b':'))
    {
        return value.to_string();
    }

    let mut escaped = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            escaped.push_str("'\\''");
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('\'');
    escaped
}
```

**Create `bench-native/src/native_exec_probe/mod.rs`:**

```rust
mod report;

use report::{ProbeReport, Status};

pub fn run_from_env() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(usage());
    };

    if args.next().is_some() {
        return Err(usage());
    }

    match command.as_str() {
        "page-size" => Err("page-size probe is implemented in Task 2".to_string()),
        "fixed-map" => Err("fixed-map probe is implemented in Task 2".to_string()),
        "execmem" => Err("execmem probe is implemented in Task 3".to_string()),
        "brk-trap" => Err("brk-trap probe is implemented in Task 4".to_string()),
        "branch-gateway" => Err("branch-gateway probe is implemented in Task 5".to_string()),
        "fault-discriminator" => Err("fault-discriminator probe is implemented in Task 6".to_string()),
        "all" => run_all(),
        _ => Err(usage()),
    }
}

fn run_all() -> Result<(), String> {
    Err("all probe is implemented after the individual probes exist".to_string())
}

fn print_one(report: ProbeReport) -> Result<(), String> {
    let failed = report.status() == Status::Fail;
    report.print();
    if failed {
        Err("native execution feasibility probe failed".to_string())
    } else {
        Ok(())
    }
}

fn usage() -> String {
    "usage: native_exec_probe page-size|fixed-map|execmem|brk-trap|branch-gateway|fault-discriminator|all".to_string()
}

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(0)
}
```

Tasks 2-6 replace the stub match arms with real probe calls as their modules are created. Task 7 replaces `run_all` with the full six-probe run.

**Acceptance Command:**

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe
```

**Expected Result:** The command exits non-zero and prints the usage string.

## Task 2: Add Page Geometry And Fixed Mapping Probes

**Files:**
- Create `bench-native/src/native_exec_probe/mapping.rs`

**Implementation:**

```rust
use super::errno;
use super::report::{ProbeReport, Status};

const TEST_ADDR: usize = 0x7000_0000_0000;
const TEST_LEN: usize = 0x4000;

pub fn page_size() -> Result<ProbeReport, String> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Ok(ProbeReport::new("page-size", Status::Fail)
            .field("sysconf", page_size)
            .field("errno", errno()));
    }

    let status = if page_size == 4096 {
        Status::Pass
    } else {
        Status::Fail
    };

    Ok(ProbeReport::new("page-size", status)
        .field("host_page_size", page_size)
        .field("linux_guest_page_size", 4096))
}

pub fn fixed_map_child() -> Result<ProbeReport, String> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Ok(ProbeReport::new("fixed-map", Status::Fail).field("fork_errno", errno()));
    }

    if pid == 0 {
        let ptr = unsafe {
            libc::mmap(
                TEST_ADDR as *mut libc::c_void,
                TEST_LEN,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            unsafe { libc::_exit(71) };
        }
        if ptr as usize != TEST_ADDR {
            unsafe { libc::_exit(72) };
        }
        unsafe {
            libc::munmap(ptr, TEST_LEN);
            libc::_exit(0);
        }
    }

    let mut status_word = 0;
    let wait = unsafe { libc::waitpid(pid, &mut status_word, 0) };
    if wait != pid {
        return Ok(ProbeReport::new("fixed-map", Status::Fail)
            .field("waitpid", wait)
            .field("errno", errno()));
    }

    if libc::WIFEXITED(status_word) {
        let code = libc::WEXITSTATUS(status_word);
        let status = if code == 0 { Status::Pass } else { Status::Fail };
        return Ok(ProbeReport::new("fixed-map", status)
            .field("addr", format!("0x{TEST_ADDR:x}"))
            .field("len", TEST_LEN)
            .field("child_exit", code));
    }

    Ok(ProbeReport::new("fixed-map", Status::Fail)
        .field("addr", format!("0x{TEST_ADDR:x}"))
        .field("status_word", status_word))
}
```

**Acceptance Commands:**

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- page-size
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- fixed-map
```

**Expected Result:** Each command prints one line with `probe=` and `status=` fields. A non-4K host page size is a real `page-size` failure and blocks the direct backend unless the design adds a 4K subpage protection strategy.

## Task 3: Add Executable Memory Probe

**Files:**
- Create `bench-native/src/native_exec_probe/execmem.rs`

**Implementation:**

```rust
use super::errno;
use super::report::{ProbeReport, Status};

const MOV_W0_42_RET: [u8; 8] = [
    0x40, 0x05, 0x80, 0x52, // mov w0, #42
    0xc0, 0x03, 0x5f, 0xd6, // ret
];

type ProbeFn = extern "C" fn() -> u32;

pub fn execmem() -> Result<ProbeReport, String> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Ok(ProbeReport::new("execmem", Status::Fail).field("page_size", page_size));
    }

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Ok(ProbeReport::new("execmem", Status::Fail).field("mmap_errno", errno()));
    }

    unsafe {
        std::ptr::copy_nonoverlapping(MOV_W0_42_RET.as_ptr(), ptr.cast::<u8>(), MOV_W0_42_RET.len());
    }

    let protect = unsafe { libc::mprotect(ptr, page_size as usize, libc::PROT_READ | libc::PROT_EXEC) };
    if protect != 0 {
        let err = errno();
        unsafe {
            libc::munmap(ptr, page_size as usize);
        }
        return Ok(ProbeReport::new("execmem", Status::Fail).field("mprotect_errno", err));
    }

    let func: ProbeFn = unsafe { std::mem::transmute(ptr) };
    let value = func();

    unsafe {
        libc::munmap(ptr, page_size as usize);
    }

    let status = if value == 42 { Status::Pass } else { Status::Fail };
    Ok(ProbeReport::new("execmem", status)
        .field("mode", "rw-to-rx")
        .field("return", value))
}
```

**Acceptance Command:**

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- execmem
```

**Expected Result:** The command prints `probe=execmem status=pass mode=rw-to-rx return=42`. A failure here blocks the branch gateway strategy and requires a separate `MAP_JIT` entitlement investigation before backend work.

## Task 4: Add BRK Trap And Ucontext Register Probe

**Files:**
- Create `bench-native/build.rs`
- Create `bench-native/native_exec_probe/ucontext_arm64.c`
- Create `bench-native/src/native_exec_probe/trap.rs`
- Modify `bench-native/Cargo.lock`

**Modify `bench-native/Cargo.toml`:**

Add a build script entry inside the existing `[package]` section and add the probe-local build dependency needed for the C shim.

```toml
[package]
name = "bench-native"
version = "0.0.0"
edition = "2021"
publish = false
build = "build.rs"

[build-dependencies]
cc = "1"
```

Do not replace the existing package metadata or `[dependencies]` table; add only `build = "build.rs"` to the package table and add the `[build-dependencies]` table.

Because `bench-native/Cargo.lock` is tracked, update and commit the lockfile entries Cargo generates for the new `cc` build dependency.

**Create `bench-native/build.rs`:**

```rust
fn main() {
    cc::Build::new()
        .file("native_exec_probe/ucontext_arm64.c")
        .warnings(true)
        .compile("native_exec_probe_ucontext");
}
```

**Create `bench-native/native_exec_probe/ucontext_arm64.c`:**

```c
#include <stdint.h>
#include <string.h>
#include <ucontext.h>

struct carrick_uc_snapshot {
    uint64_t x[9];
    uint64_t sp;
    uint64_t pc;
};

int carrick_snapshot_ucontext(void *uap, struct carrick_uc_snapshot *out) {
#if defined(__aarch64__)
    if (uap == 0 || out == 0) {
        return -1;
    }

    ucontext_t *uc = (ucontext_t *)uap;
    if (uc->uc_mcontext == 0) {
        return -2;
    }

    memset(out, 0, sizeof(*out));
    out->x[0] = uc->uc_mcontext->__ss.__x[0];
    out->x[1] = uc->uc_mcontext->__ss.__x[1];
    out->x[2] = uc->uc_mcontext->__ss.__x[2];
    out->x[3] = uc->uc_mcontext->__ss.__x[3];
    out->x[4] = uc->uc_mcontext->__ss.__x[4];
    out->x[5] = uc->uc_mcontext->__ss.__x[5];
    out->x[6] = uc->uc_mcontext->__ss.__x[6];
    out->x[7] = uc->uc_mcontext->__ss.__x[7];
    out->x[8] = uc->uc_mcontext->__ss.__x[8];
    out->sp = uc->uc_mcontext->__ss.__sp;
    out->pc = uc->uc_mcontext->__ss.__pc;
    return 0;
#else
    (void)uap;
    (void)out;
    return -3;
#endif
}
```

**Add this to `bench-native/src/native_exec_probe/trap.rs`:**

```rust
use super::errno;
use super::report::{ProbeReport, Status};

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UcontextSnapshot {
    x: [u64; 9],
    sp: u64,
    pc: u64,
}

unsafe extern "C" {
    fn carrick_snapshot_ucontext(uap: *mut libc::c_void, out: *mut UcontextSnapshot) -> libc::c_int;
}

pub fn brk_trap() -> Result<ProbeReport, String> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Ok(ProbeReport::new("brk-trap", Status::Fail).field("fork_errno", errno()));
    }

    if pid == 0 {
        child_brk_trap();
    }

    let mut status_word = 0;
    let wait = unsafe { libc::waitpid(pid, &mut status_word, 0) };
    if wait != pid {
        return Ok(ProbeReport::new("brk-trap", Status::Fail)
            .field("waitpid", wait)
            .field("errno", errno()));
    }

    if libc::WIFEXITED(status_word) {
        let code = libc::WEXITSTATUS(status_word);
        let status = if code == 0 { Status::Pass } else { Status::Fail };
        return Ok(ProbeReport::new("brk-trap", status).field("child_exit", code));
    }

    Ok(ProbeReport::new("brk-trap", Status::Fail).field("status_word", status_word))
}

fn child_brk_trap() -> ! {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = brk_handler as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTRAP, &action, std::ptr::null_mut()) != 0 {
            libc::_exit(80);
        }

        std::arch::asm!(
            "mov x0, #123",
            "mov x8, #172",
            "brk #0xf000",
            options(nostack)
        );

        libc::_exit(81);
    }
}

extern "C" fn brk_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    uap: *mut libc::c_void,
) {
    let mut snapshot = UcontextSnapshot::default();
    let rc = unsafe { carrick_snapshot_ucontext(uap, &mut snapshot) };
    let ok = rc == 0 && snapshot.x[0] == 123 && snapshot.x[8] == 172 && snapshot.pc != 0;
    unsafe {
        libc::_exit(if ok { 0 } else { 82 });
    }
}
```

**Acceptance Command:**

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- brk-trap
```

**Expected Result:** The command prints `probe=brk-trap status=pass child_exit=0`. A failure means Darwin signal/ucontext delivery is not sufficient for a slow-path syscall interception prototype.

## Task 5: Add Patchable Branch Gateway Probe

**Files:**
- Modify `bench-native/src/native_exec_probe/trap.rs`

**Add branch gateway code to `trap.rs`:**

```rust
const MOV_W0_77_RET: [u8; 8] = [
    0xa0, 0x09, 0x80, 0x52, // mov w0, #77
    0xc0, 0x03, 0x5f, 0xd6, // ret
];

type GatewayFn = extern "C" fn() -> u32;

pub fn branch_gateway() -> Result<ProbeReport, String> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Ok(ProbeReport::new("branch-gateway", Status::Fail).field("page_size", page_size));
    }

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Ok(ProbeReport::new("branch-gateway", Status::Fail).field("mmap_errno", errno()));
    }

    let base = ptr as usize;
    let guest_pc = base;
    let gateway_pc = base + 64;
    let Some(branch) = encode_b(guest_pc, gateway_pc) else {
        unsafe {
            libc::munmap(ptr, page_size as usize);
        }
        return Ok(ProbeReport::new("branch-gateway", Status::Fail).field("reason", "branch_range"));
    };

    unsafe {
        std::ptr::write_unaligned(ptr.cast::<u32>(), branch);
        std::ptr::copy_nonoverlapping(
            MOV_W0_77_RET.as_ptr(),
            (ptr.cast::<u8>()).add(64),
            MOV_W0_77_RET.len(),
        );
        libc::sys_icache_invalidate(ptr, 72);
    }

    let protect = unsafe { libc::mprotect(ptr, page_size as usize, libc::PROT_READ | libc::PROT_EXEC) };
    if protect != 0 {
        let err = errno();
        unsafe {
            libc::munmap(ptr, page_size as usize);
        }
        return Ok(ProbeReport::new("branch-gateway", Status::Fail).field("mprotect_errno", err));
    }

    let func: GatewayFn = unsafe { std::mem::transmute(ptr) };
    let value = func();

    unsafe {
        libc::munmap(ptr, page_size as usize);
    }

    let status = if value == 77 { Status::Pass } else { Status::Fail };
    Ok(ProbeReport::new("branch-gateway", status)
        .field("return", value)
        .field("branch_word", format!("0x{branch:08x}")))
}

fn encode_b(from: usize, to: usize) -> Option<u32> {
    let byte_delta = (to as isize).checked_sub(from as isize)?;
    if byte_delta % 4 != 0 {
        return None;
    }

    let instruction_delta = byte_delta / 4;
    if !(-(1 << 25)..(1 << 25)).contains(&instruction_delta) {
        return None;
    }

    Some(0x1400_0000 | ((instruction_delta as u32) & 0x03ff_ffff))
}
```

If `libc::sys_icache_invalidate` is unavailable in the local `libc` version, replace that single call with a probe-local C shim function in `ucontext_arm64.c`:

```c
void carrick_probe_clear_icache(void *start, size_t len) {
    sys_icache_invalidate(start, len);
}
```

and call it from Rust with the same `start` and `len` arguments.

**Acceptance Command:**

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- branch-gateway
```

**Expected Result:** The command prints `probe=branch-gateway status=pass return=77` and a hexadecimal `branch_word` field. A failure blocks the production branch-to-gateway syscall interception design.

## Task 6: Add Guest-Vs-Host Fault Discriminator Probe

**Files:**
- Create `bench-native/src/native_exec_probe/fault.rs`

**Implementation:**

```rust
use super::errno;
use super::report::{ProbeReport, Status};
use std::sync::atomic::{AtomicBool, Ordering};

static IN_GUEST_WINDOW: AtomicBool = AtomicBool::new(false);

pub fn fault_discriminator() -> Result<ProbeReport, String> {
    let guest_code = run_fault_child(true)?;
    let host_code = run_fault_child(false)?;

    let status = if guest_code == 90 && host_code == 91 {
        Status::Pass
    } else {
        Status::Fail
    };

    Ok(ProbeReport::new("fault-discriminator", status)
        .field("guest_fault_exit", guest_code)
        .field("host_fault_exit", host_code))
}

fn run_fault_child(mark_guest: bool) -> Result<i32, String> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork failed: errno={}", errno()));
    }

    if pid == 0 {
        child_fault(mark_guest);
    }

    let mut status_word = 0;
    let wait = unsafe { libc::waitpid(pid, &mut status_word, 0) };
    if wait != pid {
        return Err(format!("waitpid failed: waitpid={wait} errno={}", errno()));
    }

    if libc::WIFEXITED(status_word) {
        Ok(libc::WEXITSTATUS(status_word))
    } else {
        Ok(128)
    }
}

fn child_fault(mark_guest: bool) -> ! {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = fault_handler as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()) != 0 {
            libc::_exit(88);
        }
        if libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut()) != 0 {
            libc::_exit(89);
        }

        IN_GUEST_WINDOW.store(mark_guest, Ordering::SeqCst);
        std::ptr::write_volatile(std::ptr::null_mut::<u8>(), 1);
        libc::_exit(87);
    }
}

extern "C" fn fault_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _uap: *mut libc::c_void,
) {
    let in_guest = IN_GUEST_WINDOW.load(Ordering::SeqCst);
    unsafe {
        libc::_exit(if in_guest { 90 } else { 91 });
    }
}
```

**Acceptance Command:**

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- fault-discriminator
```

**Expected Result:** The command prints `probe=fault-discriminator status=pass guest_fault_exit=90 host_fault_exit=91`. This only proves the minimum process-local discriminator. Production work must later strengthen it with a guest PC range check before it handles translated Linux faults.

## Task 7: Run All Probes And Record Evidence

**Files:**
- Create `docs/2026-07-09-no-vmm-native-feasibility-evidence.md`

**Commands:**

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- all
```

If compilation fails because a Darwin symbol is unavailable in the Rust `libc` crate, fix the probe by moving only that symbol use into the probe-local C shim. Do not move production runtime logic into C.

**Evidence Document Content:**

Create `docs/2026-07-09-no-vmm-native-feasibility-evidence.md` after the command runs. Use this structure, and put the exact local stdout in the `Output` section:

````markdown
# No-VMM Native Feasibility Evidence

Date: 2026-07-09
Host: macOS Apple Silicon
Spec: docs/superpowers/specs/2026-07-09-no-vmm-direct-execution-design.md
Plan: docs/superpowers/plans/2026-07-09-no-vmm-native-feasibility-probes.md

## Command

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- all
```

## Output

Open a `text` fence here and include only the exact stdout lines from `native_exec_probe all`.

## Gate Interpretation

- `page-size`: record whether Darwin page geometry can represent the initial Linux page-size contract directly.
- `fixed-map`: record whether a child process can reserve the planned guest window at a fixed address.
- `execmem`: record whether generated same-ISA code can execute after Rust writes it.
- `brk-trap`: record whether Darwin signal/ucontext delivery can expose syscall-like register state.
- `branch-gateway`: record whether a patched AArch64 branch island can redirect guest code to a gateway.
- `fault-discriminator`: record whether process-local state can distinguish guest faults from host faults.

## Verdict

verdict: proceed-to-prototype
````

Use `verdict: blocked` instead when any required probe reports `status=fail`. Under a blocked verdict, add one paragraph naming the first failed gate and the production design issue it exposes.

## Task 8: Verify The Plan Scope And Working Tree

**Commands:**

```sh
cargo fmt --manifest-path bench-native/Cargo.toml --check
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- all
git status --short
```

**Acceptance Result:**

- `cargo fmt --manifest-path bench-native/Cargo.toml --check` exits zero.
- `native_exec_probe all` prints six probe lines.
- `git status --short` shows only the files listed in this plan plus unrelated pre-existing dirt.
- The evidence doc has an explicit `verdict:` line.

## Execution Notes

- The full backend should not be started from this plan. If the verdict is `proceed-to-prototype`, write a separate plan for a minimal `carrick-exec-darwin` prototype.
- If `page-size` fails on a 16K host, do not paper over it with optimistic prose. Record the failure and design a 4K subpage strategy or restrict the native backend to hosts where the probe passes.
- If `execmem` fails under the current binary entitlements, do not add entitlements to Carrick production code in this plan. Record the failure and make executable-memory policy a separate design item.
- If `brk-trap` passes but `branch-gateway` fails, prefer a slow-path prototype only as a follow-up experiment; do not claim the low-overhead backend is feasible yet.
- If `fault-discriminator` passes, treat it as a minimum signal-routing proof only. It does not prove Linux `SIGSEGV` fidelity, nested signal safety, or async-signal-safe recovery.

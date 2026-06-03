# ppoll / pselect6 sigmask Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the `ppoll(2)` and `pselect6(2)` signal mask during the wait, so a signal the mask blocks does not interrupt the wait (it stays pending, delivered after the syscall) — matching Linux and mirroring the landed `epoll_pwait` fix.

**Architecture:** The plumbing already exists from the `epoll_pwait` fix (commit `0473901`): `DispatchOutcome::WaitOnFds` has a `block_signals: u64` field, the runtime passes it to `ThreadWaiter::wait`, and `host_signal::has_unblocked_pending_for(tid, block_mask)` makes a blocked pending signal not break the wait. This plan only teaches `ppoll`/`pselect6` to read their sigmask arg and pass it as `block_signals` instead of `0`.

**Tech Stack:** Rust, carrick syscall dispatch (`src/dispatch/net.rs`), conformance probes (static musl aarch64 ELF), Docker arm64 LTP oracle on `localhost:5050`.

**Pre-req:** `export CARRICK_INSECURE_REGISTRIES=localhost:5050`; build with `./scripts/build-signed.sh` (plain `cargo build` strips the HVF entitlement → HV_DENIED). Kill stray guests before any timing run: `pkill -9 -f carrick`.

---

### Task 1: Failing probe — `ppoll`/`pselect6` blocked-signal does not interrupt

**Files:**
- Create: `conformance-probes/src/bin/ppollsig.rs`
- Test (oracle): Docker `alpine` vs `carrick run-elf`

- [ ] **Step 1: Write the probe** (mirrors `epollpwait.rs`'s `sigmask_blocks`, for `ppoll` and `pselect`)

```rust
//! ppoll/pselect6 with a signal mask: a blocked signal raised mid-wait (before
//! the fd is ready) must NOT interrupt the wait — it returns 1 once the fd is
//! made ready. Deterministic booleans; bounded so a broken path prints false.

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    let mut mask: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut mask);
    libc::sigaddset(&mut mask, libc::SIGUSR1);
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = noop as usize;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());

    println!("ppoll_blocks={}", run_one(false));
    println!("pselect_blocks={}", run_one(true));
}

// `use_pselect` false → ppoll, true → pselect6.
unsafe fn run_one(use_pselect: bool) -> bool {
    let mut sv = [0i32; 2];
    if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
        return false;
    }
    let parent = libc::getpid();
    let pid = libc::fork();
    if pid == 0 {
        // Raise the masked signal while the parent is blocked and the socket is
        // empty; make the fd ready only later.
        libc::usleep(50_000);
        libc::kill(parent, libc::SIGUSR1);
        libc::usleep(150_000);
        libc::write(sv[1], b"w".as_ptr().cast(), 1);
        libc::_exit(0);
    }
    let mut mask: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut mask);
    libc::sigaddset(&mut mask, libc::SIGUSR1);
    let ts = libc::timespec { tv_sec: 4, tv_nsec: 0 };
    let ret = if use_pselect {
        let mut rfds: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&mut rfds);
        libc::FD_SET(sv[0], &mut rfds);
        libc::pselect(
            sv[0] + 1,
            &mut rfds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ts,
            &mask,
        )
    } else {
        let mut pfd = libc::pollfd { fd: sv[0], events: libc::POLLIN, revents: 0 };
        libc::ppoll(&mut pfd, 1, &ts, &mask)
    };
    let mut st = 0i32;
    libc::waitpid(pid, &mut st, 0);
    libc::close(sv[0]);
    libc::close(sv[1]);
    ret == 1
}

extern "C" fn noop(_sig: libc::c_int) {}
```

- [ ] **Step 2: Build probes and run carrick vs Docker — expect carrick FALSE, Docker TRUE**

```bash
./scripts/build-probes.sh
P=conformance-probes/target/aarch64-unknown-linux-musl/release/ppollsig
docker run --rm --platform linux/arm64 -v "$PWD/conformance-probes/target/aarch64-unknown-linux-musl/release:/p:ro" alpine /p/ppollsig
pkill -9 -f carrick; ./target/release/carrick run-elf --raw --fs host "$PWD/$P"
```

Expected: Docker prints `ppoll_blocks=true` / `pselect_blocks=true`; carrick prints `false` for both (sigmask ignored → blocked signal EINTRs the wait). This is the failing state.

---

### Task 2: Apply the sigmask in `ppoll`

**Files:**
- Modify: `src/dispatch/net.rs` — `ppoll` (fn starts at the `pub(super) fn ppoll` near line 782; args read near line 786; WaitOnFds emitted near line 895)

- [ ] **Step 1: Read the sigmask arg into a `block_signals` mask**

After the `timeout_ms` decode block (just before "Read all the pollfds up front"), add:

```rust
// ppoll(fds, nfds, timeout, sigmask, sigsetsize). Capture the sigmask as a
// u64 bitmask (bit signum-1) so a blocked signal doesn't interrupt the wait
// (it stays pending, delivered after the syscall). Mirrors epoll_pwait.
let sigmask_addr = ctx.arg(3);
let sigsetsize = ctx.arg(4);
let block_signals: u64 = if sigmask_addr != 0 {
    if sigsetsize != crate::linux_abi::LINUX_RT_SIGSET_SIZE {
        return Ok(LINUX_EINVAL.into());
    }
    match memory.read_bytes(sigmask_addr, crate::linux_abi::LINUX_RT_SIGSET_SIZE as usize) {
        Ok(bytes) => {
            let mut le = [0u8; 8];
            le.copy_from_slice(&bytes[..8]);
            u64::from_le_bytes(le)
        }
        Err(_) => return Ok(LINUX_EFAULT.into()),
    }
} else {
    0
};
```

> Note: `memory` is already bound (`let memory = &mut *ctx.memory;`). Read the sigmask BEFORE the `for index in 0..nfds` loop that also borrows `memory`, so the borrow is released first (the read returns an owned `Vec`).

- [ ] **Step 2: Pass `block_signals` to ppoll's `WaitOnFds`**

Replace the `block_signals: 0,` line (with its two-line "not yet applied" comment) in ppoll's `WaitOnFds` (near line 895) with:

```rust
                block_signals,
```

- [ ] **Step 3: Build and verify ppoll passes**

```bash
./scripts/build-signed.sh
P=conformance-probes/target/aarch64-unknown-linux-musl/release/ppollsig
pkill -9 -f carrick; ./target/release/carrick run-elf --raw --fs host "$PWD/$P"
```

Expected: `ppoll_blocks=true` (pselect may still be false until Task 3).

---

### Task 3: Apply the sigmask in `pselect6`

**Files:**
- Modify: `src/dispatch/net.rs` — `pselect6` (fn starts at `pub(super) fn pselect6` near line 519)

- [ ] **Step 1: Locate pselect6's sigmask arg and its WaitOnFds emitter(s)**

Run: `grep -n "DispatchOutcome::WaitOnFds {" src/dispatch/net.rs` and read pselect6 to find how it reaches a wait (it may convert to the ppoll path or emit its own `WaitOnFds`). pselect6 ABI: `pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask_arg)` where arg5 (`sigmask_arg`) points to a `{ const sigset_t *ss; size_t ss_len; }` struct, NOT a bare sigmask. Read `ss` (offset 0) and `ss_len` (offset 8); if `ss` is non-NULL, validate `ss_len == LINUX_RT_SIGSET_SIZE` and read the 8-byte mask at `ss`.

- [ ] **Step 2: Compute `block_signals` for pselect6**

```rust
// pselect6's 6th arg points to { const sigset_t *ss; size_t ss_len; }.
let sigmask_arg = ctx.arg(5);
let block_signals: u64 = if sigmask_arg != 0 {
    let ss_ptr = match memory.read_bytes(sigmask_arg, 8) {
        Ok(b) => u64::from_le_bytes(b[..8].try_into().unwrap()),
        Err(_) => return Ok(LINUX_EFAULT.into()),
    };
    let ss_len = match memory.read_bytes(sigmask_arg + 8, 8) {
        Ok(b) => u64::from_le_bytes(b[..8].try_into().unwrap()),
        Err(_) => return Ok(LINUX_EFAULT.into()),
    };
    if ss_ptr == 0 {
        0
    } else {
        if ss_len != crate::linux_abi::LINUX_RT_SIGSET_SIZE {
            return Ok(LINUX_EINVAL.into());
        }
        match memory.read_bytes(ss_ptr, crate::linux_abi::LINUX_RT_SIGSET_SIZE as usize) {
            Ok(b) => u64::from_le_bytes(b[..8].try_into().unwrap()),
            Err(_) => return Ok(LINUX_EFAULT.into()),
        }
    }
} else {
    0
};
```

- [ ] **Step 3: Pass `block_signals` to every `WaitOnFds` pselect6 emits**

If pselect6 builds its own `WaitOnFds`, set `block_signals` there. If it delegates to a shared poll/ppoll helper that emits the `WaitOnFds`, thread `block_signals` through that helper as a parameter (default `0` for non-pselect callers). Do NOT leave any pselect6 wait path at `block_signals: 0`.

- [ ] **Step 4: Build and verify both pass**

```bash
./scripts/build-signed.sh
P=conformance-probes/target/aarch64-unknown-linux-musl/release/ppollsig
pkill -9 -f carrick; ./target/release/carrick run-elf --raw --fs host "$PWD/$P"
```

Expected: `ppoll_blocks=true` AND `pselect_blocks=true`, matching Docker (re-run the Docker line from Task 1 Step 2 to confirm identical output).

---

### Task 4: Regression-check and commit

- [ ] **Step 1: Conformance probes (includes the new `ppollsig`) + lib tests**

```bash
export CARRICK_INSECURE_REGISTRIES=localhost:5050
pkill -9 -f carrick
cargo test --release --lib -- --test-threads=1
cargo test --release --test conformance conformance_probes
```

Expected: lib `203 passed` (or current count), conformance `ok`.

- [ ] **Step 2: LTP sweep — ppoll/pselect must not regress (verify inversions are Docker jitter)**

```bash
.claude/skills/ltp-conformance/scripts/ltp-check.sh ppoll01 pselect01 pselect03 poll01 epoll_pwait01
```

Expected: `ppoll01` improves (fewer/zero failures), `epoll_pwait01` unchanged (still TPASS line-38). For any DIFF, read the failing `TPASS`/`TFAIL` lines per the ltp-conformance skill — `pselect01` is a known Docker-VM timing-jitter inversion (carrick passes more); confirm individually, do not chase.

- [ ] **Step 3: Commit**

```bash
git add src/dispatch/net.rs conformance-probes/src/bin/ppollsig.rs
git commit -m "$(cat <<'EOF'
fix(ppoll,pselect6): apply the sigmask during the wait

Mirror the epoll_pwait fix (0473901) for ppoll/pselect6: read the sigmask arg,
carry it as WaitOnFds.block_signals so a signal the mask blocks does not
interrupt the wait (stays pending, delivered after per the persistent mask).
New ppollsig probe MATCHES Docker; LTP ppoll01 improves; block_signals=0 paths
unchanged.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-review notes
- Spec coverage: implements §1 of `2026-05-23-go-bringup-followups-design.md`.
- Type consistency: `block_signals: u64` matches the field added in `0473901`; `LINUX_RT_SIGSET_SIZE` is the existing `u64` const used by `epoll_pwait`.
- pselect6's 6th arg is the `{ptr,len}` struct (not a bare sigmask) — Task 3 handles that explicitly; verify against the kernel ABI if a TFAIL appears on the EINVAL/EFAULT edge cases.

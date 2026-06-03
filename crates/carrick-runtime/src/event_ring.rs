//! Lock-free, low-perturbation in-memory event ring for diagnosing timing-
//! sensitive (Heisenbug) deadlocks — specifically the nested-forkserver
//! `test_parent_process` hang where a server forked+exec'd from a forkserver
//! worker fails to function, and ANY `eprintln`/dtrace instrumentation perturbs
//! the race enough to change the manifestation (see
//! `docs/forkserver-parent-process-deadlock.md`).
//!
//! Recording is hot-path-cheap: an atomic `fetch_add` index + two atomic
//! `store`s into a fixed array — no lock, no syscall, no allocation, ~ns. The
//! perturbing part (formatting + writing a file) happens OFF the vCPU thread on
//! a 1 Hz watchdog thread, so the guest's syscall timing is left intact.
//!
//! Entirely gated on the `CARRICK_EVENTRING` env var (a dir to dump into); when
//! unset, every `rec_*` is a single relaxed atomic load + early return.
//!
//! Each carrick process is one guest process, so the ring is per-process. On a
//! guest fork the child inherits the parent's ring memory but only the forking
//! thread survives, so [`reinit_after_fork`] resets the index + re-arms the
//! watchdog for the child.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

const N: usize = 8192;

// Each event is two u64 cells (lo, hi). A reader may observe a torn write
// (lo updated, hi stale) under concurrency; that's acceptable for a diagnostic
// (rare, and a decoded `kind` outside 1..=8 is dropped).
struct Slot {
    lo: AtomicU64,
    hi: AtomicU64,
}

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY: Slot = Slot {
    lo: AtomicU64::new(0),
    hi: AtomicU64::new(0),
};

static RING: [Slot; N] = [EMPTY; N];
static IDX: AtomicUsize = AtomicUsize::new(0);
static WATCHDOG: AtomicBool = AtomicBool::new(false);

// Event kinds.
pub const BIND: u8 = 1;
pub const LISTEN: u8 = 2;
pub const CONNECT: u8 = 3;
pub const ACCEPT: u8 = 4;
pub const EPADD: u8 = 5;
pub const EPWAIT: u8 = 6;
pub const FORK: u8 = 7;
pub const EXEC: u8 = 8;

fn dir() -> Option<&'static str> {
    static DIR: OnceLock<Option<String>> = OnceLock::new();
    DIR.get_or_init(|| std::env::var("CARRICK_EVENTRING").ok())
        .as_deref()
}

#[inline]
fn enabled() -> bool {
    dir().is_some()
}

/// Append one event. Hot-path-cheap; no-op when the ring is disabled.
#[inline]
pub fn rec(kind: u8, a: i32, b: i32, c: i32) {
    if !enabled() {
        return;
    }
    let lo = (a as u32 as u64) | ((b as u32 as u64) << 32);
    let hi = (c as u32 as u64) | ((kind as u64) << 32);
    let i = IDX.fetch_add(1, Ordering::Relaxed) % N;
    // Write hi (with the kind tag) LAST so a reader that sees a valid kind has
    // a good chance of also seeing the matching lo.
    RING[i].lo.store(lo, Ordering::Relaxed);
    RING[i].hi.store(hi, Ordering::Relaxed);
    ensure_watchdog();
}

/// Cheap, stable 32-bit hash of an AF_UNIX path, so a `connect` can be matched
/// to the `bind` of the same socket without storing the string.
pub fn path_hash(path: &[u8]) -> i32 {
    // FNV-1a.
    let mut h: u32 = 0x811c_9dc5;
    for &byte in path {
        h ^= byte as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h as i32
}

/// Reset the ring + re-arm the watchdog for a freshly forked child (its
/// inherited watchdog thread did not survive the fork).
pub fn reinit_after_fork() {
    if !enabled() {
        return;
    }
    IDX.store(0, Ordering::SeqCst);
    WATCHDOG.store(false, Ordering::SeqCst);
}

fn ensure_watchdog() {
    if WATCHDOG.swap(true, Ordering::SeqCst) {
        return; // already running for this process
    }
    let Some(d) = dir() else { return };
    let path = format!("{d}/carrick-ring.{}", std::process::id());
    let _ = std::thread::Builder::new()
        .name("carrick-eventring".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(1000));
                dump(&path);
            }
        });
}

fn decode(kind: u8, a: i32, b: i32, c: i32) -> String {
    match kind {
        BIND => format!("BIND     gfd={a} hfd={b} pathhash={c:#010x}"),
        LISTEN => format!("LISTEN   hfd={a}"),
        CONNECT => format!("CONNECT  hfd={a} rc={b} pathhash={c:#010x}"),
        ACCEPT => format!("ACCEPT   listener_hfd={a} ret={b}"),
        EPADD => format!("EPADD    kq={a} hfd={b} events={c:#x}"),
        EPWAIT => format!("EPWAIT   kq={a} ready={b} timeout={c}"),
        FORK => format!("FORK     child_pid={a}"),
        EXEC => format!("EXEC     path_present={a}"),
        _ => return String::new(),
    }
}

fn dump(path: &str) {
    use std::io::Write;
    let total = IDX.load(Ordering::SeqCst);
    let count = total.min(N);
    let start = total.saturating_sub(count);
    let mut out = String::with_capacity(count * 48);
    out.push_str(&format!(
        "# carrick event ring pid={} events={}\n",
        std::process::id(),
        total
    ));
    for k in 0..count {
        let global = start + k;
        let i = global % N;
        let lo = RING[i].lo.load(Ordering::Relaxed);
        let hi = RING[i].hi.load(Ordering::Relaxed);
        let a = (lo & 0xffff_ffff) as u32 as i32;
        let b = (lo >> 32) as u32 as i32;
        let c = (hi & 0xffff_ffff) as u32 as i32;
        let kind = (hi >> 32) as u8;
        let line = decode(kind, a, b, c);
        if line.is_empty() {
            continue; // torn/empty slot
        }
        out.push_str(&format!("{global:6} {line}\n"));
    }
    if let Ok(mut f) = std::fs::File::create(path) {
        let _ = f.write_all(out.as_bytes());
    }
}

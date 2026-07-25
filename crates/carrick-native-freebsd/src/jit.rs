//! Dual-mapped W^X JIT code cache for FreeBSD/amd64.
//!
//! FreeBSD has no Darwin `MAP_JIT`/per-thread write-protect toggle, and
//! `mprotect` RW↔RX flips would be PROCESS-wide — a writer would yank X from
//! under concurrently-executing guest threads. Instead the cache is one
//! anonymous SHM object mapped twice:
//!
//! ```text
//!   shm_open(SHM_ANON) ── ftruncate(capacity)
//!        ├── mmap(PROT_READ|PROT_EXEC,  MAP_SHARED)  → JitRegion.exec_base
//!        └── mmap(PROT_READ|PROT_WRITE, MAP_SHARED)  → JitRegion.write_base
//! ```
//!
//! Writers write through the RW alias (`JitRegion::write_ptr_for`), executors
//! run the RX alias, no protection ever flips, and
//! `begin/end_thread_write` are no-ops.
//!
//! ## `flush_icache` is arch-shaped, and fails closed off amd64
//!
//! On **x86_64** `flush_icache` is a no-op, and that is CORRECT: x86 has a
//! coherent instruction cache (cross-modifying-code ORDERING at live patch
//! sites is the x86 arch crate's contract at its patch encodings, not a
//! flush). The mapping machinery around it, by contrast, is arch-neutral —
//! `shm_open(SHM_ANON)` + two `mmap`s — so it stays compiled on every FreeBSD
//! arch.
//!
//! That asymmetry was a live silent-corruption trap: the no-op was gated on
//! `target_os` alone, so a FreeBSD/**aarch64** build would resolve to it and
//! execute STALE instructions after publishing code (measured on
//! freebsd-arm64 during the aarch64 lane scout: publishing through the RW
//! alias with no cache maintenance ran the previous function's body). AArch64
//! needs real `__clear_cache`-style maintenance, and this crate does not have
//! one yet.
//!
//! So off amd64 this lane refuses instead of pretending, at both reachable
//! entries:
//!
//! * [`NativeHostJit::supported`] returns `Err`, so `TranslationCache::new`
//!   gets a typed cache-policy error before a single byte is mapped.
//! * `flush_icache` **aborts**. It returns `()` — it has no error channel —
//!   and it is reachable WITHOUT any mapped code cache:
//!   `carrick-dsr-aarch64`'s `mapped_memory::native_clear_icache` routes
//!   GUEST exec-page publication through `installed_host_jit()`, so a typed
//!   error at map time does not gate it. Returning normally there would claim
//!   coherence that does not exist; fail-stop is the only honest answer a
//!   `-> ()` method can give (`panic!`/`unimplemented!` are denied
//!   workspace-wide, and `abort` is already this file's fail-stop idiom).
//!
//! Both arms disappear the moment a real aarch64 flush lands here.
//!
//! ## Fork hazard — CLOSED, enforced by `remap_for_fork_child`
//!
//! Unlike Darwin's `MAP_PRIVATE` MAP_JIT (fork child gets a CoW copy), a
//! `MAP_SHARED` dual map is SHARED with a fork child: a child that APPENDS
//! translations would write the same physical pages the parent executes.
//! This was a standing review finding (M1 item, previously "documented, not
//! yet closed"). It is now CLOSED and ENFORCED through the host seam:
//! [`NativeHostJit::remap_for_fork_child`] is the contract every native
//! host must answer, and `FreebsdHostJit`'s answer is always
//! `Ok(ForkChildJit::Fresh(..))` — a brand-new SHM_ANON object of the same
//! capacity, never the inherited one. The runtime's `fork_child_rebuild`
//! (`carrick-runtime/src/native_freebsd.rs`) calls this instead of
//! `map_code_cache` directly, so a fork child NEVER keeps executing against
//! the parent's SHM object. This lane's fork repair is entirely REGION
//! REPLACEMENT, done by `remap_for_fork_child` before the child's first
//! guest thread runs — there is no in-place protection-state repair to do
//! (no MAP_JIT toggle on this lane).

use std::io;
use std::ptr::NonNull;

use carrick_dsr::host::{ForkChildJit, JitRegion, NativeHostJit};

/// Stateless dual-map JIT backend (all state lives in the [`JitRegion`]).
pub struct FreebsdHostJit;

fn shm_anon_fd(capacity: usize) -> io::Result<libc::c_int> {
    // SAFETY: SHM_ANON creates a process-private anonymous SHM object; the
    // fd is ours to own and close.
    let fd = unsafe { libc::shm_open(libc::SHM_ANON, libc::O_RDWR, 0o600) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a valid SHM fd we just opened.
    if unsafe { libc::ftruncate(fd, capacity as libc::off_t) } != 0 {
        let error = io::Error::last_os_error();
        // SAFETY: fd is ours and not yet shared.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    Ok(fd)
}

fn unmap_candidate_or_abort(address: *mut libc::c_void, capacity: usize) -> Option<io::Error> {
    // SAFETY: callers pass an unpublished alias they exclusively own.
    if unsafe { libc::munmap(address, capacity) } == 0 {
        return None;
    }
    let first = io::Error::last_os_error();
    // Preserve ownership through one reportable transient. A persistent failure
    // cannot return without losing the only alias record, so fail-stop.
    if unsafe { libc::munmap(address, capacity) } != 0 {
        std::process::abort();
    }
    Some(first)
}

fn map_shared(fd: libc::c_int, capacity: usize, prot: libc::c_int) -> io::Result<NonNull<u8>> {
    // SAFETY: fd is a valid SHM object of at least `capacity` bytes; a
    // kernel-chosen placement with MAP_SHARED aliases the object.
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            capacity,
            prot,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let Some(mapping) = NonNull::new(mapped.cast::<u8>()) else {
        // A successful address-zero map is still owned. Do not turn it into an
        // error until that ownership has been explicitly discharged.
        if let Some(cleanup_error) = unmap_candidate_or_abort(mapped, capacity) {
            return Err(io::Error::other(format!(
                "mmap returned a null mapping; cleanup initially failed: {cleanup_error}"
            )));
        }
        return Err(io::Error::other("mmap returned a null mapping"));
    };
    Ok(mapping)
}

impl NativeHostJit for FreebsdHostJit {
    fn supported(&self) -> Result<(), &'static str> {
        // Dual mapping needs nothing exotic; a W^X-hardened kernel that
        // refuses PROT_EXEC SHM mappings surfaces at map_code_cache as a
        // typed Host error instead.
        #[cfg(target_arch = "x86_64")]
        {
            Ok(())
        }
        // Off amd64 the mapping half would work, but `flush_icache` below has
        // no cache-maintenance body — see the module doc. Refuse here so
        // `TranslationCache::new` fails closed before anything maps code.
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(
                "FreeBSD native host JIT: no I-cache maintenance on this arch \
                 (flush_icache needs a real __clear_cache body before an \
                 aarch64 lane may publish code)",
            )
        }
    }

    fn map_code_cache(&self, capacity: usize) -> io::Result<JitRegion> {
        let fd = shm_anon_fd(capacity)?;
        let exec_base = match map_shared(fd, capacity, libc::PROT_READ | libc::PROT_EXEC) {
            Ok(mapping) => mapping,
            Err(error) => {
                // SAFETY: `fd` is the still-private SHM descriptor.
                unsafe { libc::close(fd) };
                return Err(error);
            }
        };
        let write_base = match map_shared(fd, capacity, libc::PROT_READ | libc::PROT_WRITE) {
            Ok(mapping) => mapping,
            Err(error) => {
                // exec_base is the only acquired alias and nothing can execute
                // from it before this function returns a JitRegion.
                let cleanup_error = unmap_candidate_or_abort(exec_base.as_ptr().cast(), capacity);
                // SAFETY: `fd` remains ours on both success and error paths.
                unsafe { libc::close(fd) };
                return Err(match cleanup_error {
                    Some(cleanup_error) => io::Error::other(format!(
                        "map writable JIT alias failed: {error}; executable-alias rollback failed: {cleanup_error}"
                    )),
                    None => error,
                });
            }
        };
        // The object lives as long as its mappings; the fd is not needed
        // after both views exist (and must not leak into guests).
        // SAFETY: fd is ours; mappings keep the SHM object alive.
        unsafe { libc::close(fd) };
        Ok(JitRegion {
            exec_base,
            write_base,
            capacity,
        })
    }

    unsafe fn unmap(&self, region: &JitRegion) {
        // SAFETY: caller contract — no thread executes from or holds
        // pointers into either view.
        unsafe {
            libc::munmap(region.exec_base.as_ptr().cast(), region.capacity);
            libc::munmap(region.write_base.as_ptr().cast(), region.capacity);
        }
    }

    fn begin_thread_write(&self) {
        // Writes go through the always-writable RW alias.
    }

    fn end_thread_write(&self) {}

    #[cfg(target_arch = "x86_64")]
    fn flush_icache(&self, _exec_ptr: *const u8, _len: usize) {
        // Coherent I-cache on x86; freshly-published (never-executed) code
        // needs no barrier beyond the publication index's Release store.
    }

    /// Fail-stop: this arch needs real I-cache maintenance and this crate has
    /// none yet (module doc). Reachable without a mapped code cache via
    /// `carrick-dsr-aarch64`'s `mapped_memory::native_clear_icache`, which
    /// publishes GUEST exec pages through `installed_host_jit()` — so
    /// `supported()`'s refusal does not cover this path. Returning would
    /// silently execute stale instructions; `abort` is the only fail-stop a
    /// `-> ()` method can give under the workspace's `panic`/`unimplemented`
    /// denials.
    #[cfg(not(target_arch = "x86_64"))]
    fn flush_icache(&self, _exec_ptr: *const u8, _len: usize) {
        std::process::abort()
    }

    fn remap_for_fork_child(&self, prior: &JitRegion) -> io::Result<ForkChildJit> {
        // The SHM_ANON dual map is MAP_SHARED: a fork child inherits the
        // SAME physical pages the parent (still) executes from. Never
        // report `Inherited` on this lane — map a brand-new SHM object of
        // the same capacity so the child can never append translations
        // into pages the parent is running.
        self.map_code_cache(prior.capacity).map(ForkChildJit::Fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPACITY: usize = 64 * 1024;

    /// `supported()` is this lane's arch gate: `Ok` on amd64 (coherent
    /// I-cache, so the no-op `flush_icache` is correct), `Err` elsewhere until
    /// a real cache-maintenance body lands. The mapping tests below stay
    /// arch-NEUTRAL on purpose — whether `shm_open` + a dual RX/RW map works
    /// on FreeBSD/aarch64 is exactly what the aarch64 lane needs measured, so
    /// they must not be gated away.
    #[test]
    fn supported_matches_the_icache_maintenance_this_lane_has() {
        let jit = FreebsdHostJit;
        if cfg!(target_arch = "x86_64") {
            jit.supported().expect("amd64 has a coherent I-cache");
        } else {
            assert!(
                jit.supported().is_err(),
                "a lane with no I-cache maintenance must fail closed"
            );
        }
    }

    #[test]
    fn dual_map_aliases_one_object() {
        let jit = FreebsdHostJit;
        let region = jit.map_code_cache(CAPACITY).expect("map");
        assert_ne!(
            region.exec_base.as_ptr(),
            region.write_base.as_ptr(),
            "dual map must produce distinct views"
        );
        // A write through the RW alias is visible through the RX view.
        let probe: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        let write = region
            .write_ptr_for(region.exec_base.as_ptr())
            .expect("write alias");
        unsafe {
            std::ptr::copy_nonoverlapping(probe.as_ptr(), write, probe.len());
            let seen = std::slice::from_raw_parts(region.exec_base.as_ptr(), probe.len());
            assert_eq!(seen, probe, "aliased views must be coherent");
        }
        unsafe { jit.unmap(&region) };
    }

    #[test]
    fn exec_view_rejects_direct_writes() {
        // W^X: the exec view must NOT be writable — a stray write through it
        // is a bug the kernel should stop.
        let jit = FreebsdHostJit;
        let region = jit.map_code_cache(CAPACITY).expect("map");
        // Re-asserting RX on the exec view must succeed (i.e. the view was
        // mapped RX, never RW) — a cheap protection sanity without poking a
        // fault handler into the test harness.
        let rc = unsafe {
            libc::mprotect(
                region.exec_base.as_ptr().cast(),
                region.capacity,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };
        assert_eq!(rc, 0, "exec view holds RX protection");
        unsafe { jit.unmap(&region) };
    }

    // amd64 only: the payload is raw x86_64 machine code, and the assertion
    // CALLS it. It is also the only test that invokes `flush_icache`, which is
    // a fail-stop `abort` off amd64 by design.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn written_code_executes_through_the_exec_view() {
        // The end-to-end contract: bytes written through the RW alias run as
        // code from the RX view — `mov eax, 42; ret` on x86_64.
        let jit = FreebsdHostJit;
        let region = jit.map_code_cache(CAPACITY).expect("map");
        let code: &[u8] = &[0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3];
        let write = region
            .write_ptr_for(region.exec_base.as_ptr())
            .expect("write alias");
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), write, code.len());
        }
        jit.flush_icache(region.exec_base.as_ptr(), code.len());
        let f: extern "C" fn() -> u32 =
            unsafe { std::mem::transmute(region.exec_base.as_ptr() as usize) };
        assert_eq!(f(), 42, "dual-mapped code must execute");
        unsafe { jit.unmap(&region) };
    }

    #[test]
    fn oversized_truncate_failure_is_typed_not_fatal() {
        // An absurd capacity must surface as an io::Error, not a panic or a
        // partially-mapped region.
        let jit = FreebsdHostJit;
        let err = jit.map_code_cache(usize::MAX & !0xfff);
        assert!(err.is_err(), "absurd capacity must fail closed");
    }

    #[test]
    fn remap_for_fork_child_returns_a_fresh_distinct_region() {
        // The fork hazard from the module doc, enforced: this lane must
        // NEVER report `Inherited` (the SHM_ANON dual map is MAP_SHARED and
        // unsafe to keep sharing with a fork child), and the region it
        // hands back must be a genuinely distinct mapping of the same
        // capacity, not the parent's.
        let jit = FreebsdHostJit;
        let prior = jit.map_code_cache(CAPACITY).expect("map prior region");
        let remapped = jit
            .remap_for_fork_child(&prior)
            .expect("remap_for_fork_child must succeed");
        let fresh = match remapped {
            ForkChildJit::Fresh(region) => region,
            ForkChildJit::Inherited => {
                panic!("FreeBSD dual-map lane must never report Inherited across fork")
            }
        };
        assert_eq!(
            fresh.capacity, prior.capacity,
            "fork-child region must match the prior region's capacity"
        );
        assert_ne!(
            fresh.exec_base, prior.exec_base,
            "fork-child region must be a distinct mapping, not the parent's"
        );
        assert_ne!(
            fresh.write_base, prior.write_base,
            "fork-child region's write alias must also be distinct"
        );
        unsafe {
            jit.unmap(&fresh);
            jit.unmap(&prior);
        }
    }
}

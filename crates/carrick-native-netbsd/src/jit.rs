//! Dual-mapped W^X JIT code cache for NetBSD/amd64.
//!
//! Like FreeBSD, NetBSD has no Darwin `MAP_JIT`/per-thread write-protect
//! toggle, and `mprotect` RW↔RX flips would be PROCESS-wide — a writer would
//! yank X from under concurrently-executing guest threads (the `_lwp_create`
//! grounding probe confirmed NetBSD threads share one address space). Unlike
//! FreeBSD, NetBSD has **no `SHM_ANON`** (Task-0 grounding, §1: `grep SHM_ANON
//! /usr/include/sys/mman.h` → no match). So the anonymous backing object is
//! emulated by a uniquely-**named** `shm_open` that is `shm_unlink`ed
//! immediately — the object then lives only through its open fd and mappings,
//! and the name is gone, making it effectively anonymous:
//!
//! ```text
//!   shm_open("/carrick-jit-<pid>-<n>", O_RDWR|O_CREAT|O_EXCL)
//!        ── ftruncate(capacity) ── shm_unlink(name)   // now anonymous
//!        ├── mmap(PROT_READ|PROT_EXEC,  MAP_SHARED)  → JitRegion.exec_base
//!        └── mmap(PROT_READ|PROT_WRITE, MAP_SHARED)  → JitRegion.write_base
//! ```
//!
//! Writers write through the RW alias (`JitRegion::write_ptr_for`), executors
//! run the RX alias, no protection ever flips, and `begin/end_thread_write`
//! are no-ops.
//!
//! ## `flush_icache` is arch-shaped, and fails closed off amd64
//!
//! On **x86_64** `flush_icache` is a no-op, and that is CORRECT: x86 has a
//! coherent instruction cache (cross-modifying-code ORDERING at live patch
//! sites is the x86 arch crate's contract at its patch encodings, not a
//! flush). The mapping machinery around it is arch-neutral (`shm_open` +
//! `shm_unlink` + two `mmap`s), so it stays compiled on every NetBSD arch.
//!
//! That asymmetry was a live silent-corruption trap: the no-op was gated on
//! `target_os` alone, so a NetBSD/**aarch64** build would resolve to it and
//! execute STALE instructions after publishing code (the equivalent failure
//! was measured on freebsd-arm64 during the aarch64 lane scout). AArch64
//! needs real `__clear_cache`-style maintenance, which this crate does not
//! have yet.
//!
//! So off amd64 this lane refuses instead of pretending, at both reachable
//! entries:
//!
//! * [`NativeHostJit::supported`] returns `Err`, so `TranslationCache::new`
//!   gets a typed cache-policy error before a single byte is mapped.
//! * `flush_icache` **aborts**. It returns `()` — it has no error channel —
//!   and it is reachable WITHOUT any mapped code cache:
//!   `carrick-dsr-aarch64`'s `mapped_memory::native_clear_icache` publishes
//!   GUEST exec pages through `installed_host_jit()`, which `supported()`'s
//!   refusal does not gate. Returning normally would claim coherence that
//!   does not exist; fail-stop is the only honest answer a `-> ()` method can
//!   give under the workspace's `panic`/`unimplemented` denials.
//!
//! Both arms disappear the moment a real aarch64 flush lands here.
//!
//! ## Fork hazard — CLOSED, enforced by `remap_for_fork_child`
//!
//! A `MAP_SHARED` dual map is SHARED with a fork child: a child that APPENDS
//! translations would write the same physical pages the parent executes. The
//! Task-0 grounding probe (`jit_probe.c`) proved this on NetBSD 10.1 — a fork
//! child writing through the INHERITED RW alias corrupted the parent's exec
//! view (`RX` returned the child's byte), and a child that mapped its OWN
//! fresh object left the parent untouched. So this lane answers the host seam
//! [`NativeHostJit::remap_for_fork_child`] with `Ok(ForkChildJit::Fresh(..))`
//! — a brand-new named-shm object of the same capacity, never the inherited
//! one — exactly mirroring `FreebsdHostJit`. Fork repair is entirely REGION
//! REPLACEMENT; there is no in-place protection-state repair (no MAP_JIT
//! toggle on this lane).

use std::io;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_dsr::host::{ForkChildJit, JitRegion, NativeHostJit};

/// Stateless dual-map JIT backend (all state lives in the [`JitRegion`]).
pub struct NetbsdHostJit;

/// Monotone counter giving each named-shm object a distinct name within this
/// process. Combined with the caller's live pid (which differs between a fork
/// parent and child), this makes the `O_EXCL` create collision-free without
/// coordination across the fork boundary.
static JIT_SHM_COUNTER: AtomicU64 = AtomicU64::new(0);

const SHM_NAME_PREFIX: &[u8] = b"/carrick-jit-";

/// Write `value` in decimal into `buf` (big-endian digit order) and return the
/// number of bytes written. Allocation-free (a fixed scratch buffer) so the
/// whole `shm_named_fd` path is safe to run in a fork child of a possibly
/// multi-threaded process.
fn write_decimal(buf: &mut [u8], mut value: u64) -> usize {
    let mut scratch = [0u8; 20]; // u64::MAX is 20 digits.
    let mut n = 0;
    loop {
        scratch[n] = b'0' + (value % 10) as u8;
        value /= 10;
        n += 1;
        if value == 0 {
            break;
        }
    }
    for (i, slot) in buf.iter_mut().take(n).enumerate() {
        *slot = scratch[n - 1 - i];
    }
    n
}

/// Format `"/carrick-jit-<pid>-<counter>\0"` into `buf` and return the byte
/// length (excluding the terminating NUL, which is the pre-zeroed slot at
/// `buf[len]`). No heap allocation — see [`write_decimal`].
fn format_shm_name(buf: &mut [u8; 64], pid: libc::pid_t, counter: u64) -> usize {
    let mut pos = 0;
    for &byte in SHM_NAME_PREFIX {
        buf[pos] = byte;
        pos += 1;
    }
    pos += write_decimal(&mut buf[pos..], pid as u64);
    buf[pos] = b'-';
    pos += 1;
    pos += write_decimal(&mut buf[pos..], counter);
    pos
}

/// Open an anonymous-via-unlink named shm object of `capacity` bytes and
/// return its fd. NetBSD lacks `SHM_ANON`, so a uniquely-named object is
/// created with `O_EXCL`, sized with `ftruncate`, then `shm_unlink`ed so no
/// name survives — the object persists solely through this fd and the maps the
/// caller creates from it.
///
/// This path performs NO heap allocation on the success path, so it is safe to
/// call from a fork child (where the heap allocator lock could be held by
/// another thread).
fn shm_named_fd(capacity: usize) -> io::Result<libc::c_int> {
    // SAFETY: getpid is always safe.
    let pid = unsafe { libc::getpid() };
    // A name clash is astronomically unlikely (per-process counter + pid), but
    // O_EXCL makes it observable rather than a silent alias; bound the retry.
    for _ in 0..1024 {
        let counter = JIT_SHM_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut name = [0u8; 64];
        let _len = format_shm_name(&mut name, pid, counter);
        // SAFETY: `name` is a NUL-terminated C string in a stack buffer;
        // O_CREAT|O_EXCL creates a fresh object or fails with EEXIST.
        let fd = unsafe {
            libc::shm_open(
                name.as_ptr().cast::<libc::c_char>(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(error);
        }
        // SAFETY: fd is a valid shm fd we exclusively own.
        if unsafe { libc::ftruncate(fd, capacity as libc::off_t) } != 0 {
            let error = io::Error::last_os_error();
            // Drop both the name and the object on the sizing-failure path.
            // SAFETY: `name` still names the object; fd is ours.
            unsafe {
                libc::shm_unlink(name.as_ptr().cast::<libc::c_char>());
                libc::close(fd);
            }
            return Err(error);
        }
        // Unlink immediately: the object survives via this fd and the maps the
        // caller is about to create, so it is now effectively anonymous.
        // SAFETY: `name` names the object we just created and sized.
        unsafe { libc::shm_unlink(name.as_ptr().cast::<libc::c_char>()) };
        return Ok(fd);
    }
    Err(io::Error::other(
        "shm_open: exhausted unique JIT name attempts",
    ))
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
    // SAFETY: fd is a valid shm object of at least `capacity` bytes; a
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

impl NativeHostJit for NetbsdHostJit {
    fn supported(&self) -> Result<(), &'static str> {
        // Dual mapping needs nothing exotic; a W^X-hardened kernel that
        // refuses PROT_EXEC shm mappings surfaces at map_code_cache as a
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
                "NetBSD native host JIT: no I-cache maintenance on this arch \
                 (flush_icache needs a real __clear_cache body before an \
                 aarch64 lane may publish code)",
            )
        }
    }

    fn map_code_cache(&self, capacity: usize) -> io::Result<JitRegion> {
        let fd = shm_named_fd(capacity)?;
        let exec_base = match map_shared(fd, capacity, libc::PROT_READ | libc::PROT_EXEC) {
            Ok(mapping) => mapping,
            Err(error) => {
                // SAFETY: `fd` is the still-private shm descriptor.
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
        // The object lives as long as its mappings; the fd is not needed after
        // both views exist (and must not leak into guests).
        // SAFETY: fd is ours; mappings keep the shm object alive.
        unsafe { libc::close(fd) };
        Ok(JitRegion {
            exec_base,
            write_base,
            capacity,
        })
    }

    unsafe fn unmap(&self, region: &JitRegion) {
        // SAFETY: caller contract — no thread executes from or holds pointers
        // into either view.
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
        // The named-shm dual map is MAP_SHARED: a fork child inherits the SAME
        // physical pages the parent (still) executes from. Never report
        // `Inherited` on this lane — map a brand-new shm object of the same
        // capacity so the child can never append translations into pages the
        // parent is running (Task-0 `jit_probe.c` proof).
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
    /// on NetBSD/aarch64 (where PaX MPROTECT pins each mapping's maxprot at
    /// `mmap` time) is exactly what the aarch64 lane needs measured, so they
    /// must not be gated away.
    #[test]
    fn supported_matches_the_icache_maintenance_this_lane_has() {
        let jit = NetbsdHostJit;
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
    fn shm_name_formats_without_heap() {
        let mut buf = [0u8; 64];
        let len = format_shm_name(&mut buf, 4321, 7);
        assert_eq!(&buf[..len], b"/carrick-jit-4321-7");
        assert_eq!(buf[len], 0, "name is NUL-terminated in place");
    }

    #[test]
    fn dual_map_aliases_one_object() {
        let jit = NetbsdHostJit;
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
        // W^X: the exec view must NOT be writable — a stray write through it is
        // a bug the kernel should stop. Re-asserting RX on the exec view must
        // succeed (i.e. the view was mapped RX, never RW) — a cheap protection
        // sanity without poking a fault handler into the test harness.
        let jit = NetbsdHostJit;
        let region = jit.map_code_cache(CAPACITY).expect("map");
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
    // CALLS it. It is also one of only two tests that invoke `flush_icache`,
    // which is a fail-stop `abort` off amd64 by design.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn written_code_executes_through_the_exec_view() {
        // The end-to-end contract: bytes written through the RW alias run as
        // code from the RX view — `mov eax, 42; ret` on x86_64.
        let jit = NetbsdHostJit;
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
        let jit = NetbsdHostJit;
        let err = jit.map_code_cache(usize::MAX & !0xfff);
        assert!(err.is_err(), "absurd capacity must fail closed");
    }

    #[test]
    fn remap_for_fork_child_returns_a_fresh_distinct_region() {
        // The fork hazard from the module doc, enforced at the seam: this lane
        // must NEVER report `Inherited` (the named-shm dual map is MAP_SHARED
        // and unsafe to keep sharing with a fork child), and the region it
        // hands back must be a genuinely distinct mapping of the same capacity.
        let jit = NetbsdHostJit;
        let prior = jit.map_code_cache(CAPACITY).expect("map prior region");
        let remapped = jit
            .remap_for_fork_child(&prior)
            .expect("remap_for_fork_child must succeed");
        let fresh = match remapped {
            ForkChildJit::Fresh(region) => region,
            ForkChildJit::Inherited => {
                panic!("NetBSD dual-map lane must never report Inherited across fork")
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

    // amd64 only: the parent and child both write raw x86_64 machine code and
    // CALL it, and the test flushes the I-cache on both sides.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn fork_child_fresh_region_does_not_corrupt_parent_exec() {
        // The Task-0 `jit_probe.c` proof, now as a Rust unit test with a REAL
        // fork. The parent publishes `mov eax, 0x11; ret`. A fork child obtains
        // its Fresh region from `remap_for_fork_child`, writes a DIFFERENT
        // function (`mov eax, 0x22; ret`) into it, and executes it. Because the
        // child's region is a brand-new shm object (a MAP_SHARED dual map is
        // inherited-shared across fork — writing the INHERITED one would clobber
        // the parent's live code), the parent's exec view still returns 0x11
        // after the child exits.
        let jit = NetbsdHostJit;
        let parent = jit.map_code_cache(CAPACITY).expect("map parent region");
        let parent_code: &[u8] = &[0xb8, 0x11, 0x00, 0x00, 0x00, 0xc3]; // mov eax,0x11; ret
        let parent_write = parent
            .write_ptr_for(parent.exec_base.as_ptr())
            .expect("parent write alias");
        unsafe {
            std::ptr::copy_nonoverlapping(parent_code.as_ptr(), parent_write, parent_code.len());
        }
        let parent_fn: extern "C" fn() -> u32 =
            unsafe { std::mem::transmute(parent.exec_base.as_ptr() as usize) };
        assert_eq!(parent_fn(), 0x11, "parent code must run before fork");

        // SAFETY: the child touches only the allocation-free JIT map path and
        // `_exit`; it never unwinds, allocates, or takes a lock that another
        // test-harness thread could hold at fork time.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let status = match jit.remap_for_fork_child(&parent) {
                Ok(ForkChildJit::Fresh(region)) => {
                    let code: &[u8] = &[0xb8, 0x22, 0x00, 0x00, 0x00, 0xc3]; // mov eax,0x22; ret
                    match region.write_ptr_for(region.exec_base.as_ptr()) {
                        Some(write) => {
                            unsafe {
                                std::ptr::copy_nonoverlapping(code.as_ptr(), write, code.len());
                            }
                            let f: extern "C" fn() -> u32 =
                                unsafe { std::mem::transmute(region.exec_base.as_ptr() as usize) };
                            if f() == 0x22 { 0 } else { 10 }
                        }
                        None => 11,
                    }
                }
                Ok(ForkChildJit::Inherited) => 12, // must never happen on this lane
                Err(_) => 13,
            };
            // SAFETY: _exit is async-signal-safe; never unwind out of a fork child.
            unsafe { libc::_exit(status) };
        }

        let mut status: libc::c_int = 0;
        // SAFETY: reap the specific child we just forked.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid must reap the child");
        assert!(libc::WIFEXITED(status), "child exited normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child must run its own Fresh 0x22 region (see in-test status codes for the failure mode)"
        );
        assert_eq!(
            parent_fn(),
            0x11,
            "parent exec bytes must be untouched by the fork child's Fresh region"
        );
        unsafe { jit.unmap(&parent) };
    }
}

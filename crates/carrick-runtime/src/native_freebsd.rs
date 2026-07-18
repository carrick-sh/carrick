//! The FreeBSD/amd64 native (DSR) execution driver.
//!
//! This is the x86 sibling of the aarch64/Darwin native driver
//! (`native_darwin.rs`): it EXECUTES a static Linux x86_64 ELF as host-native
//! code through the `carrick-dsr-x86` gateway and services its Linux syscalls
//! through the SHARED, backend-neutral [`SyscallDispatcher`] — the exact
//! dispatcher the bhyve/KVM/NVMM x86 VMM lanes feed. The lane reuses, rather
//! than reimplements, the syscall machinery:
//!
//! - guest memory is an IDENTITY map (guest VA == host VA), so
//!   [`IdentityGuestMemory`] satisfies [`GuestMemory`] with plain host
//!   reads/writes;
//! - a `syscall` gateway exit is adapted into the SAME
//!   [`carrick_hal::RawSyscall`] the VMM engine produces, via
//!   [`X8664GuestArch::normalize_syscall`] (rax + rdi/rsi/rdx/r10/r8/r9,
//!   fork/vfork/poll/select desugaring, arch_prctl split);
//! - `arch_prctl(ARCH_SET_FS)` sets the gateway's `guest_fsbase` (the x86
//!   analog of the aarch64 TPIDR handling) instead of touching VMM state.
//!
//! Scope (first M2-runtime rung): a SINGLE-THREADED static binary. Threads,
//! fork/clone, the blocking-wait outcomes (`WaitOnFds`/…), and the full
//! signal machinery are the next rungs; this driver services the
//! straight-line + returned/errno/exit dispatch outcomes and surfaces the
//! rest as a typed error rather than guessing. Guest faults become typed
//! `Signal` gateway exits via `carrick-native-freebsd`'s shim.
#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]

use std::path::Path;
use std::sync::Arc;

use carrick_dsr::host::{JitRegion, NativeHostJit};
use carrick_dsr_x86::block::{X86Block, X86Exit};
use carrick_dsr_x86::decode::{X86InstClass, classify};
use carrick_dsr_x86::gateway::{CTX_FAULT_RECORD, reg, signal_stub_addr};
use carrick_dsr_x86::{
    X86DsrContext, X86ExitStatus, X86UcontextSnapshot, cflow, emit::emit_block_linked, plan_block,
};
use carrick_guest_mem::{GuestMemory, X8664SyscallFrame};
use carrick_hal::x8664_arch::{SyscallNorm, X8664GuestArch};
use carrick_native_freebsd::{FreebsdHostJit, fault};
use goblin::elf::Elf;
use goblin::elf::program_header::PT_LOAD;

use carrick_mem::memory::{LINUX_HEAP_BASE, LINUX_HEAP_SIZE, LINUX_MMAP_BASE, mmap_arena_size};

use crate::compat::{CompatReport, CompatReporter};
use crate::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};
use crate::run_result::{RunResult, RuntimeError};

/// The guest brk-heap and mmap arenas, reserved as real host backing at the
/// dispatcher's fixed layout addresses (`MemoryLayout::hvf_default`: heap at
/// 384-ish GiB, mmap arena at 384 GiB). The dispatcher's `brk`/`mmap`
/// handlers hand out addresses INSIDE these arenas and expect the
/// `GuestMemory` to have backing there (`brk` only moves a pointer; `mmap`
/// zeroes the new region THROUGH the memory). In the identity model that
/// backing is real host pages at the same VA. FreeBSD overcommits anonymous
/// RW maps (pages commit on first touch), so reserving the full 32 GiB mmap
/// arena is cheap. A guest `mmap(PROT_NONE)` guard page reads back as zero
/// rather than faulting — a fidelity gap, not a crash; enforcing guest-visible
/// per-page protection is a later rung.
struct GuestArenas {
    heap: u64,
    heap_len: usize,
    mmap: u64,
    mmap_len: usize,
}

impl GuestArenas {
    fn reserve() -> Result<Self, RuntimeError> {
        let heap_len = LINUX_HEAP_SIZE as usize;
        let mmap_len = mmap_arena_size() as usize;
        let heap = reserve_fixed_rw(LINUX_HEAP_BASE, heap_len).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "reserve guest heap arena at 0x{LINUX_HEAP_BASE:x} ({heap_len} bytes) failed"
            ))
        })?;
        let mmap = match reserve_fixed_rw(LINUX_MMAP_BASE, mmap_len) {
            Some(a) => a,
            None => {
                // SAFETY: unmapping the heap arena we just reserved.
                unsafe { libc::munmap(heap as *mut libc::c_void, heap_len) };
                return Err(RuntimeError::Unsupported(format!(
                    "reserve guest mmap arena at 0x{LINUX_MMAP_BASE:x} ({mmap_len} bytes) failed"
                )));
            }
        };
        Ok(Self {
            heap,
            heap_len,
            mmap,
            mmap_len,
        })
    }

    fn teardown(&self) {
        // SAFETY: unmapping the arenas this struct reserved.
        unsafe {
            libc::munmap(self.heap as *mut libc::c_void, self.heap_len);
            libc::munmap(self.mmap as *mut libc::c_void, self.mmap_len);
        }
    }
}

/// Reserve `[base, base+len)` as anonymous RW at EXACTLY `base` (MAP_FIXED).
/// Returns `None` if the kernel could not place it there.
fn reserve_fixed_rw(base: u64, len: usize) -> Option<u64> {
    let p = map_prot(len, libc::PROT_READ | libc::PROT_WRITE, Some(base));
    if p as isize == -1 || p as u64 != base {
        None
    } else {
        Some(p as u64)
    }
}

/// `ARCH_SET_FS` (arch_prctl(2)) — the musl/glibc TLS thread-pointer set.
const ARCH_SET_FS: u64 = 0x1002;
/// `ARCH_SET_GS`.
const ARCH_SET_GS: u64 = 0x1001;
/// `ARCH_GET_FS`.
const ARCH_GET_FS: u64 = 0x1003;
/// `ARCH_GET_GS`.
const ARCH_GET_GS: u64 = 0x1004;
/// `EINVAL`, as a negated Linux errno return.
const NEG_EINVAL: i64 = -22;

/// A guest address space where guest VA == host VA: `GuestMemory` reads and
/// writes are plain host memory accesses at the guest address. The native
/// model maps the guest image and every guest mapping into THIS process's
/// address space, so no translation is needed. Out-of-bounds/unmapped guest
/// pointers are not gated here — a bad pointer faults, and the fault shim
/// turns an in-JIT fault into a typed Signal exit (a syscall-path bad pointer
/// is a genuine EFAULT the handlers surface).
struct IdentityGuestMemory;

impl GuestMemory for IdentityGuestMemory {
    fn read_bytes_raw(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        // SAFETY: identity map — `address` is a host VA. A length-0 read is a
        // no-op; otherwise the caller asserts the range is guest-mapped.
        Ok(unsafe { std::slice::from_raw_parts(address as *const u8, length).to_vec() })
    }

    fn write_bytes_raw(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        // SAFETY: identity map — `address` is a host VA into a guest-writable
        // mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
        }
        Ok(())
    }
}

/// A loaded static-pie ELF in the host address space (guest VA == host VA).
struct LoadedImage {
    span_base: u64,
    span_len: usize,
    entry: u64,
    stack: u64,
    stack_len: usize,
    rsp: u64,
    /// Kept mapped for the lifetime of the run (argv/AT_RANDOM scratch).
    scratch: u64,
    scratch_len: usize,
    /// The page-rounded [start, end) VA ranges of the mapped PT_LOAD segments,
    /// sorted and coalesced. The reserved span can contain UNMAPPED gaps
    /// between segments; the block planner must not read across one (it would
    /// fault or decode garbage), so `code_bytes` reads only up to the end of
    /// the range containing a VA.
    segments: Vec<(u64, u64)>,
}

impl LoadedImage {
    /// Up to 16 guest code bytes at `va`, bounded to the END of the mapped
    /// segment containing `va` — so a read never crosses an unmapped gap.
    /// Empty when `va` is not in any mapped segment (a guest that jumped off
    /// mapped code).
    fn code_bytes(&self, va: u64) -> &[u8] {
        for &(start, end) in &self.segments {
            if va >= start && va < end {
                let hi = (va + 16).min(end);
                // SAFETY: [va, hi) is inside a mapped segment (guest VA == host VA).
                return unsafe { std::slice::from_raw_parts(va as *const u8, (hi - va) as usize) };
            }
        }
        &[]
    }
}

impl LoadedImage {
    /// Unmap everything the loader mapped.
    fn teardown(&self) {
        // SAFETY: teardown of mappings this loader owns; nothing executes from
        // them once the run loop has returned.
        unsafe {
            libc::munmap(self.span_base as *mut libc::c_void, self.span_len);
            libc::munmap(self.stack as *mut libc::c_void, self.stack_len);
            libc::munmap(self.scratch as *mut libc::c_void, self.scratch_len);
        }
    }
}

const PAGE: u64 = 4096;
const GUEST_STACK_LEN: usize = 8 * 1024 * 1024;

fn map_prot(len: usize, prot: i32, fixed_at: Option<u64>) -> *mut u8 {
    let (addr, flags) = match fixed_at {
        Some(a) => (
            a as *mut libc::c_void,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
        ),
        None => (std::ptr::null_mut(), libc::MAP_PRIVATE | libc::MAP_ANON),
    };
    // SAFETY: an anonymous mapping request we own.
    unsafe { libc::mmap(addr, len, prot, flags, -1, 0) }.cast()
}

/// Map a static-pie ELF at a load bias so guest VA == host VA. Reserves the
/// whole v-span (kernel picks the bias), maps each PT_LOAD with MAP_FIXED, and
/// copies the file bytes. The fixture/probe ELFs carry only R_X86_64_RELATIVE
/// (or none); this first rung requires a no-reloc / RELATIVE-only image and
/// applies RELATIVE relocations against the bias.
fn load_static_pie(bytes: &[u8], argv: &[String]) -> Result<LoadedImage, RuntimeError> {
    let elf =
        Elf::parse(bytes).map_err(|e| RuntimeError::Unsupported(format!("parse ELF: {e}")))?;
    if !elf.is_64 {
        return Err(RuntimeError::Unsupported(
            "native x86 lane requires a 64-bit ELF".to_string(),
        ));
    }

    let mut lo = u64::MAX;
    let mut hi = 0u64;
    for ph in &elf.program_headers {
        if ph.p_type == PT_LOAD {
            lo = lo.min(ph.p_vaddr & !(PAGE - 1));
            hi = hi.max((ph.p_vaddr + ph.p_memsz + PAGE - 1) & !(PAGE - 1));
        }
    }
    if lo == u64::MAX {
        return Err(RuntimeError::Unsupported(
            "ELF has no PT_LOAD segments".to_string(),
        ));
    }
    let span_len = (hi - lo) as usize;

    let span = map_prot(span_len, libc::PROT_NONE, None);
    // mmap signals failure with MAP_FAILED ((void*)-1), never NULL.
    if span as isize == -1 {
        return Err(RuntimeError::Unsupported(
            "reserve guest span failed".to_string(),
        ));
    }
    let bias = span as u64 - lo;
    let mut segments: Vec<(u64, u64)> = Vec::new();

    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        let seg_lo = (ph.p_vaddr & !(PAGE - 1)) + bias;
        let seg_hi = ((ph.p_vaddr + ph.p_memsz + PAGE - 1) & !(PAGE - 1)) + bias;
        segments.push((seg_lo, seg_hi));
        // The translator READS guest code (execution runs from the JIT cache),
        // so no host PROT_EXEC is needed; every segment is mapped R + W so its
        // file bytes and the guest's own writes land. (Enforcing per-segment
        // read-only protection is a later rung; it does not affect correctness
        // of the identity model, only guest-visible write faults.)
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let addr = map_prot((seg_hi - seg_lo) as usize, prot, Some(seg_lo));
        if addr as u64 != seg_lo {
            return Err(RuntimeError::Unsupported(format!(
                "MAP_FIXED segment at 0x{seg_lo:x} failed"
            )));
        }
        let dst = (ph.p_vaddr + bias) as *mut u8;
        let src = &bytes[ph.p_offset as usize..(ph.p_offset + ph.p_filesz) as usize];
        // SAFETY: dst is inside the just-mapped RW segment; src is in-bounds.
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
    }

    // Apply R_X86_64_RELATIVE relocations (type 8): *(base+off) = base+addend.
    // Any other relocation type means a dynamic image this first rung does not
    // support — fail closed rather than run miscomputed addresses.
    const R_X86_64_RELATIVE: u32 = 8;
    for rela in elf.dynrelas.iter() {
        if rela.r_type != R_X86_64_RELATIVE {
            return Err(RuntimeError::Unsupported(format!(
                "native x86 lane: unsupported dynamic relocation type {} (only R_X86_64_RELATIVE)",
                rela.r_type
            )));
        }
        let where_ = rela.r_offset + bias;
        let value = bias.wrapping_add(rela.r_addend.unwrap_or(0) as u64);
        // SAFETY: the reloc offset is inside a mapped RW segment.
        unsafe { (where_ as *mut u64).write_unaligned(value) };
    }

    let stack = map_prot(GUEST_STACK_LEN, libc::PROT_READ | libc::PROT_WRITE, None);
    if stack as isize == -1 {
        return Err(RuntimeError::Unsupported(
            "guest stack mmap failed".to_string(),
        ));
    }
    let scratch = map_prot(PAGE as usize, libc::PROT_READ | libc::PROT_WRITE, None);

    let rsp = build_initial_stack(
        stack as u64 + GUEST_STACK_LEN as u64,
        scratch as u64,
        argv,
        &elf,
        bias,
    );

    // Sort + coalesce adjacent segments so `code_bytes` can read across
    // touching PT_LOADs but never across a real gap.
    segments.sort_unstable();
    let mut coalesced: Vec<(u64, u64)> = Vec::with_capacity(segments.len());
    for (s, e) in segments {
        match coalesced.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => coalesced.push((s, e)),
        }
    }

    Ok(LoadedImage {
        span_base: span as u64,
        span_len,
        entry: elf.entry + bias,
        stack: stack as u64,
        stack_len: GUEST_STACK_LEN,
        rsp,
        scratch: scratch as u64,
        scratch_len: PAGE as usize,
        segments: coalesced,
    })
}

/// Build the Linux x86_64 initial stack:
/// `[argc][argv..][NULL][envp NULL][auxv..][AT_NULL]`, with argv strings and a
/// 16-byte AT_RANDOM block in the scratch page. Returns the guest rsp (argc),
/// 16-aligned. Envp is empty in this first rung.
fn build_initial_stack(stack_top: u64, scratch: u64, argv: &[String], elf: &Elf, bias: u64) -> u64 {
    const AT_NULL: u64 = 0;
    const AT_PHDR: u64 = 3;
    const AT_PHENT: u64 = 4;
    const AT_PHNUM: u64 = 5;
    const AT_PAGESZ: u64 = 6;
    const AT_ENTRY: u64 = 9;
    const AT_RANDOM: u64 = 25;

    // Lay argv strings + AT_RANDOM into the scratch page.
    let mut cur = scratch;
    let random_ptr = cur;
    // 16 pseudo-random bytes (fixed here; a later rung seeds from the host).
    // SAFETY: scratch is a mapped RW page with room for these small writes.
    unsafe {
        std::ptr::write_bytes(random_ptr as *mut u8, 0x5a, 16);
    }
    cur += 16;
    let mut arg_ptrs = Vec::with_capacity(argv.len());
    for a in argv {
        let bytes = a.as_bytes();
        // SAFETY: within the scratch page (argv for a probe is tiny).
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), cur as *mut u8, bytes.len());
            *((cur + bytes.len() as u64) as *mut u8) = 0;
        }
        arg_ptrs.push(cur);
        cur += bytes.len() as u64 + 1;
    }

    let phdr_va = elf.header.e_phoff + bias;

    // Build the stack image bottom-up as a word vector, then place it so argc
    // lands 16-aligned.
    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64); // argc
    words.extend(arg_ptrs.iter().copied()); // argv[]
    words.push(0); // argv NULL
    words.push(0); // envp NULL
    // auxv pairs
    for (k, v) in [
        (AT_PHDR, phdr_va),
        (AT_PHENT, elf.header.e_phentsize as u64),
        (AT_PHNUM, elf.header.e_phnum as u64),
        (AT_PAGESZ, PAGE),
        (AT_ENTRY, elf.entry + bias),
        (AT_RANDOM, random_ptr),
        (AT_NULL, 0),
    ] {
        words.push(k);
        words.push(v);
    }

    let bytes = (words.len() * 8) as u64;
    // 16-align argc; the ABI wants (rsp) 16-aligned at _start.
    let rsp = (stack_top - bytes) & !0xf;
    for (i, w) in words.iter().enumerate() {
        // SAFETY: within the guest stack mapping.
        unsafe { ((rsp + (i as u64) * 8) as *mut u64).write(*w) };
    }
    rsp
}

/// The result of running one translated block through the gateway: where to go
/// next, or a terminal signal.
enum Step {
    Continue(u64),
    Exit(i32),
    Fault(String),
    /// A `fork()` just made THIS process a fork child (guest `rax` already set
    /// to 0). The run loop marks itself a descendant so its eventual exit
    /// `_exit`s directly (reaped by the parent's `wait4`) instead of returning
    /// a `RunResult` up through `native_run`.
    BecameForkChild(u64),
}

/// A minimal multiply-based hasher for the guest-VA block cache. The default
/// `HashMap` uses SipHash (DoS-resistant but slow), and an lldb backtrace of a
/// hot guest loop showed SipHash dominating — the cache is looked up once per
/// block per iteration, millions of times. The keys are our OWN guest VAs (no
/// adversarial input), so a single FxHash-style multiply is both correct and
/// far cheaper. Only `write_u64` is exercised (u64 keys); other inputs fold in
/// byte-wise so the impl is still a valid `Hasher`.
#[derive(Default)]
struct VaHasher(u64);

impl std::hash::Hasher for VaHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }
    fn write_u64(&mut self, value: u64) {
        // FxHash's rotate-xor-multiply step (rustc's `rustc-hash`).
        const K: u64 = 0x51_7c_c1_b7_27_22_0a_95;
        self.0 = (self.0.rotate_left(5) ^ value).wrapping_mul(K);
    }
}

type VaBuildHasher = std::hash::BuildHasherDefault<VaHasher>;

/// Patch a chainable branch's 5-byte `jmp` slot to jump straight to a
/// translated successor block. `patch_abs` is the exec-alias address of the
/// slot's 4-byte `rel32` field; `next_abs` is the address just after it (the
/// jmp's own next-instruction address the rel32 is relative to); `target_exec`
/// is the successor's exec VA. Both endpoints live in the <4 MiB JIT cache, so
/// the displacement always fits `i32`. The write goes through the region's RW
/// alias (the exec alias is not writable).
fn patch_slot(
    region: &JitRegion,
    jit: &FreebsdHostJit,
    patch_abs: u64,
    next_abs: u64,
    target_exec: u64,
) {
    let rel = (target_exec as i64 - next_abs as i64) as i32;
    if let Some(w) = region.write_ptr_for(patch_abs as *mut u8) {
        // SAFETY: `w` is the RW alias of the 4-byte rel32 field inside the JIT.
        unsafe { std::ptr::copy_nonoverlapping(rel.to_le_bytes().as_ptr(), w, 4) };
        jit.flush_icache(patch_abs as *mut u8, 4);
    }
}

/// Serializes in-process runs. This driver mutates PROCESS-GLOBAL state — the
/// fixed guest arenas (MAP_FIXED at the layout addresses) and the process-wide
/// fault-redirect sigaction/code-region registration — so two concurrent runs
/// in one process would clobber each other's arenas and fault state. Real
/// usage forks a process per guest (single run per process); the lock makes
/// the in-process case (e.g. parallel test threads) safe by serializing.
static RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run a static x86_64 Linux ELF natively on FreeBSD/amd64 through the shared
/// dispatcher. The `dispatcher` is fully constructed by the caller (rootfs,
/// fd table, identity, container policy) exactly as the VMM path receives it.
pub(crate) fn run_static_x86_elf<A, E>(
    path: &Path,
    mut dispatcher: SyscallDispatcher,
    argv: A,
    _env: E,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    // Held for the whole run: the fixed arenas and the process-wide fault
    // shim cannot be shared across concurrent in-process runs.
    let _run_guard = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let argv: Vec<String> = argv.into_iter().collect();
    let bytes = std::fs::read(path)
        .map_err(|e| RuntimeError::Unsupported(format!("read {}: {e}", path.display())))?;
    let image = load_static_pie(&bytes, &argv)?;

    let jit = FreebsdHostJit;
    jit.supported()
        .map_err(|e| RuntimeError::Unsupported(format!("host JIT unsupported: {e:?}")))?;
    let region = jit
        .map_code_cache(4 * 1024 * 1024)
        .map_err(|e| RuntimeError::Unsupported(format!("map code cache: {e:?}")))?;

    fault::install_fault_redirect(signal_stub_addr(), CTX_FAULT_RECORD)
        .map_err(|e| RuntimeError::Unsupported(format!("install fault redirect: {e}")))?;
    fault::register_code_region(region.exec_base.as_ptr() as u64, 4 * 1024 * 1024);

    // Back the guest brk-heap and mmap arenas with real host pages at the
    // dispatcher's fixed layout addresses, so `brk`/`mmap` (which move a
    // pointer / zero a region THROUGH the memory) resolve onto live backing
    // instead of faulting the host.
    let arenas = GuestArenas::reserve()?;

    let reporter = Arc::new(CompatReporter::default());
    let tid = crate::thread::ThreadId::main_from_host_pid();
    let mut memory = IdentityGuestMemory;
    // The single-threaded blocking-I/O waiter (fd wait / poll / select / sleep
    // / blocking write), shared with the KVM/bhyve single-thread loop.
    let mut waiter = crate::io_wait::ThreadWaiter::new(tid);

    // All guest-code reads go through the segment-aware `image.code_bytes`,
    // which never crosses an unmapped gap between PT_LOAD segments.
    let read_guest = |va: u64| -> Vec<u8> { image.code_bytes(va).to_vec() };
    // Read the full body of a block. A block is planned within one segment, so
    // reading up to that segment's end (via repeated 16-byte-bounded reads
    // would be O(n); instead read the one contiguous run) is safe. `code_bytes`
    // is segment-bounded, so extend from `base` across the block by reading the
    // segment run that contains it.
    let read_block = |block: &X86Block| -> Vec<u8> {
        let base = block.start;
        let want = block.end.max(block.exit.va());
        let mut out = Vec::new();
        let mut va = base;
        // Gather the block's bytes segment-run by 16-byte code_bytes reads.
        while va < want + 16 {
            let chunk = image.code_bytes(va);
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(chunk);
            va += chunk.len() as u64;
        }
        out
    };

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = image.rsp;
    let mut guest_fsbase = 0u64;
    let mut next = image.entry;
    let mut cursor = 0usize;
    let mut traps = 0usize;
    let mut exit_code: Option<i32> = None;
    let mut fault_detail: Option<String> = None;
    let mut trap_limit_hit = false;
    // True once this process is a `fork()` descendant (see `Step::Exit`).
    let mut forked = false;

    // Translated-block cache keyed by guest VA: `(exec VA, has_edges,
    // uses_fpu)`. Guest text is read-only here (no self-modifying code), so a
    // VA always translates to the same bytes and the entry is valid for the
    // whole run. Cursor is monotonic. `has_edges` means the block ends in a
    // chainable direct branch; `uses_fpu` drives the FPU save/restore skip.
    const CODE_CACHE_LEN: usize = 4 * 1024 * 1024;
    let mut cache: std::collections::HashMap<u64, (u64, bool, bool), VaBuildHasher> =
        std::collections::HashMap::default();
    // Chain edges awaiting their target's translation: `target_va -> [(rel32
    // patch address, next-instruction address)]`. When `target_va` is
    // translated, every waiting slot is patched to jump straight to it.
    let mut pending: std::collections::HashMap<u64, Vec<(u64, u64)>, VaBuildHasher> =
        std::collections::HashMap::default();
    // Breadcrumb ring: the last guest VAs entered, for diagnosing where an
    // unhandled scenario was reached from.
    let mut history: Vec<u64> = Vec::new();

    'run: while traps < max_traps {
        history.push(next);
        if history.len() > 64 {
            history.remove(0);
        }
        let (exec, has_edges, uses_fpu) = if let Some(&hit) = cache.get(&next) {
            hit
        } else {
            // Plan bounded to the 4 KiB guest page so a block stays within one
            // mapped PT_LOAD segment (segments are page-aligned; a larger span
            // could read across an unmapped gap between them). `plan_block`
            // always includes its first instruction even if it spans the page
            // boundary (an internal, in-segment boundary), so it never returns
            // an empty `Continue{target: start}` — which the chainer would turn
            // into an infinite self-jump.
            let block = match plan_block(next, 256, PAGE, read_guest) {
                Ok(b) => b,
                Err(e) => {
                    fault_detail = Some(format!("plan_block at 0x{next:x}: {e}"));
                    break;
                }
            };
            // Defensive: a block that plans zero instructions AND only
            // CONTINUES at its own start makes no progress (a page-spanning
            // instruction that could not be planned, or the guest ran off
            // mapped code). A block whose first instruction is a TERMINATOR
            // (call/jmp/jcc/syscall/sensitive) also has zero copy-instructions
            // and `exit.va() == start` — that is normal, so match only the
            // `Continue` shape. Emit a LOUD breadcrumb on the real no-progress
            // case so an unhandled scenario is debuggable without guessing.
            let empty_self_continue = block.instructions.is_empty()
                && matches!(block.exit, X86Exit::Continue { target, .. } if target == next);
            if empty_self_continue {
                let bytes = image.code_bytes(next);
                let in_seg = image.segments.iter().any(|&(s, e)| next >= s && next < e);
                let recent: Vec<String> = history
                    .iter()
                    .rev()
                    .take(8)
                    .map(|v| format!("0x{v:x}"))
                    .collect();
                fault_detail = Some(format!(
                    "no-progress block at 0x{next:x}: exit={:?} in_segment={in_seg} \
                     bytes={:02x?} segments={:x?} recent_blocks={:?}",
                    block.exit, bytes, image.segments, recent,
                ));
                break;
            }
            let body = read_block(&block);
            let linked = match emit_block_linked(&body, &block) {
                Ok(t) => t,
                Err(e) => {
                    // Loud: include the terminator VA's bytes so an unsupported
                    // instruction is identifiable without a debugger round-trip.
                    let at = block.exit.va();
                    fault_detail = Some(format!(
                        "emit_block at 0x{next:x} ({:?}): {e} — insn bytes at 0x{at:x} = {:02x?}",
                        block.exit,
                        image.code_bytes(at),
                    ));
                    break;
                }
            };
            if cursor + linked.bytes.len() > CODE_CACHE_LEN {
                fault_detail = Some(format!(
                    "JIT code cache exhausted ({CODE_CACHE_LEN} bytes) translating 0x{next:x}"
                ));
                break;
            }
            // SAFETY: the JIT region is mapped for the run; cursor is in range.
            let exec = unsafe { region.exec_base.as_ptr().add(cursor) };
            let wptr = match region.write_ptr_for(exec) {
                Some(p) => p,
                None => {
                    fault_detail = Some("JIT write alias out of range".to_string());
                    break;
                }
            };
            // SAFETY: wptr is the RW alias of exec; linked.bytes fits.
            unsafe {
                std::ptr::copy_nonoverlapping(linked.bytes.as_ptr(), wptr, linked.bytes.len())
            };
            jit.flush_icache(exec, linked.bytes.len());
            cursor += linked.bytes.len();
            let exec_u64 = exec as u64;
            let entry = (exec_u64, !linked.edges.is_empty(), block.uses_fpu);
            cache.insert(next, entry);
            // Register this block's outgoing edges; patch any whose target is
            // already translated (a self-edge sees this block, now cached).
            for edge in &linked.edges {
                let patch_abs = exec_u64 + edge.rel32_off as u64;
                let next_abs = patch_abs + 4;
                if let Some(&(target_exec, _, _)) = cache.get(&edge.target_va) {
                    patch_slot(&region, &jit, patch_abs, next_abs, target_exec);
                } else {
                    pending
                        .entry(edge.target_va)
                        .or_default()
                        .push((patch_abs, next_abs));
                }
            }
            // Patch any earlier-translated blocks that were waiting for THIS VA.
            if let Some(waiters) = pending.remove(&next) {
                for (patch_abs, next_abs) in waiters {
                    patch_slot(&region, &jit, patch_abs, next_abs, exec_u64);
                }
            }
            entry
        };

        let mut ctx = X86DsrContext::new(snapshot, exec, next);
        ctx.guest_fsbase = guest_fsbase;
        // A chainable block runs many blocks with live FPU state, so the
        // per-block skip is unsound across a chain — restore/save around any
        // chainable entry; keep the skip only for blocks that exit immediately.
        ctx.save_fpu = if has_edges { 1 } else { u32::from(uses_fpu) };
        // Cleared so a stale value can't misread a genuine indirect exit as a
        // chain miss; only a cold stub sets it.
        ctx.chain_patch_site = 0;
        // SAFETY: exec holds a freshly translated block ending in an exit stub
        // (or chaining to one); rsp is a valid guest stack.
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
        snapshot = ctx.snapshot;

        // With chaining the EXITING block may differ from the entered one, so
        // dispatch on the exit STATUS + snapshot.rip, not the entered block.
        match X86ExitStatus::from_raw(raw) {
            Some(X86ExitStatus::Signal) => {
                fault_detail = Some(format!(
                    "guest fault: signal {} at guest addr 0x{:x} (host_rip 0x{:x})",
                    ctx.fault.signal, ctx.fault.addr, ctx.fault.host_rip
                ));
                break;
            }
            Some(X86ExitStatus::Syscall) => {
                traps += 1;
                match service_syscall(
                    &mut dispatcher,
                    &mut memory,
                    &reporter,
                    &mut waiter,
                    &mut snapshot,
                    &mut guest_fsbase,
                ) {
                    Step::Continue(rip) => next = rip,
                    Step::BecameForkChild(rip) => {
                        // This process is now a fork descendant; its exit must
                        // be reaped by the parent, not returned up.
                        forked = true;
                        next = rip;
                    }
                    Step::Exit(code) => {
                        // A fork child exits directly so the parent's wait4
                        // reaps it (and native_run prints only the top-level
                        // process's RunResult).
                        if forked {
                            // SAFETY: _exit performs no unwinding; the child's
                            // COW mappings are released by the kernel.
                            unsafe { libc::_exit(code) };
                        }
                        exit_code = Some(code);
                        break 'run;
                    }
                    Step::Fault(detail) => {
                        fault_detail = Some(detail);
                        break;
                    }
                }
            }
            Some(X86ExitStatus::Indirect) => {
                if ctx.chain_patch_site != 0 {
                    // Chain miss: a cold stub already resolved the successor VA
                    // into snapshot.rip; the pending machinery patches the slot
                    // when the target is translated (this iteration or later).
                    next = snapshot.rip;
                } else {
                    // Genuine indirect branch (call/ret/jmp r/m): re-decode it
                    // at the self-set resume VA and resolve from the snapshot.
                    let va = snapshot.rip;
                    let branch = image.code_bytes(va);
                    match cflow::resolve(branch, va, &mut snapshot) {
                        Ok(t) => next = t,
                        Err(e) => {
                            fault_detail = Some(format!("cflow resolve at 0x{va:x}: {e}"));
                            break;
                        }
                    }
                }
            }
            Some(X86ExitStatus::Sensitive) => {
                // Re-decode the sensitive instruction at the self-set resume VA
                // to recover its kind and length.
                let va = snapshot.rip;
                let bytes = image.code_bytes(va);
                match classify(bytes, va) {
                    Ok(c) => match c.class {
                        X86InstClass::Sensitive(kind) => {
                            match service_sensitive(kind, &mut snapshot) {
                                Ok(()) => next = va + c.len as u64,
                                Err(detail) => {
                                    fault_detail = Some(detail);
                                    break;
                                }
                            }
                        }
                        other => {
                            fault_detail =
                                Some(format!("sensitive exit at 0x{va:x} decoded as {other:?}"));
                            break;
                        }
                    },
                    Err(e) => {
                        fault_detail = Some(format!("sensitive re-decode at 0x{va:x}: {e}"));
                        break;
                    }
                }
            }
            None => {
                fault_detail = Some(format!("gateway returned unknown status {raw}"));
                break;
            }
        }
    }

    if traps >= max_traps && exit_code.is_none() && fault_detail.is_none() {
        trap_limit_hit = true;
    }

    fault::unregister_code_region();
    // SAFETY: nothing executes from the JIT region after the loop returns.
    unsafe { jit.unmap(&region) };
    image.teardown();
    arenas.teardown();

    // Drain the guest's stdout/stderr. Unless the caller enabled live
    // streaming (`set_stream_stdio`), the dispatcher accumulates fd 1/2 writes
    // in its internal buffers; surface them in the RunResult exactly as the
    // VMM lanes' buffered path does.
    let stdout = dispatcher.stdout();
    let stderr = dispatcher.stderr();

    let exit_code = match (exit_code, &fault_detail) {
        (Some(code), _) => code,
        (None, Some(detail)) => {
            return Err(RuntimeError::Unsupported(format!(
                "native x86 run stopped before exit: {detail}"
            )));
        }
        (None, None) => 125,
    };

    Ok(RunResult {
        exit_code,
        stdout,
        stderr,
        traps,
        report: CompatReport::default(),
        trap_limit_hit,
    })
}

/// Adapt a `syscall` gateway exit into the shared dispatcher. Builds the same
/// [`carrick_hal::RawSyscall`] the x86 VMM engine produces, drives it through
/// the shared single-threaded [`crate::runtime::service_syscall`] (which
/// services the blocking-I/O outcomes — fd wait / poll / select / sleep /
/// blocking write — by parking on the `waiter` and re-dispatching), writes the
/// terminal return value into `snapshot.rax`, and returns the resume RIP.
/// `arch_prctl(SET_FS)` sets `guest_fsbase` (VMM state has no analog here).
fn service_syscall(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut IdentityGuestMemory,
    reporter: &CompatReporter,
    waiter: &mut crate::io_wait::ThreadWaiter,
    snapshot: &mut X86UcontextSnapshot,
    guest_fsbase: &mut u64,
) -> Step {
    let frame = X8664SyscallFrame {
        rax: snapshot.gpr[reg::RAX],
        rdi: snapshot.gpr[reg::RDI],
        rsi: snapshot.gpr[reg::RSI],
        rdx: snapshot.gpr[reg::RDX],
        r10: snapshot.gpr[reg::R10],
        r8: snapshot.gpr[reg::R8],
        r9: snapshot.gpr[reg::R9],
    };
    let resume = snapshot.rip;

    let raw = match X8664GuestArch::normalize_syscall(&frame) {
        SyscallNorm::ArchPrctl { code, addr } => {
            let ret = service_arch_prctl(code, addr, snapshot, guest_fsbase, memory);
            snapshot.gpr[reg::RAX] = ret as u64;
            return Step::Continue(resume);
        }
        SyscallNorm::Plain(raw) => raw,
    };

    let request = SyscallRequest::from_raw(raw).with_current_guest_sp(Some(snapshot.gpr[reg::RSP]));
    let outcome =
        match crate::runtime::service_syscall(dispatcher, request, memory, reporter, waiter) {
            Ok(o) => o,
            Err(e) => return Step::Fault(format!("dispatch error: {e:?}")),
        };

    match outcome {
        DispatchOutcome::Returned { value } => {
            snapshot.gpr[reg::RAX] = value as u64;
            Step::Continue(resume)
        }
        DispatchOutcome::Errno { errno } => {
            snapshot.gpr[reg::RAX] = (-(errno.get() as i64)) as u64;
            Step::Continue(resume)
        }
        DispatchOutcome::Exit { code } => Step::Exit(code),
        // A default-action fatal signal from the syscall path (e.g. the guest
        // raised SIGKILL/SIGTERM through kill/tgkill): the guest is dead. Linux
        // wait status is 128+signum; the full signal-delivery machinery
        // (handlers, siginfo) is a later rung.
        DispatchOutcome::SignalDeath { signum } => Step::Exit(128 + signum),
        // fork()/clone(SIGCHLD): in the identity model a guest fork is a REAL
        // host fork — the child inherits the whole address space (guest memory,
        // JIT cache, arenas) copy-on-write, and is a real host child so the
        // parent's wait4 reaps it via host waitpid. The dispatcher's proc model
        // already distinguishes the child by `getpid() != bootstrap_host_pid`.
        DispatchOutcome::Fork {
            parent_tid_addr,
            child_tid_addr,
            child_stack,
            ..
        } => service_fork(
            parent_tid_addr,
            child_tid_addr,
            child_stack,
            snapshot,
            memory,
            resume,
        ),
        other => Step::Fault(format!(
            "native x86 driver does not service dispatch outcome {other:?} yet \
             (threads/execve/futex are later rungs)"
        )),
    }
}

/// Perform a guest `fork()` as a host `fork()`. Sets guest `rax` (0 in the
/// child, the child pid in the parent), runs the child on `child_stack` if
/// given, and honors CLONE_PARENT_SETTID / CLONE_CHILD_SETTID. Returns
/// [`Step::BecameForkChild`] in the child so the run loop `_exit`s it directly.
fn service_fork(
    parent_tid_addr: Option<u64>,
    child_tid_addr: Option<u64>,
    child_stack: u64,
    snapshot: &mut X86UcontextSnapshot,
    memory: &mut IdentityGuestMemory,
    resume: u64,
) -> Step {
    // SAFETY: a plain process fork; the child re-enters the same run loop with
    // a COW copy of every mapping.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(11);
        snapshot.gpr[reg::RAX] = (-(errno as i64)) as u64;
        return Step::Continue(resume);
    }
    if pid == 0 {
        // Child.
        snapshot.gpr[reg::RAX] = 0;
        if child_stack != 0 {
            snapshot.gpr[reg::RSP] = child_stack;
        }
        if let Some(addr) = child_tid_addr {
            let cpid = unsafe { libc::getpid() } as u32;
            let _ = memory.write_bytes(addr, &cpid.to_le_bytes());
        }
        Step::BecameForkChild(resume)
    } else {
        // Parent.
        snapshot.gpr[reg::RAX] = pid as u64;
        if let Some(addr) = parent_tid_addr {
            let _ = memory.write_bytes(addr, &(pid as u32).to_le_bytes());
        }
        Step::Continue(resume)
    }
}

/// Service `arch_prctl(code, addr)`: SET_FS installs the guest thread pointer
/// into the gateway's `guest_fsbase`; SET_GS is refused (no gs virtualization
/// yet); GET_FS/GET_GS write the current base to `*addr`.
fn service_arch_prctl(
    code: u64,
    addr: u64,
    _snapshot: &mut X86UcontextSnapshot,
    guest_fsbase: &mut u64,
    memory: &mut IdentityGuestMemory,
) -> i64 {
    match code {
        ARCH_SET_FS => {
            *guest_fsbase = addr;
            0
        }
        ARCH_GET_FS => {
            if memory
                .write_bytes(addr, &guest_fsbase.to_le_bytes())
                .is_err()
            {
                return -14; // EFAULT
            }
            0
        }
        ARCH_SET_GS | ARCH_GET_GS => NEG_EINVAL,
        _ => NEG_EINVAL,
    }
}

/// Service a sensitive (non-syscall) exit. On a same-ISA native lane the guest
/// and host CPU are identical, so `rdtsc`/`rdtscp`/`cpuid` are HONEST host
/// passthrough — the guest sees the real CPU it is running on. fs/gs base
/// instructions and gs-prefixed accesses are not yet virtualized here.
fn service_sensitive(
    kind: carrick_dsr_x86::decode::X86SensitiveKind,
    snapshot: &mut X86UcontextSnapshot,
) -> Result<(), String> {
    use carrick_dsr_x86::decode::X86SensitiveKind::*;
    match kind {
        Rdtsc { with_processor_id } => {
            let mut aux = 0u32;
            // SAFETY: rdtsc/rdtscp are unprivileged on x86_64.
            let tsc = unsafe {
                if with_processor_id {
                    core::arch::x86_64::__rdtscp(&mut aux)
                } else {
                    core::arch::x86_64::_rdtsc()
                }
            };
            snapshot.gpr[reg::RAX] = tsc & 0xffff_ffff;
            snapshot.gpr[reg::RDX] = tsc >> 32;
            if with_processor_id {
                snapshot.gpr[reg::RCX] = aux as u64;
            }
            Ok(())
        }
        Cpuid => {
            let leaf = snapshot.gpr[reg::RAX] as u32;
            let subleaf = snapshot.gpr[reg::RCX] as u32;
            // cpuid is unprivileged; the intrinsic is safe on x86_64 targets.
            let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
            snapshot.gpr[reg::RAX] = r.eax as u64;
            snapshot.gpr[reg::RBX] = r.ebx as u64;
            snapshot.gpr[reg::RCX] = r.ecx as u64;
            snapshot.gpr[reg::RDX] = r.edx as u64;
            Ok(())
        }
        SegmentBase { .. } | SegmentPrefixed { .. } | Syscall | Int80 => Err(format!(
            "native x86 first-rung driver does not service sensitive {kind:?} yet"
        )),
    }
}

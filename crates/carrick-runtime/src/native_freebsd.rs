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

use carrick_dsr::host::NativeHostJit;
use carrick_dsr_x86::block::{X86Block, X86Exit};
use carrick_dsr_x86::gateway::{CTX_FAULT_RECORD, reg, signal_stub_addr};
use carrick_dsr_x86::{
    X86DsrContext, X86ExitStatus, X86UcontextSnapshot, cflow, emit::emit_block, plan_block,
};
use carrick_guest_mem::{GuestMemory, X8664SyscallFrame};
use carrick_hal::x8664_arch::{SyscallNorm, X8664GuestArch};
use carrick_native_freebsd::{FreebsdHostJit, fault};
use goblin::elf::Elf;
use goblin::elf::program_header::PT_LOAD;

use crate::compat::{CompatReport, CompatReporter};
use crate::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};
use crate::run_result::{RunResult, RuntimeError};

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

    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        let seg_lo = (ph.p_vaddr & !(PAGE - 1)) + bias;
        let seg_hi = ((ph.p_vaddr + ph.p_memsz + PAGE - 1) & !(PAGE - 1)) + bias;
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

    Ok(LoadedImage {
        span_base: span as u64,
        span_len,
        entry: elf.entry + bias,
        stack: stack as u64,
        stack_len: GUEST_STACK_LEN,
        rsp,
        scratch: scratch as u64,
        scratch_len: PAGE as usize,
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
}

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

    let reporter = Arc::new(CompatReporter::default());
    let tid = crate::thread::ThreadId::main_from_host_pid();
    let registry = crate::thread::ThreadRegistry::new(tid);
    let futex = crate::thread::FutexTable::new();
    let mut memory = IdentityGuestMemory;

    let span_base = image.span_base;
    let span_end = image.span_base + image.span_len as u64;
    let read_guest = |va: u64| -> Vec<u8> {
        if va < span_base || va >= span_end {
            return Vec::new();
        }
        let end = (va + 16).min(span_end);
        // SAFETY: within the mapped image span.
        unsafe { std::slice::from_raw_parts(va as *const u8, (end - va) as usize).to_vec() }
    };
    // Read the full body of a block (may exceed the 16-byte plan peek).
    let read_block = |block: &X86Block| -> Vec<u8> {
        let base = block.start;
        let want = block.end.max(block.exit.va());
        let hi = (want + 16).min(span_end);
        // SAFETY: within the mapped image span.
        unsafe { std::slice::from_raw_parts(base as *const u8, (hi - base) as usize).to_vec() }
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

    'run: while traps < max_traps {
        let block = match plan_block(next, 256, PAGE, read_guest) {
            Ok(b) => b,
            Err(e) => {
                fault_detail = Some(format!("plan_block at 0x{next:x}: {e}"));
                break;
            }
        };
        let body = read_block(&block);
        let translated = match emit_block(&body, &block) {
            Ok(t) => t,
            Err(e) => {
                fault_detail = Some(format!("emit_block at 0x{next:x} ({:?}): {e}", block.exit));
                break;
            }
        };
        // SAFETY: the JIT region is mapped for the run; blocks are tiny.
        let exec = unsafe { region.exec_base.as_ptr().add(cursor) };
        let wptr = match region.write_ptr_for(exec) {
            Some(p) => p,
            None => {
                fault_detail = Some("JIT write alias out of range".to_string());
                break;
            }
        };
        // SAFETY: wptr is the RW alias of exec; translated fits the cache.
        unsafe { std::ptr::copy_nonoverlapping(translated.as_ptr(), wptr, translated.len()) };
        jit.flush_icache(exec, translated.len());
        cursor += translated.len();
        if cursor > 4 * 1024 * 1024 - 4096 {
            cursor = 0;
        }

        let resume = match block.exit {
            X86Exit::Syscall { resume, .. } => resume,
            X86Exit::ControlFlow { va, .. } | X86Exit::Sensitive { va, .. } => va,
            X86Exit::Continue { target, .. } => target,
            X86Exit::Unsupported { va } => {
                fault_detail = Some(format!("undecodable/privileged guest insn at 0x{va:x}"));
                break;
            }
        };

        let mut ctx = X86DsrContext::new(snapshot, exec as u64, resume);
        ctx.guest_fsbase = guest_fsbase;
        // SAFETY: exec holds a freshly translated block ending in an exit stub;
        // rsp is a valid guest stack.
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
        snapshot = ctx.snapshot;

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
                    tid,
                    &registry,
                    &futex,
                    &mut snapshot,
                    &mut guest_fsbase,
                ) {
                    Step::Continue(rip) => next = rip,
                    Step::Exit(code) => {
                        exit_code = Some(code);
                        break 'run;
                    }
                    Step::Fault(detail) => {
                        fault_detail = Some(detail);
                        break;
                    }
                }
            }
            Some(X86ExitStatus::Indirect) => match block.exit {
                X86Exit::ControlFlow { va, .. } => {
                    let branch = read_guest(va);
                    match cflow::resolve(&branch, va, &mut snapshot) {
                        Ok(t) => next = t,
                        Err(e) => {
                            fault_detail = Some(format!("cflow resolve at 0x{va:x}: {e}"));
                            break;
                        }
                    }
                }
                X86Exit::Continue { target, .. } => next = target,
                _ => unreachable!("Indirect exit only from ControlFlow/Continue"),
            },
            Some(X86ExitStatus::Sensitive) => {
                if let X86Exit::Sensitive { va, len, kind } = block.exit {
                    match service_sensitive(kind, &mut snapshot) {
                        Ok(()) => next = va + len as u64,
                        Err(detail) => {
                            fault_detail = Some(detail);
                            break;
                        }
                    }
                } else {
                    unreachable!("Sensitive status only from a Sensitive exit");
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

    // Drain the guest's stdout/stderr. Unless the caller enabled live
    // streaming (`set_stream_stdio`), the dispatcher accumulates fd 1/2 writes
    // in its internal buffers; surface them in the RunResult exactly as the
    // VMM lanes' buffered path does.
    let stdout = dispatcher.stdout();
    let stderr = dispatcher.stderr();

    let _ = span_end;
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
/// [`carrick_hal::RawSyscall`] the x86 VMM engine produces, feeds
/// [`SyscallDispatcher::dispatch_threaded`], writes the return value into
/// `snapshot.rax`, and returns the resume RIP. `arch_prctl(SET_FS)` sets
/// `guest_fsbase` (VMM state has no analog here).
#[allow(clippy::too_many_arguments)]
fn service_syscall(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut IdentityGuestMemory,
    reporter: &CompatReporter,
    tid: crate::thread::ThreadId,
    registry: &crate::thread::ThreadRegistry,
    futex: &crate::thread::FutexTable,
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
        match dispatcher.dispatch_threaded(request, memory, reporter, tid, registry, futex) {
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
        other => Step::Fault(format!(
            "native x86 first-rung driver does not service dispatch outcome {other:?} yet \
             (threads/fork/blocking-waits are a later rung)"
        )),
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

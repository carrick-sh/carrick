//! End-to-end proof that the x86_64 DSR lane runs a REAL static Linux ELF
//! produced by a compiler — not hand-assembly — on FreeBSD/amd64.
//!
//! This is the M2-runtime precursor: a self-contained loader + block-at-a-time
//! run loop over the real `carrick-dsr-x86` gateway, with a tiny in-test
//! Linux-syscall servicer (the production path uses `carrick-runtime`'s
//! `SyscallDispatcher`; the FreeBSD host cannot passthrough Linux syscall
//! numbers, so even this harness must translate). The guest
//! (`tests/fixtures/tinyguest-x86_64-linux`, source `tinyguest.rs`) is a
//! `#![no_std]` static-pie built with rustc/LLVM `-O -C relocation-model=pic`:
//! it computes a loop sum, `write(1, msg, len)` (msg reached RIP-relatively —
//! the rung-1 rewrite), and `exit_group(sum)`. Real LLVM instruction
//! selection through plan -> emit -> gateway -> syscall-trap.
//!
//! What this exercises beyond the hand-assembled tests: a real ELF image
//! (program headers, multiple PT_LOAD segments, a load bias), a real
//! initial-stack/auxv layout, full-page blocks that hit `Continue`
//! boundaries, and genuine compiler codegen (RIP-relative rodata, the
//! computed loop). It does NOT set up TLS (the no_std guest has none) — that
//! path is covered by `translated_x86_guest_reads_tls_through_swapped_fsbase`.
#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]

use carrick_dsr::host::NativeHostJit;
use carrick_dsr_x86::block::X86Exit;
use carrick_dsr_x86::gateway::{CTX_FAULT_RECORD, reg, signal_stub_addr};
use carrick_dsr_x86::{
    X86DsrContext, X86ExitStatus, X86UcontextSnapshot, cflow, emit::emit_block, plan_block,
};
use carrick_native_freebsd::{FreebsdHostJit, fault};
use goblin::elf::Elf;
use goblin::elf::program_header::{PF_W, PT_LOAD};

const SYS_WRITE: u64 = 1;
const SYS_EXIT_GROUP: u64 = 231;

// A loaded ELF: the reserved host span (guest VA == host VA), the load bias,
// and the absolute entry VA.
struct LoadedElf {
    span_base: *mut u8,
    span_len: usize,
    entry: u64,
}

/// Map a static-pie ELF into the host address space at a load bias, so guest
/// VA == host VA. Reserves the full v-span with one PROT_NONE mapping (the
/// kernel picks the bias), then maps each PT_LOAD with MAP_FIXED and copies
/// its file bytes. The fixture has no relocations (pure RIP-relative
/// codegen), so no relocation pass is needed.
fn load_static_pie(bytes: &[u8], elf: &Elf) -> LoadedElf {
    let page = 4096u64;
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    for ph in &elf.program_headers {
        if ph.p_type == PT_LOAD {
            lo = lo.min(ph.p_vaddr & !(page - 1));
            hi = hi.max((ph.p_vaddr + ph.p_memsz + page - 1) & !(page - 1));
        }
    }
    let span_len = (hi - lo) as usize;

    // Reserve the whole span; the kernel-chosen base becomes the load bias.
    let span = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            span_len,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    assert_ne!(span, libc::MAP_FAILED, "reserve guest span");
    let bias = span as u64 - lo;

    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        let seg_lo = (ph.p_vaddr & !(page - 1)) + bias;
        let seg_hi = ((ph.p_vaddr + ph.p_memsz + page - 1) & !(page - 1)) + bias;
        let mut prot = libc::PROT_READ;
        if ph.p_flags & PF_W != 0 {
            prot |= libc::PROT_WRITE;
        }
        // The translator READS guest code (it executes from the JIT cache), so
        // executable segments need no host PROT_EXEC; writable ones need write
        // for the copy. Add WRITE unconditionally so the memcpy lands, then it
        // stays readable — sufficient for this bring-up harness.
        let addr = unsafe {
            libc::mmap(
                seg_lo as *mut libc::c_void,
                (seg_hi - seg_lo) as usize,
                prot | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(addr as u64, seg_lo, "MAP_FIXED segment");
        let dst = (ph.p_vaddr + bias) as *mut u8;
        let src = &bytes[ph.p_offset as usize..(ph.p_offset + ph.p_filesz) as usize];
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
    }

    LoadedElf {
        span_base: span as *mut u8,
        span_len,
        entry: elf.entry + bias,
    }
}

/// Build a Linux x86_64 initial stack: `[argc][argv..][NULL][envp..][NULL]
/// [auxv..][AT_NULL]` with a 16-byte AT_RANDOM block. Returns the guest rsp.
fn build_initial_stack(stack_top: u64, arg0: u64, random_ptr: u64) -> u64 {
    // AT_ types.
    const AT_NULL: u64 = 0;
    const AT_PAGESZ: u64 = 6;
    const AT_RANDOM: u64 = 25;
    // Push order is high->low; compute the layout then write it. Slots:
    // argc, argv0, argv_null, envp_null, 3 auxv pairs (PAGESZ, RANDOM, NULL).
    let words: [u64; 9] = [
        1,    // argc
        arg0, // argv[0]
        0,    // argv NULL
        0,    // envp NULL
        AT_PAGESZ, 4096, AT_RANDOM, random_ptr, AT_NULL,
    ];
    // rsp must be 16-aligned AT the entry (SysV: the kernel aligns so that
    // after the implicit return-address slot the ABI holds). Place the block
    // so `argc` sits at a 16-aligned rsp.
    let bytes = words.len() * 8;
    let mut rsp = (stack_top - bytes as u64) & !0xf;
    let base = rsp;
    for (i, w) in words.iter().enumerate() {
        unsafe { ((base + (i * 8) as u64) as *mut u64).write(*w) };
    }
    rsp = base;
    rsp
}

fn map_rw(len: usize) -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    assert_ne!(p, libc::MAP_FAILED, "map_rw");
    p.cast()
}

#[test]
fn runs_a_real_static_pie_linux_elf_natively() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tinyguest-x86_64-linux"
    );
    let bytes = std::fs::read(path).expect("read fixture ELF");
    let elf = Elf::parse(&bytes).expect("parse ELF");
    assert!(elf.is_64, "fixture is x86_64");

    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(256 * 1024).expect("map code cache");

    // Guest faults surface as typed Signal exits rather than crashing the
    // test process.
    fault::install_fault_redirect(signal_stub_addr(), CTX_FAULT_RECORD).expect("fault redirect");
    fault::register_code_region(region.exec_base.as_ptr() as u64, 256 * 1024);

    let loaded = load_static_pie(&bytes, &elf);

    // Capture the guest's stdout through a pipe.
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // Guest stack + argv/AT_RANDOM scratch.
    let stack = map_rw(256 * 1024);
    let stack_top = stack as u64 + 256 * 1024;
    let scratch = map_rw(4096);
    unsafe {
        std::ptr::copy_nonoverlapping(c"tinyguest".to_bytes_with_nul().as_ptr(), scratch, 10)
    };
    let arg0 = scratch as u64;
    let random_ptr = scratch as u64 + 16;
    let rsp = build_initial_stack(stack_top, arg0, random_ptr);

    // Guest code is read directly from the loaded image (guest VA == host VA).
    let read_guest = |va: u64| -> Vec<u8> {
        let end = (va + 16).min(loaded.span_base as u64 + loaded.span_len as u64);
        if va < loaded.span_base as u64 || end <= va {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(va as *const u8, (end - va) as usize).to_vec() }
    };

    // Translate one block into the JIT (fresh each time — no block cache in
    // this harness; the loop re-emits, which is correct if slow).
    let mut cursor = 0usize;
    let mut translate = |guest_va: u64| -> (u64, X86Exit) {
        let block = plan_block(guest_va, 256, 4096, read_guest).expect("plan");
        let src = read_guest(block.start);
        let want = (block.end.max(block.exit.va()) - block.start) as usize;
        // The block body can exceed the 16-byte peek window; re-read enough.
        let full = {
            let base = block.start;
            let hi =
                (base + want as u64 + 16).min(loaded.span_base as u64 + loaded.span_len as u64);
            unsafe { std::slice::from_raw_parts(base as *const u8, (hi - base) as usize).to_vec() }
        };
        let _ = src;
        let translated = emit_block(&full, &block).expect("emit");
        let exec = unsafe { region.exec_base.as_ptr().add(cursor) };
        let wptr = region.write_ptr_for(exec).expect("write alias");
        unsafe { std::ptr::copy_nonoverlapping(translated.as_ptr(), wptr, translated.len()) };
        jit.flush_icache(exec, translated.len());
        cursor += translated.len();
        // Wrap the cursor if we approach capacity (blocks are tiny).
        if cursor > 256 * 1024 - 512 {
            cursor = 0;
        }
        (exec as u64, block.exit)
    };

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = rsp;
    let mut next = loaded.entry;
    let mut exit_code: Option<i32> = None;
    let mut wrote = Vec::new();

    for _ in 0..100_000 {
        let (exec, exit) = translate(next);
        let expect_status = match exit {
            X86Exit::Syscall { .. } => X86ExitStatus::Syscall,
            X86Exit::ControlFlow { .. } | X86Exit::Continue { .. } => X86ExitStatus::Indirect,
            X86Exit::Sensitive { .. } => X86ExitStatus::Sensitive,
            X86Exit::Unsupported { va } => {
                panic!("guest hit undecodable/privileged insn at 0x{va:x}")
            }
        };
        let resume = match exit {
            X86Exit::Syscall { resume, .. } => resume,
            X86Exit::ControlFlow { va, .. } | X86Exit::Sensitive { va, .. } => va,
            X86Exit::Continue { target, .. } => target,
            X86Exit::Unsupported { .. } => unreachable!(),
        };

        let mut ctx = X86DsrContext::new(snapshot, exec, resume);
        ctx.guest_fsbase = snapshot_fsbase(&snapshot);
        // SAFETY: freshly translated block ending in an exit stub; valid rsp.
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
        let status = X86ExitStatus::from_raw(raw);
        assert_eq!(
            status,
            Some(expect_status),
            "exit status mismatch at guest 0x{next:x} (fault={:?})",
            ctx.fault
        );
        snapshot = ctx.snapshot;

        match exit {
            X86Exit::Syscall { .. } => match snapshot.gpr[reg::RAX] {
                SYS_WRITE => {
                    let fd = snapshot.gpr[reg::RDI] as i32;
                    let buf = snapshot.gpr[reg::RSI] as *const u8;
                    let len = snapshot.gpr[reg::RDX] as usize;
                    // Mirror the guest's write to our capture pipe (fd 1 -> pipe).
                    let target = if fd == 1 { write_fd } else { fd };
                    let slice = unsafe { std::slice::from_raw_parts(buf, len) };
                    wrote.extend_from_slice(slice);
                    let n = unsafe { libc::write(target, slice.as_ptr().cast(), len) };
                    snapshot.gpr[reg::RAX] = n as u64;
                    next = snapshot.rip;
                }
                SYS_EXIT_GROUP => {
                    exit_code = Some(snapshot.gpr[reg::RDI] as i32);
                    break;
                }
                other => panic!("unsupported syscall {other} at guest 0x{next:x}"),
            },
            X86Exit::ControlFlow { va, .. } => {
                let branch = read_guest(va);
                next = cflow::resolve(&branch, va, &mut snapshot).expect("resolve branch");
            }
            X86Exit::Continue { target, .. } => {
                next = target;
            }
            X86Exit::Sensitive { va, .. } => {
                panic!("guest hit an unserviced sensitive instruction at 0x{va:x}");
            }
            X86Exit::Unsupported { .. } => unreachable!(),
        }
    }

    unsafe { libc::close(write_fd) };
    let mut captured = [0u8; 64];
    let n = unsafe { libc::read(read_fd, captured.as_mut_ptr().cast(), captured.len()) };
    unsafe { libc::close(read_fd) };
    assert!(n >= 0);

    assert_eq!(
        &captured[..n as usize],
        b"native-elf ok\n",
        "the real compiled guest must write its message natively"
    );
    assert_eq!(exit_code, Some(21), "guest exit_group(0+1+..+6 == 21)");

    unsafe {
        jit.unmap(&region);
        libc::munmap(loaded.span_base.cast(), loaded.span_len);
        libc::munmap(stack.cast(), 256 * 1024);
        libc::munmap(scratch.cast(), 4096);
    }
    fault::unregister_code_region();
}

/// This harness never services `arch_prctl(ARCH_SET_FS)` (the no_std guest
/// sets no TLS), so the guest fs base is always 0 — the gateway skips the
/// swap. Kept as a named seam for when a libc guest lands.
fn snapshot_fsbase(_snapshot: &X86UcontextSnapshot) -> u64 {
    0
}

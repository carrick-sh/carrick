//! End-to-end proof that the x86_64 DSR lane EXECUTES translated guest code
//! and traps its syscalls on real FreeBSD/amd64 silicon.
//!
//! No runtime, no dispatcher: this hand-assembles a tiny guest that does
//! `write(fd, "hi\n", 3); exit_group(7)`, maps it through the
//! `carrick-native-freebsd` dual-map JIT, translates it a block at a time
//! with the real planner + emitter, runs each block through the real
//! `gateway_x86_64.S` trampoline, and services the two Linux syscalls in this
//! test. Green means plan -> emit -> gateway -> syscall-trap works on the new
//! lane.
//!
//! Gated to the only host that can run it (translated x86 on an x86 host that
//! also has the FreeBSD JIT).
#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]

use carrick_dsr::host::NativeHostJit;
use carrick_dsr_x86::block::X86Exit;
use carrick_dsr_x86::gateway::{XSAVE_AREA_LEN, reg};
use carrick_dsr_x86::{
    X86DsrContext, X86ExitStatus, X86GuestGsBase, X86IndirectCacheEntry, X86UcontextSnapshot,
    X86XstateMemoryReader, X86XstateRestorePlan,
    emit::{emit_block, emit_block_linked},
    plan_block,
};
use carrick_native_freebsd::FreebsdHostJit;

// Linux x86_64 syscall numbers used by the guest.
const SYS_WRITE: u64 = 1;
const SYS_EXIT_GROUP: u64 = 231;

static FAULT_REDIRECT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

core::arch::global_asm!(
    r#"
.text
.globl carrick_test_private_xsaveopt_after_switch
.type carrick_test_private_xsaveopt_after_switch,@function
carrick_test_private_xsaveopt_after_switch:
    // rdi=private image, rsi=pattern A, rdx=pattern B, rcx=timespec,
    // r8=expected-state output. Preserve three callee-saved registers; after
    // the pushes rsp is correctly aligned for the host libc call.
    pushq %r12
    pushq %r13
    pushq %r14
    movq %rdi, %r12
    movq %r8, %r13
    movq %rcx, %r14
    movq %rdx, %r11
    vmovdqu64 (%rsi), %zmm0
    movq (%rsi), %rax
    kmovq %rax, %k1
    fldcw .Lhost_fcw_a(%rip)
    ldmxcsr .Lhost_mxcsr_a(%rip)
    xorl %eax, %eax
    xorl %ecx, %ecx
    xorl %edx, %edx
    wrpkru
    xgetbv
    xsave64 (%r12)
    vmovdqu64 (%r11), %zmm0
    movq (%r11), %rax
    kmovq %rax, %k1
    fldcw .Lhost_fcw_b(%rip)
    ldmxcsr .Lhost_mxcsr_b(%rip)
    movl $0xc0000000, %eax
    xorl %ecx, %ecx
    xorl %edx, %edx
    wrpkru
    movq %r14, %rdi
    xorl %esi, %esi
    callq nanosleep@PLT

    // Capture the exact post-context-switch host state before XSAVEOPT so the
    // test remains valid even if libc legally clobbers caller-saved xstate.
    vmovdqu64 %zmm0, 0(%r13)
    kmovq %k1, %rax
    movq %rax, 64(%r13)
    fnstcw 72(%r13)
    stmxcsr 76(%r13)
    xorl %ecx, %ecx
    rdpkru
    movl %eax, 80(%r13)
    xgetbv
    xsaveopt64 (%r12)
    fldcw .Lhost_fcw_a(%rip)
    ldmxcsr .Lhost_mxcsr_a(%rip)
    xorl %eax, %eax
    xorl %ecx, %ecx
    xorl %edx, %edx
    wrpkru
    vzeroupper
    popq %r14
    popq %r13
    popq %r12
    ret
.size carrick_test_private_xsaveopt_after_switch, .-carrick_test_private_xsaveopt_after_switch

.section .rodata
.p2align 2
.Lhost_fcw_a:
    .short 0x037f
.Lhost_fcw_b:
    .short 0x0b7f
.p2align 2
.Lhost_mxcsr_a:
    .long 0x1f80
.Lhost_mxcsr_b:
    .long 0x3f80
.text
"#,
    options(att_syntax)
);

unsafe extern "C" {
    fn carrick_test_private_xsaveopt_after_switch(
        image: *mut u8,
        pattern_a: *const u8,
        pattern_b: *const u8,
        pause: *const libc::timespec,
        expected: *mut u8,
    );
}

#[repr(C, align(64))]
struct AlignedXsave([u8; XSAVE_AREA_LEN]);

/// Assemble the guest program. `data_va` is the absolute address of the "hi\n"
/// bytes (the guest reaches it via `movabs`, so no RIP-relative fixup is
/// needed). Layout is two straight-line-to-`syscall` blocks.
fn guest_program(data_va: u64, write_fd: u64) -> Vec<u8> {
    let mut code = Vec::new();
    // --- block A: write(write_fd, data_va, 3) ---
    code.extend_from_slice(&[0xbf]); // mov edi, imm32
    code.extend_from_slice(&(write_fd as u32).to_le_bytes());
    code.extend_from_slice(&[0x48, 0xbe]); // movabs rsi, imm64
    code.extend_from_slice(&data_va.to_le_bytes());
    code.extend_from_slice(&[0xba, 0x03, 0x00, 0x00, 0x00]); // mov edx, 3
    code.extend_from_slice(&[0xb8]); // mov eax, imm32 (write)
    code.extend_from_slice(&(SYS_WRITE as u32).to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05]); // syscall
    // --- block B: exit_group(7) ---
    code.extend_from_slice(&[0xbf, 0x07, 0x00, 0x00, 0x00]); // mov edi, 7
    code.extend_from_slice(&[0xb8]); // mov eax, imm32 (exit_group)
    code.extend_from_slice(&(SYS_EXIT_GROUP as u32).to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05]); // syscall
    code
}

fn map_rw(len: usize) -> *mut u8 {
    // SAFETY: a fresh anonymous RW mapping we own.
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
    assert_ne!(p, libc::MAP_FAILED, "guest data/stack mmap");
    p.cast()
}

/// FreeBSD must make XSAVEOPT safe for a persistent user-space destination
/// after both blocking context switches and forced CPU migration. The first
/// full XSAVE seeds pattern A; pattern B is installed, the thread sleeps in the
/// kernel, and XSAVEOPT must update the same image to B rather than retaining A
/// under stale modified-state tracking.
#[test]
fn private_host_xsaveopt_survives_context_switch_and_cpu_migration() {
    if std::arch::x86_64::__cpuid_count(0x0d, 1).eax & 1 == 0
        || !std::arch::is_x86_feature_detected!("avx512f")
        || std::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 3) == 0
        || unsafe { std::arch::x86_64::_xgetbv(0) } & 0x2e0 != 0x2e0
    {
        return;
    }
    let component = |index| {
        let leaf = std::arch::x86_64::__cpuid_count(0x0d, index);
        (leaf.ebx as usize, leaf.eax as usize)
    };
    let (ymm_hi, ymm_hi_len) = component(2);
    let (opmask, opmask_len) = component(5);
    let (zmm_hi, zmm_hi_len) = component(6);
    let (pkru, pkru_len) = component(9);
    assert!(ymm_hi_len >= 16 && opmask_len >= 16 && zmm_hi_len >= 32 && pkru_len >= 4);

    let mut original: libc::cpuset_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::cpuset_getaffinity(
                libc::CPU_LEVEL_WHICH,
                libc::CPU_WHICH_TID,
                -1,
                std::mem::size_of::<libc::cpuset_t>(),
                &mut original,
            )
        },
        0,
        "read current thread affinity"
    );
    let allowed = (0..libc::CPU_SETSIZE as usize)
        // SAFETY: `original` was initialized by successful cpuset_getaffinity.
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &original) })
        .collect::<Vec<_>>();
    assert!(!allowed.is_empty(), "thread must have one allowed CPU");

    let pattern_a = [0x17u8; 64];
    let pattern_b = [0xa9u8; 64];
    let pause = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    let mut image = AlignedXsave([0; XSAVE_AREA_LEN]);
    let mut expected = [0u8; 84];
    let mut stale = 0usize;
    let mut observed_cpus = std::collections::BTreeSet::new();

    for iteration in 0..64 {
        let cpu = allowed[iteration % allowed.len().min(2)];
        let mut selected: libc::cpuset_t = unsafe { std::mem::zeroed() };
        // SAFETY: cpu came from the kernel-populated original set.
        unsafe { libc::CPU_SET(cpu, &mut selected) };
        assert_eq!(
            unsafe {
                libc::cpuset_setaffinity(
                    libc::CPU_LEVEL_WHICH,
                    libc::CPU_WHICH_TID,
                    -1,
                    std::mem::size_of::<libc::cpuset_t>(),
                    &selected,
                )
            },
            0,
            "force test-thread CPU"
        );
        image.0.fill(0);
        expected.fill(0);
        unsafe {
            carrick_test_private_xsaveopt_after_switch(
                image.0.as_mut_ptr(),
                pattern_a.as_ptr(),
                pattern_b.as_ptr(),
                &pause,
                expected.as_mut_ptr(),
            );
        }
        observed_cpus.insert(unsafe { libc::sched_getcpu() });
        let xstate_bv =
            u64::from_le_bytes(image.0[512..520].try_into().expect("standard XSAVE header"));
        let stale_components = (xstate_bv & (1 << 0) != 0 && image.0[..2] != expected[72..74])
            || (xstate_bv & (1 << 1) != 0
                && (image.0[160..176] != expected[..16] || image.0[24..28] != expected[76..80]))
            || (xstate_bv & (1 << 2) != 0 && image.0[ymm_hi..ymm_hi + 16] != expected[16..32])
            || (xstate_bv & (1 << 5) != 0 && image.0[opmask + 8..opmask + 16] != expected[64..72])
            || (xstate_bv & (1 << 6) != 0 && image.0[zmm_hi..zmm_hi + 32] != expected[32..64])
            || (xstate_bv & (1 << 9) != 0 && image.0[pkru..pkru + 4] != expected[80..84]);
        stale += usize::from(stale_components);
    }

    let restore_rc = unsafe {
        libc::cpuset_setaffinity(
            libc::CPU_LEVEL_WHICH,
            libc::CPU_WHICH_TID,
            -1,
            std::mem::size_of::<libc::cpuset_t>(),
            &original,
        )
    };
    assert_eq!(restore_rc, 0, "restore test-thread affinity");
    assert_eq!(stale, 0, "private XSAVEOPT image retained stale host XMM0");
    if allowed.len() >= 2 {
        assert!(
            observed_cpus.len() >= 2,
            "the migration half of the host XSAVEOPT contract did not run"
        );
    }
}

/// Conditional FPU save/restore correctness: a value placed in `xmm0` must
/// survive across a syscall round-trip AND across an INTEGER-only block that
/// SKIPS the fxsave/fxrstor (`save_fpu = 0`). Between blocks the host services
/// syscalls in Rust, whose own SSE use clobbers the physical xmm registers —
/// so the guest value only survives if the FPU-using blocks save/restore it
/// through the snapshot and the skipping block leaves that snapshot untouched.
/// Mirrors the driver: `ctx.save_fpu = block.uses_fpu`.
#[test]
fn conditional_fpu_save_preserves_xmm_across_a_skipping_block() {
    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");

    let stack = map_rw(64 * 1024);
    let stack_top = stack as u64 + 64 * 1024;

    const MAGIC: u64 = 0x0000_0000_0000_00A7;
    const GUEST_CODE_BASE: u64 = 0x70_0000;
    let mut program: Vec<u8> = Vec::new();
    // Block A (uses xmm -> saves): movabs rax, MAGIC; movq xmm0, rax; getpid; syscall
    program.extend_from_slice(&[0x48, 0xb8]);
    program.extend_from_slice(&MAGIC.to_le_bytes());
    program.extend_from_slice(&[0x66, 0x48, 0x0f, 0x6e, 0xc0]); // movq xmm0, rax
    program.extend_from_slice(&[0xb8, 0x27, 0x00, 0x00, 0x00]); // mov eax, 39 (getpid)
    program.extend_from_slice(&[0x0f, 0x05]); // syscall
    // Block B (INTEGER only -> skips FPU): mov eax, 39 (getpid); syscall
    program.extend_from_slice(&[0xb8, 0x27, 0x00, 0x00, 0x00]);
    program.extend_from_slice(&[0x0f, 0x05]);
    // Block C (uses xmm -> restores): movq rax, xmm0; mov edi, eax; exit_group
    program.extend_from_slice(&[0x66, 0x48, 0x0f, 0x7e, 0xc0]); // movq rax, xmm0
    program.extend_from_slice(&[0x89, 0xc7]); // mov edi, eax
    program.extend_from_slice(&[0xb8]);
    program.extend_from_slice(&(SYS_EXIT_GROUP as u32).to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05]);

    let read_guest = |va: u64| -> Vec<u8> {
        let off = (va - GUEST_CODE_BASE) as usize;
        program.get(off..).map(|s| s.to_vec()).unwrap_or_default()
    };

    let mut cursor = 0usize;
    let translate = |guest_va: u64, cursor: &mut usize| -> (u64, X86Exit, bool) {
        let block = plan_block(guest_va, 256, 4096, read_guest).expect("plan");
        let src = read_guest(block.start);
        let end_off = (block.end - block.start) as usize;
        let translated = emit_block(&src[..end_off.min(src.len())], &block).expect("emit");
        let exec = unsafe { region.exec_base.as_ptr().add(*cursor) };
        let write = region.write_ptr_for(exec).expect("write alias");
        unsafe {
            std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len());
        }
        jit.flush_icache(exec, translated.len());
        *cursor += translated.len();
        (exec as u64, block.exit, block.uses_fpu)
    };

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack_top;
    let mut context = X86DsrContext::new(snapshot, 0, 0);
    let context_addr = std::ptr::addr_of!(context);
    let mut next_guest_va = GUEST_CODE_BASE;
    let mut exit_code: Option<i32> = None;
    let mut saw_integer_skip = false;

    for _ in 0..8 {
        let (exec, exit, uses_fpu) = translate(next_guest_va, &mut cursor);
        if !uses_fpu {
            saw_integer_skip = true;
        }
        let resume = match exit {
            X86Exit::Syscall { resume, .. } => resume,
            other => panic!("fpu guest produced non-syscall exit: {other:?}"),
        };
        // Mirror the driver: mutate only scalar per-entry state and preserve
        // one stable context (including both 16 KiB XSAVE areas).
        context.prepare_entry(exec, resume, uses_fpu, None, None);
        assert_eq!(std::ptr::addr_of!(context), context_addr);
        // SAFETY: freshly translated block ending in an exit stub; valid rsp.
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut context) };
        assert_eq!(X86ExitStatus::from_raw(raw), Some(X86ExitStatus::Syscall));

        match context.snapshot.gpr[reg::RAX] {
            39 => {
                // Service getpid: return a pid AND deliberately clobber the
                // physical xmm registers (as real host syscall servicing does)
                // so a missing save/restore would corrupt the guest value.
                unsafe {
                    std::arch::asm!(
                        "pxor xmm0, xmm0",
                        "pcmpeqd xmm0, xmm0", // xmm0 = all ones — nothing like MAGIC
                        out("xmm0") _,
                    );
                }
                context.snapshot.gpr[reg::RAX] = 4242;
                next_guest_va = context.snapshot.rip;
            }
            SYS_EXIT_GROUP => {
                exit_code = Some(context.snapshot.gpr[reg::RDI] as i32);
                break;
            }
            other => panic!("unexpected syscall {other}"),
        }
    }

    assert!(
        saw_integer_skip,
        "the middle block must be integer-only (exercise the skip path)"
    );
    assert_eq!(
        exit_code,
        Some(MAGIC as i32),
        "xmm0 must survive the syscall round-trips and the skipping block"
    );
    if context.use_xsaveopt != 0 {
        assert_eq!(
            context.host_xsave_initialized, 1,
            "the first host save must initialize the persistent XSAVEOPT image"
        );
    }

    unsafe {
        jit.unmap(&region);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

#[test]
fn xrstor_sensitive_exit_captures_live_guest_xstate_before_rust_emulation() {
    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");
    let stack = map_rw(64 * 1024);

    const SOURCE_VA: u64 = 0x17_0000;
    const MAGIC: u64 = 0x8877_6655_4433_2211;
    let mut source = vec![0x48, 0xb8]; // movabs rax, MAGIC
    source.extend_from_slice(&MAGIC.to_le_bytes());
    source.extend_from_slice(&[0x66, 0x48, 0x0f, 0x6e, 0xc0]); // movq xmm0, rax
    source.extend_from_slice(&[0xeb, 0x00]); // jmp to adjacent XRSTOR block
    let target_va = SOURCE_VA + source.len() as u64;
    let source_block = plan_block(SOURCE_VA, 256, 4096, |va| {
        let offset = usize::try_from(va - SOURCE_VA).expect("source offset");
        source.get(offset..).map(<[u8]>::to_vec).unwrap_or_default()
    })
    .expect("plan xstate-producing source");
    let mut linked_source =
        emit_block_linked(&source, &source_block).expect("emit xstate-producing source");
    let edge = linked_source.edges[0];
    assert_eq!(edge.target_va, target_va);

    let target = [0x0f, 0xae, 0x6c, 0x24, 0x40];
    let target_block = plan_block(target_va, 256, 4096, |va| {
        let offset = usize::try_from(va - target_va).expect("target offset");
        target.get(offset..).map(<[u8]>::to_vec).unwrap_or_default()
    })
    .expect("plan exact XRSTOR target");
    assert!(
        target_block.uses_fpu,
        "an omitted XRSTOR terminator must request an authoritative gateway save"
    );
    let linked_target =
        emit_block_linked(&target, &target_block).expect("emit exact XRSTOR target");

    let target_offset = linked_source.bytes.len();
    let displacement = target_offset as i64 - (edge.entry_rel32_off + 4) as i64;
    linked_source.bytes[edge.entry_rel32_off..edge.entry_rel32_off + 4]
        .copy_from_slice(&(displacement as i32).to_le_bytes());
    let source_exec = region.exec_base.as_ptr();
    let target_exec = unsafe { source_exec.add(target_offset) };
    let source_write = region
        .write_ptr_for(source_exec)
        .expect("source write alias");
    let target_write = region
        .write_ptr_for(target_exec)
        .expect("target write alias");
    unsafe {
        std::ptr::copy_nonoverlapping(
            linked_source.bytes.as_ptr(),
            source_write,
            linked_source.bytes.len(),
        );
        std::ptr::copy_nonoverlapping(
            linked_target.bytes.as_ptr(),
            target_write,
            linked_target.bytes.len(),
        );
    }
    jit.flush_icache(source_exec, linked_source.bytes.len());
    jit.flush_icache(target_exec, linked_target.bytes.len());

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack as u64 + 32 * 1024;
    let mut context = X86DsrContext::new(snapshot, source_exec as u64, SOURCE_VA);
    context.prepare_entry(
        source_exec as u64,
        SOURCE_VA,
        target_block.uses_fpu,
        None,
        None,
    );
    let raw = unsafe { carrick_dsr_x86::enter_translated(&mut context) };
    assert_eq!(X86ExitStatus::from_raw(raw), Some(X86ExitStatus::Sensitive));
    assert_eq!(context.snapshot.rip, target_va);
    assert_eq!(
        &context.snapshot.xsave[160..168],
        &MAGIC.to_le_bytes(),
        "the sensitive exit must capture physical xmm0 before Rust observes the snapshot"
    );

    struct ZeroHeaderReader;
    impl X86XstateMemoryReader for ZeroHeaderReader {
        type Error = std::convert::Infallible;

        fn read_exact(
            &mut self,
            _address: carrick_guest_mem::GuestVa,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            destination.fill(0);
            Ok(())
        }
    }

    context.snapshot.gpr[reg::RAX] = 1; // request absent x87 only
    context.snapshot.gpr[reg::RDX] = 0;
    let plan = X86XstateRestorePlan::decode(&target, &context.snapshot, 0, X86GuestGsBase::Zero)
        .expect("decode exact target for Rust emulation");
    let layout = carrick_dsr_x86::signal_xstate_layout().expect("validated host xstate layout");
    context
        .snapshot
        .emulate_xrstor_with_reader(plan, &layout, &mut ZeroHeaderReader)
        .expect("emulate partial XRSTOR");
    assert_eq!(
        &context.snapshot.xsave[160..168],
        &MAGIC.to_le_bytes(),
        "unrequested SSE must preserve the pre-XRSTOR state captured by the gateway"
    );

    unsafe {
        jit.unmap(&region);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

#[test]
fn ymm_upper_half_survives_a_gateway_round_trip() {
    if !std::arch::is_x86_feature_detected!("avx") {
        return;
    }

    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");
    let data = map_rw(4096);
    let result = unsafe { data.add(64) };
    let pattern: Vec<u8> = (0..32).map(|value| value ^ 0xa5).collect();
    unsafe { std::ptr::copy_nonoverlapping(pattern.as_ptr(), data, pattern.len()) };
    let stack = map_rw(64 * 1024);

    const GUEST_CODE_BASE: u64 = 0x18_0000;
    let mut program = vec![0x48, 0xb8]; // movabs rax, data
    program.extend_from_slice(&(data as u64).to_le_bytes());
    program.extend_from_slice(&[0xc5, 0xfe, 0x6f, 0x00]); // vmovdqu ymm0, [rax]
    program.extend_from_slice(&[0xb8, 39, 0, 0, 0]); // getpid
    program.extend_from_slice(&[0x0f, 0x05]);
    program.extend_from_slice(&[0x48, 0xb8]); // movabs rax, result
    program.extend_from_slice(&(result as u64).to_le_bytes());
    program.extend_from_slice(&[0xc5, 0xfe, 0x7f, 0x00]); // vmovdqu [rax], ymm0
    program.extend_from_slice(&[0xbf, 0, 0, 0, 0]);
    program.extend_from_slice(&[0xb8]);
    program.extend_from_slice(&(SYS_EXIT_GROUP as u32).to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05]);

    let read_guest = |va: u64| -> Vec<u8> {
        let off = (va - GUEST_CODE_BASE) as usize;
        program
            .get(off..)
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default()
    };
    let mut cursor = 0usize;
    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack as u64 + 64 * 1024;
    let mut next = GUEST_CODE_BASE;

    for _ in 0..4 {
        let block = plan_block(next, 256, 4096, read_guest).expect("plan");
        let source = read_guest(block.start);
        let body_len = (block.end - block.start) as usize;
        let translated = emit_block(&source[..body_len], &block).expect("emit");
        let exec = unsafe { region.exec_base.as_ptr().add(cursor) };
        let write = region.write_ptr_for(exec).expect("write alias");
        unsafe { std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len()) };
        jit.flush_icache(exec, translated.len());
        cursor += translated.len();

        let resume = match block.exit {
            X86Exit::Syscall { resume, .. } => resume,
            other => panic!("expected syscall exit, got {other:?}"),
        };
        let mut ctx = X86DsrContext::new(snapshot, exec as u64, resume);
        ctx.save_fpu = u32::from(block.uses_fpu);
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
        assert_eq!(X86ExitStatus::from_raw(raw), Some(X86ExitStatus::Syscall));
        snapshot = ctx.snapshot;
        match snapshot.gpr[reg::RAX] {
            39 => {
                // Host work is free to use every caller-saved vector register.
                // Make that clobber deterministic instead of relying on Rust's
                // code generation to happen to touch ymm0.
                unsafe { std::arch::asm!("vzeroall") };
                snapshot.gpr[reg::RAX] = 4242;
                next = snapshot.rip;
            }
            SYS_EXIT_GROUP => break,
            other => panic!("unexpected syscall {other}"),
        }
    }

    let observed = unsafe { std::slice::from_raw_parts(result, pattern.len()) };
    assert_eq!(
        observed, pattern,
        "the gateway must preserve all 256 bits of live YMM state"
    );

    unsafe {
        jit.unmap(&region);
        libc::munmap(data.cast(), 4096);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

#[test]
fn translated_x86_guest_writes_and_exits_natively() {
    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");

    // Guest data page holding the message; a pipe captures what the guest
    // "writes" so the test is hermetic (the servicer writes to the pipe).
    let data = map_rw(4096);
    let msg = b"hi\n";
    // SAFETY: data is a 4096-byte RW mapping we own.
    unsafe { std::ptr::copy_nonoverlapping(msg.as_ptr(), data, msg.len()) };
    let data_va = data as u64;

    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // Guest stack (only needed so rsp is valid; this guest never pushes).
    let stack = map_rw(64 * 1024);
    let stack_top = stack as u64 + 64 * 1024;

    // The guest code image (translation SOURCE). Its "guest VA" is arbitrary
    // here — we translate FROM these bytes; execution runs from the JIT.
    const GUEST_CODE_BASE: u64 = 0x10_0000;
    let program = guest_program(data_va, write_fd as u64);
    let read_guest = |va: u64| -> Vec<u8> {
        let off = (va - GUEST_CODE_BASE) as usize;
        program.get(off..).map(|s| s.to_vec()).unwrap_or_default()
    };

    // Translate one block at `guest_va` into the JIT at `cursor`; return the
    // exec VA of the block and the byte length written.
    let mut cursor = 0usize;
    let translate = |guest_va: u64, cursor: &mut usize| -> (u64, X86Exit) {
        let block = plan_block(guest_va, 256, 4096, read_guest).expect("plan");
        // Source bytes for [start, end): the copy-through body.
        let src = read_guest(block.start);
        let end_off = (block.end - block.start) as usize;
        let translated = emit_block(&src[..end_off.min(src.len())], &block).expect("emit");
        let exec = unsafe { region.exec_base.as_ptr().add(*cursor) };
        let write = region.write_ptr_for(exec).expect("write alias for cursor");
        // SAFETY: `write` is inside the RW alias, `translated` fits (64 KiB
        // cache, tiny blocks).
        unsafe {
            std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len());
        }
        jit.flush_icache(exec, translated.len());
        *cursor += translated.len();
        (exec as u64, block.exit)
    };

    // Initial guest state: enter at block A, valid stack.
    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack_top;

    let mut next_guest_va = GUEST_CODE_BASE;
    let mut exit_code: Option<i32> = None;

    // Drive the block-at-a-time loop, servicing syscalls, until exit_group.
    for _ in 0..8 {
        let (exec, exit) = translate(next_guest_va, &mut cursor);
        let resume = match exit {
            X86Exit::Syscall { resume, .. } => resume,
            other => panic!("vertical-slice guest produced non-syscall exit: {other:?}"),
        };

        let mut ctx = X86DsrContext::new(snapshot, exec, resume);
        // SAFETY: `exec` holds a freshly translated block ending in the
        // syscall exit stub; rsp is a valid guest stack.
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
        assert_eq!(
            X86ExitStatus::from_raw(raw),
            Some(X86ExitStatus::Syscall),
            "block must exit through the syscall stub"
        );
        snapshot = ctx.snapshot;

        // Service the Linux syscall (rax = number; args in rdi/rsi/rdx/...).
        match snapshot.gpr[reg::RAX] {
            SYS_WRITE => {
                let fd = snapshot.gpr[reg::RDI] as i32;
                let buf = snapshot.gpr[reg::RSI] as *const libc::c_void;
                let len = snapshot.gpr[reg::RDX] as usize;
                // SAFETY: buf/len come from the guest's write args, pointing
                // at the mapped data page.
                let n = unsafe { libc::write(fd, buf, len) };
                assert!(
                    n >= 0,
                    "host write failed: {}",
                    std::io::Error::last_os_error()
                );
                snapshot.gpr[reg::RAX] = n as u64; // return value to the guest
            }
            SYS_EXIT_GROUP => {
                exit_code = Some(snapshot.gpr[reg::RDI] as i32);
                break;
            }
            other => panic!("guest issued an unexpected syscall {other}"),
        }

        // Continue at the instruction after the serviced syscall.
        next_guest_va = snapshot.rip;
        assert_eq!(
            snapshot.rip, resume,
            "the syscall exit must resume at the next guest VA"
        );
    }

    // Read what the guest wrote through the pipe.
    unsafe { libc::close(write_fd) };
    let mut captured = [0u8; 16];
    let n = unsafe { libc::read(read_fd, captured.as_mut_ptr().cast(), captured.len()) };
    unsafe { libc::close(read_fd) };
    assert!(n >= 0, "pipe read failed");

    assert_eq!(
        &captured[..n as usize],
        b"hi\n",
        "the translated guest must have written the message natively"
    );
    assert_eq!(exit_code, Some(7), "guest must exit_group(7)");

    // SAFETY: teardown of mappings we own; nothing executes from them now.
    unsafe {
        jit.unmap(&region);
        libc::munmap(data.cast(), 4096);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

/// Guest AC and DF are architectural state but hostile host execution state.
/// The gateway must snapshot both bits exactly and clear them before any cache
/// comparison or Rust return.
#[test]
fn guest_ac_and_df_are_contained_at_a_syscall_exit() {
    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");
    let stack = map_rw(64 * 1024);

    const GUEST_CODE_BASE: u64 = 0x5e_0000;
    let program = [
        0xfd, // std
        0x9c, // pushfq
        0x58, // pop rax
        0x48, 0x0d, 0x00, 0x00, 0x04, 0x00, // or rax, 1 << 18 (AC)
        0x50, // push rax
        0x9d, // popfq
        0x0f, 0x05, // syscall (gateway exit; not copied)
    ];
    let read_guest = |va: u64| -> Vec<u8> {
        let offset = (va - GUEST_CODE_BASE) as usize;
        program
            .get(offset..)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    };
    let block = plan_block(GUEST_CODE_BASE, 256, 4096, read_guest).expect("plan");
    let source = read_guest(block.start);
    let translated = emit_block(&source[..(block.end - block.start) as usize], &block)
        .expect("emit AC+DF guest");
    let exec = region.exec_base.as_ptr();
    let write = region.write_ptr_for(exec).expect("write alias");
    unsafe { std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len()) };
    jit.flush_icache(exec, translated.len());

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack as u64 + 64 * 1024;
    let resume = match block.exit {
        X86Exit::Syscall { resume, .. } => resume,
        other => panic!("expected syscall exit, got {other:?}"),
    };
    let mut context = X86DsrContext::new(snapshot, exec as u64, resume);
    let raw = unsafe { carrick_dsr_x86::enter_translated(&mut context) };
    assert_eq!(X86ExitStatus::from_raw(raw), Some(X86ExitStatus::Syscall));

    const DF: u64 = 1 << 10;
    const AC: u64 = 1 << 18;
    assert_eq!(
        context.snapshot.rflags & (DF | AC),
        DF | AC,
        "snapshot must retain the guest's exact AC+DF state"
    );
    let host_flags: u64;
    unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) host_flags) };
    assert_eq!(
        host_flags & (DF | AC),
        0,
        "gateway must clear AC+DF before returning to Rust"
    );

    unsafe {
        jit.unmap(&region);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

/// A zero guest FS base is real state (for example after ARCH_SET_FS(0)), not
/// a sentinel for retaining the host's TLS base. A copied `fs:` access must
/// fault at address zero rather than disclose a word from host TLS.
#[test]
fn zero_guest_fsbase_cannot_read_host_tls() {
    use carrick_dsr_x86::gateway::{CTX_FAULT_RECORD, signal_stub_addr};
    use carrick_native_freebsd::fault;

    let _fault_redirect_guard = FAULT_REDIRECT_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");
    fault::install_fault_redirect(signal_stub_addr(), CTX_FAULT_RECORD)
        .expect("install fault redirect");
    fault::register_code_region(region.exec_base.as_ptr() as u64, 64 * 1024);
    let stack = map_rw(64 * 1024);

    const GUEST_CODE_BASE: u64 = 0x5f_0000;
    let program = [
        0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // mov rax, fs:[0]
        0x0f, 0x05, // syscall, reached only if host FS leaked
    ];
    let read_guest = |va: u64| -> Vec<u8> {
        let offset = (va - GUEST_CODE_BASE) as usize;
        program
            .get(offset..)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    };
    let block = plan_block(GUEST_CODE_BASE, 256, 4096, read_guest).expect("plan");
    let source = read_guest(block.start);
    let translated = emit_block(&source[..(block.end - block.start) as usize], &block)
        .expect("emit zero-FS guest");
    let exec = region.exec_base.as_ptr();
    let write = region.write_ptr_for(exec).expect("write alias");
    unsafe { std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len()) };
    jit.flush_icache(exec, translated.len());

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack as u64 + 64 * 1024;
    let resume = match block.exit {
        X86Exit::Syscall { resume, .. } => resume,
        other => panic!("expected syscall-terminated block, got {other:?}"),
    };
    let mut context = X86DsrContext::new(snapshot, exec as u64, resume);
    context.guest_fsbase = 0;
    let raw = unsafe { carrick_dsr_x86::enter_translated(&mut context) };
    assert_eq!(X86ExitStatus::from_raw(raw), Some(X86ExitStatus::Signal));
    assert_eq!(context.fault.signal, libc::SIGSEGV);
    assert_eq!(context.fault.addr, 0, "zero FS must resolve fs:[0] to zero");

    fault::unregister_code_region();
    let host_tls_still_works = [7u8; 32];
    assert_eq!(host_tls_still_works[17], 7);
    unsafe {
        jit.unmap(&region);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

/// A guest that FAULTS: it dereferences an unmapped address mid-block. The
/// FreeBSD fault shim must surface this as a typed `Signal` gateway exit
/// with an accurate fault record — not kill the process — and the host must
/// keep running normally afterwards.
#[test]
fn translated_x86_guest_fault_becomes_a_signal_exit() {
    use carrick_dsr_x86::gateway::{CTX_FAULT_RECORD, signal_stub_addr};
    use carrick_native_freebsd::fault;

    let _fault_redirect_guard = FAULT_REDIRECT_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");

    fault::install_fault_redirect(signal_stub_addr(), CTX_FAULT_RECORD)
        .expect("install fault redirect");
    fault::register_code_region(region.exec_base.as_ptr() as u64, 64 * 1024);

    let stack = map_rw(64 * 1024);
    let stack_top = stack as u64 + 64 * 1024;

    // An address that is definitely unmapped: a fresh mapping, immediately
    // unmapped again.
    let probe = map_rw(4096);
    unsafe { libc::munmap(probe.cast(), 4096) };
    let bad_va = probe as u64;

    const GUEST_CODE_BASE: u64 = 0x60_0000;
    let mut program: Vec<u8> = Vec::new();
    // movabs rax, bad_va; mov eax, [rax] — faults on the load
    program.extend_from_slice(&[0x48, 0xb8]);
    program.extend_from_slice(&bad_va.to_le_bytes());
    program.extend_from_slice(&[0x8b, 0x00]);
    // (never reached) exit_group(3)
    program.extend_from_slice(&[0xbf, 0x03, 0x00, 0x00, 0x00]);
    program.extend_from_slice(&[0xb8]);
    program.extend_from_slice(&(SYS_EXIT_GROUP as u32).to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05]);

    let read_guest = |va: u64| -> Vec<u8> {
        let off = (va - GUEST_CODE_BASE) as usize;
        program.get(off..).map(|s| s.to_vec()).unwrap_or_default()
    };

    let block = plan_block(GUEST_CODE_BASE, 256, 4096, read_guest).expect("plan");
    let src = read_guest(block.start);
    let end_off = (block.end - block.start) as usize;
    let translated = emit_block(&src[..end_off.min(src.len())], &block).expect("emit");
    let exec = region.exec_base.as_ptr();
    let write = region.write_ptr_for(exec).expect("write alias");
    unsafe {
        std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len());
    }
    jit.flush_icache(exec, translated.len());

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack_top;
    let resume = match block.exit {
        X86Exit::Syscall { resume, .. } => resume,
        other => panic!("unexpected exit: {other:?}"),
    };

    let mut ctx = X86DsrContext::new(snapshot, exec as u64, resume);
    // SAFETY: freshly translated block ending in an exit stub; valid rsp.
    let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
    assert_eq!(
        X86ExitStatus::from_raw(raw),
        Some(X86ExitStatus::Signal),
        "the guest fault must surface as a typed Signal exit, not a crash"
    );
    assert_eq!(ctx.fault.signal, libc::SIGSEGV, "fault signal recorded");
    assert_eq!(ctx.fault.addr, bad_va, "si_addr is the unmapped guest VA");
    let cache_base = region.exec_base.as_ptr() as u64;
    assert!(
        ctx.fault.host_rip >= cache_base && ctx.fault.host_rip < cache_base + 64 * 1024,
        "fault RIP inside the code cache (host_rip=0x{:x})",
        ctx.fault.host_rip
    );
    // The faulting guest's rax (the bad pointer) survived into the snapshot
    // via the shared exit tail.
    assert_eq!(ctx.snapshot.gpr[reg::RAX], bad_va);

    // The host is intact: normal faulting behaviour is restored for host
    // code, and ordinary work (allocation, syscalls) still succeeds.
    fault::unregister_code_region();
    let alive = vec![42u8; 1024];
    assert_eq!(alive[512], 42);

    unsafe {
        jit.unmap(&region);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

/// A guest whose control flow goes through an INDIRECT call: `call [rax]`
/// loads a helper's address from a function-pointer table in guest memory
/// (the PLT/vtable shape), the helper writes the message and `ret`s, and the
/// caller exits. Exercises `cflow::resolve`'s memory-indirect and return
/// paths across natively executed blocks.
#[test]
fn translated_x86_guest_calls_through_a_function_pointer_table() {
    use carrick_dsr_x86::cflow;

    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");

    let data = map_rw(4096);
    let msg = b"fp\n";
    unsafe { std::ptr::copy_nonoverlapping(msg.as_ptr(), data, msg.len()) };
    let msg_va = data as u64;
    let table_va = data as u64 + 64;

    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let stack = map_rw(64 * 1024);
    let stack_top = stack as u64 + 64 * 1024;

    const GUEST_CODE_BASE: u64 = 0x50_0000;
    let mut main_code: Vec<u8> = Vec::new();
    // movabs rax, table_va; call [rax]
    main_code.extend_from_slice(&[0x48, 0xb8]);
    main_code.extend_from_slice(&table_va.to_le_bytes());
    main_code.extend_from_slice(&[0xff, 0x10]);
    // exit_group(21)
    main_code.extend_from_slice(&[0xbf, 0x15, 0x00, 0x00, 0x00]);
    main_code.extend_from_slice(&[0xb8]);
    main_code.extend_from_slice(&(SYS_EXIT_GROUP as u32).to_le_bytes());
    main_code.extend_from_slice(&[0x0f, 0x05]);
    let helper_va = GUEST_CODE_BASE + main_code.len() as u64;
    // helper: write(fd, msg, 3); ret
    let mut helper: Vec<u8> = Vec::new();
    helper.extend_from_slice(&[0xbf]);
    helper.extend_from_slice(&(write_fd as u32).to_le_bytes());
    helper.extend_from_slice(&[0x48, 0xbe]);
    helper.extend_from_slice(&msg_va.to_le_bytes());
    helper.extend_from_slice(&[0xba, 0x03, 0x00, 0x00, 0x00]);
    helper.extend_from_slice(&[0xb8]);
    helper.extend_from_slice(&(SYS_WRITE as u32).to_le_bytes());
    helper.extend_from_slice(&[0x0f, 0x05]);
    helper.extend_from_slice(&[0xc3]);
    let mut program = main_code;
    program.extend_from_slice(&helper);

    // The function-pointer table entry: helper's guest VA.
    unsafe { std::ptr::write_unaligned(table_va as *mut u64, helper_va) };

    let read_guest = |va: u64| -> Vec<u8> {
        let off = (va - GUEST_CODE_BASE) as usize;
        program.get(off..).map(|s| s.to_vec()).unwrap_or_default()
    };

    let mut cursor = 0usize;
    let translate = |guest_va: u64, cursor: &mut usize| -> (u64, X86Exit) {
        let block = plan_block(guest_va, 256, 4096, read_guest).expect("plan");
        let src = read_guest(block.start);
        let end_off = (block.end - block.start) as usize;
        let translated = emit_block(&src[..end_off.min(src.len())], &block).expect("emit");
        let exec = unsafe { region.exec_base.as_ptr().add(*cursor) };
        let write = region.write_ptr_for(exec).expect("write alias");
        unsafe {
            std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len());
        }
        jit.flush_icache(exec, translated.len());
        *cursor += translated.len();
        (exec as u64, block.exit)
    };

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack_top;
    let mut next_guest_va = GUEST_CODE_BASE;
    let mut wrote = false;
    let mut exit_code: Option<i32> = None;

    for _ in 0..16 {
        let (exec, exit) = translate(next_guest_va, &mut cursor);
        let (expect_status, resume) = match exit {
            X86Exit::Syscall { resume, .. } => (X86ExitStatus::Syscall, resume),
            X86Exit::ControlFlow { va, .. } => (X86ExitStatus::Indirect, va),
            other => panic!("unexpected exit: {other:?}"),
        };
        let mut ctx = X86DsrContext::new(snapshot, exec, resume);
        // SAFETY: freshly translated block ending in an exit stub; valid rsp.
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
        assert_eq!(X86ExitStatus::from_raw(raw), Some(expect_status));
        snapshot = ctx.snapshot;

        match exit {
            X86Exit::Syscall { .. } => match snapshot.gpr[reg::RAX] {
                SYS_WRITE => {
                    let n = unsafe {
                        libc::write(
                            snapshot.gpr[reg::RDI] as i32,
                            snapshot.gpr[reg::RSI] as *const libc::c_void,
                            snapshot.gpr[reg::RDX] as usize,
                        )
                    };
                    assert!(n >= 0);
                    snapshot.gpr[reg::RAX] = n as u64;
                    wrote = true;
                    next_guest_va = snapshot.rip;
                }
                SYS_EXIT_GROUP => {
                    exit_code = Some(snapshot.gpr[reg::RDI] as i32);
                    break;
                }
                other => panic!("unexpected syscall {other}"),
            },
            X86Exit::ControlFlow { va, .. } => {
                let branch_bytes = read_guest(va);
                next_guest_va =
                    cflow::resolve(&branch_bytes, va, &mut snapshot).expect("resolve branch");
            }
            _ => unreachable!(),
        }
    }

    unsafe { libc::close(write_fd) };
    let mut captured = [0u8; 16];
    let n = unsafe { libc::read(read_fd, captured.as_mut_ptr().cast(), captured.len()) };
    unsafe { libc::close(read_fd) };
    assert!(n >= 0);

    assert!(wrote, "the helper must have run");
    assert_eq!(&captured[..n as usize], b"fp\n");
    assert_eq!(
        exit_code,
        Some(21),
        "ret must return into main's exit sequence"
    );

    unsafe {
        jit.unmap(&region);
        libc::munmap(data.cast(), 4096);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

#[test]
fn monomorphic_return_cache_resumes_without_a_rust_round_trip() {
    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");
    let stack = map_rw(64 * 1024);
    let guest_rsp = stack as u64 + 64 * 1024 - 8;

    const RET_VA: u64 = 0x51_0000;
    const TARGET_VA: u64 = 0x52_0000;
    let ret_source = [0xC3];
    let ret_block = plan_block(RET_VA, 256, 4096, |va| {
        let off = (va - RET_VA) as usize;
        ret_source
            .get(off..)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    })
    .expect("plan ret");
    let mut linked_ret = emit_block_linked(&ret_source, &ret_block).expect("emit ret cache");
    let site = linked_ret.indirect_cache.expect("return cache metadata");
    linked_ret.bytes[site.site_id_imm_off..site.site_id_imm_off + 4]
        .copy_from_slice(&1_u32.to_le_bytes());

    let target_source = [
        0xB8,
        SYS_EXIT_GROUP as u8,
        0x00,
        0x00,
        0x00, // mov eax, exit_group
        0x0F,
        0x05, // syscall
    ];
    let target_block = plan_block(TARGET_VA, 256, 4096, |va| {
        let off = (va - TARGET_VA) as usize;
        target_source
            .get(off..)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    })
    .expect("plan target");
    let linked_target =
        emit_block_linked(&target_source, &target_block).expect("emit target syscall");

    let ret_exec = region.exec_base.as_ptr();
    let target_exec = unsafe { ret_exec.add(linked_ret.bytes.len()) };
    let ret_write = region.write_ptr_for(ret_exec).expect("ret write alias");
    let target_write = region
        .write_ptr_for(target_exec)
        .expect("target write alias");
    unsafe {
        std::ptr::copy_nonoverlapping(linked_ret.bytes.as_ptr(), ret_write, linked_ret.bytes.len());
        std::ptr::copy_nonoverlapping(
            linked_target.bytes.as_ptr(),
            target_write,
            linked_target.bytes.len(),
        );
        std::ptr::write(guest_rsp as *mut u64, TARGET_VA);
    }
    jit.flush_icache(ret_exec, linked_ret.bytes.len());
    jit.flush_icache(target_exec, linked_target.bytes.len());

    let mut entries = [X86IndirectCacheEntry::return_site(site.stack_adjust)];
    entries[0].arm(TARGET_VA, target_exec as u64);

    // A host-resident neutral interval must stay cold even when its target
    // matches: otherwise the target would inherit arbitrary host xstate.
    const HOSTILE_RFLAGS: u64 = 0x4_0CD7; // arithmetic status + DF + AC
    let mut cold_snapshot = X86UcontextSnapshot::new();
    cold_snapshot.gpr[reg::RSP] = guest_rsp;
    cold_snapshot.gpr[reg::RCX] = 0x1122_3344_5566_7788;
    cold_snapshot.rflags = HOSTILE_RFLAGS;
    let mut cold = X86DsrContext::new(cold_snapshot, ret_exec as u64, RET_VA);
    cold.prepare_entry(ret_exec as u64, RET_VA, false, None, None);
    // SAFETY: the fixed array remains live and immutable through this entry.
    unsafe { cold.publish_indirect_cache(&entries) };
    let cold_raw = unsafe { carrick_dsr_x86::enter_translated(&mut cold) };
    assert_eq!(
        X86ExitStatus::from_raw(cold_raw),
        Some(X86ExitStatus::Indirect)
    );
    assert_eq!(cold.snapshot.rip, RET_VA);
    assert_eq!(cold.snapshot.gpr[reg::RSP], guest_rsp);
    assert_eq!(cold.snapshot.gpr[reg::RCX], 0x1122_3344_5566_7788);
    assert_eq!(cold.snapshot.rflags & HOSTILE_RFLAGS, HOSTILE_RFLAGS);

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = guest_rsp;
    snapshot.gpr[reg::RCX] = 0x1122_3344_5566_7788;
    snapshot.rflags = HOSTILE_RFLAGS;
    let mut context = X86DsrContext::new(snapshot, ret_exec as u64, RET_VA);

    // A guest-resident but mismatched target also stays cold and leaves the
    // architectural return side effects unapplied for the Rust resolver.
    entries[0].arm(TARGET_VA + 1, target_exec as u64);
    context.prepare_entry(ret_exec as u64, RET_VA, true, None, None);
    // SAFETY: the fixed array remains live and immutable through this entry.
    unsafe { context.publish_indirect_cache(&entries) };
    // SAFETY: the emitted return block and guest stack are valid; the cache
    // key deliberately does not match the live target.
    let mismatch_raw = unsafe { carrick_dsr_x86::enter_translated(&mut context) };
    assert_eq!(
        X86ExitStatus::from_raw(mismatch_raw),
        Some(X86ExitStatus::Indirect)
    );
    assert_eq!(context.snapshot.rip, RET_VA);
    assert_eq!(context.snapshot.gpr[reg::RSP], guest_rsp);
    assert_eq!(context.snapshot.gpr[reg::RCX], 0x1122_3344_5566_7788);
    assert_eq!(context.snapshot.rflags & HOSTILE_RFLAGS, HOSTILE_RFLAGS);

    entries[0].arm(TARGET_VA, target_exec as u64);
    let stop_word = std::sync::atomic::AtomicU32::new(1);
    context.prepare_entry(ret_exec as u64, RET_VA, true, None, Some(&stop_word));
    // SAFETY: the fixed array remains live and immutable through this entry.
    unsafe { context.publish_indirect_cache(&entries) };
    let kicked_gprs = context.snapshot.gpr;
    let kicked_rflags = context.snapshot.rflags;

    // The cache key matches, but a nonzero stop word observes the exact
    // unexecuted-ret boundary before the gateway applies RIP/RSP mutation.
    let kicked_raw = unsafe { carrick_dsr_x86::enter_translated(&mut context) };
    assert_eq!(
        X86ExitStatus::from_raw(kicked_raw),
        Some(X86ExitStatus::Kicked)
    );
    assert_eq!(context.snapshot.rip, RET_VA);
    assert_eq!(context.snapshot.gpr, kicked_gprs);
    assert_eq!(context.snapshot.gpr[reg::RSP], guest_rsp);
    assert_eq!(context.snapshot.rflags, kicked_rflags);

    stop_word.store(0, std::sync::atomic::Ordering::Release);
    context.prepare_entry(ret_exec as u64, RET_VA, true, None, Some(&stop_word));
    // SAFETY: the fixed array remains live and immutable through this entry.
    unsafe { context.publish_indirect_cache(&entries) };

    // SAFETY: both emitted blocks are executable, the zero stop word permits
    // the matching return-cache hit, and the guest stack is valid.
    let raw = unsafe { carrick_dsr_x86::enter_translated(&mut context) };
    assert_eq!(X86ExitStatus::from_raw(raw), Some(X86ExitStatus::Syscall));
    assert_eq!(context.snapshot.rip, TARGET_VA + target_source.len() as u64);
    assert_eq!(context.snapshot.gpr[reg::RSP], guest_rsp + 8);
    assert_eq!(context.snapshot.gpr[reg::RCX], 0x1122_3344_5566_7788);
    assert_eq!(context.snapshot.rflags & HOSTILE_RFLAGS, HOSTILE_RFLAGS);

    unsafe {
        jit.unmap(&region);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

#[test]
fn guarded_direct_edge_polls_stop_word_without_changing_guest_state() {
    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");
    let stack = map_rw(64 * 1024);

    const SOURCE_VA: u64 = 0x53_0000;
    const TARGET_VA: u64 = SOURCE_VA + 2;
    let source = [0xEB, 0x00]; // jmp TARGET_VA
    let source_block = plan_block(SOURCE_VA, 256, 4096, |va| {
        let off = (va - SOURCE_VA) as usize;
        source.get(off..).map(<[u8]>::to_vec).unwrap_or_default()
    })
    .expect("plan source jmp");
    let mut linked_source = emit_block_linked(&source, &source_block).expect("emit source jmp");
    let edge = linked_source.edges[0];
    assert_eq!(edge.target_va, TARGET_VA);

    let target = [0x0F, 0x05]; // syscall: no body GPR/flag changes
    let target_block = plan_block(TARGET_VA, 256, 4096, |va| {
        let off = (va - TARGET_VA) as usize;
        target.get(off..).map(<[u8]>::to_vec).unwrap_or_default()
    })
    .expect("plan target syscall");
    let linked_target = emit_block_linked(&target, &target_block).expect("emit target syscall");

    let target_off = linked_source.bytes.len();
    let patch_rel32 = |bytes: &mut [u8], rel32_off: usize, target: usize| {
        let displacement = target as i64 - (rel32_off + 4) as i64;
        bytes[rel32_off..rel32_off + 4].copy_from_slice(&(displacement as i32).to_le_bytes());
    };
    // Mirror runtime publication: guarded successor first, entry branch last.
    patch_rel32(
        &mut linked_source.bytes,
        edge.guard_target_rel32_off,
        target_off,
    );
    patch_rel32(
        &mut linked_source.bytes,
        edge.entry_rel32_off,
        edge.guard_off,
    );

    let source_exec = region.exec_base.as_ptr();
    let target_exec = unsafe { source_exec.add(target_off) };
    let source_write = region
        .write_ptr_for(source_exec)
        .expect("source write alias");
    let target_write = region
        .write_ptr_for(target_exec)
        .expect("target write alias");
    unsafe {
        std::ptr::copy_nonoverlapping(
            linked_source.bytes.as_ptr(),
            source_write,
            linked_source.bytes.len(),
        );
        std::ptr::copy_nonoverlapping(
            linked_target.bytes.as_ptr(),
            target_write,
            linked_target.bytes.len(),
        );
    }
    jit.flush_icache(source_exec, linked_source.bytes.len());
    jit.flush_icache(target_exec, linked_target.bytes.len());

    let guest_rsp = stack as u64 + 64 * 1024;
    let mut snapshot = X86UcontextSnapshot::new();
    for (index, value) in snapshot.gpr.iter_mut().enumerate() {
        *value = 0x1111_0000_0000_0000 | index as u64;
    }
    snapshot.gpr[reg::RSP] = guest_rsp;
    // IF is immutable at CPL3, so include its live value while exercising the
    // arithmetic flags and DF that the guard must preserve exactly.
    snapshot.rflags = 0xED7;
    let expected_gprs = snapshot.gpr;
    let expected_rflags = snapshot.rflags;
    let stop_word = std::sync::atomic::AtomicU32::new(1);
    let mut context = X86DsrContext::new(snapshot, source_exec as u64, SOURCE_VA);
    context.prepare_entry(source_exec as u64, SOURCE_VA, true, None, Some(&stop_word));

    // SAFETY: the source edge and target syscall blocks are live executable
    // mappings; the nonzero guard leaves before touching the target.
    let kicked_raw = unsafe { carrick_dsr_x86::enter_translated(&mut context) };
    assert_eq!(
        X86ExitStatus::from_raw(kicked_raw),
        Some(X86ExitStatus::Kicked)
    );
    assert_eq!(context.snapshot.rip, TARGET_VA);
    assert_eq!(context.snapshot.gpr, expected_gprs);
    assert_eq!(context.snapshot.gpr[reg::RSP], guest_rsp);
    assert_eq!(context.snapshot.rflags, expected_rflags);

    stop_word.store(0, std::sync::atomic::Ordering::Release);
    context.prepare_entry(source_exec as u64, SOURCE_VA, true, None, Some(&stop_word));
    // SAFETY: the zero stop word permits the guarded edge to reach the live
    // target syscall block.
    let raw = unsafe { carrick_dsr_x86::enter_translated(&mut context) };
    assert_eq!(X86ExitStatus::from_raw(raw), Some(X86ExitStatus::Syscall));
    assert_eq!(context.snapshot.rip, TARGET_VA + target.len() as u64);
    assert_eq!(context.snapshot.gpr, expected_gprs);
    assert_eq!(context.snapshot.gpr[reg::RSP], guest_rsp);
    assert_eq!(context.snapshot.rflags, expected_rflags);

    unsafe {
        jit.unmap(&region);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

/// Assemble a guest that reaches its data ONLY through RIP-relative
/// addressing: `lea rsi, [rip+d1]` for the message pointer and
/// `mov edx, [rip+d2]` for the length stored in the data page. Verbatim
/// copy-through would compute both against the JIT-cache RIP and read
/// garbage; only the absolute-VA rewrite makes this guest work.
///
/// `code_base` is the guest VA of the first instruction; `msg_va`/`len_va`
/// are absolute VAs inside the mapped data page. The caller picks `code_base`
/// near the data page so the disp32s fit (as a real loaded image would).
fn guest_rip_relative_program(code_base: u64, msg_va: u64, len_va: u64, write_fd: u64) -> Vec<u8> {
    let mut c = Vec::new();
    let rel32 = |target: u64, next_ip: u64| -> [u8; 4] {
        let disp = target.wrapping_sub(next_ip) as i64 as i32;
        assert_eq!(
            next_ip.wrapping_add(disp as i64 as u64),
            target,
            "test layout must keep RIP-relative displacements in i32 range"
        );
        disp.to_le_bytes()
    };
    // lea rsi, [rip+d1]    (48 8d 35 d1) — message pointer
    let next_ip = code_base + c.len() as u64 + 7;
    c.extend_from_slice(&[0x48, 0x8d, 0x35]);
    c.extend_from_slice(&rel32(msg_va, next_ip));
    // mov edx, [rip+d2]    (8b 15 d2) — length loaded FROM guest memory
    let next_ip = code_base + c.len() as u64 + 6;
    c.extend_from_slice(&[0x8b, 0x15]);
    c.extend_from_slice(&rel32(len_va, next_ip));
    // mov edi, write_fd; mov eax, write; syscall
    c.extend_from_slice(&[0xbf]);
    c.extend_from_slice(&(write_fd as u32).to_le_bytes());
    c.extend_from_slice(&[0xb8]);
    c.extend_from_slice(&(SYS_WRITE as u32).to_le_bytes());
    c.extend_from_slice(&[0x0f, 0x05]);
    // exit_group(9)
    c.extend_from_slice(&[0xbf, 0x09, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0xb8]);
    c.extend_from_slice(&(SYS_EXIT_GROUP as u32).to_le_bytes());
    c.extend_from_slice(&[0x0f, 0x05]);
    c
}

#[test]
fn translated_x86_guest_reaches_data_rip_relatively() {
    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");

    // Data page: "ok\n" at +0, the write length (3u32) at +8. The guest reads
    // BOTH through RIP-relative operands.
    let data = map_rw(4096);
    let msg = b"ok\n";
    unsafe {
        std::ptr::copy_nonoverlapping(msg.as_ptr(), data, msg.len());
        std::ptr::write_unaligned(data.add(8).cast::<u32>(), msg.len() as u32);
    }
    let msg_va = data as u64;
    let len_va = data as u64 + 8;

    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let stack = map_rw(64 * 1024);
    let stack_top = stack as u64 + 64 * 1024;

    // Guest code VA near the data page (like a loaded image's text next to
    // its rodata) so the rel32 displacements are representable. The code VA
    // itself needs no mapping — it is only the translation-source coordinate.
    let guest_code_base = msg_va.wrapping_sub(0x10_000);
    let program = guest_rip_relative_program(guest_code_base, msg_va, len_va, write_fd as u64);
    let read_guest = |va: u64| -> Vec<u8> {
        let off = va.wrapping_sub(guest_code_base) as usize;
        program.get(off..).map(|s| s.to_vec()).unwrap_or_default()
    };

    let mut cursor = 0usize;
    let translate = |guest_va: u64, cursor: &mut usize| -> (u64, X86Exit) {
        let block = plan_block(guest_va, 256, 4096, read_guest).expect("plan");
        let src = read_guest(block.start);
        let end_off = (block.end - block.start) as usize;
        let translated = emit_block(&src[..end_off.min(src.len())], &block).expect("emit");
        let exec = unsafe { region.exec_base.as_ptr().add(*cursor) };
        let write = region.write_ptr_for(exec).expect("write alias");
        unsafe {
            std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len());
        }
        jit.flush_icache(exec, translated.len());
        *cursor += translated.len();
        (exec as u64, block.exit)
    };

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack_top;
    let mut next_guest_va = guest_code_base;
    let mut exit_code: Option<i32> = None;

    for _ in 0..8 {
        let (exec, exit) = translate(next_guest_va, &mut cursor);
        let resume = match exit {
            X86Exit::Syscall { resume, .. } => resume,
            other => panic!("rip-relative guest produced non-syscall exit: {other:?}"),
        };

        let mut ctx = X86DsrContext::new(snapshot, exec, resume);
        // SAFETY: `exec` holds a freshly translated block ending in the
        // syscall exit stub; rsp is a valid guest stack.
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
        assert_eq!(X86ExitStatus::from_raw(raw), Some(X86ExitStatus::Syscall));
        snapshot = ctx.snapshot;

        match snapshot.gpr[reg::RAX] {
            SYS_WRITE => {
                assert_eq!(
                    snapshot.gpr[reg::RSI],
                    msg_va,
                    "lea rsi, [rip+d] must materialize the ABSOLUTE message VA"
                );
                assert_eq!(
                    snapshot.gpr[reg::RDX],
                    msg.len() as u64,
                    "mov edx, [rip+d] must load the length from guest memory"
                );
                let n = unsafe {
                    libc::write(
                        snapshot.gpr[reg::RDI] as i32,
                        snapshot.gpr[reg::RSI] as *const libc::c_void,
                        snapshot.gpr[reg::RDX] as usize,
                    )
                };
                assert!(n >= 0, "host write: {}", std::io::Error::last_os_error());
                snapshot.gpr[reg::RAX] = n as u64;
                next_guest_va = snapshot.rip;
            }
            SYS_EXIT_GROUP => {
                exit_code = Some(snapshot.gpr[reg::RDI] as i32);
                break;
            }
            other => panic!("unexpected syscall {other}"),
        }
    }

    unsafe { libc::close(write_fd) };
    let mut captured = [0u8; 16];
    let n = unsafe { libc::read(read_fd, captured.as_mut_ptr().cast(), captured.len()) };
    unsafe { libc::close(read_fd) };
    assert!(n >= 0, "pipe read failed");

    assert_eq!(&captured[..n as usize], b"ok\n");
    assert_eq!(exit_code, Some(9), "guest must exit_group(9)");

    unsafe {
        jit.unmap(&region);
        libc::munmap(data.cast(), 4096);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

/// A guest that channels everything through virtualized r15: the message
/// pointer lives in r15 (`movabs r15` / `add r15` / `mov rsi, r15`), so every
/// instruction must be renamed against the snapshot's r15 slot — the live
/// r15 is the DSR context pointer throughout.
#[test]
fn translated_x86_guest_computes_through_virtualized_r15() {
    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");

    let data = map_rw(4096);
    // "..no" at +0; the guest writes 2 bytes from data+2 ("no" would mean the
    // r15 arithmetic didn't happen; "AB" at +2 is the expected message).
    unsafe {
        std::ptr::copy_nonoverlapping(b"..AB".as_ptr(), data, 4);
    }
    let data_va = data as u64;

    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let stack = map_rw(64 * 1024);
    let stack_top = stack as u64 + 64 * 1024;

    const GUEST_CODE_BASE: u64 = 0x30_0000;
    let mut program: Vec<u8> = Vec::new();
    // movabs r15, data_va       (49 bf imm64)
    program.extend_from_slice(&[0x49, 0xbf]);
    program.extend_from_slice(&data_va.to_le_bytes());
    // add r15, 2                (49 83 c7 02) — r15 arithmetic must stick
    program.extend_from_slice(&[0x49, 0x83, 0xc7, 0x02]);
    // mov rsi, r15              (4c 89 fe) — read the virtualized value back
    program.extend_from_slice(&[0x4c, 0x89, 0xfe]);
    // mov edx, 2; mov edi, fd; mov eax, write; syscall
    program.extend_from_slice(&[0xba, 0x02, 0x00, 0x00, 0x00]);
    program.extend_from_slice(&[0xbf]);
    program.extend_from_slice(&(write_fd as u32).to_le_bytes());
    program.extend_from_slice(&[0xb8]);
    program.extend_from_slice(&(SYS_WRITE as u32).to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05]);
    // exit_group(11)
    program.extend_from_slice(&[0xbf, 0x0b, 0x00, 0x00, 0x00]);
    program.extend_from_slice(&[0xb8]);
    program.extend_from_slice(&(SYS_EXIT_GROUP as u32).to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05]);

    let read_guest = |va: u64| -> Vec<u8> {
        let off = (va - GUEST_CODE_BASE) as usize;
        program.get(off..).map(|s| s.to_vec()).unwrap_or_default()
    };

    let mut cursor = 0usize;
    let translate = |guest_va: u64, cursor: &mut usize| -> (u64, X86Exit) {
        let block = plan_block(guest_va, 256, 4096, read_guest).expect("plan");
        let src = read_guest(block.start);
        let end_off = (block.end - block.start) as usize;
        let translated = emit_block(&src[..end_off.min(src.len())], &block).expect("emit");
        let exec = unsafe { region.exec_base.as_ptr().add(*cursor) };
        let write = region.write_ptr_for(exec).expect("write alias");
        unsafe {
            std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len());
        }
        jit.flush_icache(exec, translated.len());
        *cursor += translated.len();
        (exec as u64, block.exit)
    };

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack_top;
    let mut next_guest_va = GUEST_CODE_BASE;
    let mut exit_code: Option<i32> = None;

    for _ in 0..8 {
        let (exec, exit) = translate(next_guest_va, &mut cursor);
        let resume = match exit {
            X86Exit::Syscall { resume, .. } => resume,
            other => panic!("r15 guest produced non-syscall exit: {other:?}"),
        };
        let mut ctx = X86DsrContext::new(snapshot, exec, resume);
        // SAFETY: freshly translated block ending in an exit stub; valid rsp.
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
        assert_eq!(X86ExitStatus::from_raw(raw), Some(X86ExitStatus::Syscall));
        snapshot = ctx.snapshot;

        match snapshot.gpr[reg::RAX] {
            SYS_WRITE => {
                assert_eq!(
                    snapshot.gpr[reg::R15],
                    data_va + 2,
                    "guest r15 (movabs+add) must round-trip through the snapshot"
                );
                assert_eq!(snapshot.gpr[reg::RSI], data_va + 2, "rsi read from r15");
                let n = unsafe {
                    libc::write(
                        snapshot.gpr[reg::RDI] as i32,
                        snapshot.gpr[reg::RSI] as *const libc::c_void,
                        snapshot.gpr[reg::RDX] as usize,
                    )
                };
                assert!(n >= 0, "host write: {}", std::io::Error::last_os_error());
                snapshot.gpr[reg::RAX] = n as u64;
                next_guest_va = snapshot.rip;
            }
            SYS_EXIT_GROUP => {
                exit_code = Some(snapshot.gpr[reg::RDI] as i32);
                break;
            }
            other => panic!("unexpected syscall {other}"),
        }
    }

    unsafe { libc::close(write_fd) };
    let mut captured = [0u8; 8];
    let n = unsafe { libc::read(read_fd, captured.as_mut_ptr().cast(), captured.len()) };
    unsafe { libc::close(read_fd) };
    assert!(n >= 0);
    assert_eq!(
        &captured[..n as usize],
        b"AB",
        "r15-addressed bytes written"
    );
    assert_eq!(exit_code, Some(11));

    unsafe {
        jit.unmap(&region);
        libc::munmap(data.cast(), 4096);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

/// A guest whose data flows only through `fs:`-prefixed TLS reads: the
/// gateway must install `guest_fsbase` for the run (and restore the host's
/// on exit — the test process would die messily otherwise, since Rust/libc
/// TLS lives behind the real fs base).
#[test]
fn translated_x86_guest_reads_tls_through_swapped_fsbase() {
    use carrick_dsr_x86::gateway::fsgsbase_supported;
    assert!(
        fsgsbase_supported(),
        "this rig (Ryzen 7840HS) must expose FSGSBASE for the native lane"
    );

    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");

    // The guest "TLS block": pointer to the message at fs:[8], length at
    // fs:[16], message bytes at +24.
    let tls = map_rw(4096);
    let tls_va = tls as u64;
    let msg = b"tls\n";
    unsafe {
        std::ptr::copy_nonoverlapping(msg.as_ptr(), tls.add(24), msg.len());
        std::ptr::write_unaligned(tls.add(8).cast::<u64>(), tls_va + 24);
        std::ptr::write_unaligned(tls.add(16).cast::<u32>(), msg.len() as u32);
    }

    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let stack = map_rw(64 * 1024);
    let stack_top = stack as u64 + 64 * 1024;

    const GUEST_CODE_BASE: u64 = 0x40_0000;
    let mut program: Vec<u8> = Vec::new();
    // mov rsi, fs:[8]           (64 48 8b 34 25 08 00 00 00)
    program.extend_from_slice(&[0x64, 0x48, 0x8b, 0x34, 0x25, 0x08, 0x00, 0x00, 0x00]);
    // mov edx, fs:[16]          (64 8b 14 25 10 00 00 00)
    program.extend_from_slice(&[0x64, 0x8b, 0x14, 0x25, 0x10, 0x00, 0x00, 0x00]);
    // mov edi, fd; mov eax, write; syscall
    program.extend_from_slice(&[0xbf]);
    program.extend_from_slice(&(write_fd as u32).to_le_bytes());
    program.extend_from_slice(&[0xb8]);
    program.extend_from_slice(&(SYS_WRITE as u32).to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05]);
    // exit_group(13)
    program.extend_from_slice(&[0xbf, 0x0d, 0x00, 0x00, 0x00]);
    program.extend_from_slice(&[0xb8]);
    program.extend_from_slice(&(SYS_EXIT_GROUP as u32).to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05]);

    let read_guest = |va: u64| -> Vec<u8> {
        let off = (va - GUEST_CODE_BASE) as usize;
        program.get(off..).map(|s| s.to_vec()).unwrap_or_default()
    };

    let mut cursor = 0usize;
    let translate = |guest_va: u64, cursor: &mut usize| -> (u64, X86Exit) {
        let block = plan_block(guest_va, 256, 4096, read_guest).expect("plan");
        let src = read_guest(block.start);
        let end_off = (block.end - block.start) as usize;
        let translated = emit_block(&src[..end_off.min(src.len())], &block).expect("emit");
        let exec = unsafe { region.exec_base.as_ptr().add(*cursor) };
        let write = region.write_ptr_for(exec).expect("write alias");
        unsafe {
            std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len());
        }
        jit.flush_icache(exec, translated.len());
        *cursor += translated.len();
        (exec as u64, block.exit)
    };

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack_top;
    let mut next_guest_va = GUEST_CODE_BASE;
    let mut exit_code: Option<i32> = None;

    for _ in 0..8 {
        let (exec, exit) = translate(next_guest_va, &mut cursor);
        let resume = match exit {
            X86Exit::Syscall { resume, .. } => resume,
            other => panic!("tls guest produced non-syscall exit: {other:?}"),
        };
        let mut ctx = X86DsrContext::new(snapshot, exec, resume);
        // The guest's Linux thread pointer — what a real dispatcher installs
        // when servicing arch_prctl(ARCH_SET_FS).
        ctx.guest_fsbase = tls_va;
        // SAFETY: freshly translated block ending in an exit stub; valid rsp.
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
        assert_eq!(X86ExitStatus::from_raw(raw), Some(X86ExitStatus::Syscall));
        snapshot = ctx.snapshot;

        // Reaching this Rust code at all proves the host fs base came back
        // (thread-local errno/TLS would explode otherwise); assert the guest
        // side too.
        match snapshot.gpr[reg::RAX] {
            SYS_WRITE => {
                assert_eq!(
                    snapshot.gpr[reg::RSI],
                    tls_va + 24,
                    "mov rsi, fs:[8] must read through the GUEST fs base"
                );
                assert_eq!(snapshot.gpr[reg::RDX], msg.len() as u64, "fs:[16] length");
                let n = unsafe {
                    libc::write(
                        snapshot.gpr[reg::RDI] as i32,
                        snapshot.gpr[reg::RSI] as *const libc::c_void,
                        snapshot.gpr[reg::RDX] as usize,
                    )
                };
                assert!(n >= 0, "host write: {}", std::io::Error::last_os_error());
                snapshot.gpr[reg::RAX] = n as u64;
                next_guest_va = snapshot.rip;
            }
            SYS_EXIT_GROUP => {
                exit_code = Some(snapshot.gpr[reg::RDI] as i32);
                break;
            }
            other => panic!("unexpected syscall {other}"),
        }
    }

    unsafe { libc::close(write_fd) };
    let mut captured = [0u8; 16];
    let n = unsafe { libc::read(read_fd, captured.as_mut_ptr().cast(), captured.len()) };
    unsafe { libc::close(read_fd) };
    assert!(n >= 0);
    assert_eq!(&captured[..n as usize], b"tls\n", "TLS-sourced write");
    assert_eq!(exit_code, Some(13));

    unsafe {
        jit.unmap(&region);
        libc::munmap(tls.cast(), 4096);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

#[test]
fn translated_signed_branch_stops_before_wrapped_index() {
    use carrick_dsr_x86::cflow;

    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");
    let stack = map_rw(64 * 1024);

    const GUEST_CODE_BASE: u64 = 0x1f_0000;
    let mut program = vec![
        0x31, 0xdb, // xor ebx, ebx
        0x48, 0x83, 0xeb, 0x01, // sub rbx, 1 => u64::MAX
        0x85, 0xdb, // test ebx, ebx => SF=1
        0x78, 0x0c, // js +12, over the failure exit
        0xbf, 0x63, 0x00, 0x00, 0x00, // mov edi, 99
        0xb8,
    ];
    program.extend_from_slice(&(SYS_EXIT_GROUP as u32).to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05]);
    let signed_target = GUEST_CODE_BASE + program.len() as u64;
    program.extend_from_slice(&[0xbf, 0x07, 0x00, 0x00, 0x00]);
    program.extend_from_slice(&[0xb8]);
    program.extend_from_slice(&(SYS_EXIT_GROUP as u32).to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05]);

    let read_guest = |va: u64| -> Vec<u8> {
        let off = (va - GUEST_CODE_BASE) as usize;
        program
            .get(off..)
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default()
    };
    let block = plan_block(GUEST_CODE_BASE, 256, 4096, read_guest).expect("plan");
    let branch_va = match block.exit {
        X86Exit::ControlFlow { va, .. } => va,
        other => panic!("expected signed conditional exit, got {other:?}"),
    };
    let source = read_guest(block.start);
    let body_len = (block.end - block.start) as usize;
    let translated = emit_block(&source[..body_len], &block).expect("emit");
    let exec = region.exec_base.as_ptr();
    let write = region.write_ptr_for(exec).expect("write alias");
    unsafe { std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len()) };
    jit.flush_icache(exec, translated.len());

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack as u64 + 64 * 1024;
    let mut ctx = X86DsrContext::new(snapshot, exec as u64, branch_va);
    let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
    assert_eq!(X86ExitStatus::from_raw(raw), Some(X86ExitStatus::Indirect));
    assert_eq!(ctx.snapshot.gpr[reg::RBX], u64::MAX);
    assert_ne!(ctx.snapshot.rflags & (1 << 7), 0, "test ebx must set SF");

    let next =
        cflow::resolve(&read_guest(branch_va), branch_va, &mut ctx.snapshot).expect("resolve js");
    assert_eq!(
        next, signed_target,
        "JS must stop before an index of -1 is used"
    );

    unsafe {
        jit.unmap(&region);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

/// A guest with a real loop: `for i in 0..iters { write(fd, data, 3) }` then
/// `exit_group(iters)`, driving the `dec`/`jnz` control-flow path.
fn guest_loop_program(data_va: u64, write_fd: u64, iters: u32) -> Vec<u8> {
    let mut c = Vec::new();
    // mov r12d, iters                 (41 bc II II II II)
    c.extend_from_slice(&[0x41, 0xbc]);
    c.extend_from_slice(&iters.to_le_bytes());
    // LOOP: write(write_fd, data, 3)
    c.extend_from_slice(&[0xbf]); // mov edi, imm32
    c.extend_from_slice(&(write_fd as u32).to_le_bytes());
    c.extend_from_slice(&[0x48, 0xbe]); // movabs rsi, imm64
    c.extend_from_slice(&data_va.to_le_bytes());
    c.extend_from_slice(&[0xba, 0x03, 0x00, 0x00, 0x00]); // mov edx, 3
    c.extend_from_slice(&[0xb8]); // mov eax, write
    c.extend_from_slice(&(SYS_WRITE as u32).to_le_bytes());
    c.extend_from_slice(&[0x0f, 0x05]); // syscall
    // dec r12d ; jnz LOOP
    c.extend_from_slice(&[0x41, 0xff, 0xcc]); // dec r12d
    // jnz rel8 back to LOOP (offset 6 in the image); rel = 6 - (pos_of_jnz + 2)
    let jnz_pos = c.len();
    let rel = 6i64 - (jnz_pos as i64 + 2);
    c.extend_from_slice(&[0x75, rel as i8 as u8]); // jnz
    // exit_group(iters)
    c.extend_from_slice(&[0xbf]); // mov edi, imm32
    c.extend_from_slice(&iters.to_le_bytes());
    c.extend_from_slice(&[0xb8]); // mov eax, exit_group
    c.extend_from_slice(&(SYS_EXIT_GROUP as u32).to_le_bytes());
    c.extend_from_slice(&[0x0f, 0x05]); // syscall
    c
}

#[test]
fn translated_x86_loop_runs_control_flow_natively() {
    use carrick_dsr_x86::cflow;

    let jit = FreebsdHostJit;
    jit.supported().expect("host JIT supported");
    let region = jit.map_code_cache(64 * 1024).expect("map code cache");

    let data = map_rw(4096);
    let msg = b"x";
    unsafe { std::ptr::copy_nonoverlapping(msg.as_ptr(), data, msg.len()) };
    // The write is 3 bytes so include two more; only the "x" matters per iter.
    unsafe { std::ptr::write(data.add(1), b'y') };
    unsafe { std::ptr::write(data.add(2), b'z') };
    let data_va = data as u64;

    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let stack = map_rw(64 * 1024);
    let stack_top = stack as u64 + 64 * 1024;

    const GUEST_CODE_BASE: u64 = 0x20_0000;
    const ITERS: u32 = 4;
    let program = guest_loop_program(data_va, write_fd as u64, ITERS);
    let read_guest = |va: u64| -> Vec<u8> {
        let off = (va - GUEST_CODE_BASE) as usize;
        program.get(off..).map(|s| s.to_vec()).unwrap_or_default()
    };

    // Re-translate each block fresh (no block cache in the slice); a real loop
    // therefore re-emits its body every iteration — correct, just unchained.
    let mut cursor = 0usize;
    let translate = |guest_va: u64, cursor: &mut usize| -> (u64, X86Exit) {
        let block = plan_block(guest_va, 256, 4096, read_guest).expect("plan");
        let src = read_guest(block.start);
        let end_off = (block.end - block.start) as usize;
        let translated = emit_block(&src[..end_off.min(src.len())], &block).expect("emit");
        let exec = unsafe { region.exec_base.as_ptr().add(*cursor) };
        let write = region.write_ptr_for(exec).expect("write alias");
        unsafe {
            std::ptr::copy_nonoverlapping(translated.as_ptr(), write, translated.len());
        }
        jit.flush_icache(exec, translated.len());
        *cursor += translated.len();
        (exec as u64, block.exit)
    };

    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.gpr[reg::RSP] = stack_top;
    let mut next_guest_va = GUEST_CODE_BASE;
    let mut writes = 0u32;
    let mut exit_code: Option<i32> = None;

    // Bound generously; ITERS writes + ITERS branch blocks + a couple. Each
    // re-translation appends to the 64 KiB cache (blocks are tiny; ~64
    // iterations of ~30 bytes stays well under capacity), so the cursor grows
    // monotonically with no reset needed.
    for _ in 0..64 {
        let (exec, exit) = translate(next_guest_va, &mut cursor);
        let expect_status = match exit {
            X86Exit::Syscall { .. } => X86ExitStatus::Syscall,
            X86Exit::ControlFlow { .. } => X86ExitStatus::Indirect,
            other => panic!("unexpected exit: {other:?}"),
        };
        let resume = match exit {
            X86Exit::Syscall { resume, .. } => resume,
            X86Exit::ControlFlow { va, .. } => va, // resume filled after resolve
            _ => unreachable!(),
        };

        let mut ctx = X86DsrContext::new(snapshot, exec, resume);
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
        assert_eq!(X86ExitStatus::from_raw(raw), Some(expect_status));
        snapshot = ctx.snapshot;

        match exit {
            X86Exit::Syscall { .. } => match snapshot.gpr[reg::RAX] {
                SYS_WRITE => {
                    let n = unsafe {
                        libc::write(
                            snapshot.gpr[reg::RDI] as i32,
                            snapshot.gpr[reg::RSI] as *const libc::c_void,
                            snapshot.gpr[reg::RDX] as usize,
                        )
                    };
                    assert!(n >= 0);
                    snapshot.gpr[reg::RAX] = n as u64;
                    writes += 1;
                    next_guest_va = snapshot.rip;
                }
                SYS_EXIT_GROUP => {
                    exit_code = Some(snapshot.gpr[reg::RDI] as i32);
                    break;
                }
                other => panic!("unexpected syscall {other}"),
            },
            X86Exit::ControlFlow { va, .. } => {
                // Resolve the branch in Rust from the captured guest state.
                let branch_bytes = read_guest(va);
                next_guest_va =
                    cflow::resolve(&branch_bytes, va, &mut snapshot).expect("resolve branch");
            }
            _ => unreachable!(),
        }
    }

    unsafe { libc::close(write_fd) };
    let mut captured = [0u8; 64];
    let n = unsafe { libc::read(read_fd, captured.as_mut_ptr().cast(), captured.len()) };
    unsafe { libc::close(read_fd) };
    assert!(n >= 0);

    assert_eq!(writes, ITERS, "the loop must run exactly ITERS iterations");
    assert_eq!(
        n as u32,
        ITERS * 3,
        "each iteration writes 3 bytes natively through the trap"
    );
    assert_eq!(exit_code, Some(ITERS as i32), "guest exit_group(ITERS)");

    unsafe {
        jit.unmap(&region);
        libc::munmap(data.cast(), 4096);
        libc::munmap(stack.cast(), 64 * 1024);
    }
}

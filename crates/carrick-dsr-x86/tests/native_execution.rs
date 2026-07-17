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
use carrick_dsr_x86::gateway::reg;
use carrick_dsr_x86::{
    X86DsrContext, X86ExitStatus, X86UcontextSnapshot, emit::emit_block, plan_block,
};
use carrick_native_freebsd::FreebsdHostJit;

// Linux x86_64 syscall numbers used by the guest.
const SYS_WRITE: u64 = 1;
const SYS_EXIT_GROUP: u64 = 231;

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

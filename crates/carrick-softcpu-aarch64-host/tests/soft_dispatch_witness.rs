//! Cross-ISA production dispatch and stage-2 witness tests for the soft AArch64
//! machine facade (`SoftAarch64Vmm` + `Aarch64EngineCore<SoftAarch64Vmm>`).
//!
//! Runs un-ignored on both x86_64 and aarch64 hosts.

use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};

use carrick_aarch64::mailbox::{
    AARCH64_SYSCALL_MAILBOX_SIZE, Aarch64SyscallMailbox, MailboxState, MailboxTrapKind,
};
use carrick_guest_arch::FrameGpa;
use carrick_guest_mem::GuestMemory as _;
use carrick_hal::{GuestVmBackend, MemPerms};
use carrick_mem::memory::{LINUX_EL1_VECTORS_BASE, LINUX_SYSCALL_MAILBOX_BASE};
use carrick_softcpu_aarch64::dispatch::ExecuteBlock;
use carrick_softcpu_aarch64::handler::GuestMemory as SoftGuestMemory;
use carrick_softcpu_aarch64::state::{CpuState, ExceptionLevel, RegisterValue, VirtualAddress};
use carrick_softcpu_aarch64::translate::{Terminator, TranslatedBlock};
use carrick_softcpu_aarch64::{Gpr, Hint, Instruction, OperandRegister};
use carrick_softcpu_aarch64_host::{
    GUEST_PAGE_BYTES, Hvc2ReplyCensus, MappingGeometry, SoftFaultTermination,
    SoftSingleProcessConfig, SoftStage2, Stage2Abort, Stage2AbortAccess, Stage2AbortReason,
    run_single_process_with_executor_and_setup,
};

const CODE_VA: u64 = 0x0040_0000;
const DATA_VA: u64 = 0x0040_1000;

const PATH_OFFSET: u64 = 0x00;
const MSG_OFFSET: u64 = 0x40;
const STAT_OFFSET: u64 = 0x100;
const READ_BUF_OFFSET: u64 = 0x200;
const TIMESPEC_OFFSET: u64 = 0x300;

const FILE_PAYLOAD: &[u8] = b"rootfs file payload\n";
const STDOUT_PAYLOAD: &[u8] = b"facade witness ok\n";

const A64_SVC_0: u32 = 0xd400_0001;
const A64_HVC_2: u32 = 0xd400_0042;
const A64_ERET: u32 = 0xd69f_03e0;
/// `str x2, [x1]` (64-bit unsigned immediate 0).
const A64_STR_X2_X1: u32 = 0xf900_0022;
/// `ldr x3, [x1]` (64-bit unsigned immediate 0).
const A64_LDR_X3_X1: u32 = 0xf940_0023;
const A64_NOP: u32 = 0xd503_201f;

const NR_OPENAT: u64 = 56;
const NR_CLOSE: u64 = 57;
const NR_PIPE2: u64 = 59;
const NR_READ: u64 = 63;
const NR_WRITE: u64 = 64;
const NR_FSTAT: u64 = 80;
const NR_TIMERFD_CREATE: u64 = 85;
const NR_EXIT_GROUP: u64 = 94;
const NR_SETITIMER: u64 = 103;
const NR_CLOCK_GETTIME: u64 = 113;
const NR_TKILL: u64 = 130;
const NR_RT_SIGACTION: u64 = 134;
const NR_SHMGET: u64 = 194;
const NR_SHMAT: u64 = 196;
const NR_BRK: u64 = 214;
const NR_MUNMAP: u64 = 215;
const NR_MMAP: u64 = 222;
const NR_MPROTECT: u64 = 226;

const AT_FDCWD: u64 = (-100i64) as u64;
const O_CLOEXEC: u64 = 0x80000;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 2;
const MAP_SHARED: u64 = 1;
const MAP_ANONYMOUS: u64 = 0x20;
const CLOCK_MONOTONIC: u64 = 1;

fn build_witness_elf(code_words: &[u32], data_init: &[(usize, &[u8])]) -> Vec<u8> {
    let mut elf = vec![0u8; 0x3000];
    // Elf64_Ehdr
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    elf[24..32].copy_from_slice(&CODE_VA.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum

    let write_phdr = |buf: &mut [u8], base: usize, flags: u32, offset: u64, vaddr: u64| {
        buf[base..base + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        buf[base + 4..base + 8].copy_from_slice(&flags.to_le_bytes());
        buf[base + 8..base + 16].copy_from_slice(&offset.to_le_bytes());
        buf[base + 16..base + 24].copy_from_slice(&vaddr.to_le_bytes());
        buf[base + 24..base + 32].copy_from_slice(&vaddr.to_le_bytes());
        buf[base + 32..base + 40].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[base + 40..base + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[base + 48..base + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    };
    write_phdr(&mut elf, 64, 5, 0x1000, CODE_VA); // PF_R | PF_X
    write_phdr(&mut elf, 120, 6, 0x2000, DATA_VA); // PF_R | PF_W

    for i in 0..(0x1000 / 4) {
        let word = code_words.get(i).copied().unwrap_or(A64_NOP);
        let at = 0x1000 + i * 4;
        elf[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    for &(off, bytes) in data_init {
        let at = 0x2000 + off;
        elf[at..at + bytes.len()].copy_from_slice(bytes);
    }
    elf
}

#[derive(Default)]
struct WitnessObservations {
    brk_base: u64,
    anon_va: u64,
    opened_fd: u64,
    file_alias_va: u64,
    heap_roundtrip_word: u64,
    anon_readonly_word: u64,
    file_alias_word: u64,
}

struct ScriptedHvc2Executor {
    mailbox: Arc<AtomicPtr<Aarch64SyscallMailbox>>,
    obs: Arc<Mutex<WitnessObservations>>,
    next_seq: u64,
}

fn rx(cpu: &CpuState, index: u8) -> u64 {
    Gpr::new(index).map_or(0, |gpr| cpu.read_operand(OperandRegister::Gpr(gpr)).0)
}

fn wx(cpu: &mut CpuState, index: u8, val: u64) {
    if let Some(gpr) = Gpr::new(index) {
        cpu.write_operand(OperandRegister::Gpr(gpr), RegisterValue(val));
    }
}

fn first_u64_le(bytes: &[u8]) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(word)
}

impl ScriptedHvc2Executor {
    fn set_call(cpu: &mut CpuState, nr: u64, args: [u64; 6]) {
        wx(cpu, 8, nr);
        for (i, &arg) in args.iter().enumerate() {
            wx(cpu, i as u8, arg);
        }
    }

    fn publish_mailbox_request(&mut self, cpu: &CpuState) -> Result<(), String> {
        let ptr = self.mailbox.load(Ordering::Acquire);
        if ptr.is_null() {
            return Err("mailbox pointer was not bound before HVC #2".to_owned());
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        // SAFETY: `ptr` points to the stage-2 `Aarch64SyscallMailbox` slot while
        // the single soft vCPU is synchronously preparing `HVC #2`.
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).sequence), seq);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*ptr).trap_kind),
                MailboxTrapKind::Syscall.raw(),
            );
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).native_nr), rx(cpu, 8));
            core::ptr::write_volatile(
                &raw mut (*ptr).args,
                [
                    rx(cpu, 0),
                    rx(cpu, 1),
                    rx(cpu, 2),
                    rx(cpu, 3),
                    rx(cpu, 4),
                    rx(cpu, 5),
                ],
            );
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).resume_pc), cpu.el1.elr.0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).spsr), cpu.el1.spsr.0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).fp), rx(cpu, 29));
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).lr), rx(cpu, 30));
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).sp), cpu.sp_el0.0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).esr), cpu.el1.esr.0);
            (*ptr)
                .state
                .store(MailboxState::RequestReady.raw(), Ordering::Release);
        }
        Ok(())
    }

    fn consume_mailbox_response(&self, cpu: &mut CpuState) -> Result<(), String> {
        let ptr = self.mailbox.load(Ordering::Acquire);
        if ptr.is_null() {
            return Err("mailbox pointer was not bound on ERET".to_owned());
        }
        // SAFETY: `ptr` points to the stage-2 `Aarch64SyscallMailbox` slot.
        unsafe {
            let state = (*ptr).state.load(Ordering::Acquire);
            if state == MailboxState::Idle.raw() {
                // Non-SVC `legacy_hvc` (`EL0Fault` retry) returns directly via `eret`
                // without touching `x0` or mailbox state.
                return Ok(());
            }
            if state != MailboxState::ResponseReady.raw() {
                return Err(format!("expected ResponseReady (2) on ERET, got {state}"));
            }
            let retval = core::ptr::read_volatile(core::ptr::addr_of!((*ptr).return_value));
            wx(cpu, 0, retval);
            (*ptr)
                .state
                .store(MailboxState::Idle.raw(), Ordering::Release);
        }
        Ok(())
    }

    fn step_user_pc(&mut self, cpu: &mut CpuState) -> Result<(), String> {
        let step_index = (cpu.pc.0 - CODE_VA) / 4;
        let mut obs = self.obs.lock().map_err(|_| "poisoned obs".to_owned())?;
        let x0 = rx(cpu, 0);
        let x3 = rx(cpu, 3);
        match step_index {
            // 0: brk(0)
            0 => Self::set_call(cpu, NR_BRK, [0; 6]),
            // 1: brk(base + 0x4000)
            1 => {
                if x0 < DATA_VA + 0x1000 || (x0 as i64) < 0 {
                    return Err(format!("unexpected initial brk(0) = {x0:#x}"));
                }
                obs.brk_base = x0;
                Self::set_call(cpu, NR_BRK, [x0 + 0x4000, 0, 0, 0, 0, 0]);
            }
            // 2: str x2, [x1] into newly grown heap
            2 => {
                if x0 != obs.brk_base + 0x4000 {
                    return Err(format!("brk growth returned {x0:#x}"));
                }
                wx(cpu, 1, obs.brk_base);
                wx(cpu, 2, 0xCAFE_BABE_1234_5678);
            }
            // 3: ldr x3, [x1] from heap
            3 => {
                wx(cpu, 1, obs.brk_base);
            }
            // 4: verify heap load, then anonymous RW mmap(0x2000)
            4 => {
                obs.heap_roundtrip_word = x3;
                if obs.heap_roundtrip_word != 0xCAFE_BABE_1234_5678 {
                    return Err(format!(
                        "heap roundtrip mismatch: {:#x}",
                        obs.heap_roundtrip_word
                    ));
                }
                Self::set_call(
                    cpu,
                    NR_MMAP,
                    [
                        0,
                        0x2000,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        u64::MAX,
                        0,
                    ],
                );
            }
            // 5: str x2, [x1] into anonymous mmap
            5 => {
                if (x0 as i64) <= 0 || !x0.is_multiple_of(GUEST_PAGE_BYTES) {
                    return Err(format!("anonymous mmap failed: {x0:#x}"));
                }
                obs.anon_va = x0;
                wx(cpu, 1, x0);
                wx(cpu, 2, 0x1122_3344_5566_7788);
            }
            // 6: mprotect(anon_va, 0x2000, PROT_READ)
            6 => {
                Self::set_call(cpu, NR_MPROTECT, [obs.anon_va, 0x2000, PROT_READ, 0, 0, 0]);
            }
            // 7: ldr x3, [x1] from PROT_READ anonymous mapping
            7 => {
                if x0 != 0 {
                    return Err(format!("mprotect failed: {}", x0 as i64));
                }
                wx(cpu, 1, obs.anon_va);
            }
            // 8: verify PROT_READ load, then munmap(anon_va, 0x2000)
            8 => {
                obs.anon_readonly_word = x3;
                if obs.anon_readonly_word != 0x1122_3344_5566_7788 {
                    return Err(format!(
                        "PROT_READ load mismatch: {:#x}",
                        obs.anon_readonly_word
                    ));
                }
                Self::set_call(cpu, NR_MUNMAP, [obs.anon_va, 0x2000, 0, 0, 0, 0]);
            }
            // 9: openat(AT_FDCWD, "/hello.txt", O_RDONLY | O_CLOEXEC, 0)
            9 => {
                if x0 != 0 {
                    return Err(format!("munmap failed: {}", x0 as i64));
                }
                Self::set_call(
                    cpu,
                    NR_OPENAT,
                    [AT_FDCWD, DATA_VA + PATH_OFFSET, O_CLOEXEC, 0, 0, 0],
                );
            }
            // 10: fstat(fd, stat_buf)
            10 => {
                if (x0 as i64) < 3 {
                    return Err(format!("openat(/hello.txt) failed: {}", x0 as i64));
                }
                obs.opened_fd = x0;
                Self::set_call(cpu, NR_FSTAT, [x0, DATA_VA + STAT_OFFSET, 0, 0, 0, 0]);
            }
            // 11: read(fd, read_buf, 64)
            11 => {
                if x0 != 0 {
                    return Err(format!("fstat failed: {}", x0 as i64));
                }
                Self::set_call(
                    cpu,
                    NR_READ,
                    [obs.opened_fd, DATA_VA + READ_BUF_OFFSET, 64, 0, 0, 0],
                );
            }
            // 12: file-backed mmap(0, 0x1000, PROT_READ, MAP_SHARED, fd, 0): a
            // MapHostAlias where the host can alias a read-only fd (Linux), a
            // copy where it cannot (Darwin)
            12 => {
                if x0 != FILE_PAYLOAD.len() as u64 {
                    return Err(format!("read(/hello.txt) returned {}", x0 as i64));
                }
                Self::set_call(
                    cpu,
                    NR_MMAP,
                    [0, 0x1000, PROT_READ, MAP_SHARED, obs.opened_fd, 0],
                );
            }
            // 13: ldr x3, [x1] from MapHostAlias file mapping
            13 => {
                if (x0 as i64) <= 0 || !x0.is_multiple_of(GUEST_PAGE_BYTES) {
                    return Err(format!("file mmap failed: {x0:#x}"));
                }
                obs.file_alias_va = x0;
                wx(cpu, 1, x0);
            }
            // 14: verify file alias load, then close(fd)
            14 => {
                obs.file_alias_word = x3;
                let expected = first_u64_le(FILE_PAYLOAD);
                if obs.file_alias_word != expected {
                    return Err(format!(
                        "file alias word {:#x} != {expected:#x}",
                        obs.file_alias_word
                    ));
                }
                Self::set_call(cpu, NR_CLOSE, [obs.opened_fd, 0, 0, 0, 0, 0]);
            }
            // 15: clock_gettime(CLOCK_MONOTONIC, ts_buf)
            15 => {
                if x0 != 0 {
                    return Err(format!("close failed: {}", x0 as i64));
                }
                Self::set_call(
                    cpu,
                    NR_CLOCK_GETTIME,
                    [CLOCK_MONOTONIC, DATA_VA + TIMESPEC_OFFSET, 0, 0, 0, 0],
                );
            }
            // 16: write(1, STDOUT_PAYLOAD, len)
            16 => {
                if x0 != 0 {
                    return Err(format!("clock_gettime failed: {}", x0 as i64));
                }
                Self::set_call(
                    cpu,
                    NR_WRITE,
                    [
                        1,
                        DATA_VA + MSG_OFFSET,
                        STDOUT_PAYLOAD.len() as u64,
                        0,
                        0,
                        0,
                    ],
                );
            }
            // 17: exit_group(0)
            17 => {
                if x0 != STDOUT_PAYLOAD.len() as u64 {
                    return Err(format!("write(stdout) returned {}", x0 as i64));
                }
                Self::set_call(cpu, NR_EXIT_GROUP, [0; 6]);
            }
            other => {
                return Err(format!("unexpected user PC {:#x} (step {other})", cpu.pc.0));
            }
        }
        Ok(())
    }
}

impl ExecuteBlock for ScriptedHvc2Executor {
    type Error = String;
    type Code = ();

    fn prepare(&mut self, _block: &TranslatedBlock) -> Result<(), Self::Error> {
        Ok(())
    }

    fn execute(
        &mut self,
        block: &TranslatedBlock,
        _code: &(),
        cpu: &mut CpuState,
    ) -> Result<usize, Self::Error> {
        if cpu.pstate.el == ExceptionLevel::El0 && (CODE_VA..CODE_VA + 0x1000).contains(&cpu.pc.0) {
            self.step_user_pc(cpu)?;
        } else if cpu.pstate.el == ExceptionLevel::El1 {
            if cpu.pc.0 == LINUX_EL1_VECTORS_BASE + 0x400 {
                if carrick_hal::aarch64::is_aarch64_svc_exception(cpu.el1.esr.0) {
                    self.publish_mailbox_request(cpu)?;
                }
            } else if cpu.pc.0 == LINUX_EL1_VECTORS_BASE + 0x404 {
                self.consume_mailbox_response(cpu)?;
            }
        }

        for ins in block.guest().instructions() {
            match ins.instruction() {
                Instruction::Hint(Hint::Nop) | Instruction::Barrier(_) => {}
                _ if ins.class().terminates() => {}
                other => {
                    return Err(format!(
                        "unexpected non-terminating instruction {other:?} at PC={:#x}",
                        ins.pc().0
                    ));
                }
            }
        }

        match block.terminator() {
            Terminator::Handler(idx) | Terminator::Jump(idx) | Terminator::Fallthrough(idx) => {
                Ok(idx)
            }
            Terminator::Conditional { .. } => Err(format!(
                "unexpected conditional terminator at PC={:#x}",
                cpu.pc.0
            )),
        }
    }
}

static SOFT_CARRIER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock_soft_carrier_test() -> std::sync::MutexGuard<'static, ()> {
    SOFT_CARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn soft_facade_serves_single_process_hvc2_syscalls_via_production_kernel() {
    let _test_guard = lock_soft_carrier_test();
    let temp = tempfile::tempdir().expect("create witness rootfs tempdir");
    std::fs::write(temp.path().join("hello.txt"), FILE_PAYLOAD).expect("write rootfs /hello.txt");

    let code_words = [
        A64_SVC_0,     // 0: brk(0)
        A64_SVC_0,     // 1: brk(base + 0x4000)
        A64_STR_X2_X1, // 2: store heap word through live stage-1 + SoftStage2
        A64_LDR_X3_X1, // 3: load heap word
        A64_SVC_0,     // 4: mmap anonymous RW
        A64_STR_X2_X1, // 5: store anonymous word
        A64_SVC_0,     // 6: mprotect PROT_READ
        A64_LDR_X3_X1, // 7: load anonymous word under PROT_READ
        A64_SVC_0,     // 8: munmap anonymous
        A64_SVC_0,     // 9: openat("/hello.txt")
        A64_SVC_0,     // 10: fstat
        A64_SVC_0,     // 11: read
        A64_SVC_0,     // 12: mmap(fd) -> MapHostAlias
        A64_LDR_X3_X1, // 13: load file-backed alias word through live stage-1 + SoftStage2
        A64_SVC_0,     // 14: close(fd)
        A64_SVC_0,     // 15: clock_gettime(CLOCK_MONOTONIC)
        A64_SVC_0,     // 16: write(1, STDOUT_PAYLOAD)
        A64_SVC_0,     // 17: exit_group(0)
    ];
    let elf = build_witness_elf(
        &code_words,
        &[
            (PATH_OFFSET as usize, b"/hello.txt\0"),
            (MSG_OFFSET as usize, STDOUT_PAYLOAD),
        ],
    );

    let mailbox_slot = Arc::new(AtomicPtr::new(null_mut()));
    let obs = Arc::new(Mutex::new(WitnessObservations::default()));
    let executor = ScriptedHvc2Executor {
        mailbox: Arc::clone(&mailbox_slot),
        obs: Arc::clone(&obs),
        next_seq: 1,
    };

    let mut config = SoftSingleProcessConfig::new(&elf, "/witness");
    config.rootfs_dir = Some(temp.path());

    let mb_for_setup = Arc::clone(&mailbox_slot);
    let run = run_single_process_with_executor_and_setup(&config, executor, move |engine| {
        // Install minimal `hvc #2; eret` at EL0 synchronous SVC vector `VBAR_EL1 + 0x400`.
        let mut vec_stub = [0u8; 8];
        vec_stub[0..4].copy_from_slice(&A64_HVC_2.to_le_bytes());
        vec_stub[4..8].copy_from_slice(&A64_ERET.to_le_bytes());
        engine
            .backend()
            .write_gpa(LINUX_EL1_VECTORS_BASE + 0x400, &vec_stub)
            .map_err(|e| format!("install witness EL1 vector stub: {e}"))?;
        let ptr = engine
            .backend()
            .host_ptr(
                LINUX_SYSCALL_MAILBOX_BASE,
                AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .ok_or_else(|| "missing stage-2 syscall mailbox host_ptr".to_owned())?;
        mb_for_setup.store(ptr.cast::<Aarch64SyscallMailbox>(), Ordering::Release);
        Ok(())
    })
    .expect("single-process witness should exit cleanly through production kernel");

    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout, STDOUT_PAYLOAD);
    assert!(run.stderr.is_empty());
    assert_eq!(run.syscalls_dispatched, 13);
    assert_eq!(
        run.reply_census,
        Hvc2ReplyCensus {
            ring_completed: 0,
            kernel_dispatched: 13,
            runner_refused: 0,
        }
    );
    assert_eq!(run.terminating_fault, None);
    assert!(
        run.counted_enosys.is_empty(),
        "unexpected counted ENOSYS: {:?}",
        run.counted_enosys
    );

    let final_obs = obs.lock().expect("lock witness observations");
    assert_eq!(final_obs.heap_roundtrip_word, 0xCAFE_BABE_1234_5678);
    assert_eq!(final_obs.anon_readonly_word, 0x1122_3344_5566_7788);
    assert_eq!(
        final_obs.file_alias_word,
        u64::from_le_bytes(FILE_PAYLOAD[..8].try_into().unwrap())
    );

    // Verify kernel-written guest buffers (`fstat`, `read`, `clock_gettime`)
    // through `Aarch64EngineCore<SoftAarch64Vmm>`'s stage-1 `GuestMemory` implementation.
    let read_back = run
        .engine
        .read_bytes(DATA_VA + READ_BUF_OFFSET, FILE_PAYLOAD.len())
        .expect("read guest file buffer");
    assert_eq!(read_back, FILE_PAYLOAD);

    let stat_size_bytes = run
        .engine
        .read_bytes(DATA_VA + STAT_OFFSET + 48, 8)
        .expect("read Linux aarch64 stat.st_size");
    let st_size = i64::from_le_bytes(stat_size_bytes.try_into().unwrap());
    assert_eq!(st_size, FILE_PAYLOAD.len() as i64);

    let ts_bytes = run
        .engine
        .read_bytes(DATA_VA + TIMESPEC_OFFSET, 16)
        .expect("read clock_gettime timespec");
    let tv_sec = i64::from_le_bytes(ts_bytes[0..8].try_into().unwrap());
    let tv_nsec = i64::from_le_bytes(ts_bytes[8..16].try_into().unwrap());
    assert!(
        tv_sec > 0 || tv_nsec > 0,
        "expected positive CLOCK_MONOTONIC timespec, got ({tv_sec}, {tv_nsec})"
    );
}

#[test]
fn soft_stage2_enforces_execute_permission_and_extent_code_generations() {
    let geometry = MappingGeometry::probe();
    assert_eq!(geometry.guest_page_bytes, 4096);
    assert!(geometry.host_backing_granule >= 4096);
    assert!(geometry.host_backing_granule.is_power_of_two());

    let mut stage2 = SoftStage2::new().expect("allocate SoftStage2");
    let frame = 0x2000_0000u64;
    let mut word = [0u8; 4];

    // 1. Unmapped fetch records an Unmapped Fetch abort.
    assert!(SoftGuestMemory::fetch(&mut stage2, VirtualAddress(frame), &mut word).is_err());
    assert_eq!(
        stage2.last_abort(),
        Some(Stage2Abort {
            gpa: frame,
            access: Stage2AbortAccess::Fetch,
            reason: Stage2AbortReason::Unmapped,
        })
    );

    // 2. RW-only mapping allows read/write but denies instruction fetch and code-page marking.
    stage2
        .map_owned_anonymous(
            frame,
            GUEST_PAGE_BYTES,
            MemPerms {
                read: true,
                write: true,
                exec: false,
            },
            false,
        )
        .expect("map RW stage-2 page");
    SoftGuestMemory::write(&mut stage2, VirtualAddress(frame), &A64_NOP.to_le_bytes())
        .expect("guest write to RW page");
    SoftGuestMemory::read(&mut stage2, VirtualAddress(frame), &mut word)
        .expect("guest read from RW page");
    assert_eq!(u32::from_le_bytes(word), A64_NOP);

    assert!(SoftGuestMemory::fetch(&mut stage2, VirtualAddress(frame), &mut word).is_err());
    assert_eq!(
        stage2.last_abort(),
        Some(Stage2Abort {
            gpa: frame,
            access: Stage2AbortAccess::Fetch,
            reason: Stage2AbortReason::PermissionDenied,
        })
    );
    assert_eq!(
        SoftGuestMemory::mark_code_page(&mut stage2, FrameGpa::new(frame)),
        None,
        "NX stage-2 frame must refuse code-page registration"
    );

    // 3. Promoting stage-2 permissions to RWX admits fetch and ExtentTable code generations,
    // and both guest stores and host writes bump the frame's code generation.
    stage2
        .protect_stage2(frame, GUEST_PAGE_BYTES, MemPerms::ReadWriteExec)
        .expect("promote stage-2 page to RWX");
    SoftGuestMemory::fetch(&mut stage2, VirtualAddress(frame), &mut word)
        .expect("fetch from RWX page");
    assert_eq!(u32::from_le_bytes(word), A64_NOP);

    let gen1 = SoftGuestMemory::mark_code_page(&mut stage2, FrameGpa::new(frame))
        .expect("mark executable code page");
    assert_eq!(
        SoftGuestMemory::code_generation(&stage2, FrameGpa::new(frame)),
        Some(gen1)
    );

    SoftGuestMemory::write(
        &mut stage2,
        VirtualAddress(frame + 4),
        &A64_NOP.to_le_bytes(),
    )
    .expect("guest store into tracked code page");
    let after_guest_write = SoftGuestMemory::code_generation(&stage2, FrameGpa::new(frame))
        .expect("code generation after guest store");
    assert_ne!(
        after_guest_write, gen1,
        "guest store to tracked code page must bump ExtentTable generation"
    );

    let gen2 = SoftGuestMemory::mark_code_page(&mut stage2, FrameGpa::new(frame))
        .expect("re-mark code page after guest store");
    stage2
        .write_gpa_bytes(frame + 8, &A64_NOP.to_le_bytes())
        .expect("host DMA/ELF write into tracked code page");
    let after_host_write = SoftGuestMemory::code_generation(&stage2, FrameGpa::new(frame))
        .expect("code generation after host write");
    assert_ne!(
        after_host_write, gen2,
        "host write_gpa_bytes to tracked code page must bump ExtentTable generation"
    );
}

struct SequenceHvc2Executor {
    mailbox: Arc<AtomicPtr<Aarch64SyscallMailbox>>,
    calls: Vec<(u64, [u64; 6])>,
    returns: Arc<Mutex<Vec<i64>>>,
    next_seq: u64,
}

impl SequenceHvc2Executor {
    fn publish_mailbox_request(&mut self, cpu: &CpuState) -> Result<(), String> {
        let ptr = self.mailbox.load(Ordering::Acquire);
        if ptr.is_null() {
            return Err("mailbox pointer was not bound before HVC #2".to_owned());
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        // SAFETY: `ptr` points to the stage-2 `Aarch64SyscallMailbox` slot while
        // the single soft vCPU is synchronously preparing `HVC #2`.
        unsafe {
            core::ptr::write_volatile(&raw mut (*ptr).sequence, seq);
            core::ptr::write_volatile(&raw mut (*ptr).trap_kind, MailboxTrapKind::Syscall.raw());
            core::ptr::write_volatile(&raw mut (*ptr).native_nr, rx(cpu, 8));
            core::ptr::write_volatile(
                &raw mut (*ptr).args,
                [
                    rx(cpu, 0),
                    rx(cpu, 1),
                    rx(cpu, 2),
                    rx(cpu, 3),
                    rx(cpu, 4),
                    rx(cpu, 5),
                ],
            );
            core::ptr::write_volatile(&raw mut (*ptr).resume_pc, cpu.el1.elr.0);
            core::ptr::write_volatile(&raw mut (*ptr).spsr, cpu.el1.spsr.0);
            core::ptr::write_volatile(&raw mut (*ptr).fp, rx(cpu, 29));
            core::ptr::write_volatile(&raw mut (*ptr).lr, rx(cpu, 30));
            core::ptr::write_volatile(&raw mut (*ptr).sp, cpu.sp_el0.0);
            core::ptr::write_volatile(&raw mut (*ptr).esr, cpu.el1.esr.0);
            (*ptr)
                .state
                .store(MailboxState::RequestReady.raw(), Ordering::Release);
        }
        Ok(())
    }

    fn consume_mailbox_response(&self, cpu: &mut CpuState) -> Result<(), String> {
        let ptr = self.mailbox.load(Ordering::Acquire);
        if ptr.is_null() {
            return Err("mailbox pointer was not bound on ERET".to_owned());
        }
        // SAFETY: `ptr` points to the stage-2 `Aarch64SyscallMailbox` slot.
        unsafe {
            let state = (*ptr).state.load(Ordering::Acquire);
            if state == MailboxState::Idle.raw() {
                return Ok(());
            }
            if state != MailboxState::ResponseReady.raw() {
                return Err(format!("expected ResponseReady (2) on ERET, got {state}"));
            }
            let retval = core::ptr::read_volatile(&raw const (*ptr).return_value);
            wx(cpu, 0, retval);
            (*ptr)
                .state
                .store(MailboxState::Idle.raw(), Ordering::Release);
            self.returns
                .lock()
                .map_err(|_| "poisoned returns".to_owned())?
                .push(retval as i64);
        }
        Ok(())
    }
}

impl ExecuteBlock for SequenceHvc2Executor {
    type Error = String;
    type Code = ();

    fn prepare(&mut self, _block: &TranslatedBlock) -> Result<(), Self::Error> {
        Ok(())
    }

    fn execute(
        &mut self,
        block: &TranslatedBlock,
        _code: &(),
        cpu: &mut CpuState,
    ) -> Result<usize, Self::Error> {
        if cpu.pstate.el == ExceptionLevel::El0 && (CODE_VA..CODE_VA + 0x1000).contains(&cpu.pc.0) {
            let step_index = ((cpu.pc.0 - CODE_VA) / 4) as usize;
            let &(nr, args) = self
                .calls
                .get(step_index)
                .ok_or_else(|| format!("unexpected sequence step {step_index}"))?;
            ScriptedHvc2Executor::set_call(cpu, nr, args);
        } else if cpu.pstate.el == ExceptionLevel::El1 {
            if cpu.pc.0 == LINUX_EL1_VECTORS_BASE + 0x400 {
                if carrick_hal::aarch64::is_aarch64_svc_exception(cpu.el1.esr.0) {
                    self.publish_mailbox_request(cpu)?;
                }
            } else if cpu.pc.0 == LINUX_EL1_VECTORS_BASE + 0x404 {
                self.consume_mailbox_response(cpu)?;
            }
        }
        match block.terminator() {
            Terminator::Handler(idx) | Terminator::Jump(idx) | Terminator::Fallthrough(idx) => {
                Ok(idx)
            }
            Terminator::Conditional { .. } => Err("unexpected conditional terminator".to_owned()),
        }
    }
}

/// A kernel-raised `SIGPIPE` with its default disposition must take its
/// default action (terminate) at the guest's return from `write`, never be
/// left pending while the guest runs on (#2696).
#[test]
fn soft_single_process_pending_kernel_sigpipe_takes_default_death() {
    let _test_guard = lock_soft_carrier_test();
    let calls = vec![
        (NR_PIPE2, [DATA_VA + 0x400, 0, 0, 0, 0, 0]),
        (NR_CLOSE, [3, 0, 0, 0, 0, 0]),
        (NR_WRITE, [4, DATA_VA, 1, 0, 0, 0]),
        (NR_EXIT_GROUP, [0; 6]),
    ];
    let code_words = vec![A64_SVC_0; calls.len()];
    let elf = build_witness_elf(&code_words, &[(0, b"x")]);

    let mailbox_slot = Arc::new(AtomicPtr::new(null_mut()));
    let returns = Arc::new(Mutex::new(Vec::new()));
    let executor = SequenceHvc2Executor {
        mailbox: Arc::clone(&mailbox_slot),
        calls,
        returns: Arc::clone(&returns),
        next_seq: 1,
    };
    let config = SoftSingleProcessConfig::new(&elf, "/sigpipe-default");
    let mb_for_setup = Arc::clone(&mailbox_slot);
    let run = run_single_process_with_executor_and_setup(&config, executor, move |engine| {
        let mut vec_stub = [0u8; 8];
        vec_stub[0..4].copy_from_slice(&A64_HVC_2.to_le_bytes());
        vec_stub[4..8].copy_from_slice(&A64_ERET.to_le_bytes());
        engine
            .backend()
            .write_gpa(LINUX_EL1_VECTORS_BASE + 0x400, &vec_stub)
            .map_err(|e| format!("install witness EL1 vector stub: {e}"))?;
        let ptr = engine
            .backend()
            .host_ptr(
                LINUX_SYSCALL_MAILBOX_BASE,
                AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .ok_or_else(|| "missing stage-2 syscall mailbox host_ptr".to_owned())?;
        mb_for_setup.store(ptr.cast::<Aarch64SyscallMailbox>(), Ordering::Release);
        Ok(())
    })
    .expect("SIGPIPE run should end in signal death through the production kernel");

    let pipe_fds = run
        .engine
        .read_bytes(DATA_VA + 0x400, 8)
        .expect("read pipe2 descriptors");
    assert_eq!(pipe_fds, [3, 0, 0, 0, 4, 0, 0, 0]);
    assert_eq!(
        run.exit_code,
        128 + carrick_abi::LINUX_SIGPIPE,
        "default SIGPIPE must terminate the process at the write's return"
    );
    assert_eq!(run.terminating_fault, None);
    assert_eq!(*returns.lock().expect("lock returns"), vec![0, 0]);
    assert_eq!(run.syscalls_dispatched, 3);
}

#[test]
fn soft_single_process_refuses_timer_and_signal_syscalls_with_counted_enosys() {
    let _test_guard = lock_soft_carrier_test();
    // Prepare a 1-second `itimerval` (`it_value.tv_sec = 1`) at `DATA_VA + 0x300`,
    // a `SIG_IGN` `sigaction` at `DATA_VA + 0x340`, and a custom user-handler
    // `sigaction` (`sa_handler = CODE_VA`) at `DATA_VA + 0x380`.
    let mut itimerval = [0u8; 32];
    itimerval[16..24].copy_from_slice(&1i64.to_le_bytes());
    let mut ign_sigaction = [0u8; 32];
    ign_sigaction[0..8].copy_from_slice(&carrick_abi::LINUX_SIG_IGN.to_le_bytes());
    let mut custom_sigaction = [0u8; 32];
    custom_sigaction[0..8].copy_from_slice(&CODE_VA.to_le_bytes());
    let calls = vec![
        (NR_RT_SIGACTION, [13, DATA_VA + 0x340, 0, 8, 0, 0]), // SIGPIPE = SIG_IGN -> 0
        (NR_TIMERFD_CREATE, [CLOCK_MONOTONIC, 0, 0, 0, 0, 0]),
        (NR_SETITIMER, [0, DATA_VA + 0x300, 0, 0, 0, 0]),
        (NR_RT_SIGACTION, [10, DATA_VA + 0x380, 0, 8, 0, 0]), // custom handler -> -ENOSYS
        (NR_TKILL, [1, 0, 0, 0, 0, 0]),
        (NR_EXIT_GROUP, [0; 6]),
    ];
    let code_words = vec![A64_SVC_0; calls.len()];
    let elf = build_witness_elf(
        &code_words,
        &[
            (0x300, &itimerval),
            (0x340, &ign_sigaction),
            (0x380, &custom_sigaction),
        ],
    );

    let mailbox_slot = Arc::new(AtomicPtr::new(null_mut()));
    let returns = Arc::new(Mutex::new(Vec::new()));
    let executor = SequenceHvc2Executor {
        mailbox: Arc::clone(&mailbox_slot),
        calls,
        returns: Arc::clone(&returns),
        next_seq: 1,
    };
    let config = SoftSingleProcessConfig::new(&elf, "/refuse-timers-signals");
    let mb_for_setup = Arc::clone(&mailbox_slot);
    let run = run_single_process_with_executor_and_setup(&config, executor, move |engine| {
        let mut vec_stub = [0u8; 8];
        vec_stub[0..4].copy_from_slice(&A64_HVC_2.to_le_bytes());
        vec_stub[4..8].copy_from_slice(&A64_ERET.to_le_bytes());
        engine
            .backend()
            .write_gpa(LINUX_EL1_VECTORS_BASE + 0x400, &vec_stub)
            .map_err(|e| format!("install witness EL1 vector stub: {e}"))?;
        let ptr = engine
            .backend()
            .host_ptr(
                LINUX_SYSCALL_MAILBOX_BASE,
                AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .ok_or_else(|| "missing stage-2 syscall mailbox host_ptr".to_owned())?;
        mb_for_setup.store(ptr.cast::<Aarch64SyscallMailbox>(), Ordering::Release);
        Ok(())
    })
    .expect("single-process run should complete cleanly after counted ENOSYS refusals");

    assert_eq!(run.exit_code, 0);
    let observed_returns = returns.lock().expect("lock returns").clone();
    let enosys = carrick_abi::LINUX_ENOSYS.guest_retval();
    assert_eq!(
        observed_returns,
        vec![0, enosys, enosys, enosys, enosys],
        "SIG_IGN disposition may succeed, while custom handlers, timers, and signal sends must fail closed with -ENOSYS"
    );
    assert_eq!(
        run.counted_enosys,
        vec![
            (NR_TIMERFD_CREATE, "timerfd_create", 1),
            (NR_SETITIMER, "setitimer", 1),
            (NR_TKILL, "tkill", 1),
            (NR_RT_SIGACTION, "rt_sigaction", 1),
        ]
    );
}

#[test]
fn soft_carrier_enforces_single_live_aperture_and_compare_clears() {
    let _test_guard = lock_soft_carrier_test();

    let elf = build_witness_elf(&[A64_SVC_0], &[]);
    let make_exit_executor = || {
        let mailbox = Arc::new(AtomicPtr::new(null_mut()));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let exec = SequenceHvc2Executor {
            mailbox: Arc::clone(&mailbox),
            calls: vec![(NR_EXIT_GROUP, [0; 6])],
            returns,
            next_seq: 1,
        };
        (mailbox, exec)
    };
    let install_stub_and_bind =
        |engine: &mut carrick_softcpu_aarch64_host::SoftAarch64Engine<SequenceHvc2Executor>,
         mailbox: &AtomicPtr<Aarch64SyscallMailbox>|
         -> Result<(), String> {
            let mut vec_stub = [0u8; 8];
            vec_stub[0..4].copy_from_slice(&A64_HVC_2.to_le_bytes());
            vec_stub[4..8].copy_from_slice(&A64_ERET.to_le_bytes());
            engine
                .backend()
                .write_gpa(LINUX_EL1_VECTORS_BASE + 0x400, &vec_stub)
                .map_err(|e| format!("install witness EL1 vector stub: {e}"))?;
            let ptr = engine
                .backend()
                .host_ptr(
                    LINUX_SYSCALL_MAILBOX_BASE,
                    AARCH64_SYSCALL_MAILBOX_SIZE as usize,
                )
                .ok_or_else(|| "missing stage-2 syscall mailbox host_ptr".to_owned())?;
            mailbox.store(ptr.cast::<Aarch64SyscallMailbox>(), Ordering::Release);
            Ok(())
        };

    let entered_barrier = Arc::new(std::sync::Barrier::new(2));
    let release_barrier = Arc::new(std::sync::Barrier::new(2));
    let carrier1_ptr = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    std::thread::scope(|s| {
        let entered_for_t2 = Arc::clone(&entered_barrier);
        let release_for_t2 = Arc::clone(&release_barrier);
        let ptr_for_t2 = Arc::clone(&carrier1_ptr);
        let elf_for_t2 = &elf;

        let t2 = s.spawn(move || {
            struct ReleaseOnDrop(Arc<std::sync::Barrier>);
            impl Drop for ReleaseOnDrop {
                fn drop(&mut self) {
                    self.0.wait();
                }
            }
            entered_for_t2.wait();
            let _release = ReleaseOnDrop(release_for_t2);
            let live_ptr = ptr_for_t2.load(Ordering::Acquire);
            assert_ne!(
                live_ptr, 0,
                "carrier 1 must have published its EL1 aperture"
            );

            // Concurrent second carrier on another thread must fail closed without
            // overwriting or clearing carrier 1's live EL1 aperture.
            let (mb2, exec2) = make_exit_executor();
            let cfg2 = SoftSingleProcessConfig::new(elf_for_t2, "/concurrent-second");
            let second_res = run_single_process_with_executor_and_setup(&cfg2, exec2, |engine| {
                install_stub_and_bind(engine, &mb2)
            });
            let err = match second_res {
                Err(err) => err,
                Ok(run) => panic!(
                    "second concurrent soft carrier must fail closed, but exited {}",
                    run.exit_code
                ),
            };
            assert!(
                err.contains("already active"),
                "unexpected concurrent soft-carrier refusal message: {err}"
            );
            assert_eq!(
                carrick_el1_abi::get_el1_region_host_ptr(),
                live_ptr,
                "concurrent refusal must not clobber carrier 1's published EL1 aperture"
            );

            // A stale compare-and-clear with a mismatched address must leave carrier 1 intact.
            assert!(!carrick_el1_abi::clear_el1_region_host_ptr_if(
                live_ptr ^ 0x1000
            ));
            assert_eq!(carrick_el1_abi::get_el1_region_host_ptr(), live_ptr);
        });

        let (mb1, exec1) = make_exit_executor();
        let cfg1 = SoftSingleProcessConfig::new(&elf, "/carrier-one");
        let run1 = run_single_process_with_executor_and_setup(&cfg1, exec1, |engine| {
            install_stub_and_bind(engine, &mb1)?;
            let ptr = carrick_el1_abi::get_el1_region_host_ptr();
            carrier1_ptr.store(ptr, Ordering::Release);
            entered_barrier.wait();
            release_barrier.wait();
            assert_eq!(
                carrick_el1_abi::get_el1_region_host_ptr(),
                ptr,
                "carrier 1's EL1 aperture must still be live before stepping"
            );
            Ok(())
        })
        .expect("carrier 1 should complete cleanly after concurrent refusal");
        assert_eq!(run1.exit_code, 0);

        t2.join().expect("concurrent witness thread");
    });

    assert_eq!(
        carrick_el1_abi::get_el1_region_host_ptr(),
        0,
        "carrier 1 drop must compare-and-clear its own EL1 aperture"
    );

    // Sequential carrier after carrier 1 dropped must acquire the lease and succeed.
    let (mb3, exec3) = make_exit_executor();
    let cfg3 = SoftSingleProcessConfig::new(&elf, "/sequential-third");
    let run3 = run_single_process_with_executor_and_setup(&cfg3, exec3, |engine| {
        install_stub_and_bind(engine, &mb3)
    })
    .expect("sequential soft carrier after drop must succeed");
    assert_eq!(run3.exit_code, 0);
    assert_eq!(carrick_el1_abi::get_el1_region_host_ptr(), 0);
}

enum NegativeMmCase {
    StoreAfterMprotectReadOnly,
    LoadAfterMunmap,
    /// Not a negative case: a System V segment attached with `shmat` is a
    /// `MapHostAlias` on every host, the alias whose frame inventory the
    /// kernel must learn.
    SysvShmAlias,
}

struct NegativeMmExecutor {
    mailbox: Arc<AtomicPtr<Aarch64SyscallMailbox>>,
    case: NegativeMmCase,
    mapped_va: Arc<std::sync::atomic::AtomicU64>,
    shm_id: u64,
    next_seq: u64,
}

impl NegativeMmExecutor {
    fn publish_mailbox_request(&mut self, cpu: &CpuState) -> Result<(), String> {
        let ptr = self.mailbox.load(Ordering::Acquire);
        if ptr.is_null() {
            return Err("mailbox pointer was not bound before HVC #2".to_owned());
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        // SAFETY: `ptr` points to the stage-2 `Aarch64SyscallMailbox` slot.
        unsafe {
            core::ptr::write_volatile(&raw mut (*ptr).sequence, seq);
            core::ptr::write_volatile(&raw mut (*ptr).trap_kind, MailboxTrapKind::Syscall.raw());
            core::ptr::write_volatile(&raw mut (*ptr).native_nr, rx(cpu, 8));
            core::ptr::write_volatile(
                &raw mut (*ptr).args,
                [
                    rx(cpu, 0),
                    rx(cpu, 1),
                    rx(cpu, 2),
                    rx(cpu, 3),
                    rx(cpu, 4),
                    rx(cpu, 5),
                ],
            );
            core::ptr::write_volatile(&raw mut (*ptr).resume_pc, cpu.el1.elr.0);
            core::ptr::write_volatile(&raw mut (*ptr).spsr, cpu.el1.spsr.0);
            core::ptr::write_volatile(&raw mut (*ptr).fp, rx(cpu, 29));
            core::ptr::write_volatile(&raw mut (*ptr).lr, rx(cpu, 30));
            core::ptr::write_volatile(&raw mut (*ptr).sp, cpu.sp_el0.0);
            core::ptr::write_volatile(&raw mut (*ptr).esr, cpu.el1.esr.0);
            (*ptr)
                .state
                .store(MailboxState::RequestReady.raw(), Ordering::Release);
        }
        Ok(())
    }

    fn consume_mailbox_response(&self, cpu: &mut CpuState) -> Result<(), String> {
        let ptr = self.mailbox.load(Ordering::Acquire);
        if ptr.is_null() {
            return Err("mailbox pointer was not bound on ERET".to_owned());
        }
        // SAFETY: `ptr` points to the stage-2 `Aarch64SyscallMailbox` slot.
        unsafe {
            let state = (*ptr).state.load(Ordering::Acquire);
            if state == MailboxState::Idle.raw() {
                return Ok(());
            }
            if state != MailboxState::ResponseReady.raw() {
                return Err(format!("expected ResponseReady (2) on ERET, got {state}"));
            }
            let retval = core::ptr::read_volatile(&raw const (*ptr).return_value);
            wx(cpu, 0, retval);
            (*ptr)
                .state
                .store(MailboxState::Idle.raw(), Ordering::Release);
        }
        Ok(())
    }
}

impl ExecuteBlock for NegativeMmExecutor {
    type Error = String;
    type Code = ();

    fn prepare(&mut self, _block: &TranslatedBlock) -> Result<(), Self::Error> {
        Ok(())
    }

    fn execute(
        &mut self,
        block: &TranslatedBlock,
        _code: &(),
        cpu: &mut CpuState,
    ) -> Result<usize, Self::Error> {
        if cpu.pstate.el == ExceptionLevel::El0 && (CODE_VA..CODE_VA + 0x1000).contains(&cpu.pc.0) {
            let step = (cpu.pc.0 - CODE_VA) / 4;
            let x0 = rx(cpu, 0);
            match (&self.case, step) {
                // 0: shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | 0600)
                (NegativeMmCase::SysvShmAlias, 0) => ScriptedHvc2Executor::set_call(
                    cpu,
                    NR_SHMGET,
                    [0, 0x1000, 0o1000 | 0o600, 0, 0, 0],
                ),
                // 1: shmat(id, NULL, 0) -> MapHostAlias
                (NegativeMmCase::SysvShmAlias, 1) => {
                    if (x0 as i64) < 0 {
                        return Err(format!("shmget failed: {}", x0 as i64));
                    }
                    self.shm_id = x0;
                    ScriptedHvc2Executor::set_call(cpu, NR_SHMAT, [x0, 0, 0, 0, 0, 0]);
                }
                // 2: str x2, [x1] into the attached segment
                (NegativeMmCase::SysvShmAlias, 2) => {
                    if (x0 as i64) <= 0 || !x0.is_multiple_of(GUEST_PAGE_BYTES) {
                        return Err(format!("shmat({}) failed: {x0:#x}", self.shm_id));
                    }
                    self.mapped_va.store(x0, Ordering::Release);
                    wx(cpu, 1, x0);
                    wx(cpu, 2, 0x5348_4D41_4C49_4153);
                }
                // 3: ldr x3, [x1] back through the alias
                (NegativeMmCase::SysvShmAlias, 3) => {
                    wx(cpu, 1, self.mapped_va.load(Ordering::Acquire));
                }
                // 4: exit_group(0) with the segment still attached
                (NegativeMmCase::SysvShmAlias, 4) => {
                    if rx(cpu, 3) != 0x5348_4D41_4C49_4153 {
                        return Err(format!("shm alias load: {:#x}", rx(cpu, 3)));
                    }
                    ScriptedHvc2Executor::set_call(cpu, NR_EXIT_GROUP, [0, 0, 0, 0, 0, 0]);
                }
                // 0: mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
                (_, 0) => ScriptedHvc2Executor::set_call(
                    cpu,
                    NR_MMAP,
                    [
                        0,
                        0x1000,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        u64::MAX,
                        0,
                    ],
                ),
                // 1: str x2, [x1] into RW mapping
                (_, 1) => {
                    if (x0 as i64) <= 0 || !x0.is_multiple_of(GUEST_PAGE_BYTES) {
                        return Err(format!("mmap failed: {x0:#x}"));
                    }
                    self.mapped_va.store(x0, Ordering::Release);
                    wx(cpu, 1, x0);
                    wx(cpu, 2, 0xDEAD_BEEF_CAFE_0001);
                }
                // 2: mprotect(va, 0x1000, PROT_READ) or munmap(va, 0x1000)
                (NegativeMmCase::StoreAfterMprotectReadOnly, 2) => {
                    let va = self.mapped_va.load(Ordering::Acquire);
                    ScriptedHvc2Executor::set_call(
                        cpu,
                        NR_MPROTECT,
                        [va, 0x1000, PROT_READ, 0, 0, 0],
                    );
                }
                (NegativeMmCase::LoadAfterMunmap, 2) => {
                    let va = self.mapped_va.load(Ordering::Acquire);
                    ScriptedHvc2Executor::set_call(cpu, NR_MUNMAP, [va, 0x1000, 0, 0, 0, 0]);
                }
                // 3: ldr x3, [x1] under PROT_READ (must succeed), or faulting ldr after munmap
                (NegativeMmCase::StoreAfterMprotectReadOnly, 3) => {
                    if x0 != 0 {
                        return Err(format!("mprotect(PROT_READ) failed: {}", x0 as i64));
                    }
                    wx(cpu, 1, self.mapped_va.load(Ordering::Acquire));
                }
                (NegativeMmCase::LoadAfterMunmap, 3) => {
                    if x0 != 0 {
                        return Err(format!("munmap failed: {}", x0 as i64));
                    }
                    wx(cpu, 1, self.mapped_va.load(Ordering::Acquire));
                }
                // 4: faulting str x2, [x1] into PROT_READ page (must fault with SEGV_ACCERR)
                (NegativeMmCase::StoreAfterMprotectReadOnly, 4) => {
                    if rx(cpu, 3) != 0xDEAD_BEEF_CAFE_0001 {
                        return Err(format!("unexpected PROT_READ load: {:#x}", rx(cpu, 3)));
                    }
                    wx(cpu, 1, self.mapped_va.load(Ordering::Acquire));
                    wx(cpu, 2, 0xBAD0_BAD0_BAD0_BAD0);
                }
                (_, other) => {
                    return Err(format!(
                        "guest must not reach step {other} after faulting memory access"
                    ));
                }
            }
        } else if cpu.pstate.el == ExceptionLevel::El1 {
            if cpu.pc.0 == LINUX_EL1_VECTORS_BASE + 0x400 {
                if carrick_hal::aarch64::is_aarch64_svc_exception(cpu.el1.esr.0) {
                    self.publish_mailbox_request(cpu)?;
                }
            } else if cpu.pc.0 == LINUX_EL1_VECTORS_BASE + 0x404 {
                self.consume_mailbox_response(cpu)?;
            }
        }
        match block.terminator() {
            Terminator::Handler(idx) | Terminator::Jump(idx) | Terminator::Fallthrough(idx) => {
                Ok(idx)
            }
            Terminator::Conditional { .. } => Err("unexpected conditional terminator".to_owned()),
        }
    }
}

#[test]
fn soft_single_process_store_after_mprotect_prot_read_faults_with_segv_accerr() {
    let _test_guard = lock_soft_carrier_test();

    // Stage-2 negative check: demoting a frame to read-only denies guest writes.
    let mut stage2 = SoftStage2::new().expect("allocate SoftStage2");
    let frame = 0x2400_0000u64;
    stage2
        .map_owned_anonymous(
            frame,
            GUEST_PAGE_BYTES,
            MemPerms {
                read: true,
                write: true,
                exec: false,
            },
            false,
        )
        .expect("map RW stage-2 page");
    SoftGuestMemory::write(
        &mut stage2,
        VirtualAddress(frame),
        &0x1234_5678u32.to_le_bytes(),
    )
    .expect("write RW stage-2 page");
    stage2
        .protect_stage2(
            frame,
            GUEST_PAGE_BYTES,
            MemPerms {
                read: true,
                write: false,
                exec: false,
            },
        )
        .expect("demote stage-2 page to RO");
    assert!(
        SoftGuestMemory::write(
            &mut stage2,
            VirtualAddress(frame),
            &0x9999_9999u32.to_le_bytes()
        )
        .is_err(),
        "store to RO stage-2 page must fail"
    );
    assert_eq!(
        stage2.last_abort(),
        Some(Stage2Abort {
            gpa: frame,
            access: Stage2AbortAccess::Write,
            reason: Stage2AbortReason::PermissionDenied,
        })
    );

    // Production stage-1 + kernel dispatch negative check:
    // 0: mmap(RW), 1: str, 2: mprotect(PROT_READ), 3: ldr (ok), 4: str (SEGV_ACCERR), 5: exit_group
    let code_words = [
        A64_SVC_0,
        A64_STR_X2_X1,
        A64_SVC_0,
        A64_LDR_X3_X1,
        A64_STR_X2_X1,
        A64_SVC_0,
    ];
    let elf = build_witness_elf(&code_words, &[]);
    let mailbox = Arc::new(AtomicPtr::new(null_mut()));
    let mapped_va = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let executor = NegativeMmExecutor {
        mailbox: Arc::clone(&mailbox),
        case: NegativeMmCase::StoreAfterMprotectReadOnly,
        mapped_va: Arc::clone(&mapped_va),
        shm_id: 0,
        next_seq: 1,
    };
    let config = SoftSingleProcessConfig::new(&elf, "/mprotect-readonly-store");
    let mb_for_setup = Arc::clone(&mailbox);
    let run = run_single_process_with_executor_and_setup(&config, executor, move |engine| {
        let mut vec_stub = [0u8; 8];
        vec_stub[0..4].copy_from_slice(&A64_HVC_2.to_le_bytes());
        vec_stub[4..8].copy_from_slice(&A64_ERET.to_le_bytes());
        engine
            .backend()
            .write_gpa(LINUX_EL1_VECTORS_BASE + 0x400, &vec_stub)
            .map_err(|e| format!("install witness EL1 vector stub: {e}"))?;
        let ptr = engine
            .backend()
            .host_ptr(
                LINUX_SYSCALL_MAILBOX_BASE,
                AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .ok_or_else(|| "missing stage-2 syscall mailbox host_ptr".to_owned())?;
        mb_for_setup.store(ptr.cast::<Aarch64SyscallMailbox>(), Ordering::Release);
        Ok(())
    })
    .expect("store to PROT_READ mapping must terminate with lowered SIGSEGV");

    let anon_va = mapped_va.load(Ordering::Acquire);
    assert_ne!(anon_va, 0);
    assert_eq!(run.exit_code, 128 + 11);
    assert_eq!(
        run.terminating_fault,
        Some(SoftFaultTermination {
            signum: 11, // SIGSEGV
            si_code: 2, // SEGV_ACCERR
            fault_addr: anon_va,
            elr: CODE_VA + 4 * 4,
            syndrome: 0x9200_004f,
        })
    );

    // Read-only memory contents must remain untouched after the blocked store.
    let preserved = run
        .engine
        .read_bytes(anon_va, 8)
        .expect("read preserved PROT_READ word");
    assert_eq!(
        u64::from_le_bytes(preserved.try_into().unwrap()),
        0xDEAD_BEEF_CAFE_0001
    );
}

#[test]
fn soft_single_process_access_after_munmap_faults_with_segv_maperr() {
    let _test_guard = lock_soft_carrier_test();

    // Stage-2 negative check: unmapping a frame denies subsequent guest reads with Unmapped.
    let mut stage2 = SoftStage2::new().expect("allocate SoftStage2");
    let frame = 0x2500_0000u64;
    let mut buf = [0u8; 4];
    stage2
        .map_owned_anonymous(
            frame,
            GUEST_PAGE_BYTES,
            MemPerms {
                read: true,
                write: true,
                exec: false,
            },
            false,
        )
        .expect("map RW stage-2 page");
    stage2
        .unmap_stage2(frame, GUEST_PAGE_BYTES)
        .expect("unmap stage-2 page");
    assert!(
        SoftGuestMemory::read(&mut stage2, VirtualAddress(frame), &mut buf).is_err(),
        "load from unmapped stage-2 page must fail"
    );
    assert_eq!(
        stage2.last_abort(),
        Some(Stage2Abort {
            gpa: frame,
            access: Stage2AbortAccess::Read,
            reason: Stage2AbortReason::Unmapped,
        })
    );

    // Production stage-1 + kernel dispatch negative check:
    // 0: mmap(RW), 1: str, 2: munmap, 3: ldr (SEGV_MAPERR), 4: exit_group
    let code_words = [
        A64_SVC_0,
        A64_STR_X2_X1,
        A64_SVC_0,
        A64_LDR_X3_X1,
        A64_SVC_0,
    ];
    let elf = build_witness_elf(&code_words, &[]);
    let mailbox = Arc::new(AtomicPtr::new(null_mut()));
    let mapped_va = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let executor = NegativeMmExecutor {
        mailbox: Arc::clone(&mailbox),
        case: NegativeMmCase::LoadAfterMunmap,
        mapped_va: Arc::clone(&mapped_va),
        shm_id: 0,
        next_seq: 1,
    };
    let config = SoftSingleProcessConfig::new(&elf, "/munmap-load-fault");
    let mb_for_setup = Arc::clone(&mailbox);
    let run = run_single_process_with_executor_and_setup(&config, executor, move |engine| {
        let mut vec_stub = [0u8; 8];
        vec_stub[0..4].copy_from_slice(&A64_HVC_2.to_le_bytes());
        vec_stub[4..8].copy_from_slice(&A64_ERET.to_le_bytes());
        engine
            .backend()
            .write_gpa(LINUX_EL1_VECTORS_BASE + 0x400, &vec_stub)
            .map_err(|e| format!("install witness EL1 vector stub: {e}"))?;
        let ptr = engine
            .backend()
            .host_ptr(
                LINUX_SYSCALL_MAILBOX_BASE,
                AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .ok_or_else(|| "missing stage-2 syscall mailbox host_ptr".to_owned())?;
        mb_for_setup.store(ptr.cast::<Aarch64SyscallMailbox>(), Ordering::Release);
        Ok(())
    })
    .expect("load from munmapped mapping must terminate with lowered SIGSEGV");

    let anon_va = mapped_va.load(Ordering::Acquire);
    assert_ne!(anon_va, 0);
    assert_eq!(run.exit_code, 128 + 11);
    assert_eq!(
        run.terminating_fault,
        Some(SoftFaultTermination {
            signum: 11, // SIGSEGV
            si_code: 1, // SEGV_MAPERR
            fault_addr: anon_va,
            elr: CODE_VA + 3 * 4,
            syndrome: 0x9200_0007,
        })
    );
}

#[test]
fn soft_sysv_shm_alias_publishes_kernel_frame_inventory() {
    let _test_guard = lock_soft_carrier_test();

    // 0: shmget, 1: shmat (MapHostAlias), 2: str, 3: ldr, 4: exit_group(0)
    let code_words = [
        A64_SVC_0,
        A64_SVC_0,
        A64_STR_X2_X1,
        A64_LDR_X3_X1,
        A64_SVC_0,
    ];
    let elf = build_witness_elf(&code_words, &[]);
    let mailbox = Arc::new(AtomicPtr::new(null_mut()));
    let mapped_va = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let executor = NegativeMmExecutor {
        mailbox: Arc::clone(&mailbox),
        case: NegativeMmCase::SysvShmAlias,
        mapped_va: Arc::clone(&mapped_va),
        shm_id: 0,
        next_seq: 1,
    };
    let config = SoftSingleProcessConfig::new(&elf, "/sysv-shm-alias");
    let mb_for_setup = Arc::clone(&mailbox);
    let run = run_single_process_with_executor_and_setup(&config, executor, move |engine| {
        let mut vec_stub = [0u8; 8];
        vec_stub[0..4].copy_from_slice(&A64_HVC_2.to_le_bytes());
        vec_stub[4..8].copy_from_slice(&A64_ERET.to_le_bytes());
        engine
            .backend()
            .write_gpa(LINUX_EL1_VECTORS_BASE + 0x400, &vec_stub)
            .map_err(|e| format!("install witness EL1 vector stub: {e}"))?;
        let ptr = engine
            .backend()
            .host_ptr(
                LINUX_SYSCALL_MAILBOX_BASE,
                AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .ok_or_else(|| "missing stage-2 syscall mailbox host_ptr".to_owned())?;
        mb_for_setup.store(ptr.cast::<Aarch64SyscallMailbox>(), Ordering::Release);
        Ok(())
    })
    .expect("shmat witness should exit cleanly through production kernel");

    assert_ne!(mapped_va.load(Ordering::Acquire), 0);
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.terminating_fault, None);
    assert_eq!(
        run.reply_census,
        Hvc2ReplyCensus {
            ring_completed: 0,
            kernel_dispatched: 3,
            runner_refused: 0,
        }
    );
    // Sampled at exit; the soft backend does not yet retire alias inventory
    // on unmap (#2684), so the attached segment's mapping is still listed.
    assert!(
        run.frame_inventory.mappings.iter().any(|m| {
            m.gpa.raw() >= carrick_softcpu_aarch64_host::SOFT_ALIAS_GPA_BASE
                // shmat rounds the alias to the host page granule.
                && m.length.raw() >= GUEST_PAGE_BYTES
                && m.permissions.write
        }),
        "MapHostAlias must publish its stage-2 alias frame into the kernel frame inventory, got {:?}",
        run.frame_inventory
    );
}

const NR_GETPID: u64 = 172;
const PROT_EXEC: u64 = 4;
const MAP_FIXED: u64 = 0x10;
/// `svc #1` and `svc #2`: Linux ignores the immediate, the decoder keeps it.
const A64_SVC_1: u32 = 0xd400_0021;
const A64_SVC_2: u32 = 0xd400_0041;
const A64_B_BACK_1: u32 = 0x17ff_ffff;
const A64_B_BACK_2: u32 = 0x17ff_fffe;
const SCRATCH_OFFSET: u64 = 0x800;
const PATCH_PATH_OFFSET: u64 = 0x80;

/// How the rewrite witness retires the code page once it has run the
/// replacement words.
#[derive(Clone, Copy)]
enum CodeRetirement {
    ProtNone,
    /// A `MAP_FIXED` private file mapping replaces the page's backing.
    Remap,
}

#[derive(Clone, Copy)]
enum ResidencyPlan {
    /// `svc; b .-4`: `getpid` handoffs, then `exit_group(0)`.
    Loop { handoffs: u64 },
    /// `svc; str x2, [x1]; b .-8`: rewrite the `svc` with a guest store,
    /// then with a host `read`, then retire the page.
    Rewrite(CodeRetirement),
}

/// Drives the production carrier with real decode and dispatch. Each
/// `prepare` is one emitted block; the first word of every `svc` block it
/// runs records which code incarnation was served.
struct ResidencyExecutor {
    bridge: SequenceHvc2Executor,
    plan: ResidencyPlan,
    svc_visits: u64,
    fd: u64,
    prepared: Arc<std::sync::atomic::AtomicU64>,
    served: Arc<Mutex<Vec<u32>>>,
}

impl ResidencyExecutor {
    fn record(&self, block: &TranslatedBlock) -> Result<(), String> {
        let word = block
            .guest()
            .instructions()
            .first()
            .map(|i| i.word())
            .ok_or("empty svc block")?;
        self.served
            .lock()
            .map_err(|_| "poisoned served".to_owned())?
            .push(word);
        Ok(())
    }

    fn svc(&mut self, cpu: &mut CpuState, block: &TranslatedBlock) -> Result<(), String> {
        self.record(block)?;
        self.svc_visits += 1;
        let visit = self.svc_visits;
        let (nr, args) = match self.plan {
            ResidencyPlan::Loop { handoffs } if visit <= handoffs => (NR_GETPID, [0; 6]),
            ResidencyPlan::Loop { .. } => (NR_EXIT_GROUP, [0; 6]),
            ResidencyPlan::Rewrite(retire) => match visit {
                1 => (NR_GETPID, [0; 6]),
                2 => (
                    NR_MPROTECT,
                    [
                        CODE_VA,
                        GUEST_PAGE_BYTES,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        0,
                        0,
                        0,
                    ],
                ),
                3 => (
                    NR_OPENAT,
                    [AT_FDCWD, DATA_VA + PATCH_PATH_OFFSET, O_CLOEXEC, 0, 0, 0],
                ),
                4 => {
                    let fd = rx(cpu, 0);
                    if (fd as i64) < 3 {
                        return Err(format!("openat(/patch) failed: {}", fd as i64));
                    }
                    self.fd = fd;
                    (NR_READ, [fd, CODE_VA, 4, 0, 0, 0])
                }
                5 if rx(cpu, 0) == 4 => match retire {
                    CodeRetirement::ProtNone => {
                        (NR_MPROTECT, [CODE_VA, GUEST_PAGE_BYTES, 0, 0, 0, 0])
                    }
                    CodeRetirement::Remap => (
                        NR_MMAP,
                        [
                            CODE_VA,
                            GUEST_PAGE_BYTES,
                            PROT_READ | PROT_EXEC,
                            MAP_PRIVATE | MAP_FIXED,
                            self.fd,
                            0,
                        ],
                    ),
                },
                5 => return Err(format!("read(/patch) returned {}", rx(cpu, 0) as i64)),
                _ => {
                    return Err(format!(
                        "retired code ran again at visit {visit} (x0={})",
                        rx(cpu, 0) as i64
                    ));
                }
            },
        };
        ScriptedHvc2Executor::set_call(cpu, nr, args);
        Ok(())
    }

    fn store(&self, cpu: &mut CpuState) {
        // After the second `svc` (the RWX mprotect), overwrite the `svc`
        // word with `svc #1` and keep this store; otherwise write scratch.
        let (at, value) = match self.plan {
            ResidencyPlan::Rewrite(_) if self.svc_visits == 2 => (
                CODE_VA,
                u64::from(A64_SVC_1) | (u64::from(A64_STR_X2_X1) << 32),
            ),
            _ => (DATA_VA + SCRATCH_OFFSET, 0),
        };
        wx(cpu, 1, at);
        wx(cpu, 2, value);
    }
}

impl ExecuteBlock for ResidencyExecutor {
    type Error = String;
    type Code = ();

    fn prepare(&mut self, _block: &TranslatedBlock) -> Result<(), Self::Error> {
        self.prepared.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn execute(
        &mut self,
        block: &TranslatedBlock,
        code: &(),
        cpu: &mut CpuState,
    ) -> Result<usize, Self::Error> {
        if cpu.pstate.el != ExceptionLevel::El0 {
            return self.bridge.execute(block, code, cpu);
        }
        match cpu.pc.0 {
            CODE_VA => self.svc(cpu, block)?,
            pc if pc == CODE_VA + 4
                && self.svc_visits == 5
                && matches!(self.plan, ResidencyPlan::Rewrite(CodeRetirement::Remap)) =>
            {
                // Only the remapped file page reaches here: it holds `svc #3`.
                if (rx(cpu, 0) as i64) != CODE_VA as i64 {
                    return Err(format!("mmap(MAP_FIXED) returned {}", rx(cpu, 0) as i64));
                }
                self.record(block)?;
                ScriptedHvc2Executor::set_call(cpu, NR_EXIT_GROUP, [7, 0, 0, 0, 0, 0]);
            }
            pc if pc == CODE_VA + 4 && matches!(self.plan, ResidencyPlan::Rewrite(_)) => {
                self.store(cpu);
            }
            pc if pc == CODE_VA + 4 || pc == CODE_VA + 8 => {}
            pc => return Err(format!("unexpected user PC {pc:#x}")),
        }
        match block.terminator() {
            Terminator::Handler(idx) | Terminator::Jump(idx) | Terminator::Fallthrough(idx) => {
                Ok(idx)
            }
            Terminator::Conditional { .. } => Err("unexpected conditional terminator".to_owned()),
        }
    }
}

struct ResidencyRun {
    run: carrick_softcpu_aarch64_host::SoftProcessRun<ResidencyExecutor>,
    prepared: u64,
    served: Vec<u32>,
}

fn run_residency(plan: ResidencyPlan, rootfs: Option<&std::path::Path>) -> ResidencyRun {
    let code_words: &[u32] = match plan {
        ResidencyPlan::Loop { .. } => &[A64_SVC_0, A64_B_BACK_1],
        ResidencyPlan::Rewrite(_) => &[A64_SVC_0, A64_STR_X2_X1, A64_B_BACK_2],
    };
    let elf = build_witness_elf(code_words, &[(PATCH_PATH_OFFSET as usize, b"/patch\0")]);
    let mailbox = Arc::new(AtomicPtr::new(null_mut()));
    let prepared = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let served = Arc::new(Mutex::new(Vec::new()));
    let executor = ResidencyExecutor {
        bridge: SequenceHvc2Executor {
            mailbox: Arc::clone(&mailbox),
            calls: Vec::new(),
            returns: Arc::new(Mutex::new(Vec::new())),
            next_seq: 1,
        },
        plan,
        svc_visits: 0,
        fd: 0,
        prepared: Arc::clone(&prepared),
        served: Arc::clone(&served),
    };
    let mut config = SoftSingleProcessConfig::new(&elf, "/residency");
    config.rootfs_dir = rootfs;
    let run = run_single_process_with_executor_and_setup(&config, executor, move |engine| {
        let mut vec_stub = [0u8; 8];
        vec_stub[0..4].copy_from_slice(&A64_HVC_2.to_le_bytes());
        vec_stub[4..8].copy_from_slice(&A64_ERET.to_le_bytes());
        engine
            .backend()
            .write_gpa(LINUX_EL1_VECTORS_BASE + 0x400, &vec_stub)
            .map_err(|e| format!("install witness EL1 vector stub: {e}"))?;
        let ptr = engine
            .backend()
            .host_ptr(
                LINUX_SYSCALL_MAILBOX_BASE,
                AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .ok_or_else(|| "missing stage-2 syscall mailbox host_ptr".to_owned())?;
        mailbox.store(ptr.cast::<Aarch64SyscallMailbox>(), Ordering::Release);
        Ok(())
    })
    .expect("residency witness must finish through the production carrier");
    let served = served.lock().expect("lock served words").clone();
    ResidencyRun {
        run,
        prepared: prepared.load(Ordering::Relaxed),
        served,
    }
}

/// The loop's hot set (`svc`, `b .-4`, and the `hvc #2` and `eret` vector
/// blocks) plus the one-time path to the first `svc`.
const LOOP_EMISSION_BUDGET: u64 = 9;

#[test]
fn soft_carrier_emits_the_hot_set_once_across_provider_exits() {
    let _test_guard = lock_soft_carrier_test();
    let mut emitted = Vec::new();
    for handoffs in [10, 100] {
        let ResidencyRun {
            run,
            prepared,
            served,
        } = run_residency(ResidencyPlan::Loop { handoffs }, None);
        assert_eq!(run.exit_code, 0);
        assert_eq!(run.terminating_fault, None);
        assert_eq!(
            run.reply_census,
            Hvc2ReplyCensus {
                fixture_answers: 0,
                // The handoffs and the final `exit_group`.
                production_answers: handoffs + 1,
            }
        );
        assert_eq!(served.len() as u64, handoffs + 1);
        println!("handoffs={handoffs} emitted_blocks={prepared}");
        emitted.push(prepared);
    }
    assert!(
        emitted.iter().all(|&e| e <= LOOP_EMISSION_BUDGET),
        "the carrier re-emits its hot set at provider exits: emitted {emitted:?} \
         for 10 and 100 handoffs, budget {LOOP_EMISSION_BUDGET}"
    );
}

const A64_SVC_3: u32 = 0xd400_0061;

/// `/patch` begins with the `svc #2` read over the `svc`. The remap maps
/// its first page, which holds `svc #3` where the resident `str` was.
fn rewrite_rootfs() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("create residency rootfs");
    let mut patch = vec![0; GUEST_PAGE_BYTES as usize];
    patch[..4].copy_from_slice(&A64_SVC_2.to_le_bytes());
    patch[4..8].copy_from_slice(&A64_SVC_3.to_le_bytes());
    std::fs::write(temp.path().join("patch"), &patch).expect("write /patch");
    temp
}

#[test]
fn soft_carrier_serves_rewritten_code_and_faults_after_prot_none() {
    let _test_guard = lock_soft_carrier_test();
    let rootfs = rewrite_rootfs();
    let ResidencyRun { run, served, .. } = run_residency(
        ResidencyPlan::Rewrite(CodeRetirement::ProtNone),
        Some(rootfs.path()),
    );
    // A guest store, then a host `read` across a provider exit, replace the
    // resident `svc` block; neither may serve the earlier incarnation.
    assert_eq!(
        served,
        [A64_SVC_0, A64_SVC_0, A64_SVC_1, A64_SVC_1, A64_SVC_2]
    );
    // The fetch at `+4` faults instead of serving the resident `str`.
    assert_eq!(run.exit_code, 128 + 11);
    let fault = run.terminating_fault.expect("PROT_NONE fetch must fault");
    assert_eq!(
        (fault.signum, fault.fault_addr, fault.elr),
        (11, CODE_VA + 4, CODE_VA + 4)
    );
}

#[test]
fn soft_carrier_serves_rewritten_code_and_the_remapped_page() {
    let _test_guard = lock_soft_carrier_test();
    let rootfs = rewrite_rootfs();
    let ResidencyRun { run, served, .. } = run_residency(
        ResidencyPlan::Rewrite(CodeRetirement::Remap),
        Some(rootfs.path()),
    );
    assert_eq!(
        served,
        [
            A64_SVC_0, A64_SVC_0, A64_SVC_1, A64_SVC_1, A64_SVC_2, A64_SVC_3
        ]
    );
    assert_eq!(run.terminating_fault, None);
    assert_eq!(run.exit_code, 7);
}

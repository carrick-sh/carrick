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
    GUEST_PAGE_BYTES, MappingGeometry, SoftSingleProcessConfig, SoftStage2, Stage2Abort,
    Stage2AbortAccess, Stage2AbortReason, run_single_process_with_executor_and_setup,
};

const CODE_VA: u64 = 0x0040_0000;
const DATA_VA: u64 = 0x0040_1000;

const PATH_OFFSET: u64 = 0x00;
const MSG_OFFSET: u64 = 0x40;
const STAT_OFFSET: u64 = 0x100;
const READ_BUF_OFFSET: u64 = 0x200;
const TIMESPEC_OFFSET: u64 = 0x300;
const RLIMIT_OFFSET: u64 = 0x320;

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
const NR_READ: u64 = 63;
const NR_WRITE: u64 = 64;
const NR_FSTAT: u64 = 80;
const NR_TIMERFD_CREATE: u64 = 85;
const NR_EXIT_GROUP: u64 = 94;
const NR_SETITIMER: u64 = 103;
const NR_CLOCK_GETTIME: u64 = 113;
const NR_TKILL: u64 = 130;
const NR_RT_SIGACTION: u64 = 134;
const NR_GETUID: u64 = 174;
const NR_GETEUID: u64 = 175;
const NR_BRK: u64 = 214;
const NR_MUNMAP: u64 = 215;
const NR_MMAP: u64 = 222;
const NR_MPROTECT: u64 = 226;
const NR_PRLIMIT64: u64 = 261;

const AT_FDCWD: u64 = (-100i64) as u64;
const O_CLOEXEC: u64 = 0x80000;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 2;
const MAP_ANONYMOUS: u64 = 0x20;
const CLOCK_MONOTONIC: u64 = 1;
const RLIMIT_NOFILE: u64 = 7;

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
            // 12: file-backed mmap(0, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0) -> MapHostAlias
            12 => {
                if x0 != FILE_PAYLOAD.len() as u64 {
                    return Err(format!("read(/hello.txt) returned {}", x0 as i64));
                }
                Self::set_call(
                    cpu,
                    NR_MMAP,
                    [0, 0x1000, PROT_READ, MAP_PRIVATE, obs.opened_fd, 0],
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
            // 16: getuid()
            16 => {
                if x0 != 0 {
                    return Err(format!("clock_gettime failed: {}", x0 as i64));
                }
                Self::set_call(cpu, NR_GETUID, [0; 6]);
            }
            // 17: geteuid()
            17 => {
                if x0 != 0 {
                    return Err(format!("getuid returned {}", x0 as i64));
                }
                Self::set_call(cpu, NR_GETEUID, [0; 6]);
            }
            // 18: prlimit64(0, RLIMIT_NOFILE, 0, rlim_buf)
            18 => {
                if x0 != 0 {
                    return Err(format!("geteuid returned {}", x0 as i64));
                }
                Self::set_call(
                    cpu,
                    NR_PRLIMIT64,
                    [0, RLIMIT_NOFILE, 0, DATA_VA + RLIMIT_OFFSET, 0, 0],
                );
            }
            // 19: write(1, STDOUT_PAYLOAD, len)
            19 => {
                if x0 != 0 {
                    return Err(format!("prlimit64 failed: {}", x0 as i64));
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
            // 20: exit_group(0)
            20 => {
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
        A64_SVC_0,     // 16: getuid
        A64_SVC_0,     // 17: geteuid
        A64_SVC_0,     // 18: prlimit64(RLIMIT_NOFILE)
        A64_SVC_0,     // 19: write(1, STDOUT_PAYLOAD)
        A64_SVC_0,     // 20: exit_group(0)
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
    assert_eq!(run.syscalls_dispatched, 16);
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

    // Verify kernel-written guest buffers (`fstat`, `read`, `clock_gettime`, `prlimit64`)
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

    let rlim_bytes = run
        .engine
        .read_bytes(DATA_VA + RLIMIT_OFFSET, 16)
        .expect("read prlimit64 RLIMIT_NOFILE");
    let rlim_cur = u64::from_le_bytes(rlim_bytes[0..8].try_into().unwrap());
    assert!(rlim_cur >= 64, "expected sane RLIMIT_NOFILE cur={rlim_cur}");
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

#[test]
fn soft_single_process_refuses_timer_and_signal_syscalls_with_counted_enosys() {
    let _test_guard = lock_soft_carrier_test();
    // Prepare a 1-second `itimerval` (`it_value.tv_sec = 1`) at `DATA_VA + 0x300`
    // so `setitimer` would arm a timer on a null bridge instead of failing validation.
    let mut itimerval = [0u8; 32];
    itimerval[16..24].copy_from_slice(&1i64.to_le_bytes());
    let calls = vec![
        (NR_TIMERFD_CREATE, [CLOCK_MONOTONIC, 0, 0, 0, 0, 0]),
        (NR_SETITIMER, [0, DATA_VA + 0x300, 0, 0, 0, 0]),
        (NR_RT_SIGACTION, [13, 0, DATA_VA + 0x340, 8, 0, 0]),
        (NR_TKILL, [1, 0, 0, 0, 0, 0]),
        (NR_EXIT_GROUP, [0; 6]),
    ];
    let code_words = vec![A64_SVC_0; calls.len()];
    let elf = build_witness_elf(&code_words, &[(0x300, &itimerval)]);

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
        vec![enosys, enosys, enosys, enosys],
        "timer and signal syscalls must fail closed with -ENOSYS instead of silently succeeding"
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

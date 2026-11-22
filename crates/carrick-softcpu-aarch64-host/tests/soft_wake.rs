//! The soft AArch64 carrier's wake path (#2645 slice B): the guest's GIC CPU
//! interface and EL1 virtual timer, and the WFI park, driven through the
//! production idle entry (`Aarch64EngineCore::run_idle_entry_on_vcpu` ->
//! `owed_kick::run_idle_entry` -> `SoftAarch64Vcpu::run`), as an executor
//! with no host task enters the EL1 scheduler's wait.
//!
//! The guest code stands in for the EL1 scheduler's idle wait
//! (`carrick-el1/src/sched.rs`): program the virtual timer, WFI with IRQs
//! masked, acknowledge by polling `ICC_IAR1_EL1`, end the interrupt. Every
//! instruction is a real A64 word the soft CPU's handlers execute; the
//! executor only reports block exits, so the witness runs on every host.
//!
//! Runs un-ignored on both x86_64 and aarch64 hosts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Mutex;
use std::time::{Duration, Instant};

use carrick_aarch64::{Aarch64Exit, Aarch64Vcpu, Aarch64Vmm};
use carrick_hal::{GuestVmBackend, Reg, VcpuKick};
use carrick_mem::memory::{AddressSpace, El1IrqMode, el1_idle_entry_va, el1_slot_frame_va};
use carrick_softcpu_aarch64::dispatch::ExecuteBlock;
use carrick_softcpu_aarch64::state::CpuState;
use carrick_softcpu_aarch64::translate::{Terminator, TranslatedBlock};
use carrick_softcpu_aarch64::{Hint, Instruction};
use carrick_softcpu_aarch64_host::{GUEST_PAGE_BYTES, SoftAarch64Engine, SoftAarch64Vmm};

const CODE_VA: u64 = 0x0040_0000;
const A64_NOP: u32 = 0xd503_201f;
const A64_WFI: u32 = 0xd503_207f;
/// `hvc #5`: the EL1 idle exit.
const A64_HVC_IDLE: u32 = 0xd400_00a2;
/// `tbnz x4, #5, .-12`: retry the wait while `ICC_IAR1_EL1` was spurious
/// (1023 has bit 5 set; every Carrick INTID is below 32).
const A64_TBNZ_X4_B5_BACK3: u32 = 0x372f_ffa4;

const GIC_VTIMER_INTID: u64 = carrick_el1_abi::GIC_VTIMER_INTID as u64;
const GIC_RESCHED_INTID: u64 = carrick_el1_abi::GIC_RESCHED_INTID as u64;
const GIC_SPURIOUS_INTID: u64 = carrick_el1_abi::GIC_SPURIOUS_INTID as u64;

/// The single soft vCPU's affinity is 0 (`MPIDR_EL1` = RES1 bit 31 only).
const OWN_SGI_TARGET: u64 = carrick_guest_arch::sgi_target_of(0);

/// `(op0, op1, CRn, CRm, op2)` of the registers the wait uses.
const CNTVCT_EL0: (u32, u32, u32, u32, u32) = (3, 3, 14, 0, 2);
const CNTV_CTL_EL0: (u32, u32, u32, u32, u32) = (3, 3, 14, 3, 1);
const CNTV_CVAL_EL0: (u32, u32, u32, u32, u32) = (3, 3, 14, 3, 2);
const ICC_IAR1_EL1: (u32, u32, u32, u32, u32) = (3, 0, 12, 12, 0);
const ICC_EOIR1_EL1: (u32, u32, u32, u32, u32) = (3, 0, 12, 12, 1);
const ICC_SGI1R_EL1: (u32, u32, u32, u32, u32) = (3, 0, 12, 11, 5);
const XZR: u32 = 31;

/// C6.2.193/C6.2.191: MSR/MRS (register), op0 = 2 + o0.
const fn system(read: bool, (op0, op1, crn, crm, op2): (u32, u32, u32, u32, u32), rt: u32) -> u32 {
    0xd510_0000
        | ((read as u32) << 21)
        | ((op0 - 2) << 19)
        | (op1 << 16)
        | (crn << 12)
        | (crm << 8)
        | (op2 << 5)
        | rt
}

const fn msr(register: (u32, u32, u32, u32, u32), rt: u32) -> u32 {
    system(false, register, rt)
}

const fn mrs(rt: u32, register: (u32, u32, u32, u32, u32)) -> u32 {
    system(true, register, rt)
}

/// Reports each block's exit. Every guest word here is a block terminator
/// the soft CPU's handlers retire; a conditional terminator is the
/// `tbnz` above, decided from the architectural register state.
struct TerminatorExecutor;

impl ExecuteBlock for TerminatorExecutor {
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
        let instructions = block.guest().instructions();
        for ins in instructions {
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
            Terminator::Conditional { fallthrough, taken } => {
                let last = instructions.last().ok_or("empty conditional block")?;
                let word = last.word();
                if word & 0x7f00_0000 != 0x3700_0000 {
                    return Err(format!("unexpected conditional {word:#x}"));
                }
                let bit = ((word >> 31) << 5) | ((word >> 19) & 0x1f);
                let rt = carrick_softcpu_aarch64::Gpr::new((word & 0x1f) as u8)
                    .ok_or("tbnz register")?;
                let value = cpu
                    .read_operand(carrick_softcpu_aarch64::OperandRegister::Gpr(rt))
                    .0;
                Ok(if value >> bit & 1 != 0 {
                    taken
                } else {
                    fallthrough
                })
            }
        }
    }
}

static SOFT_CARRIER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock_soft_carrier_test() -> std::sync::MutexGuard<'static, ()> {
    SOFT_CARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A static ELF whose only segment is one page of `nop`s at [`CODE_VA`].
fn nop_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 0x2000];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&CODE_VA.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    let phdr = 64;
    elf[phdr..phdr + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf[phdr + 4..phdr + 8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    elf[phdr + 8..phdr + 16].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[phdr + 16..phdr + 24].copy_from_slice(&CODE_VA.to_le_bytes());
    elf[phdr + 24..phdr + 32].copy_from_slice(&CODE_VA.to_le_bytes());
    elf[phdr + 32..phdr + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[phdr + 40..phdr + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[phdr + 48..phdr + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    for at in (0x1000..0x2000).step_by(4) {
        elf[at..at + 4].copy_from_slice(&A64_NOP.to_le_bytes());
    }
    elf
}

/// Bring up the soft carrier exactly as the production runner finalizes its
/// image (GIC-mode EL1 vectors, HVPatch stage-1 tables), with `wait` in
/// place of the EL1 scheduler's idle entry.
fn bring_up_with_idle_wait(wait: &[u32]) -> SoftAarch64Engine<TerminatorExecutor> {
    let image = AddressSpace::load_elf_bytes_with_reader(&nop_elf(), &|_| None)
        .expect("load the witness ELF")
        .with_vdso_auxv(false)
        .with_linux_initial_stack_execfn_page_size(
            &[b"/wake".to_vec()],
            &Vec::<Vec<u8>>::new(),
            b"/wake",
            GUEST_PAGE_BYTES,
        )
        .expect("initial stack")
        .with_el0_trampoline()
        .and_then(|img| img.with_el1_vectors_mailbox_clock(true, true, El1IrqMode::Gic))
        .and_then(AddressSpace::with_identity_page)
        .and_then(AddressSpace::with_syscall_mailbox_arena)
        .and_then(AddressSpace::with_hvpatch_stage1_page_tables)
        .expect("finalize the witness image");
    let engine = SoftAarch64Vmm::bring_up_with_executor(&image, None, None, TerminatorExecutor)
        .expect("soft carrier bring-up");
    let bytes: Vec<u8> = wait.iter().flat_map(|word| word.to_le_bytes()).collect();
    // The carrier maintenance root maps the EL1 kernel hole identically.
    engine
        .backend()
        .write_gpa(el1_idle_entry_va(), &bytes)
        .expect("place the idle wait at the idle entry");
    engine
}

/// The guest's virtual counter cannot have run longer than the time since
/// `before_bring_up`: a compare value `delay` past that is at least `delay`
/// in the guest's future, and fires no earlier than `delay` from now.
fn compare_after(before_bring_up: Instant, delay: Duration) -> u64 {
    u64::try_from((before_bring_up.elapsed() + delay).as_nanos()).unwrap()
}

/// Enter the idle wait through the production idle entry, then re-enter
/// as an executor does after every exit it does not end on, until the
/// guest's idle `hvc` completes. Returns how many times the vCPU left.
fn run_idle_wait(engine: &mut SoftAarch64Engine<TerminatorExecutor>, end_pc: u64) -> usize {
    let root = engine
        .backend()
        .carrier_maintenance_root()
        .expect("carrier maintenance root");
    let vcpu = engine.vcpu_mut();
    let mut exits = 1;
    let mut exit = SoftAarch64Engine::<TerminatorExecutor>::run_idle_entry_on_vcpu(
        vcpu,
        root,
        el1_slot_frame_va(0),
    )
    .expect("idle entry");
    while vcpu.get_reg(Reg::Pc).unwrap() != end_pc {
        assert!(
            matches!(exit, Aarch64Exit::Halt),
            "idle wait left with {exit:?}"
        );
        assert!(exits < 1_000, "the idle wait spun through {exits} exits");
        exit = carrick_aarch64::owed_kick::run_idle_entry(vcpu).expect("re-enter the idle wait");
        exits += 1;
    }
    assert!(
        matches!(exit, Aarch64Exit::Halt),
        "idle hvc left with {exit:?}"
    );
    exits
}

/// A guest that WFIs until its virtual timer fires: the vCPU parks until the
/// compare value, the timer PPI is the one interrupt `ICC_IAR1_EL1`
/// acknowledges, and after its end of interrupt only a spurious INTID is
/// left. A self-targeted reschedule SGI then ends a second WFI at once and
/// is acknowledged the same way. The vCPU leaves once, at the idle `hvc`:
/// no WFI surfaces as an exit for the executor to spin on.
#[test]
fn soft_idle_wfi_parks_until_the_virtual_timer_and_acknowledges_it() {
    let _carrier_lock = lock_soft_carrier_test();
    const DELAY: Duration = Duration::from_millis(60);
    let wait = [
        msr(CNTV_CVAL_EL0, 1),
        msr(CNTV_CTL_EL0, 2),
        A64_WFI,
        mrs(3, CNTVCT_EL0),
        mrs(4, ICC_IAR1_EL1),
        A64_TBNZ_X4_B5_BACK3,
        msr(CNTV_CTL_EL0, XZR),
        msr(ICC_EOIR1_EL1, 4),
        mrs(5, ICC_IAR1_EL1),
        msr(ICC_SGI1R_EL1, 6),
        A64_WFI,
        mrs(7, ICC_IAR1_EL1),
        msr(ICC_EOIR1_EL1, 7),
        mrs(8, ICC_IAR1_EL1),
        A64_HVC_IDLE,
    ];
    let end_pc = el1_idle_entry_va() + 4 * wait.len() as u64;
    let before_bring_up = Instant::now();
    let mut engine = bring_up_with_idle_wait(&wait);
    let cval = compare_after(before_bring_up, DELAY);
    {
        let vcpu = engine.vcpu_mut();
        vcpu.set_reg(Reg::X(1), cval).unwrap();
        vcpu.set_reg(Reg::X(2), 1).unwrap(); // ENABLE, IMASK clear
        vcpu.set_reg(Reg::X(6), OWN_SGI_TARGET | (GIC_RESCHED_INTID << 24))
            .unwrap();
        for n in [3, 4, 5, 7, 8] {
            vcpu.set_reg(Reg::X(n), u64::MAX).unwrap();
        }
    }
    let started = Instant::now();
    let exits = run_idle_wait(&mut engine, end_pc);
    let waited = started.elapsed();

    let vcpu = engine.vcpu_mut();
    let reg = |n| vcpu.get_reg(Reg::X(n)).unwrap();
    assert_eq!(
        reg(4),
        GIC_VTIMER_INTID,
        "the timer PPI ends the wait (exits={exits}, waited={waited:?})"
    );
    assert!(
        reg(3) >= cval,
        "woke at counter {:#x} before the compare value {cval:#x}",
        reg(3)
    );
    assert!(waited >= DELAY, "woke after {waited:?}, before {DELAY:?}");
    assert_eq!(
        reg(5),
        GIC_SPURIOUS_INTID,
        "nothing pending after the timer's EOI"
    );
    assert_eq!(
        reg(7),
        GIC_RESCHED_INTID,
        "the self-SGI ends the second WFI"
    );
    assert_eq!(
        reg(8),
        GIC_SPURIOUS_INTID,
        "nothing pending after the SGI's EOI"
    );
    assert_eq!(
        exits, 1,
        "the vCPU left only at the idle hvc: a WFI is a park, not an exit"
    );
}

/// A host kick ends a parked WFI long before its far timer: the vCPU leaves
/// `Kicked`, past the WFI, with nothing acknowledged.
#[test]
fn soft_wfi_park_ends_on_a_cross_thread_kick() {
    let _carrier_lock = lock_soft_carrier_test();
    const FAR: Duration = Duration::from_secs(30);
    const KICK_AFTER: Duration = Duration::from_millis(40);
    let wait = [
        msr(CNTV_CVAL_EL0, 1),
        msr(CNTV_CTL_EL0, 2),
        A64_WFI,
        A64_HVC_IDLE,
    ];
    let before_bring_up = Instant::now();
    let mut engine = bring_up_with_idle_wait(&wait);
    let kick = engine.backend().kick_handle();
    let cval = compare_after(before_bring_up, FAR);
    let root = engine.backend().carrier_maintenance_root().unwrap();
    let vcpu = engine.vcpu_mut();
    vcpu.set_reg(Reg::X(1), cval).unwrap();
    vcpu.set_reg(Reg::X(2), 1).unwrap();
    // The idle entry's register setup, then one `run`, as a raw vCPU exit.
    let started = Instant::now();
    let kicker = std::thread::spawn(move || {
        std::thread::sleep(KICK_AFTER);
        kick.kick();
    });
    vcpu.set_sys_reg(
        carrick_hal::SysReg::Tcr,
        carrick_mem::arch_sysregs::TCR_EL1_BOOTSTRAP | (1 << 36),
    )
    .unwrap();
    vcpu.set_sys_reg(carrick_hal::SysReg::Ttbr0, root.raw())
        .unwrap();
    vcpu.set_sys_reg(carrick_hal::SysReg::Ttbr1, root.raw())
        .unwrap();
    vcpu.set_reg(Reg::Pc, el1_idle_entry_va()).unwrap();
    vcpu.set_reg(Reg::Pstate, 0x3c5).unwrap();
    let exit = vcpu.run().expect("run the parked wait");
    let waited = started.elapsed();
    kicker.join().unwrap();
    assert!(
        matches!(exit, Aarch64Exit::Kicked),
        "a kick ends the park: {exit:?} after {waited:?}"
    );
    assert!(
        waited >= KICK_AFTER,
        "left after {waited:?}, before the kick"
    );
    assert!(waited < FAR / 2, "the kick, not the timer, ended the park");
    assert_eq!(
        vcpu.get_reg(Reg::Pc).unwrap(),
        el1_idle_entry_va() + 12,
        "the WFI retired; re-entry resumes after it"
    );
}

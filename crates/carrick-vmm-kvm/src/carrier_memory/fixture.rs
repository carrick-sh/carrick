//! Executing hardware witnesses only: doorbells observe bytes/faults/drains.
//! No Linux syscall personality, reservation tree or provisional N1 owner.
use super::*;
use crate::{KvmVcpu, cpl0_boot::Watchdog};
use carrick_guest_arch::{ContextGeneration, MmGeneration};
use carrick_hal::{HvVcpu, HvVm, VcpuExit};
use carrick_x86::{BringupLayout, FaultDoorbellRecord, X86Reg, X86Vcpu};

pub const DATA_VA: u64 = 0x4000_0000;
const CODE_VA: u64 = 0x10000;
const LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: 0x200000,
    gdt_base: 0x500000,
    pml4_base: 0x600000,
};
const DRAIN_CODE: u64 = 0x201000;
const DRAIN_PORT: u16 = 0xcd;
const OBSERVE_PORT: u16 = 0xcc;
const EXTENT_SIZE: usize = 2 * 1024 * 1024;
fn nz(value: u64) -> Result<NonZeroU64, MemoryError> {
    NonZeroU64::new(value).ok_or_else(|| error("zero witness generation"))
}
fn root(pa: u64) -> Result<RootGpa, MemoryError> {
    RootGpa::page_aligned(FrameGpa::new(pa)).ok_or_else(|| error("unaligned witness root"))
}
fn identity(tag: u64) -> Result<BackingIdentity, MemoryError> {
    let n = nz(tag)?;
    Ok(BackingIdentity {
        frame_id: n,
        mapping_id: n,
        owner_generation: n,
        inventory_revision: n,
    })
}
fn hw<T>(result: Result<T, carrick_hal::TrapError>) -> Result<T, MemoryError> {
    result.map_err(|e| error(e.to_string()))
}
struct FixtureInventory;
impl InventoryTransaction for FixtureInventory {
    fn publish(&mut self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn commit(&mut self, _: &DescriptorReceipt) -> Result<(), MemoryError> {
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), MemoryError> {
        Ok(())
    }
}
impl InventoryRetirement for FixtureInventory {
    fn retire(&mut self, _: BackingIdentity) -> Result<(), MemoryError> {
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), MemoryError> {
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub enum Observation {
    Byte(u8),
    Fault(FaultDoorbellRecord),
}

/// Owns two live hardware MMs and CPUs. Field order drops both CPUs before VM
/// and registered backing; watchdogs always join before this owner disappears.
pub struct MemoryWitness {
    cpus: [KvmVcpu; 2],
    memory: CarrierMemory,
    contexts: [AddressContext<RootGpa>; 2],
    next_table: [u64; 2],
    sequence: u64,
    next_frame: u64,
    pub drain_count: usize,
}
impl MemoryWitness {
    pub fn context(&self, index: usize) -> AddressContext<RootGpa> {
        self.contexts[index]
    }
    pub fn words(&self) -> DescriptorWords<'_> {
        self.memory.words()
    }
    pub fn retain_output(
        &self,
        output: FrameGpa,
        len: usize,
    ) -> Result<RetainedX86Data<'_>, MemoryError> {
        self.memory.retain_output(output, len)
    }
    pub fn boot(programs: [&[u8]; 2]) -> Result<Self, MemoryError> {
        let mut system = BackingExtent::private(FrameGpa::new(0), 16 * 1024 * 1024)?;
        let boot=<carrick_hal::x8664_arch::X8664GuestArch as carrick_hal::guest_arch::GuestArch>::bootstrap_sysregs();
        let gdt: Vec<u8> = boot.gdt.iter().flat_map(|w| w.to_le_bytes()).collect();
        system.initialize(LAYOUT.gdt_base as usize, &gdt)?;
        // SYSCALL -> observation only -> SYSRETQ. Real instruction execution,
        // never a host syscall handler. No kernel stack or user-copy policy.
        system.initialize(
            LAYOUT.trampoline_base as usize,
            &[0x66, 0xba, OBSERVE_PORT as u8, 0, 0xef, 0x48, 0x0f, 0x07],
        )?;
        // CPL0 CR3 reload, then exact-context observation acknowledgement.
        system.initialize(
            DRAIN_CODE as usize,
            &[
                0x0f,
                0x20,
                0xd8,
                0x0f,
                0x22,
                0xd8,
                0x66,
                0xba,
                DRAIN_PORT as u8,
                0,
                0xef,
                0xf4,
            ],
        )?;
        hw(carrick_x86::write_fault_tables_with(LAYOUT, |pa, bytes| {
            system
                .initialize(pa as usize, bytes)
                .map_err(|e| carrick_hal::TrapError::Hypervisor(e.to_string()))
        }))?;
        for (i, program) in programs.iter().enumerate() {
            if program.len() > PAGE as usize {
                return Err(error("memory witness code exceeds one page"));
            }
            system.initialize(CODE_VA as usize + i * 4096, program)?;
        }
        let mut memory = CarrierMemory::create()?;
        let backing = PreparedBacking {
            extent: Arc::new(system),
            identity: identity(1)?,
        };
        let system_handle = memory.install(std::slice::from_ref(&backing))?[0];
        let contexts = [
            AddressContext {
                root: root(0x600000)?,
                mm: MmGeneration::new(nz(1)?),
                generation: ContextGeneration::new(nz(1)?),
            },
            AddressContext {
                root: root(0x680000)?,
                mm: MmGeneration::new(nz(2)?),
                generation: ContextGeneration::new(nz(2)?),
            },
        ];
        let mut next_table = [0x601000, 0x681000];
        let mut sequence = 0;
        let shared = memory.share(system_handle)?;
        for (i, context) in contexts.iter().enumerate() {
            let mm = nz(i as u64 + 1)?;
            memory.install_root(mm, *context)?;
            memory.attach_shared(mm, &shared)?;
            for (span, output, size, permissions) in [
                (
                    PageSpan::new(0x200000, 14 * 1024 * 1024),
                    0x200000,
                    LeafSize::Block2M,
                    Permissions {
                        writable: true,
                        executable: true,
                        user: false,
                    },
                ),
                (
                    PageSpan::new(CODE_VA, PAGE),
                    CODE_VA + i as u64 * PAGE,
                    LeafSize::Page,
                    Permissions {
                        writable: false,
                        executable: true,
                        user: true,
                    },
                ),
                (
                    PageSpan::new(0x30000, PAGE),
                    0x30000 + i as u64 * PAGE,
                    LeafSize::Page,
                    Permissions {
                        writable: true,
                        executable: false,
                        user: true,
                    },
                ),
            ] {
                let op = DescriptorOp::Map {
                    span,
                    output: FrameGpa::new(output),
                    size,
                    permissions,
                    resident: true,
                    backing: backing.identity,
                };
                publish_fixture(
                    &mut memory,
                    *context,
                    mm,
                    op,
                    &mut next_table[i],
                    &mut sequence,
                )?;
            }
        }
        let mut a = memory.vm.add_vcpu().map_err(|e| error(e.to_string()))?;
        let mut b = memory.vm.add_vcpu().map_err(|e| error(e.to_string()))?;
        for (i, cpu) in [&mut a, &mut b].into_iter().enumerate() {
            let mut layout = LAYOUT;
            layout.pml4_base = contexts[i].root.address().raw();
            hw(carrick_x86::program_longmode_entry(
                cpu, layout, CODE_VA, 0x30ff0,
            ))?;
            hw(carrick_x86::program_fault_segments(cpu, LAYOUT, i as u64))?;
        }
        Ok(Self {
            cpus: [a, b],
            memory,
            contexts,
            next_table,
            sequence,
            next_frame: 2,
            drain_count: 0,
        })
    }
    pub fn private_extent(&mut self, initial: u8) -> Result<BackingHandle, MemoryError> {
        let base = 0x2000000 + (self.next_frame - 2) * EXTENT_SIZE as u64;
        let mut extent = BackingExtent::private(FrameGpa::new(base), EXTENT_SIZE)?;
        extent.initialize(0, &[initial])?;
        let backing = PreparedBacking {
            extent: Arc::new(extent),
            identity: identity(self.next_frame)?,
        };
        self.next_frame += 1;
        Ok(self.memory.install(&[backing])?[0])
    }
    pub fn share_with(&mut self, index: usize, handle: BackingHandle) -> Result<(), MemoryError> {
        let edge = self.memory.share(handle)?;
        self.memory.attach_shared(nz(index as u64 + 1)?, &edge)
    }
    pub fn map(
        &mut self,
        index: usize,
        va: u64,
        handle: BackingHandle,
        resident: bool,
    ) -> Result<(), MemoryError> {
        let record = self.memory.record(handle)?;
        let op = DescriptorOp::Map {
            span: PageSpan::new(va, PAGE),
            output: record.backing.extent.base,
            permissions: Permissions {
                writable: true,
                executable: false,
                user: true,
            },
            size: LeafSize::Page,
            resident,
            backing: record.backing.identity,
        };
        self.edit(index, op)
    }
    pub fn edit(&mut self, index: usize, op: DescriptorOp) -> Result<(), MemoryError> {
        let context = *self
            .contexts
            .get(index)
            .ok_or_else(|| error("unknown memory witness MM"))?;
        publish_fixture(
            &mut self.memory,
            context,
            nz(index as u64 + 1)?,
            op,
            &mut self.next_table[index],
            &mut self.sequence,
        )?;
        self.drain_context(context)
    }
    pub fn first_touch(&mut self, index: usize, handle: BackingHandle) -> Result<(), MemoryError> {
        let output = self.memory.record(handle)?.backing.extent.base;
        self.edit(
            index,
            DescriptorOp::Publish {
                span: PageSpan::new(DATA_VA, PAGE),
                expected: output,
            },
        )
    }
    pub fn cow_break(
        &mut self,
        index: usize,
        old: BackingHandle,
        new: BackingHandle,
    ) -> Result<(), MemoryError> {
        let old_base = self.memory.record(old)?.backing.extent.base;
        let new_slot = self.memory.record(new)?;
        let new_base = new_slot.backing.extent.base;
        let backing = new_slot.backing.identity;
        let bytes = self.memory.read(old_base, PAGE as usize)?;
        self.memory.write(new_base, &bytes)?;
        self.edit(
            index,
            DescriptorOp::CowRepoint {
                span: PageSpan::new(DATA_VA, PAGE),
                old: old_base,
                new: new_base,
                backing,
            },
        )
    }
    fn drain_context(&mut self, context: AddressContext<RootGpa>) -> Result<(), MemoryError> {
        let mut drain = Cpl0Drain {
            cpus: &mut self.cpus,
            contexts: self.contexts,
            count: 0,
        };
        let result = drain.drain(ShootdownPlan {
            context,
            invalidation: Invalidation::ReloadCr3,
        });
        self.drain_count += drain.count;
        if result.is_err() {
            self.memory.quarantined = true;
        }
        result
    }
    pub fn revoke(&mut self, handle: BackingHandle) -> Result<(), MemoryError> {
        let mut drain = Cpl0Drain {
            cpus: &mut self.cpus,
            contexts: self.contexts,
            count: 0,
        };
        let result = self
            .memory
            .revoke(handle, &mut drain, &mut FixtureInventory);
        self.drain_count += drain.count;
        result
    }
    pub fn slot_count(&self) -> usize {
        self.memory.slot_count()
    }
    pub fn backing_byte(&self, handle: BackingHandle) -> Result<u8, MemoryError> {
        Ok(self
            .memory
            .read(self.memory.record(handle)?.backing.extent.base, 1)?[0])
    }
    pub fn observe(&mut self, index: usize) -> Result<Observation, MemoryError> {
        self.memory.admit()?;
        let cpu = self
            .cpus
            .get_mut(index)
            .ok_or_else(|| error("unknown memory witness CPU"))?;
        let watchdog = Watchdog::start();
        let mut faults = Vec::new();
        for _ in 0..32 {
            let exit = HvVcpu::run(cpu).map_err(|e| error(e.to_string()))?;
            if watchdog.expired() {
                return Err(error("memory witness deadline"));
            }
            match exit {
                VcpuExit::IoOut {
                    port: OBSERVE_PORT,
                    data,
                } if faults.is_empty() => {
                    return data
                        .first()
                        .copied()
                        .map(Observation::Byte)
                        .ok_or_else(|| error("empty byte observation"));
                }
                VcpuExit::IoOut {
                    port: carrick_x86::FAULT_DOORBELL_PORT,
                    data,
                } => {
                    let word: u32 = u32::from_le_bytes(
                        data.try_into().map_err(|_| error("invalid fault word"))?,
                    );
                    faults.push(word);
                    if faults.len() == carrick_x86::X86_FAULT_RECORD_U32_WORDS {
                        let record = hw(FaultDoorbellRecord::from_u32_words(&faults))?;
                        complete_control_exit(cpu)?;
                        hw(carrick_x86::fault_exit_from_record(
                            cpu,
                            record,
                            "memory witness",
                        ))?;
                        return Ok(Observation::Fault(record));
                    }
                }
                _ => return Err(error("unexpected memory witness exit")),
            }
        }
        Err(error("memory witness exit budget"))
    }
}
fn publish_fixture(
    memory: &mut CarrierMemory,
    context: AddressContext<RootGpa>,
    mm: NonZeroU64,
    op: DescriptorOp,
    next: &mut u64,
    sequence: &mut u64,
) -> Result<(), MemoryError> {
    *sequence += 1;
    let grants: Vec<RootGpa> = (0..8)
        .map(|i| root(*next + i * PAGE))
        .collect::<Result<_, _>>()?;
    let txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: mm,
            generation: nz(*sequence)?,
        },
        root: context.root,
        op,
        tables: &grants,
    };
    let (receipt, _) = memory.publish(&txn, &[], &mut FixtureInventory)?;
    if let DescriptorOutcome::Applied { tables_linked, .. } = receipt.outcome {
        *next += tables_linked as u64 * PAGE;
    }
    Ok(())
}
struct Cpl0Drain<'a> {
    cpus: &'a mut [KvmVcpu; 2],
    contexts: [AddressContext<RootGpa>; 2],
    count: usize,
}
// SAFETY: fixture owns both stopped CPUs with permanently assigned exact
// contexts. It executes a real CPL0 CR3 reload on each matching CPU and checks
// the acknowledgement before restoring its complete register/segment image.
unsafe impl TranslationDrain for Cpl0Drain<'_> {
    fn drain(&mut self, plan: ShootdownPlan) -> Result<(), MemoryError> {
        if plan.invalidation != Invalidation::ReloadCr3 {
            return Err(error("unsupported witness drain plan"));
        }
        let mut found = false;
        for (index, cpu) in self.cpus.iter_mut().enumerate() {
            if self.contexts[index] != plan.context {
                continue;
            }
            found = true;
            complete_control_exit(cpu)?;
            let saved_regs = cpu.fd().get_regs().map_err(|e| error(e.to_string()))?;
            let saved_system = cpu.fd().get_sregs().map_err(|e| error(e.to_string()))?;
            if saved_system.cr3 != plan.context.root.address().raw()
                || saved_system.cr4 & ((1 << 17) | (1 << 7)) != 0
            {
                return Err(error("stale/PCID/global witness context"));
            }
            let mut system = saved_system;
            system.cs.dpl = 0;
            system.cs.selector = 8;
            system.ss.dpl = 0;
            system.ss.selector = 0x10;
            cpu.fd()
                .set_sregs(&system)
                .map_err(|e| error(e.to_string()))?;
            hw(cpu.set_gpr(X86Reg::Rip, DRAIN_CODE))?;
            let watchdog = Watchdog::start();
            let exit = HvVcpu::run(cpu).map_err(|e| error(e.to_string()))?;
            if watchdog.expired()
                || !matches!(
                    exit,
                    VcpuExit::IoOut {
                        port: DRAIN_PORT,
                        ..
                    }
                )
            {
                return Err(error("CPL0 CR3 drain did not acknowledge"));
            }
            // Reinstall the exact interrupted image, including CPL and all
            // segment bases. Host sregs write is not the drain proof above.
            complete_control_exit(cpu)?;
            cpu.fd()
                .set_sregs(&saved_system)
                .map_err(|e| error(e.to_string()))?;
            cpu.fd()
                .set_regs(&saved_regs)
                .map_err(|e| error(e.to_string()))?;
            self.count += 1;
        }
        if !found {
            return Err(error("drain cannot omit a retired/parked context"));
        }
        Ok(())
    }
}

// KVM_EXIT_IO has a pending completion: GET_REGS may still name the OUT.
// Consume it under immediate_exit BEFORE saving/changing context and BEFORE
// restoring the interrupted image. Otherwise a drained CPU replays its old
// observation doorbell. This is the existing recycler's completion protocol.
fn complete_control_exit(cpu: &mut KvmVcpu) -> Result<(), MemoryError> {
    cpu.fd_mut().set_kvm_immediate_exit(1);
    let result = HvVcpu::run(cpu);
    cpu.fd_mut().set_kvm_immediate_exit(0);
    match result {
        Ok(VcpuExit::Kicked) => Ok(()),
        _ => Err(error(
            "control IO completion did not stop before guest entry",
        )),
    }
}

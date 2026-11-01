//! The same CPL0 APIC ping/pong image on two live soft or KVM vCPUs.
use carrick_softcpu_x86::*;
use std::{sync::Arc, thread, time::Duration};
pub(super) const GEN: OwnerGeneration = OwnerGeneration::FIRST;
pub(super) const PTE_P: u64 = 1;
pub(super) const PTE_W: u64 = 2;
pub(super) const PTE_U: u64 = 4;
pub(super) const PTE_NX: u64 = 1 << 63;

fn enter_cpl0(ctx: &mut SoftCpuContext, rip: u64) {
    ctx.set_cpl(0);
    ctx.cs = SoftSegment::kernel_code64(8);
    ctx.ss = SoftSegment::kernel_data(16);
    ctx.rip = rip;
}
pub(super) const TWO_VCPU_RAM_SIZE: usize = 0x4_0000; // 256 KiB identity-mapped RAM
pub(super) const TWO_VCPU_PML4_GPA: u64 = 0x1000;
pub(super) const TWO_VCPU_PDPT_GPA: u64 = 0x2000;
pub(super) const TWO_VCPU_PD0_GPA: u64 = 0x3000;
pub(super) const TWO_VCPU_PT0_GPA: u64 = 0x4000;
pub(super) const TWO_VCPU_PD3_GPA: u64 = 0x5000;
pub(super) const TWO_VCPU_PT_LAPIC_GPA: u64 = 0x6000;
pub(super) const TWO_VCPU_GDT_GPA: u64 = 0x7000;
pub(super) const TWO_VCPU_IDT0_GPA: u64 = 0x8000;
pub(super) const TWO_VCPU_IDT1_GPA: u64 = 0x9000;
pub(super) const TWO_VCPU_BSP_CODE_GPA: u64 = 0xa000;
pub(super) const TWO_VCPU_AP_CODE_GPA: u64 = 0xb000;
pub(super) const TWO_VCPU_BSP_ISR_GPA: u64 = 0xc000;
pub(super) const TWO_VCPU_AP_ISR_GPA: u64 = 0xd000;
pub(super) const TWO_VCPU_BSP_STACK_GPA: u64 = 0xe000;
pub(super) const TWO_VCPU_AP_STACK_GPA: u64 = 0xf000;
pub(super) const TWO_VCPU_SHARED_GPA: u64 = 0x1_0000;

pub(super) const IPI_PING_VEC: u8 = 0x41;
pub(super) const IPI_PONG_VEC: u8 = 0x42;
pub(super) const EXIT_PORT: u16 = 0xf4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TwoVcpuFixtureOutcome {
    bsp_apic_id: u32,
    ap_apic_id: u32,
    ap_ready: u32,
    ap_ipi_count: u32,
    ap_isr_during: u32,
    ap_isr_after_eoi: u32,
    bsp_ipi_count: u32,
    bsp_isr_during: u32,
    bsp_isr_after_eoi: u32,
    ap_done: u32,
    bsp_done: u32,
    bsp_exit_port_val: u32,
    ap_exit_port_val: u32,
}

pub(super) fn build_two_vcpu_guest_image() -> Vec<u8> {
    let mut ram = vec![0u8; TWO_VCPU_RAM_SIZE];
    let put_u64 = |buf: &mut [u8], gpa: u64, val: u64| {
        let off = gpa as usize;
        buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
    };
    let put_bytes = |buf: &mut [u8], gpa: u64, bytes: &[u8]| {
        let off = gpa as usize;
        buf[off..off + bytes.len()].copy_from_slice(bytes);
    };

    // 4-level identity-mapped page tables:
    // - 0x0000_0000..0x0004_0000 (64 x 4 KiB pages) RWX
    // - 0xfee0_0000..0xfee0_1000 (local xAPIC MMIO page) RW + NX
    let branch = PTE_P | PTE_W | PTE_U;
    put_u64(&mut ram, TWO_VCPU_PML4_GPA, TWO_VCPU_PDPT_GPA | branch);
    put_u64(&mut ram, TWO_VCPU_PDPT_GPA, TWO_VCPU_PD0_GPA | branch);
    put_u64(&mut ram, TWO_VCPU_PD0_GPA, TWO_VCPU_PT0_GPA | branch);
    for page in 0..64u64 {
        let gpa = page * 4096;
        put_u64(&mut ram, TWO_VCPU_PT0_GPA + page * 8, gpa | PTE_P | PTE_W);
    }
    put_u64(
        &mut ram,
        TWO_VCPU_PDPT_GPA + 3 * 8,
        TWO_VCPU_PD3_GPA | branch,
    );
    let pd_lapic_idx = ((LAPIC_DEFAULT_PHYS_BASE >> 21) & 0x1ff) * 8;
    put_u64(
        &mut ram,
        TWO_VCPU_PD3_GPA + pd_lapic_idx,
        TWO_VCPU_PT_LAPIC_GPA | branch,
    );
    let pt_lapic_idx = ((LAPIC_DEFAULT_PHYS_BASE >> 12) & 0x1ff) * 8;
    put_u64(
        &mut ram,
        TWO_VCPU_PT_LAPIC_GPA + pt_lapic_idx,
        LAPIC_DEFAULT_PHYS_BASE | PTE_P | PTE_W | PTE_NX,
    );

    // GDT at TWO_VCPU_GDT_GPA: 0x00 null, 0x08 64-bit kernel code, 0x10 kernel data.
    put_u64(&mut ram, TWO_VCPU_GDT_GPA, 0);
    put_u64(&mut ram, TWO_VCPU_GDT_GPA + 8, 0x00af_9b00_0000_ffff);
    put_u64(&mut ram, TWO_VCPU_GDT_GPA + 16, 0x00cf_9300_0000_ffff);

    // IDT0 (BSP): vector 0x42 (`IPI_PONG_VEC`) -> TWO_VCPU_BSP_ISR_GPA
    put_bytes(
        &mut ram,
        TWO_VCPU_IDT0_GPA + u64::from(IPI_PONG_VEC) * 16,
        &idt_gate64(TWO_VCPU_BSP_ISR_GPA, 0x08, 0, 0, true, false),
    );
    // IDT1 (AP): vector 0x41 (`IPI_PING_VEC`) -> TWO_VCPU_AP_ISR_GPA
    put_bytes(
        &mut ram,
        TWO_VCPU_IDT1_GPA + u64::from(IPI_PING_VEC) * 16,
        &idt_gate64(TWO_VCPU_AP_ISR_GPA, 0x08, 0, 0, true, false),
    );

    // Shared memory layout at TWO_VCPU_SHARED_GPA (`rdi` points here on both vCPUs;
    // `rsi` points to `LAPIC_DEFAULT_PHYS_BASE = 0xfee0_0000` on both vCPUs):

    // AP (vCPU 1) code at TWO_VCPU_AP_CODE_GPA:
    let ap_code = [
        0xFA, // cli
        0xC7, 0x86, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00,
        0x00, // mov dword ptr [rsi + 0xf0], 0x1ff
        0x8B, 0x46, 0x20, // mov eax, [rsi + 0x20]
        0xC1, 0xE8, 0x18, // shr eax, 24
        0x89, 0x47, 0x04, // mov [rdi + 0x04], eax
        0xC7, 0x47, 0x08, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [rdi + 0x08], 1
        0xE6, 0xF3, // out 0xf3, al: AP has enabled its local APIC
        0xFB, // sti
        0xF4, // hlt
        0xC7, 0x47, 0x24, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [rdi + 0x24], 1
        0xB0, 0x41, // mov al, 0x41
        0xE6, 0xF4, // out 0xf4, al
        0xF4, // hlt
    ];
    put_bytes(&mut ram, TWO_VCPU_AP_CODE_GPA, &ap_code);

    // AP ISR (vector 0x41) at TWO_VCPU_AP_ISR_GPA:
    let ap_isr = [
        0xFF, 0x47, 0x0C, // inc dword ptr [rdi + 0x0c]
        0x8B, 0x86, 0x20, 0x01, 0x00, 0x00, // mov eax, [rsi + 0x120]
        0x89, 0x47, 0x10, // mov [rdi + 0x10], eax
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // mov dword ptr [rsi + 0xb0], 0
        0x8B, 0x86, 0x20, 0x01, 0x00, 0x00, // mov eax, [rsi + 0x120]
        0x89, 0x47, 0x14, // mov [rdi + 0x14], eax
        0xC7, 0x86, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // mov dword ptr [rsi + 0x310], 0
        0xC7, 0x86, 0x00, 0x03, 0x00, 0x00, 0x42, 0x40, 0x00,
        0x00, // mov dword ptr [rsi + 0x300], 0x4042
        0x48, 0xCF, // iretq
    ];
    put_bytes(&mut ram, TWO_VCPU_AP_ISR_GPA, &ap_isr);

    // BSP (vCPU 0) code at TWO_VCPU_BSP_CODE_GPA:
    // wait_ap_ready:
    // send_ping:
    // wait_ap_done:
    // finish_bsp:
    let bsp_code = [
        0xFA, // cli
        0xC7, 0x86, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00,
        0x00, // mov dword ptr [rsi + 0xf0], 0x1ff
        0x8B, 0x46, 0x20, // mov eax, [rsi + 0x20]
        0xC1, 0xE8, 0x18, // shr eax, 24
        0x89, 0x07, // mov [rdi], eax
        // wait_ap_ready:
        // send_ping:
        0xC7, 0x86, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // mov dword ptr [rsi + 0x310], 1 << 24
        0xC7, 0x86, 0x00, 0x03, 0x00, 0x00, 0x41, 0x40, 0x00,
        0x00, // mov dword ptr [rsi + 0x300], 0x4041
        0xFB, // sti
        0xF4, // hlt
        // wait_ap_done:
        // finish_bsp:
        0xC7, 0x47, 0x28, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [rdi + 0x28], 1
        0xB0, 0x42, // mov al, 0x42
        0xE6, 0xF4, // out 0xf4, al
        0xF4, // hlt
    ];
    put_bytes(&mut ram, TWO_VCPU_BSP_CODE_GPA, &bsp_code);

    // BSP ISR (vector 0x42) at TWO_VCPU_BSP_ISR_GPA:
    let bsp_isr = [
        0xFF, 0x47, 0x18, // inc dword ptr [rdi + 0x18]
        0x8B, 0x86, 0x20, 0x01, 0x00, 0x00, // mov eax, [rsi + 0x120]
        0x89, 0x47, 0x1C, // mov [rdi + 0x1c], eax
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // mov dword ptr [rsi + 0xb0], 0
        0x8B, 0x86, 0x20, 0x01, 0x00, 0x00, // mov eax, [rsi + 0x120]
        0x89, 0x47, 0x20, // mov [rdi + 0x20], eax
        0x48, 0xCF, // iretq
    ];
    put_bytes(&mut ram, TWO_VCPU_BSP_ISR_GPA, &bsp_isr);

    ram
}

pub(super) fn decode_shared_outcome(
    ram: &[u8],
    bsp_exit_port_val: u32,
    ap_exit_port_val: u32,
) -> TwoVcpuFixtureOutcome {
    let rd = |off: usize| -> u32 {
        let base = TWO_VCPU_SHARED_GPA as usize + off;
        u32::from_le_bytes(ram[base..base + 4].try_into().unwrap())
    };
    TwoVcpuFixtureOutcome {
        bsp_apic_id: rd(0x00),
        ap_apic_id: rd(0x04),
        ap_ready: rd(0x08),
        ap_ipi_count: rd(0x0c),
        ap_isr_during: rd(0x10),
        ap_isr_after_eoi: rd(0x14),
        bsp_ipi_count: rd(0x18),
        bsp_isr_during: rd(0x1c),
        bsp_isr_after_eoi: rd(0x20),
        ap_done: rd(0x24),
        bsp_done: rd(0x28),
        bsp_exit_port_val,
        ap_exit_port_val,
    }
}

/// Shared guest memory handle allowing two `SoftMachine` instances on separate host threads
/// to share the same underlying guest RAM and `ExtentTable`.
struct SharedTwoVcpuSoftMemory {
    _backing: Arc<Vec<std::sync::atomic::AtomicU64>>,
    placement: LinearPlacement,
    extents: ExtentTable,
}
impl SharedTwoVcpuSoftMemory {
    // Caller retains the allocation through both CPU joins. The image's page tables
    // are accessed only through aligned descriptor atomics, never guest data accesses.
    unsafe fn new(base: usize, backing: Arc<Vec<std::sync::atomic::AtomicU64>>) -> Self {
        let mut extents = ExtentTable::new().unwrap();
        assert!(extents.install(ExtentRecord::new(
            FrameGpa::new(0),
            TWO_VCPU_RAM_SIZE as u64,
            GEN
        )));
        extents.set_root_generation(
            RootGpa::page_aligned(FrameGpa::new(TWO_VCPU_PML4_GPA)).unwrap(),
            GEN,
        );
        // SAFETY: caller supplies live aligned atomic-backed RAM for both CPU lifetimes.
        let placement = unsafe {
            LinearPlacement::new(base, TWO_VCPU_RAM_SIZE as u64, MmioHoles::x86_default())
        }
        .unwrap();
        Self {
            _backing: backing,
            placement,
            extents,
        }
    }
}
// SAFETY: the caller owns RAM through both joins; inventories are never edited after boot.
// Guest data writes are disjoint, and only the owning CPU reads each scratch word.
unsafe impl SoftMmuMemory for SharedTwoVcpuSoftMemory {
    fn placement(&self) -> &LinearPlacement {
        &self.placement
    }
    fn extents(&self) -> &ExtentTable {
        &self.extents
    }
    fn extents_mut(&mut self) -> &mut ExtentTable {
        &mut self.extents
    }
}

pub(super) fn run_two_vcpu_fixture_on_softmachine() -> TwoVcpuFixtureOutcome {
    let backing: Vec<std::sync::atomic::AtomicU64> = (0..(TWO_VCPU_RAM_SIZE + 4096) / 8)
        .map(|_| std::sync::atomic::AtomicU64::new(0))
        .collect();
    let backing = Arc::new(backing);
    let base = (backing.as_ptr() as usize + 4095) & !4095;
    let image = build_two_vcpu_guest_image();
    // SAFETY: initialized, aligned allocation with sufficient spare space; no CPUs yet.
    unsafe {
        std::ptr::copy_nonoverlapping(image.as_ptr(), base as *mut u8, image.len());
    }
    // SAFETY: allocation retained until both joins below.
    let shared_mem0 = unsafe { SharedTwoVcpuSoftMemory::new(base, Arc::clone(&backing)) };
    let shared_mem1 = unsafe { SharedTwoVcpuSoftMemory::new(base, Arc::clone(&backing)) };
    let cluster = Arc::new(ApicCluster::new());

    let configure_vcpu = |mem: SharedTwoVcpuSoftMemory,
                          apic_id: u8,
                          code_gpa: u64,
                          idt_gpa: u64,
                          stack_gpa: u64,
                          cluster: Arc<ApicCluster>|
     -> SoftMachine<SharedTwoVcpuSoftMemory> {
        let cpuid = Box::new(Cpl0CpuidView::with_tsc_deadline(apic_id, 1_000_000_000));
        let mut machine = SoftMachine::new(mem, cpuid).expect("SoftMachine::new");
        machine.attach_apic_cluster(cluster);
        machine.set_hlt_wait_timeout(Some(Duration::from_secs(2)));
        let ctx = machine.context_mut();
        ctx.cr3 = TWO_VCPU_PML4_GPA;
        ctx.gdtr = DescriptorTablePtr::new(23, TWO_VCPU_GDT_GPA);
        ctx.idtr = DescriptorTablePtr::new(0x0fff, idt_gpa);
        ctx.gpr[reg::RSP] = stack_gpa + 0x800;
        ctx.gpr[reg::RSI] = LAPIC_DEFAULT_PHYS_BASE;
        ctx.gpr[reg::RDI] = TWO_VCPU_SHARED_GPA;
        enter_cpl0(ctx, code_gpa);
        machine
    };

    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let cluster1 = Arc::clone(&cluster);
    let ap_handle = thread::spawn(move || {
        let mut ap = configure_vcpu(
            shared_mem1,
            1,
            TWO_VCPU_AP_CODE_GPA,
            TWO_VCPU_IDT1_GPA,
            TWO_VCPU_AP_STACK_GPA,
            cluster1,
        );
        ap.set_hlt_wait_timeout(None);
        assert!(matches!(
            ap.run(100).unwrap(),
            SoftMachineExit::IoOut { port: 0xf3, .. }
        ));
        ready_tx.send(()).unwrap();
        ap.set_hlt_wait_timeout(Some(Duration::from_secs(2)));
        match ap.run(10_000).expect("AP run") {
            SoftMachineExit::IoOut {
                port: EXIT_PORT,
                value,
                ..
            } => value,
            other => panic!("unexpected AP exit on SoftMachine: {other:?}"),
        }
    });

    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("AP enrollment");
    let bsp_handle = thread::spawn(move || {
        let mut bsp = configure_vcpu(
            shared_mem0,
            0,
            TWO_VCPU_BSP_CODE_GPA,
            TWO_VCPU_IDT0_GPA,
            TWO_VCPU_BSP_STACK_GPA,
            cluster,
        );
        match bsp.run(100_000).expect("BSP run") {
            SoftMachineExit::IoOut {
                port: EXIT_PORT,
                value,
                ..
            } => value,
            other => panic!("unexpected BSP exit on SoftMachine: {other:?}"),
        }
    });

    let ap_port_val = ap_handle.join().expect("AP thread join");
    let bsp_port_val = bsp_handle.join().expect("BSP thread join");
    // SAFETY: both CPUs have joined and no guest access remains.
    let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, TWO_VCPU_RAM_SIZE) };
    decode_shared_outcome(bytes, bsp_port_val, ap_port_val)
}

pub(super) fn expected_outcome() -> TwoVcpuFixtureOutcome {
    TwoVcpuFixtureOutcome {
        bsp_apic_id: 0,
        ap_apic_id: 1,
        ap_ready: 1,
        ap_ipi_count: 1,
        ap_isr_during: 1 << (IPI_PING_VEC - 0x40),
        ap_isr_after_eoi: 0,
        bsp_ipi_count: 1,
        bsp_isr_during: 1 << (IPI_PONG_VEC - 0x40),
        bsp_isr_after_eoi: 0,
        ap_done: 1,
        bsp_done: 1,
        bsp_exit_port_val: u32::from(IPI_PONG_VEC),
        ap_exit_port_val: u32::from(IPI_PING_VEC),
    }
}

pub(super) fn idt_gate64(
    handler: u64,
    selector: u16,
    ist: u8,
    dpl: u8,
    present: bool,
    trap_gate: bool,
) -> [u8; 16] {
    let mut gate = [0u8; 16];
    gate[0..2].copy_from_slice(&(handler as u16).to_le_bytes());
    gate[2..4].copy_from_slice(&selector.to_le_bytes());
    gate[4] = ist & 0x7;
    let gate_type = if trap_gate { 0x0f } else { 0x0e };
    gate[5] = gate_type | ((dpl & 3) << 5) | if present { 0x80 } else { 0 };
    gate[6..8].copy_from_slice(&((handler >> 16) as u16).to_le_bytes());
    gate[8..12].copy_from_slice(&((handler >> 32) as u32).to_le_bytes());
    gate
}

use carrick_hal::TrapError;

use crate::bringup_fns::BringupLayout;
use crate::vmm::{WindowRegion, X86_PML4_CAPACITY, X86Exit, X86FaultKind, X86Reg, X86Seg, X86Vcpu};

pub const FP_STUB_DOORBELL_PORT: u16 = 0xC6;
pub const FAULT_DOORBELL_PORT: u16 = 0xC7;

pub const X86_FAULT_SLOTS: u64 = 256;
pub const X86_IDT_ENTRIES: usize = 256;
pub const X86_IDT_BYTES: usize = X86_IDT_ENTRIES * 16;
const X86_FAULT_STUB_STRIDE: u64 = 128;
const X86_TSS64_BYTES: usize = 104;
pub const X86_TSS64_LIMIT: u32 = (X86_TSS64_BYTES - 1) as u32;
const X86_FAULT_VECTORS: &[u8] = &[0, 6, 8, 10, 11, 12, 13, 14, 16, 17, 19];
pub const X86_FAULT_RECORD_U32_WORDS: usize = 15;
pub const X86_FAULT_MEMORY_RECORD_BYTES: usize = std::mem::size_of::<FaultMemoryRecord>();

const KERN_CS64_SEL: u16 = 0x08;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct IdtGateAttrs: u8 {
        const INTERRUPT_GATE_64 = 0x0E;
        const PRESENT = 0x80;
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct IdtGate64 {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attrs: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

const _: () = assert!(std::mem::size_of::<IdtGate64>() == 16);

impl IdtGate64 {
    fn interrupt(offset: u64) -> Self {
        Self {
            offset_low: offset as u16,
            selector: KERN_CS64_SEL,
            ist: 0,
            attrs: (IdtGateAttrs::PRESENT | IdtGateAttrs::INTERRUPT_GATE_64).bits(),
            offset_mid: (offset >> 16) as u16,
            offset_high: (offset >> 32) as u32,
            reserved: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Idt64 {
    gates: [IdtGate64; X86_IDT_ENTRIES],
}

const _: () = assert!(std::mem::size_of::<Idt64>() == X86_IDT_BYTES);

impl Default for Idt64 {
    fn default() -> Self {
        Self {
            gates: [IdtGate64::default(); X86_IDT_ENTRIES],
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Tss64 {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iopb: u16,
}

const _: () = assert!(std::mem::size_of::<Tss64>() == X86_TSS64_BYTES);

impl Tss64 {
    fn new(rsp0: u64) -> Self {
        Self {
            reserved0: 0,
            rsp: [rsp0, 0, 0],
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            iopb: X86_TSS64_BYTES as u16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultDoorbellRecord {
    pub vector: u8,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub saved_rax: u64,
    pub cr2: u64,
}

impl FaultDoorbellRecord {
    pub fn from_u32_words(words: &[u32]) -> Result<Self, TrapError> {
        if words.len() < X86_FAULT_RECORD_U32_WORDS {
            return Err(fault_error(format!(
                "fault doorbell record too short: {} < {}",
                words.len(),
                X86_FAULT_RECORD_U32_WORDS
            )));
        }
        let vector = u8::try_from(words[0])
            .map_err(|_| fault_error(format!("fault vector does not fit in u8: {}", words[0])))?;
        let qword = |i: usize| -> u64 { u64::from(words[i]) | (u64::from(words[i + 1]) << 32) };
        Ok(Self {
            vector,
            error_code: qword(1),
            rip: qword(3),
            cs: qword(5),
            rsp: qword(7),
            rflags: qword(9),
            saved_rax: qword(11),
            cr2: qword(13),
        })
    }

    pub fn kind(self) -> X86FaultKind {
        match self.vector {
            0 => X86FaultKind::DivideError,
            6 => X86FaultKind::InvalidOpcode,
            13 => X86FaultKind::GeneralProtection,
            14 => X86FaultKind::PageFault,
            17 => X86FaultKind::AlignmentCheck,
            _ => X86FaultKind::Other,
        }
    }

    pub fn fault_addr(self) -> u64 {
        match self.kind() {
            X86FaultKind::PageFault => self.cr2,
            X86FaultKind::GeneralProtection => 0,
            X86FaultKind::DivideError
            | X86FaultKind::InvalidOpcode
            | X86FaultKind::AlignmentCheck
            | X86FaultKind::Other => self.rip,
        }
    }
}

/// Memory-backed SP4.3 fault record written by guest IDT stubs for VMMs whose
/// PIO exits do not expose the `OUT` payload. All fields are u64 so the guest
/// stub can use plain 64-bit stores and the host can convert to the compact
/// [`FaultDoorbellRecord`] used by the shared trap engine.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct FaultMemoryRecord {
    vector: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    rsp: u64,
    rflags: u64,
    saved_rax: u64,
    cr2: u64,
}

const _: () = assert!(std::mem::size_of::<FaultMemoryRecord>() == 64);

impl FaultMemoryRecord {
    pub fn new(
        vector: u64,
        error_code: u64,
        rip: u64,
        cs: u64,
        rsp: u64,
        rflags: u64,
        saved_rax: u64,
        cr2: u64,
    ) -> Self {
        Self {
            vector,
            error_code,
            rip,
            cs,
            rsp,
            rflags,
            saved_rax,
            cr2,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrapError> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return Err(fault_error(format!(
                "memory fault record too short: {} < {}",
                bytes.len(),
                std::mem::size_of::<Self>()
            )));
        }
        let mut record = Self::default();
        // SAFETY: `record` is a plain packed integer struct and `bytes` was
        // length-checked. Copying into it avoids creating references to packed
        // fields.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                std::ptr::addr_of_mut!(record).cast::<u8>(),
                std::mem::size_of::<Self>(),
            );
        }
        Ok(record)
    }

    pub fn to_doorbell_record(self) -> Result<FaultDoorbellRecord, TrapError> {
        let vector = self.vector;
        let vector = u8::try_from(vector)
            .map_err(|_| fault_error(format!("fault vector does not fit in u8: {vector}")))?;
        Ok(FaultDoorbellRecord {
            vector,
            error_code: self.error_code,
            rip: self.rip,
            cs: self.cs,
            rsp: self.rsp,
            rflags: self.rflags,
            saved_rax: self.saved_rax,
            cr2: self.cr2,
        })
    }
}

fn fault_error(msg: impl Into<String>) -> TrapError {
    TrapError::Hypervisor(format!("x86 fault tables: {}", msg.into()))
}

pub fn fault_idt_base(layout: BringupLayout) -> u64 {
    layout.pml4_base + X86_PML4_CAPACITY
}

pub fn fault_stub_base(layout: BringupLayout) -> u64 {
    fault_idt_base(layout) + X86_FAULT_SLOTS * 4096
}

pub fn fault_tss_base(layout: BringupLayout) -> u64 {
    fault_stub_base(layout) + X86_FAULT_SLOTS * 4096
}

pub fn fault_stack_base(layout: BringupLayout) -> u64 {
    fault_tss_base(layout) + X86_FAULT_SLOTS * 4096
}

pub fn fault_record_base(layout: BringupLayout) -> u64 {
    fault_stack_base(layout) + X86_FAULT_SLOTS * 4096
}

pub fn fault_slot_gpa(base: u64, slot: u64) -> Result<u64, TrapError> {
    if slot >= X86_FAULT_SLOTS {
        return Err(fault_error(format!(
            "vCPU fault slot {slot} exceeds X86_FAULT_SLOTS={X86_FAULT_SLOTS}"
        )));
    }
    Ok(base + slot * 4096)
}

pub fn add_fault_windows(regions: &mut Vec<WindowRegion>, layout: BringupLayout) {
    let slots_len = X86_FAULT_SLOTS * 4096;
    regions.push(WindowRegion {
        va: fault_idt_base(layout),
        gpa: fault_idt_base(layout),
        len: slots_len,
        read: true,
        write: false,
        exec: false,
        user: false,
        shared: false,
    });
    regions.push(WindowRegion {
        va: fault_stub_base(layout),
        gpa: fault_stub_base(layout),
        len: slots_len,
        read: true,
        write: false,
        exec: true,
        user: false,
        shared: false,
    });
    regions.push(WindowRegion {
        va: fault_tss_base(layout),
        gpa: fault_tss_base(layout),
        len: slots_len,
        read: true,
        write: true,
        exec: false,
        user: false,
        shared: false,
    });
    regions.push(WindowRegion {
        va: fault_stack_base(layout),
        gpa: fault_stack_base(layout),
        len: slots_len,
        read: true,
        write: true,
        exec: false,
        user: false,
        shared: false,
    });
    regions.push(WindowRegion {
        va: fault_record_base(layout),
        gpa: fault_record_base(layout),
        len: slots_len,
        read: true,
        write: true,
        exec: false,
        user: false,
        shared: false,
    });
}

pub fn write_fault_tables<V: crate::X86Vmm>(
    vm: &V,
    layout: BringupLayout,
) -> Result<(), TrapError> {
    write_fault_tables_with(layout, |gpa, bytes| vm.write_gpa(gpa, bytes))
}

pub fn write_fault_tables_with<F>(layout: BringupLayout, mut write: F) -> Result<(), TrapError>
where
    F: FnMut(u64, &[u8]) -> Result<(), TrapError>,
{
    for slot in 0..X86_FAULT_SLOTS {
        let idt_gpa = fault_slot_gpa(fault_idt_base(layout), slot)?;
        let stub_gpa = fault_slot_gpa(fault_stub_base(layout), slot)?;
        let tss_gpa = fault_slot_gpa(fault_tss_base(layout), slot)?;
        let stack_gpa = fault_slot_gpa(fault_stack_base(layout), slot)?;

        let idt = fault_idt(stub_gpa);
        write(idt_gpa, bytes_of(&idt))?;

        let stubs = fault_stub_page(stub_gpa)?;
        write(stub_gpa, &stubs)?;

        let tss = Tss64::new(stack_gpa + 4096);
        write(tss_gpa, bytes_of(&tss))?;
    }
    Ok(())
}

/// Write fault tables whose stubs publish the full fault record into a
/// per-vCPU memory page, then ring one `OUT` doorbell. Backends whose native PIO
/// exits include the payload can keep using [`write_fault_tables`]; this variant
/// is for backends like NVMM that expose only port/width metadata.
pub fn write_memory_record_fault_tables<V: crate::X86Vmm>(
    vm: &V,
    layout: BringupLayout,
) -> Result<(), TrapError> {
    write_memory_record_fault_tables_with(layout, |gpa, bytes| vm.write_gpa(gpa, bytes))
}

pub fn write_memory_record_fault_tables_with<F>(
    layout: BringupLayout,
    mut write: F,
) -> Result<(), TrapError>
where
    F: FnMut(u64, &[u8]) -> Result<(), TrapError>,
{
    for slot in 0..X86_FAULT_SLOTS {
        let idt_gpa = fault_slot_gpa(fault_idt_base(layout), slot)?;
        let stub_gpa = fault_slot_gpa(fault_stub_base(layout), slot)?;
        let tss_gpa = fault_slot_gpa(fault_tss_base(layout), slot)?;
        let stack_gpa = fault_slot_gpa(fault_stack_base(layout), slot)?;
        let record_gpa = fault_slot_gpa(fault_record_base(layout), slot)?;

        let idt = fault_idt(stub_gpa);
        write(idt_gpa, bytes_of(&idt))?;

        let stubs = fault_memory_record_stub_page(stub_gpa, record_gpa)?;
        write(stub_gpa, &stubs)?;

        let tss = Tss64::new(stack_gpa + 4096);
        write(tss_gpa, bytes_of(&tss))?;

        let record = FaultMemoryRecord::default();
        write(record_gpa, bytes_of(&record))?;
    }
    Ok(())
}

pub fn program_fault_segments<C: X86Vcpu>(
    vcpu: &mut C,
    layout: BringupLayout,
    slot: u64,
) -> Result<(), TrapError> {
    let segs = crate::long_mode_segment_state();
    vcpu.set_segment(
        X86Seg::Idtr,
        fault_slot_gpa(fault_idt_base(layout), slot)?,
        (X86_IDT_BYTES - 1) as u32,
        0,
    )?;
    vcpu.set_segment(
        X86Seg::Tr,
        fault_slot_gpa(fault_tss_base(layout), slot)?,
        X86_TSS64_LIMIT,
        segs.tr_ar,
    )
}

pub fn fault_exit_from_record<C: X86Vcpu>(
    vcpu: &mut C,
    record: FaultDoorbellRecord,
    backend: &str,
) -> Result<X86Exit, TrapError> {
    if record.cs & 3 != 3 {
        return Err(TrapError::Hypervisor(format!(
            "{backend}: ring-0 fault vector={} error=0x{:x} rip=0x{:x} cs=0x{:x} cr2=0x{:x}",
            record.vector, record.error_code, record.rip, record.cs, record.cr2
        )));
    }

    restore_user_after_fault(vcpu, record)?;
    Ok(X86Exit::Fault {
        kind: record.kind(),
        fault_addr: record.fault_addr(),
        error_code: record.error_code,
    })
}

fn restore_user_after_fault<C: X86Vcpu>(
    vcpu: &mut C,
    record: FaultDoorbellRecord,
) -> Result<(), TrapError> {
    crate::program_user_segments(vcpu)?;
    vcpu.set_gpr(X86Reg::Rax, record.saved_rax)?;
    vcpu.set_gpr(X86Reg::Rip, record.rip)?;
    vcpu.set_gpr(X86Reg::Rsp, record.rsp)?;
    vcpu.set_gpr(X86Reg::Rflags, record.rflags | 0x2)
}

fn vector_has_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10 | 11 | 12 | 13 | 14 | 17)
}

fn fault_idt(stub_base: u64) -> Idt64 {
    let mut idt = Idt64::default();
    for &vector in X86_FAULT_VECTORS {
        let offset = stub_base + u64::from(vector) * X86_FAULT_STUB_STRIDE;
        idt.gates[usize::from(vector)] = IdtGate64::interrupt(offset);
    }
    idt
}

fn fault_stub_page(stub_base: u64) -> Result<[u8; 4096], TrapError> {
    let mut page = [0u8; 4096];
    for &vector in X86_FAULT_VECTORS {
        let off = usize::from(vector) * X86_FAULT_STUB_STRIDE as usize;
        let stub = fault_stub_for_vector(vector)?;
        if stub.len() > X86_FAULT_STUB_STRIDE as usize {
            return Err(fault_error(format!(
                "fault stub for vector {vector} is {} bytes, stride is {}",
                stub.len(),
                X86_FAULT_STUB_STRIDE
            )));
        }
        let end = off + stub.len();
        if stub_base + end as u64 > stub_base + 4096 {
            return Err(fault_error(format!(
                "fault stub for vector {vector} exceeds page"
            )));
        }
        page[off..end].copy_from_slice(&stub);
    }
    Ok(page)
}

fn fault_stub_for_vector(vector: u8) -> Result<Vec<u8>, TrapError> {
    let mut stub = Vec::with_capacity(X86_FAULT_STUB_STRIDE as usize);
    let has_error = vector_has_error_code(vector);
    let error_off = if has_error { 8 } else { 0 };
    let rip_off = if has_error { 16 } else { 8 };
    let cs_off = if has_error { 24 } else { 16 };
    let rflags_off = if has_error { 32 } else { 24 };
    let rsp_off = if has_error { 40 } else { 32 };

    stub.push(0x50); // push %rax; preserve interrupted RAX at (%rsp)
    emit_send_imm32(&mut stub, u32::from(vector));
    if has_error {
        emit_load_stack_qword(&mut stub, error_off);
        emit_send_rax_qword(&mut stub);
    } else {
        emit_send_imm64(&mut stub, 0);
    }
    emit_load_stack_qword(&mut stub, rip_off);
    emit_send_rax_qword(&mut stub);
    emit_load_stack_qword(&mut stub, cs_off);
    emit_send_rax_qword(&mut stub);
    emit_load_stack_qword(&mut stub, rsp_off);
    emit_send_rax_qword(&mut stub);
    emit_load_stack_qword(&mut stub, rflags_off);
    emit_send_rax_qword(&mut stub);
    emit_load_stack_qword(&mut stub, 0);
    emit_send_rax_qword(&mut stub);
    stub.extend_from_slice(&[0x0F, 0x20, 0xD0]); // mov %cr2,%rax
    emit_send_rax_qword(&mut stub);
    stub.extend_from_slice(&[0xEB, 0xFE]); // jmp .

    Ok(stub)
}

fn fault_memory_record_stub_page(stub_base: u64, record_gpa: u64) -> Result<[u8; 4096], TrapError> {
    let mut page = [0u8; 4096];
    for &vector in X86_FAULT_VECTORS {
        let off = usize::from(vector) * X86_FAULT_STUB_STRIDE as usize;
        let stub = fault_memory_record_stub_for_vector(stub_base + off as u64, record_gpa, vector)?;
        if stub.len() > X86_FAULT_STUB_STRIDE as usize {
            return Err(fault_error(format!(
                "memory fault stub for vector {vector} is {} bytes, stride is {}",
                stub.len(),
                X86_FAULT_STUB_STRIDE
            )));
        }
        page[off..off + stub.len()].copy_from_slice(&stub);
    }
    Ok(page)
}

fn fault_memory_record_stub_for_vector(
    stub_start: u64,
    record_gpa: u64,
    vector: u8,
) -> Result<Vec<u8>, TrapError> {
    let mut stub = Vec::with_capacity(X86_FAULT_STUB_STRIDE as usize);
    let has_error = vector_has_error_code(vector);
    let error_off = if has_error { 8 } else { 0 };
    let rip_off = if has_error { 16 } else { 8 };
    let cs_off = if has_error { 24 } else { 16 };
    let rflags_off = if has_error { 32 } else { 24 };
    let rsp_off = if has_error { 40 } else { 32 };

    stub.push(0x50); // push %rax; preserve interrupted RAX at (%rsp)
    emit_load_imm64_rax(&mut stub, u64::from(vector));
    emit_store_rax_riprel_current(&mut stub, stub_start, record_gpa)?;

    if has_error {
        emit_load_stack_qword(&mut stub, error_off);
    } else {
        stub.extend_from_slice(&[0x31, 0xC0]); // xor %eax,%eax
    }
    emit_store_rax_riprel_current(&mut stub, stub_start, record_gpa + 8)?;

    emit_load_stack_qword(&mut stub, rip_off);
    emit_store_rax_riprel_current(&mut stub, stub_start, record_gpa + 16)?;
    emit_load_stack_qword(&mut stub, cs_off);
    emit_store_rax_riprel_current(&mut stub, stub_start, record_gpa + 24)?;
    emit_load_stack_qword(&mut stub, rsp_off);
    emit_store_rax_riprel_current(&mut stub, stub_start, record_gpa + 32)?;
    emit_load_stack_qword(&mut stub, rflags_off);
    emit_store_rax_riprel_current(&mut stub, stub_start, record_gpa + 40)?;
    emit_load_stack_qword(&mut stub, 0);
    emit_store_rax_riprel_current(&mut stub, stub_start, record_gpa + 48)?;
    stub.extend_from_slice(&[0x0F, 0x20, 0xD0]); // mov %cr2,%rax
    emit_store_rax_riprel_current(&mut stub, stub_start, record_gpa + 56)?;

    emit_load_stack_qword(&mut stub, 0);
    emit_out_eax(&mut stub);
    stub.extend_from_slice(&[0xEB, 0xFE]); // jmp .

    Ok(stub)
}

fn emit_load_stack_qword(stub: &mut Vec<u8>, offset: u8) {
    stub.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, offset]); // mov off(%rsp),%rax
}

fn emit_load_imm64_rax(stub: &mut Vec<u8>, value: u64) {
    stub.extend_from_slice(&[0x48, 0xB8]); // movabs imm64,%rax
    stub.extend_from_slice(&value.to_le_bytes());
}

fn emit_send_imm32(stub: &mut Vec<u8>, value: u32) {
    stub.push(0xB8); // mov imm32,%eax
    stub.extend_from_slice(&value.to_le_bytes());
    emit_out_eax(stub);
}

fn emit_send_imm64(stub: &mut Vec<u8>, value: u64) {
    emit_send_imm32(stub, value as u32);
    emit_send_imm32(stub, (value >> 32) as u32);
}

fn emit_send_rax_qword(stub: &mut Vec<u8>) {
    emit_out_eax(stub);
    stub.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x20]); // shr $32,%rax
    emit_out_eax(stub);
}

fn emit_out_eax(stub: &mut Vec<u8>) {
    stub.extend_from_slice(&[0xE7, FAULT_DOORBELL_PORT as u8]); // out %eax,imm8
}

fn emit_store_rax_riprel_current(
    stub: &mut Vec<u8>,
    stub_start: u64,
    target: u64,
) -> Result<(), TrapError> {
    let insn_va = stub_start + stub.len() as u64;
    emit_store_rax_riprel(stub, insn_va, target)
}

fn emit_store_rax_riprel(stub: &mut Vec<u8>, insn_va: u64, target: u64) -> Result<(), TrapError> {
    let next = insn_va + 7;
    let disp = i64::try_from(target)
        .and_then(|t| i64::try_from(next).map(|n| t - n))
        .map_err(|_| fault_error("fault stub RIP-relative target overflow"))?;
    let disp = i32::try_from(disp)
        .map_err(|_| fault_error("fault stub RIP-relative displacement overflow"))?;
    stub.extend_from_slice(&[0x48, 0x89, 0x05]); // mov %rax, disp32(%rip)
    stub.extend_from_slice(&disp.to_le_bytes());
    Ok(())
}

fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: callers pass repr(C, packed) integer-only structs copied
    // immediately into guest RAM.
    unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(value).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_layout() -> BringupLayout {
        BringupLayout {
            trampoline_base: 0x1000_0000,
            gdt_base: 0x1000_1000,
            pml4_base: 0x1000_2000,
        }
    }

    #[test]
    fn fault_tables_fit_in_kernel_window_headroom() {
        let layout = test_layout();
        let end = fault_stack_base(layout) + X86_FAULT_SLOTS * 4096;
        assert!(end <= layout.trampoline_base + 32 * 1024 * 1024);
    }

    #[test]
    fn fault_stub_streams_fixed_record_words() {
        let stub = fault_stub_for_vector(14).expect("page fault stub");
        let outs = stub
            .windows(2)
            .filter(|w| *w == [0xE7, FAULT_DOORBELL_PORT as u8])
            .count();
        assert_eq!(outs, X86_FAULT_RECORD_U32_WORDS);
        assert!(stub.len() <= X86_FAULT_STUB_STRIDE as usize);
    }

    #[test]
    fn fault_record_decodes_qword_pairs() {
        let words = [
            14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        ];
        let record = FaultDoorbellRecord::from_u32_words(&words).expect("decode");
        assert_eq!(record.vector, 14);
        assert_eq!(record.error_code, 0x22_0000_0011);
        assert_eq!(record.rip, 0x44_0000_0033);
        assert_eq!(record.cs, 0x66_0000_0055);
        assert_eq!(record.rsp, 0x88_0000_0077);
        assert_eq!(record.rflags, 0xaa_0000_0099);
        assert_eq!(record.saved_rax, 0xcc_0000_00bb);
        assert_eq!(record.cr2, 0xee_0000_00dd);
        assert_eq!(record.kind(), X86FaultKind::PageFault);
        assert_eq!(record.fault_addr(), record.cr2);
    }

    #[test]
    fn memory_record_fault_stub_writes_record_and_rings_once() {
        let layout = test_layout();
        let stub_base = fault_stub_base(layout);
        let record_gpa = fault_record_base(layout);
        let stub = fault_memory_record_stub_for_vector(
            stub_base + 14 * X86_FAULT_STUB_STRIDE,
            record_gpa,
            14,
        )
        .expect("memory-backed page-fault stub");

        let outs = stub
            .windows(2)
            .filter(|w| *w == [0xE7, FAULT_DOORBELL_PORT as u8])
            .count();
        let stores = stub.windows(3).filter(|w| *w == [0x48, 0x89, 0x05]).count();

        assert_eq!(outs, 1, "memory-backed records need only one doorbell");
        assert_eq!(stores, 8, "stub must write every packed fault-record field");
        assert!(stub.len() <= X86_FAULT_STUB_STRIDE as usize);
    }

    #[test]
    fn memory_record_decodes_packed_bytes() {
        let record = FaultMemoryRecord::new(14, 0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee);
        let decoded =
            FaultMemoryRecord::from_bytes(bytes_of(&record)).expect("decode packed memory record");

        assert_eq!(decoded.to_doorbell_record().expect("doorbell").vector, 14);
        assert_eq!(
            decoded.to_doorbell_record().expect("doorbell").fault_addr(),
            0xee
        );
    }
}

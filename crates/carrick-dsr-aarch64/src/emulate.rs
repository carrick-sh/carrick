//! AArch64 fault-path emulation for the native (DSR) backend: the
//! bad64-driven interpreters the runtime's signal lowering invokes when a
//! translated guest instruction must be completed in software — exclusive
//! monitors (`emulate_dsr_exclusive_access`), the linux4k guarded-page
//! single-instruction paths (scalar/pair/vector loads and stores, LDADD
//! atomics, load-acquire/store-release), `DC ZVA`, and the shared
//! register-file/addressing decode helpers over `NativeUcontextSnapshot`.
//!
//! Moved verbatim from `carrick-runtime/src/native_darwin.rs` as part of the
//! staged native-backend extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md):
//! these functions were the runtime's last unconditional `bad64` references.
//! The one deliberate change: they return
//! `carrick_dsr::native_error::NativeMemoryError` instead of the runtime's
//! `NativeMemoryError` (same `Unsupported` messages; the runtime converts at its
//! `?` sites via the existing `From` impl in run_result.rs).

use crate::mapped_memory::{
    NativeExclusiveReservation, NativeMappedMemory, SharedNativeMemory, child_write_stderr,
};
use crate::snapshot::NativeUcontextSnapshot;
use carrick_dsr::native_error::NativeMemoryError;
use carrick_guest_mem::{GuestMemory, MemoryError};

/// `DC ZVA` zeroing granule advertised through `DCZID_EL0` (the runtime's
/// `NATIVE_DCZID_EL0` value encodes this 64-byte block size).
pub const NATIVE_DC_ZVA_BLOCK_SIZE: usize = 64;

pub fn write_guest_ram_through_lock(
    memory: &SharedNativeMemory,
    address: u64,
    bytes: &[u8],
) -> Result<(), MemoryError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let guard = memory.upgradable_read();
    if guard.protections.range_write_denied(address, bytes.len()) {
        return Err(MemoryError::OutOfBounds {
            address,
            length: bytes.len(),
        });
    }
    if guard.range_may_execute(address, bytes.len()) {
        let mut guard = parking_lot::RwLockUpgradableReadGuard::upgrade(guard);
        guard.write_exec_page_bytes(address, bytes)
    } else {
        guard.write_bytes_raw_shared(address, bytes)
    }
}

/// [`write_guest_ram_through_lock`], chunked over a zero-filled range (the
/// `zero_guest_range` shape used by `select`/`pselect` fd-set clears).
pub fn zero_guest_ram_through_lock(
    memory: &SharedNativeMemory,
    address: u64,
    len: usize,
) -> Result<(), MemoryError> {
    carrick_guest_mem::zero_range_chunked(address, len, |addr, chunk| {
        write_guest_ram_through_lock(memory, addr, chunk)
    })
}

pub fn native_dc_zva(memory: &SharedNativeMemory, address: u64) -> Result<(), NativeMemoryError> {
    let start = address & !(NATIVE_DC_ZVA_BLOCK_SIZE as u64 - 1);
    write_guest_ram_through_lock(memory, start, &[0; NATIVE_DC_ZVA_BLOCK_SIZE]).map_err(|error| {
        NativeMemoryError::Unsupported(format!(
            "native Darwin DC ZVA failed at 0x{address:x}: {error}"
        ))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeScalarAccessKind {
    Load { sign_extend: bool },
    Store,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeScalarAccess {
    kind: NativeScalarAccessKind,
    width: usize,
    destination_width: usize,
}

pub fn bad64_gpr_index(reg: bad64::Reg) -> Option<(usize, usize)> {
    let raw = reg as u32;
    let w0 = bad64::Reg::W0 as u32;
    let w30 = bad64::Reg::W30 as u32;
    if (w0..=w30).contains(&raw) {
        return Some(((raw - w0) as usize, 4));
    }
    let x0 = bad64::Reg::X0 as u32;
    let x30 = bad64::Reg::X30 as u32;
    if (x0..=x30).contains(&raw) {
        return Some(((raw - x0) as usize, 8));
    }
    None
}

pub fn bad64_transfer_width(reg: bad64::Reg) -> Option<usize> {
    bad64_gpr_index(reg).map(|(_, width)| width).or_else(|| {
        if reg == bad64::Reg::WZR {
            Some(4)
        } else if reg == bad64::Reg::XZR {
            Some(8)
        } else {
            None
        }
    })
}

pub fn native_snapshot_read_reg(snapshot: &NativeUcontextSnapshot, reg: bad64::Reg) -> Option<u64> {
    if let Some((index, width)) = bad64_gpr_index(reg) {
        let value = snapshot.x.get(index).copied()?;
        return Some(if width == 4 {
            value & u64::from(u32::MAX)
        } else {
            value
        });
    }
    if reg == bad64::Reg::WZR || reg == bad64::Reg::XZR {
        return Some(0);
    }
    if reg == bad64::Reg::SP || reg == bad64::Reg::WSP {
        return Some(snapshot.sp);
    }
    None
}

pub fn native_snapshot_write_reg(
    snapshot: &mut NativeUcontextSnapshot,
    reg: bad64::Reg,
    value: u64,
) -> bool {
    if let Some((index, width)) = bad64_gpr_index(reg) {
        let Some(slot) = snapshot.x.get_mut(index) else {
            return false;
        };
        *slot = if width == 4 {
            value & u64::from(u32::MAX)
        } else {
            value
        };
        return true;
    }
    if reg == bad64::Reg::WZR || reg == bad64::Reg::XZR {
        return true;
    }
    if reg == bad64::Reg::SP || reg == bad64::Reg::WSP {
        snapshot.sp = value;
        return true;
    }
    false
}

pub fn add_bad64_imm(base: u64, imm: bad64::Imm) -> u64 {
    match imm {
        bad64::Imm::Signed(value) => base.wrapping_add_signed(value),
        bad64::Imm::Unsigned(value) => base.wrapping_add(value),
    }
}

pub fn extend_bad64_index(value: u64, shift: Option<bad64::Shift>) -> Option<u64> {
    match shift {
        None => Some(value),
        Some(bad64::Shift::LSL(amount) | bad64::Shift::UXTX(amount)) => {
            Some(value.wrapping_shl(amount))
        }
        Some(bad64::Shift::SXTX(amount)) => Some((value as i64 as u64).wrapping_shl(amount)),
        Some(bad64::Shift::UXTW(amount)) => Some(u64::from(value as u32).wrapping_shl(amount)),
        Some(bad64::Shift::SXTW(amount)) => {
            Some((value as u32 as i32 as i64 as u64).wrapping_shl(amount))
        }
        _ => None,
    }
}

pub fn decode_native_scalar_address(
    snapshot: &NativeUcontextSnapshot,
    operand: bad64::Operand,
) -> Option<(u64, Option<(bad64::Reg, u64)>)> {
    match operand {
        bad64::Operand::MemReg(base) => Some((native_snapshot_read_reg(snapshot, base)?, None)),
        bad64::Operand::MemOffset {
            reg: base,
            offset,
            mul_vl: false,
            arrspec: None,
        } => Some((
            add_bad64_imm(native_snapshot_read_reg(snapshot, base)?, offset),
            None,
        )),
        bad64::Operand::MemPreIdx { reg: base, imm } => {
            let address = add_bad64_imm(native_snapshot_read_reg(snapshot, base)?, imm);
            Some((address, Some((base, address))))
        }
        bad64::Operand::MemPostIdxImm { reg: base, imm } => {
            let address = native_snapshot_read_reg(snapshot, base)?;
            Some((address, Some((base, add_bad64_imm(address, imm)))))
        }
        bad64::Operand::MemExt {
            regs: [base, index],
            shift,
            arrspec: None,
        } => {
            let base = native_snapshot_read_reg(snapshot, base)?;
            let index = native_snapshot_read_reg(snapshot, index)?;
            Some((base.wrapping_add(extend_bad64_index(index, shift)?), None))
        }
        _ => None,
    }
}

pub fn decode_native_scalar_access(
    op: bad64::Op,
    transfer_width: usize,
) -> Option<NativeScalarAccess> {
    use bad64::Op;

    let access = match op {
        Op::LDR | Op::LDUR => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: false },
            width: transfer_width,
            destination_width: transfer_width,
        },
        Op::LDRB | Op::LDURB => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: false },
            width: 1,
            destination_width: transfer_width,
        },
        Op::LDRH | Op::LDURH => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: false },
            width: 2,
            destination_width: transfer_width,
        },
        Op::LDRSB | Op::LDURSB => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: true },
            width: 1,
            destination_width: transfer_width,
        },
        Op::LDRSH | Op::LDURSH => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: true },
            width: 2,
            destination_width: transfer_width,
        },
        Op::LDRSW | Op::LDURSW if transfer_width == 8 => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: true },
            width: 4,
            destination_width: 8,
        },
        Op::STR | Op::STUR => NativeScalarAccess {
            kind: NativeScalarAccessKind::Store,
            width: transfer_width,
            destination_width: transfer_width,
        },
        Op::STRB | Op::STURB => NativeScalarAccess {
            kind: NativeScalarAccessKind::Store,
            width: 1,
            destination_width: transfer_width,
        },
        Op::STRH | Op::STURH => NativeScalarAccess {
            kind: NativeScalarAccessKind::Store,
            width: 2,
            destination_width: transfer_width,
        },
        _ => return None,
    };
    Some(access)
}

pub fn native_load_value(bytes: &[u8], sign_extend: bool, destination_width: usize) -> u64 {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    if sign_extend && !bytes.is_empty() && bytes.len() < std::mem::size_of::<u64>() {
        let shift = 64 - bytes.len() * 8;
        value = ((value << shift) as i64 >> shift) as u64;
    }
    if destination_width == 4 {
        value & u64::from(u32::MAX)
    } else {
        value
    }
}

pub fn bad64_single_vector_index(operand: bad64::Operand) -> Option<usize> {
    let bad64::Operand::MultiReg {
        regs,
        arrspec: Some(bad64::ArrSpec::SixteenBytes(None)),
    } = operand
    else {
        return None;
    };
    let reg = regs[0]?;
    if regs[1..].iter().any(Option::is_some) {
        return None;
    }
    let raw = reg as u32;
    let first = bad64::Reg::V0 as u32;
    let last = bad64::Reg::V31 as u32;
    (first..=last)
        .contains(&raw)
        .then_some((raw - first) as usize)
}

pub fn bad64_vector_index_and_width(reg: bad64::Reg) -> Option<(usize, usize)> {
    let raw = reg as u32;
    let classes = [
        (bad64::Reg::B0 as u32, bad64::Reg::B31 as u32, 1),
        (bad64::Reg::H0 as u32, bad64::Reg::H31 as u32, 2),
        (bad64::Reg::S0 as u32, bad64::Reg::S31 as u32, 4),
        (bad64::Reg::D0 as u32, bad64::Reg::D31 as u32, 8),
        (bad64::Reg::Q0 as u32, bad64::Reg::Q31 as u32, 16),
        (bad64::Reg::V0 as u32, bad64::Reg::V31 as u32, 16),
    ];
    classes.iter().find_map(|(first, last, width)| {
        (*first..=*last)
            .contains(&raw)
            .then(|| ((raw - *first) as usize, *width))
    })
}

pub fn emulate_linux4k_guarded_vector_register_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    vector_reg: bad64::Reg,
    memory_operand: bad64::Operand,
    fault_address: u64,
) -> Result<(), NativeMemoryError> {
    let (vector_index, width) = bad64_vector_index_and_width(vector_reg).ok_or_else(|| {
        NativeMemoryError::Unsupported(format!(
            "native linux4k guarded vector fault does not support register {vector_reg}"
        ))
    })?;
    let write = match instruction.op() {
        bad64::Op::LDR | bad64::Op::LDUR => false,
        bad64::Op::STR | bad64::Op::STUR => true,
        _ => {
            return Err(NativeMemoryError::Unsupported(format!(
                "native linux4k guarded vector fault does not support {instruction}"
            )));
        }
    };
    let (address, writeback) =
        decode_native_scalar_address(snapshot, memory_operand).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k guarded vector fault does not support addressing for {instruction}"
            ))
        })?;
    let access_end = address.checked_add(width as u64).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k guarded vector access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, width, write) {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    let slot = snapshot.v.get_mut(vector_index).ok_or_else(|| {
        NativeMemoryError::Unsupported(format!(
            "native linux4k guarded vector index {vector_index} is out of range"
        ))
    })?;
    if write {
        memory
            .write_bytes_raw(address, &slot[..width])
            .map_err(|error| {
                NativeMemoryError::Unsupported(format!(
                    "native linux4k guarded vector store failed at 0x{address:x}: {error}"
                ))
            })?;
    } else {
        let bytes = memory.read_bytes_raw(address, width).map_err(|error| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k guarded vector load failed at 0x{address:x}: {error}"
            ))
        })?;
        slot.fill(0);
        slot[..width].copy_from_slice(&bytes);
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded vector fault could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k guarded vector PC overflow".to_string())
    })?;
    Ok(())
}

pub fn emulate_linux4k_guarded_pair_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), NativeMemoryError> {
    let [
        bad64::Operand::Reg {
            reg: first_reg,
            arrspec: None,
        },
        bad64::Operand::Reg {
            reg: second_reg,
            arrspec: None,
        },
        memory_operand,
    ] = instruction.operands()
    else {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded pair fault does not support operands for {instruction}"
        )));
    };
    let write = matches!(instruction.op(), bad64::Op::STP | bad64::Op::STNP);
    if !matches!(
        instruction.op(),
        bad64::Op::LDP | bad64::Op::LDNP | bad64::Op::LDPSW | bad64::Op::STP | bad64::Op::STNP
    ) {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded pair fault does not support {instruction}"
        )));
    }
    let vector_regs =
        bad64_vector_index_and_width(*first_reg).zip(bad64_vector_index_and_width(*second_reg));
    let gpr_regs = bad64_transfer_width(*first_reg).zip(bad64_transfer_width(*second_reg));
    let element_width = if let Some(((first_index, first_width), (second_index, second_width))) =
        vector_regs
    {
        if first_width != second_width || instruction.op() == bad64::Op::LDPSW {
            return Err(NativeMemoryError::Unsupported(format!(
                "native linux4k guarded pair has incompatible vector registers for {instruction}"
            )));
        }
        let _ = (first_index, second_index);
        first_width
    } else if let Some((first_width, second_width)) = gpr_regs {
        if first_width != second_width {
            return Err(NativeMemoryError::Unsupported(format!(
                "native linux4k guarded pair has incompatible GPR widths for {instruction}"
            )));
        }
        if instruction.op() == bad64::Op::LDPSW {
            if first_width != 8 {
                return Err(NativeMemoryError::Unsupported(format!(
                    "native linux4k guarded LDPSW requires X registers: {instruction}"
                )));
            }
            4
        } else {
            first_width
        }
    } else {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded pair requires matching GPR or vector registers: {instruction}"
        )));
    };
    let (address, writeback) =
        decode_native_scalar_address(snapshot, *memory_operand).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k guarded pair fault does not support addressing for {instruction}"
            ))
        })?;
    let total_width = element_width * 2;
    let access_end = address.checked_add(total_width as u64).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k guarded pair access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, total_width, write) {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    if let Some((base, _)) = writeback {
        let base_index = bad64_gpr_index(base).map(|(index, _)| index);
        if base_index == bad64_gpr_index(*first_reg).map(|(index, _)| index)
            || base_index == bad64_gpr_index(*second_reg).map(|(index, _)| index)
        {
            return Err(NativeMemoryError::Unsupported(format!(
                "native linux4k guarded pair rejects overlapping writeback for {instruction}"
            )));
        }
    }

    if let Some(((first_index, _), (second_index, _))) = vector_regs {
        if write {
            let first = snapshot.v[first_index];
            let second = snapshot.v[second_index];
            memory
                .write_bytes_raw(address, &first[..element_width])
                .and_then(|()| {
                    memory.write_bytes_raw(
                        address.saturating_add(element_width as u64),
                        &second[..element_width],
                    )
                })
                .map_err(|error| {
                    NativeMemoryError::Unsupported(format!(
                        "native linux4k guarded vector pair store failed at 0x{address:x}: {error}"
                    ))
                })?;
        } else {
            let bytes = memory
                .read_bytes_raw(address, total_width)
                .map_err(|error| {
                    NativeMemoryError::Unsupported(format!(
                        "native linux4k guarded vector pair load failed at 0x{address:x}: {error}"
                    ))
                })?;
            snapshot.v[first_index].fill(0);
            snapshot.v[first_index][..element_width].copy_from_slice(&bytes[..element_width]);
            snapshot.v[second_index].fill(0);
            snapshot.v[second_index][..element_width].copy_from_slice(&bytes[element_width..]);
        }
    } else if write {
        let first = native_snapshot_read_reg(snapshot, *first_reg).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k guarded pair could not read {first_reg}"
            ))
        })?;
        let second = native_snapshot_read_reg(snapshot, *second_reg).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k guarded pair could not read {second_reg}"
            ))
        })?;
        memory
            .write_bytes_raw(address, &first.to_le_bytes()[..element_width])
            .and_then(|()| {
                memory.write_bytes_raw(
                    address.saturating_add(element_width as u64),
                    &second.to_le_bytes()[..element_width],
                )
            })
            .map_err(|error| {
                NativeMemoryError::Unsupported(format!(
                    "native linux4k guarded GPR pair store failed at 0x{address:x}: {error}"
                ))
            })?;
    } else {
        let bytes = memory
            .read_bytes_raw(address, total_width)
            .map_err(|error| {
                NativeMemoryError::Unsupported(format!(
                    "native linux4k guarded GPR pair load failed at 0x{address:x}: {error}"
                ))
            })?;
        let sign_extend = instruction.op() == bad64::Op::LDPSW;
        let first = native_load_value(&bytes[..element_width], sign_extend, 8);
        let second = native_load_value(&bytes[element_width..], sign_extend, 8);
        if !native_snapshot_write_reg(snapshot, *first_reg, first)
            || !native_snapshot_write_reg(snapshot, *second_reg, second)
        {
            return Err(NativeMemoryError::Unsupported(format!(
                "native linux4k guarded pair could not update registers for {instruction}"
            )));
        }
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded pair could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k guarded pair PC overflow".to_string())
    })?;
    Ok(())
}

pub fn emulate_linux4k_guarded_vector_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), NativeMemoryError> {
    let [vector_operand, memory_operand] = instruction.operands() else {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded vector fault does not support operands for {instruction}"
        )));
    };
    let vector_index = bad64_single_vector_index(*vector_operand).ok_or_else(|| {
        NativeMemoryError::Unsupported(format!(
            "native linux4k guarded vector fault supports one .16b register, got {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, *memory_operand).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k guarded vector fault does not support addressing for {instruction}"
            ))
        })?;
    let access_end = address.checked_add(16).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k guarded vector access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    let write = instruction.op() == bad64::Op::ST1;
    if !memory.linux4k_range_allows(address, 16, write) {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    match instruction.op() {
        bad64::Op::LD1 => {
            let bytes = memory.read_bytes_raw(address, 16).map_err(|error| {
                NativeMemoryError::Unsupported(format!(
                    "native linux4k guarded vector load failed at 0x{address:x}: {error}"
                ))
            })?;
            let Some(slot) = snapshot.v.get_mut(vector_index) else {
                return Err(NativeMemoryError::Unsupported(format!(
                    "native linux4k guarded vector index {vector_index} is out of range"
                )));
            };
            slot.copy_from_slice(&bytes);
        }
        bad64::Op::ST1 => {
            let value = snapshot.v.get(vector_index).ok_or_else(|| {
                NativeMemoryError::Unsupported(format!(
                    "native linux4k guarded vector index {vector_index} is out of range"
                ))
            })?;
            memory.write_bytes_raw(address, value).map_err(|error| {
                NativeMemoryError::Unsupported(format!(
                    "native linux4k guarded vector store failed at 0x{address:x}: {error}"
                ))
            })?;
        }
        _ => {
            return Err(NativeMemoryError::Unsupported(format!(
                "native linux4k guarded vector fault does not support {instruction}"
            )));
        }
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded vector fault could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k guarded vector PC overflow".to_string())
    })?;
    Ok(())
}

pub fn atomic_add_access_width(op: bad64::Op, result_reg: bad64::Reg) -> Option<usize> {
    match op {
        bad64::Op::LDADDB | bad64::Op::LDADDAB | bad64::Op::LDADDALB | bad64::Op::LDADDLB => {
            Some(1)
        }
        bad64::Op::LDADDH | bad64::Op::LDADDAH | bad64::Op::LDADDALH | bad64::Op::LDADDLH => {
            Some(2)
        }
        bad64::Op::LDADD | bad64::Op::LDADDA | bad64::Op::LDADDAL | bad64::Op::LDADDL => {
            bad64_transfer_width(result_reg)
        }
        _ => None,
    }
}

pub fn atomic_add_ordering(
    op: bad64::Op,
    result_reg: bad64::Reg,
) -> Option<std::sync::atomic::Ordering> {
    let acquire = matches!(
        op,
        bad64::Op::LDADDA
            | bad64::Op::LDADDAB
            | bad64::Op::LDADDAH
            | bad64::Op::LDADDAL
            | bad64::Op::LDADDALB
            | bad64::Op::LDADDALH
    ) && !matches!(result_reg, bad64::Reg::WZR | bad64::Reg::XZR);
    let release = matches!(
        op,
        bad64::Op::LDADDL
            | bad64::Op::LDADDLB
            | bad64::Op::LDADDLH
            | bad64::Op::LDADDAL
            | bad64::Op::LDADDALB
            | bad64::Op::LDADDALH
    );
    atomic_add_access_width(op, result_reg)?;
    Some(match (acquire, release) {
        (false, false) => std::sync::atomic::Ordering::Relaxed,
        (true, false) => std::sync::atomic::Ordering::Acquire,
        (false, true) => std::sync::atomic::Ordering::Release,
        (true, true) => std::sync::atomic::Ordering::AcqRel,
    })
}

pub fn emulate_linux4k_guarded_atomic_add(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), NativeMemoryError> {
    let [
        bad64::Operand::Reg {
            reg: addend_reg,
            arrspec: None,
        },
        bad64::Operand::Reg {
            reg: result_reg,
            arrspec: None,
        },
        memory_operand,
    ] = instruction.operands()
    else {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k atomic add does not support operands for {instruction}"
        )));
    };
    let width = atomic_add_access_width(instruction.op(), *result_reg).ok_or_else(|| {
        NativeMemoryError::Unsupported(format!(
            "native linux4k atomic add does not support width for {instruction}"
        ))
    })?;
    if bad64_transfer_width(*addend_reg).is_none() || bad64_transfer_width(*result_reg).is_none() {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k atomic add requires GPR operands for {instruction}"
        )));
    }
    let ordering = atomic_add_ordering(instruction.op(), *result_reg).ok_or_else(|| {
        NativeMemoryError::Unsupported(format!(
            "native linux4k atomic add does not support ordering for {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, *memory_operand).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k atomic add does not support addressing for {instruction}"
            ))
        })?;
    if writeback.is_some() {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k atomic add rejects writeback for {instruction}"
        )));
    }
    let access_end = address.checked_add(width as u64).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k atomic add access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, width, false)
        || !memory.linux4k_range_allows(address, width, true)
    {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    let addend = native_snapshot_read_reg(snapshot, *addend_reg).ok_or_else(|| {
        NativeMemoryError::Unsupported(format!(
            "native linux4k atomic add could not read {addend_reg}"
        ))
    })?;
    let old = memory
        .atomic_fetch_add(address, width, addend, ordering)
        .map_err(|error| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k atomic add failed at 0x{address:x}: {error}"
            ))
        })?;
    if !native_snapshot_write_reg(snapshot, *result_reg, old) {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k atomic add could not write {result_reg}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k atomic add PC overflow".to_string())
    })?;
    Ok(())
}

pub fn ordered_atomic_access_width(op: bad64::Op, transfer_reg: bad64::Reg) -> Option<usize> {
    match op {
        bad64::Op::LDARB | bad64::Op::LDAPRB | bad64::Op::STLRB | bad64::Op::STLLRB => Some(1),
        bad64::Op::LDARH | bad64::Op::LDAPRH | bad64::Op::STLRH | bad64::Op::STLLRH => Some(2),
        bad64::Op::LDAR | bad64::Op::LDAPR | bad64::Op::STLR | bad64::Op::STLLR => {
            bad64_transfer_width(transfer_reg)
        }
        _ => None,
    }
}

pub fn emulate_linux4k_guarded_ordered_atomic_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), NativeMemoryError> {
    let [
        bad64::Operand::Reg {
            reg: transfer_reg,
            arrspec: None,
        },
        memory_operand,
    ] = instruction.operands()
    else {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k ordered atomic access does not support operands for {instruction}"
        )));
    };
    let load = matches!(
        instruction.op(),
        bad64::Op::LDAR
            | bad64::Op::LDARB
            | bad64::Op::LDARH
            | bad64::Op::LDAPR
            | bad64::Op::LDAPRB
            | bad64::Op::LDAPRH
    );
    let width = ordered_atomic_access_width(instruction.op(), *transfer_reg).ok_or_else(|| {
        NativeMemoryError::Unsupported(format!(
            "native linux4k ordered atomic access does not support width for {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, *memory_operand).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k ordered atomic access does not support addressing for {instruction}"
            ))
        })?;
    if writeback.is_some() {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k ordered atomic access rejects writeback for {instruction}"
        )));
    }
    let access_end = address.checked_add(width as u64).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k ordered atomic access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, width, !load) {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    if load {
        let value = memory.atomic_load(address, width).map_err(|error| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k ordered atomic load failed at 0x{address:x}: {error}"
            ))
        })?;
        if !native_snapshot_write_reg(snapshot, *transfer_reg, value) {
            return Err(NativeMemoryError::Unsupported(format!(
                "native linux4k ordered atomic load could not write {transfer_reg}"
            )));
        }
    } else {
        let value = native_snapshot_read_reg(snapshot, *transfer_reg).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k ordered atomic store could not read {transfer_reg}"
            ))
        })?;
        memory
            .atomic_store(address, width, value)
            .map_err(|error| {
                NativeMemoryError::Unsupported(format!(
                    "native linux4k ordered atomic store failed at 0x{address:x}: {error}"
                ))
            })?;
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k ordered atomic PC overflow".to_string())
    })?;
    Ok(())
}

pub fn exclusive_access_width(op: bad64::Op, transfer_reg: bad64::Reg) -> Option<usize> {
    match op {
        bad64::Op::LDAXRB | bad64::Op::LDXRB | bad64::Op::STLXRB | bad64::Op::STXRB => Some(1),
        bad64::Op::LDAXRH | bad64::Op::LDXRH | bad64::Op::STLXRH | bad64::Op::STXRH => Some(2),
        bad64::Op::LDAXR | bad64::Op::LDXR | bad64::Op::STLXR | bad64::Op::STXR => {
            bad64_transfer_width(transfer_reg)
        }
        _ => None,
    }
}

/// `&NativeMappedMemory`: the DSR hot path (`LDAXR`/`STLXR` and friends fire
/// on essentially every guest lock/atomic). Everything this touches --
/// `native_range_allows` and `exclusive_load_for`/`exclusive_store_for` --
/// is `&self`-safe; the reservation itself lives in the caller's
/// `NativeThreadRuntime.exclusive_reservation`, not in `NativeMappedMemory`.
pub fn emulate_dsr_exclusive_access(
    memory: &NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    reservation: &mut Option<NativeExclusiveReservation>,
    word: u32,
    guest_pc: u64,
) -> Result<(), NativeMemoryError> {
    let instruction = bad64::decode(word, guest_pc).map_err(|error| {
        NativeMemoryError::Unsupported(format!(
            "native DSR could not decode exclusive word 0x{word:08x} at 0x{guest_pc:x}: {error:?}"
        ))
    })?;
    let load = matches!(
        instruction.op(),
        bad64::Op::LDAXR
            | bad64::Op::LDAXRB
            | bad64::Op::LDAXRH
            | bad64::Op::LDXR
            | bad64::Op::LDXRB
            | bad64::Op::LDXRH
    );
    let acquire = matches!(
        instruction.op(),
        bad64::Op::LDAXR | bad64::Op::LDAXRB | bad64::Op::LDAXRH
    );
    let release = matches!(
        instruction.op(),
        bad64::Op::STLXR | bad64::Op::STLXRB | bad64::Op::STLXRH
    );
    let (status_reg, transfer_reg, memory_operand) = if load {
        let [
            bad64::Operand::Reg {
                reg: transfer_reg,
                arrspec: None,
            },
            memory_operand,
        ] = instruction.operands()
        else {
            return Err(NativeMemoryError::Unsupported(format!(
                "native DSR exclusive load does not support operands for {instruction}"
            )));
        };
        (None, *transfer_reg, *memory_operand)
    } else {
        let [
            bad64::Operand::Reg {
                reg: status_reg,
                arrspec: None,
            },
            bad64::Operand::Reg {
                reg: transfer_reg,
                arrspec: None,
            },
            memory_operand,
        ] = instruction.operands()
        else {
            return Err(NativeMemoryError::Unsupported(format!(
                "native DSR exclusive store does not support operands for {instruction}"
            )));
        };
        (Some(*status_reg), *transfer_reg, *memory_operand)
    };
    let width = exclusive_access_width(instruction.op(), transfer_reg).ok_or_else(|| {
        NativeMemoryError::Unsupported(format!(
            "native DSR exclusive access does not support width for {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, memory_operand).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native DSR exclusive access does not support addressing for {instruction}"
            ))
        })?;
    if writeback.is_some() {
        return Err(NativeMemoryError::Unsupported(format!(
            "native DSR exclusive access rejects writeback for {instruction}"
        )));
    }
    if !memory.native_range_allows(address, width, !load) {
        return Err(NativeMemoryError::Unsupported(format!(
            "native DSR exclusive {instruction} violates guest permissions at 0x{address:x}"
        )));
    }

    if load {
        let value = memory
            .exclusive_load_for(address, width, acquire, reservation)
            .map_err(|error| {
                NativeMemoryError::Unsupported(format!(
                    "native DSR exclusive load failed at 0x{address:x}: {error}"
                ))
            })?;
        if !native_snapshot_write_reg(snapshot, transfer_reg, value) {
            return Err(NativeMemoryError::Unsupported(format!(
                "native DSR exclusive load could not write {transfer_reg}"
            )));
        }
    } else {
        let value = native_snapshot_read_reg(snapshot, transfer_reg).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native DSR exclusive store could not read {transfer_reg}"
            ))
        })?;
        let stored = memory
            .exclusive_store_for(address, width, value, release, reservation)
            .map_err(|error| {
                NativeMemoryError::Unsupported(format!(
                    "native DSR exclusive store failed at 0x{address:x}: {error}"
                ))
            })?;
        let status_reg = status_reg.ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native DSR exclusive store lacks status register for {instruction}"
            ))
        })?;
        if !native_snapshot_write_reg(snapshot, status_reg, u64::from(!stored)) {
            return Err(NativeMemoryError::Unsupported(format!(
                "native DSR exclusive store could not write {status_reg}"
            )));
        }
    }
    Ok(())
}

pub fn emulate_linux4k_guarded_exclusive_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    reservation: &mut Option<NativeExclusiveReservation>,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), NativeMemoryError> {
    let load = matches!(
        instruction.op(),
        bad64::Op::LDAXR
            | bad64::Op::LDAXRB
            | bad64::Op::LDAXRH
            | bad64::Op::LDXR
            | bad64::Op::LDXRB
            | bad64::Op::LDXRH
    );
    let acquire = matches!(
        instruction.op(),
        bad64::Op::LDAXR | bad64::Op::LDAXRB | bad64::Op::LDAXRH
    );
    let release = matches!(
        instruction.op(),
        bad64::Op::STLXR | bad64::Op::STLXRB | bad64::Op::STLXRH
    );

    let (status_reg, transfer_reg, memory_operand) = if load {
        let [
            bad64::Operand::Reg {
                reg: transfer_reg,
                arrspec: None,
            },
            memory_operand,
        ] = instruction.operands()
        else {
            return Err(NativeMemoryError::Unsupported(format!(
                "native linux4k exclusive load does not support operands for {instruction}"
            )));
        };
        (None, *transfer_reg, *memory_operand)
    } else {
        let [
            bad64::Operand::Reg {
                reg: status_reg,
                arrspec: None,
            },
            bad64::Operand::Reg {
                reg: transfer_reg,
                arrspec: None,
            },
            memory_operand,
        ] = instruction.operands()
        else {
            return Err(NativeMemoryError::Unsupported(format!(
                "native linux4k exclusive store does not support operands for {instruction}"
            )));
        };
        (Some(*status_reg), *transfer_reg, *memory_operand)
    };
    let width = exclusive_access_width(instruction.op(), transfer_reg).ok_or_else(|| {
        NativeMemoryError::Unsupported(format!(
            "native linux4k exclusive access does not support width for {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, memory_operand).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k exclusive access does not support addressing for {instruction}"
            ))
        })?;
    if writeback.is_some() {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k exclusive access rejects writeback for {instruction}"
        )));
    }
    let access_end = address.checked_add(width as u64).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k exclusive access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, width, !load) {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }

    if load {
        let value = memory
            .exclusive_load(address, width, acquire, reservation)
            .map_err(|error| {
                NativeMemoryError::Unsupported(format!(
                    "native linux4k exclusive load failed at 0x{address:x}: {error}"
                ))
            })?;
        if !native_snapshot_write_reg(snapshot, transfer_reg, value) {
            return Err(NativeMemoryError::Unsupported(format!(
                "native linux4k exclusive load could not write {transfer_reg}"
            )));
        }
    } else {
        let value = native_snapshot_read_reg(snapshot, transfer_reg).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k exclusive store could not read {transfer_reg}"
            ))
        })?;
        let stored = memory
            .exclusive_store(address, width, value, release, reservation)
            .map_err(|error| {
                NativeMemoryError::Unsupported(format!(
                    "native linux4k exclusive store failed at 0x{address:x}: {error}"
                ))
            })?;
        let status_reg = status_reg.ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k exclusive store lacks status register for {instruction}"
            ))
        })?;
        if !native_snapshot_write_reg(snapshot, status_reg, u64::from(!stored)) {
            return Err(NativeMemoryError::Unsupported(format!(
                "native linux4k exclusive store could not write {status_reg}"
            )));
        }
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k exclusive PC overflow".to_string())
    })?;
    Ok(())
}

pub fn emulate_linux4k_guarded_fault(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    reservation: &mut Option<NativeExclusiveReservation>,
) -> Result<(), NativeMemoryError> {
    let fault_address = if snapshot.fault_address != 0 {
        snapshot.fault_address
    } else {
        snapshot.far
    };
    if !memory.linux4k_address_is_guarded(fault_address) {
        return Err(NativeMemoryError::Unsupported(format!(
            "native Darwin signal {} at 0x{fault_address:x} was not a guarded linux4k page (pc=0x{:x} sp=0x{:x} lr=0x{:x} x16=0x{:x} x17=0x{:x} x18=0x{:x} esr=0x{:x})",
            snapshot.signal,
            snapshot.pc,
            snapshot.sp,
            snapshot.x[30],
            snapshot.x[16],
            snapshot.x[17],
            snapshot.x[18],
            snapshot.esr
        )));
    }
    let word = memory.read_u32(snapshot.pc)?;
    let instruction = bad64::decode(word, snapshot.pc).map_err(|error| {
        NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault could not decode instruction 0x{word:08x} at 0x{:x}: {error}",
            snapshot.pc
        ))
    })?;
    if std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some() {
        child_write_stderr(
            format!(
                "native trace pid={} guarded pc=0x{:x} addr=0x{fault_address:x} esr=0x{:x} word=0x{word:08x} instruction={instruction}\n",
                unsafe { libc::getpid() },
                snapshot.pc,
                snapshot.esr
            )
            .as_bytes(),
        );
    }
    if matches!(
        instruction.op(),
        bad64::Op::LDADD
            | bad64::Op::LDADDA
            | bad64::Op::LDADDAB
            | bad64::Op::LDADDAH
            | bad64::Op::LDADDAL
            | bad64::Op::LDADDALB
            | bad64::Op::LDADDALH
            | bad64::Op::LDADDB
            | bad64::Op::LDADDH
            | bad64::Op::LDADDL
            | bad64::Op::LDADDLB
            | bad64::Op::LDADDLH
    ) {
        return emulate_linux4k_guarded_atomic_add(memory, snapshot, &instruction, fault_address);
    }
    if matches!(
        instruction.op(),
        bad64::Op::LDAR
            | bad64::Op::LDARB
            | bad64::Op::LDARH
            | bad64::Op::LDAPR
            | bad64::Op::LDAPRB
            | bad64::Op::LDAPRH
            | bad64::Op::STLR
            | bad64::Op::STLRB
            | bad64::Op::STLRH
            | bad64::Op::STLLR
            | bad64::Op::STLLRB
            | bad64::Op::STLLRH
    ) {
        return emulate_linux4k_guarded_ordered_atomic_access(
            memory,
            snapshot,
            &instruction,
            fault_address,
        );
    }
    if matches!(
        instruction.op(),
        bad64::Op::LDAXR
            | bad64::Op::LDAXRB
            | bad64::Op::LDAXRH
            | bad64::Op::LDXR
            | bad64::Op::LDXRB
            | bad64::Op::LDXRH
            | bad64::Op::STLXR
            | bad64::Op::STLXRB
            | bad64::Op::STLXRH
            | bad64::Op::STXR
            | bad64::Op::STXRB
            | bad64::Op::STXRH
    ) {
        return emulate_linux4k_guarded_exclusive_access(
            memory,
            snapshot,
            reservation,
            &instruction,
            fault_address,
        );
    }
    if matches!(instruction.op(), bad64::Op::LD1 | bad64::Op::ST1) {
        return emulate_linux4k_guarded_vector_access(
            memory,
            snapshot,
            &instruction,
            fault_address,
        );
    }
    if matches!(
        instruction.op(),
        bad64::Op::LDP | bad64::Op::LDNP | bad64::Op::LDPSW | bad64::Op::STP | bad64::Op::STNP
    ) {
        return emulate_linux4k_guarded_pair_access(memory, snapshot, &instruction, fault_address);
    }
    if let [
        bad64::Operand::Reg {
            reg: vector_reg,
            arrspec: None,
        },
        memory_operand,
    ] = instruction.operands()
        && bad64_vector_index_and_width(*vector_reg).is_some()
    {
        return emulate_linux4k_guarded_vector_register_access(
            memory,
            snapshot,
            &instruction,
            *vector_reg,
            *memory_operand,
            fault_address,
        );
    }
    let [transfer_operand, memory_operand] = instruction.operands() else {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault does not support operands for {instruction} at 0x{:x}",
            snapshot.pc
        )));
    };
    let bad64::Operand::Reg {
        reg: transfer_reg,
        arrspec: None,
    } = *transfer_operand
    else {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault requires a scalar GPR transfer for {instruction} at 0x{:x}",
            snapshot.pc
        )));
    };
    let transfer_width = bad64_transfer_width(transfer_reg).ok_or_else(|| {
        NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault does not support transfer register {transfer_reg} for {instruction}"
        ))
    })?;
    let access =
        decode_native_scalar_access(instruction.op(), transfer_width).ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k guarded fault does not support instruction {instruction} at 0x{:x}",
                snapshot.pc
            ))
        })?;
    let (address, writeback) = decode_native_scalar_address(snapshot, *memory_operand)
        .ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native linux4k guarded fault does not support addressing for {instruction} at 0x{:x}",
                snapshot.pc
            ))
        })?;
    let access_end = address.checked_add(access.width as u64).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k guarded access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    let write = matches!(access.kind, NativeScalarAccessKind::Store);
    if !memory.linux4k_range_allows(address, access.width, write) {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    if let Some((base, _)) = writeback
        && bad64_gpr_index(base).map(|(index, _)| index)
            == bad64_gpr_index(transfer_reg).map(|(index, _)| index)
    {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault rejects overlapping writeback for {instruction}"
        )));
    }

    match access.kind {
        NativeScalarAccessKind::Load { sign_extend } => {
            let bytes = memory
                .read_bytes_raw(address, access.width)
                .map_err(|error| {
                    NativeMemoryError::Unsupported(format!(
                        "native linux4k guarded load failed at 0x{address:x}: {error}"
                    ))
                })?;
            let value = native_load_value(&bytes, sign_extend, access.destination_width);
            if !native_snapshot_write_reg(snapshot, transfer_reg, value) {
                return Err(NativeMemoryError::Unsupported(format!(
                    "native linux4k guarded fault could not write {transfer_reg}"
                )));
            }
        }
        NativeScalarAccessKind::Store => {
            let value = native_snapshot_read_reg(snapshot, transfer_reg).ok_or_else(|| {
                NativeMemoryError::Unsupported(format!(
                    "native linux4k guarded fault could not read {transfer_reg}"
                ))
            })?;
            memory
                .write_bytes_raw(address, &value.to_le_bytes()[..access.width])
                .map_err(|error| {
                    NativeMemoryError::Unsupported(format!(
                        "native linux4k guarded store failed at 0x{address:x}: {error}"
                    ))
                })?;
        }
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(NativeMemoryError::Unsupported(format!(
            "native linux4k guarded fault could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        NativeMemoryError::Unsupported("native linux4k guarded PC overflow".to_string())
    })?;
    Ok(())
}

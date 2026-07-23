use carrick_guest_mem::GuestVa;

use crate::fxstate::*;
use crate::gateway::{X86UcontextSnapshot, reg};
use crate::{X86FxStateKind, X86GuestGsBase, X86XstateMemoryReader, X86XstateMemoryWriter};

const BASE: u64 = 0x20_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryError {
    Bounds,
    Injected,
}

struct Memory {
    bytes: Vec<u8>,
    reads: Vec<(u64, usize)>,
    writes: Vec<(u64, usize)>,
    fail_read: Option<usize>,
    fail_write: Option<usize>,
}

impl Memory {
    fn new(fill: u8) -> Self {
        Self {
            bytes: vec![fill; 4096],
            reads: Vec::new(),
            writes: Vec::new(),
            fail_read: None,
            fail_write: None,
        }
    }

    fn offset(address: GuestVa, len: usize) -> Result<std::ops::Range<usize>, MemoryError> {
        let start = usize::try_from(address.raw().checked_sub(BASE).ok_or(MemoryError::Bounds)?)
            .map_err(|_| MemoryError::Bounds)?;
        Ok(start..start.checked_add(len).ok_or(MemoryError::Bounds)?)
    }
}

impl X86XstateMemoryReader for Memory {
    type Error = MemoryError;

    fn read_exact(&mut self, address: GuestVa, destination: &mut [u8]) -> Result<(), Self::Error> {
        let call = self.reads.len();
        self.reads.push((address.raw(), destination.len()));
        if self.fail_read == Some(call) {
            return Err(MemoryError::Injected);
        }
        destination.copy_from_slice(
            self.bytes
                .get(Self::offset(address, destination.len())?)
                .ok_or(MemoryError::Bounds)?,
        );
        Ok(())
    }
}

impl X86XstateMemoryWriter for Memory {
    type Error = MemoryError;

    fn write_exact(&mut self, address: GuestVa, source: &[u8]) -> Result<(), Self::Error> {
        let call = self.writes.len();
        self.writes.push((address.raw(), source.len()));
        if self.fail_write == Some(call) {
            return Err(MemoryError::Injected);
        }
        self.bytes
            .get_mut(Self::offset(address, source.len())?)
            .ok_or(MemoryError::Bounds)?
            .copy_from_slice(source);
        Ok(())
    }
}

fn plan(kind: X86FxStateKind, bytes: &[u8], snapshot: &mut X86UcontextSnapshot) -> X86FxStatePlan {
    snapshot.rip = 0x40_0000;
    snapshot.gpr[reg::RAX] = BASE;
    X86FxStatePlan::decode_for_kind(kind, bytes, snapshot, 0, X86GuestGsBase::Zero)
        .expect("decode FXSAVE-family plan")
}

#[test]
fn all_four_forms_decode_and_require_sixteen_byte_alignment() {
    for (kind, bytes) in [
        (X86FxStateKind::Fxsave, &[0x0f, 0xae, 0x00][..]),
        (X86FxStateKind::Fxsave64, &[0x48, 0x0f, 0xae, 0x00][..]),
        (X86FxStateKind::Fxrstor, &[0x0f, 0xae, 0x08][..]),
        (X86FxStateKind::Fxrstor64, &[0x48, 0x0f, 0xae, 0x08][..]),
    ] {
        let mut snapshot = X86UcontextSnapshot::new();
        let decoded = plan(kind, bytes, &mut snapshot);
        assert_eq!(decoded.kind(), kind);
        assert_eq!(decoded.instruction_len() as usize, bytes.len());
        snapshot.gpr[reg::RAX] = BASE + 8;
        assert_eq!(
            X86FxStatePlan::decode_for_kind(kind, bytes, &snapshot, 0, X86GuestGsBase::Zero),
            Err(X86FxStateError::GeneralProtection(
                X86FxStateGpReason::MisalignedAddress
            ))
        );
    }
}

#[test]
fn saves_distinguish_virtual_selectors_from_rex_pointers_and_preserve_reserved_bytes() {
    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.restore_x87_selectors(0x1357, 0x2468);
    snapshot.xsave[8..16].copy_from_slice(&0x1122_3344_89ab_cdefu64.to_le_bytes());
    snapshot.xsave[16..24].copy_from_slice(&0x8877_6655_7654_3210u64.to_le_bytes());
    snapshot.xsave[32..42].fill(0x5a);
    snapshot.xsave[160..416].fill(0x6b);
    let plain = plan(X86FxStateKind::Fxsave, &[0x0f, 0xae, 0x00], &mut snapshot);
    let mut memory = Memory::new(0xa5);
    snapshot
        .emulate_fxsave_with_writer(plain, 0x2ffff, &mut memory)
        .expect("FXSAVE");
    assert_eq!(&memory.bytes[8..12], &0x89ab_cdefu32.to_le_bytes());
    assert_eq!(&memory.bytes[12..14], &0x1357u16.to_le_bytes());
    assert_eq!(&memory.bytes[14..16], &[0xa5; 2]);
    assert_eq!(&memory.bytes[20..22], &0x2468u16.to_le_bytes());
    assert_eq!(&memory.bytes[22..24], &[0xa5; 2]);
    assert_eq!(&memory.bytes[28..32], &0x2ffffu32.to_le_bytes());
    for slot in 0..8usize {
        assert_eq!(&memory.bytes[42 + slot * 16..48 + slot * 16], &[0xa5; 6]);
    }
    assert_eq!(&memory.bytes[416..512], &[0xa5; 96]);

    let rex = plan(
        X86FxStateKind::Fxsave64,
        &[0x48, 0x0f, 0xae, 0x00],
        &mut snapshot,
    );
    memory.bytes.fill(0xa5);
    snapshot
        .emulate_fxsave_with_writer(rex, 0x2ffff, &mut memory)
        .expect("FXSAVE64");
    assert_eq!(&memory.bytes[8..24], &snapshot.xsave[8..24]);
}

#[test]
fn ordered_save_fault_retains_only_earlier_writes() {
    let mut snapshot = X86UcontextSnapshot::new();
    let plan = plan(
        X86FxStateKind::Fxsave64,
        &[0x48, 0x0f, 0xae, 0x00],
        &mut snapshot,
    );
    let mut memory = Memory::new(0xa5);
    memory.fail_write = Some(5);
    assert_eq!(
        snapshot.emulate_fxsave_with_writer(plan, 0xffff, &mut memory),
        Err(X86FxStateError::Write(MemoryError::Injected))
    );
    assert_eq!(
        memory.writes,
        vec![
            (BASE, 5),
            (BASE + 6, 2),
            (BASE + 8, 16),
            (BASE + 24, 8),
            (BASE + 32, 10),
            (BASE + 48, 10),
        ]
    );
}

#[test]
fn restore_uses_defined_ranges_validates_mxcsr_and_commits_atomically() {
    let mut snapshot = X86UcontextSnapshot::new();
    snapshot.restore_x87_selectors(0xaaaa, 0xbbbb);
    snapshot.xsave[600..620].fill(0x77);
    let plan = plan(X86FxStateKind::Fxrstor, &[0x0f, 0xae, 0x08], &mut snapshot);
    let mut memory = Memory::new(0xa5);
    memory.bytes[0..2].copy_from_slice(&0xffffu16.to_le_bytes());
    memory.bytes[2..4].copy_from_slice(&0xf800u16.to_le_bytes());
    memory.bytes[4] = 0xc3;
    memory.bytes[6..8].copy_from_slice(&0xeeeeu16.to_le_bytes());
    memory.bytes[12..14].copy_from_slice(&0x1357u16.to_le_bytes());
    memory.bytes[20..22].copy_from_slice(&0x2468u16.to_le_bytes());
    memory.bytes[24..28].copy_from_slice(&0x8000_1f80u32.to_le_bytes());
    let before = snapshot.clone();
    assert_eq!(
        snapshot.emulate_fxrstor_with_reader(plan, 0x2ffff, &mut memory),
        Err(X86FxStateError::GeneralProtection(
            X86FxStateGpReason::InvalidMxcsr
        ))
    );
    assert_eq!(snapshot.xsave, before.xsave);
    assert_eq!(snapshot.x87_fcs(), before.x87_fcs());

    memory.bytes[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    memory.reads.clear();
    memory.fail_read = Some(7);
    assert_eq!(
        snapshot.emulate_fxrstor_with_reader(plan, 0x2ffff, &mut memory),
        Err(X86FxStateError::Read(MemoryError::Injected))
    );
    assert_eq!(snapshot.xsave, before.xsave);
    memory.fail_read = None;
    memory.reads.clear();
    snapshot
        .emulate_fxrstor_with_reader(plan, 0x2ffff, &mut memory)
        .expect("FXRSTOR");
    assert_eq!(
        u16::from_le_bytes(snapshot.xsave[0..2].try_into().unwrap_or([0; 2])),
        0x1f7f
    );
    assert_eq!(
        u16::from_le_bytes(snapshot.xsave[2..4].try_into().unwrap_or([0; 2])),
        0x7800
    );
    assert_eq!(
        u16::from_le_bytes(snapshot.xsave[6..8].try_into().unwrap_or([0; 2])),
        0x06ee
    );
    assert_eq!(snapshot.x87_fcs(), 0x1357);
    assert_eq!(snapshot.x87_fds(), 0x2468);
    assert_eq!(&snapshot.xsave[600..620], &[0x77; 20]);
    assert_eq!(memory.reads.last(), Some(&(BASE + 160, 256)));
    assert!(
        !memory
            .reads
            .iter()
            .any(|&(address, _)| address >= BASE + 416)
    );
}

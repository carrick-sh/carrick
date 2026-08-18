//! `bpf(2)` ABI: commands, map types, program types, element-update flags, the
//! `union bpf_attr` per-command field layouts, and the 8-byte eBPF instruction
//! encoding.
//!
//! Everything guest-visible about the bpf syscall lives here as a typed domain
//! rather than as loose integers in the dispatch layer:
//!
//! * [`BpfCmd`] — an ordinal enum over the commands carrick implements. A
//!   failed [`BpfCmd::from_raw`] means exactly what Linux answers for a
//!   command a kernel does not have: `EINVAL`.
//! * [`BpfMapType`] / [`BpfProgType`] — the map/program types carrick models.
//!   Types Linux defines but carrick does not implement fail `from_raw` and
//!   are answered `EINVAL`, the same shape a kernel built without that type
//!   gives.
//! * [`BpfUpdateFlags`] — the `BPF_ANY`/`BPF_NOEXIST`/`BPF_EXIST` element
//!   update selector. A named enum, not a bitmask: the three values are
//!   mutually exclusive on the wire.
//! * [`BpfMapCreateAttr`] / [`BpfElemAttr`] / [`BpfProgLoadAttr`] — the
//!   per-command views of `union bpf_attr`, parsed from the guest bytes at the
//!   documented offsets. The union is size-versioned (userspace passes
//!   `sizeof(union bpf_attr)` of *its* headers), so each view parses a prefix
//!   and zero-fills what the guest did not provide, exactly as the kernel
//!   reads a shorter-than-current attr.
//! * [`BpfInsn`] — one `struct bpf_insn` (8 bytes), with the class/register
//!   accessors a structural validator needs.
//!
//! Derived from the man pages (`bpf(2)`, `bpf-helpers(7)`) and differential
//! observation against the Docker oracle — never from kernel source.

/// `enum bpf_cmd` — the commands carrick implements, at their wire ordinals.
///
/// Linux answers a command value it does not know with `EINVAL`; carrick
/// answers every unlisted value — genuinely invalid or defined-but-unbuilt
/// (`BPF_OBJ_PIN`, `BPF_PROG_ATTACH`, …) — the same way, which is the shape of
/// an older kernel without that command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum BpfCmd {
    /// `BPF_MAP_CREATE`: create a map, return a new fd.
    MapCreate = 0,
    /// `BPF_MAP_LOOKUP_ELEM`: copy the value stored under `key` out.
    MapLookupElem = 1,
    /// `BPF_MAP_UPDATE_ELEM`: create or update the element under `key`.
    MapUpdateElem = 2,
    /// `BPF_MAP_DELETE_ELEM`: remove the element under `key`.
    MapDeleteElem = 3,
    /// `BPF_MAP_GET_NEXT_KEY`: iterate — write the key after `key`.
    MapGetNextKey = 4,
    /// `BPF_PROG_LOAD`: validate and load a program, return a new fd.
    ProgLoad = 5,
}

impl BpfCmd {
    /// Every implemented command, in wire order.
    pub const ALL: &'static [BpfCmd] = &[
        BpfCmd::MapCreate,
        BpfCmd::MapLookupElem,
        BpfCmd::MapUpdateElem,
        BpfCmd::MapDeleteElem,
        BpfCmd::MapGetNextKey,
        BpfCmd::ProgLoad,
    ];

    /// Classify a wire command number. `None` ⇒ `EINVAL`.
    pub fn from_raw(raw: u64) -> Option<Self> {
        Self::ALL.iter().copied().find(|cmd| *cmd as u64 == raw)
    }
}

/// `enum bpf_map_type` — the map types carrick implements, at their wire
/// ordinals (`BPF_MAP_TYPE_UNSPEC` = 0 is deliberately absent: creating an
/// UNSPEC map is `EINVAL` on Linux too).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum BpfMapType {
    /// `BPF_MAP_TYPE_HASH`: arbitrary fixed-size keys, populated on update.
    Hash = 1,
    /// `BPF_MAP_TYPE_ARRAY`: 4-byte index keys `0..max_entries`, all elements
    /// pre-allocated and zero-initialised at create.
    Array = 2,
}

impl BpfMapType {
    /// Classify a wire map type. `None` ⇒ `EINVAL` (the shape of a kernel
    /// built without that map type).
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(BpfMapType::Hash),
            2 => Some(BpfMapType::Array),
            _ => None,
        }
    }
}

/// `enum bpf_prog_type` — the program types carrick accepts for
/// [`BpfCmd::ProgLoad`]. Only `BPF_PROG_TYPE_SOCKET_FILTER` (the type every
/// LTP bpf suite loads); other types are `EINVAL`, the shape of a kernel
/// without them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum BpfProgType {
    /// `BPF_PROG_TYPE_SOCKET_FILTER`.
    SocketFilter = 1,
}

impl BpfProgType {
    /// Classify a wire program type. `None` ⇒ `EINVAL`.
    pub fn from_raw(raw: u32) -> Option<Self> {
        (raw == 1).then_some(BpfProgType::SocketFilter)
    }
}

/// `BPF_MAP_UPDATE_ELEM` flags: `BPF_ANY`/`BPF_NOEXIST`/`BPF_EXIST` are an
/// exclusive selector, not a bitmask (`bpf(2)`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum BpfUpdateFlags {
    /// `BPF_ANY` (0): create or update.
    Any = 0,
    /// `BPF_NOEXIST` (1): create only — `EEXIST` if the key is present.
    NoExist = 1,
    /// `BPF_EXIST` (2): update only — `ENOENT` if the key is absent.
    Exist = 2,
}

impl BpfUpdateFlags {
    /// Classify the wire flags word. `None` ⇒ `EINVAL` (unknown flag bits,
    /// including flags like `BPF_F_LOCK` that carrick does not implement).
    pub fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(BpfUpdateFlags::Any),
            1 => Some(BpfUpdateFlags::NoExist),
            2 => Some(BpfUpdateFlags::Exist),
            _ => None,
        }
    }
}

/// Read a little-endian `u32` at `off` from a guest-length-limited attr
/// prefix, zero when the guest's attr was too short to contain it — exactly
/// how the kernel treats a short attr from older userspace.
fn attr_u32(bytes: &[u8], off: usize) -> u32 {
    match bytes.get(off..off + 4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

/// Read a little-endian `u64` at `off` (see [`attr_u32`]).
fn attr_u64(bytes: &[u8], off: usize) -> u64 {
    match bytes.get(off..off + 8) {
        Some(b) => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        None => 0,
    }
}

/// The `BPF_MAP_CREATE` view of `union bpf_attr` (`bpf(2)`):
/// `map_type`@0, `key_size`@4, `value_size`@8, `max_entries`@12,
/// `map_flags`@16.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfMapCreateAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
}

impl BpfMapCreateAttr {
    /// Parse from the guest's attr bytes (already length-limited to the
    /// guest-passed `size`).
    pub fn parse(bytes: &[u8]) -> Self {
        Self {
            map_type: attr_u32(bytes, 0),
            key_size: attr_u32(bytes, 4),
            value_size: attr_u32(bytes, 8),
            max_entries: attr_u32(bytes, 12),
            map_flags: attr_u32(bytes, 16),
        }
    }
}

/// The element-command view of `union bpf_attr` (`bpf(2)`): `map_fd`@0
/// (then 4 bytes padding — `key` is `__aligned_u64`), `key`@8,
/// `value`/`next_key`@16, `flags`@24.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfElemAttr {
    pub map_fd: u32,
    /// Guest pointer to `key_size` bytes of key.
    pub key: u64,
    /// Guest pointer: the value buffer for lookup/update, the `next_key`
    /// output buffer for get-next-key.
    pub value_or_next_key: u64,
    pub flags: u64,
}

impl BpfElemAttr {
    /// Parse from the guest's attr bytes.
    pub fn parse(bytes: &[u8]) -> Self {
        Self {
            map_fd: attr_u32(bytes, 0),
            key: attr_u64(bytes, 8),
            value_or_next_key: attr_u64(bytes, 16),
            flags: attr_u64(bytes, 24),
        }
    }
}

/// The `BPF_PROG_LOAD` view of `union bpf_attr` (`bpf(2)`): `prog_type`@0,
/// `insn_cnt`@4, `insns`@8, `license`@16, `log_level`@24, `log_size`@28,
/// `log_buf`@32, `kern_version`@40.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfProgLoadAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    /// Guest pointer to `insn_cnt` × 8 bytes of `struct bpf_insn`.
    pub insns: u64,
    /// Guest pointer to the NUL-terminated license string.
    pub license: u64,
    pub log_level: u32,
    pub log_size: u32,
    /// Guest pointer to the verifier log buffer (`log_size` bytes).
    pub log_buf: u64,
    pub kern_version: u32,
}

impl BpfProgLoadAttr {
    /// Parse from the guest's attr bytes.
    pub fn parse(bytes: &[u8]) -> Self {
        Self {
            prog_type: attr_u32(bytes, 0),
            insn_cnt: attr_u32(bytes, 4),
            insns: attr_u64(bytes, 8),
            license: attr_u64(bytes, 16),
            log_level: attr_u32(bytes, 24),
            log_size: attr_u32(bytes, 28),
            log_buf: attr_u64(bytes, 32),
            kern_version: attr_u32(bytes, 40),
        }
    }
}

/// The classic instruction-count ceiling (`BPF_MAXINSNS`, `bpf(2)`): a
/// `BPF_PROG_LOAD` beyond it is `E2BIG`.
pub const LINUX_BPF_MAXINSNS: u32 = 4096;

/// The 8 bits of `bpf_insn.code` split as `class | mode/op` (`bpf(2)`); the
/// low 3 bits select the class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BpfInsnClass {
    /// `BPF_LD`: non-standard loads (immediate-64, classic absolute).
    Ld = 0x00,
    /// `BPF_LDX`: register loads from memory.
    Ldx = 0x01,
    /// `BPF_ST`: immediate stores to memory.
    St = 0x02,
    /// `BPF_STX`: register stores to memory.
    Stx = 0x03,
    /// `BPF_ALU`: 32-bit arithmetic.
    Alu = 0x04,
    /// `BPF_JMP`: 64-bit compares and control flow (incl. `call`/`exit`).
    Jmp = 0x05,
    /// `BPF_JMP32`: 32-bit compare jumps.
    Jmp32 = 0x06,
    /// `BPF_ALU64`: 64-bit arithmetic.
    Alu64 = 0x07,
}

impl BpfInsnClass {
    /// Decode the class bits of an opcode. Total over `0..=7`, so every
    /// opcode has a class; validity of the REST of the opcode is the
    /// validator's judgement.
    pub fn of_code(code: u8) -> Self {
        match code & 0x07 {
            0x00 => BpfInsnClass::Ld,
            0x01 => BpfInsnClass::Ldx,
            0x02 => BpfInsnClass::St,
            0x03 => BpfInsnClass::Stx,
            0x04 => BpfInsnClass::Alu,
            0x05 => BpfInsnClass::Jmp,
            0x06 => BpfInsnClass::Jmp32,
            _ => BpfInsnClass::Alu64,
        }
    }

    /// Does this class encode a jump offset in `off` (subject to the
    /// in-program target bounds check)?
    pub fn is_jump(self) -> bool {
        matches!(self, BpfInsnClass::Jmp | BpfInsnClass::Jmp32)
    }
}

/// One `struct bpf_insn` (`bpf(2)`): `code`@0, packed dst/src register
/// nibbles@1 (dst low, src high — little-endian bitfield order), `off`@2
/// (i16), `imm`@4 (i32). 8 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfInsn {
    pub code: u8,
    regs: u8,
    pub off: i16,
    pub imm: i32,
}

/// Size of one encoded `struct bpf_insn`.
pub const BPF_INSN_SIZE: usize = 8;

/// Highest eBPF register number (`R10`, the frame pointer).
pub const BPF_MAX_REG: u8 = 10;

/// `BPF_JMP | BPF_EXIT`.
const BPF_OPCODE_EXIT: u8 = 0x95;
/// `BPF_JMP | BPF_CALL` (helper call; never a jump offset).
const BPF_OPCODE_CALL: u8 = 0x85;
/// `BPF_LD | BPF_DW | BPF_IMM` — first half of the 16-byte immediate-64 load
/// (the `BPF_LD_MAP_FD` encoding); the next slot is its continuation.
const BPF_OPCODE_LD_IMM64: u8 = 0x18;

impl BpfInsn {
    /// Decode one instruction from its 8 wire bytes.
    pub fn parse(bytes: &[u8; BPF_INSN_SIZE]) -> Self {
        Self {
            code: bytes[0],
            regs: bytes[1],
            off: i16::from_le_bytes([bytes[2], bytes[3]]),
            imm: i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }

    /// Destination register number (low nibble).
    pub fn dst_reg(self) -> u8 {
        self.regs & 0x0f
    }

    /// Source register number (high nibble).
    pub fn src_reg(self) -> u8 {
        self.regs >> 4
    }

    /// The instruction class.
    pub fn class(self) -> BpfInsnClass {
        BpfInsnClass::of_code(self.code)
    }

    /// Is this `BPF_EXIT`?
    pub fn is_exit(self) -> bool {
        self.code == BPF_OPCODE_EXIT
    }

    /// Is this a helper `call` (its `off` is not a jump offset)?
    pub fn is_call(self) -> bool {
        self.code == BPF_OPCODE_CALL
    }

    /// Is this the first half of an immediate-64 load (the NEXT slot is its
    /// continuation pseudo-instruction)?
    pub fn is_ld_imm64(self) -> bool {
        self.code == BPF_OPCODE_LD_IMM64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_ordinals_match_the_wire() {
        assert_eq!(BpfCmd::from_raw(0), Some(BpfCmd::MapCreate));
        assert_eq!(BpfCmd::from_raw(5), Some(BpfCmd::ProgLoad));
        // BPF_OBJ_PIN (6) is real Linux but unimplemented here: EINVAL path.
        assert_eq!(BpfCmd::from_raw(6), None);
        assert_eq!(BpfCmd::from_raw(u64::MAX), None);
    }

    #[test]
    fn map_types_cover_hash_and_array_only() {
        assert_eq!(BpfMapType::from_raw(1), Some(BpfMapType::Hash));
        assert_eq!(BpfMapType::from_raw(2), Some(BpfMapType::Array));
        assert_eq!(BpfMapType::from_raw(0), None); // UNSPEC is EINVAL on Linux too
        assert_eq!(BpfMapType::from_raw(3), None); // PROG_ARRAY: unbuilt ⇒ EINVAL
    }

    #[test]
    fn elem_attr_offsets_match_bpf2() {
        // map_fd@0, key@8, value@16, flags@24 (key is __aligned_u64).
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&7u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x5555_6666_7777_8888u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&2u64.to_le_bytes());
        let attr = BpfElemAttr::parse(&bytes);
        assert_eq!(attr.map_fd, 7);
        assert_eq!(attr.key, 0x1111_2222_3333_4444);
        assert_eq!(attr.value_or_next_key, 0x5555_6666_7777_8888);
        assert_eq!(attr.flags, 2);
    }

    #[test]
    fn prog_load_attr_offsets_match_bpf2() {
        let mut bytes = [0u8; 48];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes()); // prog_type
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes()); // insn_cnt
        bytes[8..16].copy_from_slice(&0xAAAAu64.to_le_bytes()); // insns
        bytes[16..24].copy_from_slice(&0xBBBBu64.to_le_bytes()); // license
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes()); // log_level
        bytes[28..32].copy_from_slice(&8192u32.to_le_bytes()); // log_size
        bytes[32..40].copy_from_slice(&0xCCCCu64.to_le_bytes()); // log_buf
        bytes[40..44].copy_from_slice(&0xDDDDu32.to_le_bytes()); // kern_version
        let attr = BpfProgLoadAttr::parse(&bytes);
        assert_eq!(attr.prog_type, 1);
        assert_eq!(attr.insn_cnt, 2);
        assert_eq!(attr.insns, 0xAAAA);
        assert_eq!(attr.license, 0xBBBB);
        assert_eq!(attr.log_level, 1);
        assert_eq!(attr.log_size, 8192);
        assert_eq!(attr.log_buf, 0xCCCC);
        assert_eq!(attr.kern_version, 0xDDDD);
    }

    #[test]
    fn short_attr_prefix_zero_fills() {
        // Old-userspace attr shorter than the current union: absent fields
        // read as zero, like the kernel's short-attr handling.
        let bytes = 2u32.to_le_bytes(); // only map_type provided
        let attr = BpfMapCreateAttr::parse(&bytes);
        assert_eq!(attr.map_type, 2);
        assert_eq!(attr.key_size, 0);
        assert_eq!(attr.map_flags, 0);
    }

    #[test]
    fn insn_decodes_registers_and_exit() {
        // BPF_MOV64_IMM(BPF_REG_0, 0) = code 0xb7, dst 0, imm 0.
        let mov = BpfInsn::parse(&[0xb7, 0x00, 0, 0, 0, 0, 0, 0]);
        assert_eq!(mov.class(), BpfInsnClass::Alu64);
        assert_eq!(mov.dst_reg(), 0);
        assert!(!mov.is_exit());
        // BPF_EXIT_INSN() = 0x95.
        let exit = BpfInsn::parse(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        assert!(exit.is_exit());
        assert_eq!(exit.class(), BpfInsnClass::Jmp);
        // dst/src nibble split: regs byte 0x21 = dst 1, src 2.
        let ldx = BpfInsn::parse(&[0x79, 0x21, 0, 0, 0, 0, 0, 0]);
        assert_eq!(ldx.dst_reg(), 1);
        assert_eq!(ldx.src_reg(), 2);
        assert_eq!(ldx.class(), BpfInsnClass::Ldx);
        // BPF_LD_MAP_FD first half.
        let ld = BpfInsn::parse(&[0x18, 0x01, 0, 0, 7, 0, 0, 0]);
        assert!(ld.is_ld_imm64());
    }
}

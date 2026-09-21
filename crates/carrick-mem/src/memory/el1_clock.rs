//! Dormant mailbox clock transport. Runtime must not publish the gate until it
//! protects this mapping and normalizes asynchronous exits in the EL0 stub.
use super::*;

// Carrick-owned user ABI slot immediately above the vDSO. Static ELF images
// commonly occupy 0x30_0000_0000, so the old placement after the sigreturn
// trampoline collided with real probe text before the guest could start.
pub const STUB_BASE: u64 = crate::vdso::LINUX_VDSO_BASE + 0x1_0000;
pub const STUB_SIZE: u64 = 0x4000;
/// Reserved per-MM word. Zero-filled identity pages deliberately disable this.
/// TODO(runtime): publish only for unscaled/unfrozen hardware-counter clocks,
/// with no observer, seccomp, trap budget, or pending mandatory boundary.
pub const CLOCK_GATE_OFFSET: u64 = 16;
const ACTIVE: u16 = AARCH64_SYSCALL_MAILBOX_CLOCK_ACTIVE as u16;
const ENTRY: usize = 0xC00;
const TMP16: u64 = mailbox_offset(core::mem::offset_of!(Aarch64SyscallMailbox, clock_tmp_x16));
const TMP17: u64 = mailbox_offset(core::mem::offset_of!(Aarch64SyscallMailbox, clock_tmp_x17));
const MARKER: u16 = 0xC10C;
const _: () = assert!(TMP17 + 8 <= LINUX_SYSCALL_MAILBOX_SLOT_SIZE);
const _: () = assert!(STUB_BASE.is_multiple_of(0x4000));
const SAVED: [(u32, u64); 13] = [
    (0, AARCH64_SYSCALL_MAILBOX_OFF_ARGS),
    (1, AARCH64_SYSCALL_MAILBOX_OFF_ARGS + 8),
    (2, AARCH64_SYSCALL_MAILBOX_OFF_ARGS + 16),
    (3, AARCH64_SYSCALL_MAILBOX_OFF_ARGS + 24),
    (4, AARCH64_SYSCALL_MAILBOX_OFF_ARGS + 32),
    (5, AARCH64_SYSCALL_MAILBOX_OFF_ARGS + 40),
    (8, AARCH64_SYSCALL_MAILBOX_OFF_X8),
    (9, AARCH64_SYSCALL_MAILBOX_OFF_CLOCK_X9),
    (10, AARCH64_SYSCALL_MAILBOX_OFF_CLOCK_X10),
    (11, AARCH64_SYSCALL_MAILBOX_OFF_CLOCK_X11),
    (12, AARCH64_SYSCALL_MAILBOX_OFF_CLOCK_X12),
    (16, AARCH64_SYSCALL_MAILBOX_OFF_RESUME_X16),
    (17, AARCH64_SYSCALL_MAILBOX_OFF_RESUME_X17),
];
// EL0 stores retain ordinary stage-1/stage-2 permission and COW behavior.
const STUB: [u32; 12] = [
    0xD503_3FDF, // isb
    0xD53B_E042, // mrs x2, cntvct_el0
    0xD53B_E00A, // mrs x10, cntfrq_el0
    0x9ACA_0843, // udiv x3, x2, x10
    0x9B0A_8864, // msub x4, x3, x10, x2
    0xD299_400B, // movz x11, #0xca00
    0xF2A7_734B, // movk x11, #0x3b9a, lsl #16
    0x9B0B_7C84, // mul x4, x4, x11
    0x9ACA_0884, // udiv x4, x4, x10
    0xF900_0023, // str x3, [x1]
    0xF900_0424, // str x4, [x1, #8]
    0xD400_0001 | ((MARKER as u32) << 5),
];
const COMPLETION_PC: u64 = STUB_BASE + STUB.len() as u64 * 4;

pub(super) fn region() -> MemoryRegion {
    let mut bytes = vec![0; STUB_SIZE as usize];
    for (dst, op) in bytes.chunks_exact_mut(4).zip(STUB) {
        dst.copy_from_slice(&op.to_le_bytes());
    }
    MemoryRegion {
        start: STUB_BASE,
        end: STUB_BASE + STUB_SIZE,
        perms: SegmentPerms {
            read: true,
            write: false,
            execute: true,
        },
        shared: false,
        bytes: bytes.into(),
    }
}

struct Code<'a> {
    bytes: &'a mut [u8],
    pc: usize,
}
impl Code<'_> {
    fn emit(&mut self, op: u32) {
        self.bytes[self.pc..self.pc + 4].copy_from_slice(&op.to_le_bytes());
        self.pc += 4;
    }
    fn imm(&mut self, r: u32, v: u64) {
        self.emit(enc_movz_xn(r, v as u16, 0));
        for h in 1..4 {
            self.emit(enc_movk_xn(r, (v >> (h * 16)) as u16, h));
        }
    }
    fn branch(&mut self) -> usize {
        let p = self.pc;
        self.emit(0);
        p
    }
    fn patch(&mut self, p: usize, target: usize, cond: Option<bool>) {
        let op = match cond {
            Some(true) => enc_beq(p as u64, target as u64),
            Some(false) => enc_bne(p as u64, target as u64),
            None => enc_b(p as u64, target as u64),
        };
        self.bytes[p..p + 4].copy_from_slice(&op.to_le_bytes());
    }
    fn restore_frame(&mut self) {
        for (offset, msr) in [
            (AARCH64_SYSCALL_MAILBOX_OFF_RESUME_PC, 0xD518_4030),
            (AARCH64_SYSCALL_MAILBOX_OFF_SPSR, 0xD518_4010),
            (AARCH64_SYSCALL_MAILBOX_OFF_ESR, 0xD518_5210),
        ] {
            self.emit(enc_ldr_xt_sp(16, offset));
            self.emit(msr);
        }
        self.emit(enc_str_wt_sp(31, AARCH64_SYSCALL_MAILBOX_OFF_STATE));
    }
    fn restore_regs(&mut self, success: bool) {
        for (r, off) in SAVED {
            if r != 0 || !success {
                self.emit(enc_ldr_xt_sp(r, off));
            }
        }
        if success {
            self.emit(enc_movz_x0(0, 0));
        }
    }
}

pub(super) fn install(bytes: &mut [u8], dispatch: usize) -> ClockHandlerLayout {
    bytes[dispatch..dispatch + 4]
        .copy_from_slice(&enc_b(dispatch as u64, ENTRY as u64).to_le_bytes());
    let mut c = Code { bytes, pc: ENTRY };
    // Temporary spills must not overwrite the active transaction's originals.
    c.emit(enc_str_xt_sp(16, TMP16));
    c.emit(enc_str_xt_sp(17, TMP17));
    c.emit(enc_ldr_wt_sp(16, AARCH64_SYSCALL_MAILBOX_OFF_STATE));
    c.emit(enc_cmp_w16_imm(ACTIVE));
    let active = c.branch();
    c.emit(enc_cmp_w16_imm(0));
    let busy = c.branch();
    // Conservatively reject every nonzero flag, including the kick latch.
    c.emit(enc_ldr_wt_sp(16, AARCH64_SYSCALL_MAILBOX_OFF_FLAGS));
    c.emit(enc_cmp_w16_imm(0));
    let kicked = c.branch();
    c.emit(AARCH64_MRS_ESR_EL1_X16_OPCODE);
    c.emit(AARCH64_LSR_X16_X16_26_OPCODE);
    c.emit(AARCH64_CMP_X16_SVC64_OPCODE);
    let not_svc = c.branch();
    c.emit(enc_cmp_x8_imm(113));
    let wrong_nr = c.branch();
    c.emit(0xF100_041F); // cmp x0, #1 (CLOCK_MONOTONIC)
    let wrong_clock = c.branch();
    c.imm(17, LINUX_IDENTITY_PAGE_BASE);
    c.emit(enc_ldr_wt_xn(16, 17, IDENTITY_OFF_SHIM_ENABLED));
    c.emit(enc_cmp_w16_imm(1));
    let policy = c.branch();
    c.emit(enc_add_xd_xn_imm(17, 17, CLOCK_GATE_OFFSET as u16));
    c.emit(enc_ldar_wt_xn(16, 17));
    c.emit(enc_cmp_w16_imm(1));
    let domain = c.branch();
    c.emit(enc_ldr_xt_sp(16, TMP16));
    c.emit(enc_ldr_xt_sp(17, TMP17));
    for (r, off) in SAVED {
        c.emit(enc_str_xt_sp(r, off));
    }
    for (mrs, off) in [
        (
            AARCH64_MRS_ELR_EL1_X16_OPCODE,
            AARCH64_SYSCALL_MAILBOX_OFF_RESUME_PC,
        ),
        (
            AARCH64_MRS_SPSR_EL1_X16_OPCODE,
            AARCH64_SYSCALL_MAILBOX_OFF_SPSR,
        ),
        (
            AARCH64_MRS_ESR_EL1_X16_OPCODE,
            AARCH64_SYSCALL_MAILBOX_OFF_ESR,
        ),
    ] {
        c.emit(mrs);
        c.emit(enc_str_xt_sp(16, off));
    }
    c.emit(enc_movz_w16(ACTIVE));
    c.emit(enc_str_wt_sp(16, AARCH64_SYSCALL_MAILBOX_OFF_STATE));
    c.imm(16, STUB_BASE);
    c.emit(0xD518_4030); // msr elr_el1, x16
    c.emit(enc_ldr_xt_sp(16, AARCH64_SYSCALL_MAILBOX_OFF_RESUME_X16));
    c.emit(AARCH64_ERET_OPCODE);

    let ordinary = c.pc;
    c.emit(enc_ldr_xt_sp(16, TMP16));
    c.emit(enc_ldr_xt_sp(17, TMP17));
    c.emit(enc_b(c.pc as u64, MAILBOX_HANDLER_OFFSET as u64));
    for p in [busy, kicked, not_svc, wrong_nr, wrong_clock, policy, domain] {
        c.patch(p, ordinary, Some(false));
    }

    let completion = c.pc;
    c.patch(active, completion, Some(true));
    c.emit(AARCH64_MRS_ELR_EL1_X16_OPCODE);
    c.imm(17, COMPLETION_PC);
    c.emit(0xEB11_021F); // cmp x16, x17
    let wrong_pc = c.branch();
    c.emit(AARCH64_MRS_ESR_EL1_X16_OPCODE);
    c.imm(17, (0x15u64 << 26) | (1 << 25) | u64::from(MARKER));
    c.emit(0xEB11_021F);
    let wrong_esr = c.branch();
    c.emit(enc_ldr_wt_sp(16, AARCH64_SYSCALL_MAILBOX_OFF_FLAGS));
    c.emit(enc_cmp_w16_imm(0));
    let completion_kicked = c.branch();
    // Count successful fast completions with one LSE atomic add. Identity calls
    // predate concurrent HVPatch execution and still use ldr/add/str; clocks are
    // hot on multiple vCPUs, so sharing that sequence would lose increments.
    // This builder is selected only by the arm64 HVF lane, where FEAT_LSE is a
    // qualified host prerequisite. x16/x17 are restored below.
    c.imm(16, LINUX_IDENTITY_PAGE_BASE + IDENTITY_OFF_SHIM_SYSCALLS);
    c.emit(enc_movz_xn(17, 1, 0));
    c.emit(enc_ldaddal_x(17, 31, 16));
    c.restore_frame();
    c.restore_regs(true);
    c.emit(AARCH64_ERET_OPCODE);

    // Any active non-completion exception retries the original syscall through
    // the host. This includes valid deferred/COW output mappings, not just
    // EFAULT: the normal copyout path owns fault resolution and partial stores.
    let retry = c.pc;
    c.patch(wrong_pc, retry, Some(false));
    c.patch(wrong_esr, retry, Some(false));
    c.patch(completion_kicked, retry, Some(false));
    c.restore_frame();
    c.restore_regs(false);
    c.emit(enc_b(c.pc as u64, MAILBOX_HANDLER_OFFSET as u64));
    assert!(c.pc <= LINUX_EL1_VECTORS_SIZE as usize);
    ClockHandlerLayout {
        start: LINUX_EL1_VECTORS_BASE + ENTRY as u64,
        completion: LINUX_EL1_VECTORS_BASE + completion as u64,
        end: LINUX_EL1_VECTORS_BASE + c.pc as u64,
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Small independent interpreter of the emitted instruction subset. Unknown
    /// instructions fail closed; tests execute branches, spills and frame writes,
    /// rather than asserting the mere presence of dispatch opcodes.
    struct Machine {
        regs: [u64; 32],
        mem: BTreeMap<u64, u64>,
        elr: u64,
        spsr: u64,
        esr: u64,
        pc: usize,
        equal: bool,
        vectors: Vec<u8>,
    }
    const SP: u64 = 0x10000;
    impl Machine {
        fn new() -> Self {
            let mut m = Self {
                regs: std::array::from_fn(|i| 0xAB00 + i as u64),
                mem: BTreeMap::new(),
                elr: 0x12345678,
                spsr: 0xA0000000,
                esr: (0x15 << 26) | (1 << 25),
                pc: ENTRY,
                equal: false,
                vectors: el1_vectors_bytes_mailbox_clock(true, false),
            };
            m.regs[0] = 1;
            m.regs[8] = 113;
            m.regs[31] = SP;
            m.mem
                .insert(LINUX_IDENTITY_PAGE_BASE + IDENTITY_OFF_SHIM_ENABLED, 1);
            m.mem
                .insert(LINUX_IDENTITY_PAGE_BASE + CLOCK_GATE_OFFSET, 1);
            m
        }
        fn read(&self, addr: u64) -> u64 {
            *self.mem.get(&addr).unwrap_or(&0)
        }
        fn run(&mut self) -> &'static str {
            for _ in 0..300 {
                if self.pc == MAILBOX_HANDLER_OFFSET {
                    return "host";
                }
                let op = u32::from_le_bytes(
                    self.vectors[self.pc..self.pc + 4].try_into().expect("word"),
                );
                let pc = self.pc;
                self.pc += 4;
                let rt = (op & 31) as usize;
                let rn = ((op >> 5) & 31) as usize;
                if op == AARCH64_ERET_OPCODE {
                    return "eret";
                }
                if op & 0xFC000000 == 0x14000000 {
                    let d = ((op << 6) as i32 >> 6) as i64 * 4;
                    self.pc = (pc as i64 + d) as usize;
                } else if op & 0xFF000010 == 0x54000000 {
                    let d = (((op >> 5) & 0x7FFFF) << 13) as i32 >> 13;
                    if self.equal == (op & 15 == 0) {
                        self.pc = (pc as i64 + i64::from(d) * 4) as usize;
                    }
                } else if op & 0xFFC00000 == 0xF9000000 || op & 0xFFC00000 == 0xB9000000 {
                    let scale = if op >> 30 == 3 { 8 } else { 4 };
                    let addr = self.regs[rn] + u64::from((op >> 10) & 0xFFF) * scale;
                    self.mem
                        .insert(addr, if rt == 31 { 0 } else { self.regs[rt] });
                } else if op & 0xFFC00000 == 0xF9400000 || op & 0xFFC00000 == 0xB9400000 {
                    let scale = if op >> 30 == 3 { 8 } else { 4 };
                    let value = self.read(self.regs[rn] + u64::from((op >> 10) & 0xFFF) * scale);
                    self.regs[rt] = if scale == 4 {
                        value & 0xFFFF_FFFF
                    } else {
                        value
                    };
                } else if op & 0xFFE0FC00 == 0x88C0FC00 {
                    self.regs[rt] = self.read(self.regs[rn]) & 0xFFFF_FFFF;
                } else if op & 0xFF800000 == 0xD2800000 || op & 0xFF800000 == 0x52800000 {
                    self.regs[rt] = u64::from((op >> 5) & 0xFFFF) << (((op >> 21) & 3) * 16);
                } else if op & 0xFF800000 == 0xF2800000 {
                    let shift = ((op >> 21) & 3) * 16;
                    self.regs[rt] = (self.regs[rt] & !(0xFFFF << shift))
                        | (u64::from((op >> 5) & 0xFFFF) << shift);
                } else if op & 0xFFC00000 == 0xF1000000 || op & 0xFFC00000 == 0x71000000 {
                    self.equal = self.regs[rn] == u64::from((op >> 10) & 0xFFF);
                } else if op & 0xFFC00000 == 0x91000000 {
                    self.regs[rt] = self.regs[rn] + u64::from((op >> 10) & 0xFFF);
                } else {
                    match op {
                        AARCH64_MRS_ESR_EL1_X16_OPCODE => self.regs[16] = self.esr,
                        AARCH64_LSR_X16_X16_26_OPCODE => self.regs[16] >>= 26,
                        AARCH64_MRS_ELR_EL1_X16_OPCODE => self.regs[16] = self.elr,
                        AARCH64_MRS_SPSR_EL1_X16_OPCODE => self.regs[16] = self.spsr,
                        0xD5184030 => self.elr = self.regs[16],
                        0xD5184010 => self.spsr = self.regs[16],
                        0xD5185210 => self.esr = self.regs[16],
                        0xEB11021F => self.equal = self.regs[16] == self.regs[17],
                        op if op == enc_ldaddal_x(17, 31, 16) => {
                            let address = self.regs[16];
                            let next = self.read(address).wrapping_add(self.regs[17]);
                            self.mem.insert(address, next);
                        }
                        _ => panic!("unsupported opcode {op:08x} at {pc:x}"),
                    }
                }
            }
            panic!("unbounded generated control flow")
        }
        fn exception(&mut self, pc: u64, esr: u64) {
            self.pc = ENTRY;
            self.elr = pc;
            self.esr = esr;
            self.spsr = 0x60000000;
        }
    }
    pub(crate) fn assert_fstat_host_fallback(bytes: &[u8], entry: usize) {
        let mut m = Machine::new();
        m.vectors = bytes.to_vec();
        m.pc = entry;
        m.regs[8] = 80;
        let original = (m.regs, m.elr, m.spsr, m.esr);
        assert_eq!(m.run(), "host");
        assert_eq!((m.regs, m.elr, m.spsr, m.esr), original);
    }

    #[test]
    fn ineligible_calls_preserve_arguments_and_frame() {
        for case in 0..6 {
            let mut m = Machine::new();
            match case {
                0 => {
                    m.mem
                        .insert(LINUX_IDENTITY_PAGE_BASE + CLOCK_GATE_OFFSET, 0);
                }
                1 => {
                    m.mem
                        .insert(LINUX_IDENTITY_PAGE_BASE + IDENTITY_OFF_SHIM_ENABLED, 0);
                }
                2 => m.regs[8] = 114,
                3 => m.regs[0] = 0,
                4 => m.esr = 0x24 << 26,
                _ => {
                    m.mem.insert(SP + AARCH64_SYSCALL_MAILBOX_OFF_STATE, 1);
                }
            }
            let original = (m.regs, m.elr, m.spsr, m.esr);
            assert_eq!(m.run(), "host");
            assert_eq!((m.regs, m.elr, m.spsr, m.esr), original, "case {case}");
        }
    }
    #[test]
    fn kick_before_admission_forces_original_host_syscall() {
        let mut m = Machine::new();
        m.mem.insert(SP + AARCH64_SYSCALL_MAILBOX_OFF_FLAGS, 1);
        let original = (m.regs, m.elr, m.spsr, m.esr);
        assert_eq!(m.run(), "host");
        assert_eq!((m.regs, m.elr, m.spsr, m.esr), original);
    }

    #[test]
    fn kick_during_active_clock_forces_host_boundary_on_completion() {
        let mut m = Machine::new();
        let original = (m.regs, m.elr, m.spsr, m.esr);
        assert_eq!(m.run(), "eret");
        m.mem.insert(SP + AARCH64_SYSCALL_MAILBOX_OFF_FLAGS, 1);
        m.exception(COMPLETION_PC, (0x15 << 26) | (1 << 25) | u64::from(MARKER));
        assert_eq!(m.run(), "host");
        assert_eq!((m.regs, m.elr, m.spsr, m.esr), original);
        assert_eq!(
            m.read(LINUX_IDENTITY_PAGE_BASE + IDENTITY_OFF_SHIM_SYSCALLS),
            0
        );
    }

    #[test]
    fn completion_restores_all_registers_and_original_frame() {
        let mut m = Machine::new();
        let original = (m.regs, m.elr, m.spsr, m.esr);
        assert_eq!(m.run(), "eret");
        assert_eq!(m.elr, STUB_BASE);
        assert_eq!(m.read(SP + AARCH64_SYSCALL_MAILBOX_OFF_STATE), 3);
        for (r, _) in SAVED {
            m.regs[r as usize] = 0xDEAD;
        }
        // Stub leaves x8 untouched; the ingress test starts after legacy shims.
        m.regs[8] = 113;
        m.exception(COMPLETION_PC, (0x15 << 26) | (1 << 25) | u64::from(MARKER));
        assert_eq!(m.run(), "eret");
        let mut expected = original.0;
        expected[0] = 0;
        assert_eq!(m.regs, expected);
        assert_eq!((m.elr, m.spsr, m.esr), (original.1, original.2, original.3));
        assert_eq!(m.read(SP + AARCH64_SYSCALL_MAILBOX_OFF_STATE), 0);
        assert_eq!(
            m.read(LINUX_IDENTITY_PAGE_BASE + IDENTITY_OFF_SHIM_SYSCALLS),
            1,
            "successful clock completion must be counted atomically"
        );
    }
    #[test]
    fn faults_and_wrong_markers_retry_original_syscall_without_counting() {
        for (pc, esr) in [
            (STUB_BASE + 36, 0x24 << 26),
            (STUB_BASE + 40, 0x24 << 26),
            (COMPLETION_PC, (0x15 << 26) | (1 << 25)),
            (
                COMPLETION_PC - 4,
                (0x15 << 26) | (1 << 25) | u64::from(MARKER),
            ),
        ] {
            let mut m = Machine::new();
            let original = (m.regs, m.elr, m.spsr, m.esr);
            assert_eq!(m.run(), "eret");
            for (r, _) in SAVED {
                m.regs[r as usize] = 0xBAD;
            }
            m.exception(pc, esr);
            assert_eq!(m.run(), "host");
            assert_eq!((m.regs, m.elr, m.spsr, m.esr), original);
            assert_eq!(m.read(SP + AARCH64_SYSCALL_MAILBOX_OFF_STATE), 0);
            assert_eq!(
                m.read(LINUX_IDENTITY_PAGE_BASE + IDENTITY_OFF_SHIM_SYSCALLS),
                0
            );
        }
    }
    #[test]
    fn forged_marker_without_active_transaction_cannot_complete() {
        let mut m = Machine::new();
        m.regs[8] = 999;
        m.exception(COMPLETION_PC, (0x15 << 26) | (1 << 25) | u64::from(MARKER));
        let original = m.regs;
        assert_eq!(m.run(), "host");
        assert_eq!(m.regs, original);
    }
    #[test]
    fn el0_stub_computes_timespec_without_touching_other_registers() {
        for ticks in [0, 1, 23_999_999, 24_000_000, 123_456_789_123] {
            let frequency = 24_000_000;
            let mut regs = std::array::from_fn::<_, 32, _>(|i| 0x1000 + i as u64);
            regs[1] = 0x20000;
            let original = regs;
            let mut stores = BTreeMap::new();
            for op in STUB {
                let rd = (op & 31) as usize;
                let rn = ((op >> 5) & 31) as usize;
                let rm = ((op >> 16) & 31) as usize;
                let ra = ((op >> 10) & 31) as usize;
                match op {
                    0xD5033FDF => (),
                    0xD53BE042 => regs[2] = ticks,
                    0xD53BE00A => regs[10] = frequency,
                    _ if op & 0xFFE0FC00 == 0x9AC00800 => regs[rd] = regs[rn] / regs[rm],
                    _ if op & 0xFF800000 == 0xD2800000 => {
                        regs[rd] = u64::from((op >> 5) & 0xFFFF) << (((op >> 21) & 3) * 16)
                    }
                    _ if op & 0xFF800000 == 0xF2800000 => {
                        let shift = ((op >> 21) & 3) * 16;
                        regs[rd] = (regs[rd] & !(0xFFFF << shift))
                            | (u64::from((op >> 5) & 0xFFFF) << shift);
                    }
                    _ if op & 0xFFE08000 == 0x9B008000 => {
                        regs[rd] = regs[ra].wrapping_sub(regs[rn] * regs[rm])
                    }
                    _ if op & 0xFFE08000 == 0x9B000000 => {
                        regs[rd] = regs[rn] * regs[rm] + if ra == 31 { 0 } else { regs[ra] }
                    }
                    _ if op & 0xFFC00000 == 0xF9000000 => {
                        stores.insert(regs[rn] + u64::from((op >> 10) & 0xFFF) * 8, regs[rd]);
                    }
                    _ if op & 0xFFE0001F == 0xD4000001 => {
                        assert_eq!((op >> 5) & 0xFFFF, u32::from(MARKER))
                    }
                    _ => panic!("unexpected stub opcode {op:08x}"),
                }
            }
            assert_eq!(stores.len(), 2);
            assert_eq!(stores[&original[1]], ticks / frequency);
            assert_eq!(
                stores[&(original[1] + 8)],
                (ticks % frequency) * 1_000_000_000 / frequency
            );
            for r in 0..32 {
                if ![2, 3, 4, 10, 11].contains(&r) {
                    assert_eq!(regs[r], original[r], "x{r}");
                }
            }
        }
    }

    #[test]
    fn fresh_identity_page_keeps_clock_admission_disabled() {
        let image = AddressSpace::from_regions(0, vec![])
            .expect("empty")
            .with_identity_page()
            .expect("identity");
        let page = image
            .regions
            .iter()
            .find(|r| r.start == LINUX_IDENTITY_PAGE_BASE)
            .expect("identity page");
        assert_eq!(
            &page.bytes.prefix()[CLOCK_GATE_OFFSET as usize..CLOCK_GATE_OFFSET as usize + 4],
            &[0; 4]
        );
    }

    #[test]
    fn stub_mapping_collision_is_rejected() {
        let image = AddressSpace::from_regions(0, vec![region()]).expect("stub");
        assert!(matches!(
            image.with_el1_vectors_mailbox_clock(true, false),
            Err(AddressSpaceError::OverlappingRegion { .. })
        ));
    }

    #[test]
    fn builders_install_read_execute_stub_only_with_fast_paths() {
        for enabled in [false, true] {
            let image = AddressSpace::from_regions(0, vec![])
                .expect("empty")
                .with_el1_vectors_mailbox_clock(enabled, false)
                .expect("vectors");
            let stub = image.regions.iter().find(|r| r.start == STUB_BASE);
            assert_eq!(stub.is_some(), enabled);
            if let Some(stub) = stub {
                assert!(stub.perms.read && stub.perms.execute && !stub.perms.write);
            }
        }
    }
}

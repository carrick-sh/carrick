//! The guest-visible ISA, independent of any optional extensions on the host.
use crate::state::{ExceptionLevel, SystemValue};
use crate::{Instruction, SimdCompute, SystemRegister};
use carrick_abi::{LinuxAarch64Hwcap, LinuxAarch64Hwcap2};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestCpuProfile {
    hwcap: LinuxAarch64Hwcap,
    hwcap2: LinuxAarch64Hwcap2,
}

pub const GUEST_CPU_PROFILE: GuestCpuProfile = GuestCpuProfile {
    hwcap: LinuxAarch64Hwcap::FP
        .union(LinuxAarch64Hwcap::ASIMD)
        .union(LinuxAarch64Hwcap::CRC32)
        .union(LinuxAarch64Hwcap::CPUID),
    hwcap2: LinuxAarch64Hwcap2::empty(),
};

impl GuestCpuProfile {
    pub const fn hwcap(self) -> LinuxAarch64Hwcap {
        self.hwcap
    }

    pub const fn hwcap2(self) -> LinuxAarch64Hwcap2 {
        self.hwcap2
    }

    pub(crate) fn admits(self, instruction: Instruction, el: ExceptionLevel) -> bool {
        let required = match instruction {
            Instruction::AtomicAdd(_) if el == ExceptionLevel::El0 => LinuxAarch64Hwcap::ATOMICS,
            Instruction::SimdCompute(SimdCompute::FloatingPoint) => LinuxAarch64Hwcap::FP,
            Instruction::SimdCompute(SimdCompute::AdvancedSimd) | Instruction::SimdCopy(_) => {
                LinuxAarch64Hwcap::ASIMD
            }
            Instruction::Crc32(_) => LinuxAarch64Hwcap::CRC32,
            _ => return true,
        };
        self.hwcap.contains(required)
    }

    /// Architectural ID reads are routed to this Rust-side profile, never
    /// copied as host MRS. EL0 gets Linux's sanitized CPUID register space.
    pub(crate) fn read_id(self, r: SystemRegister, el: ExceptionLevel) -> Option<SystemValue> {
        if (r.op0, r.op1, r.crn) != (3, 0, 0) {
            return None;
        }
        let el0 = el == ExceptionLevel::El0;
        if el0 && !self.hwcap.contains(LinuxAarch64Hwcap::CPUID) {
            return None;
        }
        let value = match (r.crm, r.op2) {
            (4, 0) => {
                // FEAT_FP and FEAT_AdvSIMD use 0 for baseline, 0xf for absent.
                let fp = if self.hwcap.contains(LinuxAarch64Hwcap::FP) {
                    0
                } else {
                    0xf
                };
                let simd = if self.hwcap.contains(LinuxAarch64Hwcap::ASIMD) {
                    0
                } else {
                    0xf
                };
                (simd << 20) | (fp << 16) | if el0 { 0 } else { 0x11 }
            }
            (6, 0) => {
                (u64::from(self.hwcap.contains(LinuxAarch64Hwcap::CRC32)) << 16)
                    | (u64::from(self.hwcap.contains(LinuxAarch64Hwcap::ATOMICS)) << 21)
            }
            (4, 1) | (6, 1 | 2) => 0, // no extensions in PFR1, ISAR1 or ISAR2
            (0, 0 | 6) if el0 => 0,   // synthetic MIDR and REVIDR
            (0, 5) if el0 => 1 << 31, // MPIDR's reserved one bit, no topology exposure
            (2..=7, _) if el0 => 0,
            _ => return None,
        };
        Some(SystemValue(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ProgramCounter;
    use crate::translate::{ExitReason, GuestInstruction, InstructionClass};

    #[test]
    fn profile_exposes_the_same_isa_to_auxv_id_reads_and_el0_admission() {
        let profile = GUEST_CPU_PROFILE;
        assert_eq!(
            profile.hwcap(),
            LinuxAarch64Hwcap::FP
                | LinuxAarch64Hwcap::ASIMD
                | LinuxAarch64Hwcap::CRC32
                | LinuxAarch64Hwcap::CPUID
        );
        assert!(profile.hwcap2().is_empty());
        let isar0 = SystemRegister::from_word(0xd538_0603);
        let pfr0 = SystemRegister::from_word(0xd538_0404);
        assert_eq!(
            profile.read_id(isar0, ExceptionLevel::El0),
            Some(SystemValue(1 << 16))
        );
        assert_eq!(
            profile.read_id(pfr0, ExceptionLevel::El0),
            Some(SystemValue(0))
        );
        assert_eq!(
            GuestInstruction::decode_el0(ProgramCounter(0), 0xf821_0002).class(),
            InstructionClass::Exit(ExitReason::Undefined)
        );
        assert_eq!(
            GuestInstruction::decode_el0(ProgramCounter(0), 0x9ac1_4c02).class(),
            InstructionClass::Exit(ExitReason::RegisterCompute)
        );
    }
}

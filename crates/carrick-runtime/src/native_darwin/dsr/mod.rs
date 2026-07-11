pub(super) mod decode;
pub(super) mod types;

#[cfg(test)]
mod tests {
    use super::decode::classify;
    use super::types::{DirectKind, IndirectKind, InstAction, PcRelativeKind, SensitiveKind};
    use carrick_guest_mem::GuestVa;
    use proptest::prelude::*;

    const PC: GuestVa = GuestVa(0x1000);

    #[test]
    fn classifies_copy_syscall_and_control_flow() {
        assert!(matches!(
            classify(0x9100_0400, PC),
            Ok(InstAction::Copy(0x9100_0400))
        ));
        assert!(matches!(
            classify(0xd400_0001, PC),
            Ok(InstAction::Syscall { resume }) if resume == GuestVa(0x1004)
        ));
        assert!(matches!(
            classify(0x1400_0002, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Branch && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0x9400_0002, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Call && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xd61f_0000, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Branch
        ));
        assert!(matches!(
            classify(0xd65f_03c0, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Return
        ));
    }

    #[test]
    fn classifies_pc_relative_and_sensitive_operations() {
        assert!(matches!(
            classify(0x1000_0040, PC),
            Ok(InstAction::PcRelative(inst))
                if inst.kind == PcRelativeKind::Adr && inst.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xd53b_d040, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadTpidr
        ));
        assert!(matches!(
            classify(0xd51b_d040, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::WriteTpidr
        ));
        assert!(matches!(
            classify(0xd50b_7420, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::DcZva
        ));
        assert!(matches!(
            classify(0x9000_0000, PC),
            Ok(InstAction::PcRelative(inst)) if inst.kind == PcRelativeKind::Adrp
        ));
        assert!(matches!(
            classify(0x5800_0040, PC),
            Ok(InstAction::PcRelative(inst))
                if inst.kind == PcRelativeKind::LiteralLoad && inst.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xd53b_0020, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadCtr
        ));
        assert!(matches!(
            classify(0xd53b_00e0, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadDczid
        ));
        assert!(matches!(
            classify(0xd50b_7b20, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::DcCvau
        ));
        assert!(matches!(
            classify(0xd50b_7520, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::IcIvau
        ));
    }

    #[test]
    fn classifies_conditional_compare_test_and_indirect_calls() {
        assert!(matches!(
            classify(0x5400_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Conditional && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xb400_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::CompareZero { nonzero: false }
                    && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xb500_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::CompareZero { nonzero: true }
        ));
        assert!(matches!(
            classify(0x3600_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::TestBit { nonzero: false }
        ));
        assert!(matches!(
            classify(0x3700_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::TestBit { nonzero: true }
        ));
        assert!(matches!(
            classify(0xd63f_0000, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Call
        ));
    }

    proptest! {
        #[test]
        fn direct_branch_targets_follow_signed_imm26(word_offset in -0x1ff_ffff_i32..=0x1ff_ffff_i32) {
            let pc = GuestVa(0x1_0000_0000);
            let immediate = (word_offset as u32) & 0x03ff_ffff;
            let word = 0x1400_0000 | immediate;
            let expected = GuestVa(pc.raw().wrapping_add_signed(i64::from(word_offset) * 4));
            prop_assert!(matches!(
                classify(word, pc),
                Ok(InstAction::Direct(exit))
                    if exit.kind == DirectKind::Branch && exit.target == expected
            ));
        }

        #[test]
        fn adr_targets_follow_signed_imm21(byte_offset in -0x10_0000_i32..=0x0f_ffff_i32) {
            let pc = GuestVa(0x1_0000_0000);
            let immediate = (byte_offset as u32) & 0x001f_ffff;
            let immlo = immediate & 0x3;
            let immhi = immediate >> 2;
            let word = 0x1000_0000 | (immlo << 29) | (immhi << 5);
            let expected = GuestVa(pc.raw().wrapping_add_signed(i64::from(byte_offset)));
            prop_assert!(matches!(
                classify(word, pc),
                Ok(InstAction::PcRelative(inst))
                    if inst.kind == PcRelativeKind::Adr && inst.target == expected
            ));
        }
    }
}

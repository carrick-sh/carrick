//! VM-free Intel VMX segment checks, clean-room from Intel SDM vol. 3
//! §§26.3.1.1–26.3.1.4 (order number 325384). No backend dependencies.
//! This models Carrick's four-level IA-32e entry lane; capability-dependent
//! CR fixed masks, interrupt injection, debug MSRs and CR3 are backend checks.

use crate::X86Seg;

/// Raw hidden segment state, including deliberately invalid diagnostic inputs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuestSegment {
    pub base: u64,
    pub limit: u32,
    pub ar: u32,
    pub selector: u16,
}

#[derive(Clone, Debug)]
pub struct LongModeSegments {
    pub cs: GuestSegment,
    pub ss: GuestSegment,
    pub ds: GuestSegment,
    pub es: GuestSegment,
    pub fs: GuestSegment,
    pub gs: GuestSegment,
    pub tr: GuestSegment,
    pub ldtr: GuestSegment,
    pub cr0: u64,
    pub cr4: u64,
    pub efer: u64,
    pub rflags: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmxGuestStateRule {
    Granularity,
    ReservedAccessRights,
    SegmentType,
    SystemBit,
    Present,
    SelectorTable,
    SelectorPrivilege,
    DescriptorPrivilege,
    BaseAddress,
    LongCodeDefaultSize,
    TaskRegisterUnusable,
    LongModeControls,
    EferReserved,
    PagingWithoutProtection,
    RestrictedProtection,
    RflagsReserved,
    Virtual8086,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmxGuestStateViolation {
    pub segment: Option<X86Seg>,
    pub rule: VmxGuestStateRule,
}

fn canonical(base: u64) -> bool {
    ((base << 16) as i64 >> 16) as u64 == base
}

/// Check all eight hidden descriptors and the modeled IA-32e control state.
/// `unrestricted` is the effective VMX unrestricted-guest control, not a
/// relaxation of long-mode, TR, reserved-bit, or granularity checks.
pub fn check_vmx_guest_segments(
    s: &LongModeSegments,
    unrestricted: bool,
) -> Result<(), Vec<VmxGuestStateViolation>> {
    use VmxGuestStateRule as Rule;
    let mut errors = Vec::new();
    let mut check = |ok: bool, segment, rule| {
        if !ok {
            errors.push(VmxGuestStateViolation { segment, rule });
        }
    };
    let pe = s.cr0 & 1 != 0;
    let pg = s.cr0 & (1 << 31) != 0;
    let lma = s.efer & (1 << 10) != 0;
    let lme = s.efer & (1 << 8) != 0;
    check(
        lma && lme && pg && s.cr4 & (1 << 5) != 0,
        None,
        Rule::LongModeControls,
    );
    check(s.efer & !0xd01 == 0, None, Rule::EferReserved);
    check(!pg || pe, None, Rule::PagingWithoutProtection);
    check(unrestricted || (pe && pg), None, Rule::RestrictedProtection);
    check(
        s.rflags & 2 != 0 && s.rflags & (!0x3fffff | 0x8028) == 0,
        None,
        Rule::RflagsReserved,
    );
    check(s.rflags & (1 << 17) == 0, None, Rule::Virtual8086);
    let dpl = |seg: GuestSegment| (seg.ar >> 5) & 3;
    check(
        unrestricted || s.ss.selector & 3 == s.cs.selector & 3,
        Some(X86Seg::Ss),
        Rule::SelectorPrivilege,
    );
    let ct = s.cs.ar & 15;
    check(
        match ct {
            3 => unrestricted && dpl(s.cs) == 0,
            9 | 11 => dpl(s.cs) == dpl(s.ss),
            13 | 15 => dpl(s.cs) <= dpl(s.ss),
            _ => false,
        },
        Some(X86Seg::Cs),
        Rule::DescriptorPrivilege,
    );
    check(
        unrestricted || dpl(s.ss) == u32::from(s.ss.selector & 3),
        Some(X86Seg::Ss),
        Rule::DescriptorPrivilege,
    );
    check(
        (ct != 3 && pe) || dpl(s.ss) == 0,
        Some(X86Seg::Ss),
        Rule::DescriptorPrivilege,
    );
    for (name, seg) in [
        (X86Seg::Cs, s.cs),
        (X86Seg::Ss, s.ss),
        (X86Seg::Ds, s.ds),
        (X86Seg::Es, s.es),
        (X86Seg::Fs, s.fs),
        (X86Seg::Gs, s.gs),
        (X86Seg::Tr, s.tr),
        (X86Seg::Ldtr, s.ldtr),
    ] {
        let usable = seg.ar & (1 << 16) == 0;
        let code = name == X86Seg::Cs;
        let tr = name == X86Seg::Tr;
        let ldt = name == X86Seg::Ldtr;
        if tr || (ldt && usable) {
            check(seg.selector & 4 == 0, Some(name), Rule::SelectorTable);
        }
        let base_ok = match name {
            X86Seg::Tr | X86Seg::Fs | X86Seg::Gs => canonical(seg.base),
            X86Seg::Ldtr => !usable || canonical(seg.base),
            _ => (!code && !usable) || seg.base >> 32 == 0,
        };
        check(base_ok, Some(name), Rule::BaseAddress);
        if tr {
            check(usable, Some(name), Rule::TaskRegisterUnusable);
        }
        if !(usable || code || tr) {
            continue;
        }
        check(
            seg.ar & 0xfffe_0f00 == 0,
            Some(name),
            Rule::ReservedAccessRights,
        );
        let g = seg.ar & (1 << 15) != 0;
        check(
            (!g || seg.limit & 0xfff == 0xfff) && (g || seg.limit >> 20 == 0),
            Some(name),
            Rule::Granularity,
        );
        let typ = seg.ar & 15;
        check(
            match name {
                X86Seg::Cs => matches!(typ, 9 | 11 | 13 | 15) || (unrestricted && typ == 3),
                X86Seg::Ss => matches!(typ, 3 | 7),
                X86Seg::Tr => typ == 11,
                X86Seg::Ldtr => typ == 2,
                _ => typ & 1 != 0 && (typ & 8 == 0 || typ & 2 != 0),
            },
            Some(name),
            Rule::SegmentType,
        );
        check(
            (seg.ar & 16 != 0) != (tr || ldt),
            Some(name),
            Rule::SystemBit,
        );
        check(seg.ar & 128 != 0, Some(name), Rule::Present);
        if code {
            check(
                !lma || seg.ar & (1 << 13) == 0 || seg.ar & (1 << 14) == 0,
                Some(name),
                Rule::LongCodeDefaultSize,
            );
        }
        if !unrestricted
            && matches!(name, X86Seg::Ds | X86Seg::Es | X86Seg::Fs | X86Seg::Gs)
            && typ <= 11
        {
            check(
                dpl(seg) >= u32::from(seg.selector & 3),
                Some(name),
                Rule::DescriptorPrivilege,
            );
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Privilege admitted by Carrick's long-mode entry constructors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentDpl {
    Kernel,
    User,
}

/// A hidden descriptor whose granularity always represents its byte limit.
/// Fields are private so rebasing or changing privilege cannot split G/limit.
/// Access rights use the VMX encoding: type/S/DPL/P in bits 0–7,
/// AVL/L/D-B/G in bits 12–15, and unusable in bit 16 (§24.4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentDescriptor(GuestSegment);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnrepresentableSegmentLimit(pub u32);

impl SegmentDescriptor {
    /// Admit a byte limit and derive G, ignoring the caller's G bit.
    /// Other access rights are checked by the VM-entry validator.
    pub const fn from_fields(
        base: u64,
        limit: u32,
        ar: u32,
        selector: u16,
    ) -> Result<Self, UnrepresentableSegmentLimit> {
        if limit & 0xfff != 0xfff && limit >> 20 != 0 {
            return Err(UnrepresentableSegmentLimit(limit));
        }
        Ok(Self::representable(base, limit, ar, selector))
    }
    const fn granularity(limit: u32) -> u32 {
        if limit & 0xfff == 0xfff { 1 << 15 } else { 0 }
    }
    const fn representable(base: u64, limit: u32, ar: u32, selector: u16) -> Self {
        Self(GuestSegment {
            base,
            limit,
            ar: (ar & !(1 << 15)) | Self::granularity(limit),
            selector,
        })
    }
    pub const fn tss64_busy(base: u64) -> Self {
        Self::representable(base, crate::fault::X86_TSS64_LIMIT, 0x8b, 0)
    }
    pub const fn code64(dpl: SegmentDpl) -> Self {
        let (privilege, selector) = match dpl {
            SegmentDpl::Kernel => (0, 8),
            SegmentDpl::User => (3, 0x23),
        };
        Self::representable(0, u32::MAX, 0x209b | (privilege << 5), selector)
    }
    pub const fn flat_data(dpl: SegmentDpl, base: u64) -> Self {
        let (privilege, selector) = match dpl {
            SegmentDpl::Kernel => (0, 0x10),
            SegmentDpl::User => (3, 0x1b),
        };
        Self::representable(base, u32::MAX, 0x4093 | (privilege << 5), selector)
    }
    pub const fn unusable_ldt() -> Self {
        Self(GuestSegment {
            base: 0,
            limit: 0,
            ar: 1 << 16,
            selector: 0,
        })
    }
    /// GDTR/IDTR pseudo-descriptor for the shared programming surface.
    pub const fn table(base: u64, limit: u16) -> Self {
        Self(GuestSegment {
            base,
            limit: limit as u32,
            ar: 0,
            selector: 0,
        })
    }
    pub const fn with_base(mut self, base: u64) -> Self {
        self.0.base = base;
        self
    }
    pub const fn with_selector(mut self, selector: u16) -> Self {
        self.0.selector = selector;
        self
    }
    pub const fn base(self) -> u64 {
        self.0.base
    }
    pub const fn limit(self) -> u32 {
        self.0.limit
    }
    pub const fn access_rights(self) -> u32 {
        self.0.ar
    }
    pub const fn selector(self) -> u16 {
        self.0.selector
    }
}
impl From<SegmentDescriptor> for GuestSegment {
    fn from(value: SegmentDescriptor) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GuestSegment, LongModeSegments, SegmentDescriptor, UnrepresentableSegmentLimit,
        VmxGuestStateRule, VmxGuestStateViolation, check_vmx_guest_segments,
    };
    use crate::X86Seg;
    use crate::long_mode_segment_state;
    fn current(kernel: bool) -> LongModeSegments {
        let a = long_mode_segment_state();
        let data = GuestSegment {
            base: 0,
            limit: u32::MAX,
            ar: a.data_ar,
            selector: 0x1b,
        };
        LongModeSegments {
            cs: GuestSegment {
                ar: if kernel { a.kernel_cs_ar } else { a.cs_ar },
                selector: if kernel { 8 } else { 0x23 },
                ..data
            },
            ss: GuestSegment {
                ar: if kernel { a.kernel_data_ar } else { a.data_ar },
                selector: if kernel { 0x10 } else { 0x1b },
                ..data
            },
            ds: data,
            es: data,
            fs: data,
            gs: data,
            tr: GuestSegment {
                base: 0x10000,
                limit: crate::fault::X86_TSS64_LIMIT,
                ar: a.tr_ar,
                selector: 0,
            },
            ldtr: GuestSegment {
                ar: a.ldtr_ar,
                ..GuestSegment::default()
            },
            cr0: 0x80010033,
            cr4: 0x340620,
            efer: 0xd01,
            rflags: 2,
        }
    }
    #[test]
    fn vmx_current_user_segments_are_valid() {
        assert_eq!(check_vmx_guest_segments(&current(false), false), Ok(()));
    }
    #[test]
    fn vmx_current_kernel_segments_are_valid() {
        assert_eq!(check_vmx_guest_segments(&current(true), false), Ok(()));
    }
    #[test]
    fn vmx_tr_granularity_is_never_relaxed() {
        for unrestricted in [false, true] {
            let mut s = current(false);
            s.tr.ar |= 1 << 15;
            assert!(
                check_vmx_guest_segments(&s, unrestricted)
                    .expect_err("invalid TR")
                    .contains(&VmxGuestStateViolation {
                        segment: Some(X86Seg::Tr),
                        rule: VmxGuestStateRule::Granularity
                    })
            );
        }
    }
    #[test]
    fn vmx_rejects_independent_descriptor_and_control_defects() {
        use VmxGuestStateRule as Rule;
        type Mutation = (VmxGuestStateRule, fn(&mut LongModeSegments));
        let mutations: &[Mutation] = &[
            (Rule::SegmentType, |s| s.tr.ar = (s.tr.ar & !15) | 9),
            (Rule::SystemBit, |s| s.tr.ar |= 16),
            (Rule::Present, |s| s.tr.ar &= !128),
            (Rule::TaskRegisterUnusable, |s| s.tr.ar |= 1 << 16),
            (Rule::SelectorTable, |s| s.tr.selector |= 4),
            (Rule::ReservedAccessRights, |s| s.tr.ar |= 1 << 8),
            (Rule::ReservedAccessRights, |s| s.cs.ar |= 1 << 17),
            (Rule::Granularity, |s| s.cs.ar &= !(1 << 15)),
            (Rule::BaseAddress, |s| s.tr.base = 1 << 48),
            (Rule::BaseAddress, |s| s.fs.base = 1 << 48),
            (Rule::BaseAddress, |s| s.cs.base = 1 << 32),
            (Rule::SelectorPrivilege, |s| s.ss.selector = 0x10),
            (Rule::DescriptorPrivilege, |s| s.ss.ar &= !(3 << 5)),
            (Rule::LongCodeDefaultSize, |s| s.cs.ar |= 1 << 14),
            (Rule::SegmentType, |s| s.ds.ar &= !1),
            (Rule::SegmentType, |s| s.ds.ar = (s.ds.ar & !15) | 9),
            (Rule::DescriptorPrivilege, |s| s.ds.ar &= !(3 << 5)),
            (Rule::SegmentType, |s| s.ldtr.ar = 0x83),
            (Rule::LongModeControls, |s| s.efer &= !(1 << 8)),
            (Rule::LongModeControls, |s| s.cr4 &= !(1 << 5)),
            (Rule::EferReserved, |s| s.efer |= 1 << 63),
            (Rule::PagingWithoutProtection, |s| s.cr0 &= !1),
            (Rule::RflagsReserved, |s| s.rflags &= !2),
            (Rule::RflagsReserved, |s| s.rflags |= 1 << 22),
            (Rule::Virtual8086, |s| s.rflags |= 1 << 17),
        ];
        for (rule, mutate) in mutations {
            let mut s = current(false);
            mutate(&mut s);
            assert!(
                check_vmx_guest_segments(&s, false)
                    .expect_err("defect")
                    .iter()
                    .any(|v| v.rule == *rule),
                "missing {rule:?}"
            );
        }
    }
    #[test]
    fn vmx_unusable_and_unrestricted_exceptions_are_precise() {
        let mut s = current(false);
        s.ds = GuestSegment {
            base: u64::MAX,
            limit: 0x12345678,
            ar: 0xffff_ffff,
            selector: 7,
        };
        s.ldtr = s.ds;
        assert_eq!(check_vmx_guest_segments(&s, false), Ok(()));
        s.ss.selector = 0x10;
        assert!(check_vmx_guest_segments(&s, false).is_err());
        assert_eq!(check_vmx_guest_segments(&s, true), Ok(()));
        // An unusable CS still has its access rights and base checked.
        s.cs.ar |= (1 << 16) | (1 << 8);
        assert!(check_vmx_guest_segments(&s, true).is_err());
    }
    #[test]
    fn descriptors_derive_granularity_or_refuse_the_limit() {
        for (limit, g) in [
            (0, 0),
            (0x67, 0),
            (0xffe, 0),
            (0xfff, 1),
            (0xffffe, 0),
            (0xfffff, 1),
            (0x100fff, 1),
            (u32::MAX, 1),
        ] {
            let d = SegmentDescriptor::from_fields(0, limit, 0x808b, 0).expect("representable");
            assert_eq!((d.access_rights() >> 15) & 1, g);
            assert_eq!(d.limit(), limit);
        }
        for limit in [0x100000, 0x12345678, 0xffff_fffe] {
            assert_eq!(
                SegmentDescriptor::from_fields(0, limit, 0x8b, 0),
                Err(UnrepresentableSegmentLimit(limit))
            );
        }
        let tr = SegmentDescriptor::tss64_busy(0xffff_ffff_8000_0000);
        assert_eq!(tr.access_rights(), 0x8b);
        assert_eq!(tr.limit(), 0x67);
        assert_eq!(tr.with_base(0x10000).access_rights(), 0x8b);
    }
}

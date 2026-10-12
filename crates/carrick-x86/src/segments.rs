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
    use VmxGuestStateRule::*;
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
        LongModeControls,
    );
    check(s.efer & !0xd01 == 0, None, EferReserved);
    check(!pg || pe, None, PagingWithoutProtection);
    check(unrestricted || (pe && pg), None, RestrictedProtection);
    check(
        s.rflags & 2 != 0 && s.rflags & (!0x3fffff | 0x8028) == 0,
        None,
        RflagsReserved,
    );
    check(s.rflags & (1 << 17) == 0, None, Virtual8086);
    let dpl = |seg: GuestSegment| (seg.ar >> 5) & 3;
    check(
        unrestricted || s.ss.selector & 3 == s.cs.selector & 3,
        Some(X86Seg::Ss),
        SelectorPrivilege,
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
        DescriptorPrivilege,
    );
    check(
        unrestricted || dpl(s.ss) == u32::from(s.ss.selector & 3),
        Some(X86Seg::Ss),
        DescriptorPrivilege,
    );
    check(
        (ct != 3 && pe) || dpl(s.ss) == 0,
        Some(X86Seg::Ss),
        DescriptorPrivilege,
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
            check(seg.selector & 4 == 0, Some(name), SelectorTable);
        }
        let base_ok = match name {
            X86Seg::Tr | X86Seg::Fs | X86Seg::Gs => canonical(seg.base),
            X86Seg::Ldtr => !usable || canonical(seg.base),
            _ => (!code && !usable) || seg.base >> 32 == 0,
        };
        check(base_ok, Some(name), BaseAddress);
        if tr {
            check(usable, Some(name), TaskRegisterUnusable);
        }
        if !(usable || code || tr) {
            continue;
        }
        check(seg.ar & 0xfffe_0f00 == 0, Some(name), ReservedAccessRights);
        let g = seg.ar & (1 << 15) != 0;
        check(
            (!g || seg.limit & 0xfff == 0xfff) && (g || seg.limit >> 20 == 0),
            Some(name),
            Granularity,
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
            SegmentType,
        );
        check((seg.ar & 16 != 0) == !(tr || ldt), Some(name), SystemBit);
        check(seg.ar & 128 != 0, Some(name), Present);
        if code {
            check(
                !lma || seg.ar & (1 << 13) == 0 || seg.ar & (1 << 14) == 0,
                Some(name),
                LongCodeDefaultSize,
            );
        }
        if !unrestricted
            && matches!(name, X86Seg::Ds | X86Seg::Es | X86Seg::Fs | X86Seg::Gs)
            && typ <= 11
        {
            check(
                dpl(seg) >= u32::from(seg.selector & 3),
                Some(name),
                DescriptorPrivilege,
            );
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}

//! Known answers for the AArch64 stage-1 walk. Hand-built descriptors use
//! the Arm ARM D5.3 encodings directly (independent expected values, not
//! this crate's constants); the production witnesses walk the bytes
//! `carrick_mem::memory::stage1_identity_page_tables` builds for the
//! hardware profile, under the registers `carrick_mem::arch_sysregs`
//! programs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::vec::Vec;

use super::*;
use crate::descriptor_refusal::DescriptorRefusal;
use carrick_mem::arch_sysregs::{SCTLR_EL1_BOOTSTRAP, TCR_EL1_BOOTSTRAP};
use carrick_mem::memory::{
    LINUX_KERNEL_REGION_BASE, LINUX_NULL_GUARD_END, LINUX_PAGE_TABLES_BASE, LINUX_ROSETTA_IPA_BASE,
    LINUX_ROSETTA_VA_BASE, stage1_identity_page_tables,
};

/// Descriptor words keyed by physical address; anything absent reads 0
/// unless it lies outside every admitted table, which refuses.
struct Words {
    words: BTreeMap<u64, u64>,
    tables: Vec<u64>,
    loads: Cell<u32>,
}

impl Words {
    fn new() -> Self {
        Self {
            words: BTreeMap::new(),
            tables: Vec::new(),
            loads: Cell::new(0),
        }
    }
    fn table(&mut self, pa: u64) -> u64 {
        self.tables.push(pa);
        pa
    }
    fn set(&mut self, table: u64, index: u64, descriptor: u64) {
        assert!(self.tables.contains(&table));
        self.words.insert(table + index * 8, descriptor);
    }
}

impl LiveDescriptorWords for Words {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        self.loads.set(self.loads.get() + 1);
        if !self.tables.contains(&(pa & !0xfff)) {
            return Err(DescriptorRefusal::MissingTable);
        }
        Ok(self.words.get(&pa).copied().unwrap_or(0))
    }
    fn compare_exchange(&self, _: u64, _: u64, _: u64) -> Result<bool, DescriptorRefusal> {
        panic!("the AArch64 walk with HA=HD=0 never updates a descriptor")
    }
    fn store_unlinked(&self, _: u64, _: u64) -> Result<(), DescriptorRefusal> {
        panic!("the walk never stores")
    }
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _: u64, _: u64) {}
}

/// The production image's table bytes at their guest-physical base.
struct ImageWords {
    base: u64,
    bytes: Vec<u8>,
}

impl LiveDescriptorWords for ImageWords {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        let offset = pa
            .checked_sub(self.base)
            .ok_or(DescriptorRefusal::TableOutsidePrimary)? as usize;
        let word = self
            .bytes
            .get(offset..offset + 8)
            .ok_or(DescriptorRefusal::TableOutsidePrimary)?;
        Ok(u64::from_le_bytes(word.try_into().unwrap()))
    }
    fn compare_exchange(&self, _: u64, _: u64, _: u64) -> Result<bool, DescriptorRefusal> {
        panic!("no descriptor update with HA=HD=0")
    }
    fn store_unlinked(&self, _: u64, _: u64) -> Result<(), DescriptorRefusal> {
        panic!("the walk never stores")
    }
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _: u64, _: u64) {}
}

// D5.3 encodings, written out independently of the module's constants.
const TABLE: u64 = 0b11;
const BLOCK: u64 = 0b01;
const PAGE: u64 = 0b11;
const AF: u64 = 1 << 10;
const NG: u64 = 1 << 11;
const AP_EL1_RW: u64 = 0b00 << 6;
const AP_ALL_RW: u64 = 0b01 << 6;
const AP_EL1_RO: u64 = 0b10 << 6;
const AP_ALL_RO: u64 = 0b11 << 6;
const D_PXN: u64 = 1 << 53;
const D_UXN: u64 = 1 << 54;

/// TCR with T0SZ=T1SZ=16, TG1=4K, IPS=40 bits, TBI0/TBI1: the fields the
/// production bootstrap value programs, rebuilt by hand.
const TCR_48: u64 = 16 | (16 << 16) | (0b10 << 30) | (0b010 << 32) | (1 << 37) | (1 << 38);

const ROOT0: u64 = 0x10_0000;
const ROOT1: u64 = 0x20_0000;

fn regime(tcr: u64, sctlr: u64) -> Aarch64Regime {
    Aarch64Regime::new(tcr, ROOT0, ROOT1, sctlr).unwrap()
}

fn ctx(el: Aarch64El, class: Aarch64AccessClass, pan: bool, uao: bool) -> Aarch64WalkContext {
    Aarch64WalkContext {
        regime: regime(TCR_48, 0),
        el,
        pan,
        uao,
        class,
    }
}

fn el0() -> Aarch64WalkContext {
    ctx(Aarch64El::El0, Aarch64AccessClass::Ordinary, false, false)
}
fn el1() -> Aarch64WalkContext {
    ctx(Aarch64El::El1, Aarch64AccessClass::Ordinary, false, false)
}

/// A four-level path from ROOT0 for `va` ending at an L3 page `leaf`.
fn page_tables(va: u64, leaf: u64) -> Words {
    let mut w = Words::new();
    let l0 = w.table(ROOT0);
    let l1 = w.table(0x11_0000);
    let l2 = w.table(0x12_0000);
    let l3 = w.table(0x13_0000);
    w.set(l0, (va >> 39) & 511, l1 | TABLE);
    w.set(l1, (va >> 30) & 511, l2 | TABLE);
    w.set(l2, (va >> 21) & 511, l3 | TABLE);
    w.set(l3, (va >> 12) & 511, leaf);
    w
}

fn walk(
    words: &impl LiveDescriptorWords,
    context: &Aarch64WalkContext,
    va: u64,
    access: LeafAccess,
) -> Result<Aarch64Leaf, WalkError<Aarch64Fault>> {
    Aarch64Walker.walk(words, context, GuestVa::new(va), access)
}

fn fault_of(
    result: Result<Aarch64Leaf, WalkError<Aarch64Fault>>,
) -> Option<(Aarch64FaultKind, Aarch64Level)> {
    match result {
        Ok(_) => None,
        Err(WalkError::Fault(f)) => Some((f.kind, f.level)),
        Err(WalkError::Refusal(r)) => panic!("unexpected refusal {r:?}"),
    }
}

const VA: u64 = 0x0000_1234_5678_9abc;
const OUT: u64 = 0x0000_0080_4321_0000;

#[test]
fn page_walk_translates_with_four_loads_and_exact_span() {
    let w = page_tables(VA, OUT | PAGE | AF | AP_ALL_RW);
    let leaf = walk(&w, &el0(), VA, LeafAccess::Read).unwrap();
    assert_eq!(leaf.output().raw(), OUT | 0xabc);
    assert_eq!(leaf.span().base().raw(), OUT);
    assert_eq!(leaf.span().bytes(), 4096);
    assert_eq!(leaf.level(), Aarch64Level::L3);
    assert_eq!(leaf.range(), VaRange::Lower);
    assert_eq!(
        w.loads.get(),
        4,
        "a cold 48-bit walk reads four descriptors"
    );
}

#[test]
fn blocks_translate_at_l1_and_l2_with_their_spans() {
    let mut w = Words::new();
    let l0 = w.table(ROOT0);
    let l1 = w.table(0x11_0000);
    let l2 = w.table(0x12_0000);
    w.set(l0, 0, l1 | TABLE);
    // L1[1]: 1 GiB block at 0x80_0000_0000 (VA 0x4000_0000..).
    w.set(l1, 1, 0x80_0000_0000 | BLOCK | AF | AP_ALL_RW);
    // L1[2] -> L2; L2[3]: 2 MiB block at 0x40_0060_0000.
    w.set(l1, 2, l2 | TABLE);
    w.set(l2, 3, 0x40_0060_0000 | BLOCK | AF | AP_ALL_RW);
    let giant = walk(&w, &el0(), 0x7654_3210, LeafAccess::Read).unwrap();
    assert_eq!(giant.output().raw(), 0x80_0000_0000 + 0x3654_3210);
    assert_eq!(
        (giant.span().base().raw(), giant.span().bytes()),
        (0x80_0000_0000, 1 << 30)
    );
    assert_eq!(giant.level(), Aarch64Level::L1);
    let big_va = (2 << 30) | (3 << 21) | 0x1_2345;
    let big = walk(&w, &el0(), big_va, LeafAccess::Read).unwrap();
    assert_eq!(big.output().raw(), 0x40_0060_0000 + 0x1_2345);
    assert_eq!(big.span().bytes(), 1 << 21);
    assert_eq!(big.level(), Aarch64Level::L2);
}

#[test]
fn invalid_and_reserved_descriptors_fault_at_their_own_level() {
    use Aarch64FaultKind::Translation;
    // Empty L0 slot.
    let mut w = Words::new();
    w.table(ROOT0);
    assert_eq!(
        fault_of(walk(&w, &el1(), VA, LeafAccess::Read)),
        Some((Translation, Aarch64Level::L0))
    );
    // An L0 block is reserved without LPA2.
    let l0 = ROOT0;
    w.set(l0, (VA >> 39) & 511, 0x80_0000_0000 | BLOCK | AF);
    assert_eq!(
        fault_of(walk(&w, &el1(), VA, LeafAccess::Read)),
        Some((Translation, Aarch64Level::L0))
    );
    // Empty L2 slot.
    let mut w = page_tables(VA, 0);
    w.set(0x12_0000, (VA >> 21) & 511, 0);
    assert_eq!(
        fault_of(walk(&w, &el1(), VA, LeafAccess::Read)),
        Some((Translation, Aarch64Level::L2))
    );
    // L3 type 01 is reserved.
    let w = page_tables(VA, OUT | BLOCK | AF);
    assert_eq!(
        fault_of(walk(&w, &el1(), VA, LeafAccess::Read)),
        Some((Translation, Aarch64Level::L3))
    );
    // An invalid descriptor with a retained output (a prepared or retired
    // owner leaf) is architecturally invalid.
    let w = page_tables(VA, (OUT | PAGE | AF | (1 << 56)) & !1);
    assert_eq!(
        fault_of(walk(&w, &el1(), VA, LeafAccess::Read)),
        Some((Translation, Aarch64Level::L3))
    );
}

#[test]
fn access_flag_clear_faults_before_any_permission_check() {
    // EL0 write to an EL1-only read-only page with AF=0: AF wins (D5.8.3).
    let w = page_tables(VA, OUT | PAGE | AP_EL1_RO);
    assert_eq!(
        fault_of(walk(&w, &el0(), VA, LeafAccess::Write)),
        Some((Aarch64FaultKind::AccessFlag, Aarch64Level::L3))
    );
    let mut w = Words::new();
    let l0 = w.table(ROOT0);
    let l1 = w.table(0x11_0000);
    w.set(l0, 0, l1 | TABLE);
    w.set(l1, 1, 0x80_0000_0000 | BLOCK | AP_ALL_RW);
    assert_eq!(
        fault_of(walk(&w, &el1(), 1 << 30, LeafAccess::Read)),
        Some((Aarch64FaultKind::AccessFlag, Aarch64Level::L1))
    );
}

#[test]
fn ap_matrix_matches_d5_4_for_el0_el1_and_unprivileged_el1() {
    use LeafAccess::{Read, Write};
    let ldtr = ctx(
        Aarch64El::El1,
        Aarch64AccessClass::Unprivileged,
        false,
        false,
    );
    // (AP, EL0 read, EL0 write, EL1 read, EL1 write)
    let matrix = [
        (AP_EL1_RW, false, false, true, true),
        (AP_ALL_RW, true, true, true, true),
        (AP_EL1_RO, false, false, true, false),
        (AP_ALL_RO, true, false, true, false),
    ];
    for (ap, el0_r, el0_w, el1_r, el1_w) in matrix {
        let w = page_tables(VA, OUT | PAGE | AF | ap | D_UXN | D_PXN);
        let ok = |c: &Aarch64WalkContext, a| walk(&w, c, VA, a).is_ok();
        assert_eq!(ok(&el0(), Read), el0_r, "EL0 read AP={ap:#x}");
        assert_eq!(ok(&el0(), Write), el0_w, "EL0 write AP={ap:#x}");
        assert_eq!(ok(&el1(), Read), el1_r, "EL1 read AP={ap:#x}");
        assert_eq!(ok(&el1(), Write), el1_w, "EL1 write AP={ap:#x}");
        // LDTR/STTR at EL1 with UAO=0 use the EL0 column.
        assert_eq!(ok(&ldtr, Read), el0_r, "LDTR AP={ap:#x}");
        assert_eq!(ok(&ldtr, Write), el0_w, "STTR AP={ap:#x}");
        // At EL0 the unprivileged class is just an EL0 access.
        let el0_ldtr = ctx(
            Aarch64El::El0,
            Aarch64AccessClass::Unprivileged,
            false,
            false,
        );
        assert_eq!(ok(&el0_ldtr, Read), el0_r);
        if !el0_w {
            assert_eq!(
                fault_of(walk(&w, &el0(), VA, Write)),
                Some((Aarch64FaultKind::Permission, Aarch64Level::L3))
            );
        }
    }
}

#[test]
fn pan_denies_privileged_data_to_el0_pages_ldtr_bypasses_it_unless_uao() {
    use Aarch64AccessClass::{Ordinary, Unprivileged};
    use LeafAccess::{Execute, Read, Write};
    let user = page_tables(VA, OUT | PAGE | AF | AP_ALL_RW);
    let kernel = page_tables(VA, OUT | PAGE | AF | AP_EL1_RW | D_UXN);
    let pan = ctx(Aarch64El::El1, Ordinary, true, false);
    let ldtr_pan = ctx(Aarch64El::El1, Unprivileged, true, false);
    let ldtr_uao_pan = ctx(Aarch64El::El1, Unprivileged, true, true);
    let ldtr_uao = ctx(Aarch64El::El1, Unprivileged, false, true);
    // PAN=1: ordinary EL1 load/store to an EL0-accessible page faults.
    for access in [Read, Write] {
        assert_eq!(
            fault_of(walk(&user, &pan, VA, access)),
            Some((Aarch64FaultKind::Permission, Aarch64Level::L3))
        );
        assert!(walk(&kernel, &pan, VA, access).is_ok());
        // LDTR/STTR (UAO=0) check EL0 permissions: PAN does not apply.
        assert!(walk(&user, &ldtr_pan, VA, access).is_ok());
        assert!(walk(&kernel, &ldtr_pan, VA, access).is_err());
        // UAO=1: unprivileged instructions behave as ordinary EL1 accesses,
        // PAN included.
        assert!(walk(&user, &ldtr_uao_pan, VA, access).is_err());
        assert!(walk(&kernel, &ldtr_uao, VA, access).is_ok());
    }
    // PAN never restricts instruction fetch (FEAT_PAN3 not implemented, so
    // EPAN is RES0 even when set).
    let exec = page_tables(VA, OUT | PAGE | AF | AP_EL1_RO | D_UXN);
    let epan = Aarch64WalkContext {
        regime: regime(TCR_48, 1 << 57),
        ..pan
    };
    assert!(walk(&exec, &pan, VA, Execute).is_ok());
    assert!(walk(&exec, &epan, VA, Execute).is_ok());
}

#[test]
fn execute_never_rules_uxn_pxn_el0_writable_and_wxn() {
    use LeafAccess::Execute;
    let perm = Some((Aarch64FaultKind::Permission, Aarch64Level::L3));
    // EL0 execute-only: AP=00 with UXN=0 is executable at EL0.
    let xom = page_tables(VA, OUT | PAGE | AF | AP_EL1_RW | D_PXN);
    assert!(walk(&xom, &el0(), VA, Execute).is_ok());
    assert_eq!(fault_of(walk(&xom, &el1(), VA, Execute)), perm);
    // UXN denies EL0, PXN denies EL1.
    let kernel = page_tables(VA, OUT | PAGE | AF | AP_EL1_RO | D_UXN);
    assert_eq!(fault_of(walk(&kernel, &el0(), VA, Execute)), perm);
    assert!(walk(&kernel, &el1(), VA, Execute).is_ok());
    // EL0-writable memory is privileged execute-never even with PXN=0.
    let user_rw = page_tables(VA, OUT | PAGE | AF | AP_ALL_RW);
    assert_eq!(fault_of(walk(&user_rw, &el1(), VA, Execute)), perm);
    assert!(walk(&user_rw, &el0(), VA, Execute).is_ok());
    // WXN: writable at the fetching EL is execute-never.
    let wxn = |el| Aarch64WalkContext {
        regime: regime(TCR_48, 1 << 19),
        ..ctx(el, Aarch64AccessClass::Ordinary, false, false)
    };
    assert_eq!(
        fault_of(walk(&user_rw, &wxn(Aarch64El::El0), VA, Execute)),
        perm
    );
    let kernel_rw = page_tables(VA, OUT | PAGE | AF | AP_EL1_RW | D_UXN);
    assert!(walk(&kernel_rw, &el1(), VA, Execute).is_ok());
    assert_eq!(
        fault_of(walk(&kernel_rw, &wxn(Aarch64El::El1), VA, Execute)),
        perm
    );
    // Read-only memory stays executable under WXN.
    assert!(walk(&kernel, &wxn(Aarch64El::El1), VA, Execute).is_ok());
}

#[test]
fn table_restrictions_fold_into_the_leaf_permission() {
    use LeafAccess::{Execute, Read, Write};
    let perm = Some((Aarch64FaultKind::Permission, Aarch64Level::L3));
    let with_l1_table_bits = |bits: u64| {
        let mut w = page_tables(VA, OUT | PAGE | AF | AP_ALL_RW);
        w.set(ROOT0, (VA >> 39) & 511, 0x11_0000 | TABLE | bits);
        w
    };
    // APTable[0] (bit 61): no EL0 access, and so no PAN fault at EL1.
    let no_el0 = with_l1_table_bits(1 << 61);
    assert_eq!(fault_of(walk(&no_el0, &el0(), VA, Read)), perm);
    let pan = ctx(Aarch64El::El1, Aarch64AccessClass::Ordinary, true, false);
    assert!(walk(&no_el0, &pan, VA, Write).is_ok());
    // APTable[1] (bit 62): read-only at every EL.
    let ro = with_l1_table_bits(1 << 62);
    assert!(walk(&ro, &el0(), VA, Read).is_ok());
    assert_eq!(fault_of(walk(&ro, &el0(), VA, Write)), perm);
    assert_eq!(fault_of(walk(&ro, &el1(), VA, Write)), perm);
    // UXNTable (bit 60) and PXNTable (bit 59).
    let uxn = with_l1_table_bits(1 << 60);
    assert_eq!(fault_of(walk(&uxn, &el0(), VA, Execute)), perm);
    let mut kernel = page_tables(VA, OUT | PAGE | AF | AP_EL1_RO);
    assert!(walk(&kernel, &el1(), VA, Execute).is_ok());
    kernel.set(0x11_0000, (VA >> 30) & 511, 0x12_0000 | TABLE | (1 << 59));
    assert_eq!(fault_of(walk(&kernel, &el1(), VA, Execute)), perm);
}

#[test]
fn ttbr_split_selects_by_bit_55_under_tbi_and_checks_the_range() {
    use LeafAccess::Read;
    let low_va = 0x0000_0000_4000_1000_u64;
    let high_va = 0xffff_ffff_c000_1000_u64;
    let mut w = Words::new();
    let l0_low = w.table(ROOT0);
    let l1_low = w.table(0x11_0000);
    let l0_high = w.table(ROOT1);
    let l1_high = w.table(0x21_0000);
    w.set(l0_low, 0, l1_low | TABLE);
    w.set(l1_low, 1, 0x40_0000_0000 | BLOCK | AF | AP_ALL_RW);
    w.set(l0_high, 511, l1_high | TABLE);
    w.set(l1_high, 511, 0x50_0000_0000 | BLOCK | AF | AP_EL1_RW);
    let low = walk(&w, &el1(), low_va, Read).unwrap();
    assert_eq!(
        (low.output().raw(), low.range()),
        (0x40_0000_1000, VaRange::Lower)
    );
    let high = walk(&w, &el1(), high_va, Read).unwrap();
    assert_eq!(
        (high.output().raw(), high.range()),
        (0x50_0000_1000, VaRange::Upper)
    );
    // TBI: a tagged lower pointer translates as its untagged address.
    let tagged = walk(&w, &el1(), low_va | (0x5a << 56), Read).unwrap();
    assert_eq!(tagged.output(), low.output());
    // A tag on an upper pointer with bit 55 set still selects TTBR1.
    let tagged_high = walk(&w, &el1(), (high_va & !(0xff << 56)) | (0x12 << 56), Read).unwrap();
    assert_eq!(tagged_high.output(), high.output());
    // Bits 55:48 must equal the range bit.
    let hole = 0x0001_0000_0000_0000_u64;
    let err = walk(&w, &el1(), hole, Read).unwrap_err();
    assert_eq!(
        err,
        WalkError::Fault(Aarch64Fault {
            kind: Aarch64FaultKind::Translation,
            level: Aarch64Level::L0,
            va: GuestVa::new(hole),
            access: Read,
        })
    );
    // Without TBI0 the top byte is checked: a tag faults at level 0.
    let no_tbi = Aarch64WalkContext {
        regime: regime(TCR_48 & !(1 << 37), 0),
        ..el1()
    };
    assert_eq!(
        fault_of(walk(&w, &no_tbi, low_va | (0x5a << 56), Read)),
        Some((Aarch64FaultKind::Translation, Aarch64Level::L0))
    );
    assert!(walk(&w, &no_tbi, low_va, Read).is_ok());
    // EPD1 disables TTBR1 walks: a level-0 translation fault, no load.
    let epd1 = Aarch64WalkContext {
        regime: regime(TCR_48 | (1 << 23), 0),
        ..el1()
    };
    w.loads.set(0);
    assert_eq!(
        fault_of(walk(&w, &epd1, high_va, Read)),
        Some((Aarch64FaultKind::Translation, Aarch64Level::L0))
    );
    assert_eq!(w.loads.get(), 0);
    assert!(walk(&w, &epd1, low_va, Read).is_ok());
}

#[test]
fn root_switch_retranslates_the_same_va() {
    let a = page_tables(VA, OUT | PAGE | AF | AP_ALL_RW);
    let mut b = Words::new();
    let l0 = b.table(0x30_0000);
    let l1 = b.table(0x31_0000);
    b.set(l0, (VA >> 39) & 511, l1 | TABLE);
    b.set(
        l1,
        (VA >> 30) & 511,
        0x90_0000_0000 | BLOCK | AF | AP_ALL_RO | NG,
    );
    let mut context = el0();
    let first = walk(&a, &context, VA, LeafAccess::Write).unwrap();
    assert_eq!(first.output().raw(), OUT | 0xabc);
    context.regime = Aarch64Regime::new(TCR_48, 0x30_0000 | (7 << 48), ROOT1, 0).unwrap();
    let second = walk(&b, &context, VA, LeafAccess::Read).unwrap();
    assert_eq!(
        second.output().raw(),
        0x90_0000_0000 | (VA & ((1 << 30) - 1))
    );
    assert_eq!(
        fault_of(walk(&b, &context, VA, LeafAccess::Write)),
        Some((Aarch64FaultKind::Permission, Aarch64Level::L1))
    );
    // Through the first root's words the second root has no tables.
    assert_eq!(
        walk(&a, &context, VA, LeafAccess::Read),
        Err(WalkError::Refusal(DescriptorRefusal::MissingTable))
    );
}

#[test]
fn ng_and_the_tcr_selected_asid_are_reported() {
    let global = page_tables(VA, OUT | PAGE | AF | AP_ALL_RW | (0b101 << 2) | (1 << 52));
    let leaf = walk(&global, &el0(), VA, LeafAccess::Read).unwrap();
    assert!(leaf.global());
    assert_eq!(leaf.attr_index(), 0b101);
    assert!(leaf.contiguous_hint());
    assert_eq!(leaf.span().bytes(), 4096, "the hint never widens the span");
    let private = page_tables(VA, OUT | PAGE | AF | AP_ALL_RW | NG);
    let ttbr0 = ROOT0 | (0x1234 << 48);
    let ttbr1 = ROOT1 | (0x5678 << 48);
    let with = |tcr| Aarch64WalkContext {
        regime: Aarch64Regime::new(tcr, ttbr0, ttbr1, 0).unwrap(),
        ..el0()
    };
    let leaf = walk(&private, &with(TCR_48), VA, LeafAccess::Read).unwrap();
    assert!(!leaf.global());
    assert_eq!(leaf.asid(), 0x34, "AS=0: 8-bit ASID from TTBR0");
    let as16 = TCR_48 | (1 << 36);
    assert_eq!(with(as16).regime.asid(), 0x1234);
    assert_eq!(
        with(as16 | (1 << 22)).regime.asid(),
        0x5678,
        "A1 selects TTBR1"
    );
}

#[test]
fn address_size_faults_for_ttbr_table_and_output_above_ips() {
    use Aarch64FaultKind::AddressSize;
    // IPS = 40 bits.
    let too_high = 1u64 << 40;
    let mut context = el1();
    context.regime = Aarch64Regime::new(TCR_48, too_high, ROOT1, 0).unwrap();
    let w = page_tables(VA, OUT | PAGE | AF);
    assert_eq!(
        fault_of(walk(&w, &context, VA, LeafAccess::Read)),
        Some((AddressSize, Aarch64Level::L0))
    );
    let mut w = page_tables(VA, OUT | PAGE | AF);
    w.set(0x11_0000, (VA >> 30) & 511, too_high | TABLE);
    assert_eq!(
        fault_of(walk(&w, &el1(), VA, LeafAccess::Read)),
        Some((AddressSize, Aarch64Level::L1))
    );
    let w = page_tables(VA, too_high | PAGE | AF);
    assert_eq!(
        fault_of(walk(&w, &el1(), VA, LeafAccess::Read)),
        Some((AddressSize, Aarch64Level::L3))
    );
    // The same output is in range with IPS = 48 bits.
    let mut wide = el1();
    wide.regime = regime((TCR_48 & !(0b111 << 32)) | (0b101 << 32), 0);
    assert_eq!(
        walk(&w, &wide, VA, LeafAccess::Read)
            .unwrap()
            .output()
            .raw(),
        too_high | 0xabc
    );
}

#[test]
fn smaller_input_size_starts_at_a_later_level() {
    // T0SZ = 25: 39-bit input, start at L1 with a full 512-entry table.
    let tcr = (TCR_48 & !0x3f) | 25;
    let mut w = Words::new();
    let l1 = w.table(ROOT0);
    w.set(l1, 3, 0x80_0000_0000 | BLOCK | AF | AP_ALL_RW);
    let context = Aarch64WalkContext {
        regime: regime(tcr, 0),
        ..el0()
    };
    let leaf = walk(&w, &context, (3 << 30) | 0x10, LeafAccess::Read).unwrap();
    assert_eq!(leaf.output().raw(), 0x80_0000_0010);
    assert_eq!(w.loads.get(), 1);
    // Bit 39 is outside a 39-bit lower range.
    assert_eq!(
        fault_of(walk(&w, &context, 1 << 39, LeafAccess::Read)),
        Some((Aarch64FaultKind::Translation, Aarch64Level::L0))
    );
    // T0SZ = 24: 40-bit input, L0 start table of two entries (16 bytes).
    let tcr = (TCR_48 & !0x3f) | 24;
    let mut w = Words::new();
    let l0 = w.table(ROOT0);
    let l1 = w.table(0x11_0000);
    w.set(l0, 1, l1 | TABLE);
    w.set(l1, 0, 0x80_0000_0000 | BLOCK | AF | AP_ALL_RW);
    let context = Aarch64WalkContext {
        regime: regime(tcr, 0),
        ..el0()
    };
    let leaf = walk(&w, &context, 1 << 39, LeafAccess::Read).unwrap();
    assert_eq!(leaf.output().raw(), 0x80_0000_0000);
}

#[test]
fn descriptor_memory_refusal_is_not_a_guest_fault() {
    let w = Words::new();
    assert_eq!(
        walk(&w, &el1(), VA, LeafAccess::Read),
        Err(WalkError::Refusal(DescriptorRefusal::MissingTable))
    );
}

#[test]
fn regime_admission_refuses_what_the_profile_does_not_implement() {
    assert!(Aarch64Regime::new(TCR_EL1_BOOTSTRAP, 0, 0, SCTLR_EL1_BOOTSTRAP).is_ok());
    assert_eq!(TCR_EL1_BOOTSTRAP, TCR_48 | (0x3f << 8) | (0x3f << 24));
    let refuse = |tcr| Aarch64Regime::new(tcr, 0, 0, 0).unwrap_err();
    assert_eq!(
        refuse(TCR_48 | (0b10 << 14)),
        UnsupportedRegime::Granule {
            upper: false,
            encoding: 0b10
        }
    );
    assert_eq!(
        refuse(TCR_48 & !(0b11 << 30) | (0b01 << 30)),
        UnsupportedRegime::Granule {
            upper: true,
            encoding: 0b01
        }
    );
    assert_eq!(
        refuse((TCR_48 & !0x3f) | 12),
        UnsupportedRegime::InputSize {
            upper: false,
            tnsz: 12
        }
    );
    assert_eq!(
        refuse((TCR_48 & !(0x3f << 16)) | (40 << 16)),
        UnsupportedRegime::InputSize {
            upper: true,
            tnsz: 40
        }
    );
    assert_eq!(
        refuse(TCR_48 | (0b110 << 32)),
        UnsupportedRegime::OutputSize { ips: 0b110 }
    );
    for bit in [39, 40, 41, 42, 43, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59] {
        assert_eq!(
            refuse(TCR_48 | (1 << bit)),
            UnsupportedRegime::Feature { bits: 1 << bit },
            "TCR bit {bit}"
        );
    }
}

#[test]
fn fault_status_codes_are_the_esr_fsc_values() {
    let f = |kind, level| {
        Aarch64Fault {
            kind,
            level,
            va: GuestVa::new(0),
            access: LeafAccess::Read,
        }
        .status_code()
    };
    use Aarch64FaultKind::*;
    use Aarch64Level::*;
    assert_eq!(f(AddressSize, L0), 0x00);
    assert_eq!(f(Translation, L0), 0x04);
    assert_eq!(f(Translation, L3), 0x07);
    assert_eq!(f(AccessFlag, L1), 0x09);
    assert_eq!(f(AccessFlag, L3), 0x0b);
    assert_eq!(f(Permission, L2), 0x0e);
    assert_eq!(f(Permission, L3), 0x0f);
}

fn production() -> (ImageWords, Aarch64Regime) {
    let words = ImageWords {
        base: LINUX_PAGE_TABLES_BASE,
        bytes: stage1_identity_page_tables(),
    };
    // Bootstrap programs both TTBRs to the table base (ASID 0).
    let regime = Aarch64Regime::new(
        TCR_EL1_BOOTSTRAP,
        LINUX_PAGE_TABLES_BASE,
        LINUX_PAGE_TABLES_BASE,
        SCTLR_EL1_BOOTSTRAP,
    )
    .unwrap();
    (words, regime)
}

#[test]
fn production_identity_tables_enforce_the_hardware_permissions() {
    use Aarch64AccessClass::{Ordinary, Unprivileged};
    use LeafAccess::{Execute, Read, Write};
    let (words, regime) = production();
    let c = |el, class, pan| Aarch64WalkContext {
        regime,
        el,
        pan,
        uao: false,
        class,
    };
    let el0 = c(Aarch64El::El0, Ordinary, false);
    let el1 = c(Aarch64El::El1, Ordinary, false);
    let el1_pan = c(Aarch64El::El1, Ordinary, true);
    let ldtr_pan = c(Aarch64El::El1, Unprivileged, true);
    let perm = |level| Some((Aarch64FaultKind::Permission, level));
    // The null guard is unmapped at L3.
    for va in [0, 0x8000, LINUX_NULL_GUARD_END - 1] {
        assert_eq!(
            fault_of(walk(&words, &el0, va, Read)),
            Some((Aarch64FaultKind::Translation, Aarch64Level::L3)),
            "{va:#x}"
        );
    }
    // The first user page after the guard: EL0 RW + exec, EL1 no exec.
    let user = LINUX_NULL_GUARD_END;
    let leaf = walk(&words, &el0, user, Write).unwrap();
    assert_eq!(
        (leaf.output().raw(), leaf.level()),
        (user, Aarch64Level::L3)
    );
    assert!(walk(&words, &el0, user, Execute).is_ok());
    assert_eq!(
        fault_of(walk(&words, &el1, user, Execute)),
        perm(Aarch64Level::L3)
    );
    // PAN: privileged data access to a user page faults; LDTR does not.
    assert_eq!(
        fault_of(walk(&words, &el1_pan, user, Read)),
        perm(Aarch64Level::L3)
    );
    assert!(walk(&words, &ldtr_pan, user, Read).is_ok());
    assert!(walk(&words, &el1, user, Write).is_ok());
    // The kernel hole's first 2 MiB: EL1 RW + exec, EL0 nothing.
    let kernel = LINUX_KERNEL_REGION_BASE;
    let leaf = walk(&words, &el1, kernel, Execute).unwrap();
    assert_eq!(leaf.level(), Aarch64Level::L2);
    assert_eq!(leaf.span().bytes(), 1 << 21);
    assert!(walk(&words, &el1_pan, kernel, Write).is_ok());
    for access in [Read, Write, Execute] {
        assert_eq!(
            fault_of(walk(&words, &el0, kernel, access)),
            perm(Aarch64Level::L2)
        );
    }
    // An LDTR from EL1 into the kernel hole is checked as EL0.
    assert_eq!(
        fault_of(walk(&words, &ldtr_pan, kernel, Read)),
        perm(Aarch64Level::L2)
    );
    // The Rosetta alias: a nonidentity L2 user block high in the lower range.
    let rosetta = walk(&words, &el0, LINUX_ROSETTA_VA_BASE + 0x1234, Read).unwrap();
    assert_eq!(rosetta.output().raw(), LINUX_ROSETTA_IPA_BASE + 0x1234);
    assert_eq!(rosetta.level(), Aarch64Level::L2);
    // Boot leaves are global (nG clear).
    assert!(rosetta.global());
    // The upper range uses TTBR1 (here the same root): VA bit 55 set,
    // bits 47:39 index L0[511], which the boot tables leave empty.
    assert_eq!(
        fault_of(walk(&words, &el1, 0xffff_ff80_0000_0000, Read)),
        Some((Aarch64FaultKind::Translation, Aarch64Level::L0))
    );
}

#[test]
fn production_walk_agrees_with_the_existing_raw_walk_on_outputs() {
    let (words, regime) = production();
    let context = Aarch64WalkContext {
        regime,
        el: Aarch64El::El1,
        pan: false,
        uao: false,
        class: Aarch64AccessClass::Ordinary,
    };
    let mut va = 0u64;
    let mut checked = 0;
    // Sample the low 2 MiB pages, the kernel L2 region and 1 GiB blocks.
    let mut samples: Vec<u64> = (0..512).map(|i| i << 12).collect();
    samples.extend((0..512).map(|i| LINUX_KERNEL_REGION_BASE + (i << 21) + 0x40));
    samples.extend((1..512).map(|i| (i << 30) + 0x123));
    samples.push(LINUX_ROSETTA_VA_BASE + 0x777);
    for sample in samples {
        va = sample;
        let raw = super::super::walk_descriptors(&words.bytes, words.base, va);
        let (level, descriptor) = super::super::terminal_entry(raw);
        let ours = walk(&words, &context, va, LeafAccess::Read);
        if descriptor & 1 == 0 {
            assert!(
                matches!(ours, Err(WalkError::Fault(f)) if f.kind == Aarch64FaultKind::Translation && f.level as usize == level),
                "{va:#x}: {ours:?}"
            );
            continue;
        }
        let leaf = ours.unwrap_or_else(|e| panic!("{va:#x}: {e:?}"));
        assert_eq!(leaf.level() as usize, level, "{va:#x}");
        assert_eq!(leaf.descriptor(), descriptor, "{va:#x}");
        checked += 1;
    }
    assert!(
        checked > 1000,
        "{checked} translations compared, last {va:#x}"
    );
}

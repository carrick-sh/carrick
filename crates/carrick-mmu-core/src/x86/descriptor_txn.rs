//! Four-level, 4 KiB x86 descriptor transactions. No MM or reservation ledger.
pub use crate::aarch64::descriptor_txn::{
    BackingIdentity, DescriptorJournal, DescriptorRefusal, DescriptorTxnId, InlineJournal,
    JournalEntry, LiveDescriptorWords, PageSpan,
};
use alloc::{collections::BTreeMap, vec::Vec};
use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};

pub const PAGE: u64 = 4096;
pub const PRESENT: u64 = 1;
pub const WRITE: u64 = 1 << 1;
pub const USER: u64 = 1 << 2;
pub const HUGE: u64 = 1 << 7;
pub const PREPARED: u64 = 1 << 9;
pub const COW: u64 = 1 << 10;
pub const MAY_WRITE: u64 = 1 << 11;
pub const NX: u64 = 1 << 63;
pub const ADDRESS: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    pub writable: bool,
    pub executable: bool,
    pub user: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafSize {
    Page,
    Block2M,
    Block1G,
}
impl LeafSize {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Page => PAGE,
            Self::Block2M => 1 << 21,
            Self::Block1G => 1 << 30,
        }
    }
    const fn level(self) -> usize {
        match self {
            Self::Page => 3,
            Self::Block2M => 2,
            Self::Block1G => 1,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorOp {
    Map {
        span: PageSpan,
        output: FrameGpa,
        permissions: Permissions,
        size: LeafSize,
        resident: bool,
        backing: BackingIdentity,
    },
    Publish {
        span: PageSpan,
        expected: FrameGpa,
    },
    Protect {
        span: PageSpan,
        permissions: Permissions,
    },
    ArmCow(PageSpan),
    CowRepoint {
        span: PageSpan,
        old: FrameGpa,
        new: FrameGpa,
        backing: BackingIdentity,
    },
    Unmap(PageSpan),
    Coalesce {
        span: PageSpan,
        size: LeafSize,
    },
}
impl DescriptorOp {
    pub fn span(self) -> PageSpan {
        match self {
            Self::Map { span, .. }
            | Self::Publish { span, .. }
            | Self::Protect { span, .. }
            | Self::CowRepoint { span, .. }
            | Self::Coalesce { span, .. }
            | Self::ArmCow(span)
            | Self::Unmap(span) => span,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct DescriptorTxn<'a> {
    pub id: DescriptorTxnId,
    pub root: RootGpa,
    pub op: DescriptorOp,
    pub tables: &'a [RootGpa],
}
#[derive(Clone, Debug)]
pub struct DescriptorPlan {
    entries: Vec<JournalEntry>,
    pub tables_linked: usize,
    pub words_read: usize,
    id: DescriptorTxnId,
    digest: u64,
    span: PageSpan,
}
impl DescriptorPlan {
    pub fn live_stores(&self) -> usize {
        self.entries.len()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorOutcome {
    Applied { stores: usize, tables_linked: usize },
    Refused(DescriptorRefusal),
    RolledBack(DescriptorRefusal),
    Indeterminate(DescriptorRefusal),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorReceipt {
    pub id: DescriptorTxnId,
    pub outcome: DescriptorOutcome,
    digest: u64,
}

/// Plan under the exact-MM editor. Grants must be exclusively owned, unlinked
/// zero pages. All walks and allocation/journal capacity checks precede stores.
/// No hardware A/D writer may race this editor; a violated exclusion poisons
/// rollback rather than discarding hardware changes.
pub fn plan_descriptor_txn<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    txn: &DescriptorTxn<'_>,
    live_root: RootGpa,
) -> Result<DescriptorPlan, DescriptorRefusal> {
    if txn.root != live_root {
        return Err(DescriptorRefusal::StaleRoot);
    }
    let span = txn.op.span();
    if !valid_span(span) || !valid_pa(txn.root.address().raw()) || txn.root.address().raw() == 0 {
        return Err(DescriptorRefusal::BadRange);
    }
    if txn.tables.len() > crate::aarch64::descriptor_txn::MAX_TABLE_GRANTS {
        return Err(DescriptorRefusal::TablesExhausted);
    }
    let mut editor = Planner {
        words,
        txn,
        overlay: BTreeMap::new(),
        entries: Vec::new(),
        used: 0,
        reads: 0,
    };
    for (i, grant) in txn.tables.iter().enumerate() {
        let pa = grant.address().raw();
        if !valid_pa(pa) || pa == 0 || *grant == txn.root || txn.tables[..i].contains(grant) {
            return Err(DescriptorRefusal::BadTableGrant);
        }
        for offset in (0..PAGE).step_by(8) {
            if editor.read(pa + offset)? != 0 {
                return Err(DescriptorRefusal::BadTableGrant);
            }
        }
    }
    let size = match txn.op {
        DescriptorOp::Map { size, .. } | DescriptorOp::Coalesce { size, .. } => size,
        _ => LeafSize::Page,
    };
    if !span.va.is_multiple_of(size.bytes()) || !span.len.is_multiple_of(size.bytes()) {
        return Err(DescriptorRefusal::BadRange);
    }
    match txn.op {
        DescriptorOp::Map { output, .. } => validate_output(output, span.len, size.bytes())?,
        DescriptorOp::Publish { expected, .. } => validate_output(expected, span.len, PAGE)?,
        DescriptorOp::CowRepoint { old, new, .. } => {
            validate_output(old, span.len, PAGE)?;
            validate_output(new, span.len, PAGE)?;
            if old == new {
                return Err(DescriptorRefusal::WrongBacking);
            }
        }
        DescriptorOp::Coalesce {
            size: LeafSize::Page,
            ..
        } => return Err(DescriptorRefusal::BadRange),
        _ => {}
    }
    let mut offset = 0;
    while offset < span.len {
        offset += editor.edit(
            txn.root.address().raw(),
            0,
            span.va + offset,
            offset,
            size.level(),
        )?;
    }
    Ok(DescriptorPlan {
        entries: editor.entries,
        tables_linked: editor.used,
        words_read: editor.reads,
        id: txn.id,
        digest: txn.digest(),
        span,
    })
}

fn valid_pa(pa: u64) -> bool {
    pa & !ADDRESS == 0
}
fn canonical(va: u64) -> bool {
    !((1 << 47)..0xffff_8000_0000_0000).contains(&va)
}
fn valid_span(span: PageSpan) -> bool {
    span.len != 0
        && span.va.is_multiple_of(PAGE)
        && span.len.is_multiple_of(PAGE)
        && span.end().is_some_and(|end| {
            canonical(span.va) && canonical(end - 1) && ((span.va ^ (end - 1)) >> 47 == 0)
        })
}
fn validate_output(output: FrameGpa, len: u64, alignment: u64) -> Result<(), DescriptorRefusal> {
    if !valid_pa(output.raw())
        || !output.raw().is_multiple_of(alignment)
        || output
            .raw()
            .checked_add(len)
            .is_none_or(|end| end > (1 << 52))
    {
        return Err(DescriptorRefusal::BadRange);
    }
    Ok(())
}
fn level_bytes(level: usize) -> u64 {
    1u64 << (39 - level * 9)
}
fn leaf_output(entry: u64, level: usize) -> u64 {
    (entry & ADDRESS) & !(level_bytes(level) - 1)
}
fn permissions(p: Permissions) -> u64 {
    (if p.writable { WRITE | MAY_WRITE } else { 0 })
        | (if p.executable { 0 } else { NX })
        | (if p.user { USER } else { 0 })
}
const ACCESSED: u64 = 1 << 5;
const DIRTY: u64 = 1 << 6;
const PAT_LARGE: u64 = 1 << 12;
const FLAGS: u64 = PRESENT
    | WRITE
    | USER
    | (1 << 3)
    | (1 << 4)
    | ACCESSED
    | DIRTY
    | HUGE
    | PREPARED
    | COW
    | MAY_WRITE
    | NX;
fn validate_entry(entry: u64, level: usize) -> Result<(), DescriptorRefusal> {
    if entry & !(ADDRESS | FLAGS) != 0 || (level == 0 && entry & HUGE != 0) {
        return Err(DescriptorRefusal::Malformed);
    }
    if level < 3
        && entry & HUGE != 0
        && entry & (level_bytes(level) - 1) & ADDRESS & !PAT_LARGE != 0
    {
        return Err(DescriptorRefusal::Malformed);
    }
    if level < 3 && entry & HUGE == 0 && entry & (PREPARED | COW | MAY_WRITE) != 0 {
        return Err(DescriptorRefusal::Malformed);
    }
    Ok(())
}
struct Planner<'a, 't, W: LiveDescriptorWords + ?Sized> {
    words: &'a W,
    txn: &'a DescriptorTxn<'t>,
    overlay: BTreeMap<u64, u64>,
    entries: Vec<JournalEntry>,
    used: usize,
    reads: usize,
}
impl<W: LiveDescriptorWords + ?Sized> Planner<'_, '_, W> {
    fn read(&mut self, pa: u64) -> Result<u64, DescriptorRefusal> {
        if let Some(value) = self.overlay.get(&pa) {
            return Ok(*value);
        }
        self.reads += 1;
        self.words.load(pa)
    }
    fn set(&mut self, pa: u64, after: u64) -> Result<(), DescriptorRefusal> {
        let before = self.read(pa)?;
        if before == after {
            return Ok(());
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| DescriptorRefusal::JournalCapacity)?;
        self.entries.push(JournalEntry {
            pa,
            before,
            after,
            bbm_va: 0,
            bbm_len: 0,
        });
        self.overlay.insert(pa, after);
        Ok(())
    }
    fn grant(&mut self) -> Result<u64, DescriptorRefusal> {
        let page = self
            .txn
            .tables
            .get(self.used)
            .ok_or(DescriptorRefusal::TablesExhausted)?
            .address()
            .raw();
        self.used += 1;
        Ok(page)
    }
    fn split(&mut self, entry: u64, level: usize) -> Result<u64, DescriptorRefusal> {
        let child = self.grant()?;
        let output = leaf_output(entry, level);
        let mut flags = entry & !ADDRESS;
        let pat = entry & PAT_LARGE != 0;
        flags &= !HUGE;
        if level + 1 < 3 {
            flags |= HUGE;
            if pat {
                flags |= PAT_LARGE;
            }
        } else if pat {
            flags |= HUGE;
        }
        for index in 0..512 {
            self.set(
                child + index * 8,
                (output + index * level_bytes(level + 1)) | flags,
            )?;
        }
        Ok(child)
    }
    fn edit(
        &mut self,
        table: u64,
        level: usize,
        va: u64,
        offset: u64,
        target: usize,
    ) -> Result<u64, DescriptorRefusal> {
        // A supplied grant cannot also be a preexisting reachable table.
        if self.txn.tables[self.used..]
            .iter()
            .any(|g| g.address().raw() == table)
        {
            return Err(DescriptorRefusal::BadTableGrant);
        }
        let slot = table + ((va >> (39 - level * 9)) & 511) * 8;
        let entry = self.read(slot)?;
        validate_entry(entry, level)?;
        let bytes = level_bytes(level);
        let remaining = self.txn.op.span().len - offset;
        if entry == 0 && matches!(self.txn.op, DescriptorOp::Unmap(_)) {
            return Ok(remaining.min(bytes - (va & (bytes - 1))));
        }
        let coarse = level > 0
            && level < 3
            && entry & HUGE != 0
            && va.is_multiple_of(bytes)
            && remaining >= bytes
            && match self.txn.op {
                DescriptorOp::Protect { .. }
                | DescriptorOp::ArmCow(_)
                | DescriptorOp::Unmap(_)
                | DescriptorOp::Publish { .. } => true,
                DescriptorOp::CowRepoint { new, .. } => (new.raw() + offset).is_multiple_of(bytes),
                _ => false,
            };
        if level == target || coarse {
            self.terminal(slot, entry, level, offset)?;
            return Ok(bytes);
        }
        let child;
        let mut link = None;
        if entry == 0 {
            if !matches!(self.txn.op, DescriptorOp::Map { .. }) {
                return Err(DescriptorRefusal::MissingTable);
            }
            child = self.grant()?;
            link = Some(child | PRESENT | WRITE | USER);
        } else if entry & HUGE != 0 {
            child = self.split(entry, level)?;
            link = Some(child | PRESENT | WRITE | USER);
        } else {
            if entry & PRESENT == 0 || entry & WRITE == 0 || entry & USER == 0 || entry & NX != 0 {
                return Err(DescriptorRefusal::PermissionDenied);
            }
            child = entry & ADDRESS;
            if child == 0 {
                return Err(DescriptorRefusal::MissingTable);
            }
        }
        let advanced = self.edit(child, level + 1, va, offset, target)?;
        // Descendants are initialized before their first reachable parent link.
        if let Some(value) = link {
            self.set(slot, value)?;
        }
        Ok(advanced)
    }
    fn terminal(
        &mut self,
        slot: u64,
        entry: u64,
        level: usize,
        offset: u64,
    ) -> Result<(), DescriptorRefusal> {
        if level < 3
            && entry != 0
            && entry & HUGE == 0
            && !matches!(self.txn.op, DescriptorOp::Coalesce { .. })
        {
            return Err(DescriptorRefusal::Occupied);
        }
        let new = match self.txn.op {
            DescriptorOp::Map {
                output,
                permissions: p,
                resident,
                ..
            } => {
                if entry != 0 {
                    return Err(DescriptorRefusal::Occupied);
                }
                (output.raw() + offset)
                    | permissions(p)
                    | if resident { PRESENT } else { PREPARED }
                    | if level < 3 { HUGE } else { 0 }
            }
            DescriptorOp::Publish { expected, .. } => {
                if entry & PREPARED == 0 || entry & PRESENT != 0 {
                    return Err(DescriptorRefusal::NotPrepared);
                }
                if leaf_output(entry, level) != expected.raw() + offset {
                    return Err(DescriptorRefusal::WrongBacking);
                }
                (entry | PRESENT) & !PREPARED
            }
            DescriptorOp::Protect { permissions: p, .. } => {
                if entry & (PRESENT | PREPARED) == 0 {
                    return Err(DescriptorRefusal::MissingTable);
                }
                if entry & COW != 0 {
                    return Err(DescriptorRefusal::CowArmed);
                }
                entry & !(WRITE | USER | NX | MAY_WRITE) | permissions(p)
            }
            DescriptorOp::ArmCow(_) => {
                if entry & (PRESENT | PREPARED) == 0 {
                    return Err(DescriptorRefusal::MissingTable);
                }
                if entry & WRITE != 0 {
                    (entry & !WRITE) | COW | MAY_WRITE
                } else {
                    entry
                }
            }
            DescriptorOp::CowRepoint { old, new, .. } => {
                if entry & COW == 0 || entry & MAY_WRITE == 0 {
                    return Err(DescriptorRefusal::NotCowArmed);
                }
                if leaf_output(entry, level) != old.raw() + offset {
                    return Err(DescriptorRefusal::WrongBacking);
                }
                (entry & !(ADDRESS | COW)) | (new.raw() + offset) | WRITE
            }
            DescriptorOp::Unmap(_) => 0,
            DescriptorOp::Coalesce { .. } => self.coalesced(entry, level)?,
        };
        self.set(slot, new)
    }
    fn coalesced(&mut self, entry: u64, level: usize) -> Result<u64, DescriptorRefusal> {
        if entry & PRESENT == 0 || entry & HUGE != 0 {
            return Err(DescriptorRefusal::MissingTable);
        }
        let table = entry & ADDRESS;
        let first = self.read(table)?;
        validate_entry(first, level + 1)?;
        if first & PRESENT == 0 || (level + 1 < 3 && first & HUGE == 0) {
            return Err(DescriptorRefusal::Malformed);
        }
        let output = leaf_output(first, level + 1);
        if !output.is_multiple_of(level_bytes(level)) {
            return Err(DescriptorRefusal::WrongBacking);
        }
        for index in 1..512 {
            let value = self.read(table + index * 8)?;
            if value != first + index * level_bytes(level + 1) {
                return Err(DescriptorRefusal::WrongBacking);
            }
        }
        let pat = if level + 1 == 3 {
            first & HUGE != 0
        } else {
            first & PAT_LARGE != 0
        };
        let mut flags = (first & !ADDRESS) & !HUGE;
        if pat {
            flags |= PAT_LARGE;
        }
        if entry & WRITE == 0 {
            flags &= !WRITE;
        }
        if entry & USER == 0 {
            flags &= !USER;
        }
        flags |= entry & NX;
        Ok(output | flags | HUGE)
    }
}

impl DescriptorTxn<'_> {
    /// Same receipt binding as ARM: identity alone does not bind an operation.
    pub fn digest(&self) -> u64 {
        let mix = |h: u64, w: u64| (h ^ w).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let span = self.op.span();
        let mut hash = 0x7838_3654;
        for word in [
            self.id.mm_key.get(),
            self.id.generation.get(),
            self.root.address().raw(),
            span.va,
            span.len,
        ] {
            hash = mix(hash, word);
        }
        let (kind, a, b, flags, backing) = match self.op {
            DescriptorOp::Map {
                output,
                permissions: p,
                size,
                resident,
                backing,
                ..
            } => (
                1,
                output.raw(),
                size.bytes(),
                permissions(p) | u64::from(resident),
                Some(backing),
            ),
            DescriptorOp::Publish { expected, .. } => (2, expected.raw(), 0, 0, None),
            DescriptorOp::Protect { permissions: p, .. } => (3, 0, 0, permissions(p), None),
            DescriptorOp::ArmCow(_) => (4, 0, 0, 0, None),
            DescriptorOp::CowRepoint {
                old, new, backing, ..
            } => (5, old.raw(), new.raw(), 0, Some(backing)),
            DescriptorOp::Unmap(_) => (6, 0, 0, 0, None),
            DescriptorOp::Coalesce { size, .. } => (7, size.bytes(), 0, 0, None),
        };
        for word in [kind, a, b, flags] {
            hash = mix(hash, word);
        }
        if let Some(b) = backing {
            for word in [
                b.frame_id.get(),
                b.mapping_id.get(),
                b.owner_generation.get(),
                b.inventory_revision.get(),
            ] {
                hash = mix(hash, word);
            }
        }
        hash = mix(hash, self.tables.len() as u64);
        for table in self.tables {
            hash = mix(hash, table.address().raw());
        }
        hash
    }
    pub fn verify_receipt(&self, receipt: &DescriptorReceipt) -> Result<(), DescriptorRefusal> {
        if receipt.id != self.id || receipt.digest != self.digest() {
            return Err(DescriptorRefusal::WrongMm);
        }
        if !matches!(receipt.outcome, DescriptorOutcome::Applied { .. }) {
            return Err(DescriptorRefusal::Contended);
        }
        Ok(())
    }
}
fn undo<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    entries: &[JournalEntry],
    span: PageSpan,
) -> bool {
    let mut restored = true;
    for entry in entries.iter().rev() {
        restored &= words.compare_exchange(entry.pa, entry.after, entry.before) == Ok(true);
    }
    words.publish_barrier();
    words.invalidate_range(span.va, span.len);
    restored
}
/// Undo an applied plan before owner admission reopens (inventory/slot failure).
/// Retain this plan and the exact editor until the complete unit commits.
pub fn rollback_descriptor_plan<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    plan: &DescriptorPlan,
) -> DescriptorOutcome {
    if undo(words, &plan.entries, plan.span) {
        DescriptorOutcome::RolledBack(DescriptorRefusal::Contended)
    } else {
        DescriptorOutcome::Indeterminate(DescriptorRefusal::Contended)
    }
}
pub fn apply_descriptor_plan<W: LiveDescriptorWords + ?Sized, J: DescriptorJournal + ?Sized>(
    words: &W,
    plan: &DescriptorPlan,
    journal: &mut J,
) -> DescriptorReceipt {
    let outcome = if !journal.reserve(plan.entries.len()) {
        DescriptorOutcome::Refused(DescriptorRefusal::JournalCapacity)
    } else {
        let mut error = None;
        for entry in &plan.entries {
            words.publish_barrier();
            match words.compare_exchange(entry.pa, entry.before, entry.after) {
                Ok(true) => {
                    if !journal.push(*entry) {
                        let restored =
                            words.compare_exchange(entry.pa, entry.after, entry.before) == Ok(true);
                        error = Some((DescriptorRefusal::JournalCapacity, restored));
                        break;
                    }
                }
                _ => {
                    error = Some((DescriptorRefusal::Contended, true));
                    break;
                }
            }
        }
        if let Some((reason, restored)) = error {
            if undo(words, journal.entries(), plan.span) && restored {
                DescriptorOutcome::RolledBack(reason)
            } else {
                DescriptorOutcome::Indeterminate(reason)
            }
        } else {
            words.publish_barrier();
            words.invalidate_range(plan.span.va, plan.span.len);
            DescriptorOutcome::Applied {
                stores: plan.entries.len(),
                tables_linked: plan.tables_linked,
            }
        }
    };
    DescriptorReceipt {
        id: plan.id,
        digest: plan.digest,
        outcome,
    }
}
pub fn execute_descriptor_txn<W: LiveDescriptorWords + ?Sized, J: DescriptorJournal + ?Sized>(
    words: &W,
    txn: &DescriptorTxn<'_>,
    live_root: RootGpa,
    journal: &mut J,
) -> DescriptorReceipt {
    match plan_descriptor_txn(words, txn, live_root) {
        Ok(plan) => apply_descriptor_plan(words, &plan, journal),
        Err(reason) => DescriptorReceipt {
            id: txn.id,
            digest: txn.digest(),
            outcome: DescriptorOutcome::Refused(reason),
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Execute,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultClass {
    NotPresent,
    CowWrite,
    Protection,
    Nx,
    Reserved,
}
/// Read-only walk; neither backing readiness nor semantic owner rights can be
/// inferred from this hardware translation. The N1 owner authenticates both.
pub fn translate<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: RootGpa,
    va: UserVa,
    access: Access,
    user: bool,
) -> Result<FrameGpa, FaultClass> {
    if !canonical(va.raw()) {
        return Err(FaultClass::Reserved);
    }
    let mut table = root.address().raw();
    for level in 0..4 {
        let entry = words
            .load(table + ((va.raw() >> (39 - level * 9)) & 511) * 8)
            .map_err(|_| FaultClass::Reserved)?;
        validate_entry(entry, level).map_err(|_| FaultClass::Reserved)?;
        if entry & PRESENT == 0 {
            return Err(FaultClass::NotPresent);
        }
        if user && entry & USER == 0 {
            return Err(FaultClass::Protection);
        }
        if access == Access::Execute && entry & NX != 0 {
            return Err(FaultClass::Nx);
        }
        if access == Access::Write && entry & WRITE == 0 {
            return Err(if entry & COW != 0 {
                FaultClass::CowWrite
            } else {
                FaultClass::Protection
            });
        }
        if level == 3 || entry & HUGE != 0 {
            return Ok(FrameGpa::new(
                leaf_output(entry, level) + (va.raw() & (level_bytes(level) - 1)),
            ));
        }
        table = entry & ADDRESS;
    }
    Err(FaultClass::Reserved)
}

#[cfg(test)]
mod tests;

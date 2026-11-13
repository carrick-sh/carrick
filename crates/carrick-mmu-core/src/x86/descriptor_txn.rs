//! Four-level, 4 KiB x86 descriptor transactions. No MM or reservation ledger.
pub use crate::aarch64::descriptor_txn::{
    BackingIdentity, DescriptorJournal, DescriptorTxnId, InlineJournal, JournalEntry, PageSpan,
};
pub use crate::descriptor_refusal::DescriptorRefusal;
pub use crate::live_descriptor_words::LiveDescriptorWords;
use alloc::{collections::BTreeMap, vec::Vec};
use carrick_guest_arch::{
    Access as GuestAccess, EditBacking, EditCowAccess, EditIntent, EditLeafSize, EditOperation,
    EditPermissions, FrameGpa, RootGpa, UserVa,
};

pub const PAGE: u64 = 4096;
pub const PRESENT: u64 = 1;
pub const WRITE: u64 = 1 << 1;
pub const USER: u64 = 1 << 2;
pub const HUGE: u64 = 1 << 7;
pub const PREPARED: u64 = 1 << 9;
pub const COW: u64 = 1 << 10;
pub const MAY_WRITE: u64 = 1 << 11;
/// Owner-issued private leaf; host Map leaves never carry this bit.
pub const PRIVATE: u64 = 1 << 52;
/// Owner-issued execute ceiling, retained when Protect sets NX.
pub const MAY_EXEC: u64 = 1 << 53;
/// Invalid terminal retaining the old output until owner scrub settles it.
pub const RETIRED: u64 = 1 << 8;
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
    /// A complete owner grant: prepare neighbors and publish only the fault
    /// span under the same rollback journal, with no intermediate receipt.
    Prepare {
        span: PageSpan,
        output: FrameGpa,
        permissions: Permissions,
        resident: PageSpan,
        backing: BackingIdentity,
    },
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
        access: Access,
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
    /// Owner retirement retains an inaccessible physical predecessor for scrub.
    Retire(PageSpan),
    Unmap(PageSpan),
    Coalesce {
        span: PageSpan,
        size: LeafSize,
    },
}
impl DescriptorOp {
    pub fn span(self) -> PageSpan {
        match self {
            Self::Prepare { span, .. }
            | Self::Map { span, .. }
            | Self::Publish { span, .. }
            | Self::Protect { span, .. }
            | Self::CowRepoint { span, .. }
            | Self::Coalesce { span, .. }
            | Self::ArmCow(span)
            | Self::Retire(span)
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

impl<'a> DescriptorTxn<'a> {
    /// Lower one exact-MM owner intent. Every unsupported Linux permission or
    /// COW mode is rejected before planning any descriptor store.
    pub fn from_intent(intent: &'a EditIntent<'_, RootGpa>) -> Result<Self, DescriptorRefusal> {
        let owner = intent.owner();
        let span = PageSpan::new(intent.range().start().raw(), intent.range().len().raw());
        let permissions = |perms: EditPermissions| {
            perms.readable.then_some(Permissions {
                writable: perms.writable,
                executable: perms.executable,
                user: perms.user,
            })
        };
        let backing = |value: EditBacking| BackingIdentity {
            frame_id: value.frame_id,
            mapping_id: value.mapping_id,
            owner_generation: value.owner_generation,
            inventory_revision: value.inventory_revision,
        };
        let size = |value: EditLeafSize| match value {
            EditLeafSize::Page => LeafSize::Page,
            EditLeafSize::Block2M => LeafSize::Block2M,
            EditLeafSize::Block1G => LeafSize::Block1G,
        };
        let operation = match intent.operation() {
            EditOperation::Prepare {
                output,
                permissions: requested,
                resident,
                backing: identity,
            } => DescriptorOp::Prepare {
                span,
                output,
                permissions: permissions(requested).ok_or(DescriptorRefusal::BadEncoding)?,
                resident: PageSpan::new(resident.start().raw(), resident.len().raw()),
                backing: backing(identity),
            },
            EditOperation::Map {
                output,
                permissions: requested,
                size: leaf_size,
                resident,
                backing: identity,
            } => DescriptorOp::Map {
                span,
                output,
                permissions: permissions(requested).ok_or(DescriptorRefusal::BadEncoding)?,
                size: size(leaf_size),
                resident,
                backing: backing(identity),
            },
            EditOperation::Publish { expected, access } => DescriptorOp::Publish {
                span,
                expected,
                access: match access {
                    GuestAccess::Read => Access::Read,
                    GuestAccess::Write => Access::Write,
                    GuestAccess::Execute => Access::Execute,
                },
            },
            EditOperation::Protect {
                permissions: requested,
            } => DescriptorOp::Protect {
                span,
                permissions: permissions(requested).ok_or(DescriptorRefusal::BadEncoding)?,
            },
            EditOperation::ArmCow {
                kernel_only: false,
                executable: false,
                adopt_private: false,
                excluded_len,
                ..
            } if excluded_len.raw() == 0 => DescriptorOp::ArmCow(span),
            EditOperation::CowRepoint {
                old,
                new,
                backing: identity,
                access: EditCowAccess::RecordedPrivate,
            } => DescriptorOp::CowRepoint {
                span,
                old,
                new,
                backing: backing(identity),
            },
            EditOperation::Unmap => DescriptorOp::Retire(span),
            EditOperation::Coalesce { size: leaf_size } => DescriptorOp::Coalesce {
                span,
                size: size(leaf_size),
            },
            _ => return Err(DescriptorRefusal::BadEncoding),
        };
        Ok(Self {
            id: DescriptorTxnId {
                mm_key: owner.mm_key(),
                generation: owner.generation(),
            },
            root: owner.root(),
            op: operation,
            tables: intent.table_grants(),
        })
    }
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

impl DescriptorReceipt {
    /// Identity of the exact edit that produced this guest-owned receipt.
    pub const fn edit_identity(&self) -> u64 {
        self.digest
    }
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
        DescriptorOp::Prepare {
            output, resident, ..
        } => {
            validate_output(output, span.len, PAGE)?;
            if !resident.is_well_formed() || !span.contains_span(resident) {
                return Err(DescriptorRefusal::BadRange);
            }
        }
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
/// A CPL0 leaf may grant user access only in the lower canonical half. The
/// kernel image, metadata, stacks, and LAPIC live in the upper half. Check
/// prepared leaves too, so a later Publish cannot reveal a mismatched leaf.
pub fn check_leaf_privilege_matches_range(va: UserVa, entry: u64) -> Result<(), DescriptorRefusal> {
    if !canonical(va.raw()) {
        return Err(DescriptorRefusal::BadRange);
    }
    if entry & (PRESENT | PREPARED) != 0 {
        let lower_half = va.raw() < (1 << 47);
        if (entry & USER != 0) != lower_half {
            return Err(DescriptorRefusal::PermissionDenied);
        }
    }
    Ok(())
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
const fn level_bytes(level: usize) -> u64 {
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
pub const ACCESSED: u64 = 1 << 5;
pub const DIRTY: u64 = 1 << 6;
pub const PAT_LARGE: u64 = 1 << 12;
const FLAGS: u64 = PRESENT
    | WRITE
    | USER
    | (1 << 3)
    | (1 << 4)
    | ACCESSED
    | DIRTY
    | HUGE
    | RETIRED
    | PREPARED
    | COW
    | MAY_WRITE
    | PRIVATE
    | MAY_EXEC
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
    if level < 3
        && entry & HUGE == 0
        && entry & (PREPARED | COW | MAY_WRITE | RETIRED | PRIVATE | MAY_EXEC) != 0
    {
        return Err(DescriptorRefusal::Malformed);
    }
    Ok(())
}

/// Split one coarse terminal without changing PAT or prepared/COW state.
pub fn split_terminal_descriptor(
    entry: u64,
    level: usize,
    index: usize,
) -> Result<u64, DescriptorRefusal> {
    if !matches!(level, 1 | 2) || index >= 512 || entry & HUGE == 0 {
        return Err(DescriptorRefusal::Malformed);
    }
    validate_entry(entry, level)?;
    let mut flags = (entry & !ADDRESS) & !HUGE;
    let pat = entry & PAT_LARGE != 0;
    if level + 1 < 3 {
        flags |= HUGE;
        if pat {
            flags |= PAT_LARGE;
        }
    } else if pat {
        flags |= HUGE;
    }
    Ok((leaf_output(entry, level) + index as u64 * level_bytes(level + 1)) | flags)
}

pub fn arm_cow_terminal(entry: u64) -> Result<u64, DescriptorRefusal> {
    if entry & (PRESENT | PREPARED) == 0 {
        return Err(DescriptorRefusal::MissingTable);
    }
    Ok(if entry & WRITE != 0 {
        (entry & !WRITE) | COW | MAY_WRITE
    } else {
        entry
    })
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
        for index in 0..512 {
            self.set(
                child + index * 8,
                split_terminal_descriptor(entry, level, index as usize)?,
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
        if entry == 0
            && matches!(
                self.txn.op,
                DescriptorOp::Unmap(_) | DescriptorOp::Retire(_)
            )
        {
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
                | DescriptorOp::Retire(_)
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
            if !matches!(
                self.txn.op,
                DescriptorOp::Map { .. } | DescriptorOp::Prepare { .. }
            ) {
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
                ..
            }
            | DescriptorOp::Prepare {
                output,
                permissions: p,
                ..
            } => {
                if entry != 0 {
                    return Err(DescriptorRefusal::Occupied);
                }
                let resident = match self.txn.op {
                    DescriptorOp::Map { resident, .. } => resident,
                    DescriptorOp::Prepare { resident, span, .. } => {
                        resident.contains(span.va + offset)
                    }
                    _ => false,
                };
                (output.raw() + offset)
                    | permissions(p)
                    | if matches!(self.txn.op, DescriptorOp::Prepare { .. }) {
                        PRIVATE | if p.executable { MAY_EXEC } else { 0 }
                    } else {
                        0
                    }
                    | if resident { PRESENT } else { PREPARED }
                    | if level < 3 { HUGE } else { 0 }
            }
            DescriptorOp::Publish {
                expected, access, ..
            } => {
                if entry & PREPARED == 0 || entry & PRESENT != 0 {
                    return Err(DescriptorRefusal::NotPrepared);
                }
                if leaf_output(entry, level) != expected.raw() + offset {
                    return Err(DescriptorRefusal::WrongBacking);
                }
                if entry & USER == 0
                    || matches!(access, Access::Write) && entry & WRITE == 0
                    || matches!(access, Access::Execute) && entry & NX != 0
                {
                    return Err(DescriptorRefusal::PermissionDenied);
                }
                (entry | PRESENT) & !PREPARED
            }
            DescriptorOp::Protect { permissions: p, .. } => {
                if entry & (PRESENT | PREPARED) == 0 {
                    return Err(DescriptorRefusal::MissingTable);
                }
                if entry & PRIVATE == 0 {
                    return Err(DescriptorRefusal::NotPrivateAnonymous);
                }
                if entry & COW != 0 {
                    return Err(DescriptorRefusal::CowArmed);
                }
                if p.writable && entry & MAY_WRITE == 0 || p.executable && entry & MAY_EXEC == 0 {
                    return Err(DescriptorRefusal::PermissionWidening);
                }
                entry & !(WRITE | USER | NX) | (permissions(p) & (WRITE | USER | NX))
            }
            DescriptorOp::ArmCow(_) => arm_cow_terminal(entry)?,
            DescriptorOp::CowRepoint { old, new, .. } => {
                if leaf_output(entry, level) != old.raw() + offset {
                    return Err(DescriptorRefusal::WrongBacking);
                }
                if entry & RETIRED != 0 && entry & (PRESENT | PREPARED) == 0 {
                    (entry & !ADDRESS) | (new.raw() + offset)
                } else {
                    if entry & COW == 0 || entry & MAY_WRITE == 0 {
                        return Err(DescriptorRefusal::NotCowArmed);
                    }
                    (entry & !(ADDRESS | COW)) | (new.raw() + offset) | WRITE
                }
            }
            DescriptorOp::Retire(_) => {
                if entry & (PRESENT | PREPARED) == 0 || entry & USER == 0 || entry & PRIVATE == 0 {
                    return Err(DescriptorRefusal::NotPrivateAnonymous);
                }
                (entry & !(PRESENT | PREPARED | COW)) | RETIRED
            }
            DescriptorOp::Unmap(_) => 0,
            DescriptorOp::Coalesce { .. } => self.coalesced(entry, level)?,
        };
        check_leaf_privilege_matches_range(UserVa::new(self.txn.op.span().va + offset), new)?;
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
    /// Stable identity checked by the host after this exact guest edit.
    pub fn edit_identity(&self) -> u64 {
        self.digest()
    }
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
            DescriptorOp::Prepare {
                output,
                permissions: p,
                resident,
                backing,
                ..
            } => {
                hash = mix(hash, resident.va);
                hash = mix(hash, resident.len);
                (8, output.raw(), PAGE, permissions(p), Some(backing))
            }
            DescriptorOp::Publish {
                expected, access, ..
            } => (
                2,
                expected.raw(),
                0,
                match access {
                    Access::Read => 1,
                    Access::Write => 2,
                    Access::Execute => 3,
                },
                None,
            ),
            DescriptorOp::Protect { permissions: p, .. } => (3, 0, 0, permissions(p), None),
            DescriptorOp::ArmCow(_) => (4, 0, 0, 0, None),
            DescriptorOp::CowRepoint {
                old, new, backing, ..
            } => (5, old.raw(), new.raw(), 0, Some(backing)),
            DescriptorOp::Unmap(_) => (6, 0, 0, 0, None),
            DescriptorOp::Retire(_) => (9, 0, 0, 0, None),
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
    translate_leaf(words, root, va, access, user).map(|leaf| leaf.output)
}

/// Default `MAXPHYADDR` for the pinned x86-64-v3 guest CPUID view (`48` physical address bits).
pub const DEFAULT_MAX_PHY_ADDR: u8 = 48;

/// Minimum architectural `MAXPHYADDR` in 64-bit paging (`32`).
pub const MIN_MAX_PHY_ADDR: u8 = 32;

/// Maximum architectural `MAXPHYADDR` in 64-bit 4-level paging (`52`).
pub const MAX_MAX_PHY_ADDR: u8 = 52;

/// Compute the mask of reserved physical-address bits `[51 : max_phy_addr]` for a given
/// `max_phy_addr` (`32..=52`), per Intel SDM Vol. 3A §4.5.
#[inline]
pub const fn reserved_phyaddr_mask(max_phy_addr: u8) -> u64 {
    let clamped = if max_phy_addr < MIN_MAX_PHY_ADDR {
        MIN_MAX_PHY_ADDR
    } else if max_phy_addr > MAX_MAX_PHY_ADDR {
        MAX_MAX_PHY_ADDR
    } else {
        max_phy_addr
    };
    if clamped >= MAX_MAX_PHY_ADDR {
        0
    } else {
        let width = (MAX_MAX_PHY_ADDR - clamped) as u32;
        ((1u64 << width) - 1) << (clamped as u32)
    }
}

/// Return `true` if a **present** (`P == 1`) paging-structure entry at `level` (`0 = PML4 .. 3 = PT`)
/// has any hardware-reserved bit set under `(max_phy_addr, nxe)` per Intel SDM Vol. 3A §4.5.
///
/// Hardware ignores software-available bits `8..=11` on both leaf and non-leaf entries and bits
/// `52..=62` on all entries (when `CR4.PKE == 0`).
#[inline]
pub const fn has_hardware_reserved_bits_when_present(
    entry: u64,
    level: usize,
    max_phy_addr: u8,
    nxe: bool,
) -> bool {
    if (entry & reserved_phyaddr_mask(max_phy_addr)) != 0 {
        return true;
    }
    if !nxe && (entry & NX) != 0 {
        return true;
    }
    if level == 0 && (entry & HUGE) != 0 {
        return true;
    }
    if (level == 1 || level == 2) && (entry & HUGE) != 0 {
        let unaligned_mask = (level_bytes(level) - 1) & ADDRESS & !PAT_LARGE;
        if (entry & unaligned_mask) != 0 {
            return true;
        }
    }
    false
}

/// Hardware walk configuration for [`translate_leaf_hardware`] (Intel SDM Vol. 3A §4.5–§4.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwareWalkConfig {
    /// Physical address width (`32..=52`; bits `[51 : max_phy_addr]` are reserved on present entries).
    pub max_phy_addr: u8,
    /// `IA32_EFER.NXE` (`false` makes bit 63 reserved; `true` enables execute-disable).
    pub nxe: bool,
    /// `CR0.WP` (`false` allows supervisor writes to read-only pages).
    pub cr0_wp: bool,
    /// `CR4.SMEP` (`true` faults supervisor instruction fetches from effective-user pages).
    pub cr4_smep: bool,
    /// `CR4.SMAP` (`true` faults supervisor data accesses to effective-user pages when `rflags_ac == false`).
    pub cr4_smap: bool,
    /// `RFLAGS.AC` (`true` permits supervisor data accesses to user pages when `cr4_smap == true`).
    pub rflags_ac: bool,
    /// When `true`, atomically sets `ACCESSED` on every walked entry and `DIRTY` on leaf writes via CAS.
    pub update_ad: bool,
}

impl HardwareWalkConfig {
    /// Standard hardware walk configuration (`MAXPHYADDR = 48`, `NXE = WP = SMEP = SMAP = update_ad = true`, `AC = false`).
    #[inline]
    pub const fn new() -> Self {
        Self {
            max_phy_addr: DEFAULT_MAX_PHY_ADDR,
            nxe: true,
            cr0_wp: true,
            cr4_smep: true,
            cr4_smap: true,
            rflags_ac: false,
            update_ad: true,
        }
    }
}

impl Default for HardwareWalkConfig {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Detailed hardware translation stop classification returned by [`translate_leaf_hardware`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareFaultClass {
    /// Linear address is non-canonical under 48-bit 4-level paging (`#GP(0)` / `#SS(0)`, never `#PF`).
    NonCanonical,
    /// Descriptor word load or CAS failed in the underlying [`LiveDescriptorWords`] store.
    DescriptorLoad(DescriptorRefusal),
    /// Entry at some walked level had `PRESENT == 0` (`#PF` with `P = 0`).
    NotPresent,
    /// Present entry had a hardware-reserved bit set (`#PF` with `P = 1, RSVD = 1`).
    Reserved,
    /// Page-level `U/S` or `W/R` permission check failed (`#PF` with `P = 1`).
    Protection,
    /// Write hit a read-only leaf armed with the software `COW` bit (`#PF` with `P = 1, W/R = 1`).
    CowWrite,
    /// Instruction fetch hit an entry with `NX == 1` when `EFER.NXE == 1` (`#PF` with `P = 1, I/D = 1`).
    Nx,
    /// Supervisor instruction fetch hit an effective-user page when `CR4.SMEP == 1` (`#PF` with `P = 1, I/D = 1`).
    Smep,
    /// Supervisor data access hit an effective-user page when `CR4.SMAP == 1 && RFLAGS.AC == 0` (`#PF` with `P = 1`).
    Smap,
    /// Atomic `ACCESSED`/`DIRTY` `compare_exchange` exceeded [`MAX_AD_CAS_RETRIES`] failed CAS attempts.
    AdCasRetryExhausted {
        /// Number of failed `A`/`D` CAS attempts (`MAX_AD_CAS_RETRIES`).
        retries: usize,
    },
}

impl HardwareFaultClass {
    /// Project a hardware fault class onto the ring-level [`FaultClass`].
    #[inline]
    pub const fn to_fault_class(self) -> FaultClass {
        match self {
            Self::NotPresent => FaultClass::NotPresent,
            Self::CowWrite => FaultClass::CowWrite,
            Self::Protection | Self::Smep | Self::Smap => FaultClass::Protection,
            Self::Nx => FaultClass::Nx,
            Self::NonCanonical
            | Self::DescriptorLoad(_)
            | Self::Reserved
            | Self::AdCasRetryExhausted { .. } => FaultClass::Reserved,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranslatedLeaf {
    pub output: FrameGpa,
    pub executable: bool,
    pub ancestors_writable: bool,
    pub effective_user: bool,
    pub effective_writable: bool,
    pub descriptor: u64,
    pub size: u64,
}

#[derive(Clone, Copy)]
enum WalkMode<'a> {
    Ring,
    Hardware(&'a HardwareWalkConfig),
}

/// Total livelock/contention bound on failed `ACCESSED`/`DIRTY` `compare_exchange` attempts per walk.
///
/// When a failed CAS reloads a word whose `PRESENT`, output address, and permission/structural bits
/// (`WRITE | USER | HUGE | NX`) are unchanged (e.g., a peer toggling software-available bits `8..=11`
/// or `52..=62`), the walker retries the CAS in place on that word without restarting the 4-level
/// walk; when a material bit changed, it restarts from the root. Every failed CAS counts against
/// `MAX_AD_CAS_RETRIES` so an adversarial concurrent writer flipping software-available bits cannot
/// spin a soft-vCPU walk forever.
pub const MAX_AD_CAS_RETRIES: usize = 64;

/// Read one terminal word, including a prepared non-present leaf. This is
/// observation only; it never grants backing or descriptor-write authority.
pub fn read_terminal_descriptor<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: RootGpa,
    va: UserVa,
) -> Result<(u64, u64), DescriptorRefusal> {
    if !canonical(va.raw()) {
        return Err(DescriptorRefusal::BadRange);
    }
    let mut table = root.address().raw();
    for level in 0..4 {
        let entry = words.load(table + ((va.raw() >> (39 - level * 9)) & 511) * 8)?;
        validate_entry(entry, level)?;
        if level == 3 || entry & HUGE != 0 {
            return Ok((entry, level_bytes(level)));
        }
        if entry & PRESENT == 0 {
            return Err(DescriptorRefusal::MissingTable);
        }
        table = entry & ADDRESS;
    }
    Err(DescriptorRefusal::MissingTable)
}

fn walk_leaf_inner<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: RootGpa,
    va: UserVa,
    access: Access,
    user: bool,
    mode: WalkMode<'_>,
) -> Result<TranslatedLeaf, HardwareFaultClass> {
    if !canonical(va.raw()) {
        return Err(HardwareFaultClass::NonCanonical);
    }
    if let WalkMode::Hardware(cfg) = mode
        && (root.address().raw() & reserved_phyaddr_mask(cfg.max_phy_addr)) != 0
    {
        return Err(HardwareFaultClass::Reserved);
    }

    let mut retries = 0usize;
    'walk: loop {
        let mut table = root.address().raw();
        let mut executable = true;
        let mut ancestors_writable = true;
        let mut effective_user = true;
        let mut walked_slots = [(0u64, 0u64); 4];

        for level in 0..4 {
            let slot_pa = table + ((va.raw() >> (39 - level * 9)) & 511) * 8;
            let mut entry = words
                .load(slot_pa)
                .map_err(HardwareFaultClass::DescriptorLoad)?;
            walked_slots[level] = (slot_pa, entry);

            match mode {
                WalkMode::Ring => {
                    validate_entry(entry, level).map_err(|_| HardwareFaultClass::Reserved)?;
                    if entry & PRESENT == 0 {
                        return Err(HardwareFaultClass::NotPresent);
                    }
                    executable &= entry & NX == 0;
                    effective_user &= entry & USER != 0;
                    if user && entry & USER == 0 {
                        return Err(HardwareFaultClass::Protection);
                    }
                    if access == Access::Execute && entry & NX != 0 {
                        return Err(HardwareFaultClass::Nx);
                    }
                    if access == Access::Write && entry & WRITE == 0 {
                        return Err(if entry & COW != 0 {
                            HardwareFaultClass::CowWrite
                        } else {
                            HardwareFaultClass::Protection
                        });
                    }
                }
                WalkMode::Hardware(cfg) => {
                    if entry & PRESENT == 0 {
                        return Err(HardwareFaultClass::NotPresent);
                    }
                    if has_hardware_reserved_bits_when_present(
                        entry,
                        level,
                        cfg.max_phy_addr,
                        cfg.nxe,
                    ) {
                        return Err(HardwareFaultClass::Reserved);
                    }
                    executable &= entry & NX == 0;
                    effective_user &= entry & USER != 0;
                }
            }

            if level == 3 || entry & HUGE != 0 {
                let effective_writable = ancestors_writable && (entry & WRITE != 0);
                if let WalkMode::Hardware(cfg) = mode {
                    if user {
                        if !effective_user {
                            return Err(HardwareFaultClass::Protection);
                        }
                        if access == Access::Execute && !executable {
                            return Err(HardwareFaultClass::Nx);
                        }
                        if access == Access::Write && !effective_writable {
                            return Err(if ancestors_writable && (entry & COW != 0) {
                                HardwareFaultClass::CowWrite
                            } else {
                                HardwareFaultClass::Protection
                            });
                        }
                    } else if access == Access::Execute {
                        if cfg.cr4_smep && effective_user {
                            return Err(HardwareFaultClass::Smep);
                        }
                        if !executable {
                            return Err(HardwareFaultClass::Nx);
                        }
                    } else {
                        if cfg.cr4_smap && !cfg.rflags_ac && effective_user {
                            return Err(HardwareFaultClass::Smap);
                        }
                        if access == Access::Write && cfg.cr0_wp && !effective_writable {
                            return Err(if ancestors_writable && (entry & COW != 0) {
                                HardwareFaultClass::CowWrite
                            } else {
                                HardwareFaultClass::Protection
                            });
                        }
                    }

                    if cfg.update_ad {
                        const MATERIAL_AD_MASK: u64 = PRESENT | WRITE | USER | HUGE | ADDRESS | NX;
                        walked_slots[level] = (slot_pa, entry);
                        for (i, &(pa, mut cur)) in walked_slots[..=level].iter().enumerate() {
                            let needed = ACCESSED
                                | if i == level && access == Access::Write {
                                    DIRTY
                                } else {
                                    0
                                };
                            while cur & needed != needed {
                                if words
                                    .compare_exchange(pa, cur, cur | needed)
                                    .map_err(HardwareFaultClass::DescriptorLoad)?
                                {
                                    cur |= needed;
                                    break;
                                }
                                if retries >= MAX_AD_CAS_RETRIES {
                                    return Err(HardwareFaultClass::AdCasRetryExhausted {
                                        retries,
                                    });
                                }
                                retries += 1;
                                let next =
                                    words.load(pa).map_err(HardwareFaultClass::DescriptorLoad)?;
                                if (next & MATERIAL_AD_MASK) != (cur & MATERIAL_AD_MASK) {
                                    continue 'walk;
                                }
                                cur = next;
                            }
                            if i == level {
                                entry = cur;
                            }
                        }
                    }
                }

                return Ok(TranslatedLeaf {
                    output: FrameGpa::new(
                        leaf_output(entry, level) + (va.raw() & (level_bytes(level) - 1)),
                    ),
                    executable,
                    ancestors_writable,
                    effective_user,
                    effective_writable,
                    descriptor: entry,
                    size: level_bytes(level),
                });
            }

            ancestors_writable &= entry & WRITE != 0;
            table = entry & ADDRESS;
        }
        return Err(HardwareFaultClass::Reserved);
    }
}

pub fn translate_leaf<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: RootGpa,
    va: UserVa,
    access: Access,
    user: bool,
) -> Result<TranslatedLeaf, FaultClass> {
    walk_leaf_inner(words, root, va, access, user, WalkMode::Ring)
        .map_err(HardwareFaultClass::to_fault_class)
}

/// Hardware-mode 4-level page-table walk sharing the single walk loop of [`translate_leaf`].
///
/// Loads each walked descriptor word once per attempt, enforces hardware reserved-bit and
/// non-leaf/leaf ignored-bit rules (`MAXPHYADDR`, `EFER.NXE`), evaluates `CR0.WP`, `CR4.SMEP`,
/// and `CR4.SMAP` (with `RFLAGS.AC`), and atomically sets `ACCESSED` on every walked level and
/// `DIRTY` on leaf writes via `compare_exchange` (restarting the walk if a concurrent PTE update
/// causes the CAS to fail).
pub fn translate_leaf_hardware<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: RootGpa,
    va: UserVa,
    access: Access,
    user: bool,
    config: &HardwareWalkConfig,
) -> Result<TranslatedLeaf, HardwareFaultClass> {
    walk_leaf_inner(words, root, va, access, user, WalkMode::Hardware(config))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CowClass {
    Unmapped,
    NotCowArmed,
    NoWriteIntent,
    AncestorNotWritable,
    AlreadyWritable,
    ExecutableDenied,
    Unreachable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CowRun {
    pub va: u64,
    pub old_ipa: FrameGpa,
    pub len: u64,
    pub compound_offset: u64,
    pub executable: bool,
}

/// Classify one CPL3 COW write through the live PML4. The exact-MM editor
/// remains held by the caller through the eventual copy and repoint.
pub fn classify_guest_cow_write<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: RootGpa,
    far: UserVa,
    publish_executable: bool,
) -> Result<CowRun, CowClass> {
    let leaf =
        translate_leaf(words, root, far, Access::Read, true).map_err(|reason| match reason {
            FaultClass::NotPresent | FaultClass::Protection => CowClass::Unmapped,
            _ => CowClass::Unreachable,
        })?;
    if !leaf.ancestors_writable {
        return Err(CowClass::AncestorNotWritable);
    }
    if leaf.descriptor & WRITE != 0 {
        return Err(CowClass::AlreadyWritable);
    }
    if leaf.size != PAGE {
        return Err(CowClass::Unmapped);
    }
    if leaf.descriptor & COW == 0 {
        return Err(CowClass::NotCowArmed);
    }
    if leaf.descriptor & MAY_WRITE == 0 {
        return Err(CowClass::NoWriteIntent);
    }
    if leaf.executable && !publish_executable {
        return Err(CowClass::ExecutableDenied);
    }
    let old_ipa = FrameGpa::new(leaf.output.raw() & !(PAGE - 1));
    Ok(CowRun {
        va: far.raw() & !(PAGE - 1),
        old_ipa,
        len: PAGE,
        // A host COW grant is one 16 KiB compound on both ISAs.
        compound_offset: old_ipa.raw() & (16 * 1024 - 1),
        executable: leaf.executable,
    })
}

#[cfg(test)]
mod tests;

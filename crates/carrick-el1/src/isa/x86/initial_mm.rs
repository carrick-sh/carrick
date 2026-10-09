//! The unpublished x86 initial address-space owner.
//! ELF parsing is supplied by `carrick-mem::elf` on the host crossing; the
//! stack bytes, frame initialization and descriptor edits belong to CPL0.
extern crate alloc as image_alloc;

use carrick_el1_abi::GuestMmuPublication;
use carrick_guest_arch::{
    AddressContext, ContextGeneration, EditBacking, EditIntent, EditOperation, EditOwner,
    EditPermissions, FrameGpa, GuestLen, MmGeneration, RootGpa, UserRange, UserVa,
};
use carrick_mmu_core::x86::descriptor_txn::{
    DescriptorOutcome, DescriptorTxn, InlineJournal, LiveDescriptorWords, PRESENT, USER,
    execute_descriptor_txn,
};
use carrick_sched_core::{ParkedContextWords, X86_XSAVE_BYTES};
use core::num::NonZeroU64;
use image_alloc::{collections::BTreeSet, vec::Vec};

const PAGE: u64 = 4096;
const USER_END: u64 = 0x0000_8000_0000_0000;

/// Linux auxiliary-vector tags from the common Linux ABI. The values are
/// encoded here because the guest image cannot link the host-side ABI crate.
#[repr(u64)]
#[derive(Clone, Copy)]
enum AuxvTag {
    Null = 0,
    Phdr = 3,
    Phent = 4,
    Phnum = 5,
    Pagesz = 6,
    Flags = 8,
    Entry = 9,
    Uid = 11,
    Euid = 12,
    Gid = 13,
    Egid = 14,
    Platform = 15,
    Hwcap = 16,
    Clktck = 17,
    Secure = 23,
    Random = 25,
    Hwcap2 = 26,
    Execfn = 31,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialMmError {
    InvalidRange,
    InvalidString,
    StackTooLarge,
    FrameUnavailable,
    DescriptorRefused,
    DescriptorIndeterminate,
    PublicationRefused,
}

/// Inputs from a validated static ELF load plan. `random` is a fresh 16-byte
/// carrier CSPRNG grant; the guest places its bytes and publishes the address.
pub struct InitialStackSpec<'a> {
    pub entry: u64,
    pub phdr: u64,
    pub phent: u16,
    pub phnum: u16,
    pub argv: &'a [&'a [u8]],
    pub envp: &'a [&'a [u8]],
    pub random: [u8; 16],
    pub stack_top: u64,
    pub stack_size: u64,
}

/// Only the initialized tail is materialized; the rest of the stack remains
/// an MM reservation. `base` and `bytes` cover whole 4 KiB pages.
pub struct InitialStackImage {
    pub base: u64,
    pub bytes: Vec<u8>,
    pub rsp: u64,
    pub auxv: Vec<(u64, u64)>,
}

fn push_string(
    bytes: &mut [u8],
    base: u64,
    cursor: &mut usize,
    string: &[u8],
) -> Result<u64, InitialMmError> {
    if string.contains(&0) {
        return Err(InitialMmError::InvalidString);
    }
    let len = string
        .len()
        .checked_add(1)
        .ok_or(InitialMmError::StackTooLarge)?;
    *cursor = cursor
        .checked_sub(len)
        .ok_or(InitialMmError::StackTooLarge)?;
    bytes[*cursor..*cursor + string.len()].copy_from_slice(string);
    bytes[*cursor + string.len()] = 0;
    Ok(base + *cursor as u64)
}

fn put_word(bytes: &mut [u8], cursor: &mut usize, value: u64) {
    bytes[*cursor..*cursor + 8].copy_from_slice(&value.to_le_bytes());
    *cursor += 8;
}

/// Construct Linux's x86_64 process-entry stack in guest-owned bytes.
/// `RSP` points at argc, is 16-byte aligned, and the auxv follows the two
/// terminated pointer vectors. No host-written stack page is admitted.
pub fn build_initial_stack(
    spec: &InitialStackSpec<'_>,
) -> Result<InitialStackImage, InitialMmError> {
    if spec.stack_top == 0
        || spec.stack_top > USER_END
        || spec.stack_top & (PAGE - 1) != 0
        || spec.stack_size == 0
        || spec.stack_size & (PAGE - 1) != 0
        || spec.stack_top.checked_sub(spec.stack_size).is_none()
        || spec.entry >= USER_END
        || spec.phdr >= USER_END
        || spec.phent == 0
        || spec.phnum == 0
    {
        return Err(InitialMmError::InvalidRange);
    }
    let string_bytes = spec
        .argv
        .iter()
        .chain(spec.envp.iter())
        .try_fold(0usize, |sum, value| {
            sum.checked_add(value.len().checked_add(1)?)
        })
        .ok_or(InitialMmError::StackTooLarge)?;
    let execfn = spec.argv.first().copied().unwrap_or(b"");
    let auxv_count = 18usize;
    let pointer_words = 1usize
        .checked_add(spec.argv.len())
        .and_then(|sum| sum.checked_add(1 + spec.envp.len() + 1))
        .and_then(|sum| sum.checked_add(auxv_count * 2))
        .ok_or(InitialMmError::StackTooLarge)?;
    let required = string_bytes
        .checked_add(
            execfn
                .len()
                .checked_add(1)
                .ok_or(InitialMmError::StackTooLarge)?,
        )
        .and_then(|sum| sum.checked_add(b"x86_64".len() + 1 + 16 + 32))
        .and_then(|sum| sum.checked_add(pointer_words * 8))
        .ok_or(InitialMmError::StackTooLarge)?;
    let tail_len = required
        .checked_add(PAGE as usize - 1)
        .map(|sum| sum & !(PAGE as usize - 1))
        .ok_or(InitialMmError::StackTooLarge)?;
    if tail_len as u64 > spec.stack_size {
        return Err(InitialMmError::StackTooLarge);
    }
    let base = spec.stack_top - tail_len as u64;
    let mut bytes = image_alloc::vec![0; tail_len];
    let mut cursor = tail_len;
    let mut argv = Vec::with_capacity(spec.argv.len());
    for value in spec.argv.iter().rev() {
        argv.push(push_string(&mut bytes, base, &mut cursor, value)?);
    }
    argv.reverse();
    let mut envp = Vec::with_capacity(spec.envp.len());
    for value in spec.envp.iter().rev() {
        envp.push(push_string(&mut bytes, base, &mut cursor, value)?);
    }
    envp.reverse();
    let execfn = push_string(&mut bytes, base, &mut cursor, execfn)?;
    let platform = push_string(&mut bytes, base, &mut cursor, b"x86_64")?;
    cursor &= !15;
    cursor = cursor
        .checked_sub(16)
        .ok_or(InitialMmError::StackTooLarge)?;
    bytes[cursor..cursor + 16].copy_from_slice(&spec.random);
    let random = base + cursor as u64;
    cursor &= !15;
    let auxv = image_alloc::vec![
        (AuxvTag::Phdr as u64, spec.phdr),
        (AuxvTag::Phent as u64, u64::from(spec.phent)),
        (AuxvTag::Phnum as u64, u64::from(spec.phnum)),
        (AuxvTag::Pagesz as u64, PAGE),
        (AuxvTag::Flags as u64, 0),
        (AuxvTag::Entry as u64, spec.entry),
        (AuxvTag::Uid as u64, 0),
        (AuxvTag::Euid as u64, 0),
        (AuxvTag::Gid as u64, 0),
        (AuxvTag::Egid as u64, 0),
        (AuxvTag::Platform as u64, platform),
        (AuxvTag::Hwcap as u64, 0),
        (AuxvTag::Clktck as u64, 100),
        (AuxvTag::Secure as u64, 0),
        (AuxvTag::Random as u64, random),
        (AuxvTag::Hwcap2 as u64, 0),
        (AuxvTag::Execfn as u64, execfn),
        (AuxvTag::Null as u64, 0),
    ];
    let occupied = pointer_words
        .checked_mul(8)
        .ok_or(InitialMmError::StackTooLarge)?;
    let sp_offset = cursor
        .checked_sub(occupied)
        .ok_or(InitialMmError::StackTooLarge)?
        & !15;
    let mut at = sp_offset;
    put_word(&mut bytes, &mut at, argv.len() as u64);
    for address in argv {
        put_word(&mut bytes, &mut at, address);
    }
    put_word(&mut bytes, &mut at, 0);
    for address in envp {
        put_word(&mut bytes, &mut at, address);
    }
    put_word(&mut bytes, &mut at, 0);
    for &(tag, value) in &auxv {
        put_word(&mut bytes, &mut at, tag);
        put_word(&mut bytes, &mut at, value);
    }
    Ok(InitialStackImage {
        base,
        bytes,
        rsp: base + sp_offset as u64,
        auxv,
    })
}

/// File bytes already staged in guest physical memory by the carrier.
#[derive(Clone, Copy)]
pub struct InitialSourceRange {
    pub start: FrameGpa,
    pub len: GuestLen,
}

/// One page-aligned PT_LOAD span. File bytes begin at
/// `start + initialized_offset`; every other byte owes private zero fill.
pub struct InitialImageRegion {
    pub start: UserVa,
    pub len: GuestLen,
    pub initialized_offset: GuestLen,
    pub initialized: InitialSourceRange,
    pub perms: EditPermissions,
}

pub struct InitialImageSpec<'a> {
    pub regions: &'a [InitialImageRegion],
    pub stack: InitialStackSpec<'a>,
}

#[derive(Clone, Copy)]
enum RegionContents<'a> {
    Guest(InitialSourceRange),
    Stack(&'a [u8]),
}

impl RegionContents<'_> {
    fn len(&self) -> u64 {
        match self {
            Self::Guest(source) => source.len.raw(),
            Self::Stack(bytes) => bytes.len() as u64,
        }
    }
}

struct MappedRegion<'a> {
    start: u64,
    len: u64,
    initialized_offset: u64,
    contents: RegionContents<'a>,
    perms: EditPermissions,
}

/// A carrier-inventory grant of one zeroed, private 4 KiB frame. The owner
/// authenticates its shape before writing bytes or publishing a user leaf.
#[derive(Clone, Copy)]
pub struct InitialDataGrant {
    pub frame: FrameGpa,
    pub backing: EditBacking,
}

/// The carrier supplies physical custody; the guest owns its page tables.
/// The source retains every granted frame until the complete unpublished MM
/// either publishes or aborts. On error the caller aborts all grants as one
/// inventory transaction; it must never expose a partially built root.
pub trait InitialFrameSource {
    fn take_zeroed_table(&mut self) -> Option<RootGpa>;
    fn take_zeroed_data(&mut self) -> Option<InitialDataGrant>;
    fn copy_guest_data(
        &mut self,
        grant: InitialDataGrant,
        offset: u16,
        source: FrameGpa,
        len: u16,
    ) -> bool;
    fn write_data(&mut self, grant: InitialDataGrant, offset: u16, bytes: &[u8]) -> bool;
}

/// One completed but still unpublished address space. The caller consumes all
/// descriptor publications under its closed-MM editor before opening the task.
pub struct InitialMmImage {
    pub address: AddressContext<RootGpa>,
    pub context: ParkedContextWords,
    pub stack_pointer: u64,
    /// First byte beyond the highest ELF PT_LOAD page; Linux brk begins here.
    pub initial_break: UserVa,
    pub publications: Vec<GuestMmuPublication>,
}

fn valid_page(frame: FrameGpa) -> bool {
    frame.raw() != 0 && frame.raw() & (PAGE - 1) == 0 && frame.raw() < (1 << 52)
}

fn checked_region(region: &MappedRegion<'_>) -> Result<u64, InitialMmError> {
    let end = region
        .start
        .checked_add(region.len)
        .ok_or(InitialMmError::InvalidRange)?;
    let initialized_end = region
        .initialized_offset
        .checked_add(region.contents.len())
        .ok_or(InitialMmError::InvalidRange)?;
    if region.start < PAGE
        || region.start & (PAGE - 1) != 0
        || region.len == 0
        || region.len & (PAGE - 1) != 0
        || end > USER_END
        || initialized_end > region.len
        || matches!(region.contents, RegionContents::Guest(source) if source.start.raw() == 0
            || source.start.raw().checked_add(source.len.raw()).is_none_or(|end| end > (1 << 52)))
        || !region.perms.user
        || (!region.perms.readable && (region.perms.writable || region.perms.executable))
    {
        return Err(InitialMmError::InvalidRange);
    }
    Ok(end)
}

fn table_count(regions: &[MappedRegion<'_>]) -> Result<usize, InitialMmError> {
    let mut pml4 = BTreeSet::new();
    let mut pdpt = BTreeSet::new();
    let mut pd = BTreeSet::new();
    for region in regions {
        let end = checked_region(region)?;
        for va in (region.start..end).step_by(PAGE as usize) {
            pml4.insert(va >> 39);
            pdpt.insert(va >> 30);
            pd.insert(va >> 21);
        }
    }
    pml4.len()
        .checked_add(pdpt.len())
        .and_then(|total| total.checked_add(pd.len()))
        .ok_or(InitialMmError::InvalidRange)
}

/// Build a fresh x86 address space under the closed exact-MM editor.
///
/// # Safety
/// The caller owns an unpublished MM with `mm_key`/`generation`, authenticates
/// the live `source_root`, and excludes every other descriptor writer to the
/// supplied zeroed frame grants. The carrier retains the supervisor direct
/// window and all grants through publication or complete abort. On error it
/// must discard the uninstalled root and all its grants together.
pub unsafe fn install_initial_image<W: LiveDescriptorWords + ?Sized, S: InitialFrameSource>(
    words: &W,
    source: &mut S,
    source_root: RootGpa,
    mm_key: NonZeroU64,
    generation: NonZeroU64,
    image: &InitialImageSpec<'_>,
) -> Result<InitialMmImage, InitialMmError> {
    let stack = build_initial_stack(&image.stack)?;
    let stack_region = MappedRegion {
        start: stack.base,
        len: stack.bytes.len() as u64,
        initialized_offset: 0,
        contents: RegionContents::Stack(&stack.bytes),
        perms: EditPermissions {
            readable: true,
            writable: true,
            executable: false,
            user: true,
        },
    };
    let mut spans: Vec<MappedRegion<'_>> = image
        .regions
        .iter()
        .map(|region| MappedRegion {
            start: region.start.raw(),
            len: region.len.raw(),
            initialized_offset: region.initialized_offset.raw(),
            contents: RegionContents::Guest(region.initialized),
            perms: region.perms,
        })
        .collect();
    spans.push(stack_region);
    spans.sort_by_key(|region| region.start);
    let mut previous_end = 0;
    for region in &spans {
        let end = checked_region(region)?;
        if region.start < previous_end {
            return Err(InitialMmError::InvalidRange);
        }
        previous_end = end;
    }
    if !image.regions.iter().any(|region| {
        region.perms.executable
            && image.stack.entry >= region.start.raw()
            && image.stack.entry < region.start.raw() + region.len.raw()
    }) {
        return Err(InitialMmError::InvalidRange);
    }
    let initial_break = UserVa::new(
        image
            .regions
            .iter()
            .map(|region| region.start.raw() + region.len.raw())
            .max()
            .ok_or(InitialMmError::InvalidRange)?,
    );
    let root = source
        .take_zeroed_table()
        .ok_or(InitialMmError::FrameUnavailable)?;
    if !valid_page(root.address()) || root == source_root {
        return Err(InitialMmError::FrameUnavailable);
    }
    let mut seen = BTreeSet::new();
    seen.insert(source_root.address().raw());
    seen.insert(root.address().raw());
    // Inherit shared supervisor branches only. The fresh MM must never
    // borrow another MM's temporary copy tables; its lower half is zero.
    for index in 256..512_u64 {
        if !<carrick_mmu_core::x86::owner_mmu::X86Mmu as
            carrick_mmu_core::owner_mmu::OwnerForkMmu>::is_shared_root_entry(index as usize) {
            continue;
        }
        let word = words
            .load(source_root.address().raw() + index * 8)
            .map_err(|_| InitialMmError::DescriptorRefused)?;
        if word != 0 && (word & PRESENT == 0 || word & USER != 0 || word & (1 << 7) != 0) {
            return Err(InitialMmError::DescriptorRefused);
        }
        words
            .store_unlinked(root.address().raw() + index * 8, word)
            .map_err(|_| InitialMmError::DescriptorRefused)?;
    }
    let count = table_count(&spans)?;
    let mut tables = Vec::with_capacity(count);
    for _ in 0..count {
        let table = source
            .take_zeroed_table()
            .ok_or(InitialMmError::FrameUnavailable)?;
        if !valid_page(table.address()) || !seen.insert(table.address().raw()) {
            return Err(InitialMmError::FrameUnavailable);
        }
        tables.push(table);
    }
    let mut used_tables = 0;
    let mut publications = Vec::new();
    for region in spans {
        let end = region.start + region.len;
        let initialized_start = region.start + region.initialized_offset;
        let initialized_end = initialized_start + region.contents.len();
        for va in (region.start..end).step_by(PAGE as usize) {
            let grant = source
                .take_zeroed_data()
                .ok_or(InitialMmError::FrameUnavailable)?;
            if !valid_page(grant.frame) || !seen.insert(grant.frame.raw()) {
                return Err(InitialMmError::FrameUnavailable);
            }
            let copy_start = va.max(initialized_start);
            let copy_end = (va + PAGE).min(initialized_end);
            if copy_start < copy_end {
                let offset = (copy_start - va) as u16;
                let from = copy_start - initialized_start;
                let len = (copy_end - copy_start) as u16;
                let copied = match region.contents {
                    RegionContents::Guest(staged) => source.copy_guest_data(
                        grant,
                        offset,
                        FrameGpa::new(staged.start.raw() + from),
                        len,
                    ),
                    RegionContents::Stack(bytes) => source.write_data(
                        grant,
                        offset,
                        &bytes[from as usize..from as usize + usize::from(len)],
                    ),
                };
                if !copied {
                    return Err(InitialMmError::FrameUnavailable);
                }
            }
            // SAFETY: the caller's closed-MM edit right and exact root remain
            // held across the complete unpublished image transaction.
            let owner = unsafe { EditOwner::issue(root, mm_key, generation) };
            let range = UserRange::checked(UserVa::new(va), GuestLen::new(PAGE))
                .ok_or(InitialMmError::InvalidRange)?;
            let intent = EditIntent::checked(
                owner,
                range,
                EditOperation::Prepare {
                    output: grant.frame,
                    permissions: region.perms,
                    resident: range,
                    backing: grant.backing,
                },
                &tables[used_tables..],
            )
            .ok_or(InitialMmError::InvalidRange)?;
            let txn = DescriptorTxn::from_intent(&intent)
                .map_err(|_| InitialMmError::DescriptorRefused)?;
            let receipt = execute_descriptor_txn(words, &txn, root, &mut InlineJournal::new());
            let DescriptorOutcome::Applied { tables_linked, .. } = receipt.outcome else {
                return Err(InitialMmError::DescriptorRefused);
            };
            let publication = GuestMmuPublication::from_x86_receipt(&txn, &receipt)
                .ok_or(InitialMmError::PublicationRefused)?;
            used_tables += tables_linked;
            publications.push(publication);
        }
    }
    let mut copy_tables = [root; carrick_mmu_core::x86::copy_window::COW_COPY_TABLE_PAGES];
    for table in &mut copy_tables {
        *table = source
            .take_zeroed_table()
            .ok_or(InitialMmError::FrameUnavailable)?;
        if !valid_page(table.address()) || !seen.insert(table.address().raw()) {
            return Err(InitialMmError::FrameUnavailable);
        }
    }
    carrick_mmu_core::x86::copy_window::provision_cow_copy_window(words, root, copy_tables)
        .map_err(|outcome| match outcome {
            DescriptorOutcome::Indeterminate(_) => InitialMmError::DescriptorIndeterminate,
            _ => InitialMmError::DescriptorRefused,
        })?;
    let address = AddressContext {
        root,
        mm: MmGeneration::new(mm_key),
        generation: ContextGeneration::new(generation),
    };
    #[cfg(target_os = "none")]
    super::x86::mmu::register_shared_supervisor_tables(words, source_root)
        .map_err(|_| InitialMmError::DescriptorRefused)?;
    let mut frame = [0; 20];
    frame[15] = image.stack.entry;
    frame[16] = 0x23; // user 64-bit code selector in the CPL0 GDT
    frame[17] = 0x202; // fixed bit plus interrupt enable
    frame[18] = stack.rsp;
    frame[19] = 0x1b; // user data selector in the CPL0 GDT
    Ok(InitialMmImage {
        address,
        context: ParkedContextWords::from_parts(frame, address, 0, 0, [0; X86_XSAVE_BYTES]),
        stack_pointer: stack.rsp,
        initial_break,
        publications,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
    use carrick_mmu_core::x86::descriptor_txn::{Access, translate_leaf};
    use std::{boxed::Box, collections::BTreeMap, sync::Mutex};

    struct TestWords(Mutex<BTreeMap<u64, u64>>);
    impl TestWords {
        fn new() -> Self {
            let mut words = BTreeMap::new();
            words.insert(0x60_0000 + 511 * 8, 0x20_0003);
            Self(Mutex::new(words))
        }
    }
    impl LiveDescriptorWords for TestWords {
        fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
            Ok(*self.0.lock().unwrap().get(&pa).unwrap_or(&0))
        }
        fn compare_exchange(
            &self,
            pa: u64,
            before: u64,
            after: u64,
        ) -> Result<bool, DescriptorRefusal> {
            let mut words = self.0.lock().unwrap();
            if *words.get(&pa).unwrap_or(&0) != before {
                return Ok(false);
            }
            words.insert(pa, after);
            Ok(true)
        }
        fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
            let mut words = self.0.lock().unwrap();
            if *words.get(&pa).unwrap_or(&0) != 0 {
                return Err(DescriptorRefusal::Contended);
            }
            words.insert(pa, value);
            Ok(())
        }
        fn publish_barrier(&self) {}
        fn invalidate_range(&self, _: u64, _: u64) {}
    }

    struct TestFrames {
        next_table: u64,
        next_data: u64,
        data: BTreeMap<u64, Box<[u8; 4096]>>,
        staged: BTreeMap<u64, Vec<u8>>,
    }
    impl TestFrames {
        fn new() -> Self {
            Self {
                next_table: 0x80_0000,
                next_data: 0x90_0000,
                data: BTreeMap::new(),
                staged: BTreeMap::new(),
            }
        }
        fn data_at(&self, pa: u64) -> &[u8; 4096] {
            self.data.get(&pa).unwrap()
        }
    }
    impl InitialFrameSource for TestFrames {
        fn take_zeroed_table(&mut self) -> Option<RootGpa> {
            let address = self.next_table;
            self.next_table += PAGE;
            RootGpa::page_aligned(FrameGpa::new(address))
        }
        fn take_zeroed_data(&mut self) -> Option<InitialDataGrant> {
            let address = self.next_data;
            self.next_data += PAGE;
            self.data.insert(address, Box::new([0; 4096]));
            let identity = NonZeroU64::new(address)?;
            Some(InitialDataGrant {
                frame: FrameGpa::new(address),
                backing: EditBacking {
                    frame_id: identity,
                    mapping_id: identity,
                    owner_generation: NonZeroU64::MIN,
                    inventory_revision: NonZeroU64::MIN,
                },
            })
        }
        fn copy_guest_data(
            &mut self,
            grant: InitialDataGrant,
            offset: u16,
            source: FrameGpa,
            len: u16,
        ) -> bool {
            let Some((&base, staged)) = self.staged.range(..=source.raw()).next_back() else {
                return false;
            };
            let from = (source.raw() - base) as usize;
            let Some(bytes) = staged.get(from..from + usize::from(len)) else {
                return false;
            };
            let Some(target) = self.data.get_mut(&grant.frame.raw()) else {
                return false;
            };
            let offset = usize::from(offset);
            let Some(target) = target.get_mut(offset..offset + usize::from(len)) else {
                return false;
            };
            target.copy_from_slice(bytes);
            true
        }
        fn write_data(&mut self, grant: InitialDataGrant, offset: u16, bytes: &[u8]) -> bool {
            let Some(page) = self.data.get_mut(&grant.frame.raw()) else {
                return false;
            };
            let start = usize::from(offset);
            let Some(target) = page.get_mut(start..start + bytes.len()) else {
                return false;
            };
            target.copy_from_slice(bytes);
            true
        }
    }

    #[test]
    fn fresh_owner_maps_static_text_data_and_stack_with_publications() {
        use carrick_guest_arch::EditPermissions;
        let regions = [
            InitialImageRegion {
                start: UserVa::new(0x400000),
                len: GuestLen::new(0x1000),
                initialized_offset: GuestLen::new(0),
                initialized: InitialSourceRange {
                    start: FrameGpa::new(0x10_000),
                    len: GuestLen::new(12),
                },
                perms: EditPermissions {
                    readable: true,
                    writable: false,
                    executable: true,
                    user: true,
                },
            },
            InitialImageRegion {
                start: UserVa::new(0x402000),
                len: GuestLen::new(0x1000),
                initialized_offset: GuestLen::new(0),
                initialized: InitialSourceRange {
                    start: FrameGpa::new(0x11_000),
                    len: GuestLen::new(3),
                },
                perms: EditPermissions {
                    readable: true,
                    writable: true,
                    executable: false,
                    user: true,
                },
            },
        ];
        let stack = InitialStackSpec {
            entry: 0x400000,
            phdr: 0x400040,
            phent: 56,
            phnum: 1,
            argv: &[b"/tiny"],
            envp: &[],
            random: [0x5a; 16],
            stack_top: 0x7fff_0000,
            stack_size: 0x4000,
        };
        let words = TestWords::new();
        let mut frames = TestFrames::new();
        frames
            .staged
            .insert(0x10_000, b"\xb8\xe7\0\0\0\xbf\x07\0\0\0\x0f\x05".to_vec());
        frames.staged.insert(0x11_000, b"hi\n".to_vec());
        let image = InitialImageSpec {
            regions: &regions,
            stack,
        };
        let source_root = RootGpa::page_aligned(FrameGpa::new(0x60_0000)).unwrap();
        let source_copy_tables = [0x61_0000, 0x61_1000, 0x61_2000]
            .map(|pa| RootGpa::page_aligned(FrameGpa::new(pa)).unwrap());
        carrick_mmu_core::x86::copy_window::provision_cow_copy_window(
            &words,
            source_root,
            source_copy_tables,
        )
        .unwrap();
        // SAFETY: this isolated fixture owns its source root and every fresh
        // table/data frame until the unpublished image is inspected.
        let loaded = unsafe {
            install_initial_image(
                &words,
                &mut frames,
                source_root,
                core::num::NonZeroU64::new(77).unwrap(),
                core::num::NonZeroU64::MIN,
                &image,
            )
        }
        .unwrap();
        let child_copy_tables =
            carrick_mmu_core::x86::copy_window::cow_copy_table_frames(&words, loaded.address.root)
                .unwrap();
        for (child, source) in child_copy_tables.iter().zip(source_copy_tables) {
            assert_ne!(
                *child, source,
                "initial MM must own its private supervisor branch"
            );
        }
        let stack_leaf = translate_leaf(
            &words,
            loaded.address.root,
            UserVa::new(loaded.stack_pointer),
            Access::Write,
            true,
        )
        .unwrap();
        assert_ne!(
            stack_leaf.descriptor & carrick_mmu_core::x86::descriptor_txn::PRIVATE,
            0,
            "the initial anonymous stack needs owner-private COW custody"
        );
        let data_leaf = translate_leaf(
            &words,
            loaded.address.root,
            UserVa::new(0x402000),
            Access::Write,
            true,
        )
        .unwrap();
        assert_ne!(
            data_leaf.descriptor & carrick_mmu_core::x86::descriptor_txn::PRIVATE,
            0,
            "initial ELF data is private Linux mapping custody too"
        );
        assert_eq!(loaded.publications.len(), 3);
        assert_eq!(loaded.initial_break.raw(), 0x403000);
        assert_eq!(loaded.context.frame[15], 0x400000);
        assert_eq!(loaded.context.frame[16], 0x23);
        assert_eq!(loaded.context.frame[17], 0x202);
        assert_eq!(loaded.context.frame[18], loaded.stack_pointer);
        assert_eq!(loaded.context.frame[19], 0x1b);
        assert!(loaded.context.authenticates(loaded.address));
        let leaf = translate_leaf(
            &words,
            loaded.address.root,
            UserVa::new(0x400000),
            Access::Execute,
            true,
        )
        .unwrap();
        assert_eq!(
            frames.data_at(leaf.output.raw())[..12],
            frames.staged[&0x10_000][..]
        );
        assert!(
            frames.data_at(leaf.output.raw())[12..]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            translate_leaf(
                &words,
                loaded.address.root,
                UserVa::new(0x400000),
                Access::Write,
                true,
            )
            .is_err()
        );
        let data = translate_leaf(
            &words,
            loaded.address.root,
            UserVa::new(0x402000),
            Access::Write,
            true,
        )
        .unwrap();
        assert_eq!(&frames.data_at(data.output.raw())[..3], b"hi\n");
        assert!(
            frames.data_at(data.output.raw())[3..]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(frames.next_data, 0x90_3000, "one data grant per user page");
        assert_eq!(
            frames.next_table, 0x80_9000,
            "one root, five user tables and three private copy tables"
        );
        assert_ne!(loaded.address.root.address().raw(), 0x60_0000);
    }

    #[test]
    fn guest_stack_has_sysv_order_and_exact_auxv_addresses() {
        let spec = InitialStackSpec {
            entry: 0x401000,
            phdr: 0x400040,
            phent: 56,
            phnum: 2,
            argv: &[b"/tiny", b"seven"],
            envp: &[b"MODE=test"],
            random: [0x5a; 16],
            stack_top: 0x7fff_0000,
            stack_size: 0x4000,
        };
        let stack = build_initial_stack(&spec).unwrap();
        let word = |va: u64| {
            let offset = (va - stack.base) as usize;
            u64::from_le_bytes(stack.bytes[offset..offset + 8].try_into().unwrap())
        };
        assert_eq!(stack.rsp & 15, 0);
        assert_eq!(word(stack.rsp), 2);
        assert_eq!(word(stack.rsp + 24), 0);
        assert_eq!(word(stack.rsp + 40), 0);
        for (address, expected) in [
            (word(stack.rsp + 8), b"/tiny\0".as_slice()),
            (word(stack.rsp + 16), b"seven\0".as_slice()),
            (word(stack.rsp + 32), b"MODE=test\0".as_slice()),
        ] {
            assert_eq!(
                &stack.bytes[(address - stack.base) as usize..][..expected.len()],
                expected
            );
        }
        let aux_start = stack.rsp + 48;
        for (index, &(tag, value)) in stack.auxv.iter().enumerate() {
            assert_eq!(word(aux_start + index as u64 * 16), tag);
            assert_eq!(word(aux_start + index as u64 * 16 + 8), value);
        }
        let random = stack.auxv.iter().find(|(tag, _)| *tag == 25).unwrap().1;
        assert_eq!(
            &stack.bytes[(random - stack.base) as usize..][..16],
            &[0x5a; 16]
        );
        assert_eq!(stack.auxv.last(), Some(&(0, 0)));
    }
}

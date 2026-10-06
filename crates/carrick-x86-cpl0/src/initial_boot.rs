use super::InitialWords;
use carrick_el1::isa::x86::initial_mm::{
    InitialDataGrant, InitialFrameSource, InitialImageRegion, InitialImageSpec, InitialSourceRange,
    InitialStackSpec, install_initial_image,
};
use carrick_el1_abi::{
    X86_CPL0_INITIAL_EXTENT_GPA, X86_CPL0_INITIAL_EXTENT_MAX_SIZE, X86_CPL0_INITIAL_EXTENT_VA,
    X86_INITIAL_BOOT_LOADED, X86_INITIAL_BOOT_MAGIC, X86_INITIAL_BOOT_PORT,
    X86_INITIAL_BOOT_REFUSED, X86_INITIAL_BOOT_VERSION, X86_INITIAL_MAX_REGIONS,
    X86_INITIAL_MAX_STRINGS, X86InitialBootGrant, X86InitialBootRegion, X86InitialBootRequest,
    X86InitialBootString,
};
use carrick_guest_arch::{EditBacking, EditPermissions, FrameGpa, GuestLen, MmuBackend, RootGpa, UserVa};
use core::num::NonZeroU64;
use rust_alloc::vec::Vec;

const EXTENT_BASE: u64 = X86_CPL0_INITIAL_EXTENT_GPA;
const PAGE: u64 = 4096;

const fn extent_va(gpa: u64) -> u64 {
    X86_CPL0_INITIAL_EXTENT_VA + (gpa - EXTENT_BASE)
}

fn span(gpa: u64, bytes: u64, end: u64) -> bool {
    gpa >= EXTENT_BASE && gpa.checked_add(bytes).is_some_and(|last| last <= end)
}

fn area(gpa: u64, bytes: u64, end: u64) -> Option<(u64, u64)> {
    if !span(gpa, bytes, end) { return None; }
    Some((gpa, gpa.checked_add(bytes)?))
}

fn disjoint(mut areas: Vec<(u64, u64)>) -> bool {
    areas.retain(|(start, end)| start != end);
    areas.sort_unstable_by_key(|(start, _)| *start);
    areas.windows(2).all(|pair| pair[0].1 <= pair[1].0)
}

fn records<T>(gpa: u64, count: usize, end: u64) -> Option<&'static [T]> {
    let bytes = count.checked_mul(core::mem::size_of::<T>())? as u64;
    if !gpa.is_multiple_of(core::mem::align_of::<T>() as u64) || !span(gpa, bytes, end) {
        return None;
    }
    // SAFETY: the sole stopped carrier staged these retained records in the
    // supervisor direct window before this entry was installed on CPU 0.
    Some(unsafe { core::slice::from_raw_parts(extent_va(gpa) as *const T, count) })
}

struct GrantedFrames<'a> {
    grants: &'a [X86InitialBootGrant],
    table_count: usize,
    tables_taken: usize,
    data_taken: usize,
    staged_end: u64,
    extent_end: u64,
}

impl GrantedFrames<'_> {
    fn valid(&self, grant: &X86InitialBootGrant) -> bool {
        grant.gpa.is_multiple_of(PAGE)
            && span(grant.gpa, PAGE, self.extent_end)
            && grant.frame_id != 0
            && grant.mapping_id != 0
            && grant.owner_generation != 0
            && grant.inventory_revision != 0
    }
}

impl InitialFrameSource for GrantedFrames<'_> {
    fn take_zeroed_table(&mut self) -> Option<RootGpa> {
        let grant = self.grants.get(self.tables_taken)?;
        if self.tables_taken >= self.table_count || !self.valid(grant) {
            return None;
        }
        self.tables_taken += 1;
        RootGpa::page_aligned(FrameGpa::new(grant.gpa))
    }

    fn take_zeroed_data(&mut self) -> Option<InitialDataGrant> {
        let grant = self.grants.get(self.table_count + self.data_taken)?;
        if !self.valid(grant) {
            return None;
        }
        self.data_taken += 1;
        Some(InitialDataGrant {
            frame: FrameGpa::new(grant.gpa),
            backing: EditBacking {
                frame_id: NonZeroU64::new(grant.frame_id)?,
                mapping_id: NonZeroU64::new(grant.mapping_id)?,
                owner_generation: NonZeroU64::new(grant.owner_generation)?,
                inventory_revision: NonZeroU64::new(grant.inventory_revision)?,
            },
        })
    }

    fn copy_guest_data(&mut self, grant: InitialDataGrant, offset: u16, source: FrameGpa, len: u16) -> bool {
        let start = source.raw();
        if !self.grants[self.table_count..self.table_count + self.data_taken]
            .iter().any(|candidate| candidate.gpa == grant.frame.raw())
            || !span(start, u64::from(len), self.staged_end)
            || u64::from(offset) + u64::from(len) > PAGE
        {
            return false;
        }
        // SAFETY: the source is a staged immutable byte span, and this grant
        // is a distinct retained private frame still hidden from EL0.
        unsafe {
            core::ptr::copy_nonoverlapping(
                extent_va(start) as *const u8,
                (extent_va(grant.frame.raw()) + u64::from(offset)) as *mut u8,
                usize::from(len),
            );
        }
        true
    }

    fn write_data(&mut self, grant: InitialDataGrant, offset: u16, bytes: &[u8]) -> bool {
        if !self.grants[self.table_count..self.table_count + self.data_taken]
            .iter().any(|candidate| candidate.gpa == grant.frame.raw())
            || u64::from(offset).checked_add(bytes.len() as u64).is_none_or(|end| end > PAGE)
        {
            return false;
        }
        // SAFETY: this exact unpublished frame grant is retained, writable
        // and disjoint from the staged byte source.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (extent_va(grant.frame.raw()) + u64::from(offset)) as *mut u8,
                bytes.len(),
            );
        }
        true
    }
}

fn load(request: &mut X86InitialBootRequest) -> Option<(u64, u64)> {
    if request.magic != X86_INITIAL_BOOT_MAGIC
        || request.version != X86_INITIAL_BOOT_VERSION
        || request.region_count == 0
        || request.region_count as usize > X86_INITIAL_MAX_REGIONS
        || usize::from(request.argc) + usize::from(request.envc) > X86_INITIAL_MAX_STRINGS
        || request.extent_pages == 0
    {
        return None;
    }
    let extent_bytes = u64::from(request.extent_pages).checked_mul(PAGE)?;
    if extent_bytes > X86_CPL0_INITIAL_EXTENT_MAX_SIZE { return None; }
    let end = EXTENT_BASE.checked_add(extent_bytes)?;
    if !span(EXTENT_BASE, core::mem::size_of::<X86InitialBootRequest>() as u64, end) {
        return None;
    }
    let string_count = usize::from(request.argc) + usize::from(request.envc);
    let grant_count = (request.table_grant_count as usize).checked_add(request.data_grant_count as usize)?;
    let mut areas = Vec::with_capacity(5 + request.region_count as usize + string_count);
    areas.push(area(EXTENT_BASE, core::mem::size_of::<X86InitialBootRequest>() as u64, end)?);
    areas.push(area(request.regions_gpa, (request.region_count as usize).checked_mul(core::mem::size_of::<X86InitialBootRegion>())? as u64, end)?);
    areas.push(area(request.strings_gpa, string_count.checked_mul(core::mem::size_of::<X86InitialBootString>())? as u64, end)?);
    areas.push(area(request.grants_gpa, grant_count.checked_mul(core::mem::size_of::<X86InitialBootGrant>())? as u64, end)?);
    areas.push(area(request.publications_gpa, (request.publication_capacity as usize).checked_mul(core::mem::size_of::<carrick_el1_abi::GuestMmuPublication>())? as u64, end)?);
    if !disjoint(areas.clone()) { return None; }
    let regions = records::<X86InitialBootRegion>(request.regions_gpa, request.region_count as usize, end)?;
    let strings = records::<X86InitialBootString>(request.strings_gpa, string_count, end)?;
    let grants = records::<X86InitialBootGrant>(request.grants_gpa, grant_count, end)?;
    let publications = records::<carrick_el1_abi::GuestMmuPublication>(request.publications_gpa, request.publication_capacity as usize, end)?;
    let first_grant = grants.first()?.gpa;
    if request.table_grant_count == 0 || request.data_grant_count == 0 || request.publication_capacity < request.data_grant_count {
        return None;
    }
    for (index, grant) in grants.iter().enumerate() {
        if grant.gpa != first_grant.checked_add(index as u64 * PAGE)? || grant.gpa < request.publications_gpa {
            return None;
        }
    }
    let staged_end = first_grant;
    areas.push(area(first_grant, grant_count.checked_mul(PAGE as usize)? as u64, end)?);
    for region in regions {
        areas.push(area(region.source_gpa, region.initialized_len, staged_end)?);
    }
    for string in strings {
        areas.push(area(string.source_gpa, string.len, staged_end)?);
    }
    if !disjoint(areas) { return None; }
    let mut image_regions = Vec::with_capacity(regions.len());
    for region in regions {
        if !span(region.source_gpa, region.initialized_len, staged_end) || region.permissions & !7 != 0 {
            return None;
        }
        image_regions.push(InitialImageRegion {
            start: UserVa::new(region.start),
            len: GuestLen::new(region.len),
            initialized_offset: GuestLen::new(region.initialized_offset),
            initialized: InitialSourceRange { start: FrameGpa::new(region.source_gpa), len: GuestLen::new(region.initialized_len) },
            perms: EditPermissions {
                readable: region.permissions & 1 != 0,
                writable: region.permissions & 2 != 0,
                executable: region.permissions & 4 != 0,
                user: true,
            },
        });
    }
    let mut argv = Vec::with_capacity(request.argc as usize);
    let mut envp = Vec::with_capacity(request.envc as usize);
    for (index, string) in strings.iter().enumerate() {
        if string.len > 0x1_0000 || !span(string.source_gpa, string.len, staged_end) { return None; }
        // SAFETY: the host staged immutable bytes in this retained window.
        let value = unsafe { core::slice::from_raw_parts(extent_va(string.source_gpa) as *const u8, string.len as usize) };
        if index < request.argc as usize { argv.push(value); } else { envp.push(value); }
    }
    let stack = InitialStackSpec {
        entry: request.entry,
        phdr: request.phdr,
        phent: request.phent,
        phnum: request.phnum,
        argv: &argv,
        envp: &envp,
        random: request.random,
        stack_top: request.stack_top,
        stack_size: request.stack_size,
    };
    let source_root = carrick_el1::isa::x86::hardware_live_root().ok()?;
    if source_root.address().raw() != 0x60_0000 { return None; }
    let mut source = GrantedFrames {
        grants,
        table_count: request.table_grant_count as usize,
        tables_taken: 0,
        data_taken: 0,
        staged_end,
        extent_end: end,
    };
    let mm = NonZeroU64::new(request.mm_key)?;
    let generation = NonZeroU64::new(request.generation)?;
    // SAFETY: CPU 1 is stopped. The caller owns this unopened MM, the one
    // source root and the complete disjoint private frame grant transaction.
    let table_end = first_grant.checked_add(request.table_grant_count as u64 * PAGE)?;
    let loaded = unsafe { install_initial_image(
        &InitialWords::production(first_grant, table_end), &mut source, source_root, mm, generation,
        &InitialImageSpec { regions: &image_regions, stack },
    ) }.ok()?;
    if loaded.publications.len() > publications.len() { return None; }
    // SAFETY: the stopped host reserved exactly this writable publication
    // array and guest MM owner has completed every descriptor edit.
    unsafe {
        core::ptr::copy_nonoverlapping(loaded.publications.as_ptr(), publications.as_ptr() as *mut _, loaded.publications.len());
    }
    request.publication_count = loaded.publications.len() as u32;
    request.result_root_gpa = loaded.address.root.address().raw();
    request.result_rsp = loaded.stack_pointer;
    request.result_table_used = source.tables_taken as u32;
    request.result_data_used = source.data_taken as u32;
    request.result_initial_break = loaded.initial_break.raw();
    super::anonymous::admit_tables(first_grant, table_end);
    Some((request.entry, loaded.stack_pointer))
}

core::arch::global_asm!(
    ".global carrick_x86_boot_iret",
    "carrick_x86_boot_iret:",
    "push 0x1b",
    "push rsi",
    "push 0x202",
    "push 0x23",
    "push rdi",
    "swapgs",
    "iretq",
);

unsafe extern "C" { fn carrick_x86_boot_iret(entry: u64, stack: u64) -> !; }

fn fatal_boot() -> ! {
    // SAFETY: the carrier owns this fatal control doorbell; HLT prevents a
    // refused boot from spinning inside KVM_RUN if the host resumes it.
    unsafe { core::arch::asm!("out dx, al", in("dx") super::FATAL_PORT, in("al") 0_u8, options(nostack, preserves_flags)); }
    super::halt()
}

#[unsafe(no_mangle)]
pub extern "C" fn carrick_x86_initial_boot(request_va: u64) -> ! {
    if request_va != X86_CPL0_INITIAL_EXTENT_VA { fatal_boot(); }
    // SAFETY: the carrier owns and retained this exact initialized request.
    let request = unsafe { &mut *(request_va as *mut X86InitialBootRequest) };
    let loaded = load(request);
    request.result_status = if loaded.is_some() { X86_INITIAL_BOOT_LOADED } else { X86_INITIAL_BOOT_REFUSED };
    // SAFETY: OUT is the carrier's privileged boot-completion doorbell. The
    // host authenticates descriptors and inventory before resuming this CPU.
    unsafe { core::arch::asm!("out dx, al", in("dx") X86_INITIAL_BOOT_PORT, in("rax") request_va, options(nostack, preserves_flags)); }
    let Some((entry, stack)) = loaded else { fatal_boot() };
    let Some(root) = RootGpa::page_aligned(FrameGpa::new(request.result_root_gpa)) else { fatal_boot() };
    let Some(mm) = NonZeroU64::new(request.mm_key) else { fatal_boot() };
    let Some(generation) = NonZeroU64::new(request.generation) else { fatal_boot() };
    let context = carrick_guest_arch::AddressContext {
        root,
        mm: carrick_guest_arch::MmGeneration::new(mm),
        generation: carrick_guest_arch::ContextGeneration::new(generation),
    };
    if carrick_el1::isa::x86::X86Backend.install_context(context).is_err() { loop { core::hint::spin_loop(); } }
    // SAFETY: after host acknowledgement, the exact MM is published and the
    // user selectors/entry/stack came from the guest-owned image transaction.
    unsafe { carrick_x86_boot_iret(entry, stack) }
}

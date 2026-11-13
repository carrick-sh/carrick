//! The staged inputs of an x86 exec successor's in-guest build (#2235).
//!
//! The host loads and checks the successor image before the arm, then
//! stages one carrier-retained private extent tied to that exact
//! preparation: a header, the image's rows and strings, the reserved table
//! and data grants, a publication area, and the image's initialized file
//! bytes. After the arm the adopter reads the extent through the
//! predecessor's exact-MM copy window, runs boot's editor over the grants,
//! and writes its descriptor publications and results back to the same
//! extent. The host never writes a descriptor or the successor's stack; it
//! reads the results back only in the consuming adoption crossing.
//!
//! This module is the one owner of the extent's wire layout: the host
//! encodes it ([`encode_exec_build`]), the guest decodes and runs it
//! ([`ExecBuildPlan`]), and the host authenticates the results
//! ([`read_exec_build_results`]).
extern crate alloc as build_alloc;

use super::x86_initial_mm::{
    InitialDataGrant, InitialFrameSource, InitialImageRegion, InitialImageSpec, InitialMmError,
    InitialMmImage, InitialSourceRange, InitialStackSpec,
};
use build_alloc::vec::Vec;
use carrick_core_abi::service::ExecBuildSource;
use carrick_core_abi::{
    X86_INITIAL_BOOT_LOADED, X86_INITIAL_BOOT_PENDING, X86_INITIAL_BOOT_VERSION,
    X86_INITIAL_MAX_REGIONS, X86InitialBootGrant, X86InitialBootRegion, X86InitialBootRequest,
    X86InitialBootString,
};
use carrick_el1_abi::GuestMmuPublication;
use carrick_guest_arch::{EditBacking, EditPermissions, FrameGpa, GuestLen, RootGpa, UserVa};
use core::mem::size_of;
use core::num::NonZeroU64;

const PAGE: u64 = 4096;

/// The magic of an exec build header; boot's request record carries
/// [`carrick_core_abi::X86_INITIAL_BOOT_MAGIC`] instead.
pub const X86_EXEC_BUILD_MAGIC: u64 = u64::from_le_bytes(*b"CXEXEC01");

/// A window access the guest could not map, or a span past its page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowRefused;

/// Page access to one build extent. Every call names one page and a span
/// inside it; the guest maps that page alone, for that call alone.
pub trait ExecBuildWindow {
    /// Read `out.len()` bytes at `offset` of the extent page `page`.
    fn read(&mut self, page: FrameGpa, offset: usize, out: &mut [u8]) -> Result<(), WindowRefused>;
    /// Write `bytes` at `offset` of the page `page` (an extent page or an
    /// unpublished data grant).
    fn write(&mut self, page: FrameGpa, offset: usize, bytes: &[u8]) -> Result<(), WindowRefused>;
    /// Copy `len` bytes from `source_offset` of the extent page `source`
    /// to `destination_offset` of the unpublished data grant `destination`.
    fn copy(
        &mut self,
        source: FrameGpa,
        source_offset: usize,
        destination: FrameGpa,
        destination_offset: usize,
        len: usize,
    ) -> Result<(), WindowRefused>;
}

fn split_pages(gpa: u64, len: usize) -> impl Iterator<Item = (FrameGpa, usize, usize, usize)> {
    // (page, offset in page, offset in span, length)
    let mut done = 0usize;
    core::iter::from_fn(move || {
        if done >= len {
            return None;
        }
        let address = gpa + done as u64;
        let offset = (address & (PAGE - 1)) as usize;
        let take = (PAGE as usize - offset).min(len - done);
        let item = (FrameGpa::new(address & !(PAGE - 1)), offset, done, take);
        done += take;
        Some(item)
    })
}

fn read_span(window: &mut impl ExecBuildWindow, gpa: u64, out: &mut [u8]) -> bool {
    let len = out.len();
    split_pages(gpa, len)
        .all(|(page, offset, at, take)| window.read(page, offset, &mut out[at..at + take]).is_ok())
}

fn write_span(window: &mut impl ExecBuildWindow, gpa: u64, bytes: &[u8]) -> bool {
    split_pages(gpa, bytes.len())
        .all(|(page, offset, at, take)| window.write(page, offset, &bytes[at..at + take]).is_ok())
}

fn as_bytes<T: Copy>(records: &[T]) -> &[u8] {
    // SAFETY: every caller passes padding-free repr(C) records of u64/u32
    // words, fully initialized, borrowed for the returned lifetime.
    unsafe {
        core::slice::from_raw_parts(
            records.as_ptr().cast::<u8>(),
            core::mem::size_of_val(records),
        )
    }
}

fn from_bytes<T: Copy>(bytes: &[u8]) -> Option<Vec<T>> {
    if !bytes.len().is_multiple_of(size_of::<T>()) {
        return None;
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(bytes.len() / size_of::<T>())
        .ok()?;
    for chunk in bytes.chunks_exact(size_of::<T>()) {
        // SAFETY: every bit pattern of these u64/u32-only records is valid;
        // the read is unaligned over exactly one record's bytes.
        records.push(unsafe { core::ptr::read_unaligned(chunk.as_ptr().cast::<T>()) });
    }
    Some(records)
}

const fn page_up(value: u64) -> u64 {
    (value + PAGE - 1) & !(PAGE - 1)
}

/// One page-rounded PT_LOAD region of an exec image, as the host's loader
/// describes it.
pub struct ExecBuildRegion<'a> {
    pub start: u64,
    pub end: u64,
    pub initialized_offset: u64,
    pub file_bytes: &'a [u8],
    /// Bit 0 read, bit 1 write, bit 2 execute.
    pub permissions: u64,
}

/// Everything the host stages for one build.
pub struct ExecBuildInputs<'a> {
    pub regions: &'a [ExecBuildRegion<'a>],
    pub executable_region_count: usize,
    pub entry: u64,
    pub executable_entry: u64,
    pub interpreter_base: u64,
    pub phdr: u64,
    pub phent: u16,
    pub phnum: u16,
    pub argv: &'a [Vec<u8>],
    pub env: &'a [Vec<u8>],
    /// The reserved fork-stock tables, in the order the editor takes them;
    /// the first is the sealed root.
    pub tables: &'a [RootGpa],
    /// The inventory data grants, in the order the editor takes them.
    pub data: &'a [X86InitialBootGrant],
    pub stack_top: u64,
    pub stack_size: u64,
    pub random: [u8; 16],
    pub mm_key: NonZeroU64,
    pub generation: NonZeroU64,
}

/// Where one encoded extent's areas sit, as absolute GPAs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExtentLayout {
    regions: u64,
    strings: u64,
    grants: u64,
    string_bytes: u64,
    publications: u64,
    image: u64,
    end: u64,
}

impl ExtentLayout {
    fn of(header: &X86InitialBootRequest, base: u64, string_bytes: u64) -> Option<Self> {
        let regions = base + size_of::<X86InitialBootRequest>() as u64;
        let strings = regions.checked_add(
            u64::from(header.region_count) * size_of::<X86InitialBootRegion>() as u64,
        )?;
        let string_count = u64::from(header.argc) + u64::from(header.envc);
        let grants =
            strings.checked_add(string_count * size_of::<X86InitialBootString>() as u64)?;
        let grant_count =
            u64::from(header.table_grant_count).checked_add(u64::from(header.data_grant_count))?;
        let string_start = grants
            .checked_add(grant_count.checked_mul(size_of::<X86InitialBootGrant>() as u64)?)?;
        let publications = page_up(string_start.checked_add(string_bytes)?);
        let image = page_up(
            publications.checked_add(
                u64::from(header.publication_capacity)
                    .checked_mul(size_of::<GuestMmuPublication>() as u64)?,
            )?,
        );
        Some(Self {
            regions,
            strings,
            grants,
            string_bytes: string_start,
            publications,
            image,
            end: image,
        })
    }
}

/// An encoded extent: its bytes (a whole number of pages), the build source
/// the manifest seals, and how many leading bytes hold the records and the
/// publication area (everything but the staged image bytes), the prefix
/// the host keeps to authenticate the build's results.
pub struct EncodedExecBuild {
    pub bytes: Vec<u8>,
    pub source: ExecBuildSource,
    pub results_len: usize,
}

/// One extent's header, areas and region records at `base`, before any
/// byte is written.
struct LaidOutExtent<'a> {
    header: X86InitialBootRequest,
    layout: ExtentLayout,
    regions: Vec<X86InitialBootRegion>,
    image_spans: Vec<(u64, &'a [u8])>,
    image_end: u64,
}

fn lay_out<'a>(
    base: FrameGpa,
    inputs: &ExecBuildInputs<'a>,
) -> Result<LaidOutExtent<'a>, InitialMmError> {
    let invalid = InitialMmError::InvalidRange;
    if base.raw() == 0
        || !base.raw().is_multiple_of(PAGE)
        || inputs.regions.is_empty()
        || inputs.regions.len() > X86_INITIAL_MAX_REGIONS
        || inputs.executable_region_count == 0
        || inputs.executable_region_count > inputs.regions.len()
        || inputs.tables.is_empty()
        || inputs.data.is_empty()
    {
        return Err(invalid);
    }
    let string_bytes = inputs
        .argv
        .iter()
        .chain(inputs.env)
        .try_fold(0u64, |sum, value| sum.checked_add(value.len() as u64))
        .ok_or(invalid)?;
    let mut header = X86InitialBootRequest {
        magic: X86_EXEC_BUILD_MAGIC,
        version: X86_INITIAL_BOOT_VERSION,
        region_count: inputs.regions.len() as u32,
        entry: inputs.entry,
        phdr: inputs.phdr,
        phent: inputs.phent,
        phnum: inputs.phnum,
        argc: u16::try_from(inputs.argv.len()).map_err(|_| InitialMmError::StackTooLarge)?,
        envc: u16::try_from(inputs.env.len()).map_err(|_| InitialMmError::StackTooLarge)?,
        table_grant_count: u32::try_from(inputs.tables.len()).map_err(|_| invalid)?,
        data_grant_count: u32::try_from(inputs.data.len()).map_err(|_| invalid)?,
        publication_capacity: u32::try_from(inputs.data.len()).map_err(|_| invalid)?,
        publication_count: 0,
        stack_top: inputs.stack_top,
        stack_size: inputs.stack_size,
        random: inputs.random,
        result_status: X86_INITIAL_BOOT_PENDING,
        mm_key: inputs.mm_key.get(),
        generation: inputs.generation.get(),
        executable_entry: inputs.executable_entry,
        interpreter_base: inputs.interpreter_base,
        executable_region_count: inputs.executable_region_count as u32,
        layout_hash: carrick_el1_abi::EL1_ABI_LAYOUT_HASH,
        ..Default::default()
    };
    let layout = ExtentLayout::of(&header, base.raw(), string_bytes).ok_or(invalid)?;
    header.regions_gpa = layout.regions;
    header.strings_gpa = layout.strings;
    header.grants_gpa = layout.grants;
    header.publications_gpa = layout.publications;
    // Image bytes: each region's on its own pages, page offset preserved.
    let mut image_end = layout.image;
    let mut regions = Vec::with_capacity(inputs.regions.len());
    let mut image_spans = Vec::with_capacity(inputs.regions.len());
    for region in inputs.regions {
        if region.end <= region.start || region.permissions & !7 != 0 {
            return Err(invalid);
        }
        let first = region
            .start
            .checked_add(region.initialized_offset)
            .ok_or(invalid)?;
        let source = if region.file_bytes.is_empty() {
            // Nothing is copied; the editor still requires a real address.
            layout.image
        } else {
            let source = image_end + (first & (PAGE - 1));
            image_end = page_up(
                source
                    .checked_add(region.file_bytes.len() as u64)
                    .ok_or(invalid)?,
            );
            image_spans.push((source, region.file_bytes));
            source
        };
        regions.push(X86InitialBootRegion {
            start: region.start,
            len: region.end - region.start,
            initialized_offset: region.initialized_offset,
            source_gpa: source,
            initialized_len: region.file_bytes.len() as u64,
            permissions: region.permissions,
        });
    }
    header.extent_pages = u32::try_from((image_end - base.raw()) / PAGE).map_err(|_| invalid)?;
    Ok(LaidOutExtent {
        header,
        layout,
        regions,
        image_spans,
        image_end,
    })
}

/// The pages one build extent for `inputs` takes, wherever it is placed
/// (only the counts and lengths of `inputs` matter, never their values).
pub fn exec_build_pages(inputs: &ExecBuildInputs<'_>) -> Result<u32, InitialMmError> {
    Ok(lay_out(FrameGpa::new(PAGE), inputs)?.header.extent_pages)
}

/// Encode one build extent at `base`. The image bytes of each region start
/// on their own page at the same page offset as their first user address,
/// so every copy the editor makes reads exactly one staged page.
pub fn encode_exec_build(
    base: FrameGpa,
    inputs: &ExecBuildInputs<'_>,
) -> Result<EncodedExecBuild, InitialMmError> {
    let LaidOutExtent {
        header,
        layout,
        regions,
        image_spans,
        image_end,
    } = lay_out(base, inputs)?;
    let source =
        ExecBuildSource::checked(base, header.extent_pages).ok_or(InitialMmError::InvalidRange)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact((image_end - base.raw()) as usize)
        .map_err(|_| InitialMmError::FrameUnavailable)?;
    bytes.resize((image_end - base.raw()) as usize, 0);
    let at = |gpa: u64| (gpa - base.raw()) as usize;
    let mut put = |gpa: u64, data: &[u8]| {
        bytes[at(gpa)..at(gpa) + data.len()].copy_from_slice(data);
    };
    put(base.raw(), as_bytes(core::slice::from_ref(&header)));
    put(layout.regions, as_bytes(&regions));
    let mut cursor = layout.string_bytes;
    let mut strings = Vec::with_capacity(inputs.argv.len() + inputs.env.len());
    for value in inputs.argv.iter().chain(inputs.env) {
        strings.push(X86InitialBootString {
            source_gpa: cursor,
            len: value.len() as u64,
        });
        put(cursor, value);
        cursor += value.len() as u64;
    }
    put(layout.strings, as_bytes(&strings));
    let grants: Vec<X86InitialBootGrant> = inputs
        .tables
        .iter()
        .map(|table| X86InitialBootGrant {
            gpa: table.address().raw(),
            ..Default::default()
        })
        .chain(inputs.data.iter().copied())
        .collect();
    put(layout.grants, as_bytes(&grants));
    for (source, data) in image_spans {
        put(source, data);
    }
    Ok(EncodedExecBuild {
        bytes,
        source,
        results_len: at(layout.image),
    })
}

/// A decoded, checked build extent: what the guest reads before it takes a
/// single grant.
pub struct ExecBuildPlan {
    source: ExecBuildSource,
    header: X86InitialBootRequest,
    layout: ExtentLayout,
    regions: Vec<X86InitialBootRegion>,
    strings: Vec<Vec<u8>>,
    grants: Vec<X86InitialBootGrant>,
}

impl ExecBuildPlan {
    /// Read and check the extent `source` names for successor `mm` at
    /// `generation`. Every span is checked to lie in its own area of the
    /// extent before anything is used.
    pub fn decode(
        window: &mut impl ExecBuildWindow,
        source: ExecBuildSource,
        mm: NonZeroU64,
        generation: NonZeroU64,
    ) -> Result<Self, InitialMmError> {
        let invalid = InitialMmError::InvalidRange;
        let mut raw = [0u8; size_of::<X86InitialBootRequest>()];
        if !read_span(window, source.base.raw(), &mut raw) {
            return Err(InitialMmError::FrameUnavailable);
        }
        let header = from_bytes::<X86InitialBootRequest>(&raw)
            .and_then(|mut records| records.pop())
            .ok_or(invalid)?;
        if header.magic != X86_EXEC_BUILD_MAGIC
            || header.version != X86_INITIAL_BOOT_VERSION
            || header.layout_hash != carrick_el1_abi::EL1_ABI_LAYOUT_HASH
            || header.result_status != X86_INITIAL_BOOT_PENDING
            || header.publication_count != 0
            || header.mm_key != mm.get()
            || header.generation != generation.get()
            || header.extent_pages != source.pages.get()
            || header.region_count == 0
            || header.region_count as usize > X86_INITIAL_MAX_REGIONS
            || header.executable_region_count == 0
            || header.executable_region_count > header.region_count
            || header.table_grant_count == 0
            || header.data_grant_count == 0
            || header.publication_capacity != header.data_grant_count
        {
            return Err(invalid);
        }
        // The string bytes' length is the one area size the header does not
        // state: they fill the records up to the publication page.
        let probe = ExtentLayout::of(&header, source.base.raw(), 0).ok_or(invalid)?;
        let string_bytes = header
            .publications_gpa
            .checked_sub(probe.string_bytes)
            .ok_or(invalid)?;
        let layout = ExtentLayout::of(&header, source.base.raw(), string_bytes)
            .filter(|layout| layout.publications == header.publications_gpa)
            .ok_or(invalid)?;
        if header.regions_gpa != layout.regions
            || header.strings_gpa != layout.strings
            || header.grants_gpa != layout.grants
            || layout.image > source.end()
        {
            return Err(invalid);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact((layout.publications - layout.regions) as usize)
            .map_err(|_| InitialMmError::FrameUnavailable)?;
        records.resize((layout.publications - layout.regions) as usize, 0);
        if !read_span(window, layout.regions, &mut records) {
            return Err(InitialMmError::FrameUnavailable);
        }
        let slice = |from: u64, to: u64| {
            &records[(from - layout.regions) as usize..(to - layout.regions) as usize]
        };
        let regions = from_bytes::<X86InitialBootRegion>(slice(layout.regions, layout.strings))
            .ok_or(invalid)?;
        let string_records =
            from_bytes::<X86InitialBootString>(slice(layout.strings, layout.grants))
                .ok_or(invalid)?;
        let grants = from_bytes::<X86InitialBootGrant>(slice(layout.grants, layout.string_bytes))
            .ok_or(invalid)?;
        let mut strings = Vec::with_capacity(string_records.len());
        for string in &string_records {
            let end = string.source_gpa.checked_add(string.len).ok_or(invalid)?;
            if string.source_gpa < layout.string_bytes || end > layout.publications {
                return Err(InitialMmError::InvalidString);
            }
            strings.push(slice(string.source_gpa, end).to_vec());
        }
        for region in &regions {
            let end = region
                .source_gpa
                .checked_add(region.initialized_len)
                .ok_or(invalid)?;
            if region.source_gpa < layout.image
                || end > source.end()
                || region.permissions & !7 != 0
            {
                return Err(invalid);
            }
        }
        let (tables, data) = grants.split_at(header.table_grant_count as usize);
        if tables
            .iter()
            .any(|table| table.gpa == 0 || !table.gpa.is_multiple_of(PAGE))
            || data.iter().any(|grant| {
                grant.gpa == 0
                    || !grant.gpa.is_multiple_of(PAGE)
                    || grant.frame_id == 0
                    || grant.mapping_id == 0
                    || grant.owner_generation == 0
                    || grant.inventory_revision == 0
                    || (source.base.raw()..source.end()).contains(&grant.gpa)
            })
        {
            return Err(InitialMmError::FrameUnavailable);
        }
        Ok(Self {
            source,
            header,
            layout,
            regions,
            strings,
            grants,
        })
    }

    /// The sealed root: the first reserved table.
    pub fn root(&self) -> Option<RootGpa> {
        RootGpa::page_aligned(FrameGpa::new(self.grants.first()?.gpa))
    }

    /// Run `install` (boot's editor) over this plan's grants and staged
    /// bytes, then write its publications and results to the extent.
    pub fn build<W: ExecBuildWindow>(
        &self,
        window: &mut W,
        install: impl FnOnce(
            &mut ExecBuildFrames<'_, W>,
            &InitialImageSpec<'_>,
        ) -> Result<InitialMmImage, InitialMmError>,
    ) -> Result<InitialMmImage, InitialMmError> {
        let regions: Vec<InitialImageRegion> = self
            .regions
            .iter()
            .map(|region| InitialImageRegion {
                start: UserVa::new(region.start),
                len: GuestLen::new(region.len),
                initialized_offset: GuestLen::new(region.initialized_offset),
                initialized: InitialSourceRange {
                    start: FrameGpa::new(region.source_gpa),
                    len: GuestLen::new(region.initialized_len),
                },
                perms: EditPermissions {
                    readable: region.permissions & 1 != 0,
                    writable: region.permissions & 2 != 0,
                    executable: region.permissions & 4 != 0,
                    user: true,
                },
            })
            .collect();
        let argc = usize::from(self.header.argc);
        let argv: Vec<&[u8]> = self.strings[..argc].iter().map(Vec::as_slice).collect();
        let envp: Vec<&[u8]> = self.strings[argc..].iter().map(Vec::as_slice).collect();
        let spec = InitialImageSpec {
            regions: &regions,
            executable_region_count: self.header.executable_region_count as usize,
            entry: UserVa::new(self.header.entry),
            stack: InitialStackSpec {
                entry: self.header.executable_entry,
                interpreter_base: self.header.interpreter_base,
                phdr: self.header.phdr,
                phent: self.header.phent,
                phnum: self.header.phnum,
                argv: &argv,
                envp: &envp,
                random: self.header.random,
                stack_top: self.header.stack_top,
                stack_size: self.header.stack_size,
            },
        };
        let mut frames = ExecBuildFrames {
            window,
            plan: self,
            tables_taken: 0,
            data_taken: 0,
        };
        let image = install(&mut frames, &spec)?;
        let (tables_used, data_used) = (frames.tables_taken, frames.data_taken);
        if Some(image.address.root) != self.root()
            || image.publications.len() != data_used
            || data_used != self.header.data_grant_count as usize
        {
            return Err(InitialMmError::PublicationRefused);
        }
        if !write_span(
            window,
            self.layout.publications,
            as_bytes(&image.publications),
        ) {
            return Err(InitialMmError::FrameUnavailable);
        }
        let mut header = self.header;
        header.publication_count = image.publications.len() as u32;
        header.result_root_gpa = image.address.root.address().raw();
        header.result_rsp = image.stack_pointer;
        header.result_table_used = tables_used as u32;
        header.result_data_used = data_used as u32;
        header.result_initial_break = image.initial_break.raw();
        header.result_status = X86_INITIAL_BOOT_LOADED;
        if !write_span(
            window,
            self.source.base.raw(),
            as_bytes(core::slice::from_ref(&header)),
        ) {
            return Err(InitialMmError::FrameUnavailable);
        }
        Ok(image)
    }
}

/// The editor's frame source over one plan: the reserved tables in order,
/// the data grants in order, and copies from the plan's staged image bytes
/// only, each within one staged page.
pub struct ExecBuildFrames<'a, W> {
    window: &'a mut W,
    plan: &'a ExecBuildPlan,
    tables_taken: usize,
    data_taken: usize,
}

impl<W> ExecBuildFrames<'_, W> {
    fn taken(&self, grant: InitialDataGrant) -> bool {
        let tables = self.plan.header.table_grant_count as usize;
        self.plan.grants[tables..tables + self.data_taken]
            .iter()
            .any(|candidate| candidate.gpa == grant.frame.raw())
    }
}

impl<W: ExecBuildWindow> InitialFrameSource for ExecBuildFrames<'_, W> {
    fn take_zeroed_table(&mut self) -> Option<RootGpa> {
        if self.tables_taken >= self.plan.header.table_grant_count as usize {
            return None;
        }
        let grant = self.plan.grants.get(self.tables_taken)?;
        self.tables_taken += 1;
        RootGpa::page_aligned(FrameGpa::new(grant.gpa))
    }

    fn take_zeroed_data(&mut self) -> Option<InitialDataGrant> {
        let tables = self.plan.header.table_grant_count as usize;
        let grant = self.plan.grants.get(tables + self.data_taken)?;
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

    fn copy_guest_data(
        &mut self,
        grant: InitialDataGrant,
        offset: u16,
        source: FrameGpa,
        len: u16,
    ) -> bool {
        let start = source.raw();
        let within_page = (start & (PAGE - 1)) + u64::from(len) <= PAGE;
        if !self.taken(grant)
            || start < self.plan.layout.image
            || start
                .checked_add(u64::from(len))
                .is_none_or(|end| end > self.plan.source.end())
            || !within_page
            || u64::from(offset) + u64::from(len) > PAGE
        {
            return false;
        }
        self.window
            .copy(
                FrameGpa::new(start & !(PAGE - 1)),
                (start & (PAGE - 1)) as usize,
                grant.frame,
                usize::from(offset),
                usize::from(len),
            )
            .is_ok()
    }

    fn write_data(&mut self, grant: InitialDataGrant, offset: u16, bytes: &[u8]) -> bool {
        if !self.taken(grant)
            || u64::from(offset)
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > PAGE)
        {
            return false;
        }
        self.window
            .write(grant.frame, usize::from(offset), bytes)
            .is_ok()
    }
}

/// What a completed build reported, authenticated by the host against the
/// extent it encoded.
pub struct ExecBuildResults {
    pub root: RootGpa,
    pub stack_pointer: u64,
    pub initial_break: u64,
    pub tables_used: usize,
    pub publications: Vec<GuestMmuPublication>,
}

/// Read a completed build's results. `encoded` is the leading
/// [`EncodedExecBuild::results_len`] bytes the host encoded at `source`;
/// `current` is the same prefix read back after the guest's build. Every
/// byte the host wrote must be unchanged but the header's result fields and
/// the publication area; the results must name the sealed root and stack
/// pointer and exactly one publication per data grant.
pub fn read_exec_build_results(
    encoded: &[u8],
    current: &[u8],
    source: ExecBuildSource,
    sealed_root: RootGpa,
    sealed_stack_pointer: u64,
) -> Option<ExecBuildResults> {
    let size = size_of::<X86InitialBootRequest>();
    if encoded.len() != current.len() || encoded.len() < size {
        return None;
    }
    let before = from_bytes::<X86InitialBootRequest>(&encoded[..size])?.pop()?;
    let after = from_bytes::<X86InitialBootRequest>(&current[..size])?.pop()?;
    let mut expected = after;
    expected.publication_count = 0;
    expected.result_root_gpa = 0;
    expected.result_rsp = 0;
    expected.result_table_used = 0;
    expected.result_data_used = 0;
    expected.result_initial_break = 0;
    expected.result_status = X86_INITIAL_BOOT_PENDING;
    let publications = (before.publications_gpa.checked_sub(source.base.raw())?) as usize;
    let capacity = before.publication_capacity as usize * size_of::<GuestMmuPublication>();
    let unchanged = as_bytes(core::slice::from_ref(&expected))
        == as_bytes(core::slice::from_ref(&before))
        && publications >= size
        && publications + capacity <= encoded.len()
        && encoded[size..publications] == current[size..publications]
        && encoded[publications + capacity..] == current[publications + capacity..];
    if !unchanged
        || after.result_status != X86_INITIAL_BOOT_LOADED
        || after.result_root_gpa != sealed_root.address().raw()
        || after.result_rsp != sealed_stack_pointer
        || after.publication_count != before.data_grant_count
        || after.result_data_used != before.data_grant_count
        || after.result_table_used == 0
        || after.result_table_used > before.table_grant_count
    {
        return None;
    }
    let publications = from_bytes::<GuestMmuPublication>(current.get(
        publications
            ..publications + after.publication_count as usize * size_of::<GuestMmuPublication>(),
    )?)?;
    Some(ExecBuildResults {
        root: sealed_root,
        stack_pointer: after.result_rsp,
        initial_break: after.result_initial_break,
        tables_used: after.result_table_used as usize,
        publications,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::isa::x86_initial_mm::install_initial_image;
    use crate::isa::x86_initial_mm::tests::TestWords;
    use carrick_mmu_core::x86::descriptor_txn::{Access, LiveDescriptorWords, translate_leaf};
    use std::collections::BTreeMap;

    /// Guest RAM as whole pages; every access names one page, as the copy
    /// window maps one.
    #[derive(Default)]
    struct Ram {
        pages: BTreeMap<u64, Box<[u8; 4096]>>,
        accesses: usize,
    }
    impl Ram {
        fn page(&mut self, page: FrameGpa) -> &mut [u8; 4096] {
            self.pages
                .entry(page.raw())
                .or_insert_with(|| Box::new([0; 4096]))
        }
        fn load(&mut self, base: u64, bytes: &[u8]) {
            for (index, chunk) in bytes.chunks(4096).enumerate() {
                self.page(FrameGpa::new(base + index as u64 * 4096))[..chunk.len()]
                    .copy_from_slice(chunk);
            }
        }
        fn dump(&mut self, base: u64, pages: u32) -> Vec<u8> {
            (0..u64::from(pages))
                .flat_map(|page| self.page(FrameGpa::new(base + page * 4096)).to_vec())
                .collect()
        }
    }
    impl ExecBuildWindow for Ram {
        fn read(
            &mut self,
            page: FrameGpa,
            offset: usize,
            out: &mut [u8],
        ) -> Result<(), WindowRefused> {
            self.accesses += 1;
            out.copy_from_slice(&self.page(page)[offset..offset + out.len()]);
            Ok(())
        }
        fn write(
            &mut self,
            page: FrameGpa,
            offset: usize,
            bytes: &[u8],
        ) -> Result<(), WindowRefused> {
            self.accesses += 1;
            self.page(page)[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
        fn copy(
            &mut self,
            source: FrameGpa,
            source_offset: usize,
            destination: FrameGpa,
            destination_offset: usize,
            len: usize,
        ) -> Result<(), WindowRefused> {
            self.accesses += 1;
            let bytes = self.page(source)[source_offset..source_offset + len].to_vec();
            self.page(destination)[destination_offset..destination_offset + len]
                .copy_from_slice(&bytes);
            Ok(())
        }
    }

    const BASE: u64 = 0x200_0000;
    const TEXT: &[u8] = b"\xb8\xe7\0\0\0\xbf\x07\0\0\0\x0f\x05";

    fn grants(count: usize, first: u64) -> Vec<X86InitialBootGrant> {
        (0..count as u64)
            .map(|page| X86InitialBootGrant {
                gpa: first + page * PAGE,
                frame_id: 10 + page,
                mapping_id: 20 + page,
                owner_generation: 1,
                inventory_revision: 1,
            })
            .collect()
    }

    const ENV: &[Vec<u8>] = &[];

    fn regions() -> [ExecBuildRegion<'static>; 2] {
        [
            ExecBuildRegion {
                start: 0x40_0000,
                end: 0x40_1000,
                initialized_offset: 0,
                file_bytes: TEXT,
                permissions: 5,
            },
            // Data whose file bytes begin mid-page: the staged copy keeps
            // the same page offset, so the copy reads one staged page.
            ExecBuildRegion {
                start: 0x40_2000,
                end: 0x40_4000,
                initialized_offset: 0xff0,
                file_bytes: b"0123456789abcdefXYZ",
                permissions: 3,
            },
        ]
    }

    fn inputs<'a>(
        argv: &'a [Vec<u8>],
        tables: &'a [RootGpa],
        data: &'a [X86InitialBootGrant],
        regions: &'a [ExecBuildRegion<'a>],
    ) -> ExecBuildInputs<'a> {
        ExecBuildInputs {
            regions,
            executable_region_count: 2,
            entry: 0x40_0000,
            executable_entry: 0x40_0000,
            interpreter_base: 0,
            phdr: 0x40_0040,
            phent: 56,
            phnum: 1,
            argv,
            env: ENV,
            tables,
            data,
            stack_top: 0x7fff_0000,
            stack_size: 0x4000,
            random: [7; 16],
            mm_key: NonZeroU64::new(91).unwrap(),
            generation: NonZeroU64::new(3).unwrap(),
        }
    }

    fn encode(
        argv: &[Vec<u8>],
        tables: &[RootGpa],
        data: &[X86InitialBootGrant],
    ) -> EncodedExecBuild {
        let regions = regions();
        encode_exec_build(FrameGpa::new(BASE), &inputs(argv, tables, data, &regions)).unwrap()
    }

    fn stock(count: u64) -> Vec<RootGpa> {
        (0..count)
            .map(|page| RootGpa::page_aligned(FrameGpa::new(0xa0_0000 + page * PAGE)).unwrap())
            .collect()
    }

    /// The host encodes the extent, the guest reads it through single-page
    /// accesses and runs boot's editor over its grants, and the host reads
    /// back exactly the results that name the sealed root and stack: the
    /// file bytes land at their page offsets, the stack carries argv, and
    /// one publication per data grant comes back.
    #[test]
    fn a_staged_build_round_trips_through_single_page_access() {
        let words = TestWords::new();
        let predecessor = RootGpa::page_aligned(FrameGpa::new(0x70_0000)).unwrap();
        words
            .store_unlinked(predecessor.address().raw() + 511 * 8, 0x20_0003)
            .unwrap();
        // One frame per page of every row (three) and of the stack (four);
        // the root, five prefix tables and the private copy branch.
        let data = grants(3 + 4, 0x90_0000);
        let tables = stock(6 + 3);
        let argv = [b"/bin/successor".to_vec(), b"arg".to_vec()];
        let encoded = encode(&argv, &tables, &data);
        assert_eq!(encoded.source.base.raw(), BASE);
        let mut ram = Ram::default();
        ram.load(BASE, &encoded.bytes);
        let mm = NonZeroU64::new(91).unwrap();
        let generation = NonZeroU64::new(3).unwrap();
        let plan = ExecBuildPlan::decode(&mut ram, encoded.source, mm, generation).unwrap();
        assert_eq!(plan.root(), Some(tables[0]));
        let image = plan
            .build(&mut ram, |frames, spec| {
                // SAFETY: the isolated fixture owns every table and frame.
                unsafe { install_initial_image(&words, frames, predecessor, mm, generation, spec) }
            })
            .unwrap();
        assert_eq!(
            exec_build_pages(&inputs(&argv, &tables, &data, &regions())).unwrap(),
            encoded.source.pages.get()
        );
        let mut current = ram.dump(BASE, encoded.source.pages.get());
        current.truncate(encoded.results_len);
        let prefix = &encoded.bytes[..encoded.results_len];
        let results = read_exec_build_results(
            prefix,
            &current,
            encoded.source,
            tables[0],
            image.stack_pointer,
        )
        .expect("the host authenticates the guest's results");
        assert_eq!(results.publications, image.publications);
        assert_eq!(results.publications.len(), data.len());
        assert_eq!(results.initial_break, 0x40_4000);
        let byte_at = |ram: &mut Ram, va: u64| {
            let leaf =
                translate_leaf(&words, tables[0], UserVa::new(va), Access::Read, true).unwrap();
            ram.page(FrameGpa::new(leaf.output.raw() & !(PAGE - 1)))
                [(leaf.output.raw() & (PAGE - 1)) as usize]
        };
        assert_eq!(byte_at(&mut ram, 0x40_0000), TEXT[0]);
        assert_eq!(byte_at(&mut ram, 0x40_2ff0), b'0');
        assert_eq!(byte_at(&mut ram, 0x40_3002), b'Z');
        assert_eq!(byte_at(&mut ram, 0x40_2fef), 0);
        let argc = {
            let leaf = translate_leaf(
                &words,
                tables[0],
                UserVa::new(image.stack_pointer),
                Access::Read,
                true,
            )
            .unwrap();
            let page = *ram.page(FrameGpa::new(leaf.output.raw() & !(PAGE - 1)));
            let at = (leaf.output.raw() & (PAGE - 1)) as usize;
            u64::from_le_bytes(page[at..at + 8].try_into().unwrap())
        };
        assert_eq!(argc, 2);
        // A tampered host field, or a result naming another root, refuses.
        let mut tampered = current.clone();
        tampered[size_of::<X86InitialBootRequest>()] ^= 1;
        assert!(
            read_exec_build_results(
                prefix,
                &tampered,
                encoded.source,
                tables[0],
                image.stack_pointer
            )
            .is_none()
        );
        assert!(
            read_exec_build_results(
                prefix,
                &current,
                encoded.source,
                tables[1],
                image.stack_pointer
            )
            .is_none()
        );
        // Unbuilt: nothing to authenticate.
        assert!(
            read_exec_build_results(
                prefix,
                prefix,
                encoded.source,
                tables[0],
                image.stack_pointer
            )
            .is_none()
        );
    }

    /// The guest refuses an extent for another successor, a header whose
    /// areas do not lie where the layout puts them, and a data grant inside
    /// the extent itself, before it takes any grant.
    #[test]
    fn a_foreign_or_malformed_extent_is_refused_before_any_grant() {
        let tables = stock(7);
        let data = grants(7, 0x90_0000);
        let encoded = encode(&[b"/bin/successor".to_vec()], &tables, &data);
        let mm = NonZeroU64::new(91).unwrap();
        let generation = NonZeroU64::new(3).unwrap();
        let mut ram = Ram::default();
        ram.load(BASE, &encoded.bytes);
        assert!(
            ExecBuildPlan::decode(
                &mut ram,
                encoded.source,
                NonZeroU64::new(92).unwrap(),
                generation
            )
            .is_err()
        );
        assert!(ExecBuildPlan::decode(&mut ram, encoded.source, mm, NonZeroU64::MIN).is_err());
        let mut moved = encoded.bytes.clone();
        // grants_gpa
        let offset = core::mem::offset_of!(X86InitialBootRequest, grants_gpa);
        moved[offset] ^= 8;
        let mut ram = Ram::default();
        ram.load(BASE, &moved);
        assert!(ExecBuildPlan::decode(&mut ram, encoded.source, mm, generation).is_err());
        let inside = grants(7, BASE);
        let encoded = encode(&[b"/bin/successor".to_vec()], &tables, &inside);
        let mut ram = Ram::default();
        ram.load(BASE, &encoded.bytes);
        assert!(ExecBuildPlan::decode(&mut ram, encoded.source, mm, generation).is_err());
    }
}

//! The reservation rows of a native exec successor's image.
//!
//! A native successor's address space has one authority, its ring-owned
//! reservation root. Its ELF images (the executable and its interpreter) are
//! therefore not pre-built by the carrier: every file-backed page becomes a
//! private file node whose byte source is the loaded image, and every bss
//! page a private anonymous node, both supplied by the ring on first touch
//! exactly like a private file `mmap`. The ring then edits those mappings
//! itself (RELRO `mprotect`, `munmap`) because the leaves it builds are its
//! own. The heap backing is likewise left to the root's brk policy. Everything
//! else the carrier still builds (stack, vDSO) is recorded as an opaque row,
//! so no carrier-built user leaf lies outside a node.
use super::backing::{PrivateFileMapEntry, boot_private_file_backings};
use super::*;
use carrick_el1_abi::{
    ReservationMm, ReservationNodeFlags, ReservationProtection, ReservationRange,
};

/// One successor root row: its range, protection and flags, and for a file
/// page the index of its loaded-image source and the offset into it.
#[derive(::core::clone::Clone, ::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub(in crate::dispatch) struct SuccessorRow {
    pub(in crate::dispatch) range: ReservationRange,
    pub(in crate::dispatch) protection: ReservationProtection,
    pub(in crate::dispatch) flags: ReservationNodeFlags,
    pub(in crate::dispatch) source: Option<(usize, u64)>,
}

/// The successor's rows, the image regions the carrier must not map, and
/// the loaded-image sources the file rows name (with their path labels).
#[derive(::core::fmt::Debug)]
pub(in crate::dispatch) struct SuccessorPlan {
    pub(in crate::dispatch) rows: Vec<SuccessorRow>,
    pub(in crate::dispatch) lazy_regions: Vec<(u64, u64)>,
    pub(in crate::dispatch) sources: Vec<(PrivateFileMapEntry, String)>,
}

/// What a native successor's preparation hands its carrier: the regions it
/// leaves unmapped (the ring supplies them) and the byte sources it supplies
/// them from, already named by the successor root's nodes.
pub struct NativeSuccessorImage {
    pub lazy_regions: Vec<(u64, u64)>,
    pub sources: Vec<Arc<dyn carrick_hal::fork_stock::HostBackingRetention>>,
}

const PAGE: u64 = 4096;

fn protection(read: bool, write: bool, execute: bool) -> Option<ReservationProtection> {
    ReservationProtection::from_bits(
        u64::from(read) | (u64::from(write) << 1) | (u64::from(execute) << 2),
    )
}

/// Rows for one image: page-granular ELF spans of every region a file
/// mapping touches become lazy nodes; other user regions become opaque rows.
pub(in crate::dispatch) fn successor_plan(
    image: &crate::memory::AddressSpace,
    layout: MemoryLayout,
) -> Result<SuccessorPlan, LinuxErrno> {
    let files: Vec<_> = image
        .file_mappings()
        .iter()
        .filter(|mapping| !mapping.path.is_empty())
        .collect();
    let sources: Vec<(PrivateFileMapEntry, String)> = boot_private_file_backings(image)
        .into_iter()
        .map(|entry| {
            let label = files
                .iter()
                .find(|mapping| mapping.start <= entry.start && entry.end <= mapping.end)
                .map(|mapping| mapping.path.clone())
                .unwrap_or_default();
            (entry, label)
        })
        .collect();
    // Writable spans first: a page a writable segment shares is writable.
    let spans: Vec<(u64, u64, bool, bool)> = image
        .rw_spans()
        .iter()
        .map(|span| (span.start, span.start + span.len, true, span.exec))
        .chain(
            image
                .ro_spans()
                .iter()
                .map(|span| (span.start, span.start + span.len, false, span.exec)),
        )
        .collect();
    let mut rows = Vec::new();
    let mut lazy_regions = Vec::new();
    for region in image.regions() {
        if crate::memory::is_carrick_kernel_only_range(region.start, region.end) {
            continue;
        }
        let map = ProcMapsEntry {
            start: region.start,
            end: region.end,
            read: region.perms.read,
            write: region.perms.write,
            execute: region.perms.execute,
            sharing: ProcMapSharing::Private,
            path: String::new(),
        };
        if boot_region_is_hidden_heap_backing(&map, layout) {
            // The root's brk policy owns the heap: no carrier leaf, no node
            // until the program break grows over it.
            lazy_regions.push((region.start, region.end));
            continue;
        }
        if boot_region_is_hidden_reservation(&map, layout) {
            continue;
        }
        let range = ReservationRange::new(region.start, region.end).ok_or(LINUX_ENOMEM)?;
        if !files
            .iter()
            .any(|mapping| mapping.start < region.end && mapping.end > region.start)
        {
            // Carrier-built (stack, vDSO): an obstacle the ring never edits.
            let stack = region.end == crate::memory::LINUX_STACK_TOP;
            rows.push(SuccessorRow {
                range,
                protection: protection(region.perms.read, region.perms.write, region.perms.execute)
                    .ok_or(LINUX_ENOMEM)?,
                flags: if stack {
                    ReservationNodeFlags::PRIVATE.union(ReservationNodeFlags::GROWSDOWN)
                } else {
                    ReservationNodeFlags::PRIVATE
                },
                source: None,
            });
            continue;
        }
        lazy_regions.push((region.start, region.end));
        // Page by page: a writable span wins over a read-only one; a page in
        // no span is a hole between segments and gets no node.
        let mut page = region.start;
        while page < region.end {
            let next = page + PAGE;
            let Some(&(_, _, write, execute)) = spans
                .iter()
                .find(|(start, end, _, _)| *start <= page && next <= *end)
            else {
                page = next;
                continue;
            };
            let source = sources
                .iter()
                .position(|(entry, _)| entry.start <= page && next <= entry.end);
            let row = SuccessorRow {
                range: ReservationRange::new(page, next).ok_or(LINUX_ENOMEM)?,
                protection: protection(true, write, execute).ok_or(LINUX_ENOMEM)?,
                flags: if source.is_some() {
                    ReservationNodeFlags::PRIVATE.union(ReservationNodeFlags::FILE)
                } else {
                    ReservationNodeFlags::ANONYMOUS_PRIVATE
                },
                source: source.map(|index| {
                    let entry = &sources[index].0;
                    (index, entry.offset + (page - entry.start))
                }),
            };
            // Extend the previous row when this page continues it exactly.
            match rows.last_mut() {
                Some(last)
                    if last.range.end() == page
                        && last.protection == row.protection
                        && last.flags == row.flags
                        && match (last.source, row.source) {
                            (Some((li, lo)), Some((ri, ro))) => {
                                li == ri && lo + last.range.len() == ro
                            }
                            (None, None) => true,
                            _ => false,
                        } =>
                {
                    last.range =
                        ReservationRange::new(last.range.start(), next).ok_or(LINUX_ENOMEM)?;
                }
                _ => rows.push(row),
            }
            page = next;
        }
    }
    rows.sort_by_key(|row| row.range.start());
    if rows
        .windows(2)
        .any(|pair| pair[0].range.end() > pair[1].range.start())
    {
        return Err(LINUX_ENOMEM);
    }
    Ok(SuccessorPlan {
        rows,
        lazy_regions,
        sources,
    })
}

impl SyscallDispatcher {
    /// Import a native exec successor's image rows into its published,
    /// unadmitted reservation root (`successor`), before its ring owner
    /// seals and adopts it. The returned sources must join the successor's
    /// physical custody, and its lazy regions must not be carrier-mapped.
    /// A refused import leaves the root as it was.
    pub fn prepare_native_successor(
        &self,
        image: &crate::memory::AddressSpace,
        successor: ReservationMm,
    ) -> Result<NativeSuccessorImage, LinuxErrno> {
        let authority = self.mm_authority();
        let (layout, custody) = {
            let state = authority.lock();
            (state.layout, Arc::clone(&state.host_backing_custody))
        };
        let plan = successor_plan(image, layout)?;
        let leases = plan
            .sources
            .iter()
            .map(|(entry, label)| {
                custody.retain_exclusive_source(entry.backing.clone(), label.clone())
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(LINUX_ENOMEM)?;
        let provider = authority
            .reservation_provider_for_publication()
            .ok_or(LINUX_ENOMEM)?;
        let view = provider.prepare().map_err(|_| LINUX_ENOMEM)?;
        let mut root = view.lock(successor).map_err(|_| LINUX_ENOMEM)?;
        if root.mm() != successor || root.is_admitted() {
            return Err(LINUX_ENOMEM);
        }
        let imported = plan.rows.iter().try_for_each(|row| match row.source {
            Some((index, offset)) => root.import_with_backing(
                row.range,
                row.protection,
                row.flags,
                leases[index].identity(offset),
            ),
            None => root.import_with(row.range, row.protection, row.flags),
        });
        if imported.is_err() {
            let _ = root.abort_import();
            return Err(LINUX_ENOMEM);
        }
        Ok(NativeSuccessorImage {
            lazy_regions: plan.lazy_regions,
            sources: leases
                .into_iter()
                .map(|lease| {
                    Arc::new(lease) as Arc<dyn carrick_hal::fork_stock::HostBackingRetention>
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ET_EXEC AArch64 image with an R-X text page at 0x400000 and an RW
    /// data segment at 0x402000: one file page of data, then two bss pages.
    fn two_segment_exec() -> Vec<u8> {
        const PT_LOAD: u32 = 1;
        let mut elf = vec![0_u8; 0x3000];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&2_u16.to_le_bytes());
        let segment = |elf: &mut Vec<u8>,
                       ph: usize,
                       flags: u32,
                       offset: u64,
                       va: u64,
                       file: u64,
                       mem: u64| {
            elf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            elf[ph + 4..ph + 8].copy_from_slice(&flags.to_le_bytes());
            elf[ph + 8..ph + 16].copy_from_slice(&offset.to_le_bytes());
            elf[ph + 16..ph + 24].copy_from_slice(&va.to_le_bytes());
            elf[ph + 24..ph + 32].copy_from_slice(&va.to_le_bytes());
            elf[ph + 32..ph + 40].copy_from_slice(&file.to_le_bytes());
            elf[ph + 40..ph + 48].copy_from_slice(&mem.to_le_bytes());
            elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
        };
        // Text: file 0..0x2000 (headers + code) at 0x400000, R-X.
        segment(&mut elf, 64, 5, 0, 0x400000, 0x2000, 0x2000);
        // Data: file 0x2000..0x2800 at 0x402000, then bss to 0x405000, RW.
        segment(&mut elf, 120, 6, 0x2000, 0x402000, 0x800, 0x3000);
        elf[0x1000..0x1004].copy_from_slice(&0xd503_201f_u32.to_le_bytes());
        elf[0x2000..0x2004].copy_from_slice(b"DATA");
        elf
    }

    /// A native successor's ELF pages are lazy root nodes (file pages with
    /// their loaded-image source, bss anonymous), its image regions are not
    /// carrier-mapped, and every other carrier-built user region is covered
    /// by a row.
    #[test]
    fn successor_image_rows_cover_every_user_leaf_and_make_elf_pages_lazy() {
        let image = crate::memory::AddressSpace::load_elf_bytes(&two_segment_exec())
            .unwrap()
            .with_main_file_path("/bin/two")
            .with_linux_initial_stack(vec![b"two".to_vec()], Vec::<Vec<u8>>::new())
            .unwrap();
        let plan = successor_plan(&image, MemoryLayout::hvf_default()).unwrap();
        let file = ReservationNodeFlags::PRIVATE.union(ReservationNodeFlags::FILE);
        let row_at = |address: u64| {
            plan.rows
                .iter()
                .find(|row| row.range.start() <= address && address < row.range.end())
                .unwrap_or_else(|| panic!("no row covers {address:#x}: {:#x?}", plan.rows))
        };
        let text = row_at(0x401000);
        assert_eq!(
            (text.flags, text.protection.bits()),
            (file, 0b101),
            "text is R-X file"
        );
        let data = row_at(0x402000);
        assert_eq!(
            (data.flags, data.protection.bits()),
            (file, 0b011),
            "data is RW file"
        );
        let (index, offset) = data.source.expect("a file row names its source");
        let entry = &plan.sources[index].0;
        assert_eq!(plan.sources[index].1, "/bin/two");
        assert_eq!(entry.offset + (0x402000 - entry.start), offset);
        let bss = row_at(0x404000);
        assert_eq!(
            (bss.flags, bss.protection.bits(), bss.source),
            (ReservationNodeFlags::ANONYMOUS_PRIVATE, 0b011, None),
            "bss is lazy private anonymous"
        );
        assert!(
            plan.lazy_regions
                .iter()
                .any(|(start, end)| *start <= 0x400000 && 0x405000 <= *end),
            "the image region is not carrier-mapped: {:#x?}",
            plan.lazy_regions
        );
        // Every other user region the carrier still builds has a row.
        for region in image.regions() {
            if crate::memory::is_carrick_kernel_only_range(region.start, region.end)
                || plan.lazy_regions.contains(&(region.start, region.end))
            {
                continue;
            }
            let map = ProcMapsEntry {
                start: region.start,
                end: region.end,
                read: region.perms.read,
                write: region.perms.write,
                execute: region.perms.execute,
                sharing: ProcMapSharing::Private,
                path: String::new(),
            };
            if boot_region_is_hidden_reservation(&map, MemoryLayout::hvf_default()) {
                continue;
            }
            let row = row_at(region.start);
            assert_eq!(
                (row.range.start(), row.range.end()),
                (region.start, region.end)
            );
            assert!(
                !row.flags.contains(ReservationNodeFlags::ANONYMOUS),
                "opaque"
            );
        }
    }
}

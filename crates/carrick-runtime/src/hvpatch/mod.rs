//! HVF execution with static text patched to enter in-guest syscall islands.

use std::path::{Path, PathBuf};

use crate::dispatch::SyscallDispatcher;
use crate::memory::{AddressSpace, AddressSpaceError};
use crate::runtime::{RunResult, RuntimeError};
use carrick_mem::elf::SegmentPerms;
use info_page::{INFO_PAGE_BASE, InfoPage, info_page_bytes};
use island::passthrough_island_bytes;
use patcher::{ISLAND_STUB_SIZE, PatchError, PatchSite, patch_svc_zero};

mod info_page;
mod island;
mod patcher;

const PAGE_SIZE: u64 = 4096;
const STAGE2_PAGE_SIZE: u64 = crate::trap::HVF_PAGE_SIZE;
const SVC_ZERO: u32 = 0xd400_0001;

#[derive(Debug)]
struct PreparedImage {
    image: AddressSpace,
    manifest: Vec<PatchSite>,
    island_bases: Vec<u64>,
}

#[derive(Debug, thiserror::Error)]
enum PrepareError {
    #[error(transparent)]
    AddressSpace(#[from] AddressSpaceError),
    #[error(transparent)]
    Patch(#[from] PatchError),
    #[error("no free island page within B range of executable region 0x{start:x}..0x{end:x}")]
    NoIsland { start: u64, end: u64 },
    #[error("loaded executable region index {0} disappeared during hvpatch preparation")]
    MissingRegion(usize),
}

fn align_up_stage2(value: u64) -> Option<u64> {
    value
        .checked_add(STAGE2_PAGE_SIZE - 1)
        .map(|v| v & !(STAGE2_PAGE_SIZE - 1))
}

fn span_is_free(base: u64, size: u64, ranges: &[(u64, u64)]) -> bool {
    let Some(end) = base.checked_add(size) else {
        return false;
    };
    ranges
        .iter()
        .all(|&(occupied_start, occupied_end)| end <= occupied_start || base >= occupied_end)
}

fn find_island_base(
    region_start: u64,
    region_end: u64,
    svc_sites: &[u64],
    occupied: &[(u64, u64)],
) -> Result<u64, PrepareError> {
    let island_span = u64::try_from(svc_sites.len())
        .ok()
        .and_then(|count| count.checked_mul(ISLAND_STUB_SIZE))
        .and_then(align_up_stage2)
        .ok_or(PrepareError::NoIsland {
            start: region_start,
            end: region_end,
        })?;
    let branches_fit = |base: u64| {
        svc_sites.iter().enumerate().all(|(index, &site)| {
            let Some(stub) = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_mul(ISLAND_STUB_SIZE))
                .and_then(|offset| base.checked_add(offset))
            else {
                return false;
            };
            let Some(stub_return) = stub.checked_add(4) else {
                return false;
            };
            let Some(site_return) = site.checked_add(4) else {
                return false;
            };
            patcher::encode_b(site, stub).is_ok()
                && patcher::encode_b(stub_return, site_return).is_ok()
        })
    };
    let mut candidate = align_up_stage2(region_end).ok_or(PrepareError::NoIsland {
        start: region_start,
        end: region_end,
    })?;
    loop {
        if branches_fit(candidate) && span_is_free(candidate, island_span, occupied) {
            return Ok(candidate);
        }
        let Some(next) = candidate.checked_add(STAGE2_PAGE_SIZE) else {
            break;
        };
        candidate = next;
        if !branches_fit(candidate) {
            break;
        }
    }

    let Some(mut candidate) = region_start
        .checked_sub(STAGE2_PAGE_SIZE)
        .map(|v| v & !(STAGE2_PAGE_SIZE - 1))
    else {
        return Err(PrepareError::NoIsland {
            start: region_start,
            end: region_end,
        });
    };
    loop {
        if branches_fit(candidate) && span_is_free(candidate, island_span, occupied) {
            return Ok(candidate);
        }
        let Some(previous) = candidate.checked_sub(STAGE2_PAGE_SIZE) else {
            break;
        };
        candidate = previous;
        if !branches_fit(candidate) {
            break;
        }
    }
    Err(PrepareError::NoIsland {
        start: region_start,
        end: region_end,
    })
}

fn prepare_image(mut image: AddressSpace, info: InfoPage) -> Result<PreparedImage, PrepareError> {
    let mut occupied: Vec<(u64, u64)> = Vec::with_capacity(image.regions().len() + 1);
    for region in image.regions() {
        let end = align_up_stage2(region.end).ok_or(PrepareError::NoIsland {
            start: region.start,
            end: region.end,
        })?;
        occupied.push((region.start & !(STAGE2_PAGE_SIZE - 1), end));
    }
    occupied.push((INFO_PAGE_BASE, INFO_PAGE_BASE + STAGE2_PAGE_SIZE));

    let executable_regions: Vec<(usize, u64, u64, Vec<u64>)> = image
        .regions()
        .iter()
        .enumerate()
        .filter(|(_, region)| region.perms.execute)
        .filter_map(|(index, region)| {
            let sites: Vec<u64> = region
                .bytes()
                .chunks_exact(4)
                .enumerate()
                .filter_map(|(word_index, bytes)| {
                    let word = u32::from_le_bytes(bytes.try_into().ok()?);
                    (word == SVC_ZERO).then(|| region.start + (word_index as u64 * 4))
                })
                .collect();
            (!sites.is_empty()).then_some((index, region.start, region.end, sites))
        })
        .collect();

    let mut manifest = Vec::new();
    let mut islands = Vec::new();
    for (region_index, start, end, sites) in executable_regions {
        let island_base = find_island_base(start, end, &sites, &occupied)?;
        let region_bytes = image
            .region_bytes_mut(region_index)
            .ok_or(PrepareError::MissingRegion(region_index))?;
        let region_manifest = patch_svc_zero(region_bytes, start, island_base)?;
        let island_bytes = passthrough_island_bytes(&region_manifest)?;
        let island_len =
            u64::try_from(island_bytes.len()).map_err(|_| PatchError::AddressOverflow)?;
        let mapped_size =
            align_up_stage2(island_len).ok_or(PrepareError::NoIsland { start, end })?;
        occupied.push((island_base, island_base + mapped_size));
        manifest.extend(region_manifest);
        islands.push((island_base, island_bytes));
    }

    let rx = SegmentPerms {
        read: true,
        write: false,
        execute: true,
    };
    let island_bases: Vec<u64> = islands.iter().map(|(base, _)| *base).collect();
    for (island_base, island_bytes) in islands {
        image = image.with_region_bytes(island_base, rx, false, island_bytes)?;
    }
    let info_perms = SegmentPerms {
        read: true,
        write: true,
        execute: false,
    };
    image = image.with_region_bytes(INFO_PAGE_BASE, info_perms, false, info_page_bytes(info))?;

    Ok(PreparedImage {
        image,
        manifest,
        island_bases,
    })
}

pub(crate) fn finish_hvpatch_image(
    image: AddressSpace,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
) -> Result<RunResult, RuntimeError> {
    let prepared = prepare_image(image, InfoPage::default()).map_err(|error| {
        RuntimeError::Unsupported(format!("hvpatch image preparation failed: {error}"))
    })?;
    let _patch_summary = (prepared.manifest.len(), prepared.island_bases.len());
    crate::runtime::finish_and_run_image(prepared.image, dispatcher, max_traps, debug_state_path)
}

pub(crate) fn run_static_hvpatch<A, E>(
    path: &Path,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let argv: Vec<String> = argv.into_iter().collect();
    let env: Vec<String> = env.into_iter().collect();
    let identity = argv.first().cloned().unwrap_or_else(|| {
        path.canonicalize()
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .into_owned()
    });
    dispatcher.set_executable_identity(
        identity,
        argv.clone(),
        env.iter().map(|value| value.as_bytes().to_vec()).collect(),
    );
    let file = std::fs::read(path).map_err(AddressSpaceError::Io)?;
    let image = AddressSpace::load_elf_bytes_with_reader(&file, &|interpreter| {
        dispatcher
            .read_exec_file(interpreter)
            .or_else(|| std::fs::read(interpreter).ok())
    })?
    .with_vdso_auxv(crate::runtime::vdso_enabled_for_debug())
    .with_linux_initial_stack_page_size(argv, env, PAGE_SIZE)?;
    finish_hvpatch_image(image, dispatcher, max_traps, debug_state_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::AddressSpace;
    use carrick_mem::elf::SegmentPerms;
    use info_page::{INFO_PAGE_BASE, InfoPage};

    const RX: SegmentPerms = SegmentPerms {
        read: true,
        write: false,
        execute: true,
    };

    fn text(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn prepares_loaded_text_with_near_island_and_fixed_info_page() {
        let image = AddressSpace::from_segments(
            0x400000,
            [(0x400000, RX, text(&[0xd503_201f, 0xd400_0001]), 0x1000)],
        )
        .unwrap();

        let prepared = prepare_image(image, InfoPage::default()).expect("prepare hvpatch image");

        assert_eq!(prepared.manifest.len(), 1);
        assert_eq!(prepared.manifest[0].guest_va, 0x400004);
        assert_eq!(prepared.island_bases, vec![0x404000]);
        assert!(
            prepared
                .image
                .regions()
                .iter()
                .any(|r| r.start == INFO_PAGE_BASE)
        );
        let code = prepared
            .image
            .regions()
            .iter()
            .find(|r| r.start == 0x400000)
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(code.bytes()[4..8].try_into().unwrap()),
            patcher::encode_b(0x400004, 0x404000).unwrap()
        );
    }

    #[test]
    fn assigns_a_near_island_to_each_distant_executable_region() {
        let image = AddressSpace::from_segments(
            0x400000,
            [
                (0x400000, RX, text(&[0xd400_0001]), 0x1000),
                (0x80_0000_0000, RX, text(&[0xd400_0001]), 0x1000),
            ],
        )
        .unwrap();

        let prepared = prepare_image(image, InfoPage::default()).expect("prepare two images");

        assert_eq!(prepared.manifest.len(), 2);
        assert_eq!(prepared.island_bases, vec![0x404000, 0x80_0000_4000]);
    }

    #[test]
    fn leaves_tpidr_el0_reads_unmodified() {
        let mrs_x0_tpidr_el0 = 0xd53b_d040;
        let image = AddressSpace::from_segments(
            0x400000,
            [(0x400000, RX, text(&[mrs_x0_tpidr_el0]), 0x1000)],
        )
        .unwrap();

        let prepared = prepare_image(image, InfoPage::default()).expect("prepare hvpatch image");
        let code = prepared.image.regions().first().unwrap();
        assert_eq!(
            u32::from_le_bytes(code.bytes()[0..4].try_into().unwrap()),
            mrs_x0_tpidr_el0
        );
        assert!(prepared.manifest.is_empty());
        assert!(prepared.island_bases.is_empty());
    }
}

//! Single-owner physical RAM for the AArch64 soft dispatcher.
use carrick_guest_arch::FrameGpa;
use carrick_softcpu_aarch64::handler::{CodeGeneration, GuestMemory, InlineRam, MemoryFault};
use carrick_softcpu_aarch64::state::VirtualAddress;
use carrick_softmmu::{
    ExtentRecord, ExtentTable, GenerationExhausted, OwnerGeneration, PAGE_SIZE_4K,
};
use std::collections::BTreeMap;

const PAGE_BYTES: usize = PAGE_SIZE_4K as usize;
const OWNER: OwnerGeneration = OwnerGeneration::FIRST;

/// Sparse RAM with exclusive ownership of both the backing and its extent
/// inventory. Loader and guest writes use the same mutation path. A mutable
/// borrow for dispatch excludes all external writes and extent edits.
pub struct SoftMemory {
    pages: BTreeMap<FrameGpa, Box<[u8; PAGE_BYTES]>>,
    extents: ExtentTable,
}

impl SoftMemory {
    pub fn new() -> Result<Self, GenerationExhausted> {
        Ok(Self {
            pages: BTreeMap::new(),
            extents: ExtentTable::new()?,
        })
    }

    /// Back an aligned physical page with zeroes. An existing mapping and
    /// its contents are preserved.
    pub fn map_zero(&mut self, frame: FrameGpa) -> Result<(), MemoryFault> {
        if self.pages.contains_key(&frame) {
            return Ok(());
        }
        if !self
            .extents
            .install(ExtentRecord::new(frame, PAGE_SIZE_4K, OWNER))
        {
            return Err(MemoryFault {
                address: VirtualAddress(frame.raw()),
            });
        }
        self.pages.insert(frame, Box::new([0; PAGE_BYTES]));
        Ok(())
    }

    /// Retire one page before releasing its backing. The host launcher owns
    /// this inventory exclusively and does not register any soft vCPU seats.
    /// Reinstalling the physical page gets a fresh code incarnation.
    pub fn unmap_frame(&mut self, frame: FrameGpa) -> Result<(), MemoryFault> {
        let fault = MemoryFault {
            address: VirtualAddress(frame.raw()),
        };
        if let Some(retirement) = self.extents.remove(frame, None).map_err(|_| fault)? {
            // There are no seated CPUs, so the domain can complete now.
            let completion = retirement.pending.try_complete().map_err(|_| fault)?;
            self.extents.reclaim(&completion);
            self.pages.remove(&frame);
        }
        Ok(())
    }
}

fn frame_at(address: u64) -> FrameGpa {
    FrameGpa::new(address & !(PAGE_SIZE_4K - 1))
}

impl GuestMemory for SoftMemory {
    fn code_cache_domain(&self) -> Option<carrick_softmmu::ExtentTableId> {
        Some(self.extents.identity())
    }

    fn stage1_is_local(&self) -> bool {
        true
    }

    fn read(&mut self, address: VirtualAddress, mut bytes: &mut [u8]) -> Result<(), MemoryFault> {
        if self.extents.is_terminal() {
            return Err(MemoryFault { address });
        }
        let end = address
            .0
            .checked_add(bytes.len() as u64)
            .ok_or(MemoryFault { address })?;
        let mut at = address.0;
        while at < end {
            let frame = frame_at(at);
            let page = self.pages.get(&frame).ok_or(MemoryFault {
                address: VirtualAddress(at),
            })?;
            let offset = (at - frame.raw()) as usize;
            let len = bytes.len().min(PAGE_BYTES - offset);
            bytes[..len].copy_from_slice(&page[offset..offset + len]);
            bytes = &mut bytes[len..];
            at += len as u64;
        }
        Ok(())
    }

    fn write(&mut self, address: VirtualAddress, mut bytes: &[u8]) -> Result<(), MemoryFault> {
        if bytes.is_empty() {
            return Ok(());
        }
        let end = address
            .0
            .checked_add(bytes.len() as u64)
            .ok_or(MemoryFault { address })?;
        let first = frame_at(address.0).raw();
        let last = frame_at(end - 1).raw();
        let frames = (first..=last).step_by(PAGE_BYTES).map(FrameGpa::new);
        for frame in frames.clone() {
            if !self.pages.contains_key(&frame) {
                return Err(MemoryFault {
                    address: VirtualAddress(address.0.max(frame.raw())),
                });
            }
        }
        for frame in frames {
            // The physical owner is exclusively borrowed, so revocation is
            // published before bytes become visible to any dispatcher.
            self.extents
                .invalidate_host_written_page(frame, OWNER)
                .map_err(|_| MemoryFault {
                    address: VirtualAddress(address.0.max(frame.raw())),
                })?;
        }
        let mut at = address.0;
        while at < end {
            let frame = frame_at(at);
            let page = self.pages.get_mut(&frame).ok_or(MemoryFault {
                address: VirtualAddress(at),
            })?;
            let offset = (at - frame.raw()) as usize;
            let len = bytes.len().min(PAGE_BYTES - offset);
            page[offset..offset + len].copy_from_slice(&bytes[..len]);
            bytes = &bytes[len..];
            at += len as u64;
        }
        Ok(())
    }

    fn inline_ram(&mut self, read: Option<FrameGpa>, write: Option<FrameGpa>) -> InlineRam<'_> {
        if self.extents.is_terminal() {
            return InlineRam::None;
        }
        let read = read.filter(|frame| self.pages.contains_key(frame));
        let write = write.filter(|frame| {
            self.pages.contains_key(frame)
                && self
                    .extents
                    .authenticate_frame(*frame, OWNER)
                    .is_some_and(|page| !self.extents.is_code_page(page))
        });
        match (read, write) {
            (Some(r), Some(w)) if r == w => self
                .pages
                .get_mut(&w)
                .map_or(InlineRam::None, |page| InlineRam::Shared(page)),
            (Some(r), Some(w)) => {
                let mut range = self.pages.range_mut(r.min(w)..=r.max(w));
                let (Some((_, lo)), Some((_, hi))) = (range.next(), range.next_back()) else {
                    return InlineRam::None;
                };
                let (read, write) = if r < w { (lo, hi) } else { (hi, lo) };
                InlineRam::Separate {
                    read: Some(read),
                    write: Some(write),
                }
            }
            (read, write) => {
                if let Some(w) = write {
                    InlineRam::Separate {
                        read: None,
                        write: self.pages.get_mut(&w).map(Box::as_mut),
                    }
                } else {
                    InlineRam::Separate {
                        read: read.and_then(|r| self.pages.get(&r)).map(Box::as_ref),
                        write: None,
                    }
                }
            }
        }
    }

    fn invalidate_code_frame(&mut self, frame: FrameGpa) -> Result<bool, MemoryFault> {
        if self.pages.contains_key(&frame) {
            self.extents
                .invalidate_host_written_page(frame, OWNER)
                .map_err(|_| MemoryFault {
                    address: VirtualAddress(frame.raw()),
                })?;
        }
        Ok(true)
    }

    fn mark_code_page(&mut self, frame: FrameGpa) -> Option<CodeGeneration> {
        let page = self.extents.authenticate_frame(frame, OWNER)?;
        let generation = self.extents.mark_code_page(page, &mut []);
        (generation != 0).then_some(CodeGeneration(generation))
    }

    fn code_generation(&self, frame: FrameGpa) -> Option<CodeGeneration> {
        let page = self.extents.authenticate_frame(frame, OWNER)?;
        self.extents
            .is_code_page(page)
            .then(|| CodeGeneration(self.extents.code_generation(page)))
    }
}

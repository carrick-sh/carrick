//! `carrick-softcpu-aarch64-host` — the arm64 host launch for the aarch64
//! copy-through engine (#1236, docs/design/soft-aarch64-translator.md, "Host
//! adapter"). [`HostBlockRunner`] publishes a translated block through
//! `carrick_host_jit::JitCodeBuffer` and calls it with host SP on an engine
//! frame at the top of a dedicated region, implementing the dispatcher's
//! `ExecuteBlock`. Native execution exists only on Linux arm64; every other
//! host gets [`HostError::UnsupportedHost`] from [`HostBlockRunner::new`].
//! macOS arm64 (MAP_JIT and `pthread_jit_write_protect_np`) is a later slice.
#![deny(unsafe_op_in_unsafe_fn)]

mod memory;

pub use memory::SoftMemory;

use carrick_softcpu_aarch64::dispatch::ExecuteBlock;
use carrick_softcpu_aarch64::state::CpuState;
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
use carrick_softcpu_aarch64::translate::BlockFrame;
use carrick_softcpu_aarch64::translate::TranslatedBlock;
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
use carrick_softcpu_aarch64::{
    dispatch::{BlockMemory, ChainBudget, ChainExit, ResidentBlock},
    handler::InlineRam,
    state::ProgramCounter,
    translate::frame,
};
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
use std::sync::Arc;

/// Why a block could not be launched on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// This host cannot run A64 blocks natively (not Linux arm64).
    UnsupportedHost,
    /// The executable code buffer could not be mapped.
    Allocate,
    /// The block's words could not be published executable.
    Publish,
}

/// Bytes of the region host SP points into while a block runs; a host signal
/// delivered mid-block writes its frame below the engine frame, inside it.
pub const FRAME_REGION_BYTES: usize = 64 * 1024;

/// An immutable executable block. Its mapping lives as long as the resident
/// dispatcher entry, so no later publication can change these instructions.
pub struct HostCode {
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    _mapping: carrick_host_jit::JitCodeBuffer,
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    entry: usize,
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    linked: Option<(ProgramCounter, usize)>,
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    simd: bool,
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    _unsupported: core::convert::Infallible,
}

// SAFETY: HostCode is constructed only after publishing its private mapping.
// It exposes no mutable access. Readers may run its immutable instructions
// concurrently, with separate frames, and the mapping lives through each call.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe impl Sync for HostCode {}

/// Only the runner writes these records. Emitted code reads a tag and branches
/// to the linked entry, while the parallel owner slot pins its RX mapping.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NativeLink {
    pc: u64,
    entry: usize,
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
const _: () = {
    assert!(size_of::<NativeLink>() == 1 << frame::LINK_SHIFT);
    assert!(core::mem::offset_of!(NativeLink, pc) == frame::LINK_PC as usize);
    assert!(core::mem::offset_of!(NativeLink, entry) == frame::LINK_ENTRY as usize);
};

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
struct LinkBank {
    native: [NativeLink; frame::CHAIN_SLOTS],
    owners: [Option<Arc<ResidentBlock<HostCode>>>; frame::CHAIN_SLOTS],
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
impl LinkBank {
    fn new() -> Self {
        Self {
            native: [NativeLink::default(); frame::CHAIN_SLOTS],
            owners: core::array::from_fn(|_| None),
        }
    }

    fn link(&mut self, pc: u64, entry: usize, resident: &Arc<ResidentBlock<HostCode>>) {
        let index = ((pc / 4) as usize) & (frame::CHAIN_SLOTS - 1);
        if self.owners[index]
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, resident))
        {
            return;
        }
        self.native[index] = NativeLink { pc, entry };
        self.owners[index] = Some(Arc::clone(resident));
    }

    fn unlink(&mut self, frame: Option<carrick_guest_arch::FrameGpa>) {
        if frame.is_none() {
            self.native.fill(NativeLink::default());
            self.owners.fill(None);
        } else {
            for (link, owner) in self.native.iter_mut().zip(&mut self.owners) {
                if owner
                    .as_ref()
                    .is_some_and(|owner| Some(owner.frame()) == frame)
                {
                    *link = NativeLink::default();
                    *owner = None;
                }
            }
        }
    }
}

/// Runs translated blocks natively on a Linux arm64 host.
pub struct HostBlockRunner {
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    publication: carrick_host_jit::PublicationWork,
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    retain_blocks: bool,
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    retain_stage1: bool,
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    inline_memory: bool,
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    chain_blocks: bool,
    /// SIMD and scalar blocks have different host stack layouts. A launch
    /// can only inherit an entry from the bank matching its cold prologue.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    links: Box<[LinkBank; 2]>,
    /// The engine frame region: the frame is its last element, so everything
    /// below it is headroom for host signal frames.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    region: Box<[BlockFrame]>,
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    _unsupported: (),
}

impl HostBlockRunner {
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    pub fn publication_work(&self) -> carrick_host_jit::PublicationWork {
        self.publication
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    pub fn new() -> Result<Self, HostError> {
        let frames = FRAME_REGION_BYTES / core::mem::size_of::<BlockFrame>();
        Ok(Self {
            publication: carrick_host_jit::PublicationWork::default(),
            retain_blocks: std::env::var_os("CARRICK_SOFT_AARCH64_CACHE").as_deref()
                != Some(std::ffi::OsStr::new("0")),
            retain_stage1: std::env::var_os("CARRICK_SOFT_AARCH64_TLB").as_deref()
                != Some(std::ffi::OsStr::new("0")),
            inline_memory: cfg!(target_endian = "little")
                && std::env::var_os("CARRICK_SOFT_AARCH64_INLINE_MEMORY").as_deref()
                    != Some(std::ffi::OsStr::new("0")),
            chain_blocks: std::env::var_os("CARRICK_SOFT_AARCH64_CHAIN").as_deref()
                != Some(std::ffi::OsStr::new("0")),
            links: Box::new(core::array::from_fn(|_| LinkBank::new())),
            region: vec![BlockFrame::default(); frames].into_boxed_slice(),
        })
    }

    /// Override the environment setting for an explicit on/off differential.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    pub fn with_chaining(mut self, enabled: bool) -> Self {
        self.chain_blocks = enabled;
        self
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    pub fn new() -> Result<Self, HostError> {
        Err(HostError::UnsupportedHost)
    }
}

impl ExecuteBlock for HostBlockRunner {
    type Error = HostError;
    type Code = HostCode;

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn retain_blocks(&self) -> bool {
        self.retain_blocks
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn retain_stage1(&self) -> bool {
        self.retain_stage1
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn inline_memory(&self) -> bool {
        self.inline_memory
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn chain_blocks(&self) -> bool {
        self.chain_blocks
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn link_block(&mut self, resident: &Arc<ResidentBlock<HostCode>>) {
        let (_, code) = resident.prepared();
        if let Some((pc, entry)) = code.linked {
            self.links[usize::from(code.simd)].link(pc.0, entry, resident);
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn unlink(&mut self, frame: Option<carrick_guest_arch::FrameGpa>) {
        for bank in self.links.as_mut() {
            bank.unlink(frame);
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn prepare(&mut self, block: &TranslatedBlock) -> Result<HostCode, HostError> {
        let words = block.words();
        #[cfg(target_endian = "little")]
        // SAFETY: the initialized u32 slice contains contiguous little-endian
        // instructions. The byte slice borrows exactly the same storage.
        let bytes =
            unsafe { core::slice::from_raw_parts(words.as_ptr().cast(), size_of_val(words)) };
        #[cfg(target_endian = "big")]
        let little_endian: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        #[cfg(target_endian = "big")]
        let bytes = little_endian.as_slice();
        let mut mapping =
            carrick_host_jit::JitCodeBuffer::new(bytes.len()).ok_or(HostError::Allocate)?;
        let entry = mapping.publish(bytes);
        let work = mapping.publication_work();
        self.publication.publications += work.publications;
        self.publication.mprotect_calls += work.mprotect_calls;
        self.publication.icache_syncs += work.icache_syncs;
        let entry = entry.ok_or(HostError::Publish)? as usize;
        Ok(HostCode {
            _mapping: mapping,
            entry,
            linked: block
                .linked_entry()
                .map(|offset| (block.guest().start(), entry + offset)),
            simd: block.uses_simd(),
        })
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    fn prepare(&mut self, _block: &TranslatedBlock) -> Result<HostCode, HostError> {
        Err(HostError::UnsupportedHost)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn execute(
        &mut self,
        block: &TranslatedBlock,
        code: &HostCode,
        cpu: &mut CpuState,
    ) -> Result<usize, HostError> {
        self.execute_with_memory(block, code, cpu, BlockMemory::default())
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn execute_with_memory(
        &mut self,
        _block: &TranslatedBlock,
        code: &HostCode,
        cpu: &mut CpuState,
        memory: BlockMemory<'_>,
    ) -> Result<usize, HostError> {
        Ok(self.launch(code, cpu, memory, None).exit)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn execute_chain(
        &mut self,
        _block: &TranslatedBlock,
        code: &HostCode,
        cpu: &mut CpuState,
        memory: BlockMemory<'_>,
        budget: ChainBudget<'_>,
    ) -> Result<ChainExit<HostCode>, HostError> {
        Ok(self.launch(code, cpu, memory, Some(budget)))
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    fn execute(
        &mut self,
        _block: &TranslatedBlock,
        _code: &HostCode,
        _cpu: &mut CpuState,
    ) -> Result<usize, HostError> {
        Err(HostError::UnsupportedHost)
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
impl HostBlockRunner {
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn launch(
        &mut self,
        code: &HostCode,
        cpu: &mut CpuState,
        mut memory: BlockMemory<'_>,
        budget: Option<ChainBudget<'_>>,
    ) -> ChainExit<HostCode> {
        let top = self.region.len() - 1;
        self.region[top].load_from(cpu);
        let (read_ptr, write_ptr) = match &mut memory.ram {
            InlineRam::None => (0, 0),
            InlineRam::Separate { read, write } => (
                read.map_or(0, |page| page.as_ptr() as u64),
                write
                    .as_deref_mut()
                    .map_or(0, |page| page.as_mut_ptr() as u64),
            ),
            InlineRam::Shared(page) => {
                let ptr = page.as_mut_ptr() as u64;
                (ptr, ptr)
            }
        };
        let slots = &mut self.region[top].slots;
        let bank = &self.links[usize::from(code.simd)];
        let mut remaining = 0;
        if let Some(budget) = &budget {
            slots[frame::CHAIN_LAST as usize / 8] = u64::MAX;
            slots[frame::CHAIN_RETIRED as usize / 8] = 0;
            remaining = budget.steps.saturating_sub(1);
            slots[frame::CHAIN_TABLE as usize / 8] = bank.native.as_ptr() as u64;
            slots[frame::CHAIN_REMAINING as usize / 8] = remaining;
            slots[frame::CHAIN_PENDING as usize / 8] = core::ptr::from_ref(budget.pending) as u64;
            slots[frame::CHAIN_POLL_MASK as usize / 8] = u64::from(budget.poll_mask);
        }
        slots[frame::INLINE_READ_VA as usize / 8] = memory.read.map_or(0, |va| va.raw());
        slots[frame::INLINE_WRITE_VA as usize / 8] = memory.write.map_or(0, |va| va.raw());
        slots[frame::INLINE_READ_PTR as usize / 8] = read_ptr;
        slots[frame::INLINE_WRITE_PTR as usize / 8] = write_ptr;
        // Derived from the whole region: host signal frames land below `top`.
        let slot = self.region.as_mut_ptr().wrapping_add(top);
        // SAFETY: `code.entry` is the RX start of an emitted AAPCS64
        // function (translate::entry_stub/common_exit) that takes the frame
        // in x0, restores x19..x30 and host SP before returning the exit
        // index in x0. Inline accesses use only these live RAM loans, after
        // checking the virtual page tag and natural alignment. A missing
        // loan (null pointer) exits before transferring bytes. `slot` is the
        // 16-byte aligned last frame of the live region. Code and all backing
        // allocations outlive the call. A linked entry inherits this same
        // frame, RAM loans and ABI prologue. The immutable bank can only
        // name published entries of the same SIMD mode and pins each mapping
        // for the entire call. The pending byte is loaded with LDARB while
        // the AtomicU8 borrow is live.
        let index = unsafe {
            let block_fn =
                core::mem::transmute::<usize, extern "C" fn(*mut BlockFrame) -> u64>(code.entry);
            block_fn(slot)
        };
        self.region[top].slots[frame::INLINE_READ_PTR as usize / 8] = 0;
        self.region[top].slots[frame::INLINE_WRITE_PTR as usize / 8] = 0;
        self.region[top].store_to(cpu);
        let slots = &mut self.region[top].slots;
        if budget.is_some() {
            let last = bank
                .owners
                .get(slots[frame::CHAIN_LAST as usize / 8] as usize);
            slots[frame::CHAIN_TABLE as usize / 8] = 0;
            slots[frame::CHAIN_PENDING as usize / 8] = 0;
            ChainExit {
                exit: index as usize,
                last: last.and_then(Clone::clone),
                preceding_blocks: remaining - slots[frame::CHAIN_REMAINING as usize / 8],
                preceding_instructions: slots[frame::CHAIN_RETIRED as usize / 8],
                indirect_target: ProgramCounter(slots[frame::CHAIN_TARGET as usize / 8]),
            }
        } else {
            ChainExit::single(index as usize, cpu.pc)
        }
    }
}
#[cfg(all(test, not(all(target_arch = "aarch64", target_os = "linux"))))]
mod tests {
    use super::*;

    #[test]
    fn other_hosts_refuse_with_a_typed_error() {
        assert!(matches!(
            HostBlockRunner::new(),
            Err(HostError::UnsupportedHost)
        ));
    }
}

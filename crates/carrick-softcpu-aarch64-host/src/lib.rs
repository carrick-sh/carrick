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
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    _unsupported: core::convert::Infallible,
}

/// Runs translated blocks natively on a Linux arm64 host.
pub struct HostBlockRunner {
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    publication: carrick_host_jit::PublicationWork,
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    retain_blocks: bool,
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    retain_stage1: bool,
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
            region: vec![BlockFrame::default(); frames].into_boxed_slice(),
        })
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
        Ok(HostCode {
            _mapping: mapping,
            entry: entry.ok_or(HostError::Publish)? as usize,
        })
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    fn prepare(&mut self, _block: &TranslatedBlock) -> Result<HostCode, HostError> {
        Err(HostError::UnsupportedHost)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn execute(
        &mut self,
        _block: &TranslatedBlock,
        code: &HostCode,
        cpu: &mut CpuState,
    ) -> Result<usize, HostError> {
        let top = self.region.len() - 1;
        self.region[top].load_from(cpu);
        // Derived from the whole region: host signal frames land below `top`.
        let slot = self.region.as_mut_ptr().wrapping_add(top);
        // SAFETY: `code.entry` is the RX start of an emitted AAPCS64
        // function (translate::entry_stub/common_exit) that takes the frame
        // in x0, restores x19..x30 and host SP before returning the exit
        // index in x0, and touches no memory but the frame and the region
        // below it (memory words always exit). `slot` is the 16-byte aligned
        // last frame of the live region, and `code` outlives the call.
        let index = unsafe {
            let block_fn =
                core::mem::transmute::<usize, extern "C" fn(*mut BlockFrame) -> u64>(code.entry);
            block_fn(slot)
        };
        self.region[top].store_to(cpu);
        Ok(index as usize)
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

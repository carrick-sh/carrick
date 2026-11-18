//! `carrick-softcpu-aarch64-host` — the arm64 host launch for the aarch64
//! copy-through engine (#1236, docs/design/soft-aarch64-translator.md, "Host
//! adapter"). [`HostBlockRunner`] publishes a translated block through
//! `carrick_host_jit::JitCodeBuffer` and calls it with host SP on an engine
//! frame at the top of a dedicated region, implementing the dispatcher's
//! `ExecuteBlock`. Native execution exists only on Linux arm64; every other
//! host gets [`HostError::UnsupportedHost`] from [`HostBlockRunner::new`].
//! macOS arm64 (MAP_JIT and `pthread_jit_write_protect_np`) is a later slice.
#![deny(unsafe_op_in_unsafe_fn)]

use carrick_softcpu_aarch64::dispatch::ExecuteBlock;
use carrick_softcpu_aarch64::translate::{BlockFrame, TranslatedBlock};

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

/// Executable bytes for one translated block at a time (a 64-word guest
/// block emits well under 4 KiB).
pub const CODE_BYTES: usize = 256 * 1024;

/// Runs translated blocks natively on a Linux arm64 host.
pub struct HostBlockRunner {
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    code: carrick_host_jit::JitCodeBuffer,
    /// The engine frame region: the frame is its last element, so everything
    /// below it is headroom for host signal frames.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    region: Box<[BlockFrame]>,
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    _unsupported: (),
}

impl HostBlockRunner {
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    pub fn new() -> Result<Self, HostError> {
        let frames = FRAME_REGION_BYTES / core::mem::size_of::<BlockFrame>();
        Ok(Self {
            code: carrick_host_jit::JitCodeBuffer::new(CODE_BYTES).ok_or(HostError::Allocate)?,
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

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn execute(
        &mut self,
        block: &TranslatedBlock,
        frame: &mut BlockFrame,
    ) -> Result<usize, HostError> {
        let bytes: Vec<u8> = block.words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let entry = self.code.publish(&bytes).ok_or(HostError::Publish)?;
        let top = self.region.len() - 1;
        self.region[top] = frame.clone();
        // Derived from the whole region: host signal frames land below `top`.
        let slot = self.region.as_mut_ptr().wrapping_add(top);
        // SAFETY: `entry` is the RX start of `block.words`, an AAPCS64
        // function (translate::entry_stub/common_exit) that takes the frame
        // in x0, restores x19..x30 and host SP before returning the exit
        // index in x0, and touches no memory but the frame and the region
        // below it (memory words always exit). `slot` is the 16-byte aligned
        // last frame of the live region, and `self.code` outlives the call.
        let index = unsafe {
            let block_fn = core::mem::transmute::<usize, extern "C" fn(*mut BlockFrame) -> u64>(
                entry as usize,
            );
            block_fn(slot)
        };
        frame.clone_from(&self.region[top]);
        Ok(index as usize)
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    fn execute(
        &mut self,
        _block: &TranslatedBlock,
        _frame: &mut BlockFrame,
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

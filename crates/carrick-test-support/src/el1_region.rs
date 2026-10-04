//! Owned, aligned bytes for VM-free tests of the EL1 region layout.

use carrick_el1_abi::{
    CurrentTask, DelegatedFile, DelegatedInotify, DelegatedOpenFile, EL1_REGION_SIZE, ZoneTables,
};
use core::mem::align_of;

/// Page alignment covers the cache-line-aligned records addressed by ABI
/// offsets. A byte vector's allocation does not promise that alignment.
#[repr(align(4096))]
pub struct TestEl1Region([u8; EL1_REGION_SIZE as usize]);

const _: () = {
    assert!(align_of::<TestEl1Region>() >= align_of::<DelegatedFile>());
    assert!(align_of::<TestEl1Region>() >= align_of::<DelegatedInotify>());
    assert!(align_of::<TestEl1Region>() >= align_of::<DelegatedOpenFile>());
    assert!(align_of::<TestEl1Region>() >= align_of::<CurrentTask>());
    assert!(align_of::<TestEl1Region>() >= align_of::<ZoneTables>());
};

impl TestEl1Region {
    pub fn zeroed() -> Box<Self> {
        // SAFETY: the only field is a byte array; every zero byte is valid.
        // Box allocates with this type's alignment without a region-sized
        // temporary on the test thread's stack.
        unsafe { Box::<Self>::new_zeroed().assume_init() }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
}

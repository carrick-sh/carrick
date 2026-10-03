/// Retained host byte source. This grants no mapping or permission authority:
/// the owner tree supplies the VA, protection, sharing and fork policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct HostBackingIdentity {
    handle: core::num::NonZeroU64,
    generation: core::num::NonZeroU64,
    offset: u64,
}
impl HostBackingIdentity {
    pub const fn new(
        handle: core::num::NonZeroU64,
        generation: core::num::NonZeroU64,
        offset: u64,
    ) -> Self {
        Self {
            handle,
            generation,
            offset,
        }
    }
    pub const fn handle(self) -> core::num::NonZeroU64 {
        self.handle
    }
    pub const fn generation(self) -> core::num::NonZeroU64 {
        self.generation
    }
    pub const fn offset(self) -> u64 {
        self.offset
    }
    pub fn advance(self, bytes: u64) -> Option<Self> {
        Some(Self {
            offset: self.offset.checked_add(bytes)?,
            ..self
        })
    }
}

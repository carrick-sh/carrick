//! ISA-neutral stage-1 translation vocabulary shared by every walker.

/// Bytes in one 4 KiB translation granule page.
const PAGE: u64 = 4096;

/// The direction of one EL0 access, as decoded from the fault syndrome.
/// The discriminants are the wire encoding of the
/// `hvpatch__stale__stage1__retry` probe's access argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LeafAccess {
    Read = 0,
    Write = 1,
    Execute = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafSize {
    Page,
    Block2M,
    Block1G,
}
impl LeafSize {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Page => PAGE,
            Self::Block2M => 1 << 21,
            Self::Block1G => 1 << 30,
        }
    }
}

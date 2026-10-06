//! The single Linux ordinal-to-family routing table.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnonymousCall {
    Brk,
    Munmap,
    Mremap,
    Mmap,
    Mprotect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Anonymous(AnonymousCall),
    Read,
    Write,
    EpollWait,
    Lifecycle,
    Futex,
    InotifyAdd,
    InotifyRemove,
    FileSeek,
    FilePositioned,
    AllocatorControl,
    Unported,
}

/// Route one AArch64 Linux ordinal. Family implementations are temporary
/// EL1 traits until orders 6-9 move their semantic bodies; they never choose
/// another family or own completion.
pub const fn route_aarch64(ordinal: u64, allocator_control: u64) -> Family {
    match ordinal {
        214 => Family::Anonymous(AnonymousCall::Brk),
        215 => Family::Anonymous(AnonymousCall::Munmap),
        216 => Family::Anonymous(AnonymousCall::Mremap),
        222 => Family::Anonymous(AnonymousCall::Mmap),
        226 => Family::Anonymous(AnonymousCall::Mprotect),
        63 => Family::Read,
        64 => Family::Write,
        22 => Family::EpollWait,
        62 => Family::FileSeek,
        67 | 68 => Family::FilePositioned,
        27 => Family::InotifyAdd,
        28 => Family::InotifyRemove,
        98 => Family::Futex,
        93 | 132 | 135 | 99 | 220 => Family::Lifecycle,
        nr if nr == allocator_control => Family::AllocatorControl,
        _ => Family::Unported,
    }
}

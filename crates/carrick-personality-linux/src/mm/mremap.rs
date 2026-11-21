//! Linux argument validation shared by both native rings and host dispatch.

use carrick_guest_arch::{GuestLen, GuestVa};
use carrick_syscall_abi::{LINUX_EINVAL, LINUX_ENOMEM, LinuxErrno, LinuxMremapFlags};

/// A well-formed `mremap(2)` request: page-rounded sizes and decoded flags.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct MremapRequest {
    pub old_address: GuestVa,
    pub old_size: GuestLen,
    pub new_size: GuestLen,
    pub new_address: GuestVa,
    pub may_move: bool,
    pub move_fixed: bool,
    pub dontunmap: bool,
}

/// The argument-only `mremap(2)` validation every venue answers first.
///
/// Errno precedence is oracle-derived (real Linux 6.12.76, docker
/// gcc:latest, 2026-07-23 — see .superpowers/sdd/mremap-ruling-report.md) and
/// follows man 2 mremap's documented EINVAL conditions: no unrecognized flag
/// bits, new_size != 0, MREMAP_FIXED/MREMAP_DONTUNMAP only paired with
/// MREMAP_MAYMOVE, and MREMAP_DONTUNMAP only with old_size == new_size. Real
/// Linux validates ALL of these — even for requests that use MREMAP_FIXED or
/// MREMAP_DONTUNMAP — before it would ever attempt the remap, so a malformed
/// request (e.g. an unrelated garbage bit ORed onto MREMAP_FIXED) surfaces
/// the EINVAL real Linux would give.
pub fn mremap_request(
    page_size: GuestLen,
    old_address: GuestVa,
    old_size: GuestLen,
    new_size_req: GuestLen,
    flags: u64,
    new_address: GuestVa,
) -> Result<MremapRequest, LinuxErrno> {
    let flags = LinuxMremapFlags::from_bits_retain(flags);
    let page_size = page_size.raw();
    if new_size_req.raw() == 0 {
        return Err(LINUX_EINVAL);
    }
    if !LinuxMremapFlags::all().contains(flags) {
        return Err(LINUX_EINVAL);
    }
    // `man 2 mremap`: `old_address` must be page aligned. A misaligned
    // request once ran the whole move, then could not reclaim the misaligned
    // source and hit the fail-stop abort (`memflagmatrix` asks for exactly
    // this). Ordering against the other EINVAL checks is unobservable, but
    // it must precede the size rounding below, which answers ENOMEM.
    if !old_address.raw().is_multiple_of(page_size) {
        return Err(LINUX_EINVAL);
    }
    let may_move = flags.contains(LinuxMremapFlags::MAYMOVE);
    // A zero `old_size` asks for a NEW mapping of the same pages, which
    // necessarily relocates, so it requires MREMAP_MAYMOVE
    // (`memflagmatrix` `mremap_old_len_zero_einval`).
    if old_size.raw() == 0 && !may_move {
        return Err(LINUX_EINVAL);
    }
    let old_size = old_size
        .raw()
        .checked_next_multiple_of(page_size)
        .ok_or(LINUX_ENOMEM)?;
    let new_size = new_size_req
        .raw()
        .checked_next_multiple_of(page_size)
        .ok_or(LINUX_ENOMEM)?;
    let move_fixed = flags.contains(LinuxMremapFlags::FIXED);
    let dontunmap = flags.contains(LinuxMremapFlags::DONTUNMAP);
    if (move_fixed || dontunmap) && !may_move {
        return Err(LINUX_EINVAL);
    }
    if dontunmap && new_size != old_size {
        return Err(LINUX_EINVAL);
    }
    // Two MREMAP_FIXED well-formedness checks, both EINVAL (mremap05 cases
    // 2/3: "new_addr has to be page aligned", "old/new area must not
    // overlap").
    if move_fixed
        && (!new_address.raw().is_multiple_of(page_size)
            || old_address
                .raw()
                .checked_add(old_size)
                .is_none_or(|old_end| {
                    old_address.raw() < new_address.raw().saturating_add(new_size)
                        && new_address.raw() < old_end
                }))
    {
        return Err(LINUX_EINVAL);
    }
    Ok(MremapRequest {
        old_address,
        old_size: GuestLen::new(old_size),
        new_size: GuestLen::new(new_size),
        new_address,
        may_move,
        move_fixed,
        dontunmap,
    })
}

//! Shared Linux `mremap(2)` argument validation.
//!
//! One validator for every venue (the host kernel's dispatcher and the
//! shared ring decoder), so both answer a malformed request with the same
//! errno before any lookup or effect. Authority:
//! <https://man7.org/linux/man-pages/man2/mremap.2.html>.

use carrick_syscall_abi::{LINUX_EINVAL, LINUX_ENOMEM, LinuxErrno, LinuxMremapFlags};

/// A well-formed `mremap(2)` request: page-rounded sizes and decoded flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub old_address: u64,
    pub old_size: u64,
    pub new_size: u64,
    pub new_address: u64,
    pub may_move: bool,
    pub move_fixed: bool,
    pub dontunmap: bool,
}

/// The argument-only `mremap(2)` validation every venue answers first.
///
/// Errno precedence is oracle-derived (real Linux 6.12.76, docker
/// gcc:latest, 2026-07-23) and follows man 2 mremap's documented EINVAL
/// conditions: no unrecognized flag bits, new_size != 0,
/// MREMAP_FIXED/MREMAP_DONTUNMAP only paired with MREMAP_MAYMOVE, and
/// MREMAP_DONTUNMAP only with old_size == new_size. Real Linux validates ALL
/// of these, even for requests that use MREMAP_FIXED or MREMAP_DONTUNMAP,
/// before it would ever attempt the remap, so a malformed request (e.g. an
/// unrelated garbage bit ORed onto MREMAP_FIXED) surfaces the EINVAL real
/// Linux would give.
pub fn request(
    page_size: u64,
    old_address: u64,
    old_size: u64,
    new_size_req: u64,
    flags: u64,
    new_address: u64,
) -> Result<Request, LinuxErrno> {
    let flags = LinuxMremapFlags::from_bits_retain(flags);
    if new_size_req == 0 {
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
    if !old_address.is_multiple_of(page_size) {
        return Err(LINUX_EINVAL);
    }
    let may_move = flags.contains(LinuxMremapFlags::MAYMOVE);
    // A zero `old_size` asks for a NEW mapping of the same pages, which
    // necessarily relocates, so it requires MREMAP_MAYMOVE
    // (`memflagmatrix` `mremap_old_len_zero_einval`).
    if old_size == 0 && !may_move {
        return Err(LINUX_EINVAL);
    }
    let old_size = align_up(old_size, page_size).ok_or(LINUX_ENOMEM)?;
    let new_size = align_up(new_size_req, page_size).ok_or(LINUX_ENOMEM)?;
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
        && (!new_address.is_multiple_of(page_size)
            || overlaps(old_address, old_size, new_address, new_size))
    {
        return Err(LINUX_EINVAL);
    }
    Ok(Request {
        old_address,
        old_size,
        new_size,
        new_address,
        may_move,
        move_fixed,
        dontunmap,
    })
}

fn align_up(value: u64, page_size: u64) -> Option<u64> {
    let mask = page_size.checked_sub(1)?;
    value.checked_add(mask).map(|value| value & !mask)
}

/// Whether `[a, a + a_len)` and `[b, b + b_len)` overlap. A source end past
/// the address space overlaps everything; a destination end saturates.
fn overlaps(a: u64, a_len: u64, b: u64, b_len: u64) -> bool {
    let Some(a_end) = a.checked_add(a_len) else {
        return true;
    };
    a < b.saturating_add(b_len) && b < a_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_syscall_abi::{LINUX_MREMAP_DONTUNMAP, LINUX_MREMAP_FIXED, LINUX_MREMAP_MAYMOVE};

    const PAGE: u64 = 4096;

    #[test]
    fn well_formed_requests_round_sizes_and_decode_flags() {
        assert_eq!(
            request(PAGE, 0x1000, 1, 0x1001, LINUX_MREMAP_MAYMOVE, 0),
            Ok(Request {
                old_address: 0x1000,
                old_size: PAGE,
                new_size: 2 * PAGE,
                new_address: 0,
                may_move: true,
                move_fixed: false,
                dontunmap: false,
            })
        );
    }

    #[test]
    fn malformed_requests_answer_linux_errnos_in_linux_order() {
        // new_size 0, unknown bits, misaligned source: EINVAL.
        assert_eq!(request(PAGE, 0x1000, PAGE, 0, 0, 0), Err(LINUX_EINVAL));
        assert_eq!(
            request(PAGE, 0x1000, PAGE, PAGE, 1 << 9, 0),
            Err(LINUX_EINVAL)
        );
        assert_eq!(request(PAGE, 0x1001, PAGE, PAGE, 0, 0), Err(LINUX_EINVAL));
        // old_size 0 needs MAYMOVE; FIXED and DONTUNMAP need MAYMOVE.
        assert_eq!(request(PAGE, 0x1000, 0, PAGE, 0, 0), Err(LINUX_EINVAL));
        assert_eq!(
            request(PAGE, 0x1000, PAGE, PAGE, LINUX_MREMAP_FIXED, 0x9000),
            Err(LINUX_EINVAL)
        );
        assert_eq!(
            request(
                PAGE,
                0x1000,
                PAGE,
                2 * PAGE,
                LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_DONTUNMAP,
                0
            ),
            Err(LINUX_EINVAL)
        );
        // A fixed destination overlapping the source, or misaligned.
        let fixed = LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED;
        assert_eq!(
            request(PAGE, 0x1000, PAGE, PAGE, fixed, 0x1000),
            Err(LINUX_EINVAL)
        );
        assert_eq!(
            request(PAGE, 0x1000, PAGE, PAGE, fixed, 0x9001),
            Err(LINUX_EINVAL)
        );
        // A size that cannot round up is ENOMEM.
        assert_eq!(
            request(PAGE, 0x1000, PAGE, u64::MAX, 0, 0),
            Err(LINUX_ENOMEM)
        );
    }
}

//! A zeroed EL1 region costs the pages a test touches, not its 128 MiB.
//!
//! VM-free suites build hundreds of these fixtures. When each one committed
//! the whole region, `carrick-el1-linux` and `carrick-el1-abi` grew to 6-10 GB
//! resident and hung 19 GB worker VMs (carrick#2822).
#![allow(clippy::unwrap_used)]

use carrick_test_support::TestEl1Region;

/// Bytes of `[base, base + len)` resident in memory, by `mincore(2)`.
fn resident_bytes(base: *const u8, len: usize) -> usize {
    // SAFETY: sysconf reads a constant of this process.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    assert_eq!(base as usize % page, 0, "the region starts on a page");
    let mut pages = vec![0u8; len.div_ceil(page)];
    // SAFETY: the range is one live mapping; `pages` holds one byte per page.
    let status = unsafe { libc::mincore(base as _, len, pages.as_mut_ptr() as _) };
    assert_eq!(status, 0, "mincore: {}", std::io::Error::last_os_error());
    pages.iter().filter(|&&state| state & 1 != 0).count() * page
}

#[test]
fn a_zeroed_region_commits_only_the_pages_it_touches() {
    let len = carrick_el1_abi::EL1_REGION_SIZE as usize;
    let mut region = TestEl1Region::zeroed();
    let base = region.as_mut_ptr();
    // SAFETY: the offset is inside the region this test owns.
    unsafe { base.add(len / 2).write(1) };
    let resident = resident_bytes(base, len);
    // One write commits one page (16 KiB on macOS), never the region and
    // never a 2 MiB transparent huge page.
    assert!(
        resident <= 256 * 1024,
        "{resident} of {len} region bytes resident after one write"
    );
}

//! Retained supervisor aliases and bounded user-permission walks for CPL0.
use carrick_guest_arch::{FrameGpa, KernelVa, RootGpa, UserVa};

/// Resolve a retained table frame, without conferring table edit authority.
pub fn table_alias(frame: FrameGpa) -> Option<KernelVa> {
    carrick_el1_abi::x86_cpl0_table_alias(frame)
}

pub(crate) fn page_allows(
    root: RootGpa,
    user: UserVa,
    write: bool,
    mut load: impl FnMut(KernelVa) -> Option<u64>,
) -> bool {
    const PRESENT: u64 = 1;
    const WRITABLE: u64 = 1 << 1;
    const USER: u64 = 1 << 2;
    const LARGE: u64 = 1 << 7;
    const TABLE_ADDR: u64 = 0x000f_ffff_ffff_f000;
    let mut table = root.address();
    for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
        let Some(mapped) = table_alias(table) else {
            return false;
        };
        let index = (user.raw() >> shift) & 511;
        let Some(desc) = load(KernelVa::new(mapped.raw() + index * 8)) else {
            return false;
        };
        if desc & (PRESENT | USER) != (PRESENT | USER) || (write && desc & WRITABLE == 0) {
            return false;
        }
        if level == 0 && desc & LARGE != 0 {
            return false;
        }
        if level == 3 || (level == 1 || level == 2) && desc & LARGE != 0 {
            return true;
        }
        table = FrameGpa::new(desc & TABLE_ADDR);
    }
    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use carrick_el1_abi::{X86_CPL0_INITIAL_EXTENT_GPA, X86_CPL0_INITIAL_EXTENT_VA};

    #[test]
    fn permission_walk_reads_initial_extent_tables_and_preserves_permissions() {
        let physical = X86_CPL0_INITIAL_EXTENT_GPA + 0x2000;
        let root = RootGpa::page_aligned(FrameGpa::new(physical)).expect("aligned root");
        let user = UserVa::new(0x401000);
        for (write, writable, expected, expected_reads) in [
            (false, false, true, 4),
            (true, true, true, 4),
            (true, false, false, 3),
        ] {
            let mut reads = 0;
            let allowed = page_allows(root, user, write, |address| {
                let level = reads;
                reads += 1;
                let shift = [39, 30, 21, 12][level];
                let offset = ((user.raw() >> shift) & 511) * 8;
                // These are the actual four supervisor aliases, independent
                // of the resolver under test. The old direct alias is absent.
                let expected_address =
                    X86_CPL0_INITIAL_EXTENT_VA + 0x2000 + level as u64 * 4096 + offset;
                assert_eq!(address.raw(), expected_address);
                let next = if level == 3 {
                    0x800000
                } else {
                    physical + (level as u64 + 1) * 4096
                };
                let flags = if level == 2 && !writable { 5 } else { 7 };
                Some(next | flags)
            });
            assert_eq!(allowed, expected);
            assert_eq!(reads, expected_reads, "at most four descriptor loads");
        }
    }
}

//! Stage-1 page-table growth: thousands of scattered 4 KiB anonymous
//! mappings, each in its own 2 MiB region, so the process needs far more
//! leaf tables than one 448-table arena holds.
//!
//! CPython's `test_compiler_recursion_limit` (a million-node AST) and any
//! process with a sparse address space hit this; before multi-arena page
//! tables the guest got ENOMEM from `mmap`, and a broken extension-arena
//! publication shows up here as a refused mapping or a page that does not
//! read back.
//!
//! Invariants encoded, all boolean:
//!
//!   * 3000 `MAP_FIXED` 4 KiB anonymous mappings at 2 MiB strides all
//!     succeed (each needs its own L2 entry and L3 table).
//!   * Every mapping reads back as zeros and then holds a written byte.
//!   * Unmapping all of them succeeds, and remapping the first 500 succeeds
//!     again (freed tables are reusable).
//!
//! Deterministic output: booleans only.

use conformance_probes::report;

const COUNT: usize = 3000;
const STRIDE: usize = 2 * 1024 * 1024;
const BASE: usize = 0x7100_0000_0000;

fn main() {
    unsafe {
        let mut mapped = 0usize;
        let mut zero_ok = true;
        let mut write_ok = true;
        for i in 0..COUNT {
            let va = (BASE + i * STRIDE) as *mut libc::c_void;
            let p = libc::mmap(
                va,
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            );
            if p != va {
                break;
            }
            mapped += 1;
            let b = p as *mut u8;
            if *b != 0 || *b.add(4095) != 0 {
                zero_ok = false;
            }
            *b = (i % 251) as u8 + 1;
            if *b != (i % 251) as u8 + 1 {
                write_ok = false;
            }
        }
        let all_mapped = mapped == COUNT;
        let mut unmapped_ok = true;
        for i in 0..mapped {
            if libc::munmap((BASE + i * STRIDE) as *mut libc::c_void, 4096) != 0 {
                unmapped_ok = false;
            }
        }
        let mut remapped = 0usize;
        for i in 0..500 {
            let va = (BASE + i * STRIDE) as *mut libc::c_void;
            let p = libc::mmap(
                va,
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            );
            if p == va {
                remapped += 1;
                *(p as *mut u8) = 1;
            }
        }
        report!(
            all_scattered_mappings_succeed = all_mapped,
            mappings_read_back_zero = zero_ok && all_mapped,
            mappings_hold_written_byte = write_ok && all_mapped,
            unmap_all_ok = unmapped_ok && all_mapped,
            remap_after_unmap_ok = remapped == 500,
        );
    }
}

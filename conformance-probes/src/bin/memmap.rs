//! mmap/mremap and MAP_SHARED file-mapping COHERENCE probe. Built to surface
//! the suspected apt DynamicMMap cache bug: apt grows a MAP_SHARED file mapping
//! via mremap and relies on shared-mapping write-through to the file. If carrick
//! models MAP_SHARED as a private snapshot, or loses pages on mremap-grow, the
//! coherence/preservation bools below diverge from real arm64 Linux.
//!
//! The conformance harness runs this identical static binary under carrick and
//! real Linux and diffs line by line — a divergent line names the exact edge.
//!
//! Deterministic only: NEVER print addresses or varying sizes. Print booleans,
//! read-back contents, rc, or errno. Each fallible call yields `=ERR:<errno>`
//! on failure. Patterns assume a 4096-byte page (both carrick and ubuntu-arm64).

use std::ffi::CString;

const PAGE: usize = 4096;

fn main() {
    // Sanity: confirm the runtime page size is 4096 (we never print the raw
    // value, only whether the pattern assumption holds).
    {
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        println!("pagesize_is_4096={}", ps == 4096);
    }

    section_a_mremap_grow();
    section_a2_mremap_nomaymove();
    section_b_shared_coherence();
    section_c_edges();
}

// ---------------------------------------------------------------------------
// A2 — mremap grow WITHOUT MREMAP_MAYMOVE that cannot extend in place.
//
// One mmap of 3 contiguous pages gives us a region where the page directly
// above page 0 is already mapped (page 1). Asking to grow JUST page 0 to two
// pages WITHOUT MREMAP_MAYMOVE cannot extend in place (page 1 is occupied) and
// must fail with ENOMEM — no MAP_FIXED needed, so this is portable & robust.
// Then growing page 0 WITH MREMAP_MAYMOVE succeeds, preserving its byte.
// ---------------------------------------------------------------------------
fn section_a2_mremap_nomaymove() {
    let base = mmap_anon(PAGE * 3);
    if base.is_null() {
        println!("a2_mmap_base=ERR:{}", errno());
        return;
    }
    fill_page(base, 0, 0xC1);

    // Grow page 0 (1 page) to 2 pages WITHOUT MAYMOVE → blocked by page 1 → ENOMEM.
    let r = unsafe { libc::mremap(base, PAGE, PAGE * 2, 0) };
    println!(
        "a2_grow_nomaymove_enomem={}",
        r == libc::MAP_FAILED && errno() == libc::ENOMEM
    );

    // Grow page 0 WITH MAYMOVE → succeeds and preserves the original byte. The
    // kernel may relocate, so use the returned pointer for the read-back.
    let np = unsafe { libc::mremap(base, PAGE, PAGE * 2, libc::MREMAP_MAYMOVE) };
    if np == libc::MAP_FAILED {
        println!("a2_grow_maymove=ERR:{}", errno());
        // base+page1,page2 still mapped; release them.
        unsafe {
            libc::munmap((base as *mut u8).add(PAGE) as *mut _, PAGE * 2);
        }
    } else {
        println!("a2_grow_maymove_success={}", true);
        println!(
            "a2_grow_maymove_preserved={}",
            page_first_last_eq(np, 0, 0xC1)
        );
        unsafe {
            libc::munmap(np, PAGE * 2);
            // page1 & page2 of the original region are untouched by the move.
            libc::munmap((base as *mut u8).add(PAGE) as *mut _, PAGE * 2);
        }
    }
}

// ---------------------------------------------------------------------------
// A — mremap grow preserves ALL pages.
// ---------------------------------------------------------------------------
fn section_a_mremap_grow() {
    // mmap anonymous RW, 2 pages. Fill page i entirely with byte (0xA0 + i).
    let p = mmap_anon(PAGE * 2);
    if p.is_null() {
        println!("a_mmap_2page=ERR:{}", errno());
        return;
    }
    fill_page(p, 0, 0xA0);
    fill_page(p, 1, 0xA1);

    // mremap to 8 pages (MREMAP_MAYMOVE).
    let np = unsafe { libc::mremap(p, PAGE * 2, PAGE * 8, libc::MREMAP_MAYMOVE) };
    if np == libc::MAP_FAILED {
        println!("a_mremap_grow_2to8=ERR:{}", errno());
        return;
    }
    // Verify first AND last byte of EACH original page survived the grow.
    let preserved = page_first_last_eq(np, 0, 0xA0) && page_first_last_eq(np, 1, 0xA1);
    println!("a_grow_all_orig_pages_preserved={}", preserved);

    // Write distinct patterns into the NEW pages (2..8), read them back.
    let mut newpages_ok = true;
    for i in 2..8u8 {
        fill_page(np, i as usize, 0xB0u8.wrapping_add(i));
    }
    for i in 2..8u8 {
        if !page_first_last_eq(np, i as usize, 0xB0u8.wrapping_add(i)) {
            newpages_ok = false;
        }
    }
    println!("a_newpages_readback_ok={}", newpages_ok);

    unsafe { libc::munmap(np, PAGE * 8) };

    // Successive grows 2->4->8->16, re-verifying the original 2 pages each time.
    {
        let mut cur = mmap_anon(PAGE * 2);
        if cur.is_null() {
            println!("a_repeated_grow=ERR:{}", errno());
        } else {
            fill_page(cur, 0, 0xA0);
            fill_page(cur, 1, 0xA1);
            let mut old_pages = 2usize;
            let mut all_ok = true;
            for &new_pages in &[4usize, 8, 16] {
                let r = unsafe {
                    libc::mremap(
                        cur,
                        PAGE * old_pages,
                        PAGE * new_pages,
                        libc::MREMAP_MAYMOVE,
                    )
                };
                if r == libc::MAP_FAILED {
                    all_ok = false;
                    println!("a_repeated_grow_step=ERR:{}", errno());
                    break;
                }
                cur = r;
                old_pages = new_pages;
                if !(page_first_last_eq(cur, 0, 0xA0) && page_first_last_eq(cur, 1, 0xA1)) {
                    all_ok = false;
                }
            }
            println!("a_mremap_repeated_grow_preserved={}", all_ok);

            // mremap SHRINK 16 -> 2 pages.
            let r = unsafe {
                libc::mremap(cur, PAGE * old_pages, PAGE * 2, libc::MREMAP_MAYMOVE)
            };
            if r == libc::MAP_FAILED {
                println!("a_shrink_16to2=ERR:{}", errno());
            } else {
                println!("a_shrink_16to2_rc_success={}", true);
                let intact =
                    page_first_last_eq(r, 0, 0xA0) && page_first_last_eq(r, 1, 0xA1);
                println!("a_shrink_remaining_pages_intact={}", intact);
                unsafe { libc::munmap(r, PAGE * 2) };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// B — MAP_SHARED file mapping coherence (the key apt-relevant edges).
//
// EXPECTED DIVERGENCE POINTS: if carrick models MAP_SHARED as a private
// snapshot rather than a true shared file mapping, the three coherence bools
// below (b_mmap_shared_write_visible_via_read, b_file_write_visible_via_mmap,
// b_two_shared_maps_coherent) will print `false` under carrick but `true` on
// real arm64 Linux. Those are the lines to prioritize.
// ---------------------------------------------------------------------------
fn section_b_shared_coherence() {
    let path = "/tmp/mm_shared";
    let fd = open(path, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
    if fd < 0 {
        println!("b_open=ERR:{}", errno());
        return;
    }
    if unsafe { libc::ftruncate(fd, (PAGE * 2) as libc::off_t) } != 0 {
        println!("b_ftruncate=ERR:{}", errno());
        unsafe { libc::close(fd) };
        return;
    }

    let map1 = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if map1 == libc::MAP_FAILED {
        println!("b_mmap_shared=ERR:{}", errno());
        unsafe { libc::close(fd) };
        return;
    }
    println!("b_mmap_shared_ok={}", true);

    // 1) Write a known 16-byte marker at offset 0 THROUGH the mapping, msync,
    //    then pread() the fd at offset 0 and compare.
    let marker_a: [u8; 16] = *b"MARKER_A__012345";
    unsafe {
        std::ptr::copy_nonoverlapping(marker_a.as_ptr(), map1 as *mut u8, marker_a.len());
    }
    let _ = unsafe { libc::msync(map1, PAGE * 2, libc::MS_SYNC) };
    let mut rb = [0u8; 16];
    let n = unsafe { libc::pread(fd, rb.as_mut_ptr() as *mut _, rb.len(), 0) };
    let read_eq = n == marker_a.len() as isize && rb == marker_a;
    println!("b_mmap_shared_write_visible_via_read={}", read_eq);

    // 2) pwrite a different 16-byte marker at offset 4096 to the fd, then read
    //    it THROUGH the mapping.
    let marker_b: [u8; 16] = *b"MARKER_B__abcdef";
    let wn = unsafe { libc::pwrite(fd, marker_b.as_ptr() as *const _, marker_b.len(), PAGE as libc::off_t) };
    let mut via_map = [0u8; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(
            (map1 as *const u8).add(PAGE),
            via_map.as_mut_ptr(),
            via_map.len(),
        );
    }
    let map_reflects = wn == marker_b.len() as isize && via_map == marker_b;
    println!("b_file_write_visible_via_mmap={}", map_reflects);

    // 3) Second fd, second MAP_SHARED mapping; write through #1, read through #2.
    let fd2 = open(path, libc::O_RDWR, 0);
    if fd2 < 0 {
        println!("b_open2=ERR:{}", errno());
    } else {
        let map2 = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE * 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd2,
                0,
            )
        };
        if map2 == libc::MAP_FAILED {
            println!("b_mmap_shared2=ERR:{}", errno());
        } else {
            let marker_c: [u8; 16] = *b"MARKER_C__XYZ789";
            unsafe {
                std::ptr::copy_nonoverlapping(
                    marker_c.as_ptr(),
                    map1 as *mut u8,
                    marker_c.len(),
                );
            }
            // No msync required for shared-mapping coherence between two
            // mappings of the same file on Linux, but issue one to be safe.
            let _ = unsafe { libc::msync(map1, PAGE * 2, libc::MS_SYNC) };
            let mut via2 = [0u8; 16];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    map2 as *const u8,
                    via2.as_mut_ptr(),
                    via2.len(),
                );
            }
            println!("b_two_shared_maps_coherent={}", via2 == marker_c);
            unsafe { libc::munmap(map2, PAGE * 2) };
        }
        unsafe { libc::close(fd2) };
    }

    unsafe {
        libc::munmap(map1, PAGE * 2);
        libc::close(fd);
    }
}

// ---------------------------------------------------------------------------
// C — basic edges.
// ---------------------------------------------------------------------------
fn section_c_edges() {
    // mmap with length 0 -> EINVAL.
    {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                0,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            println!("c_mmap_len0=ERR:{}", errno());
        } else {
            // Should not happen on Linux; report so the diff catches it.
            println!("c_mmap_len0=UNEXPECTED_OK");
            unsafe { libc::munmap(p, PAGE) };
        }
    }

    // MAP_FIXED is fragile — SKIP (documented).

    // mmap(PROT_NONE) a page, mprotect to RW, write+read.
    {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            println!("c_mmap_protnone=ERR:{}", errno());
        } else {
            let rc = unsafe { libc::mprotect(p, PAGE, libc::PROT_READ | libc::PROT_WRITE) };
            if rc != 0 {
                println!("c_mprotect_rw=ERR:{}", errno());
            } else {
                println!("c_mprotect_rw_rc_success={}", true);
                let b = p as *mut u8;
                unsafe {
                    *b = 0x7e;
                    *b.add(PAGE - 1) = 0x7f;
                }
                let ok = unsafe { *b == 0x7e && *b.add(PAGE - 1) == 0x7f };
                println!("c_protnone_then_rw_readback_ok={}", ok);
            }
            unsafe { libc::munmap(p, PAGE) };
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// mmap an anonymous RW region of `len` bytes; returns null on failure.
fn mmap_anon(len: usize) -> *mut libc::c_void {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        std::ptr::null_mut()
    } else {
        p
    }
}

/// Fill page `idx` of mapping `base` entirely with `byte`.
fn fill_page(base: *mut libc::c_void, idx: usize, byte: u8) {
    let p = unsafe { (base as *mut u8).add(idx * PAGE) };
    unsafe {
        std::ptr::write_bytes(p, byte, PAGE);
    }
}

/// True iff the first AND last byte of page `idx` equal `byte`.
fn page_first_last_eq(base: *mut libc::c_void, idx: usize, byte: u8) -> bool {
    let p = unsafe { (base as *const u8).add(idx * PAGE) };
    unsafe { *p == byte && *p.add(PAGE - 1) == byte }
}

/// Open helper returning the raw fd (or -1 on error).
fn open(path: &str, flags: i32, mode: u32) -> i32 {
    let c = CString::new(path).unwrap();
    unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

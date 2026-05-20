//! Memory-management probe. Exercises mmap/mprotect/munmap/mremap/brk/sbrk/
//! madvise/mlock/munlock/msync syscalls and prints one labelled line per
//! observation. The conformance harness runs this identical static binary
//! under carrick and real Linux and diffs line by line — a divergent line
//! names the exact failing syscall.
//!
//! Deterministic only: never print addresses or sizes that vary. Print
//! booleans, read-back contents, rc, or errno. Each fallible call yields
//! `=ERR:<errno>` on failure.

use std::ffi::CString;

const PAGE: usize = 4096;

fn main() {
    // mmap anonymous RW: 1 page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS.
    // Print whether it returned a non-MAP_FAILED pointer, then write a byte
    // pattern and read it back (deterministic content).
    {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            println!("mmap_anon=ERR:{}", errno());
        } else {
            println!("mmap_anon_ok={}", true);
            // Write a deterministic byte pattern: 0,1,2,3 at the first 4 bytes.
            let bytes = p as *mut u8;
            unsafe {
                for i in 0..4u8 {
                    *bytes.add(i as usize) = i;
                }
            }
            let mut readback = [0u8; 4];
            unsafe {
                for i in 0..4usize {
                    readback[i] = *bytes.add(i);
                }
            }
            println!(
                "mmap_anon_readback={},{},{},{}",
                readback[0], readback[1], readback[2], readback[3]
            );

            // mprotect that region to PROT_READ.
            let rc = unsafe { libc::mprotect(p, PAGE, libc::PROT_READ) };
            if rc != 0 {
                println!("mprotect_r=ERR:{}", errno());
            } else {
                println!("mprotect_r_rc={}", rc);
            }

            // madvise(MADV_DONTNEED) on the mapping (still mapped, RO is fine).
            let rc = unsafe { libc::madvise(p, PAGE, libc::MADV_DONTNEED) };
            if rc != 0 {
                println!("madvise_dontneed=ERR:{}", errno());
            } else {
                println!("madvise_dontneed_rc={}", rc);
            }

            // munmap it.
            let rc = unsafe { libc::munmap(p, PAGE) };
            if rc != 0 {
                println!("munmap=ERR:{}", errno());
            } else {
                println!("munmap_rc={}", rc);
            }
        }
    }

    // mremap: mmap 1 page, write a sentinel first byte, mremap to 2 pages
    // (MREMAP_MAYMOVE), confirm rc-success and that the first byte is
    // preserved after grow.
    {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            println!("mremap=ERR:{}", errno());
        } else {
            // Write a sentinel byte before growing.
            unsafe { *(p as *mut u8) = 0x5a };
            let np = unsafe { libc::mremap(p, PAGE, PAGE * 2, libc::MREMAP_MAYMOVE) };
            if np == libc::MAP_FAILED {
                println!("mremap=ERR:{}", errno());
            } else {
                println!("mremap_ok={}", true);
                let first = unsafe { *(np as *const u8) };
                println!("mremap_preserved={}", first == 0x5a);
                unsafe { libc::munmap(np, PAGE * 2) };
            }
        }
    }

    // brk(0)/sbrk(0): print whether the current break is non-zero. Do NOT print
    // the address itself.
    {
        let cur = unsafe { libc::sbrk(0) };
        // sbrk returns (void*)-1 on error.
        if cur == (-1isize) as *mut libc::c_void {
            println!("sbrk0=ERR:{}", errno());
        } else {
            println!("sbrk0_nonzero={}", !cur.is_null());
        }
    }

    // mlock/munlock a page: print rc for each (may be 0 or EPERM). On failure
    // print the errno so the diff reveals carrick vs Linux; both acceptable.
    {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            println!("mlock=ERR:{}", errno());
        } else {
            let rc = unsafe { libc::mlock(p, PAGE) };
            if rc != 0 {
                println!("mlock=ERR:{}", errno());
            } else {
                println!("mlock_rc={}", rc);
            }
            let rc = unsafe { libc::munlock(p, PAGE) };
            if rc != 0 {
                println!("munlock=ERR:{}", errno());
            } else {
                println!("munlock_rc={}", rc);
            }
            unsafe { libc::munmap(p, PAGE) };
        }
    }

    // msync on a file-backed mapping: create a 1-page file, mmap shared RW,
    // write a byte, msync(MS_SYNC).
    {
        let path = CString::new("/tmp/mem_msync").unwrap();
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
        };
        if fd < 0 {
            println!("msync=ERR:{}", errno());
        } else {
            unsafe { libc::ftruncate(fd, PAGE as libc::off_t) };
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            if p == libc::MAP_FAILED {
                println!("msync=ERR:{}", errno());
            } else {
                unsafe { *(p as *mut u8) = 0x42 };
                let rc = unsafe { libc::msync(p, PAGE, libc::MS_SYNC) };
                if rc != 0 {
                    println!("msync=ERR:{}", errno());
                } else {
                    println!("msync_rc={}", rc);
                }
                unsafe { libc::munmap(p, PAGE) };
            }
            unsafe { libc::close(fd) };
        }
    }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

const CEILING: usize = 1 << 47;
const PAGE: usize = 4096;

fn main() {
    const { assert!(cfg!(target_arch = "x86_64")) };
    for scale in [1, 8, 32] {
        let mut mappings = Vec::new();
        for _ in 0..scale {
            let address = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    PAGE,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(address, libc::MAP_FAILED);
            assert!((address as usize) < CEILING - PAGE);
            mappings.push(address);
        }
        println!("mmap_null_lower_half_{scale}=true");
        for address in mappings {
            assert_eq!(unsafe { libc::munmap(address, PAGE) }, 0);
        }
    }
    // Low 48 bits must not be stripped from a native x86 address. Check both
    // the first noncanonical VA and high-half/wrapped values.
    for address in [
        CEILING - 2 * PAGE,
        CEILING - PAGE,
        CEILING,
        CEILING + PAGE,
        (1usize << 48) + PAGE,
        usize::MAX - PAGE + 1,
    ] {
        let mapped = unsafe {
            libc::mmap(
                address as *mut _,
                PAGE,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        let errno = if mapped == libc::MAP_FAILED {
            std::io::Error::last_os_error().raw_os_error().unwrap()
        } else {
            assert_eq!(unsafe { libc::munmap(mapped, PAGE) }, 0);
            0
        };
        println!("mmap_fixed_{address:#x}_errno={errno}");
    }
}

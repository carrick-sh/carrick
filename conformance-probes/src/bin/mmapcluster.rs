use conformance_probes::report;

const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;
const HIGH_FIXED_ADDR: usize = 0x7fff_0000_0000;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

unsafe fn close_if_valid(fd: i32) {
    if fd >= 0 {
        libc::close(fd);
    }
}

fn mapping_perms(addr: usize) -> Option<String> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let mut containing = None;
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let perms = parts.next()?;
        let (lo, hi) = range.split_once('-')?;
        let lo = usize::from_str_radix(lo, 16).ok()?;
        let hi = usize::from_str_radix(hi, 16).ok()?;
        if lo == addr {
            return Some(perms.to_string());
        }
        if addr >= lo && addr < hi {
            containing = Some(perms.to_string());
        }
    }
    containing
}

/// Large Linux virtual mappings reserve address space without allocating their
/// entire byte length. Touch only three pages, then release the whole extent.
fn sparse_large_mapping(label: &str, length: usize) {
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let base = libc::mmap(
            core::ptr::null_mut(),
            length,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        );
        let map_errno = if base == libc::MAP_FAILED { errno() } else { 0 };
        let mut protect_ok = 0;
        let mut initial_zero = 0;
        let mut distinct = 0;
        let mut unmap_rc = -1;
        if base != libc::MAP_FAILED {
            let offsets = [0, (length / 2 / page) * page, length - page];
            let mut protected = [false; 3];
            for (i, offset) in offsets.iter().enumerate() {
                let address = (base as usize + offset) as *mut u8;
                if libc::mprotect(address.cast(), page, libc::PROT_READ | libc::PROT_WRITE) == 0 {
                    protected[i] = true;
                    protect_ok += 1;
                    if address.read_volatile() == 0 {
                        initial_zero += 1;
                    }
                    address.write_volatile((i + 1) as u8);
                }
            }
            for (i, offset) in offsets.iter().enumerate() {
                if protected[i]
                    && ((base as usize + offset) as *const u8).read_volatile() == (i + 1) as u8
                {
                    distinct += 1;
                }
            }
            unmap_rc = libc::munmap(base, length);
        }
        println!("{label}_map_errno={map_errno}");
        println!("{label}_protected_pages={protect_ok}");
        println!("{label}_initial_zero_pages={initial_zero}");
        println!("{label}_distinct_pages={distinct}");
        println!("{label}_unmap={unmap_rc}");
    }
}

/// Large writable reservations must support both guest faults and kernel-first
/// copyin/copyout on distinct, previously untouched pages. All pipe I/O is
/// nonblocking so a broken transfer is an observation rather than a stuck probe.
fn sparse_large_rw_mapping(label: &str, length: usize) {
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let base = libc::mmap(
            core::ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        );
        let map_errno = if base == libc::MAP_FAILED { errno() } else { 0 };
        let mut initial_zero = 0;
        let mut distinct = 0;
        let mut kernel_copyin = 0;
        let mut kernel_copyout = 0;
        let mut pipe_errno = 0;
        let mut unmap_rc = -1;
        if base != libc::MAP_FAILED {
            let offsets = [0, (length / 2 / page) * page, length - 3 * page];
            let mut pipes = [-1; 2];
            let pipe_ok = libc::pipe2(pipes.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) == 0;
            if !pipe_ok {
                pipe_errno = errno();
            }
            for (i, offset) in offsets.iter().enumerate() {
                let direct = (base as usize + offset) as *mut u8;
                let input = direct.add(page);
                let output = direct.add(2 * page);
                // Kernel reads this fresh page before any guest load/store.
                if pipe_ok {
                    let mut observed = 0xffu8;
                    if libc::write(pipes[1], input.cast(), 1) == 1
                        && libc::read(pipes[0], (&mut observed as *mut u8).cast(), 1) == 1
                        && observed == 0
                    {
                        kernel_copyin += 1;
                    }
                    let value = (i + 11) as u8;
                    // Kernel writes a different fresh page before its first guest access.
                    if libc::write(pipes[1], (&value as *const u8).cast(), 1) == 1
                        && libc::read(pipes[0], output.cast(), 1) == 1
                        && output.read_volatile() == value
                    {
                        kernel_copyout += 1;
                    }
                }
                if direct.read_volatile() == 0 {
                    initial_zero += 1;
                }
                direct.write_volatile((i + 1) as u8);
            }
            if pipe_ok {
                libc::close(pipes[0]);
                libc::close(pipes[1]);
            }
            for (i, offset) in offsets.iter().enumerate() {
                let direct = (base as usize + offset) as *const u8;
                if direct.read_volatile() == (i + 1) as u8
                    && direct.add(page).read_volatile() == 0
                    && direct.add(2 * page).read_volatile() == (i + 11) as u8
                {
                    distinct += 1;
                }
            }
            unmap_rc = libc::munmap(base, length);
        }
        println!("{label}_rw_map_errno={map_errno}");
        println!("{label}_rw_pipe_errno={pipe_errno}");
        println!("{label}_rw_initial_zero_pages={initial_zero}");
        println!("{label}_rw_distinct_groups={distinct}");
        println!("{label}_rw_kernel_first_copyin={kernel_copyin}");
        println!("{label}_rw_kernel_first_copyout={kernel_copyout}");
        println!("{label}_rw_unmap={unmap_rc}");
    }
}

fn main() {
    unsafe {
        libc::mkdir(c"/tmp".as_ptr(), 0o777);

        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let private_base = libc::mmap(
            core::ptr::null_mut(),
            page * 2,
            libc::PROT_NONE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        let private = if private_base == libc::MAP_FAILED {
            libc::MAP_FAILED
        } else {
            libc::mmap(
                (private_base as usize + page) as *mut libc::c_void,
                page,
                libc::PROT_READ,
                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        let shared_base = libc::mmap(
            core::ptr::null_mut(),
            page * 2,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        let shared = if shared_base == libc::MAP_FAILED {
            libc::MAP_FAILED
        } else {
            libc::mmap(
                (shared_base as usize + page) as *mut libc::c_void,
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        let private_perms = if private == libc::MAP_FAILED {
            "MAP_FAILED".to_string()
        } else {
            mapping_perms(private as usize).unwrap_or_else(|| "missing".to_string())
        };
        let shared_perms = if shared == libc::MAP_FAILED {
            "MAP_FAILED".to_string()
        } else {
            mapping_perms(shared as usize).unwrap_or_else(|| "missing".to_string())
        };

        let fd = libc::open(
            c"/tmp/mmapcluster_file".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if fd >= 0 {
            let bytes = [b'A'; 4096];
            libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len());
        }
        errno_reset();
        let write_only_map = libc::mmap(
            core::ptr::null_mut(),
            page,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0,
        );
        let write_only_errno = errno();
        if write_only_map != libc::MAP_FAILED {
            libc::munmap(write_only_map, page);
        }

        let first = libc::mmap(
            core::ptr::null_mut(),
            page,
            libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        errno_reset();
        let noreplace = libc::mmap(
            first,
            page,
            libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        let noreplace_errno = errno();
        if noreplace != libc::MAP_FAILED {
            libc::munmap(noreplace, page);
        }

        let pagemap_fd = libc::open(c"/proc/self/pagemap".as_ptr(), libc::O_RDONLY);
        let pagemap_open_ok = pagemap_fd >= 0;
        close_if_valid(pagemap_fd);

        let bus_fd = libc::open(
            c"/tmp/mmapcluster_bus".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if bus_fd >= 0 {
            libc::ftruncate(bus_fd, (page / 2) as libc::off_t);
        }
        let bus_map = libc::mmap(
            core::ptr::null_mut(),
            page * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            bus_fd,
            0,
        );
        let bus_child_signal = if bus_map == libc::MAP_FAILED {
            -1
        } else {
            let pid = libc::fork();
            if pid == 0 {
                *((bus_map as usize + page + 1) as *mut u8) = 1;
                libc::_exit(0);
            }
            let mut status = 0;
            libc::wait4(pid, &mut status, 0, core::ptr::null_mut());
            if libc::WIFSIGNALED(status) {
                libc::WTERMSIG(status)
            } else {
                0
            }
        };

        errno_reset();
        let high = libc::mmap(
            HIGH_FIXED_ADDR as *mut libc::c_void,
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        let high_errno = errno();
        if high != libc::MAP_FAILED {
            libc::munmap(high, page);
        }

        report!(
            private_perms = private_perms.as_str(),
            shared_perms = shared_perms.as_str(),
            write_only_errno = write_only_errno,
            noreplace_errno = noreplace_errno,
            pagemap_open_ok = pagemap_open_ok,
            bus_child_signal = bus_child_signal,
            high_errno = high_errno,
        );

        if private != libc::MAP_FAILED {
            libc::munmap(private_base, page * 2);
        }
        if shared != libc::MAP_FAILED {
            libc::munmap(shared_base, page * 2);
        }
        if bus_map != libc::MAP_FAILED {
            libc::munmap(bus_map, page * 2);
        }
        close_if_valid(bus_fd);
        close_if_valid(fd);
    }
    sparse_large_mapping("vma64g", 64usize << 30);
    sparse_large_mapping("vma16t", 16usize << 40);
    sparse_large_rw_mapping("vma64g", 64usize << 30);
    sparse_large_rw_mapping("vma16t", 16usize << 40);
}

unsafe fn errno_reset() {
    #[cfg(any(target_env = "gnu", target_env = "musl"))]
    {
        *libc::__errno_location() = 0;
    }
}

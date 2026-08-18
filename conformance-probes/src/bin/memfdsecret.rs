//! memfd_secret(2) probe. Creates a secret-memory fd and pins down the ABI
//! shape LTP's `tst_fd` helper and `splice07` rely on: flag validation, the
//! `/proc/self/fd` link name, the read/write(2) rejection (secretmem has no
//! file read/write methods), ftruncate+fstat sizing, the MAP_PRIVATE
//! rejection (secretmem mappings must be MAP_SHARED), a working MAP_SHARED
//! read/write mapping, and the secrecy property itself — the mapped page is
//! NOT readable through `/proc/self/mem`.
//!
//! Deterministic: prints booleans and errno numbers only (no fds, addresses,
//! or sizes beyond the fixed ftruncate length). Runs under Docker's default
//! seccomp profile, which allows memfd_secret (the differential oracle).

use std::io::Read;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn main() {
    unsafe {
        // Unknown flag bit → EINVAL (only FD_CLOEXEC is defined).
        let bad = libc::syscall(libc::SYS_memfd_secret, 0xffu32 as libc::c_ulong);
        println!(
            "create_badflags_einval={}",
            bad == -1 && errno() == libc::EINVAL
        );

        let fd = libc::syscall(libc::SYS_memfd_secret, 0u64) as libc::c_int;
        println!("create_ok={}", fd >= 0);
        if fd < 0 {
            // Without a fd nothing below is meaningful; print a stable tail so
            // the diff shows exactly one failing line per behaviour.
            println!("cloexec_default_clear=false");
            println!("fd_link_secretmem=false");
            println!("read_errno=-1");
            println!("write_errno=-1");
            println!("ftruncate_ok=false");
            println!("fstat_size=-1");
            println!("mmap_private_errno=-1");
            println!("mmap_shared_ok=false");
            println!("map_rw=false");
            println!("procmem_hidden=false");
            println!("create_cloexec_set=false");
            return;
        }

        // flags=0 → FD_CLOEXEC clear.
        let fdflags = libc::fcntl(fd, libc::F_GETFD);
        println!(
            "cloexec_default_clear={}",
            fdflags >= 0 && fdflags & libc::FD_CLOEXEC == 0
        );

        // /proc/self/fd/<n> names the secretmem inode.
        let mut link = [0u8; 256];
        let path = format!("/proc/self/fd/{fd}\0");
        let n = libc::readlink(
            path.as_ptr() as *const libc::c_char,
            link.as_mut_ptr() as *mut libc::c_char,
            link.len(),
        );
        let link_str = if n > 0 {
            std::str::from_utf8(&link[..n as usize]).unwrap_or("")
        } else {
            ""
        };
        println!("fd_link_secretmem={}", link_str.contains("secretmem"));

        // read(2)/write(2) are not supported on a secretmem fd.
        let mut byte = [0u8; 1];
        let r = libc::read(fd, byte.as_mut_ptr() as *mut _, 1);
        println!("read_errno={}", if r == -1 { errno() } else { 0 });
        let w = libc::write(fd, byte.as_ptr() as *const _, 1);
        println!("write_errno={}", if w == -1 { errno() } else { 0 });

        // ftruncate sets the size; fstat reports it.
        let t = libc::ftruncate(fd, 4096);
        println!("ftruncate_ok={}", t == 0);
        let mut st: libc::stat = core::mem::zeroed();
        let s = libc::fstat(fd, &mut st);
        println!("fstat_size={}", if s == 0 { st.st_size } else { -1 });

        // MAP_PRIVATE of secretmem is rejected; MAP_SHARED works.
        let p = libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            fd,
            0,
        );
        println!(
            "mmap_private_errno={}",
            if p == libc::MAP_FAILED { errno() } else { 0 }
        );
        if p != libc::MAP_FAILED {
            libc::munmap(p, 4096);
        }
        let m = libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        println!("mmap_shared_ok={}", m != libc::MAP_FAILED);
        if m == libc::MAP_FAILED {
            println!("map_rw=false");
            println!("procmem_hidden=false");
        } else {
            let cell = m as *mut u8;
            cell.write_volatile(0xa5);
            println!("map_rw={}", cell.read_volatile() == 0xa5);

            // The secrecy property: the page must NOT be readable through
            // /proc/self/mem (the kernel cannot GUP secretmem pages).
            let hidden = match std::fs::File::open("/proc/self/mem") {
                Ok(mut f) => {
                    use std::io::Seek;
                    let mut buf = [0u8; 1];
                    match f
                        .seek(std::io::SeekFrom::Start(m as u64))
                        .and_then(|_| f.read(&mut buf))
                    {
                        Ok(1) => false, // readable → NOT hidden
                        _ => true,
                    }
                }
                Err(_) => false,
            };
            println!("procmem_hidden={hidden}");
            libc::munmap(m, 4096);
        }
        libc::close(fd);

        // The close-on-exec creation flag. memfd_secret(2) documents a
        // close-on-exec bit in the flag word; probe BOTH candidate spellings
        // (FD_CLOEXEC=1 and O_CLOEXEC) so the oracle pins down which value the
        // ABI actually takes: print the creation errno (0 = success) and
        // whether the resulting fd carries FD_CLOEXEC.
        for (label, bits) in [
            ("fd_cloexec", libc::FD_CLOEXEC as libc::c_ulong),
            ("o_cloexec", libc::O_CLOEXEC as libc::c_ulong),
        ] {
            let cfd = libc::syscall(libc::SYS_memfd_secret, bits) as libc::c_int;
            let create_errno = if cfd >= 0 { 0 } else { errno() };
            let flag_set = cfd >= 0 && {
                let f = libc::fcntl(cfd, libc::F_GETFD);
                f >= 0 && f & libc::FD_CLOEXEC != 0
            };
            println!("create_{label}_errno={create_errno}");
            println!("create_{label}_cloexec_set={flag_set}");
            if cfd >= 0 {
                libc::close(cfd);
            }
        }
    }
}

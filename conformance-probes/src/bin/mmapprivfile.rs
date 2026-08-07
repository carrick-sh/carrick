//! MAP_PRIVATE file-mapping contract: the observable semantics carrick's
//! private-file mmap must provide regardless of HOW it materializes the
//! mapping (eager snapshot today, host file-backed `MAP_PRIVATE|MAP_FIXED`
//! under the E1 lowering). Pinned before the lowering lands so it can catch
//! the lowering breaking the contract (Move-3 Task 5,
//! docs/superpowers/plans/2026-08-06-move3-amplification-ledger.md §2/E1).
//!
//! Clauses, each printed as its own line so a DIFF pinpoints the failing op:
//!   * map-time content: mapped bytes equal file bytes, at offset 0 and at a
//!     non-zero page-aligned offset, under PROT_READ|WRITE and read-only fd;
//!   * EOF zero tail: the last partially-backed page reads zero beyond EOF;
//!   * beyond-EOF fault: a page wholly beyond map-time EOF delivers SIGBUS
//!     (Linux BUS_ADRERR). At HEAD carrick's mmap-arena path zero-fills the
//!     whole range instead — that clause is the E1 red-first receipt;
//!   * COW privacy: a store through the mapping never reaches the file;
//!   * detachment for written pages: a later ftruncate through a second fd
//!     does not disturb a page the guest already COW'd by writing;
//!   * fd independence: the mapping outlives close(fd).
//!
//! Deliberately NOT pinned (divergent between Linux and carrick's documented
//! map-time-frozen contract, in one direction or the other, so no DIFF-free
//! line exists): reads of UNTOUCHED pages after an external truncate (Linux
//! SIGBUS, carrick keeps data), and file growth re-exposing formerly
//! beyond-EOF pages (Linux fault-time check, carrick map-time freeze).
//! Everything is page-size-relative: the native lane runs 16 KiB guest pages
//! against the oracle's 4 KiB, so no absolute offset may appear in output.

use conformance_probes::{reap, report};

fn pattern(i: usize) -> u8 {
    ((i * 7) ^ (i >> 8)) as u8
}

const PATH: &str = "/tmp/mmapprivfile_probe\0";

/// Create the backing file with `file_bytes` pattern bytes and map `pages`
/// pages MAP_PRIVATE at `map_offset`. Returns (map, page_size, fd).
unsafe fn setup(
    pages: usize,
    file_bytes: usize,
    map_offset: usize,
    prot: i32,
) -> (*mut u8, usize, i32) {
    let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    let fd = libc::open(
        PATH.as_ptr().cast(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    );
    assert!(fd >= 0, "open failed");
    let buf: Vec<u8> = (0..file_bytes).map(pattern).collect();
    assert_eq!(
        libc::pwrite(fd, buf.as_ptr().cast(), file_bytes, 0),
        file_bytes as isize,
        "pwrite failed"
    );
    let p = libc::mmap(
        core::ptr::null_mut(),
        pages * page,
        prot,
        libc::MAP_PRIVATE,
        fd,
        map_offset as libc::off_t,
    );
    assert_ne!(p, libc::MAP_FAILED, "mmap failed");
    (p.cast::<u8>(), page, fd)
}

unsafe fn teardown(p: *mut u8, pages: usize, page: usize, fd: i32) {
    libc::munmap(p.cast(), pages * page);
    libc::close(fd);
    libc::unlink(PATH.as_ptr().cast());
}

/// Run `f` in a forked child; report how it terminated. exit 0 = clause holds.
unsafe fn in_child(f: impl Fn() -> i32) -> String {
    let pid = libc::fork();
    if pid == 0 {
        libc::_exit(f());
    }
    let (_, status) = reap(pid);
    if libc::WIFEXITED(status) {
        format!("exit:{}", libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        let name = match sig {
            libc::SIGBUS => "SIGBUS",
            libc::SIGSEGV => "SIGSEGV",
            _ => "signal",
        };
        format!("{name}")
    } else {
        "unknown".to_string()
    }
}

fn main() {
    unsafe {
        libc::mkdir(c"/tmp".as_ptr(), 0o777);
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        // File covers two full pages plus half of the third: page 2 is the
        // partially-backed page (zero tail), page 3 is wholly beyond EOF.
        let file_bytes = 2 * page + page / 2;

        // 1. map-time content at offset 0, RW mapping.
        let (p, _, fd) = setup(4, file_bytes, 0, libc::PROT_READ | libc::PROT_WRITE);
        let spots = [0usize, 1, page - 1, page + 3, 2 * page, file_bytes - 1];
        let content_ok = spots.iter().all(|&i| *p.add(i) == pattern(i));
        report!(content_at_zero_offset = content_ok);

        // 2. EOF zero tail of the partially-backed page.
        let tail_ok = (0..64).all(|i| *p.add(file_bytes + i) == 0) && *p.add(3 * page - 1) == 0;
        report!(zero_tail_after_eof = tail_ok);

        // 3. a page wholly beyond map-time EOF faults SIGBUS.
        let addr = p as usize;
        report!(
            beyond_eof_page = in_child(|| {
                let v = core::ptr::read_volatile((addr + 3 * page + 8) as *const u8);
                // Reaching here means no fault; exit with the byte (Linux never
                // gets here). 200 disambiguates a zero byte from a clean exit.
                if v == 0 { 200 } else { 201 }
            })
        );

        // 4. COW privacy: a store through the mapping never reaches the file.
        *p.add(page + 16) = 0x5a;
        let mut readback = 0u8;
        assert_eq!(
            libc::pread(
                fd,
                (&mut readback as *mut u8).cast(),
                1,
                (page + 16) as libc::off_t
            ),
            1
        );
        report!(
            cow_store_private_to_file = (readback == pattern(page + 16)),
            cow_store_visible_in_map = (*p.add(page + 16) == 0x5a),
        );

        // 5. detachment for written pages: ftruncate through a second fd does
        //    not disturb an already-COW'd page.
        *p = 0x77; // COW page 0
        let fd2 = libc::open(PATH.as_ptr().cast(), libc::O_RDWR);
        assert!(fd2 >= 0);
        assert_eq!(libc::ftruncate(fd2, 1), 0);
        libc::close(fd2);
        report!(written_page_survives_truncate = (*p == 0x77));
        teardown(p, 4, page, fd);

        // 6. mapping at a non-zero page-aligned offset, read-only fd + PROT_READ
        //    (the loader/linker shape), and the mapping outlives close(fd).
        let (p, _, fd) = setup(1, file_bytes, page, libc::PROT_READ);
        // Remap read-only through an O_RDONLY fd to model the loader exactly.
        libc::munmap(p.cast(), page);
        let rfd = libc::open(PATH.as_ptr().cast(), libc::O_RDONLY);
        assert!(rfd >= 0);
        let p = libc::mmap(
            core::ptr::null_mut(),
            page,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            rfd,
            page as libc::off_t,
        );
        assert_ne!(p, libc::MAP_FAILED);
        let p = p.cast::<u8>();
        libc::close(rfd);
        let offset_ok = (0..8).all(|i| *p.add(i) == pattern(page + i));
        report!(
            nonzero_offset_rdonly_content = offset_ok,
            mapping_survives_fd_close = (*p.add(4) == pattern(page + 4)),
        );
        libc::munmap(p.cast(), page);
        libc::close(fd);
        libc::unlink(PATH.as_ptr().cast());

        println!("DONE");
    }
}

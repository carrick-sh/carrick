//! Conformance probe for SEEK_DATA and SEEK_HOLE mapping on sparse files and non-seekable streams.
//!
//! Invariants:
//! - Sparse regular file of 1 MiB with 4 KiB data at 0 and 4 KiB data at 512 KiB:
//!   * Offset 0: SEEK_DATA -> 0, SEEK_HOLE -> 4096
//!   * Offset 100: SEEK_DATA -> 100, SEEK_HOLE -> 4096
//!   * Offset 4096: SEEK_DATA -> 524288, SEEK_HOLE -> 4096
//!   * Offset 524288 (512 KiB): SEEK_DATA -> 524288, SEEK_HOLE -> 528384
//!   * Offset 528384 (512 KiB + 4096): SEEK_DATA -> -1 (ENXIO), SEEK_HOLE -> 528384
//!   * Offset 1048576 (EOF): SEEK_DATA -> -1 (ENXIO), SEEK_HOLE -> -1 (ENXIO)
//!   * Offset 1048577 (past EOF): SEEK_DATA -> -1 (ENXIO), SEEK_HOLE -> -1 (ENXIO)
//!   * Offset -1 (negative): SEEK_DATA/SEEK_HOLE fail; the errno is reported
//!     as a number so the oracle, not an assumption, names it
//! - Pipe descriptor:
//!   * SEEK_DATA -> -1 (ESPIPE)
//!   * SEEK_HOLE -> -1 (ESPIPE)

use conformance_probes::{errno, report};

const LINUX_SEEK_DATA: libc::c_int = 3;
const LINUX_SEEK_HOLE: libc::c_int = 4;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr().cast(), 0o777);
        let path = b"/tmp/cr_seekholemap\0".as_ptr().cast();
        libc::unlink(path);
        let fd = libc::open(path, libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC, 0o644);
        assert!(fd >= 0, "open temp file failed");

        assert_eq!(libc::ftruncate(fd, 1048576), 0);
        let buf = [0xAAu8; 4096];
        assert_eq!(libc::pwrite(fd, buf.as_ptr().cast(), 4096, 0), 4096);
        assert_eq!(libc::pwrite(fd, buf.as_ptr().cast(), 4096, 524288), 4096);

        // Offsets: 0
        let d0 = libc::lseek(fd, 0, LINUX_SEEK_DATA);
        let h0 = libc::lseek(fd, 0, LINUX_SEEK_HOLE);

        // Offsets: 100
        let d100 = libc::lseek(fd, 100, LINUX_SEEK_DATA);
        let h100 = libc::lseek(fd, 100, LINUX_SEEK_HOLE);

        // Offsets: 4096
        let d4096 = libc::lseek(fd, 4096, LINUX_SEEK_DATA);
        let h4096 = libc::lseek(fd, 4096, LINUX_SEEK_HOLE);

        // Offsets: 524288 (512 KiB)
        let d512k = libc::lseek(fd, 524288, LINUX_SEEK_DATA);
        let h512k = libc::lseek(fd, 524288, LINUX_SEEK_HOLE);

        // Offsets: 528384 (512 KiB + 4096)
        let d528k = libc::lseek(fd, 528384, LINUX_SEEK_DATA);
        let d528k_err = if d528k == -1 { errno() } else { 0 };
        let h528k = libc::lseek(fd, 528384, LINUX_SEEK_HOLE);

        // Offsets: 1048576 (EOF)
        let deof = libc::lseek(fd, 1048576, LINUX_SEEK_DATA);
        let deof_err = if deof == -1 { errno() } else { 0 };
        let heof = libc::lseek(fd, 1048576, LINUX_SEEK_HOLE);
        let heof_err = if heof == -1 { errno() } else { 0 };

        // Offsets: 1048577 (past EOF)
        let dpast = libc::lseek(fd, 1048577, LINUX_SEEK_DATA);
        let dpast_err = if dpast == -1 { errno() } else { 0 };
        let hpast = libc::lseek(fd, 1048577, LINUX_SEEK_HOLE);
        let hpast_err = if hpast == -1 { errno() } else { 0 };

        // Negative offset
        let dneg = libc::lseek(fd, -1, LINUX_SEEK_DATA);
        let dneg_err = if dneg == -1 { errno() } else { 0 };
        let hneg = libc::lseek(fd, -1, LINUX_SEEK_HOLE);
        let hneg_err = if hneg == -1 { errno() } else { 0 };

        // Pipe
        let mut pfd = [-1i32; 2];
        assert_eq!(libc::pipe(pfd.as_mut_ptr()), 0);
        let pdata = libc::lseek(pfd[0], 0, LINUX_SEEK_DATA);
        let pdata_err = if pdata == -1 { errno() } else { 0 };
        let phole = libc::lseek(pfd[0], 0, LINUX_SEEK_HOLE);
        let phole_err = if phole == -1 { errno() } else { 0 };

        // LTP lseek11 discovers allocation granularity by repeatedly shrinking
        // and writing one byte beyond EOF. Pre-sizing a sparse file above does
        // not exercise this growth path. Report values, not guessed extents.
        let cycle_offsets = [256i64, 512, 1024, 2048, 4096, 8192, 16384];
        let mut cycle_results = Vec::new();
        for offset in cycle_offsets {
            let truncate_rc = libc::ftruncate(fd, 0);
            let write_rc = libc::pwrite(fd, b"a".as_ptr().cast(), 1, offset);
            let sync_rc = libc::fsync(fd);
            let data = libc::lseek(fd, 0, LINUX_SEEK_DATA);
            let data_errno = if data < 0 { errno() } else { 0 };
            let hole = libc::lseek(fd, 0, LINUX_SEEK_HOLE);
            let hole_errno = if hole < 0 { errno() } else { 0 };
            cycle_results.push((
                offset,
                truncate_rc,
                write_rc,
                sync_rc,
                data,
                data_errno,
                hole,
                hole_errno,
            ));
        }

        libc::close(pfd[0]);
        libc::close(pfd[1]);
        libc::close(fd);
        libc::unlink(path);

        report!(
            seek_data_at_0 = d0 == 0,
            seek_hole_at_0 = h0 == 4096,
            seek_data_at_100 = d100 == 100,
            seek_hole_at_100 = h100 == 4096,
            seek_data_at_4096 = d4096 == 524288,
            seek_hole_at_4096 = h4096 == 4096,
            seek_data_at_512k = d512k == 524288,
            seek_hole_at_512k = h512k == 528384,
            seek_data_at_528k_enxio = d528k == -1 && d528k_err == libc::ENXIO,
            seek_hole_at_528k = h528k == 528384,
            seek_data_eof_enxio = deof == -1 && deof_err == libc::ENXIO,
            seek_hole_eof_enxio = heof == -1 && heof_err == libc::ENXIO,
            seek_data_past_eof_enxio = dpast == -1 && dpast_err == libc::ENXIO,
            seek_hole_past_eof_enxio = hpast == -1 && hpast_err == libc::ENXIO,
            seek_data_negative_fails = dneg == -1,
            seek_data_negative_errno = dneg_err,
            seek_hole_negative_fails = hneg == -1,
            seek_hole_negative_errno = hneg_err,
            pipe_seek_data_espipe = pdata == -1 && pdata_err == libc::ESPIPE,
            pipe_seek_hole_espipe = phole == -1 && phole_err == libc::ESPIPE,
        );
        for (offset, truncate_rc, write_rc, sync_rc, data, data_errno, hole, hole_errno) in
            cycle_results
        {
            println!("seek_cycle_{offset}_truncate_rc={truncate_rc}");
            println!("seek_cycle_{offset}_write_rc={write_rc}");
            println!("seek_cycle_{offset}_sync_rc={sync_rc}");
            println!("seek_cycle_{offset}_data={data}");
            println!("seek_cycle_{offset}_data_errno={data_errno}");
            println!("seek_cycle_{offset}_hole={hole}");
            println!("seek_cycle_{offset}_hole_errno={hole_errno}");
        }
    }
}

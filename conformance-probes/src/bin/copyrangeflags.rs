//! copy_file_range(2) flags and offset semantics probe.
//!
//! Covers:
//! - Nonzero flags rejection (copy_file_range requires flags == 0; nonzero -> -1/EINVAL).
//! - NULL offsets advancing both file descriptor seek positions.
//! - Explicit offset pointers updating the pointed offsets without changing fd seek positions.
//! - Zero-length copy returning 0 without modifying offsets or positions.
//! - Invalid same-file overlapping range returning -1/EINVAL with unmodified offsets.
//!
//! Output is normalized to deterministic booleans only.

use conformance_probes::{arm_alarm_ms, disarm_alarm, errno, report};
use std::ffi::CString;

struct TempFile {
    path: String,
}

impl TempFile {
    fn new(path: String) -> Self {
        if let Ok(c) = CString::new(path.as_bytes()) {
            let _ = unsafe { libc::unlink(c.as_ptr()) };
        }
        Self { path }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Ok(c) = CString::new(self.path.as_bytes()) {
            let _ = unsafe { libc::unlink(c.as_ptr()) };
        }
    }
}

unsafe fn create_file_with_data(path: &str, data: &[u8]) -> i32 {
    let Ok(c) = CString::new(path) else {
        return -1;
    };
    let fd = libc::open(
        c.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    );
    if fd < 0 {
        return -1;
    }
    let n = libc::write(fd, data.as_ptr() as *const libc::c_void, data.len());
    if n != data.len() as isize {
        libc::close(fd);
        return -1;
    }
    libc::lseek(fd, 0, libc::SEEK_SET);
    fd
}

unsafe fn read_at(fd: i32, offset: libc::off_t, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let n = libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, len, offset);
    if n == len as isize {
        buf
    } else {
        Vec::new()
    }
}

fn main() {
    unsafe {
        // Probe-local 5-second upper-bound alarm.
        arm_alarm_ms(5000);

        let tmp_dir = CString::new("/tmp").unwrap();
        libc::mkdir(tmp_dir.as_ptr(), 0o777);

        let pid = libc::getpid();
        let src_path = format!("/tmp/cr_test_src_{pid}.tmp");
        let dst_path = format!("/tmp/cr_test_dst_{pid}.tmp");
        let same_path = format!("/tmp/cr_test_same_{pid}.tmp");

        let _clean_src = TempFile::new(src_path.clone());
        let _clean_dst = TempFile::new(dst_path.clone());
        let _clean_same = TempFile::new(same_path.clone());

        let seed_data: Vec<u8> = (0..64).map(|i| (b'A' + (i % 26)) as u8).collect();

        let src_fd = create_file_with_data(&src_path, &seed_data);
        let dst_fd = create_file_with_data(&dst_path, &[0u8; 64]);
        let same_fd = create_file_with_data(&same_path, &seed_data);

        if src_fd < 0 || dst_fd < 0 || same_fd < 0 {
            report!(
                nonzero_flags_einval = false,
                null_offsets_advance = false,
                explicit_offsets_update = false,
                zero_length_noop = false,
                same_file_overlap_einval = false,
            );
            if src_fd >= 0 {
                libc::close(src_fd);
            }
            if dst_fd >= 0 {
                libc::close(dst_fd);
            }
            if same_fd >= 0 {
                libc::close(same_fd);
            }
            disarm_alarm();
            return;
        }

        // 1. Nonzero flags rejection: flags != 0 must return -1 with EINVAL.
        let r_flag1 = libc::copy_file_range(
            src_fd,
            core::ptr::null_mut(),
            dst_fd,
            core::ptr::null_mut(),
            8,
            1,
        );
        let err_flag1 = errno();
        let r_flag_high = libc::copy_file_range(
            src_fd,
            core::ptr::null_mut(),
            dst_fd,
            core::ptr::null_mut(),
            8,
            0x1000,
        );
        let err_flag_high = errno();
        let r_flag_max = libc::copy_file_range(
            src_fd,
            core::ptr::null_mut(),
            dst_fd,
            core::ptr::null_mut(),
            8,
            u32::MAX,
        );
        let err_flag_max = errno();

        let nonzero_flags_einval = (r_flag1 == -1 && err_flag1 == libc::EINVAL)
            && (r_flag_high == -1 && err_flag_high == libc::EINVAL)
            && (r_flag_max == -1 && err_flag_max == libc::EINVAL);

        // 2. Zero-length behavior: len == 0 returns 0 without modifying offsets or positions.
        libc::lseek(src_fd, 4, libc::SEEK_SET);
        libc::lseek(dst_fd, 8, libc::SEEK_SET);
        let mut off_in_zero: libc::off_t = 12;
        let mut off_out_zero: libc::off_t = 16;

        let r_zero_exp =
            libc::copy_file_range(src_fd, &mut off_in_zero, dst_fd, &mut off_out_zero, 0, 0);
        let pos_src_zero1 = libc::lseek(src_fd, 0, libc::SEEK_CUR);
        let pos_dst_zero1 = libc::lseek(dst_fd, 0, libc::SEEK_CUR);

        let r_zero_null = libc::copy_file_range(
            src_fd,
            core::ptr::null_mut(),
            dst_fd,
            core::ptr::null_mut(),
            0,
            0,
        );
        let pos_src_zero2 = libc::lseek(src_fd, 0, libc::SEEK_CUR);
        let pos_dst_zero2 = libc::lseek(dst_fd, 0, libc::SEEK_CUR);

        let zero_length_noop = r_zero_exp == 0
            && off_in_zero == 12
            && off_out_zero == 16
            && pos_src_zero1 == 4
            && pos_dst_zero1 == 8
            && r_zero_null == 0
            && pos_src_zero2 == 4
            && pos_dst_zero2 == 8;

        // 3. NULL offsets: reads/writes at current fd seek positions and advances both.
        libc::lseek(src_fd, 2, libc::SEEK_SET);
        libc::lseek(dst_fd, 5, libc::SEEK_SET);
        let copy_len = 10;
        let r_null = libc::copy_file_range(
            src_fd,
            core::ptr::null_mut(),
            dst_fd,
            core::ptr::null_mut(),
            copy_len,
            0,
        );
        let pos_src_after = libc::lseek(src_fd, 0, libc::SEEK_CUR);
        let pos_dst_after = libc::lseek(dst_fd, 0, libc::SEEK_CUR);
        let dst_null_bytes = read_at(dst_fd, 5, copy_len);
        let src_null_bytes = &seed_data[2..12];

        let null_offsets_advance = r_null == copy_len as isize
            && pos_src_after == 12
            && pos_dst_after == 15
            && dst_null_bytes == src_null_bytes;

        // 4. Explicit offset pointers: updates pointer values without altering fd seek positions.
        libc::lseek(src_fd, 3, libc::SEEK_SET);
        libc::lseek(dst_fd, 7, libc::SEEK_SET);
        let mut off_in_exp: libc::off_t = 10;
        let mut off_out_exp: libc::off_t = 20;
        let exp_len = 8;
        let r_exp = libc::copy_file_range(
            src_fd,
            &mut off_in_exp,
            dst_fd,
            &mut off_out_exp,
            exp_len,
            0,
        );
        let pos_src_exp_after = libc::lseek(src_fd, 0, libc::SEEK_CUR);
        let pos_dst_exp_after = libc::lseek(dst_fd, 0, libc::SEEK_CUR);
        let dst_exp_bytes = read_at(dst_fd, 20, exp_len);
        let src_exp_bytes = &seed_data[10..18];

        let explicit_offsets_update = r_exp == exp_len as isize
            && off_in_exp == 18
            && off_out_exp == 28
            && pos_src_exp_after == 3
            && pos_dst_exp_after == 7
            && dst_exp_bytes == src_exp_bytes;

        // 5. Invalid same-file overlapping range: returns -1/EINVAL; pointed offsets unchanged.
        let mut same_in: libc::off_t = 4;
        let mut same_out: libc::off_t = 8;
        // Range [4, 16) overlaps with [8, 20) in [8, 16) on the same file.
        let r_overlap = libc::copy_file_range(same_fd, &mut same_in, same_fd, &mut same_out, 12, 0);
        let err_overlap = errno();

        let same_file_overlap_einval =
            r_overlap == -1 && err_overlap == libc::EINVAL && same_in == 4 && same_out == 8;

        report!(
            nonzero_flags_einval = nonzero_flags_einval,
            null_offsets_advance = null_offsets_advance,
            explicit_offsets_update = explicit_offsets_update,
            zero_length_noop = zero_length_noop,
            same_file_overlap_einval = same_file_overlap_einval,
        );

        libc::close(src_fd);
        libc::close(dst_fd);
        libc::close(same_fd);
        disarm_alarm();
    }
}

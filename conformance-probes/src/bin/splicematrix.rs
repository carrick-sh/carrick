//! Splice, vmsplice, tee, and pipe flag, error, and readiness conformance matrix probe.
//!
//! Exercises Linux flag validation, invalid descriptor combinations, offset constraints,
//! and non-blocking transfer semantics across:
//! 1. `pipe2` Flag & Direction Matrix: invalid flags, `O_NONBLOCK | O_CLOEXEC` inheritance,
//!    wrong-direction operations (`read` on write-end, `write` on read-end, `lseek` -> `ESPIPE`),
//!    and empty non-blocking `EAGAIN`.
//! 2. `splice` Error & Constraint Matrix: invalid fds, non-pipe pairs (file-to-file, socket-to-socket),
//!    access mode mismatch, non-null pipe offsets (`ESPIPE`), negative file offsets (`EINVAL`),
//!    `O_APPEND` output rejection (`EINVAL`), invalid flag bits (`EINVAL`), and zero-length handling.
//! 3. `vmsplice` and `tee` Error Matrices: non-pipe targets, bad fds, zero segments, segment count
//!    limits (`UIO_MAXIOV`), invalid flags, duplicate pipe rejection on `tee` (`EINVAL`), and
//!    non-blocking pipe-to-pipe splice with empty-drain `EAGAIN`.
//!
//! Output format: deterministic `key=value` lines diffed against the Linux oracle.
//! Uses unique temp paths with explicit cleanup before and after tests.

use conformance_probes::{errno, report};
use std::ffi::CString;

const SYS_SPLICE: libc::c_long = libc::SYS_splice;
const SYS_VMSPLICE: libc::c_long = libc::SYS_vmsplice;
const SYS_TEE: libc::c_long = libc::SYS_tee;
const SYS_PIPE2: libc::c_long = libc::SYS_pipe2;

const SPLICE_F_MOVE: libc::c_uint = 1;
const SPLICE_F_NONBLOCK: libc::c_uint = 2;
const SPLICE_F_MORE: libc::c_uint = 4;
const SPLICE_F_GIFT: libc::c_uint = 8;

unsafe fn create_temp_file(path: &str, flags: i32) -> i32 {
    let c = CString::new(path).unwrap();
    libc::open(c.as_ptr(), flags, 0o644)
}

unsafe fn unlink_file(path: &str) {
    let c = CString::new(path).unwrap();
    libc::unlink(c.as_ptr());
}

// -----------------------------------------------------------------------------
// 1. pipe2 Flag & Direction Matrix
// -----------------------------------------------------------------------------

unsafe fn test_pipe2_matrix() {
    let mut fds = [-1i32; 2];

    // 1.1 pipe2 with invalid flags -> EINVAL
    let p_inv = libc::syscall(SYS_PIPE2, fds.as_mut_ptr(), 0x1000_0000i32);
    let p_inv_einval = p_inv == -1 && errno() == libc::EINVAL;

    // 1.2 pipe2 with O_NONBLOCK | O_CLOEXEC
    let p_valid = libc::syscall(
        SYS_PIPE2,
        fds.as_mut_ptr(),
        libc::O_NONBLOCK | libc::O_CLOEXEC,
    );
    let p_valid_ok = p_valid == 0;
    let (rd, wr) = (fds[0], fds[1]);

    let (rd_nb, rd_clo, wr_nb, wr_clo) = if p_valid_ok {
        let fl_r = libc::fcntl(rd, libc::F_GETFL);
        let fd_r = libc::fcntl(rd, libc::F_GETFD);
        let fl_w = libc::fcntl(wr, libc::F_GETFL);
        let fd_w = libc::fcntl(wr, libc::F_GETFD);
        (
            (fl_r & libc::O_NONBLOCK) != 0,
            (fd_r & libc::FD_CLOEXEC) != 0,
            (fl_w & libc::O_NONBLOCK) != 0,
            (fd_w & libc::FD_CLOEXEC) != 0,
        )
    } else {
        (false, false, false, false)
    };

    // 1.3 Wrong-direction operations on pipe ends
    let mut buf = [0u8; 4];
    let r_from_wr = libc::read(wr, buf.as_mut_ptr() as *mut libc::c_void, 1);
    let r_from_wr_ebadf = r_from_wr == -1 && errno() == libc::EBADF;

    let w_to_rd = libc::write(rd, buf.as_ptr() as *const libc::c_void, 1);
    let w_to_rd_ebadf = w_to_rd == -1 && errno() == libc::EBADF;

    let seek_rd = libc::lseek(rd, 0, libc::SEEK_SET);
    let seek_rd_espipe = seek_rd == -1 && errno() == libc::ESPIPE;

    let seek_wr = libc::lseek(wr, 0, libc::SEEK_SET);
    let seek_wr_espipe = seek_wr == -1 && errno() == libc::ESPIPE;

    // 1.4 Empty non-blocking pipe read -> EAGAIN
    let r_empty = libc::read(rd, buf.as_mut_ptr() as *mut libc::c_void, 1);
    let r_empty_eagain = r_empty == -1 && errno() == libc::EAGAIN;

    libc::close(rd);
    libc::close(wr);

    report!(
        pipe2_invalid_flags_einval = p_inv_einval,
        pipe2_nonblock_cloexec_flags = p_valid_ok && rd_nb && rd_clo && wr_nb && wr_clo,
        pipe_wrong_direction_ebadf = r_from_wr_ebadf && w_to_rd_ebadf,
        pipe_lseek_espipe = seek_rd_espipe && seek_wr_espipe,
        pipe_empty_nonblock_read_eagain = r_empty_eagain,
    );
}

// -----------------------------------------------------------------------------
// 2. splice Error & Constraint Matrix
// -----------------------------------------------------------------------------

unsafe fn test_splice_matrix() {
    let pid = libc::getpid();
    let file_path1 = format!("/tmp/splicematrix_f1_{pid}.tmp");
    let file_path2 = format!("/tmp/splicematrix_f2_{pid}.tmp");
    let file_path_app = format!("/tmp/splicematrix_app_{pid}.tmp");

    unlink_file(&file_path1);
    unlink_file(&file_path2);
    unlink_file(&file_path_app);

    let f1 = create_temp_file(&file_path1, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC);
    let f2 = create_temp_file(&file_path2, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC);
    let f_app = create_temp_file(
        &file_path_app,
        libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
    );

    let test_data = b"splice_seed_bytes";
    libc::write(
        f1,
        test_data.as_ptr() as *const libc::c_void,
        test_data.len(),
    );
    libc::lseek(f1, 0, libc::SEEK_SET);

    let mut pipe_fds = [-1i32; 2];
    libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_NONBLOCK);
    let (rd, wr) = (pipe_fds[0], pipe_fds[1]);

    // 2.1 Invalid FDs -> EBADF
    let sp_bad_in = libc::syscall(
        SYS_SPLICE,
        -1,
        std::ptr::null_mut::<libc::loff_t>(),
        wr,
        std::ptr::null_mut::<libc::loff_t>(),
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let sp_bad_in_ebadf = sp_bad_in == -1 && errno() == libc::EBADF;

    let sp_bad_out = libc::syscall(
        SYS_SPLICE,
        rd,
        std::ptr::null_mut::<libc::loff_t>(),
        -1,
        std::ptr::null_mut::<libc::loff_t>(),
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let sp_bad_out_ebadf = sp_bad_out == -1 && errno() == libc::EBADF;

    // 2.2 Neither fd is a pipe -> EINVAL
    let mut off_in: libc::loff_t = 0;
    let mut off_out: libc::loff_t = 0;
    let sp_file_file = libc::syscall(
        SYS_SPLICE,
        f1,
        &mut off_in as *mut _,
        f2,
        &mut off_out as *mut _,
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let sp_file_file_einval = sp_file_file == -1 && errno() == libc::EINVAL;

    let mut sv = [-1i32; 2];
    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());
    let sp_sock_sock = libc::syscall(
        SYS_SPLICE,
        sv[0],
        std::ptr::null_mut::<libc::loff_t>(),
        sv[1],
        std::ptr::null_mut::<libc::loff_t>(),
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let sp_sock_sock_einval = sp_sock_sock == -1 && errno() == libc::EINVAL;
    libc::close(sv[0]);
    libc::close(sv[1]);

    // 2.3 Access mode mismatch: reading from write-only fd, writing to read-only fd
    let f_ro = create_temp_file(&file_path1, libc::O_RDONLY);
    let sp_wr_ro = libc::syscall(
        SYS_SPLICE,
        rd,
        std::ptr::null_mut::<libc::loff_t>(),
        f_ro,
        &mut off_out as *mut _,
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let sp_wr_ro_ebadf = sp_wr_ro == -1 && errno() == libc::EBADF;
    libc::close(f_ro);

    let f_wo = create_temp_file(&file_path1, libc::O_WRONLY);
    let sp_rd_wo = libc::syscall(
        SYS_SPLICE,
        f_wo,
        &mut off_in as *mut _,
        wr,
        std::ptr::null_mut::<libc::loff_t>(),
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let sp_rd_wo_ebadf = sp_rd_wo == -1 && errno() == libc::EBADF;
    libc::close(f_wo);

    // 2.4 Non-NULL offset on pipe endpoint -> ESPIPE
    let mut pipe_off: libc::loff_t = 0;
    let sp_pipe_off_in = libc::syscall(
        SYS_SPLICE,
        rd,
        &mut pipe_off as *mut _,
        f2,
        &mut off_out as *mut _,
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let sp_pipe_off_in_espipe = sp_pipe_off_in == -1 && errno() == libc::ESPIPE;

    let sp_pipe_off_out = libc::syscall(
        SYS_SPLICE,
        f1,
        &mut off_in as *mut _,
        wr,
        &mut pipe_off as *mut _,
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let sp_pipe_off_out_espipe = sp_pipe_off_out == -1 && errno() == libc::ESPIPE;

    // 2.5 Negative offset on non-pipe endpoint -> EINVAL
    let mut neg_off: libc::loff_t = -1;
    let sp_neg_off = libc::syscall(
        SYS_SPLICE,
        f1,
        &mut neg_off as *mut _,
        wr,
        std::ptr::null_mut::<libc::loff_t>(),
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let sp_neg_off_einval = sp_neg_off == -1 && errno() == libc::EINVAL;

    // 2.6 Splicing to an O_APPEND file -> EINVAL
    let sp_append = libc::syscall(
        SYS_SPLICE,
        rd,
        std::ptr::null_mut::<libc::loff_t>(),
        f_app,
        std::ptr::null_mut::<libc::loff_t>(),
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let sp_append_einval = sp_append == -1 && errno() == libc::EINVAL;

    // 2.7 Invalid flags -> EINVAL
    let sp_bad_fl = libc::syscall(
        SYS_SPLICE,
        rd,
        std::ptr::null_mut::<libc::loff_t>(),
        f2,
        &mut off_out as *mut _,
        1usize,
        0x1000_0000u32 | SPLICE_F_NONBLOCK,
    );
    let sp_bad_fl_einval = sp_bad_fl == -1 && errno() == libc::EINVAL;

    // 2.8 Zero-length splice with valid flag combinations returns 0
    let sp_zero = libc::syscall(
        SYS_SPLICE,
        rd,
        std::ptr::null_mut::<libc::loff_t>(),
        wr,
        std::ptr::null_mut::<libc::loff_t>(),
        0usize,
        SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_GIFT | SPLICE_F_NONBLOCK,
    );
    let sp_zero_ok = sp_zero == 0;

    libc::close(f1);
    libc::close(f2);
    libc::close(f_app);
    libc::close(rd);
    libc::close(wr);
    unlink_file(&file_path1);
    unlink_file(&file_path2);
    unlink_file(&file_path_app);

    report!(
        splice_invalid_fd_ebadf = sp_bad_in_ebadf && sp_bad_out_ebadf,
        splice_non_pipe_targets_einval = sp_file_file_einval && sp_sock_sock_einval,
        splice_access_mode_mismatch_ebadf = sp_wr_ro_ebadf && sp_rd_wo_ebadf,
        splice_pipe_offset_espipe = sp_pipe_off_in_espipe && sp_pipe_off_out_espipe,
        splice_negative_file_offset_einval = sp_neg_off_einval,
        splice_append_target_einval = sp_append_einval,
        splice_invalid_flags_einval = sp_bad_fl_einval,
        splice_zero_length_success = sp_zero_ok,
    );
}

// -----------------------------------------------------------------------------
// 3. vmsplice & tee Error and Transfer Matrices
// -----------------------------------------------------------------------------

unsafe fn test_vmsplice_and_tee_matrix() {
    let pid = libc::getpid();
    let file_path = format!("/tmp/splicematrix_vm_{pid}.tmp");
    unlink_file(&file_path);
    let f = create_temp_file(&file_path, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC);

    let mut pipe_a = [-1i32; 2];
    let mut pipe_b = [-1i32; 2];
    libc::pipe2(pipe_a.as_mut_ptr(), libc::O_NONBLOCK);
    libc::pipe2(pipe_b.as_mut_ptr(), libc::O_NONBLOCK);
    let (a_rd, a_wr) = (pipe_a[0], pipe_a[1]);
    let (b_rd, b_wr) = (pipe_b[0], pipe_b[1]);

    let mut data = [0x5au8; 16];
    let iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };

    // 3.1 vmsplice error conditions
    // vmsplice on regular file -> EBADF
    let vm_file = libc::syscall(SYS_VMSPLICE, f, &iov as *const _, 1usize, SPLICE_F_NONBLOCK);
    let vm_file_ebadf = vm_file == -1 && errno() == libc::EBADF;

    // vmsplice on bad fd -> EBADF
    let vm_badf = libc::syscall(
        SYS_VMSPLICE,
        -1,
        &iov as *const _,
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let vm_badf_ebadf = vm_badf == -1 && errno() == libc::EBADF;

    // vmsplice with nr_segs = 0 returns 0
    let vm_zero_segs = libc::syscall(
        SYS_VMSPLICE,
        a_wr,
        std::ptr::null::<libc::iovec>(),
        0usize,
        SPLICE_F_NONBLOCK,
    );
    let vm_zero_segs_ok = vm_zero_segs == 0;

    // vmsplice with nr_segs > UIO_MAXIOV (1024) -> EINVAL
    let vm_maxiov = libc::syscall(
        SYS_VMSPLICE,
        a_wr,
        &iov as *const _,
        1025usize,
        SPLICE_F_NONBLOCK,
    );
    let vm_maxiov_einval = vm_maxiov == -1 && errno() == libc::EINVAL;

    // vmsplice with invalid flags -> EINVAL
    let vm_bad_fl = libc::syscall(
        SYS_VMSPLICE,
        a_wr,
        &iov as *const _,
        1usize,
        0x1000_0000u32 | SPLICE_F_NONBLOCK,
    );
    let vm_bad_fl_einval = vm_bad_fl == -1 && errno() == libc::EINVAL;

    // vmsplice to read-end of pipe -> EBADF
    let vm_rd_end = libc::syscall(
        SYS_VMSPLICE,
        a_rd,
        &iov as *const _,
        1usize,
        SPLICE_F_NONBLOCK,
    );
    let vm_rd_end_ebadf = vm_rd_end == -1 && errno() == libc::EBADF;

    // 3.2 tee error conditions
    // tee on non-pipe fds -> EINVAL
    let tee_files = libc::syscall(SYS_TEE, f, f, 1usize, SPLICE_F_NONBLOCK);
    let tee_files_einval = tee_files == -1 && errno() == libc::EINVAL;

    let tee_one_file = libc::syscall(SYS_TEE, f, b_wr, 1usize, SPLICE_F_NONBLOCK);
    let tee_one_file_einval = tee_one_file == -1 && errno() == libc::EINVAL;

    // tee with same pipe (a_rd to a_wr) -> EINVAL
    let tee_same = libc::syscall(SYS_TEE, a_rd, a_wr, 1usize, SPLICE_F_NONBLOCK);
    let tee_same_einval = tee_same == -1 && errno() == libc::EINVAL;

    // tee with invalid flags -> EINVAL
    let tee_bad_fl = libc::syscall(
        SYS_TEE,
        a_rd,
        b_wr,
        1usize,
        0x1000_0000u32 | SPLICE_F_NONBLOCK,
    );
    let tee_bad_fl_einval = tee_bad_fl == -1 && errno() == libc::EINVAL;

    // tee zero length returns 0
    let tee_zero = libc::syscall(SYS_TEE, a_rd, b_wr, 0usize, SPLICE_F_NONBLOCK);
    let tee_zero_ok = tee_zero == 0;

    // 3.3 Non-blocking pipe-to-pipe splice and drain validation
    let msg = b"splice_matrix_msg!";
    libc::write(a_wr, msg.as_ptr() as *const libc::c_void, msg.len());

    let sp_xfer = libc::syscall(
        SYS_SPLICE,
        a_rd,
        std::ptr::null_mut::<libc::loff_t>(),
        b_wr,
        std::ptr::null_mut::<libc::loff_t>(),
        msg.len(),
        SPLICE_F_NONBLOCK,
    );
    let sp_xfer_count = sp_xfer == msg.len() as i64;

    let mut recv_buf = [0u8; 32];
    let n_read = libc::read(
        b_rd,
        recv_buf.as_mut_ptr() as *mut libc::c_void,
        recv_buf.len(),
    );
    let recv_match = n_read == msg.len() as isize && &recv_buf[..msg.len()] == msg;

    // Empty pipe splice with SPLICE_F_NONBLOCK -> EAGAIN
    let sp_empty = libc::syscall(
        SYS_SPLICE,
        a_rd,
        std::ptr::null_mut::<libc::loff_t>(),
        b_wr,
        std::ptr::null_mut::<libc::loff_t>(),
        msg.len(),
        SPLICE_F_NONBLOCK,
    );
    let sp_empty_eagain = sp_empty == -1 && errno() == libc::EAGAIN;

    libc::close(f);
    libc::close(a_rd);
    libc::close(a_wr);
    libc::close(b_rd);
    libc::close(b_wr);
    unlink_file(&file_path);

    report!(
        vmsplice_error_matrix = vm_file_ebadf
            && vm_badf_ebadf
            && vm_zero_segs_ok
            && vm_maxiov_einval
            && vm_bad_fl_einval
            && vm_rd_end_ebadf,
        tee_error_matrix = tee_files_einval
            && tee_one_file_einval
            && tee_same_einval
            && tee_bad_fl_einval
            && tee_zero_ok,
        splice_pipe_to_pipe_nonblock_and_eagain = sp_xfer_count && recv_match && sp_empty_eagain,
    );
}

fn main() {
    unsafe {
        test_pipe2_matrix();
        test_splice_matrix();
        test_vmsplice_and_tee_matrix();
    }
}

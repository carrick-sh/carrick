//! Minimal legacy Linux AIO syscall contract.
//!
//! LTP's `io_*` cases need setup/teardown, validation, and submit
//! counts/access errors. This probe keeps that reduced shape separate from the
//! larger LTP harness.

use conformance_probes::{errno, report};

const SYS_IO_SETUP: libc::c_long = 0;
const SYS_IO_DESTROY: libc::c_long = 1;
const SYS_IO_SUBMIT: libc::c_long = 2;
const SYS_IO_CANCEL: libc::c_long = 3;
const SYS_IO_GETEVENTS: libc::c_long = 4;

const IOCB_CMD_PREAD: u16 = 0;
const IOCB_CMD_PWRITE: u16 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct Iocb {
    data: u64,
    key: u32,
    rw_flags: u32,
    opcode: u16,
    reqprio: i16,
    fd: u32,
    buf: u64,
    nbytes: u64,
    offset: i64,
    reserved2: u64,
    flags: u32,
    resfd: u32,
}

unsafe fn io_setup(nr: u64, ctx: *mut u64) -> libc::c_long {
    unsafe { libc::syscall(SYS_IO_SETUP, nr, ctx) }
}

unsafe fn io_destroy(ctx: u64) -> libc::c_long {
    unsafe { libc::syscall(SYS_IO_DESTROY, ctx) }
}

unsafe fn io_submit(ctx: u64, nr: i64, iocbpp: *mut *mut Iocb) -> libc::c_long {
    unsafe { libc::syscall(SYS_IO_SUBMIT, ctx, nr, iocbpp) }
}

unsafe fn io_cancel(ctx: u64, iocb: *mut Iocb, event: *mut u8) -> libc::c_long {
    unsafe { libc::syscall(SYS_IO_CANCEL, ctx, iocb, event) }
}

unsafe fn io_getevents(ctx: u64) -> libc::c_long {
    unsafe { libc::syscall(SYS_IO_GETEVENTS, ctx, 0, 0, core::ptr::null_mut::<u8>(), 0usize) }
}

fn syscall_errno(rc: libc::c_long) -> i32 {
    if rc == 0 { 0 } else { errno() }
}

fn main() {
    unsafe {
        let null_ctx_errno = syscall_errno(io_setup(1, core::ptr::null_mut()));

        let mut nonzero = 7u64;
        let nonzero_ctx_errno = syscall_errno(io_setup(1, &mut nonzero));

        let mut zero_ctx = 0u64;
        let zero_events_errno = syscall_errno(io_setup(0, &mut zero_ctx));

        let mut huge_ctx = 0u64;
        let huge_errno = syscall_errno(io_setup(u64::MAX - 1, &mut huge_ctx));

        let mut u32_neg_ctx = 0u64;
        let u32_neg_events_errno = syscall_errno(io_setup(u32::MAX as u64, &mut u32_neg_ctx));

        let mut over_aio_max_ctx = 0u64;
        let over_aio_max_errno = syscall_errno(io_setup(65_537, &mut over_aio_max_ctx));

        let mut ctx = 0u64;
        let setup_errno = syscall_errno(io_setup(4, &mut ctx));
        let ctx_nonzero = ctx != 0;

        let invalid_ctx = ctx.wrapping_add(0x1000);
        let destroy_invalid_errno = syscall_errno(io_destroy(invalid_ctx));
        let getevents_invalid_errno = syscall_errno(io_getevents(invalid_ctx));
        let cancel_null_errno =
            syscall_errno(io_cancel(ctx, core::ptr::null_mut(), core::ptr::null_mut()));
        let cancel_invalid_null_errno = syscall_errno(io_cancel(
            invalid_ctx,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        ));

        let aio_max_nr_fd = libc::open(c"/proc/sys/fs/aio-max-nr".as_ptr(), libc::O_RDONLY);
        let mut aio_max_nr_buf = [0u8; 32];
        let aio_max_nr_readable = if aio_max_nr_fd >= 0 {
            let n = libc::read(
                aio_max_nr_fd,
                aio_max_nr_buf.as_mut_ptr().cast(),
                aio_max_nr_buf.len(),
            );
            let _ = libc::close(aio_max_nr_fd);
            n > 0
        } else {
            false
        };

        libc::mkdir(c"/tmp".as_ptr(), 0o777);
        let rdonly =
            libc::open(c"/tmp/legacyaio_rd".as_ptr(), libc::O_RDONLY | libc::O_CREAT, 0o600);
        let wronly =
            libc::open(c"/tmp/legacyaio_wr".as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o600);
        let rdwr = libc::open(c"/tmp/legacyaio_rw".as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600);
        let fds_ok = rdonly >= 0 && wronly >= 0 && rdwr >= 0;

        let mut byte = 0u8;
        let mut read_iocb = Iocb {
            data: 0,
            key: 0,
            rw_flags: 0,
            opcode: IOCB_CMD_PREAD,
            reqprio: 0,
            fd: rdwr as u32,
            buf: (&mut byte as *mut u8) as u64,
            nbytes: 0,
            offset: 0,
            reserved2: 0,
            flags: 0,
            resfd: 0,
        };
        let mut write_iocb = read_iocb;
        write_iocb.opcode = IOCB_CMD_PWRITE;

        let mut read_ptr = &mut read_iocb as *mut Iocb;
        let submit_one = io_submit(ctx, 1, &mut read_ptr);
        let mut read_ptr = &mut read_iocb as *mut Iocb;
        let submit_zero = io_submit(ctx, 0, &mut read_ptr);
        let mut read_ptr = &mut read_iocb as *mut Iocb;
        let invalid_nr_errno = syscall_errno(io_submit(ctx, -1, &mut read_ptr));
        let invalid_iocbpp_errno = syscall_errno(io_submit(ctx, 1, 1usize as *mut *mut Iocb));
        let mut null_iocb: *mut Iocb = core::ptr::null_mut();
        let null_iocb_errno = syscall_errno(io_submit(ctx, 1, &mut null_iocb));

        read_iocb.fd = (-1i32) as u32;
        let mut read_ptr = &mut read_iocb as *mut Iocb;
        let badfd_errno = syscall_errno(io_submit(ctx, 1, &mut read_ptr));
        read_iocb.fd = wronly as u32;
        let mut read_ptr = &mut read_iocb as *mut Iocb;
        let read_wronly_errno = syscall_errno(io_submit(ctx, 1, &mut read_ptr));
        write_iocb.fd = rdonly as u32;
        let mut write_ptr = &mut write_iocb as *mut Iocb;
        let write_rdonly_errno = syscall_errno(io_submit(ctx, 1, &mut write_ptr));

        let destroy_errno = syscall_errno(io_destroy(ctx));
        let _ = libc::close(rdonly);
        let _ = libc::close(wronly);
        let _ = libc::close(rdwr);

        report!(
            null_ctx_errno = null_ctx_errno,
            nonzero_ctx_errno = nonzero_ctx_errno,
            zero_events_errno = zero_events_errno,
            huge_errno = huge_errno,
            u32_neg_events_errno = u32_neg_events_errno,
            over_aio_max_errno = over_aio_max_errno,
            setup_errno = setup_errno,
            ctx_nonzero = ctx_nonzero,
            destroy_invalid_errno = destroy_invalid_errno,
            getevents_invalid_errno = getevents_invalid_errno,
            cancel_null_errno = cancel_null_errno,
            cancel_invalid_null_errno = cancel_invalid_null_errno,
            aio_max_nr_readable = aio_max_nr_readable,
            fds_ok = fds_ok,
            submit_one = submit_one,
            submit_zero = submit_zero,
            invalid_nr_errno = invalid_nr_errno,
            invalid_iocbpp_errno = invalid_iocbpp_errno,
            null_iocb_errno = null_iocb_errno,
            badfd_errno = badfd_errno,
            read_wronly_errno = read_wronly_errno,
            write_rdonly_errno = write_rdonly_errno,
            destroy_errno = destroy_errno,
        );
    }
}

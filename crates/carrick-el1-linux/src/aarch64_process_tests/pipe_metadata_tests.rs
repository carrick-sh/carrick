//! #1901: metadata must follow pipe2 into the ring descriptor namespace.
use carrick_abi::*;
use carrick_personality_linux::crossing::nr;
use carrick_test_support::GuestUserBuffer;

#[derive(Clone, Copy)]
pub(super) enum Case {
    Stat,
    EmptyPath,
    Flags,
    DescriptorFlags,
    Duplicate,
    DuplicateCloexec,
    PipeSize,
    PipeShrinkBusy,
    SubprocessPattern,
    Readable,
    Nonblocking,
    IoctlCloexec,
    ExecCloexec,
    Terminal,
    Seek,
    Dup,
    Dup3,
    Close,
}

macro_rules! witness {
    ($root:ident, $child:ident, $case:ident) => {
        #[test]
        fn $root() {
            super::native_descriptor_metadata_witness(
                None,
                true,
                false,
                false,
                false,
                false,
                Some(Case::$case),
            );
        }
        #[test]
        fn $child() {
            super::native_descriptor_metadata_witness(
                None,
                false,
                false,
                false,
                false,
                false,
                Some(Case::$case),
            );
        }
    };
}

witness!(
    serial_host_pipe_metadata_root_stat,
    serial_host_pipe_metadata_child_stat,
    Stat
);
witness!(
    serial_host_pipe_metadata_root_empty_path,
    serial_host_pipe_metadata_child_empty_path,
    EmptyPath
);
witness!(
    serial_host_pipe_metadata_root_flags,
    serial_host_pipe_metadata_child_flags,
    Flags
);
witness!(
    serial_host_pipe_metadata_root_fdflags,
    serial_host_pipe_metadata_child_fdflags,
    DescriptorFlags
);
witness!(
    serial_host_pipe_metadata_root_dupfd,
    serial_host_pipe_metadata_child_dupfd,
    Duplicate
);
witness!(
    serial_host_pipe_metadata_root_dupfd_cloexec,
    serial_host_pipe_metadata_child_dupfd_cloexec,
    DuplicateCloexec
);
witness!(
    serial_host_pipe_metadata_root_size,
    serial_host_pipe_metadata_child_size,
    PipeSize
);
witness!(
    serial_host_pipe_metadata_root_shrink_busy,
    serial_host_pipe_metadata_child_shrink_busy,
    PipeShrinkBusy
);
witness!(
    serial_host_pipe_metadata_root_subprocess,
    serial_host_pipe_metadata_child_subprocess,
    SubprocessPattern
);
witness!(
    serial_host_pipe_metadata_root_fionread,
    serial_host_pipe_metadata_child_fionread,
    Readable
);
witness!(
    serial_host_pipe_metadata_root_fionbio,
    serial_host_pipe_metadata_child_fionbio,
    Nonblocking
);
witness!(
    serial_host_pipe_metadata_root_terminal,
    serial_host_pipe_metadata_child_terminal,
    Terminal
);
witness!(
    serial_host_pipe_metadata_root_seek,
    serial_host_pipe_metadata_child_seek,
    Seek
);
witness!(
    serial_host_pipe_metadata_root_dup,
    serial_host_pipe_metadata_child_dup,
    Dup
);
witness!(
    serial_host_pipe_metadata_root_dup3,
    serial_host_pipe_metadata_child_dup3,
    Dup3
);
witness!(
    serial_host_pipe_metadata_root_close,
    serial_host_pipe_metadata_child_close,
    Close
);

macro_rules! exec_witness {
    ($name:ident, $case:ident) => {
        #[test]
        fn $name() {
            super::native_exec_pipe_tests::metadata_successor(Case::$case);
        }
    };
}

witness!(
    serial_host_pipe_metadata_root_ioctl_cloexec,
    serial_host_pipe_metadata_child_ioctl_cloexec,
    IoctlCloexec
);
exec_witness!(serial_host_pipe_metadata_exec_stat, Stat);
exec_witness!(serial_host_pipe_metadata_exec_empty_path, EmptyPath);
exec_witness!(serial_host_pipe_metadata_exec_flags, Flags);
exec_witness!(
    serial_host_pipe_metadata_exec_descriptor_flags,
    DescriptorFlags
);
exec_witness!(serial_host_pipe_metadata_exec_duplicate, Duplicate);
exec_witness!(
    serial_host_pipe_metadata_exec_duplicate_cloexec,
    DuplicateCloexec
);
exec_witness!(serial_host_pipe_metadata_exec_pipe_size, PipeSize);
exec_witness!(serial_host_pipe_metadata_exec_shrink_busy, PipeShrinkBusy);
exec_witness!(serial_host_pipe_metadata_exec_subprocess, SubprocessPattern);
exec_witness!(serial_host_pipe_metadata_exec_readable, Readable);
exec_witness!(serial_host_pipe_metadata_exec_nonblocking, Nonblocking);
exec_witness!(serial_host_pipe_metadata_exec_ioctl_cloexec, IoctlCloexec);
exec_witness!(serial_host_pipe_metadata_exec_terminal, Terminal);
exec_witness!(serial_host_pipe_metadata_exec_seek, Seek);
exec_witness!(serial_host_pipe_metadata_exec_dup, Dup);
exec_witness!(serial_host_pipe_metadata_exec_dup3, Dup3);
exec_witness!(serial_host_pipe_metadata_exec_close, Close);

exec_witness!(
    serial_host_pipe_metadata_exec_inherited_cloexec,
    ExecCloexec
);

pub(super) fn exercise(case: Case, mut call: impl FnMut(u64, [u64; 4]) -> i64) {
    let output = GuestUserBuffer::zeroed(8);
    assert_eq!(
        call(nr::PIPE2.raw(), [output.arg(), LINUX_O_NONBLOCK, 0, 0]),
        0
    );
    let fds: Vec<_> = output
        .as_bytes()
        .chunks_exact(4)
        .map(|bytes| u32::from_ne_bytes(bytes.try_into().unwrap()) as u64)
        .collect();
    let (read, write) = (fds[0], fds[1]);
    let data = GuestUserBuffer::from_bytes(b"hi\n");
    match case {
        Case::Stat | Case::EmptyPath => {
            let empty = GuestUserBuffer::from_bytes(b"\0");
            let mut stat = |fd| {
                let out = GuestUserBuffer::zeroed(core::mem::size_of::<LinuxStat>());
                let result = if matches!(case, Case::Stat) {
                    call(nr::FSTAT.raw(), [fd, out.arg(), 0, 0])
                } else {
                    call(
                        nr::NEWFSTATAT.raw(),
                        [fd, empty.arg(), out.arg(), LINUX_AT_EMPTY_PATH],
                    )
                };
                assert_eq!(result, 0, "stat errno number: {}", -result);
                let value =
                    <LinuxStat as zerocopy::FromBytes>::read_from_bytes(out.as_bytes()).unwrap();
                assert_eq!(value.st_mode & LINUX_S_IFMT, LINUX_S_IFIFO);
                assert_eq!(value.st_mode & 0o777, 0o600);
                assert_eq!({ value.st_blksize }, 4096);
                (value.st_dev, value.st_ino)
            };
            let identity = stat(read);
            assert_eq!(identity, stat(write), "both pipe ends share an inode");
            assert_eq!(identity, stat(read), "inode survives repeated queries");
            // fd 3 belongs to a distinct inherited pipe while both children live.
            assert_ne!(
                identity,
                stat(3),
                "two live pipes must have distinct identities"
            );
        }
        Case::Flags => {
            assert_eq!(
                call(nr::FCNTL.raw(), [read, LINUX_F_GETFL, 0, 0]),
                LINUX_O_NONBLOCK as i64
            );
            assert_eq!(
                call(nr::FCNTL.raw(), [write, LINUX_F_SETFL, LINUX_O_NONBLOCK, 0]),
                0
            );
            assert_eq!(
                call(nr::FCNTL.raw(), [write, LINUX_F_GETFL, 0, 0]),
                (LINUX_O_WRONLY | LINUX_O_NONBLOCK) as i64
            );
            assert_eq!(call(nr::FCNTL.raw(), [read, LINUX_F_SETFL, 0, 0]), 0);
            assert_eq!(call(nr::FCNTL.raw(), [read, LINUX_F_GETFL, 0, 0]), 0);
        }
        Case::DescriptorFlags => {
            assert_eq!(
                call(nr::FCNTL.raw(), [read, LINUX_F_SETFD, LINUX_FD_CLOEXEC, 0]),
                0
            );
            assert_eq!(call(nr::FCNTL.raw(), [read, LINUX_F_GETFD, 0, 0]), 1);
            assert_eq!(call(nr::FCNTL.raw(), [write, LINUX_F_GETFD, 0, 0]), 0);
        }
        Case::Duplicate | Case::DuplicateCloexec | Case::Dup | Case::Dup3 => {
            let copy = match case {
                Case::Dup => call(nr::DUP.raw(), [write, 0, 0, 0]),
                Case::Dup3 => call(nr::DUP3.raw(), [write, 31, LINUX_O_CLOEXEC, 0]),
                _ => call(
                    nr::FCNTL.raw(),
                    [
                        write,
                        if matches!(case, Case::Duplicate) {
                            LINUX_F_DUPFD
                        } else {
                            LINUX_F_DUPFD_CLOEXEC
                        },
                        31,
                        0,
                    ],
                ),
            };
            assert!(copy >= 0, "dup errno number: {}", -copy);
            let copy = copy as u64;
            assert_eq!(
                call(nr::FCNTL.raw(), [copy, LINUX_F_GETFD, 0, 0]),
                i64::from(matches!(case, Case::DuplicateCloexec | Case::Dup3))
            );
            assert_eq!(
                call(nr::FCNTL.raw(), [copy, LINUX_F_SETFL, LINUX_O_NONBLOCK, 0]),
                0
            );
            assert_eq!(
                call(nr::FCNTL.raw(), [write, LINUX_F_GETFL, 0, 0]),
                (LINUX_O_WRONLY | LINUX_O_NONBLOCK) as i64
            );
            assert_eq!(call(nr::WRITE.raw(), [copy, data.arg(), 3, 0]), 3);
            assert_eq!(call(nr::CLOSE.raw(), [copy, 0, 0, 0]), 0);
        }
        Case::PipeSize => {
            assert_eq!(
                call(nr::FCNTL.raw(), [read, LINUX_F_GETPIPE_SZ, 0, 0]),
                65536
            );
            assert_eq!(
                call(nr::FCNTL.raw(), [write, LINUX_F_SETPIPE_SZ, 4096, 0]),
                4096
            );
            assert_eq!(
                call(nr::FCNTL.raw(), [read, LINUX_F_GETPIPE_SZ, 0, 0]),
                4096
            );
        }
        Case::PipeShrinkBusy => {
            let payload = GuestUserBuffer::zeroed(4097);
            assert_eq!(call(nr::WRITE.raw(), [write, payload.arg(), 4097, 0]), 4097);
            assert_eq!(
                call(nr::FCNTL.raw(), [read, LINUX_F_SETPIPE_SZ, 4096, 0]),
                -16,
                "shrinking below buffered bytes must return EBUSY(16)"
            );
            assert_eq!(
                call(nr::FCNTL.raw(), [write, LINUX_F_GETPIPE_SZ, 0, 0]),
                65536,
                "a refused shrink preserves capacity"
            );
            let received = GuestUserBuffer::zeroed(4097);
            assert_eq!(call(nr::READ.raw(), [read, received.arg(), 4097, 0]), 4097);
            assert_eq!(
                call(nr::FCNTL.raw(), [write, LINUX_F_SETPIPE_SZ, 4096, 0]),
                4096,
                "the same shrink succeeds after draining"
            );
        }
        Case::SubprocessPattern => {
            // CPython probes a new pipe before using it. Repeat those probes
            // on fd 3, inherited from the still-live parent across fork/exec.
            for fd in [read, 3] {
                let stat = GuestUserBuffer::zeroed(core::mem::size_of::<LinuxStat>());
                assert_eq!(call(nr::FSTAT.raw(), [fd, stat.arg(), 0, 0]), 0);
                let stat =
                    <LinuxStat as zerocopy::FromBytes>::read_from_bytes(stat.as_bytes()).unwrap();
                assert_eq!(stat.st_mode & LINUX_S_IFMT, LINUX_S_IFIFO);
                let count = GuestUserBuffer::from_value(-1i32);
                assert_eq!(
                    call(nr::IOCTL.raw(), [fd, LINUX_FIONREAD, count.arg(), 0]),
                    0
                );
                assert_eq!(i32::from_ne_bytes(count.as_bytes().try_into().unwrap()), 0);
                assert_eq!(call(nr::IOCTL.raw(), [fd, LINUX_TCGETS, 0, 0]), -25);
                assert_eq!(call(nr::LSEEK.raw(), [fd, 0, 0, 0]), -29);
                let flags = call(nr::FCNTL.raw(), [fd, LINUX_F_GETFL, 0, 0]);
                assert!(flags >= 0, "F_GETFL errno number: {}", -flags);
                assert_eq!(
                    call(
                        nr::FCNTL.raw(),
                        [fd, LINUX_F_SETFL, flags as u64 | LINUX_O_NONBLOCK, 0]
                    ),
                    0
                );
                assert_eq!(
                    call(nr::FCNTL.raw(), [fd, LINUX_F_GETFL, 0, 0]),
                    flags | LINUX_O_NONBLOCK as i64
                );
                assert_eq!(call(nr::FCNTL.raw(), [fd, LINUX_F_GETPIPE_SZ, 0, 0]), 65536);
            }
        }
        Case::Readable => {
            assert_eq!(call(nr::WRITE.raw(), [write, data.arg(), 3, 0]), 3);
            let count = GuestUserBuffer::zeroed(4);
            for fd in [read, write] {
                assert_eq!(
                    call(nr::IOCTL.raw(), [fd, LINUX_FIONREAD, count.arg(), 0]),
                    0
                );
                assert_eq!(i32::from_ne_bytes(count.as_bytes().try_into().unwrap()), 3);
            }
        }
        Case::Nonblocking => {
            let off = GuestUserBuffer::from_value(0i32);
            assert_eq!(
                call(nr::IOCTL.raw(), [read, LINUX_FIONBIO, off.arg(), 0]),
                0
            );
            assert_eq!(call(nr::FCNTL.raw(), [read, LINUX_F_GETFL, 0, 0]), 0);
        }
        Case::ExecCloexec => {
            assert_eq!(
                call(nr::FCNTL.raw(), [6, LINUX_F_GETFD, 0, 0]),
                -9,
                "exec must remove the inherited CLOEXEC alias"
            );
        }
        Case::IoctlCloexec => {
            // Linux asm-generic ioctl numbers, shared by ARM64 and x86_64.
            assert_eq!(call(nr::IOCTL.raw(), [read, 0x5451, 0, 0]), 0); // FIOCLEX
            assert_eq!(call(nr::FCNTL.raw(), [read, LINUX_F_GETFD, 0, 0]), 1);
            assert_eq!(call(nr::FCNTL.raw(), [write, LINUX_F_GETFD, 0, 0]), 0);
            assert_eq!(call(nr::IOCTL.raw(), [read, 0x5450, 0, 0]), 0); // FIONCLEX
            assert_eq!(call(nr::FCNTL.raw(), [read, LINUX_F_GETFD, 0, 0]), 0);
        }
        Case::Terminal => assert_eq!(call(nr::IOCTL.raw(), [read, LINUX_TCGETS, 0, 0]), -25),
        Case::Seek => assert_eq!(call(nr::LSEEK.raw(), [read, 0, 0, 0]), -29),
        Case::Close => {
            assert_eq!(call(nr::CLOSE.raw(), [write, 0, 0, 0]), 0);
            assert_eq!(call(nr::CLOSE.raw(), [write, 0, 0, 0]), -9);
            let byte = GuestUserBuffer::zeroed(1);
            assert_eq!(
                call(nr::READ.raw(), [read, byte.arg(), 1, 0]),
                0,
                "last writer close publishes EOF"
            );
            return;
        }
    }
    assert_eq!(call(nr::CLOSE.raw(), [read, 0, 0, 0]), 0);
    assert_eq!(call(nr::CLOSE.raw(), [write, 0, 0, 0]), 0);
}

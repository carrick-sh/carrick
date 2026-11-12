//! The one fd-operand resolver for a host crossing (#2157 B0 T2).
//!
//! A crossing's descriptor operand is declared once, on its
//! [`OperandSpec`](carrick_personality_linux::dispatch::OperandSpec), and
//! resolved here against the caller's ring descriptor tables. Every venue asks
//! the same resolver; only applying a verdict to its frame registers is the
//! venue's mechanic. Enabling a crossing for an ISA is then a table flip.

use carrick_el1_abi::{
    DelegatedOpenFile, FdMapSlot, FdSlotKind, HostObjectBinding, fd_map_lookup_kind,
};
use carrick_personality_linux::crossing::{AllowedHostCrossing, HostCrossingSet};
use carrick_personality_linux::dispatch::{FdOperand, HostCrossingPreflight};
use carrick_personality_linux::native_host_file::NativeDescriptor;
use carrick_syscall_abi::CanonicalNr;

/// What a guest descriptor names, for a host crossing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdOperandClass {
    /// A ring description bound to a host object (a stdio route or an
    /// explicit host fd).
    HostObject(HostObjectBinding),
    /// No ring description: the number is the root's host task's own
    /// descriptor, which crosses unchanged.
    HostBacked,
    /// The ring's own object (pipe, eventfd, epoll, in-zone file, inotify, or
    /// a host file held by the ring's descriptor table).
    InZone,
    /// No open descriptor with this number.
    Absent,
}

/// How a crossing's operands leave the ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossingOperand {
    /// Cross unchanged.
    Pass,
    /// Cross with argument `index` replaced by the host object's fd.
    Rewrite { index: u8, host_fd: i32 },
    /// Cross as a host-object write of `binding`.
    ObjectWrite(HostObjectBinding),
    /// Never forwarded: answered in ring with a counted ENOSYS.
    InRing,
    /// Answered with EBADF.
    BadFd,
}

impl CrossingOperand {
    /// The shared dispatch owner's verdict; the venue keeps `self` to apply
    /// a crossing's register rewrite on the Forward route.
    pub const fn preflight(self) -> HostCrossingPreflight {
        match self {
            Self::Pass | Self::Rewrite { .. } | Self::ObjectWrite(_) => {
                HostCrossingPreflight::Proceed
            }
            Self::InRing => HostCrossingPreflight::RefusedInRing,
            Self::BadFd => HostCrossingPreflight::BadFd,
        }
    }
}

/// Classify `fd` in the caller's ring tables. `ring` resolves it in the
/// caller's fd-core namespace when one is published. A description the ring
/// holds, in-zone or backed by a host file the carrier opened for a staged
/// `openat`, is the ring's: its number names nothing in the root's host task,
/// so crossing with it unchanged would reach whatever that task has under the
/// number. An absent fd-core entry says nothing about a descriptor the root's
/// host task opened.
pub fn classify_fd_operand(
    fd_map: &[FdMapSlot],
    opens: &[DelegatedOpenFile],
    file_table: u64,
    fd: i32,
    ring: impl FnOnce(i32) -> Option<NativeDescriptor>,
) -> FdOperandClass {
    if fd < 0 {
        return FdOperandClass::Absent;
    }
    match fd_map_lookup_kind(fd_map, file_table, fd) {
        Some((FdSlotKind::File(handle), _)) => handle
            .checked_sub(1)
            .and_then(|index| opens.get(index as usize))
            .map_or(FdOperandClass::Absent, |open| {
                open.host_object()
                    .map_or(FdOperandClass::InZone, FdOperandClass::HostObject)
            }),
        Some((FdSlotKind::Inotify(_), _)) => FdOperandClass::InZone,
        None if matches!(
            ring(fd),
            Some(NativeDescriptor::InZone(_) | NativeDescriptor::HostBacked { .. })
        ) =>
        {
            FdOperandClass::InZone
        }
        // The ring admits stdio for every table it serves, so a missing
        // 0..=2 was closed; a higher number is the host task's own.
        None if (0..=2).contains(&fd) => FdOperandClass::Absent,
        None => FdOperandClass::HostBacked,
    }
}

/// `AT_FDCWD`.
const AT_FDCWD: i32 = -100;

/// The verdict for one `(dirfd, path)` pair at `dirfd_index`. Linux consults
/// the directory descriptor only for a relative (or empty) path. A ring-held
/// directory is the ring's own description: its number names nothing in the
/// root's host task, and the shared path staging serves no relative base
/// through it yet (`native_host_file`'s `path_base`), so the call is the
/// ring's counted ENOSYS rather than a path resolved against whatever the
/// host task has under that number.
fn dir_operand(
    args: &[u64; 6],
    dirfd_index: u8,
    classify: &mut impl FnMut(i32) -> FdOperandClass,
    first_path_byte: &mut impl FnMut(u64) -> Option<u8>,
) -> CrossingOperand {
    let dirfd = args[dirfd_index as usize] as i32;
    if dirfd == AT_FDCWD {
        return CrossingOperand::Pass;
    }
    let first = first_path_byte(args[dirfd_index as usize + 1]);
    if first.is_none_or(|byte| byte == b'/') {
        return CrossingOperand::Pass;
    }
    match classify(dirfd) {
        FdOperandClass::HostBacked | FdOperandClass::HostObject(_) => CrossingOperand::Pass,
        FdOperandClass::InZone => CrossingOperand::InRing,
        // An empty path is `ENOENT` before the descriptor is consulted.
        FdOperandClass::Absent if first == Some(0) => CrossingOperand::Pass,
        FdOperandClass::Absent => CrossingOperand::BadFd,
    }
}

/// Resolve the descriptor operand of `canonical` for `set`. A call that is
/// not an allowed crossing in `set` passes: the crossing table refuses it.
/// `first_path_byte` reads the first byte of the user path at an address
/// (`None`: unreadable, which the crossing itself then reports).
pub fn resolve_crossing_operand(
    set: HostCrossingSet,
    canonical: CanonicalNr,
    args: &[u64; 6],
    mut classify: impl FnMut(i32) -> FdOperandClass,
    mut first_path_byte: impl FnMut(u64) -> Option<u8>,
) -> CrossingOperand {
    let crossing = match set {
        HostCrossingSet::X86 => AllowedHostCrossing::from_canonical_x86(canonical),
        HostCrossingSet::Aarch64 => AllowedHostCrossing::from_canonical_aarch64(canonical),
    };
    let Some(crossing) = crossing else {
        return CrossingOperand::Pass;
    };
    let spec = crossing.operand_spec();
    let (index, object_write) = match spec.fd_operand() {
        FdOperand::None => return CrossingOperand::Pass,
        FdOperand::DirFd { index } => {
            for dirfd in [Some(index), spec.second_dirfd()].into_iter().flatten() {
                let verdict = dir_operand(args, dirfd, &mut classify, &mut first_path_byte);
                if verdict != CrossingOperand::Pass {
                    return verdict;
                }
            }
            return CrossingOperand::Pass;
        }
        FdOperand::Unresolved => return CrossingOperand::InRing,
        FdOperand::Fd { index } => (index, false),
        FdOperand::ObjectWrite => (0, true),
    };
    // Linux takes a descriptor as an int: the upper half is ignored.
    let fd = args[index as usize] as i32;
    match classify(fd) {
        FdOperandClass::HostBacked => CrossingOperand::Pass,
        FdOperandClass::InZone => CrossingOperand::InRing,
        FdOperandClass::Absent => CrossingOperand::BadFd,
        FdOperandClass::HostObject(binding) => {
            let Some(host_fd) = binding
                .stdio_fd()
                .or_else(|| binding.host_fd().map(|fd| fd.raw()))
            else {
                return CrossingOperand::BadFd;
            };
            if host_fd == fd {
                CrossingOperand::Pass
            } else if object_write {
                CrossingOperand::ObjectWrite(binding)
            } else {
                CrossingOperand::Rewrite { index, host_fd }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_personality_linux::crossing::nr;
    use carrick_personality_linux::native_host_file::InZoneKind;

    const X86: HostCrossingSet = HostCrossingSet::X86;

    fn resolve(canonical: CanonicalNr, fd: u64, class: FdOperandClass) -> CrossingOperand {
        resolve_crossing_operand(X86, canonical, &[fd, 0, 0, 0, 0, 0], |_| class, |_| None)
    }

    #[test]
    fn every_operand_class_has_one_verdict() {
        let stderr = HostObjectBinding::STDERR;
        for canonical in [nr::READ, nr::LSEEK, nr::PREAD64, nr::PWRITE64] {
            assert_eq!(
                resolve(canonical, 2, FdOperandClass::HostObject(stderr)),
                CrossingOperand::Pass,
                "{canonical:?}: a host object under its own number"
            );
            assert_eq!(
                resolve(canonical, 5, FdOperandClass::HostObject(stderr)),
                CrossingOperand::Rewrite {
                    index: 0,
                    host_fd: 2
                },
                "{canonical:?}: a host object under another number"
            );
            assert_eq!(
                resolve(canonical, 7, FdOperandClass::HostBacked),
                CrossingOperand::Pass
            );
            assert_eq!(
                resolve(canonical, 7, FdOperandClass::InZone),
                CrossingOperand::InRing
            );
            assert_eq!(
                resolve(canonical, 7, FdOperandClass::Absent),
                CrossingOperand::BadFd
            );
        }
        assert_eq!(
            resolve(nr::WRITE, 5, FdOperandClass::HostObject(stderr)),
            CrossingOperand::ObjectWrite(stderr)
        );
        assert_eq!(
            resolve(nr::WRITE, 2, FdOperandClass::HostObject(stderr)),
            CrossingOperand::Pass
        );
    }

    #[test]
    fn non_descriptor_and_unallowed_calls_pass_to_the_crossing_table() {
        // openat's dirfd is its path owner's; exit names no descriptor; a
        // call x86 does not allow (fstat) is the crossing table's to refuse.
        for canonical in [nr::OPENAT, nr::EXIT_GROUP, nr::FSTAT] {
            assert_eq!(
                resolve_crossing_operand(
                    X86,
                    canonical,
                    &[3, 0, 0, 0, 0, 0],
                    |_| panic!("{canonical:?} classified a descriptor"),
                    |_| None,
                ),
                CrossingOperand::Pass
            );
        }
    }

    #[test]
    fn a_ring_held_dirfd_is_consulted_only_for_a_relative_path() {
        let resolve = |nr: CanonicalNr, args: [u64; 6], class, first: Option<u8>| {
            resolve_crossing_operand(X86, nr, &args, |_| class, |_| first)
        };
        let at_cwd = -100i64 as u64;
        // mkdirat(dirfd, path, mode)
        let args = |dirfd| [dirfd, 0x1000, 0o755, 0, 0, 0];
        for (name, dirfd, class, first, want) in [
            (
                "AT_FDCWD",
                at_cwd,
                FdOperandClass::InZone,
                Some(b'x'),
                CrossingOperand::Pass,
            ),
            (
                "absolute path",
                5,
                FdOperandClass::InZone,
                Some(b'/'),
                CrossingOperand::Pass,
            ),
            (
                "ring-held, relative",
                5,
                FdOperandClass::InZone,
                Some(b'x'),
                CrossingOperand::InRing,
            ),
            (
                "host task's own",
                5,
                FdOperandClass::HostBacked,
                Some(b'x'),
                CrossingOperand::Pass,
            ),
            (
                "closed",
                5,
                FdOperandClass::Absent,
                Some(b'x'),
                CrossingOperand::BadFd,
            ),
            (
                "closed, empty path",
                5,
                FdOperandClass::Absent,
                Some(0),
                CrossingOperand::Pass,
            ),
            (
                "unreadable path",
                5,
                FdOperandClass::InZone,
                None,
                CrossingOperand::Pass,
            ),
        ] {
            assert_eq!(
                resolve(nr::MKDIRAT, args(dirfd), class, first),
                want,
                "{name}"
            );
        }
        // renameat names a second directory: olddirfd AT_FDCWD, newdirfd ring-held.
        assert_eq!(
            resolve(
                nr::RENAMEAT,
                [at_cwd, 0x1000, 5, 0x2000, 0, 0],
                FdOperandClass::InZone,
                Some(b'x')
            ),
            CrossingOperand::InRing
        );
        // symlinkat(target, newdirfd, linkpath): the dirfd is argument 1.
        assert_eq!(
            resolve(
                nr::SYMLINKAT,
                [0x1000, 5, 0x2000, 0, 0, 0],
                FdOperandClass::InZone,
                Some(b'x')
            ),
            CrossingOperand::InRing
        );
    }

    #[test]
    fn classify_reads_the_ring_tables() {
        let fd_map: [FdMapSlot; 8] = core::array::from_fn(|_| FdMapSlot::new());
        let objects: [carrick_el1_abi::DelegatedFile; 8] =
            core::array::from_fn(|_| carrick_el1_abi::DelegatedFile::new());
        let opens: [DelegatedOpenFile; 8] = core::array::from_fn(|_| DelegatedOpenFile::new());
        let table = 10;
        crate::file_table::admit_stdio(&fd_map, &opens, &objects, table, [true, true, false]);
        let none = |_| None;
        assert_eq!(
            classify_fd_operand(&fd_map, &opens, table, 1, none),
            FdOperandClass::HostObject(HostObjectBinding::STDOUT)
        );
        assert_eq!(
            classify_fd_operand(&fd_map, &opens, table, 2, none),
            FdOperandClass::Absent,
            "a closed stdio number"
        );
        assert_eq!(
            classify_fd_operand(&fd_map, &opens, table, -1, none),
            FdOperandClass::Absent
        );
        assert_eq!(
            classify_fd_operand(&fd_map, &opens, table, 7, none),
            FdOperandClass::HostBacked
        );
        let pipe = |_| {
            Some(NativeDescriptor::InZone(InZoneKind::Pipe(
                carrick_syscall_abi::LinuxPipeIdentity::new(1, 1),
            )))
        };
        assert_eq!(
            classify_fd_operand(&fd_map, &opens, table, 7, pipe),
            FdOperandClass::InZone
        );
        // A host file the ring holds for a staged open is the ring's too: the
        // root's host task has nothing under its number.
        let held = |_| {
            Some(NativeDescriptor::HostBacked {
                access: carrick_personality_linux::native_host_file::DescriptionAccess::ReadWrite,
            })
        };
        assert_eq!(
            classify_fd_operand(&fd_map, &opens, table, 3, held),
            FdOperandClass::InZone
        );
    }
}

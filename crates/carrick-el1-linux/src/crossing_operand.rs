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
    /// The ring's own object (pipe, eventfd, epoll, in-zone file, inotify).
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
/// caller's fd-core namespace when one is published; only its in-zone answer
/// is used, since a host-backed or absent fd-core entry says nothing about a
/// descriptor the root's host task opened.
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
        None if matches!(ring(fd), Some(NativeDescriptor::InZone(_))) => FdOperandClass::InZone,
        // The ring admits stdio for every table it serves, so a missing
        // 0..=2 was closed; a higher number is the host task's own.
        None if (0..=2).contains(&fd) => FdOperandClass::Absent,
        None => FdOperandClass::HostBacked,
    }
}

/// Resolve the descriptor operand of `canonical` for `set`. A call that is
/// not an allowed crossing in `set` passes: the crossing table refuses it.
pub fn resolve_crossing_operand(
    set: HostCrossingSet,
    canonical: CanonicalNr,
    args: &[u64; 6],
    classify: impl FnOnce(i32) -> FdOperandClass,
) -> CrossingOperand {
    let crossing = match set {
        HostCrossingSet::X86 => AllowedHostCrossing::from_canonical_x86(canonical),
        HostCrossingSet::Aarch64 => AllowedHostCrossing::from_canonical_aarch64(canonical),
    };
    let Some(crossing) = crossing else {
        return CrossingOperand::Pass;
    };
    let (index, object_write) = match crossing.operand_spec().fd_operand() {
        FdOperand::None | FdOperand::DirFd { .. } => return CrossingOperand::Pass,
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
        resolve_crossing_operand(X86, canonical, &[fd, 0, 0, 0, 0, 0], |_| class)
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
                resolve_crossing_operand(X86, canonical, &[3, 0, 0, 0, 0, 0], |_| {
                    panic!("{canonical:?} classified a descriptor")
                }),
                CrossingOperand::Pass
            );
        }
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
    }
}

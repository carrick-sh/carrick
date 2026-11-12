//! Venue-independent admission and staging for CPL0 native host-file calls.
//! Split from the bare-metal venue lookup so the decision is host-testable.
use carrick_core_abi::service::ServiceOrigin;
use carrick_el1_abi::CurrentTask;
use carrick_el1_linux::file::MemoryValidator;
use carrick_personality_linux::crossing::HostCrossingSet;
use carrick_personality_linux::entry::CanonicalCall;
use carrick_personality_linux::native_host_file::{
    HostFileCall, HostFileStage, NativeDescriptor, NativeNamespace,
};

/// Whether CPL0 stages this decoded call for `origin`. `delegated(fd)`
/// says whether the carrier's file table delegates `fd` to a host object
/// (the run's stdio streams).
///
/// - Path opens, access checks and stats, descriptor stats, and reads,
///   seeks and directory reads are staged for every task: the descriptor an
///   open installs lives in the caller's ring namespace, so every later call
///   on it must resolve there too (#1714: glibc's loader opened a library
///   in ring and then read it through the host table, EBADF).
/// - A read, seek or `write` of a delegated stdio descriptor keeps its host
///   route, which owns the terminal and blocking-read semantics. `writev` has
///   no x86 host route, so it is staged for every descriptor and a stdio
///   stream reaches the run's stdio sink through the shared venue.
/// - Path mutations stay child-scoped: the initial task keeps its host route.
///   `ftruncate` names a descriptor, so it follows the descriptor: one the
///   root's `openat` installed lives in the ring namespace and the host task
///   has nothing under its number (#2157 B1).
pub(crate) fn admits(
    call: HostFileCall,
    origin: ServiceOrigin,
    delegated: impl FnOnce(i32) -> bool,
) -> bool {
    match call {
        HostFileCall::Ftruncate { fd, .. } if origin == ServiceOrigin::Initial => !delegated(fd),
        call if call.uses_child_mutation_venue() => origin != ServiceOrigin::Initial,
        HostFileCall::Openat { .. }
        | HostFileCall::Faccessat { .. }
        | HostFileCall::Statx { .. }
        | HostFileCall::Newfstatat { .. }
        | HostFileCall::Fstat { .. }
        | HostFileCall::Getdents64 { .. }
        | HostFileCall::Writev { .. } => true,
        // A child's write has no host route; it is staged for every
        // descriptor, as before.
        HostFileCall::Write { .. } if origin != ServiceOrigin::Initial => true,
        HostFileCall::Write { fd, .. }
        | HostFileCall::Read { fd, .. }
        | HostFileCall::Pread { fd, .. }
        | HostFileCall::Lseek { fd, .. } => !delegated(fd),
        _ => false,
    }
}

/// Decode, admit and stage `call` against the caller's ring namespace.
/// `None` keeps the call on its existing route, including when no ring
/// namespace is published.
pub(crate) fn stage_call<V, R>(
    call: &CanonicalCall,
    task: &CurrentTask,
    validator: &V,
    origin: ServiceOrigin,
    delegated: impl FnOnce(i32) -> bool,
    namespace: impl FnOnce() -> Option<([u64; 3], R)>,
) -> Option<HostFileStage>
where
    V: MemoryValidator,
    R: FnMut(i32) -> Option<NativeDescriptor>,
{
    let decoded = HostFileCall::decode(
        carrick_syscall_abi::CanonicalNr::new(call.canonical.raw()),
        &call.args,
    )?;
    if !admits(decoded, origin, delegated) {
        return None;
    }
    // No published ring namespace (venue or table unavailable): keep the
    // existing route, as ARM's staging does, so an initial write keeps its
    // stdout route and a strict refusal stays the crossing table's.
    let (table, mut resolve) = namespace()?;
    // A descriptor is owned by exactly one table. The run root's ring
    // namespace holds what its staged calls opened; a descriptor absent
    // there (one the host table opened) keeps the host route, which answers
    // it, rather than a ring EBADF. Only a call with an x86 host crossing
    // has that route: the ring answers the rest, so a bad or closed
    // descriptor is EBADF there, not a counted ENOSYS (#2138 P0-1).
    let canonical = carrick_syscall_abi::CanonicalNr::new(call.canonical.raw());
    let host_route = origin == ServiceOrigin::Initial && HostCrossingSet::X86.is_allowed(canonical);
    let mut absent = false;
    let mut resolve = |fd| {
        let descriptor = resolve(fd);
        absent |= matches!(descriptor, Some(NativeDescriptor::Absent));
        descriptor
    };
    let mut releases = |_: &mut [carrick_core_abi::host_file::MapSourceReply]| 0;
    let staged = carrick_el1_linux::dispatch::stage_native_host_file(
        decoded,
        task,
        validator,
        &mut NativeNamespace {
            table,
            resolve: &mut resolve,
            releases: &mut releases,
        },
    );
    if absent && host_route {
        return None;
    }
    Some(staged.unwrap_or(HostFileStage::InRing))
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_personality_linux::entry::decode_x86_64;
    use carrick_personality_linux::native_host_file::{DescriptionAccess, InZoneKind};

    struct Resident;
    impl MemoryValidator for Resident {
        fn writable_bytes(&self, _user_va: u64, len: usize) -> usize {
            len
        }
        fn readable_bytes(&self, _user_va: u64, len: usize) -> usize {
            len
        }
    }

    const INITIAL: ServiceOrigin = ServiceOrigin::Initial;
    const CHILD: ServiceOrigin = ServiceOrigin::Descendant;

    fn host() -> Option<NativeDescriptor> {
        Some(NativeDescriptor::HostBacked {
            access: DescriptionAccess::ReadWrite,
        })
    }

    fn stage(
        nr: u64,
        args: [u64; 6],
        origin: ServiceOrigin,
        fd: Option<NativeDescriptor>,
    ) -> Option<HostFileStage> {
        let call = decode_x86_64(nr, args, 0x8000);
        let task = CurrentTask::new();
        stage_call(
            &call,
            &task,
            &Resident,
            origin,
            |_| false,
            || Some(([3, 4, 5], |_| fd)),
        )
    }

    #[test]
    fn descendant_write_and_writev_stage_host_stdout() {
        let bytes = *b"hello\n";
        let buf = bytes.as_ptr() as u64;
        let iov = [buf, bytes.len() as u64];
        let write = stage(1, [1, buf, bytes.len() as u64, 0, 0, 0], CHILD, host());
        assert!(
            matches!(write, Some(HostFileStage::Request { .. })),
            "write {write:?}"
        );
        let writev = stage(20, [1, iov.as_ptr() as u64, 1, 0, 0, 0], CHILD, host());
        assert!(
            matches!(writev, Some(HostFileStage::Request { .. })),
            "writev {writev:?}"
        );
    }

    fn stage_delegated(
        nr: u64,
        args: [u64; 6],
        origin: ServiceOrigin,
        delegated: bool,
    ) -> Option<HostFileStage> {
        let call = decode_x86_64(nr, args, 0x8000);
        let task = CurrentTask::new();
        stage_call(
            &call,
            &task,
            &Resident,
            origin,
            |_| delegated,
            || Some(([3, 4, 5], |_| host())),
        )
    }

    #[test]
    fn initial_stdio_transfers_keep_the_host_route_and_writev_stages() {
        // A delegated stdio stream's read, seek and write keep the host
        // route, which owns their terminal semantics. `writev` has no x86
        // host route (#1714: the loader's error message was ENOSYS), so it
        // stages for every descriptor and reaches the run's stdio sink.
        let mut bytes = *b"hello\n";
        let buf = bytes.as_mut_ptr() as u64;
        let iov = [buf, bytes.len() as u64];
        let len = bytes.len() as u64;
        for (name, nr, args) in [
            ("write", 1, [1, buf, len, 0, 0, 0]),
            ("read", 0, [0, buf, len, 0, 0, 0]),
            ("pread64", 17, [0, buf, len, 0, 0, 0]),
            ("lseek", 8, [1, 0, 0, 0, 0, 0]),
        ] {
            assert_eq!(stage_delegated(nr, args, INITIAL, true), None, "{name}");
        }
        let writev = stage_delegated(20, [1, iov.as_ptr() as u64, 1, 0, 0, 0], INITIAL, true);
        assert!(
            matches!(writev, Some(HostFileStage::Request { .. })),
            "writev {writev:?}"
        );
    }

    #[test]
    fn initial_ring_descriptor_calls_stage_in_the_ring_namespace() {
        // #1714: the root's `openat` installs its descriptor in the ring
        // namespace, so every later call on it must resolve there: before
        // this, read/pread64/lseek/fstat went to the host table (EBADF) and
        // the loader exited 127.
        let mut buf = [0u8; 256];
        let out = buf.as_mut_ptr() as u64;
        let empty = *b"\0";
        for (name, nr, args) in [
            ("read", 0, [3, out, 64, 0, 0, 0]),
            ("pread64", 17, [3, out, 64, 0, 0, 0]),
            ("lseek", 8, [3, 0, 0, 0, 0, 0]),
            ("fstat", 5, [3, out, 0, 0, 0, 0]),
            (
                "newfstatat",
                262,
                [3, empty.as_ptr() as u64, out, 0x1000, 0, 0],
            ),
            ("getdents64", 217, [3, out, 64, 0, 0, 0]),
            ("write", 1, [3, out, 4, 0, 0, 0]),
        ] {
            let staged = stage_delegated(nr, args, INITIAL, false);
            assert!(
                matches!(staged, Some(HostFileStage::Request { .. })),
                "{name}: {staged:?}"
            );
        }
    }

    #[test]
    fn root_descriptor_absent_from_the_ring_keeps_the_host_route() {
        // A descriptor the host table opened for the run root is not in its
        // ring namespace; the host route owns it (one table per descriptor).
        let mut buf = [0u8; 64];
        let out = buf.as_mut_ptr() as u64;
        for (origin, expected_route_kept) in [(INITIAL, true), (CHILD, false)] {
            let staged = stage(
                17,
                [3, out, 1, 0, 0, 0],
                origin,
                Some(NativeDescriptor::Absent),
            );
            assert_eq!(
                staged.is_none(),
                expected_route_kept,
                "{origin:?}: {staged:?}"
            );
        }
    }

    #[test]
    fn root_bad_descriptor_without_a_host_crossing_is_the_ring_ebadf() {
        // #2138 P0-1: writev and getdents64 have no x86 host crossing, so
        // declining an absent descriptor made them a counted ENOSYS. The ring
        // answers them: EBADF (9). (statx became a crossing in #2157 B1: an
        // absent descriptor keeps the host route, whose resolver answers
        // EBADF.)
        let mut buf = [0u8; 256];
        let out = buf.as_mut_ptr() as u64;
        let iov = [out, 1];
        for fd in [u64::MAX, 3] {
            for (name, nr, args) in [
                ("writev", 20, [fd, iov.as_ptr() as u64, 1, 0, 0, 0]),
                ("getdents64", 217, [fd, out, 64, 0, 0, 0]),
            ] {
                let staged = stage(nr, args, INITIAL, Some(NativeDescriptor::Absent));
                assert_eq!(
                    staged,
                    Some(HostFileStage::Returned(
                        carrick_personality_linux::entry::SyscallResult::from_errno(
                            carrick_syscall_abi::LINUX_EBADF
                        )
                    )),
                    "{name} fd {}",
                    fd as i64
                );
            }
        }
    }

    #[test]
    fn x86_stat_requests_reply_canonically_and_complete_in_x86_layout() {
        use carrick_core_abi::host_file::HostFileRequestView;
        use carrick_personality_linux::native_host_file::{
            LINUX_STAT_BYTES, OutputLayout, X8664_STAT_BYTES,
        };
        let mut buf = [0u8; 256];
        let out = buf.as_mut_ptr() as u64;
        let Some(HostFileStage::Request {
            mut record,
            output: Some(output),
            ..
        }) = stage_delegated(5, [3, out, 0, 0, 0, 0], INITIAL, false)
        else {
            panic!("fstat stages a request");
        };
        // The user buffer is x86's 144 bytes; the carrier's reply area is
        // the canonical 128-byte record (a larger area is a chdir lookup).
        assert_eq!(
            (output.len, output.layout),
            (X8664_STAT_BYTES, OutputLayout::X8664Stat)
        );
        let view = HostFileRequestView::parse(&mut record).unwrap();
        assert_eq!(view.output_capacity(), LINUX_STAT_BYTES);
    }

    #[test]
    fn unpublished_namespace_keeps_the_existing_route() {
        // #1954 P0-2: an absent venue or table was staged InRing, so an
        // initial write to stdout returned counted ENOSYS (-38).
        let bytes = *b"hello\n";
        let buf = bytes.as_ptr() as u64;
        let iov = [buf, bytes.len() as u64];
        let task = CurrentTask::new();
        for origin in [INITIAL, CHILD] {
            for (nr, args) in [
                (1, [1, buf, bytes.len() as u64, 0, 0, 0]),
                (20, [1, iov.as_ptr() as u64, 1, 0, 0, 0]),
            ] {
                let call = decode_x86_64(nr, args, 0x8000);
                let staged = stage_call(
                    &call,
                    &task,
                    &Resident,
                    origin,
                    |_| false,
                    || None::<([u64; 3], fn(i32) -> Option<NativeDescriptor>)>,
                );
                assert_eq!(staged, None, "{origin:?} nr {nr}");
            }
        }
    }

    #[test]
    fn write_to_in_zone_pipe_stays_in_ring() {
        let pipe = Some(NativeDescriptor::InZone(InZoneKind::Pipe(
            carrick_syscall_abi::LinuxPipeIdentity::new(1, 1),
        )));
        let bytes = *b"x";
        let args = [1, bytes.as_ptr() as u64, 1, 0, 0, 0];
        assert_eq!(stage(1, args, CHILD, pipe), Some(HostFileStage::InRing));
    }

    #[test]
    fn ftruncate_follows_its_descriptor_for_the_root_too() {
        // The root's ring-held file has no host-task descriptor to truncate:
        // the ring venue stages it, as for a descendant. A descriptor the
        // host table opened keeps the host route; a delegated stdio stream
        // does too.
        let args = [3, 0, 0, 0, 0, 0];
        for origin in [INITIAL, CHILD] {
            assert!(
                matches!(
                    stage(77, args, origin, host()),
                    Some(HostFileStage::Request { .. })
                ),
                "{origin:?}"
            );
        }
        assert_eq!(
            stage(77, args, INITIAL, Some(NativeDescriptor::Absent)),
            None
        );
        assert_eq!(stage_delegated(77, args, INITIAL, true), None);
    }

    #[test]
    fn mutations_are_descendant_only() {
        // x86_64 numbers: mkdirat 258, unlinkat 263, renameat2 316,
        // truncate 76, ftruncate 77, symlinkat 266, linkat 265, utimensat 280.
        let path = *b"/x\0";
        let p = path.as_ptr() as u64;
        let cases: [(&str, u64, [u64; 6]); 7] = [
            ("mkdirat", 258, [!99u64, p, 0o755, 0, 0, 0]),
            ("unlinkat", 263, [!99u64, p, 0, 0, 0, 0]),
            ("symlinkat", 266, [p, !99u64, p, 0, 0, 0]),
            ("linkat", 265, [!99u64, p, !99u64, p, 0, 0]),
            ("renameat2", 316, [!99u64, p, !99u64, p, 0, 0]),
            ("utimensat", 280, [!99u64, p, 0, 0, 0, 0]),
            ("truncate", 76, [p, 0, 0, 0, 0, 0]),
        ];
        for (name, nr, args) in cases {
            assert!(
                stage(nr, args, CHILD, host()).is_some(),
                "{name}: a descendant is staged"
            );
            assert_eq!(
                stage(nr, args, INITIAL, host()),
                None,
                "{name}: the initial task keeps its host route"
            );
        }
    }
}

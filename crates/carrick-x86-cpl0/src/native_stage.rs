//! Venue-independent admission and staging for CPL0 native host-file calls.
//! Split from the bare-metal venue lookup so the decision is host-testable.
use carrick_core_abi::service::ServiceOrigin;
use carrick_el1_abi::CurrentTask;
use carrick_el1_linux::file::MemoryValidator;
use carrick_personality_linux::crossing::HostCrossingSet;
use carrick_personality_linux::entry::CanonicalCall;
use carrick_personality_linux::native_host_file::{
    HostFileStage, NativeDescriptor, NativeNamespace, admit_or_cross,
};

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
    let canonical = carrick_syscall_abi::CanonicalNr::new(call.canonical.raw());
    let decoded = match admit_or_cross(
        HostCrossingSet::X86,
        canonical,
        &call.args,
        origin,
        delegated,
        |address, len| validator.writable_bytes(address, len),
    ) {
        Ok(decoded) => decoded,
        Err(existing_route) => return existing_route,
    };
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

    struct Untouched;
    impl MemoryValidator for Untouched {
        fn writable_bytes(&self, _user_va: u64, _len: usize) -> usize {
            0
        }
        fn readable_bytes(&self, _user_va: u64, len: usize) -> usize {
            len
        }
    }

    fn stage_output(
        validator: &impl MemoryValidator,
        nr: u64,
        args: [u64; 6],
    ) -> Option<HostFileStage> {
        let call = decode_x86_64(nr, args, 0x8000);
        stage_call(
            &call,
            &CurrentTask::new(),
            validator,
            INITIAL,
            |_| false,
            || Some(([3, 4, 5], |_| None)),
        )
    }

    #[test]
    fn a_crossing_output_is_made_writable_before_the_effect() {
        // x86_64 statfs 137, readlinkat 267, getxattr 191, mkdirat 258.
        let (path, out) = (0x7000_0000u64, 0x7000_1000u64);
        let fault = Some(HostFileStage::PrepareOutput { address: out });
        assert_eq!(
            stage_output(&Untouched, 137, [path, out, 0, 0, 0, 0]),
            fault
        );
        assert_eq!(
            stage_output(&Untouched, 267, [!99u64, path, out, 64, 0, 0]),
            fault
        );
        assert_eq!(
            stage_output(&Untouched, 191, [path, path, out, 16, 0, 0]),
            fault
        );
        // A buffer that reaches into the next page prepares that page too:
        // the result may land on either side of the boundary. The first page
        // is resident, so the next is the one supplied.
        struct FirstPage(u64);
        impl MemoryValidator for FirstPage {
            fn writable_bytes(&self, user_va: u64, len: usize) -> usize {
                (self.0 + 0x1000).saturating_sub(user_va).min(len as u64) as usize
            }
            fn readable_bytes(&self, _user_va: u64, len: usize) -> usize {
                len
            }
        }
        assert_eq!(
            stage_output(&FirstPage(out), 191, [path, path, out + 0xffe, 16, 0, 0]),
            Some(HostFileStage::PrepareOutput {
                address: out + 0x1000
            })
        );
        assert_eq!(
            HostFileStage::PrepareOutput { address: out }.refused(),
            HostFileStage::Crossing
        );
        // Already writable, a zero-length buffer, and a call with no
        // guest output all proceed to the crossing.
        assert_eq!(stage_output(&Resident, 137, [path, out, 0, 0, 0, 0]), None);
        assert_eq!(
            stage_output(&Untouched, 191, [path, path, out, 0, 0, 0]),
            None
        );
        assert_eq!(
            stage_output(&Untouched, 258, [!99u64, path, 0o755, 0, 0, 0]),
            None
        );
    }

    /// readlinkat (x86_64 267) decodes as the native file family's call,
    /// which this venue never admits: the root's keeps its host crossing, so
    /// its untouched output page is prepared first, then the same call
    /// crosses (#2201 with #1862). Nothing here stages it as a host-file
    /// request.
    #[test]
    fn a_root_readlinkat_prepares_its_output_then_crosses() {
        let (path, out) = (0x7000_0000u64, 0x7000_1000u64);
        let args = [!99u64, path, out, 64, 0, 0];
        assert_eq!(
            stage_output(&Untouched, 267, args),
            Some(HostFileStage::PrepareOutput { address: out })
        );
        assert_eq!(stage_output(&Resident, 267, args), None);
    }

    #[test]
    fn a_child_readlinkat_prepares_untouched_output_then_keeps_the_family_route() {
        let (path, out) = (0x7000_0000u64, 0x7000_1000u64);
        let call = decode_x86_64(267, [!99u64, path, out, 64, 0, 0], 0x8000);
        let task = CurrentTask::new();
        fn stage(
            validator: &impl MemoryValidator,
            call: &CanonicalCall,
            task: &CurrentTask,
        ) -> Option<HostFileStage> {
            stage_call(
                call,
                task,
                validator,
                CHILD,
                |_| false,
                || Some(([3, 4, 5], |_| None)),
            )
        }
        assert_eq!(
            stage(&Untouched, &call, &task),
            Some(HostFileStage::PrepareOutput { address: out })
        );
        assert_eq!(stage(&Resident, &call, &task), None);
        assert_eq!(
            carrick_personality_linux::dispatch::route_x86(78, 0),
            carrick_personality_linux::dispatch::Family::NativeHostFile,
        );
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

    /// #2206: coreutils' `mkdir -p` fchdirs (x86 81, canonical 50) into
    /// each directory it creates. A descendant stages the chdir lookup of
    /// its descriptor, completed from the reply as `chdir`'s is; the
    /// initial task keeps its host route; the ring answers a descriptor
    /// that is no directory.
    #[test]
    fn descendant_fchdir_stages_the_chdir_lookup_and_completes_from_its_reply() {
        use carrick_core_abi::host_file::{HostFileOp, HostFileRequestView};
        use carrick_personality_linux::entry::SyscallResult;
        use carrick_personality_linux::native_host_file::{CHDIR_REPLY_BYTES, chdir_target};
        let args = [3, 0, 0, 0, 0, 0];
        assert_eq!(
            stage(81, args, INITIAL, host()),
            None,
            "the initial task keeps its host route"
        );
        let Some(HostFileStage::Request {
            mut record,
            output,
            resolves_path,
            map,
            chdir,
        }) = stage(81, args, CHILD, host())
        else {
            panic!("a descendant's fchdir of a host-backed descriptor is staged");
        };
        assert_eq!(
            (output, resolves_path, map, chdir),
            (None, true, None, true),
            "a chdir lookup under the caller's access context"
        );
        let view = HostFileRequestView::parse(&mut record).unwrap();
        assert_eq!(view.header().op, HostFileOp::Fchdir);
        assert_eq!(view.header().fd, 3);
        assert_eq!(view.header().table, [3, 4, 5]);
        assert_eq!(view.input(), b"");
        assert_eq!(view.output_capacity(), CHDIR_REPLY_BYTES);
        let mut stat = carrick_syscall_abi::LinuxStat::from_fields(
            &carrick_syscall_abi::LinuxPipeIdentity::new(1, 1).stat_fields(),
        );
        stat.st_mode = carrick_syscall_abi::LINUX_S_IFDIR | 0o755;
        let mut reply = zerocopy::IntoBytes::as_bytes(&stat).to_vec();
        reply.extend_from_slice(b"/tmp/a");
        view.reply(0, &reply).unwrap();
        assert_eq!(chdir_target(&record).unwrap().as_bytes(), b"/tmp/a");

        let pipe = Some(NativeDescriptor::InZone(InZoneKind::Pipe(
            carrick_syscall_abi::LinuxPipeIdentity::new(1, 1),
        )));
        for (descriptor, errno) in [
            (pipe, carrick_syscall_abi::LINUX_ENOTDIR),
            (
                Some(NativeDescriptor::Absent),
                carrick_syscall_abi::LINUX_EBADF,
            ),
        ] {
            assert_eq!(
                stage(81, args, CHILD, descriptor),
                Some(HostFileStage::Returned(SyscallResult::from_errno(errno))),
                "{errno:?}"
            );
        }
    }
}

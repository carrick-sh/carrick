//! Venue-independent admission and staging for CPL0 native host-file calls.
//! Split from the bare-metal venue lookup so the decision is host-testable.
use carrick_core_abi::service::ServiceOrigin;
use carrick_el1_abi::CurrentTask;
use carrick_el1_linux::file::MemoryValidator;
use carrick_personality_linux::entry::CanonicalCall;
use carrick_personality_linux::native_host_file::{
    HostFileCall, HostFileStage, NativeDescriptor, NativeNamespace,
};

/// Whether CPL0 stages this decoded call for `origin`. Mutations are
/// child-scoped (the initial task keeps its host route). Beyond path
/// opens/stats, only `Write`/`Writev` are admitted, and only for a
/// descendant, so a child's redirected host-file stdout is served; descriptor
/// reads stay on their existing route until slice 3. The initial task's
/// write keeps its host route: x86 `begin_host_file_call` refuses an initial
/// root's staged `Write` (counted ENOSYS) while the carrier retains its
/// filesystem custody.
pub(crate) fn admits(call: HostFileCall, origin: ServiceOrigin) -> bool {
    if call.uses_child_mutation_venue()
        || matches!(
            call,
            HostFileCall::Write { .. } | HostFileCall::Writev { .. }
        )
    {
        return origin != ServiceOrigin::Initial;
    }
    matches!(
        call,
        HostFileCall::Openat { .. } | HostFileCall::Faccessat { .. } | HostFileCall::Statx { .. }
    )
}

/// Decode, admit and stage `call` against the caller's ring namespace.
/// `None` keeps the call on its existing route, including when no ring
/// namespace is published.
pub(crate) fn stage_call<V, R>(
    call: &CanonicalCall,
    task: &CurrentTask,
    validator: &V,
    origin: ServiceOrigin,
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
    if !admits(decoded, origin) {
        return None;
    }
    // No published ring namespace (venue or table unavailable): keep the
    // existing route, as ARM's staging does, so an initial write keeps its
    // stdout route and a strict refusal stays the crossing table's.
    let (table, mut resolve) = namespace()?;
    let mut releases = |_: &mut [carrick_core_abi::host_file::MapSourceReply]| 0;
    Some(
        carrick_el1_linux::dispatch::stage_native_host_file(
            decoded,
            task,
            validator,
            &mut NativeNamespace {
                table,
                resolve: &mut resolve,
                releases: &mut releases,
            },
        )
        .unwrap_or(HostFileStage::InRing),
    )
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
        stage_call(&call, &task, &Resident, origin, || {
            Some(([3, 4, 5], |_| fd))
        })
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

    #[test]
    fn initial_write_and_writev_keep_the_host_route() {
        // #1954: an initial root's staged write reaches `begin_host_file_call`,
        // which refuses it as counted ENOSYS (-38) while the carrier retains
        // the root's filesystem; the initial write keeps its host route.
        let bytes = *b"hello\n";
        let buf = bytes.as_ptr() as u64;
        let iov = [buf, bytes.len() as u64];
        assert_eq!(
            stage(1, [1, buf, bytes.len() as u64, 0, 0, 0], INITIAL, host()),
            None
        );
        assert_eq!(
            stage(20, [1, iov.as_ptr() as u64, 1, 0, 0, 0], INITIAL, host()),
            None
        );
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
                let staged = stage_call(&call, &task, &Resident, origin, || {
                    None::<([u64; 3], fn(i32) -> Option<NativeDescriptor>)>
                });
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
    fn mutations_are_descendant_only() {
        // x86_64 numbers: mkdirat 258, unlinkat 263, renameat2 316,
        // truncate 76, ftruncate 77, symlinkat 266, linkat 265, utimensat 280.
        let path = *b"/x\0";
        let p = path.as_ptr() as u64;
        let cases: [(&str, u64, [u64; 6]); 8] = [
            ("mkdirat", 258, [!99u64, p, 0o755, 0, 0, 0]),
            ("unlinkat", 263, [!99u64, p, 0, 0, 0, 0]),
            ("symlinkat", 266, [p, !99u64, p, 0, 0, 0]),
            ("linkat", 265, [!99u64, p, !99u64, p, 0, 0]),
            ("renameat2", 316, [!99u64, p, !99u64, p, 0, 0]),
            ("utimensat", 280, [!99u64, p, 0, 0, 0, 0]),
            ("truncate", 76, [p, 0, 0, 0, 0, 0]),
            ("ftruncate", 77, [3, 0, 0, 0, 0, 0]),
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

//! Private file mappings of an admitted MM (#1103, #1124, #1141).
//!
//! The owner portal refuses every transfer on `Gate` while the MM's gate is
//! raised, and the `mmap`/`madvise`/`mremap` mutation guard raised it. So a
//! private file mapping must never initialize, restore or move its bytes
//! through the owner inside the syscall: it keeps retained source custody in
//! the root node, discard returns pages to that source and relocation moves
//! the node with its source. These witnesses hold the MM's own gate for the
//! whole syscall, exactly as the production guard does.

use super::*;
use carrick_el1_abi::{El1MmHandle, PortalOwnerWait, PortalWaitCause};
use std::num::NonZeroU64;

const MADV_DONTNEED: u64 = carrick_abi::LINUX_MADV_DONTNEED;
const FIXED_PRIVATE: u64 = LINUX_MAP_PRIVATE | carrick_abi::LINUX_MAP_FIXED;

/// Refuse every owner transfer as the live portal does while this MM's own
/// mutation guard holds its gate.
fn hold_own_gate(memory: &CountingMmapMemory, root: &Root) {
    let nz = |value| NonZeroU64::new(value).unwrap();
    // SAFETY: the scripted backend models this exact MM's held mutation gate.
    let wait = unsafe {
        PortalOwnerWait::from_owner(
            El1MmHandle::from_admitted_owner(nz(1), root.mm, nz(1)),
            PortalWaitCause::Gate,
            15,
        )
    };
    memory.owner_gate.set(Some(wait));
}

/// The bytes a first touch of `[address, address+len)` supplies: the root
/// node's retained source at the matching offset.
fn source_bytes(dispatcher: &SyscallDispatcher, root: &Root, address: u64, len: u64) -> Vec<u8> {
    let mapping = root
        .lock()
        .mapping(address)
        .unwrap_or_else(|| panic!("no root node at {address:#x}"));
    let backing = mapping
        .host_backing
        .unwrap_or_else(|| panic!("root node at {address:#x} has no retained source"))
        .advance(address - mapping.range.start())
        .unwrap();
    dispatcher
        .mem_view()
        .read_host_backing(backing, len as usize)
        .unwrap()
}

fn madvise(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut CountingMmapMemory,
    address: u64,
    len: u64,
) -> DispatchOutcome {
    call(
        dispatcher,
        memory,
        SYS_MADVISE,
        [address, len, MADV_DONTNEED, 0, 0, 0],
    )
}

fn pages(count: u8) -> Vec<u8> {
    (0..count)
        .flat_map(|page| vec![page + 1; PAGE as usize])
        .collect()
}

fn pwrite_host_file(dispatcher: &SyscallDispatcher, fd: i32, offset: u64, byte: u8) {
    let open = dispatcher.open_file(fd).unwrap();
    let guard = crate::kernel::FileDescription::read_for_io(&open.description).unwrap();
    let OpenDescription::HostFile { host_fd, .. } = &*guard else {
        panic!("fixture fd is not a host file");
    };
    // SAFETY: the description guard retains the host fd for this write.
    let written = unsafe {
        libc::pwrite(
            host_fd.raw(),
            std::ptr::from_ref(&byte).cast(),
            1,
            offset as libc::off_t,
        )
    };
    assert_eq!(written, 1);
}

/// Every file description a private mapping can name (the in-memory
/// `/opt/carrick/el1-sched` fixture of #1103's TLB tests, synthetic, overlay
/// and host files, and host files under `MAP_POPULATE` and `MAP_LOCKED`)
/// maps under the MM's own gate without one owner copy.
#[test]
fn admitted_private_file_mmap_of_every_description_never_copies_under_its_own_gate() {
    let payload: Vec<u8> = (0..PAGE as usize + 37)
        .map(|index| (index % 251) as u8 + 1)
        .collect();
    let install = |dispatcher: &SyscallDispatcher, kind: &str| -> i32 {
        let base = || OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY);
        let description = match kind {
            "in-memory" => OpenDescription::InMemoryFile {
                base: base(),
                path: "/opt/carrick/el1-sched".into(),
                contents: Arc::new(parking_lot::RwLock::new(carrick_vfs::SparseBuffer::from(
                    payload.clone(),
                ))),
                offset: 0,
                writable: false,
                max_size: payload.len(),
            },
            "synthetic" => OpenDescription::SyntheticFile {
                base: base(),
                path: "/proc/synthetic".into(),
                contents: payload.clone(),
                offset: 0,
            },
            "overlay" => OpenDescription::File {
                base: base(),
                path: "/overlay/file".into(),
                metadata: RootFsMetadata {
                    path: "/overlay/file".into(),
                    kind: RootFsEntryKind::File,
                    mode: 0o644,
                    size: payload.len(),
                },
                contents: FileContents::dense(payload.clone()),
                offset: 0,
                writable: false,
            },
            _ => {
                install_host_file_fd(dispatcher, FILE_FD, &payload);
                return FILE_FD;
            }
        };
        returned(dispatcher.fs_view().install_fd(description, 0)) as i32
    };
    for (kind, extra) in [
        ("in-memory", 0),
        ("synthetic", 0),
        ("overlay", 0),
        ("host", 0),
        ("host", carrick_abi::LINUX_MAP_POPULATE),
        ("host", carrick_abi::LINUX_MAP_LOCKED),
    ] {
        let mut dispatcher = SyscallDispatcher::new();
        let fd = install(&dispatcher, kind);
        let root = Root::admit(&dispatcher);
        let mut memory = arena_memory();
        hold_own_gate(&memory, &root);
        let address = LINUX_MMAP_BASE + 14 * PAGE;
        assert_eq!(
            host_mmap(
                &mut dispatcher,
                &mut memory,
                address,
                2 * PAGE,
                RW,
                FIXED_PRIVATE | extra,
                fd,
            ),
            DispatchOutcome::Returned {
                value: address as i64
            },
            "{kind} flags={extra:#x}: a self-held gate is not ENOMEM"
        );
        assert_eq!(
            memory.write_calls.get(),
            0,
            "{kind}: no owner copy under the closed gate"
        );
        assert_eq!(
            source_bytes(&dispatcher, &root, address, PAGE),
            payload[..PAGE as usize],
            "{kind}"
        );
        let tail = source_bytes(&dispatcher, &root, address + PAGE, PAGE);
        assert_eq!(&tail[..37], &payload[PAGE as usize..], "{kind}");
        assert!(tail[37..].iter().all(|byte| *byte == 0), "{kind}");
        if extra == carrick_abi::LINUX_MAP_LOCKED {
            assert_eq!(locked_memory(&dispatcher), [(address, address + 2 * PAGE)]);
        }
    }
}

/// `MADV_DONTNEED` returns a dirty private file page to its retained source:
/// the next touch reads the file again (and sees later file writes) with no
/// owner write under the MM's own gate, and only the discarded page retires.
#[test]
fn admitted_private_file_discard_returns_pages_to_the_retained_source() {
    let mut dispatcher = SyscallDispatcher::new();
    install_host_file_fd(&dispatcher, FILE_FD, &pages(4));
    let root = Root::admit(&dispatcher);
    let mut memory = arena_memory();
    let file = returned(host_mmap(
        &mut dispatcher,
        &mut memory,
        0,
        4 * PAGE,
        RW,
        LINUX_MAP_PRIVATE,
        FILE_FD,
    )) as u64;
    memory.write_bytes(file + PAGE, &[0x52]).unwrap();
    let writes = memory.write_calls.get();
    memory.unmap_log.borrow_mut().clear();
    hold_own_gate(&memory, &root);

    assert_eq!(
        madvise(&mut dispatcher, &mut memory, file + PAGE, PAGE),
        DispatchOutcome::Returned { value: 0 },
        "discard under the MM's own gate is not ENOMEM"
    );
    assert_eq!(memory.write_calls.get(), writes, "no owner restore copy");
    assert_eq!(
        memory.unmap_log.borrow().as_slice(),
        [(file + PAGE, PAGE as usize)],
        "exactly the discarded page leaves its private frame"
    );
    assert_eq!(source_bytes(&dispatcher, &root, file + PAGE, 1), [2]);
    // A clean page reads the live file, so a later write is visible.
    pwrite_host_file(&dispatcher, FILE_FD, PAGE, 0x61);
    assert_eq!(source_bytes(&dispatcher, &root, file + PAGE, 1), [0x61]);
    // The rest of the mapping keeps its node and source.
    assert_eq!(source_bytes(&dispatcher, &root, file, 1), [1]);
    assert_eq!(source_bytes(&dispatcher, &root, file + 3 * PAGE, 1), [4]);
}

/// The executable's header page (`AT_PHDR`) is a loaded-image source node
/// after admission; discarding it restores the image bytes without a copy
/// (`case_private_file_exec_discard_preserves_header`).
#[test]
fn admitted_loaded_image_discard_restores_the_image_without_a_copy() {
    let mut dispatcher = SyscallDispatcher::new();
    let start = 0x40_0000;
    let image: Vec<u8> = (0..PAGE as usize).map(|index| index as u8).collect();
    dispatcher
        .publish_exec_image_state(
            dispatcher.mm_authority().mm_id,
            vec![ProcMapsEntry {
                start,
                end: start + PAGE,
                read: true,
                write: false,
                execute: true,
                sharing: carrick_vfs::ProcMapSharing::Private,
                path: "/usr/bin/python3".to_owned(),
            }],
            Vec::new(),
            vec![crate::core_dump::FileMapping {
                start,
                end: start + PAGE,
                file_page_offset: 0,
                path: "/usr/bin/python3".to_owned(),
            }],
            vec![PrivateFileMapEntry {
                start,
                end: start + PAGE,
                offset: 0,
                backing: PrivateFileBacking::LoadedImage {
                    initialized_offset: 0,
                    bytes: Arc::new(image.clone()),
                },
            }],
        )
        .commit();
    let root = Root::admit(&dispatcher);
    let mut memory = CountingMmapMemory::new(start, PAGE as usize);
    hold_own_gate(&memory, &root);
    assert_eq!(
        madvise(&mut dispatcher, &mut memory, start, PAGE),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(memory.write_calls.get(), 0);
    assert_eq!(source_bytes(&dispatcher, &root, start, PAGE), image);
}

/// `mremap(MREMAP_MAYMOVE | MREMAP_FIXED)` of a retained private file node
/// moves the root node with its source offset (Linux keeps the file
/// association across a move): the destination's later discard reads the
/// file page that moved there.
#[test]
fn admitted_private_file_mremap_moves_the_node_with_its_source() {
    let mut dispatcher = SyscallDispatcher::new();
    install_host_file_fd(&dispatcher, FILE_FD, &pages(4));
    let root = Root::admit(&dispatcher);
    let mut memory = arena_memory();
    let file = returned(host_mmap(
        &mut dispatcher,
        &mut memory,
        0,
        4 * PAGE,
        RW,
        LINUX_MAP_PRIVATE,
        FILE_FD,
    )) as u64;
    memory.write_bytes(file, &[0x51]).unwrap();
    let destination = anon_mmap(&mut dispatcher, &mut memory, 0, 8 * PAGE) + PAGE;

    assert_eq!(
        mremap(
            &mut dispatcher,
            &mut memory,
            [
                file,
                4 * PAGE,
                4 * PAGE,
                MREMAP_MAYMOVE | MREMAP_FIXED,
                destination
            ],
        ),
        DispatchOutcome::Returned {
            value: destination as i64
        },
        "a retained private file node moves; it is not EFAULT"
    );
    assert_eq!(root.node(file), None, "the source range is unmapped");
    assert_eq!(memory.read_bytes(destination, 1).unwrap(), [0x51]);
    let moved = root.lock().mapping(destination).unwrap();
    assert_eq!(moved.range.start(), destination);
    assert_eq!(moved.range.end(), destination + 4 * PAGE);
    assert!(!moved.anonymous);
    for page in 0..4 {
        assert_eq!(
            source_bytes(&dispatcher, &root, destination + page * PAGE, 1),
            [page as u8 + 1]
        );
    }
    // Discard at the destination now restores the moved file offset.
    hold_own_gate(&memory, &root);
    assert_eq!(
        madvise(&mut dispatcher, &mut memory, destination + 2 * PAGE, PAGE),
        DispatchOutcome::Returned { value: 0 }
    );
    pwrite_host_file(&dispatcher, FILE_FD, 2 * PAGE, 0x62);
    assert_eq!(
        source_bytes(&dispatcher, &root, destination + 2 * PAGE, 1),
        [0x62]
    );
}

/// Two live processes privately map one shared file description (a
/// fork-inherited fd). One discards and moves its mapping under its own
/// gate; the other's node, bytes and source custody are untouched, and the
/// source stays readable for it after the first unmaps everything.
#[test]
fn two_processes_private_file_edits_keep_each_owner_and_source() {
    let mut first = SyscallDispatcher::new();
    install_host_file_fd(&first, FILE_FD, &pages(4));
    let mut second = SyscallDispatcher::new();
    let shared = first.open_file(FILE_FD).unwrap();
    second
        .captured_file_table()
        .write_open_files(None)
        .insert(FILE_FD, shared);
    let first_root = Root::admit(&first);
    // A second process of the same carrier: its own MM slot and provider.
    let second_root = first_root.publish_child(&second);
    second
        .install_reservation_provider(Arc::new(Provider(first_root.carrier.clone())))
        .unwrap();
    assert_eq!(
        admit(&second, El1AdmissionOrigin::Bind, true),
        Ok(El1Admission::Delegated)
    );
    let mut first_memory = arena_memory();
    let mut second_memory = arena_memory();
    let map = |dispatcher: &mut SyscallDispatcher, memory: &mut CountingMmapMemory| {
        returned(host_mmap(
            dispatcher,
            memory,
            0,
            4 * PAGE,
            RW,
            LINUX_MAP_PRIVATE,
            FILE_FD,
        )) as u64
    };
    let first_map = map(&mut first, &mut first_memory);
    let second_map = map(&mut second, &mut second_memory);
    first_memory.write_bytes(first_map + PAGE, &[0x71]).unwrap();
    second_memory
        .write_bytes(second_map + PAGE, &[0x72])
        .unwrap();
    let second_node = second_root.lock().mapping(second_map).unwrap();

    hold_own_gate(&first_memory, &first_root);
    assert_eq!(
        madvise(&mut first, &mut first_memory, first_map + PAGE, PAGE),
        DispatchOutcome::Returned { value: 0 }
    );
    first_memory.owner_gate.set(None);
    let destination = anon_mmap(&mut first, &mut first_memory, 0, 8 * PAGE) + PAGE;
    assert_eq!(
        returned(mremap(
            &mut first,
            &mut first_memory,
            [
                first_map,
                4 * PAGE,
                4 * PAGE,
                MREMAP_MAYMOVE | MREMAP_FIXED,
                destination
            ],
        )) as u64,
        destination
    );
    assert_eq!(
        second_root.lock().mapping(second_map),
        Some(second_node),
        "the other process's root node is unchanged"
    );
    assert_eq!(
        second_memory.read_bytes(second_map + PAGE, 1).unwrap(),
        [0x72]
    );
    assert_eq!(
        source_bytes(&first, &first_root, destination + PAGE, 1),
        [2],
        "the editing process discarded its own private copy only"
    );
    assert_eq!(
        call(
            &mut first,
            &mut first_memory,
            SYS_MUNMAP,
            [destination, 4 * PAGE, 0, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    first
        .captured_file_table()
        .write_open_files(None)
        .remove(&FILE_FD);
    assert_eq!(
        source_bytes(&second, &second_root, second_map + 2 * PAGE, 1),
        [3],
        "the other process keeps its retained source"
    );
}

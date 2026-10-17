//! Real-backend witnesses for `carrick_el1::substrate::zone_file_service`.
//! Records are created and admitted through Carrick VFS and production
//! admission; the service sees only neutral keys and the region's tables.
mod serial_host {
    use crate::dispatch::fd_table::{HostFdRef, OpenDescription, OpenDescriptionBase, OpenFile};
    use crate::dispatch::fs::FsState;
    use crate::el1_delegation::{
        ALLOCATED_OPEN_FILES, HOST_SERVED, clear_el1_region_host_ptr, delegated_file_object,
        delegation_counts, enter_zone_at_open, open_file_object, owned_recall,
        recall_all_delegated, record_el1_region_host_ptr,
    };
    use crate::kernel::{FileTableId, RlimitSet};
    use carrick_abi::LINUX_O_RDWR;
    use carrick_core::file::{FileOperation, FilePin, FilePinKey, FileService, IoError, WriteAt};
    use carrick_el1::substrate::zone_file_service::{
        ZoneFileService, ZoneFileTables, ZoneFileVenue, ZonePinSlice, ZonePinSlots, ZonePinStorage,
        ZonePinTable,
    };
    use carrick_el1_abi::{
        AdmittedOpenReference, DELEGATED_FLAG_APPEND, DelegatedOpenFile, OpenReferenceKey,
        OpenReferenceWork, SlotId, get_el1_region_host_ptr,
    };
    use std::cell::Cell;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    struct Region {
        _lock: parking_lot::MutexGuard<'static, ()>,
        _buffer: Box<carrick_test_support::TestEl1Region>,
    }
    impl Region {
        fn new() -> Self {
            let lock = TEST_LOCK.lock();
            let buffer = carrick_test_support::TestEl1Region::zeroed();
            record_el1_region_host_ptr(buffer.as_ptr() as usize);
            Self {
                _lock: lock,
                _buffer: buffer,
            }
        }
        fn tables(&self) -> ZoneFileTables<'_> {
            // SAFETY: the region is retained and recorded for the borrow.
            unsafe { ZoneFileTables::at_region(self._buffer.as_ptr() as usize) }
        }
    }
    impl Drop for Region {
        fn drop(&mut self) {
            recall_all_delegated();
            clear_el1_region_host_ptr();
        }
    }

    #[derive(Default)]
    struct Venue {
        terminal: Cell<usize>,
        last: Cell<Option<OpenReferenceKey>>,
        records_observed: Cell<u64>,
        cas_observed: Cell<u64>,
    }
    impl ZoneFileVenue for Venue {
        fn terminal_queued(&self, key: OpenReferenceKey) {
            self.terminal.set(self.terminal.get() + 1);
            self.last.set(Some(key));
        }
        fn observe_record(&self, _handle: u32, work: OpenReferenceWork) {
            self.records_observed.set(self.records_observed.get() + 1);
            self.cas_observed
                .set(self.cas_observed.get() + work.cas_attempts);
        }
    }

    /// Counting storage wrapper over [`ZonePinSlots`] that counts every slot
    /// probe made by [`ZoneFileService`] during allocation or key resolution.
    struct CountingPinSlots<const N: usize> {
        inner: ZonePinSlots<N>,
        slots_observed: Cell<u64>,
    }
    impl<const N: usize> CountingPinSlots<N> {
        fn new() -> Self {
            Self {
                inner: ZonePinSlots::<N>::new(),
                slots_observed: Cell::new(0),
            }
        }
        fn slots_observed(&self) -> u64 {
            self.slots_observed.get()
        }
    }
    impl<const N: usize> ZonePinStorage for CountingPinSlots<N> {
        fn pin_slice(&self) -> &ZonePinSlice {
            self.inner.as_slice()
        }
        fn pin_slice_mut(&mut self) -> &mut ZonePinSlice {
            self.inner.as_slice_mut()
        }
        fn observe_slot(&self, _index: usize) {
            self.slots_observed.set(self.slots_observed.get() + 1);
        }
    }

    /// One mounted host root; every open goes through production VFS open
    /// and admission, and holds its own host description reference.
    struct Root {
        scratch: tempfile::TempDir,
        fs: FsState,
    }
    struct Admitted {
        open: OpenFile,
        admitted: AdmittedOpenReference,
        closed: Cell<bool>,
    }
    impl Admitted {
        fn admitted(&self) -> AdmittedOpenReference {
            self.admitted
        }
        fn key(&self) -> OpenReferenceKey {
            self.admitted.key()
        }
        fn handle(&self) -> u32 {
            self.admitted.handle()
        }
        fn record(&self) -> &'static DelegatedOpenFile {
            open_file_object(get_el1_region_host_ptr(), self.handle())
        }
        fn close_host(&self) {
            assert!(!self.closed.replace(true));
            self.open.description.release_fd_ref();
        }
    }
    impl Drop for Admitted {
        fn drop(&mut self) {
            if !self.closed.get() {
                self.open.description.release_fd_ref();
            }
        }
    }
    impl Root {
        fn new() -> Self {
            let scratch = tempfile::tempdir().unwrap();
            let backend =
                carrick_vfs::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
            let mut root = carrick_vfs::RootFsVfs::new();
            drop(root.set_overlay(Box::new(backend)));
            let mut fs = FsState::new_with_host_resolver(None);
            fs.rootfs_vfs = Arc::new(root);
            Self { scratch, fs }
        }
        /// VFS open (`create` makes the file) followed by production admission.
        fn admit(&self, path: &str, create: bool, fd: i32) -> Admitted {
            if create {
                self.fs.rootfs_vfs.create_file(path).unwrap();
            }
            let carrick_vfs::vfs::rootfs::OpenDispatchResult::HostFile {
                host_fd,
                metadata,
                writable,
            } = self
                .fs
                .rootfs_vfs
                .open_for_dispatch(path, false, false, false, true)
                .unwrap()
            else {
                panic!("the fixture must use the real host VFS backend");
            };
            let description = crate::dispatch::fd_table::kernel_file_description(
                Arc::new(parking_lot::RwLock::new(OpenDescription::HostFile {
                    base: OpenDescriptionBase::new(LINUX_O_RDWR),
                    host_fd: HostFdRef::new(host_fd),
                    metadata,
                    writable,
                })),
                LINUX_O_RDWR,
            );
            description.retain_fd_ref();
            let open = OpenFile::new(description, 0);
            enter_zone_at_open(
                &open,
                FileTableId::from_raw_u64(1).unwrap(),
                fd,
                &self.fs,
                Some(&RlimitSet::carrick_defaults()),
                None,
            )
            .unwrap();
            let admitted = open.description.admitted_open_reference().unwrap();
            Admitted {
                open,
                admitted,
                closed: Cell::new(false),
            }
        }
        fn host_bytes(&self, name: &str) -> Vec<u8> {
            std::fs::read(self.scratch.path().join(name)).unwrap()
        }
    }

    fn service<'a, 's, S: ZonePinStorage + ?Sized>(
        region: &'a Region,
        venue: &'a Venue,
        pins: &'a mut ZonePinTable<'s, S>,
    ) -> ZoneFileService<'a, 's, Venue, S> {
        ZoneFileService::new(region.tables(), SlotId::new(0), venue, pins)
    }
    fn ready<T>(op: FileOperation<T>) -> Result<T, IoError> {
        match op {
            FileOperation::Ready(result) => result,
            FileOperation::Pending(_) => panic!("resident zone work never suspends"),
        }
    }
    fn read<S: ZonePinStorage + ?Sized>(
        svc: &mut ZoneFileService<'_, '_, Venue, S>,
        pin: &FilePin,
        at: u64,
        len: usize,
    ) -> Vec<u8> {
        let mut buf = vec![0; len];
        let n = ready(svc.read_at(pin, at, &mut buf)).unwrap();
        buf.truncate(n);
        buf
    }
    fn replay(key: FilePinKey) -> FilePin {
        FilePin::from_backend(key)
    }
    /// Retire every pinned record and its inode through the host drain.
    fn retire(admitted: &[&Admitted]) {
        owned_recall::test_drain_external();
        for open in admitted {
            assert!(owned_recall::wait_for_open_retirement(open.handle()));
            assert!(owned_recall::wait_for_cleanup_bounded(
                open.open.description.el1_identity().unwrap()
            ));
        }
    }

    #[test]
    fn zone_file_create_write_read_two_live_pins_are_coherent_and_preserve_cursors() {
        let region = Region::new();
        let root = Root::new();
        let a = root.admit("/data", true, 3);
        let b = root.admit("/data", false, 4);
        assert_eq!(
            a.record().inode_handle.load(Ordering::Acquire),
            b.record().inode_handle.load(Ordering::Acquire)
        );
        let venue = Venue::default();
        let mut slots = ZonePinSlots::<4>::new();
        let mut pins = ZonePinTable::new(&mut slots).unwrap();
        let mut svc = service(&region, &venue, &mut pins);
        let pa = svc.pin_admitted(a.admitted()).unwrap();
        let pb = svc.pin_admitted(b.admitted()).unwrap();
        a.close_host();
        b.close_host();
        let (cursor_a, cursor_b) = (
            a.record().offset.load(Ordering::Acquire),
            b.record().offset.load(Ordering::Acquire),
        );
        let (recalls, served) = (
            delegation_counts().recalls,
            HOST_SERVED.load(Ordering::Acquire),
        );
        assert_eq!(
            ready(svc.write_at(&pa, WriteAt::Offset(0), b"hello")),
            Ok(5)
        );
        assert_eq!(read(&mut svc, &pb, 0, 16), b"hello");
        assert_eq!(ready(svc.write_at(&pb, WriteAt::Offset(3), b"p!")), Ok(2));
        assert_eq!(read(&mut svc, &pa, 0, 16), b"help!");
        assert_eq!(ready(svc.attributes(&pa)).unwrap().len, 5);
        assert_eq!(ready(svc.attributes(&pb)).unwrap().len, 5);
        // EOF: exact and beyond return zero; a short read returns the rest.
        assert_eq!(read(&mut svc, &pa, 5, 4), b"");
        assert_eq!(read(&mut svc, &pb, 100, 4), b"");
        assert_eq!(read(&mut svc, &pa, 2, 10), b"lp!");
        assert_eq!(svc.last_work().bytes_moved, 3);
        assert_eq!(a.record().offset.load(Ordering::Acquire), cursor_a);
        assert_eq!(b.record().offset.load(Ordering::Acquire), cursor_b);
        assert_eq!(delegation_counts().recalls, recalls);
        assert_eq!(HOST_SERVED.load(Ordering::Acquire), served);
        // Retiring one consumer's record leaves the other's authority intact.
        assert_eq!(ready(svc.release(pa)), Ok(()));
        assert_eq!(venue.terminal.get(), 1);
        assert_eq!(venue.last.get(), Some(a.key()));
        owned_recall::test_drain_external();
        assert!(owned_recall::wait_for_open_retirement(a.handle()));
        assert_eq!(read(&mut svc, &pb, 0, 16), b"help!");
        assert_eq!(ready(svc.write_at(&pb, WriteAt::End, b"?")), Ok(1));
        assert_eq!(ready(svc.release(pb)), Ok(()));
        assert_eq!(venue.terminal.get(), 2);
        drop(svc);
        assert_eq!(pins.close(), Ok(()));
        retire(&[&b]);
        assert_eq!(root.host_bytes("data"), b"help!?");
        drop(region);
    }

    #[test]
    fn zone_file_append_across_two_live_pins_never_overwrites() {
        let region = Region::new();
        let root = Root::new();
        let a = root.admit("/log", true, 3);
        let b = root.admit("/log", false, 4);
        let venue = Venue::default();
        let mut slots = ZonePinSlots::<2>::new();
        let mut pins = ZonePinTable::new(&mut slots).unwrap();
        let mut svc = service(&region, &venue, &mut pins);
        let pa = svc.pin_admitted(a.admitted()).unwrap();
        let pb = svc.pin_admitted(b.admitted()).unwrap();
        a.close_host();
        b.close_host();
        let (cursor_a, cursor_b) = (
            a.record().offset.load(Ordering::Acquire),
            b.record().offset.load(Ordering::Acquire),
        );
        for (pin, bytes) in [(&pa, b"aa"), (&pb, b"bb"), (&pa, b"cc"), (&pb, b"dd")] {
            assert_eq!(ready(svc.write_at(pin, WriteAt::End, bytes)), Ok(2));
        }
        assert_eq!(read(&mut svc, &pa, 0, 16), b"aabbccdd");
        assert_eq!(a.record().offset.load(Ordering::Acquire), cursor_a);
        assert_eq!(b.record().offset.load(Ordering::Acquire), cursor_b);
        assert_eq!(ready(svc.release(pa)), Ok(()));
        assert_eq!(ready(svc.release(pb)), Ok(()));
        drop(svc);
        assert_eq!(pins.close(), Ok(()));
        retire(&[&a, &b]);
        assert_eq!(root.host_bytes("log"), b"aabbccdd");
        drop(region);
    }

    /// Unit test for `ZoneFileService`'s positional APPEND flag check only.
    /// Production VFS admission refuses `O_APPEND` descriptions today
    /// (`UnsupportedFlags`), so setting `DELEGATED_FLAG_APPEND` on the record
    /// is a forced unit state and not end-to-end admission evidence (#574,
    /// tied to #384 / F4).
    #[test]
    fn append_contract_unit_with_forced_flag() {
        let region = Region::new();
        let root = Root::new();
        let a = root.admit("/log", true, 3);
        let venue = Venue::default();
        let mut slots = ZonePinSlots::<1>::new();
        let mut pins = ZonePinTable::new(&mut slots).unwrap();
        let mut svc = service(&region, &venue, &mut pins);
        let pin = svc.pin_admitted(a.admitted()).unwrap();
        a.close_host();
        assert_eq!(ready(svc.write_at(&pin, WriteAt::Offset(0), b"aa")), Ok(2));
        a.record()
            .flags
            .fetch_or(DELEGATED_FLAG_APPEND, Ordering::AcqRel);
        assert_eq!(
            ready(svc.write_at(&pin, WriteAt::Offset(0), b"XX")),
            Err(IoError::AccessDenied)
        );
        assert_eq!(ready(svc.write_at(&pin, WriteAt::End, b"bb")), Ok(2));
        a.record()
            .flags
            .fetch_and(!DELEGATED_FLAG_APPEND, Ordering::AcqRel);
        assert_eq!(read(&mut svc, &pin, 0, 16), b"aabb");
        assert_eq!(ready(svc.release(pin)), Ok(()));
        drop(svc);
        assert_eq!(pins.close(), Ok(()));
        retire(&[&a]);
        assert_eq!(root.host_bytes("log"), b"aabb");
        drop(region);
    }

    #[test]
    fn zone_file_replayed_and_foreign_pins_are_stale_and_spare_live_peers() {
        let region = Region::new();
        let root = Root::new();
        let a = root.admit("/data", true, 3);
        let venue = Venue::default();
        let mut slots = ZonePinSlots::<2>::new();
        let mut other_slots = ZonePinSlots::<2>::new();
        let mut pins = ZonePinTable::new(&mut slots).unwrap();
        let mut other_pins = ZonePinTable::new(&mut other_slots).unwrap();
        let mut svc = service(&region, &venue, &mut pins);
        let mut other = service(&region, &venue, &mut other_pins);
        let p1 = svc.pin_admitted(a.admitted()).unwrap();
        let p2 = svc.pin_admitted(a.admitted()).unwrap();
        a.close_host();
        let generation = a.key().incarnation;
        assert_eq!(a.record().lifetime.ring_references(generation), Some(2));
        // A key issued by another service instance names nothing here.
        let foreign = other.pin_admitted(a.admitted()).unwrap();
        assert_eq!(a.record().lifetime.ring_references(generation), Some(3));
        assert_eq!(
            ready(svc.write_at(&foreign, WriteAt::Offset(0), b"x")),
            Err(IoError::Stale)
        );
        assert_eq!(
            ready(svc.release(replay(foreign.key()))),
            Err(IoError::Stale)
        );
        assert_eq!(ready(other.release(foreign)), Ok(()));
        assert_eq!(a.record().lifetime.ring_references(generation), Some(2));
        // A replay of a released key cannot consume the live peer's reference.
        let released = p1.key();
        assert_eq!(ready(svc.release(p1)), Ok(()));
        assert_eq!(ready(svc.release(replay(released))), Err(IoError::Stale));
        // The slot is reused under a new generation; the old key stays dead.
        let reused = svc.pin_admitted(a.admitted()).unwrap();
        assert_ne!(reused.key(), released);
        assert_eq!(
            ready(svc.attributes(&replay(released))),
            Err(IoError::Stale)
        );
        assert_eq!(a.record().lifetime.ring_references(generation), Some(2));
        assert_eq!(venue.terminal.get(), 0);
        assert_eq!(ready(svc.write_at(&p2, WriteAt::Offset(0), b"ok")), Ok(2));
        assert_eq!(ready(svc.release(reused)), Ok(()));
        assert_eq!(ready(svc.release(p2)), Ok(()));
        assert_eq!(venue.terminal.get(), 1);
        assert_eq!(venue.last.get(), Some(a.key()));
        drop((svc, other));
        assert_eq!(pins.close(), Ok(()));
        assert_eq!(other_pins.close(), Ok(()));
        retire(&[&a]);
        assert_eq!(root.host_bytes("data"), b"ok");
        drop(region);
    }

    #[test]
    fn zone_file_pin_exhaustion_rolls_back_and_retired_handles_refuse_old_keys() {
        let region = Region::new();
        let root = Root::new();
        let a = root.admit("/data", true, 3);
        // Re-admitting the same table index while the record is live is refused.
        assert_eq!(
            unsafe {
                carrick_el1_abi::admit_open_file_in_region(
                    get_el1_region_host_ptr(),
                    (a.handle() - 1) as usize,
                    a.key().incarnation + 1,
                    true,
                )
            },
            None
        );
        let venue = Venue::default();
        let mut slots = ZonePinSlots::<1>::new();
        let mut pins = ZonePinTable::new(&mut slots).unwrap();
        let mut svc = service(&region, &venue, &mut pins);
        let live = svc.pin_admitted(a.admitted()).unwrap();
        a.close_host();
        let old = a.admitted();
        let handle = a.handle();
        assert_eq!(
            svc.pin_admitted(old).err(),
            Some(IoError::CapacityExhausted)
        );
        assert_eq!(
            a.record().lifetime.ring_references(old.incarnation()),
            Some(1)
        );
        assert_eq!(ready(svc.write_at(&live, WriteAt::End, b"kept")), Ok(4));
        let released = live.key();
        assert_eq!(ready(svc.release(live)), Ok(()));
        assert_eq!(venue.terminal.get(), 1);
        retire(&[&a]);
        assert!(!ALLOCATED_OPEN_FILES.lock()[handle as usize - 1].allocated);
        assert_eq!(root.host_bytes("data"), b"kept");
        // The handle is reused by a new admission; old keys name nothing.
        let next = root.admit("/next", true, 4);
        assert_eq!(next.handle(), handle);
        assert_eq!(svc.pin_admitted(old).err(), Some(IoError::Stale));
        assert_eq!(ready(svc.release(replay(released))), Err(IoError::Stale));
        let pin = svc.pin_admitted(next.admitted()).unwrap();
        assert_eq!(read(&mut svc, &pin, 0, 8), b"");
        assert_eq!(ready(svc.release(pin)), Ok(()));
        assert_eq!(venue.terminal.get(), 1);
        drop(svc);
        assert_eq!(pins.close(), Ok(()));
        drop(next);
        drop(region);
    }

    fn run_population_witness<const N: usize>() {
        let region = Region::new();
        let root = Root::new();
        let mut admitted = Vec::with_capacity(N);
        for i in 0..N {
            admitted.push(root.admit("/data", i == 0, 3 + i as i32));
            assert_eq!(admitted[i].handle(), (i + 1) as u32);
        }
        let venue = Venue::default();
        let mut slots = CountingPinSlots::<N>::new();
        let mut pins = Vec::with_capacity(N);
        {
            let mut table = ZonePinTable::new(&mut slots).unwrap();
            let mut svc = service(&region, &venue, &mut table);
            for (idx, target) in admitted.iter().enumerate() {
                let before_rec = venue.records_observed.get();
                let before_cas = venue.cas_observed.get();
                pins.push(svc.pin_admitted(target.admitted()).unwrap());
                assert_eq!(venue.records_observed.get() - before_rec, 1);
                assert_eq!(venue.cas_observed.get() - before_cas, 1);
                assert_eq!(svc.last_work().cas_attempts, 1);
                assert_eq!(svc.last_work().records_visited, 1);
                assert_eq!(svc.last_work().slots_visited, 1);
                assert_eq!(
                    target
                        .record()
                        .lifetime
                        .ring_references(target.key().incarnation),
                    Some(1)
                );
                let _ = idx;
            }
        }
        assert_eq!(slots.slots_observed(), N as u64);

        // Vacate a slot in the middle while `N - 1` distinct records remain
        // pinned, then re-allocate and perform positional I/O on the last slot
        // to prove O(1) slot/record work under full table occupancy through the
        // test's CountingPinSlots and Venue wrappers.
        let mid = N / 2;
        let mid_target = &admitted[mid];
        let old_mid = pins.remove(mid);
        {
            let mut table = ZonePinTable::new(&mut slots).unwrap();
            let mut svc = service(&region, &venue, &mut table);
            let before_rec = venue.records_observed.get();
            let before_cas = venue.cas_observed.get();
            assert_eq!(ready(svc.release(old_mid)), Ok(()));
            assert_eq!(venue.records_observed.get() - before_rec, 1);
            assert_eq!(venue.cas_observed.get() - before_cas, 1);
            assert_eq!(svc.last_work().cas_attempts, 1);
            assert_eq!(svc.last_work().records_visited, 1);
            assert_eq!(svc.last_work().slots_visited, 1);
        }
        assert_eq!(slots.slots_observed(), N as u64 + 1);

        let new_mid = {
            let mut table = ZonePinTable::new(&mut slots).unwrap();
            let mut svc = service(&region, &venue, &mut table);
            let before_rec = venue.records_observed.get();
            let before_cas = venue.cas_observed.get();
            let pin = svc.pin_admitted(mid_target.admitted()).unwrap();
            assert_eq!(venue.records_observed.get() - before_rec, 1);
            assert_eq!(venue.cas_observed.get() - before_cas, 1);
            assert_eq!(svc.last_work().cas_attempts, 1);
            assert_eq!(svc.last_work().records_visited, 1);
            assert_eq!(svc.last_work().slots_visited, 1);
            pin
        };
        assert_eq!(slots.slots_observed(), N as u64 + 2);
        pins.insert(mid, new_mid);

        for open in &admitted {
            open.close_host();
        }

        {
            let mut table = ZonePinTable::new(&mut slots).unwrap();
            let mut svc = service(&region, &venue, &mut table);
            let tail = &pins[N - 1];
            let before_rec = venue.records_observed.get();
            assert_eq!(ready(svc.write_at(tail, WriteAt::Offset(0), b"ok")), Ok(2));
            assert_eq!(venue.records_observed.get() - before_rec, 1);
            assert_eq!(svc.last_work().records_visited, 1);
            assert_eq!(svc.last_work().slots_visited, 1);
            let before_rec = venue.records_observed.get();
            assert_eq!(read(&mut svc, tail, 0, 2), b"ok");
            assert_eq!(venue.records_observed.get() - before_rec, 1);
            assert_eq!(svc.last_work().records_visited, 1);
            assert_eq!(svc.last_work().slots_visited, 1);
        }
        assert_eq!(slots.slots_observed(), N as u64 + 4);

        {
            let mut table = ZonePinTable::new(&mut slots).unwrap();
            let mut svc = service(&region, &venue, &mut table);
            for pin in pins {
                let before_rec = venue.records_observed.get();
                let before_cas = venue.cas_observed.get();
                assert_eq!(ready(svc.release(pin)), Ok(()));
                assert_eq!(venue.records_observed.get() - before_rec, 1);
                assert_eq!(venue.cas_observed.get() - before_cas, 1);
                assert_eq!(svc.last_work().cas_attempts, 1);
                assert_eq!(svc.last_work().records_visited, 1);
                assert_eq!(svc.last_work().slots_visited, 1);
            }
            drop(svc);
            assert_eq!(table.close(), Ok(()));
        }
        assert_eq!(slots.slots_observed(), 2 * N as u64 + 4);
        assert_eq!(venue.terminal.get(), N);
        let refs: Vec<&Admitted> = admitted.iter().collect();
        retire(&refs);
        drop(region);
    }

    #[test]
    fn zone_file_pin_release_visits_one_record_at_each_population() {
        run_population_witness::<1>();
        run_population_witness::<16>();
        run_population_witness::<512>();
    }

    #[test]
    fn zone_file_positional_io_visits_only_touched_pages_and_bytes() {
        const PAGE: usize = 4096;
        for span in [0usize, 4096, 65536] {
            let region = Region::new();
            let root = Root::new();
            let sentinel = vec![0x5a; PAGE + 65536 + PAGE];
            std::fs::write(root.scratch.path().join("data"), &sentinel).unwrap();
            let a = root.admit("/data", false, 3);
            let inode = a.record().inode_handle.load(Ordering::Acquire);
            let object = delegated_file_object(get_el1_region_host_ptr(), inode);
            assert_eq!(object.dirty_mask.load(Ordering::Acquire), 0);
            let venue = Venue::default();
            let mut slots = ZonePinSlots::<1>::new();
            let mut pins = ZonePinTable::new(&mut slots).unwrap();
            let mut svc = service(&region, &venue, &mut pins);
            let pin = svc.pin_admitted(a.admitted()).unwrap();
            a.close_host();
            let bytes = vec![0xa5; span];
            assert_eq!(
                ready(svc.write_at(&pin, WriteAt::Offset(PAGE as u64), &bytes)),
                Ok(span)
            );
            assert_eq!(svc.last_work().bytes_moved, span);
            let pages = (span / PAGE) as u32;
            let touched = if pages == 0 {
                0
            } else {
                (u64::MAX >> (64 - pages)) << 1
            };
            assert_eq!(object.dirty_mask.load(Ordering::Acquire), touched);
            assert_eq!(read(&mut svc, &pin, PAGE as u64, span), bytes);
            assert_eq!(svc.last_work().bytes_moved, span);
            let mut expected = sentinel.clone();
            expected[PAGE..PAGE + span].copy_from_slice(&bytes);
            assert_eq!(read(&mut svc, &pin, 0, expected.len()), expected);
            assert_eq!(ready(svc.release(pin)), Ok(()));
            drop(svc);
            assert_eq!(pins.close(), Ok(()));
            retire(&[&a]);
            assert_eq!(root.host_bytes("data"), expected);
            drop(region);
        }
    }

    #[test]
    fn zone_file_marked_inode_queues_read_and_write_events_and_refuses_busy_or_spilled_watches() {
        let region = Region::new();
        let root = Root::new();
        let a = root.admit("/watched", true, 3);
        let inode_handle = a.record().inode_handle.load(Ordering::Acquire);
        let region_ptr = get_el1_region_host_ptr();
        let inotify_ptr = (region_ptr + carrick_el1_abi::EL1_INOTIFY_TABLE_OFFSET as usize)
            as *const carrick_el1_abi::DelegatedInotify;
        let inotify = unsafe { &*inotify_ptr };
        inotify.reset_queue();
        inotify
            .state
            .store(carrick_el1_abi::DELEGATED_STATE_GUEST, Ordering::Release);
        assert!(crate::el1_delegation::attach_zone_watch(
            inode_handle,
            1,
            inotify,
            7,
            0x01 | 0x02,
        ));
        let venue = Venue::default();
        let mut slots = ZonePinSlots::<1>::new();
        let mut pins = ZonePinTable::new(&mut slots).unwrap();
        let mut svc = service(&region, &venue, &mut pins);
        let pin = svc.pin_admitted(a.admitted()).unwrap();
        a.close_host();
        assert_eq!(
            ready(svc.write_at(&pin, WriteAt::Offset(0), b"hello")),
            Ok(5)
        );
        assert_eq!(inotify.queued_bytes.load(Ordering::Acquire), 16);
        let mut raw = [0u8; 16];
        assert_eq!(inotify.drain_into(&mut raw), Ok(16));
        assert_eq!(i32::from_ne_bytes(raw[0..4].try_into().unwrap()), 7);
        assert_eq!(u32::from_ne_bytes(raw[4..8].try_into().unwrap()), 0x02);
        assert_eq!(read(&mut svc, &pin, 0, 5), b"hello");
        assert_eq!(inotify.queued_bytes.load(Ordering::Acquire), 16);
        assert_eq!(inotify.drain_into(&mut raw), Ok(16));
        assert_eq!(u32::from_ne_bytes(raw[4..8].try_into().unwrap()), 0x01);
        // Zero-byte write and EOF read move no bytes and queue no event.
        assert_eq!(ready(svc.write_at(&pin, WriteAt::Offset(0), b"")), Ok(0));
        assert_eq!(read(&mut svc, &pin, 5, 4), b"");
        assert_eq!(inotify.queued_bytes.load(Ordering::Acquire), 0);
        // A spilled or contended watch instance refuses Unsupported before mutating.
        inotify.spilled.store(1, Ordering::Release);
        assert_eq!(
            ready(svc.write_at(&pin, WriteAt::Offset(0), b"NOPE")),
            Err(IoError::Unsupported)
        );
        inotify.spilled.store(0, Ordering::Release);
        assert!(inotify.host_lock_bounded(1));
        assert_eq!(
            ready(svc.write_at(&pin, WriteAt::Offset(0), b"NOPE")),
            Err(IoError::Unsupported)
        );
        inotify.unlock();
        assert_eq!(read(&mut svc, &pin, 0, 5), b"hello");
        assert_eq!(inotify.drain_into(&mut raw), Ok(16));
        assert_eq!(ready(svc.release(pin)), Ok(()));
        drop(svc);
        assert_eq!(pins.close(), Ok(()));
        retire(&[&a]);
        assert_eq!(root.host_bytes("watched"), b"hello");
        drop(region);
    }

    #[test]
    fn zone_file_drop_and_rebuild_over_same_storage_preserves_live_pins_and_never_overwrites_slot()
    {
        let region = Region::new();
        let root = Root::new();
        let a = root.admit("/a", true, 3);
        let b = root.admit("/b", true, 4);
        let venue = Venue::default();
        let mut slots = ZonePinSlots::<2>::new();
        let pa = {
            let mut pins = ZonePinTable::new(&mut slots).unwrap();
            let mut svc = service(&region, &venue, &mut pins);
            let pa = svc.pin_admitted(a.admitted()).unwrap();
            drop(svc);
            // Closing the table while `pa` is live is refused without losing `pa`.
            assert_eq!(pins.close(), Err(IoError::Stale));
            pa
        };
        a.close_host();
        // Dropping both the service and ZonePinTable wrapper over the same
        // slot storage and rebuilding both recovers the live pin `pa` and
        // allocates `pb` into slot 1 without overwriting slot 0.
        let mut pins = ZonePinTable::new(&mut slots).unwrap();
        assert_eq!(pins.live_pins(), 1);
        let mut svc = service(&region, &venue, &mut pins);
        let pb = svc.pin_admitted(b.admitted()).unwrap();
        assert_eq!(svc.last_work().slots_visited, 1);
        b.close_host();
        assert_eq!(
            a.record().lifetime.ring_references(a.key().incarnation),
            Some(1)
        );
        assert_eq!(
            b.record().lifetime.ring_references(b.key().incarnation),
            Some(1)
        );
        assert_eq!(ready(svc.write_at(&pa, WriteAt::Offset(0), b"one")), Ok(3));
        assert_eq!(ready(svc.write_at(&pb, WriteAt::Offset(0), b"two")), Ok(3));
        assert_eq!(ready(svc.release(pa)), Ok(()));
        assert_eq!(ready(svc.release(pb)), Ok(()));
        assert_eq!(venue.terminal.get(), 2);
        drop(svc);
        assert_eq!(pins.live_pins(), 0);
        assert_eq!(pins.close(), Ok(()));
        retire(&[&a, &b]);
        assert_eq!(root.host_bytes("a"), b"one");
        assert_eq!(root.host_bytes("b"), b"two");
        drop(region);
    }

    #[test]
    fn zone_file_release_queues_terminal_handoff_in_service_region_not_global_pointer() {
        let region = Region::new();
        let other_region = carrick_test_support::TestEl1Region::zeroed();
        let service_region_ptr = region._buffer.as_ptr() as usize;
        let root = Root::new();
        let a = root.admit("/non_global", true, 3);
        let venue = Venue::default();
        let mut slots = ZonePinSlots::<1>::new();
        let mut pins = ZonePinTable::new(&mut slots).unwrap();
        let mut svc = service(&region, &venue, &mut pins);
        let pa = svc.pin_admitted(a.admitted()).unwrap();
        a.close_host();
        assert_eq!(
            ready(svc.write_at(&pa, WriteAt::Offset(0), b"region")),
            Ok(6)
        );
        // Point the process-global aperture pointer at a different region before
        // releasing `pa`, proving `ZoneFileService::release` marks the pending
        // handoff in its own `ZoneFileTables` region rather than the global pointer.
        record_el1_region_host_ptr(other_region.as_ptr() as usize);
        assert_eq!(ready(svc.release(pa)), Ok(()));
        assert_eq!(venue.terminal.get(), 1);
        assert_eq!(venue.last.get(), Some(a.key()));
        assert!(
            !unsafe { carrick_el1_abi::pending_at(other_region.as_ptr() as usize) }
                .is_marked(a.handle())
        );
        assert!(unsafe { carrick_el1_abi::pending_at(service_region_ptr) }.is_marked(a.handle()));
        record_el1_region_host_ptr(service_region_ptr);
        owned_recall::test_drain_external_at(service_region_ptr);
        assert!(!unsafe { carrick_el1_abi::pending_at(service_region_ptr) }.is_marked(a.handle()));
        assert!(owned_recall::wait_for_open_retirement(a.handle()));
        assert!(owned_recall::wait_for_cleanup_bounded(
            a.open.description.el1_identity().unwrap()
        ));
        assert_eq!(root.host_bytes("non_global"), b"region");
        drop(svc);
        assert_eq!(pins.close(), Ok(()));
        drop(region);
    }

    #[test]
    fn zone_file_demoted_inode_is_unsupported_while_generation_change_is_stale() {
        let region = Region::new();
        let root = Root::new();
        let a = root.admit("/a", true, 3);
        let b = root.admit("/b", true, 4);
        let venue = Venue::default();
        let mut slots = ZonePinSlots::<2>::new();
        let mut pins = ZonePinTable::new(&mut slots).unwrap();
        let mut svc = service(&region, &venue, &mut pins);
        let pa = svc.pin_admitted(a.admitted()).unwrap();
        let pb = svc.pin_admitted(b.admitted()).unwrap();
        a.close_host();
        b.close_host();
        crate::el1_delegation::recall_inode(a.open.description.el1_identity().unwrap());
        let mut buf = [0u8; 4];
        assert_eq!(
            ready(svc.read_at(&pa, 0, &mut buf)),
            Err(IoError::Unsupported)
        );
        assert_eq!(
            ready(svc.write_at(&pa, WriteAt::Offset(0), b"x")),
            Err(IoError::Unsupported)
        );
        assert_eq!(ready(svc.attributes(&pa)), Err(IoError::Unsupported));
        let prev_gen = b.record().generation.load(Ordering::Acquire);
        b.record().generation.store(prev_gen + 1, Ordering::Release);
        let stale_read = ready(svc.read_at(&pb, 0, &mut buf));
        let stale_write = ready(svc.write_at(&pb, WriteAt::Offset(0), b"y"));
        let stale_attr = ready(svc.attributes(&pb));
        b.record().generation.store(prev_gen, Ordering::Release);
        assert_eq!(stale_read, Err(IoError::Stale));
        assert_eq!(stale_write, Err(IoError::Stale));
        assert_eq!(stale_attr, Err(IoError::Stale));
        assert_eq!(ready(svc.release(pa)), Ok(()));
        assert_eq!(ready(svc.release(pb)), Ok(()));
        drop(svc);
        assert_eq!(pins.close(), Ok(()));
        retire(&[&b]);
        drop(region);
    }
}

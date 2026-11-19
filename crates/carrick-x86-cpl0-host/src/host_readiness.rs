//! CPL0 carrier witnesses for the shared host-readiness crossing.

mod tests {
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    use carrick_el1_abi::{
        HostBoundFd, HostObjectBinding, HostReadinessCrossing, HostReadinessEntry,
    };
    use carrick_guest_arch::KernelVa;
    use carrick_kernel::dispatch::StdioReadiness;
    use carrick_kernel::host_readiness::{
        BoundHostFds, HostReadinessStep, ReadinessCrossing, ReadinessWait, sample_entries,
    };
    use std::os::fd::FromRawFd;

    fn frame(mask_kind: u64, timeout: u64) -> [u64; 7] {
        [
            HostReadinessCrossing::NUMBER,
            HostReadinessCrossing::FRAME_TAG,
            0x1000,
            3,
            timeout,
            1 << 9,
            mask_kind,
        ]
    }

    fn entry(fd: usize, events: i16) -> HostReadinessEntry {
        HostReadinessEntry {
            binding: [
                HostObjectBinding::STDIN,
                HostObjectBinding::STDOUT,
                HostObjectBinding::STDERR,
            ][fd],
            events,
            revents: 0,
            poll_index: 0,
        }
    }

    #[test]
    fn decode_routes_only_tagged_crossings_and_refuses_malformed_ones() {
        let now = Instant::now();
        let no_clock = || panic!("no timeout clock needed");
        let mut untagged = frame(HostReadinessCrossing::MASK_NONE, 0);
        untagged[1] = 0x40_1000;
        assert_eq!(
            ReadinessCrossing::decode(untagged, no_clock).unwrap(),
            ReadinessCrossing::Other
        );
        assert_eq!(
            ReadinessCrossing::decode(frame(7, 0), no_clock).unwrap(),
            ReadinessCrossing::Refused(carrick_abi::LINUX_EINVAL)
        );
        assert_eq!(
            ReadinessCrossing::decode(frame(HostReadinessCrossing::MASK_NONE, 1 << 40), no_clock)
                .unwrap(),
            ReadinessCrossing::Refused(carrick_abi::LINUX_EINVAL)
        );
        let ReadinessCrossing::Request(request) =
            ReadinessCrossing::decode(frame(HostReadinessCrossing::MASK_REPLACE, 250), || now)
                .unwrap()
        else {
            panic!("tagged crossing")
        };
        assert_eq!((request.address, request.count), (KernelVa::new(0x1000), 3));
        assert_eq!(
            request.sig_mask,
            carrick_abi::WaitSigMask::Replace(carrick_abi::SigSet::from_raw(1 << 9))
        );
        assert_eq!(
            request.wait(now),
            ReadinessWait::Until(Some(Duration::from_millis(250)))
        );
        assert_eq!(
            request.wait(now + Duration::from_millis(250)),
            ReadinessWait::Expired
        );
        let ReadinessCrossing::Request(forever) = ReadinessCrossing::decode(
            frame(HostReadinessCrossing::MASK_NONE, (-1i64) as u64),
            no_clock,
        )
        .unwrap() else {
            panic!("tagged crossing")
        };
        assert_eq!(forever.wait(now), ReadinessWait::Until(None));
    }

    /// Rust std's startup probe: `poll` fds 0-2 with no events and a zero
    /// timeout. Open descriptors report nothing; a closed one `POLLNVAL`.
    #[test]
    fn stdio_sample_reports_open_and_closed_descriptors() {
        let bound = BoundHostFds::from_stdio([
            None,
            Some(StdioReadiness::AlwaysWritable),
            Some(StdioReadiness::AlwaysWritable),
        ])
        .unwrap();
        let mut entries = [entry(0, 0), entry(1, 0), entry(2, 0)];
        assert_eq!(
            sample_entries(&mut entries, &bound).unwrap(),
            HostReadinessStep::Ready(1)
        );
        assert_eq!(entries.map(|entry| entry.revents), [libc::POLLNVAL, 0, 0]);
        let mut writable = [entry(1, libc::POLLOUT)];
        assert_eq!(
            sample_entries(&mut writable, &bound).unwrap(),
            HostReadinessStep::Ready(1)
        );
        assert_eq!(writable[0].revents, libc::POLLOUT);
    }

    /// A host-bound stdin with nothing to read is sampled through the
    /// table's own duplicate, and a wait watches that duplicate.
    #[test]
    fn an_idle_host_stdin_asks_to_wait_on_its_duplicate() {
        let mut pipe = [0; 2];
        // SAFETY: `pipe` is a live two-element array.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        // SAFETY: both ends were just created and are owned here.
        let (read, _write) =
            unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
        let bound = BoundHostFds::from_stdio([
            Some(StdioReadiness::Host(
                HostBoundFd::new(read.as_raw_fd()).unwrap(),
            )),
            None,
            None,
        ])
        .unwrap();
        let mut entries = [entry(0, libc::POLLIN)];
        let HostReadinessStep::Wait(fds) = sample_entries(&mut entries, &bound).unwrap() else {
            panic!("an empty pipe is not readable")
        };
        assert_eq!(fds.len(), 1);
        assert_ne!(fds[0].0.raw(), read.as_raw_fd());
        assert_eq!(entries[0].revents, 0);
    }
}

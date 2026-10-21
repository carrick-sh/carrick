use carrick_guest_arch::UserVa;
use carrick_personality_linux::{
    dispatch::{Family, FamilyCompletion, route_x86},
    sched::{SchedCall, SchedVenue, serve_sched},
};

#[test]
fn x86_native_sched_yield_uses_canonical_in_ring_completion() {
    // x86 native ordinal 24 is translated to canonical ordinal 124.
    assert_eq!(route_x86(124, 0), Family::Sched(SchedCall::Yield));
    let mut venue = Venue {
        pid: 0,
        exists: None,
        copies: false,
    };
    assert_eq!(
        serve_sched(SchedCall::Yield, &mut venue),
        FamilyCompletion::Complete(0)
    );
}

struct Venue {
    pid: u64,
    exists: Option<bool>,
    copies: bool,
}
impl SchedVenue for Venue {
    fn argument(&self, index: usize) -> u64 {
        if index == 0 { self.pid } else { 4096 }
    }
    fn current_pid(&self) -> Option<u32> {
        Some(1)
    }
    fn pid_exists(&self, pid: u32) -> Option<bool> {
        if pid == 1 { Some(true) } else { self.exists }
    }
    fn copy_out(&mut self, _: UserVa, _: &[u8]) -> bool {
        self.copies
    }
    fn copy_in(&mut self, _: UserVa, _: &mut [u8]) -> bool {
        self.copies
    }
    fn guest_cpu_count(&self) -> usize {
        carrick_core::affinity::MAX_GUEST_CPUS
    }

    fn get_affinity(
        &self,
        _: u32,
    ) -> Result<carrick_core::affinity::CpuAffinity, carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LINUX_ESRCH)
    }
    fn set_affinity(
        &mut self,
        _: u32,
        _: carrick_core::affinity::CpuAffinity,
    ) -> Result<carrick_core::affinity::CpuAffinity, carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LINUX_ESRCH)
    }
}
#[test]
fn unavailable_copy_declines_instead_of_inventing_efault() {
    let mut venue = Venue {
        pid: 0,
        exists: None,
        copies: false,
    };
    assert_eq!(
        serve_sched(SchedCall::RrGetInterval, &mut venue),
        FamilyCompletion::Forward
    );
}

#[test]
fn existing_child_and_absent_pid_use_the_namespace_authority() {
    for (exists, expected) in [
        (Some(true), FamilyCompletion::Complete(0)),
        (Some(false), FamilyCompletion::Complete(-3)),
        (None, FamilyCompletion::Forward),
    ] {
        let mut venue = Venue {
            pid: 72,
            exists,
            copies: true,
        };
        assert_eq!(serve_sched(SchedCall::RrGetInterval, &mut venue), expected);
    }
}

struct AffinityVenue {
    args: [u64; 3],
    affinity: carrick_core::affinity::CpuAffinity,
    in_buf: [u8; 128],
    out_buf: [u8; 128],
    out_len: usize,
    esrch: bool,
    ncpu: usize,
    copy_fail: bool,
    current_cpu: Option<u32>,
}

impl Default for AffinityVenue {
    fn default() -> Self {
        Self {
            args: [0; 3],
            affinity: carrick_core::affinity::CpuAffinity::default(),
            in_buf: [0; 128],
            out_buf: [0; 128],
            out_len: 0,
            esrch: false,
            ncpu: 64,
            copy_fail: false,
            current_cpu: None,
        }
    }
}

impl SchedVenue for AffinityVenue {
    fn argument(&self, index: usize) -> u64 {
        self.args.get(index).copied().unwrap_or(0)
    }
    fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool {
        if self.copy_fail || dst.raw() == 0 {
            return false;
        }
        let n = src.len().min(self.out_buf.len());
        self.out_buf[..n].copy_from_slice(&src[..n]);
        self.out_len = n;
        true
    }
    fn copy_in(&mut self, src: UserVa, dst: &mut [u8]) -> bool {
        if self.copy_fail || (!dst.is_empty() && src.raw() == 0) {
            return false;
        }
        let n = dst.len().min(self.in_buf.len());
        dst[..n].copy_from_slice(&self.in_buf[..n]);
        true
    }
    fn guest_cpu_count(&self) -> usize {
        self.ncpu
    }

    fn current_cpu(&self) -> Option<u32> {
        self.current_cpu
    }
    fn get_affinity(
        &self,
        _pid: u32,
    ) -> Result<carrick_core::affinity::CpuAffinity, carrick_syscall_abi::LinuxErrno> {
        if self.esrch {
            Err(carrick_syscall_abi::LINUX_ESRCH)
        } else {
            Ok(self.affinity)
        }
    }
    fn set_affinity(
        &mut self,
        _pid: u32,
        mask: carrick_core::affinity::CpuAffinity,
    ) -> Result<carrick_core::affinity::CpuAffinity, carrick_syscall_abi::LinuxErrno> {
        if self.esrch {
            Err(carrick_syscall_abi::LINUX_ESRCH)
        } else {
            let online = carrick_core::affinity::CpuAffinity::all(self.ncpu);
            let effective = carrick_core::affinity::compute_effective_affinity(&mask, &online)
                .ok_or(carrick_syscall_abi::LINUX_EINVAL)?;
            self.affinity = effective;
            Ok(effective)
        }
    }
}

#[test]
fn sched_getaffinity_validation_and_success() {
    for (args, copy_fail, esrch, expected) in [
        ([0, 4, 0x1000], false, false, -22),  // short GET
        ([0, 8, 0], false, false, -14),       // null output
        ([0, 8, 0x1000], true, false, -14),   // failed copy-out
        ([9999, 8, 0x1000], false, true, -3), // absent thread
        ([0, 8, 0x1000], false, false, 8),
    ] {
        let mut venue = AffinityVenue {
            args,
            copy_fail,
            esrch,
            affinity: carrick_core::affinity::CpuAffinity::single(1),
            ..Default::default()
        };
        assert_eq!(
            serve_sched(SchedCall::GetAffinity, &mut venue),
            FamilyCompletion::Complete(expected),
            "args={args:?}, copy_fail={copy_fail}"
        );
        if expected == 8 {
            assert_eq!(venue.out_len, 8);
            assert_eq!(&venue.out_buf[..8], &2u64.to_le_bytes());
        } else {
            assert_eq!(venue.out_len, 0);
        }
    }
}

#[test]
fn sched_setaffinity_validation_and_success() {
    for (args, mask, ncpu, copy_fail, esrch, errno) in [
        ([0, 0, 0x1000], 0u64, 64, false, false, -22), // empty input
        ([0, 8, 0], 0, 64, false, false, -14),         // null input
        ([0, 8, 0x1000], 0, 64, true, false, -14),     // failed copy-in
        ([0, 8, 0x1000], 0, 64, false, false, -22),    // empty intersection
        ([0, 8, 0x1000], 1 << 5, 4, false, false, -22), // absent CPU
        ([9999, 8, 0x1000], 1, 64, false, true, -3),   // absent thread
    ] {
        let mut venue = AffinityVenue {
            args,
            ncpu,
            copy_fail,
            esrch,
            ..Default::default()
        };
        venue.in_buf[..8].copy_from_slice(&mask.to_le_bytes());
        let before = venue.affinity;
        assert_eq!(
            serve_sched(SchedCall::SetAffinity, &mut venue),
            FamilyCompletion::Complete(errno),
            "args={args:?}, mask={mask}"
        );
        assert_eq!(venue.affinity, before);
    }
    for (size, mask) in [(1, 2u64), (4, 1), (8, 2)] {
        let mut venue = AffinityVenue {
            args: [0, size, 0x1000],
            ncpu: 4,
            ..Default::default()
        };
        venue.in_buf[..8].copy_from_slice(&mask.to_le_bytes());
        assert_eq!(
            serve_sched(SchedCall::SetAffinity, &mut venue),
            FamilyCompletion::Complete(0)
        );
        assert_eq!(venue.affinity.words(), &[mask]);
    }
    let mut venue = AffinityVenue {
        args: [0, 8, 0x1000],
        ncpu: 4,
        current_cpu: Some(0),
        ..Default::default()
    };
    venue.in_buf[..8].copy_from_slice(&2u64.to_le_bytes());
    assert_eq!(
        serve_sched(SchedCall::SetAffinity, &mut venue),
        FamilyCompletion::CompleteWithWork(0)
    );
}

#[test]
fn arm_affinity_ordinals_route_exactly_to_ring_scheduler() {
    use carrick_personality_linux::dispatch::route_aarch64;
    assert_eq!(route_aarch64(122, 0), Family::Sched(SchedCall::SetAffinity));
    assert_eq!(route_aarch64(123, 0), Family::Sched(SchedCall::GetAffinity));
}

#[test]
fn missing_affinity_target_precedes_empty_mask_validation() {
    let mut venue = AffinityVenue {
        args: [9999, 8, 0x1000],
        esrch: true,
        ..Default::default()
    };
    assert_eq!(
        serve_sched(SchedCall::SetAffinity, &mut venue),
        FamilyCompletion::Complete(-3)
    );
}

#[test]
fn missing_getaffinity_target_precedes_null_output() {
    let mut venue = AffinityVenue {
        args: [9999, 8, 0],
        esrch: true,
        ..Default::default()
    };
    assert_eq!(
        serve_sched(SchedCall::GetAffinity, &mut venue),
        FamilyCompletion::Complete(-3)
    );
    assert_eq!(venue.out_len, 0);
}

#[test]
fn empty_setaffinity_never_dereferences_the_mask_pointer() {
    for (pid, expected) in [(0, -22), (9999, -3)] {
        let mut venue = AffinityVenue {
            args: [pid, 0, 0],
            copy_fail: true,
            esrch: pid != 0,
            ..Default::default()
        };
        assert_eq!(
            serve_sched(SchedCall::SetAffinity, &mut venue),
            FamilyCompletion::Complete(expected),
        );
    }
}

#[test]
fn arm_affinity_routes_in_ring_and_x86_stays_unported() {
    for nr in [122, 123] {
        assert_ne!(
            carrick_personality_linux::dispatch::route_aarch64(nr, 0),
            Family::Unported
        );
        assert_eq!(route_x86(nr, 0), Family::Unported);
    }
}

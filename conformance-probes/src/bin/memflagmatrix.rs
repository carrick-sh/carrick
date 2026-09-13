//! Linux memory-management flag and error matrix conformance probe.
//!
//! Compact table-driven matrix covering flag combinations, boundary/alignment
//! errors, and state-transition invariants for:
//!  - mmap(2)
//!  - mprotect(2)
//!  - madvise(2)
//!  - mincore(2)
//!  - mremap(2)
//!
//! Output format: deterministic `key=value` lines diffed line-by-line against
//! the native Linux oracle.

use conformance_probes::{errno, report, run_bounded_bool_child};
use std::ffi::c_void;
use std::time::{Duration, Instant};

const MAP_FIXED_NOREPLACE: i32 = 0x100000;
const MADV_WIPEONFORK: i32 = 18;
const MADV_KEEPONFORK: i32 = 19;
const MREMAP_DONTUNMAP: i32 = 4;
const PARTIAL_DONTFORK_PAGES: usize = 12;
const PARTIAL_DONTFORK_OBSERVATIONS: usize = 4;
const PARTIAL_DONTFORK_EXTRA_OFFSET: usize = 2 + PARTIAL_DONTFORK_OBSERVATIONS * 3;
const PARTIAL_DONTFORK_PACKET_WORDS: usize = PARTIAL_DONTFORK_EXTRA_OFFSET + 7;
const PARTIAL_DONTFORK_TIMEOUT: Duration = Duration::from_secs(2);

fn page_size() -> usize {
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ps > 0 && (ps as usize).is_power_of_two() {
        ps as usize
    } else {
        4096
    }
}

unsafe fn get_unmapped_page(page: usize) -> *mut c_void {
    let p = libc::mmap(
        core::ptr::null_mut(),
        page * 2,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        return core::ptr::null_mut();
    }
    libc::munmap(p, page * 2);
    p
}

unsafe fn run_in_child<F: FnOnce() -> bool>(f: F) -> bool {
    let mut fds = [0i32; 2];
    if libc::pipe(fds.as_mut_ptr()) != 0 {
        return false;
    }
    let pid = libc::fork();
    if pid < 0 {
        libc::close(fds[0]);
        libc::close(fds[1]);
        return false;
    }
    if pid == 0 {
        libc::close(fds[0]);
        let ok = f();
        let val = [ok as u8];
        let _ = libc::write(fds[1], val.as_ptr().cast(), 1);
        libc::close(fds[1]);
        libc::_exit(0);
    }
    libc::close(fds[1]);
    let mut val = [0u8; 1];
    let n = libc::read(fds[0], val.as_mut_ptr().cast(), 1);
    libc::close(fds[0]);
    let mut status = 0;
    while libc::waitpid(pid, &mut status, 0) < 0 {
        if errno() != libc::EINTR {
            break;
        }
    }
    n == 1 && val[0] == 1 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

#[derive(Clone, Copy)]
struct PartialDontforkChild {
    pipe_setup: bool,
    forked: bool,
    fork_errno: i32,
    report_present: bool,
    completed: bool,
    exit: i32,
    signal: i32,
    timed_out: bool,
    packet: [i32; PARTIAL_DONTFORK_PACKET_WORDS],
}

impl Default for PartialDontforkChild {
    fn default() -> Self {
        Self {
            pipe_setup: false,
            forked: false,
            fork_errno: 0,
            report_present: false,
            completed: false,
            exit: -1,
            signal: -1,
            timed_out: false,
            packet: [0; PARTIAL_DONTFORK_PACKET_WORDS],
        }
    }
}

impl PartialDontforkChild {
    fn observation(&self, slot: usize) -> String {
        let offset = 2 + slot * 3;
        format!(
            "rc:{},errno:{},byte_xor_expected:{}",
            self.packet[offset],
            self.packet[offset + 1],
            self.packet[offset + 2]
        )
    }

    fn write_observation(&self) -> i32 {
        self.packet[1]
    }
}

fn partial_dontfork_page_marker(page_index: usize) -> u8 {
    0x20 + page_index as u8
}

unsafe fn reap_partial_dontfork_child(pid: libc::pid_t, deadline: Instant) -> Option<(i32, i32)> {
    loop {
        let mut status = 0;
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid {
            let exit = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            };
            let signal = if libc::WIFSIGNALED(status) {
                libc::WTERMSIG(status)
            } else {
                -1
            };
            return Some((exit, signal));
        }
        if rc == -1 && errno() != libc::EINTR {
            return Some((-1, -1));
        }
        if Instant::now() >= deadline {
            return None;
        }
        libc::usleep(1_000);
    }
}

unsafe fn run_partial_dontfork_child(
    base: *mut u8,
    page: usize,
    observed_pages: [usize; PARTIAL_DONTFORK_OBSERVATIONS],
    write_page: usize,
    zero_expected_page: Option<usize>,
    remap_page: Option<usize>,
    fork_again: bool,
) -> PartialDontforkChild {
    let mut result = PartialDontforkChild::default();
    let mut fds = [0; 2];
    if libc::pipe(fds.as_mut_ptr()) != 0 {
        return result;
    }
    result.pipe_setup = true;

    let pid = libc::fork();
    if pid < 0 {
        result.fork_errno = errno();
        libc::close(fds[0]);
        libc::close(fds[1]);
        return result;
    }
    if pid == 0 {
        libc::close(fds[0]);
        let mut packet = [0i32; PARTIAL_DONTFORK_PACKET_WORDS];
        packet[0] = 1;
        for (slot, page_index) in observed_pages.into_iter().enumerate() {
            let address = base.add(page_index * page);
            let mut residency = [0u8; 1];
            *libc::__errno_location() = 0;
            let rc = libc::mincore(address.cast(), page, residency.as_mut_ptr());
            let observed_errno = if rc == -1 { errno() } else { 0 };
            let observed_byte = if rc == 0 {
                let expected = if zero_expected_page == Some(page_index) {
                    0
                } else {
                    partial_dontfork_page_marker(page_index)
                };
                (*address ^ expected) as i32
            } else {
                -1
            };
            let offset = 2 + slot * 3;
            packet[offset] = rc;
            packet[offset + 1] = observed_errno;
            packet[offset + 2] = observed_byte;
        }
        let write_address = base.add(write_page * page);
        let mut residency = [0u8; 1];
        if libc::mincore(write_address.cast(), page, residency.as_mut_ptr()) == 0 {
            *write_address = 0xd1;
            packet[1] = *write_address as i32;
        } else {
            packet[1] = -1;
        }
        if let Some(remap_page) = remap_page {
            let remap_address = base.add(remap_page * page);
            *libc::__errno_location() = 0;
            let remapped = libc::mmap(
                remap_address.cast(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            );
            packet[PARTIAL_DONTFORK_EXTRA_OFFSET] = i32::from(remapped == libc::MAP_FAILED) * -1;
            packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 1] = if remapped == libc::MAP_FAILED {
                errno()
            } else {
                0
            };
            if remapped != libc::MAP_FAILED {
                *remap_address = 0xe2;
                packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 2] = *remap_address as i32;
                if fork_again {
                    let nested = run_bounded_bool_child(|| {
                        if *remap_address != 0xe2 || *write_address != 0xd1 {
                            return false;
                        }
                        *remap_address = 0xe3;
                        *write_address = 0xd2;
                        *remap_address == 0xe3 && *write_address == 0xd2
                    });
                    packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 3] =
                        i32::from(nested.result == Some(true));
                    packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 4] = i32::from(
                        nested.exit == Some(0) && nested.signal.is_none() && !nested.timed_out,
                    );
                    packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 5] = i32::from(*remap_address == 0xe2);
                    packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 6] = i32::from(*write_address == 0xd1);
                }
            }
        }
        let bytes = core::slice::from_raw_parts(
            packet.as_ptr().cast::<u8>(),
            core::mem::size_of_val(&packet),
        );
        let written = libc::write(fds[1], bytes.as_ptr().cast(), bytes.len());
        libc::close(fds[1]);
        libc::_exit(i32::from(written != bytes.len() as isize));
    }

    result.forked = true;
    libc::close(fds[1]);
    let deadline = Instant::now() + PARTIAL_DONTFORK_TIMEOUT;
    let mut poll_fd = libc::pollfd {
        fd: fds[0],
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            result.timed_out = true;
            break;
        }
        let remaining_ms = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        let rc = libc::poll(&mut poll_fd, 1, remaining_ms);
        if rc > 0 {
            let bytes = core::slice::from_raw_parts_mut(
                result.packet.as_mut_ptr().cast::<u8>(),
                core::mem::size_of_val(&result.packet),
            );
            result.report_present =
                libc::read(fds[0], bytes.as_mut_ptr().cast(), bytes.len()) == bytes.len() as isize;
            break;
        }
        if rc == 0 {
            result.timed_out = true;
            break;
        }
        if errno() != libc::EINTR {
            break;
        }
    }
    libc::close(fds[0]);

    if !result.timed_out {
        if let Some((exit, signal)) = reap_partial_dontfork_child(pid, deadline) {
            result.exit = exit;
            result.signal = signal;
            result.completed = exit == 0 && signal == -1;
            return result;
        }
        result.timed_out = true;
    }

    let _ = libc::kill(pid, libc::SIGKILL);
    let cleanup_deadline = Instant::now() + Duration::from_secs(1);
    if let Some((exit, signal)) = reap_partial_dontfork_child(pid, cleanup_deadline) {
        result.exit = exit;
        result.signal = signal;
    }
    result
}

unsafe fn madvise_observation(address: *mut u8, page: usize, advice: i32) -> (i32, i32) {
    *libc::__errno_location() = 0;
    let rc = libc::madvise(address.cast(), page, advice);
    (rc, if rc == -1 { errno() } else { 0 })
}

fn advice_text(observation: (i32, i32)) -> String {
    format!("rc:{},errno:{}", observation.0, observation.1)
}

unsafe fn test_partial_dontfork_matrix(page: usize) {
    let mapping_len = page * PARTIAL_DONTFORK_PAGES;
    let mapping = libc::mmap(
        core::ptr::null_mut(),
        mapping_len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mapping_setup = mapping != libc::MAP_FAILED;
    let mut granule_setup = false;
    let mut aligned_page = 0usize;
    let mut expected = [0u8; PARTIAL_DONTFORK_PAGES];

    let mut middle_setup = (-1, 0);
    let mut middle_reset = (-1, 0);
    let mut prefix_setup = (-1, 0);
    let mut suffix_setup = (-1, 0);
    let mut prefix_reset = (-1, 0);
    let mut suffix_reset = (-1, 0);
    let mut disjoint_first_setup = (-1, 0);
    let mut disjoint_second_setup = (-1, 0);
    let mut restored_setup = (-1, 0);
    let mut disjoint_final_reset = (-1, 0);
    let mut middle = PartialDontforkChild::default();
    let mut prefix_suffix = PartialDontforkChild::default();
    let mut disjoint = PartialDontforkChild::default();
    let mut restored = PartialDontforkChild::default();
    let mut mixed = PartialDontforkChild::default();
    let mut middle_parent_retained = false;
    let mut middle_parent_cow = false;
    let mut prefix_suffix_parent_retained = false;
    let mut prefix_suffix_parent_cow = false;
    let mut disjoint_parent_retained = false;
    let mut disjoint_parent_cow = false;
    let mut restored_parent_retained = false;
    let mut restored_parent_cow = false;
    let mut mixed_omit_setup = (-1, 0);
    let mut mixed_wipe_setup = (-1, 0);
    let mut mixed_omit_reset = (-1, 0);
    let mut mixed_wipe_reset = (-1, 0);
    let mut mixed_parent_retained = false;
    let mut mixed_parent_cow = false;

    if mapping_setup {
        let base = mapping as *mut u8;
        for (index, expected_byte) in expected.iter_mut().enumerate() {
            *expected_byte = partial_dontfork_page_marker(index);
            *base.add(index * page) = *expected_byte;
        }

        const HOST_GRANULE: usize = 16 * 1024;
        if page == 4096 {
            let delta = (HOST_GRANULE - (base as usize % HOST_GRANULE)) % HOST_GRANULE;
            aligned_page = delta / page;
            granule_setup = aligned_page + 4 <= PARTIAL_DONTFORK_PAGES;
        }

        if granule_setup {
            let middle_hole = aligned_page + 1;
            middle_setup =
                madvise_observation(base.add(middle_hole * page), page, libc::MADV_DONTFORK);
            if middle_setup.0 == 0 {
                middle = run_partial_dontfork_child(
                    base,
                    page,
                    [
                        aligned_page,
                        middle_hole,
                        aligned_page + 2,
                        aligned_page + 3,
                    ],
                    aligned_page,
                    None,
                    None,
                    false,
                );
            }
            middle_parent_retained = expected
                .iter()
                .enumerate()
                .all(|(index, byte)| *base.add(index * page) == *byte);
            middle_parent_cow = middle.completed
                && middle.report_present
                && middle.write_observation() == 0xd1
                && *base.add(aligned_page * page) == expected[aligned_page];
            middle_reset =
                madvise_observation(base.add(middle_hole * page), page, libc::MADV_DOFORK);

            prefix_setup = madvise_observation(base, page, libc::MADV_DONTFORK);
            suffix_setup = madvise_observation(
                base.add((PARTIAL_DONTFORK_PAGES - 1) * page),
                page,
                libc::MADV_DONTFORK,
            );
            if prefix_setup.0 == 0 && suffix_setup.0 == 0 {
                prefix_suffix = run_partial_dontfork_child(
                    base,
                    page,
                    [0, 1, PARTIAL_DONTFORK_PAGES - 2, PARTIAL_DONTFORK_PAGES - 1],
                    1,
                    None,
                    None,
                    false,
                );
            }
            prefix_suffix_parent_retained = expected
                .iter()
                .enumerate()
                .all(|(index, byte)| *base.add(index * page) == *byte);
            prefix_suffix_parent_cow = prefix_suffix.completed
                && prefix_suffix.report_present
                && prefix_suffix.write_observation() == 0xd1
                && *base.add(page) == expected[1];
            prefix_reset = madvise_observation(base, page, libc::MADV_DOFORK);
            suffix_reset = madvise_observation(
                base.add((PARTIAL_DONTFORK_PAGES - 1) * page),
                page,
                libc::MADV_DOFORK,
            );

            let first_hole = aligned_page + 1;
            let second_hole = aligned_page + 3;
            disjoint_first_setup =
                madvise_observation(base.add(first_hole * page), page, libc::MADV_DONTFORK);
            disjoint_second_setup =
                madvise_observation(base.add(second_hole * page), page, libc::MADV_DONTFORK);
            if disjoint_first_setup.0 == 0 && disjoint_second_setup.0 == 0 {
                disjoint = run_partial_dontfork_child(
                    base,
                    page,
                    [first_hole, aligned_page, second_hole, aligned_page + 2],
                    aligned_page,
                    None,
                    None,
                    false,
                );
            }
            disjoint_parent_retained = expected
                .iter()
                .enumerate()
                .all(|(index, byte)| *base.add(index * page) == *byte);
            disjoint_parent_cow = disjoint.completed
                && disjoint.report_present
                && disjoint.write_observation() == 0xd1
                && *base.add(aligned_page * page) == expected[aligned_page];

            restored_setup =
                madvise_observation(base.add(second_hole * page), page, libc::MADV_DOFORK);
            if restored_setup.0 == 0 {
                restored = run_partial_dontfork_child(
                    base,
                    page,
                    [first_hole, aligned_page, second_hole, aligned_page + 2],
                    second_hole,
                    None,
                    None,
                    false,
                );
            }
            restored_parent_retained = expected
                .iter()
                .enumerate()
                .all(|(index, byte)| *base.add(index * page) == *byte);
            restored_parent_cow = restored.completed
                && restored.report_present
                && restored.write_observation() == 0xd1
                && *base.add(second_hole * page) == expected[second_hole];
            disjoint_final_reset =
                madvise_observation(base.add(first_hole * page), page, libc::MADV_DOFORK);

            let mixed_omit = aligned_page + 1;
            let mixed_wipe = aligned_page + 2;
            let mixed_write = aligned_page + 3;
            mixed_omit_setup =
                madvise_observation(base.add(mixed_omit * page), page, libc::MADV_DONTFORK);
            mixed_wipe_setup =
                madvise_observation(base.add(mixed_wipe * page), page, MADV_WIPEONFORK);
            if mixed_omit_setup.0 == 0 && mixed_wipe_setup.0 == 0 {
                mixed = run_partial_dontfork_child(
                    base,
                    page,
                    [aligned_page, mixed_omit, mixed_wipe, mixed_write],
                    mixed_write,
                    Some(mixed_wipe),
                    Some(mixed_omit),
                    true,
                );
            }
            mixed_parent_retained = expected
                .iter()
                .enumerate()
                .all(|(index, byte)| *base.add(index * page) == *byte);
            mixed_parent_cow = mixed.completed
                && mixed.report_present
                && mixed.write_observation() == 0xd1
                && *base.add(mixed_write * page) == expected[mixed_write];
            mixed_omit_reset =
                madvise_observation(base.add(mixed_omit * page), page, libc::MADV_DOFORK);
            mixed_wipe_reset =
                madvise_observation(base.add(mixed_wipe * page), page, MADV_KEEPONFORK);
        }

        libc::munmap(mapping, mapping_len);
    }

    report!(
        madvise_partial_mapping_setup = mapping_setup,
        madvise_partial_4k_inside_aligned_16k_setup = granule_setup,
        madvise_partial_middle_setup = advice_text(middle_setup),
        madvise_partial_middle_pipe_setup = middle.pipe_setup,
        madvise_partial_middle_forked = middle.forked,
        madvise_partial_middle_fork_errno = middle.fork_errno,
        madvise_partial_middle_child_report = middle.report_present && middle.packet[0] == 1,
        madvise_partial_middle_child_completed = middle.completed,
        madvise_partial_middle_child_exit = middle.exit,
        madvise_partial_middle_child_signal = middle.signal,
        madvise_partial_middle_child_timeout = middle.timed_out,
        madvise_partial_middle_prefix = middle.observation(0),
        madvise_partial_middle_hole = middle.observation(1),
        madvise_partial_middle_suffix_first = middle.observation(2),
        madvise_partial_middle_suffix_second = middle.observation(3),
        madvise_partial_middle_child_write = middle.write_observation(),
        madvise_partial_middle_parent_retained = middle_parent_retained,
        madvise_partial_middle_parent_cow_isolated = middle_parent_cow,
        madvise_partial_middle_reset = advice_text(middle_reset),
        madvise_partial_edges_prefix_setup = advice_text(prefix_setup),
        madvise_partial_edges_suffix_setup = advice_text(suffix_setup),
        madvise_partial_edges_pipe_setup = prefix_suffix.pipe_setup,
        madvise_partial_edges_forked = prefix_suffix.forked,
        madvise_partial_edges_fork_errno = prefix_suffix.fork_errno,
        madvise_partial_edges_child_report =
            prefix_suffix.report_present && prefix_suffix.packet[0] == 1,
        madvise_partial_edges_child_completed = prefix_suffix.completed,
        madvise_partial_edges_child_exit = prefix_suffix.exit,
        madvise_partial_edges_child_signal = prefix_suffix.signal,
        madvise_partial_edges_child_timeout = prefix_suffix.timed_out,
        madvise_partial_edges_prefix = prefix_suffix.observation(0),
        madvise_partial_edges_retained_first = prefix_suffix.observation(1),
        madvise_partial_edges_retained_last = prefix_suffix.observation(2),
        madvise_partial_edges_suffix = prefix_suffix.observation(3),
        madvise_partial_edges_child_write = prefix_suffix.write_observation(),
        madvise_partial_edges_parent_retained = prefix_suffix_parent_retained,
        madvise_partial_edges_parent_cow_isolated = prefix_suffix_parent_cow,
        madvise_partial_edges_prefix_reset = advice_text(prefix_reset),
        madvise_partial_edges_suffix_reset = advice_text(suffix_reset),
        madvise_partial_disjoint_first_setup = advice_text(disjoint_first_setup),
        madvise_partial_disjoint_second_setup = advice_text(disjoint_second_setup),
        madvise_partial_disjoint_pipe_setup = disjoint.pipe_setup,
        madvise_partial_disjoint_forked = disjoint.forked,
        madvise_partial_disjoint_fork_errno = disjoint.fork_errno,
        madvise_partial_disjoint_child_report = disjoint.report_present && disjoint.packet[0] == 1,
        madvise_partial_disjoint_child_completed = disjoint.completed,
        madvise_partial_disjoint_child_exit = disjoint.exit,
        madvise_partial_disjoint_child_signal = disjoint.signal,
        madvise_partial_disjoint_child_timeout = disjoint.timed_out,
        madvise_partial_disjoint_first_hole = disjoint.observation(0),
        madvise_partial_disjoint_retained_first = disjoint.observation(1),
        madvise_partial_disjoint_second_hole = disjoint.observation(2),
        madvise_partial_disjoint_retained_second = disjoint.observation(3),
        madvise_partial_disjoint_child_write = disjoint.write_observation(),
        madvise_partial_disjoint_parent_retained = disjoint_parent_retained,
        madvise_partial_disjoint_parent_cow_isolated = disjoint_parent_cow,
        madvise_partial_dofork_restore_setup = advice_text(restored_setup),
        madvise_partial_dofork_pipe_setup = restored.pipe_setup,
        madvise_partial_dofork_forked = restored.forked,
        madvise_partial_dofork_fork_errno = restored.fork_errno,
        madvise_partial_dofork_child_report = restored.report_present && restored.packet[0] == 1,
        madvise_partial_dofork_child_completed = restored.completed,
        madvise_partial_dofork_child_exit = restored.exit,
        madvise_partial_dofork_child_signal = restored.signal,
        madvise_partial_dofork_child_timeout = restored.timed_out,
        madvise_partial_dofork_remaining_hole = restored.observation(0),
        madvise_partial_dofork_retained_first = restored.observation(1),
        madvise_partial_dofork_restored_page = restored.observation(2),
        madvise_partial_dofork_retained_second = restored.observation(3),
        madvise_partial_dofork_child_write = restored.write_observation(),
        madvise_partial_dofork_parent_retained = restored_parent_retained,
        madvise_partial_dofork_parent_cow_isolated = restored_parent_cow,
        madvise_partial_disjoint_final_reset = advice_text(disjoint_final_reset),
        madvise_partial_mixed_omit_setup = advice_text(mixed_omit_setup),
        madvise_partial_mixed_wipe_setup = advice_text(mixed_wipe_setup),
        madvise_partial_mixed_pipe_setup = mixed.pipe_setup,
        madvise_partial_mixed_forked = mixed.forked,
        madvise_partial_mixed_fork_errno = mixed.fork_errno,
        madvise_partial_mixed_child_report = mixed.report_present && mixed.packet[0] == 1,
        madvise_partial_mixed_child_completed = mixed.completed,
        madvise_partial_mixed_child_exit = mixed.exit,
        madvise_partial_mixed_child_signal = mixed.signal,
        madvise_partial_mixed_child_timeout = mixed.timed_out,
        madvise_partial_mixed_preserved = mixed.observation(0),
        madvise_partial_mixed_omitted = mixed.observation(1),
        madvise_partial_mixed_wiped = mixed.observation(2),
        madvise_partial_mixed_retained = mixed.observation(3),
        madvise_partial_mixed_child_write = mixed.write_observation(),
        madvise_partial_mixed_remap_rc = mixed.packet[PARTIAL_DONTFORK_EXTRA_OFFSET],
        madvise_partial_mixed_remap_errno = mixed.packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 1],
        madvise_partial_mixed_remap_write = mixed.packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 2],
        madvise_partial_mixed_nested_result = mixed.packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 3],
        madvise_partial_mixed_nested_completed = mixed.packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 4],
        madvise_partial_mixed_nested_remap_cow = mixed.packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 5],
        madvise_partial_mixed_nested_retained_cow = mixed.packet[PARTIAL_DONTFORK_EXTRA_OFFSET + 6],
        madvise_partial_mixed_parent_retained = mixed_parent_retained,
        madvise_partial_mixed_parent_cow_isolated = mixed_parent_cow,
        madvise_partial_mixed_omit_reset = advice_text(mixed_omit_reset),
        madvise_partial_mixed_wipe_reset = advice_text(mixed_wipe_reset),
    );
}

unsafe fn test_mmap_matrix(page: usize) {
    // 1. Missing MAP_TYPE (neither MAP_SHARED nor MAP_PRIVATE specified) -> EINVAL
    let no_type = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        0,
        -1,
        0,
    );
    let no_type_einval = no_type == libc::MAP_FAILED && errno() == libc::EINVAL;
    if no_type != libc::MAP_FAILED {
        libc::munmap(no_type, page);
    }

    // 2. Conflicting MAP_TYPE (both MAP_SHARED and MAP_PRIVATE specified) -> EINVAL
    let both_types = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let both_types_einval = both_types == libc::MAP_FAILED && errno() == libc::EINVAL;
    if both_types != libc::MAP_FAILED {
        libc::munmap(both_types, page);
    }

    // 3. Length == 0 on anonymous mmap -> EINVAL
    let len_zero = libc::mmap(
        core::ptr::null_mut(),
        0,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let len_zero_einval = len_zero == libc::MAP_FAILED && errno() == libc::EINVAL;
    if len_zero != libc::MAP_FAILED {
        libc::munmap(len_zero, page);
    }

    // 4. Unaligned offset on anonymous mmap -> EINVAL
    let unaligned_offset = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        1,
    );
    let unaligned_offset_einval = unaligned_offset == libc::MAP_FAILED && errno() == libc::EINVAL;
    if unaligned_offset != libc::MAP_FAILED {
        libc::munmap(unaligned_offset, page);
    }

    // 5. Invalid protection flags bitmask -> EINVAL
    let invalid_prot = libc::mmap(
        core::ptr::null_mut(),
        page,
        1 << 28,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let invalid_prot_result = if invalid_prot == libc::MAP_FAILED {
        format!("errno:{}", errno())
    } else {
        libc::munmap(invalid_prot, page);
        "success".to_owned()
    };

    // 6. MAP_FIXED with unaligned target address -> EINVAL
    let fixed_unaligned = libc::mmap(
        (page + 1) as *mut c_void,
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
        -1,
        0,
    );
    let fixed_unaligned_einval = fixed_unaligned == libc::MAP_FAILED && errno() == libc::EINVAL;
    if fixed_unaligned != libc::MAP_FAILED {
        libc::munmap(fixed_unaligned, page);
    }

    // 7. MAP_FIXED_NOREPLACE on an existing mapping -> EEXIST
    let base = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut noreplace_existing_eexist = false;
    if base != libc::MAP_FAILED {
        let clash = libc::mmap(
            base,
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        noreplace_existing_eexist = clash == libc::MAP_FAILED && errno() == libc::EEXIST;
        if clash != libc::MAP_FAILED && clash != base {
            libc::munmap(clash, page);
        }
        libc::munmap(base, page);
    }

    // 8. MAP_FIXED_NOREPLACE on an unmapped page -> succeeds at exact address
    let unmapped = get_unmapped_page(page);
    let mut noreplace_unmapped_ok = false;
    if !unmapped.is_null() {
        let placed = libc::mmap(
            unmapped,
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        noreplace_unmapped_ok = placed == unmapped;
        if placed != libc::MAP_FAILED {
            libc::munmap(placed, page);
        }
    }

    // 9. MAP_POPULATE makes anonymous pages immediately resident
    let pop = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
        -1,
        0,
    );
    let mut pop_resident = false;
    if pop != libc::MAP_FAILED {
        let mut vec = [0u8; 1];
        let rc = libc::mincore(pop, page, vec.as_mut_ptr());
        pop_resident = rc == 0 && (vec[0] & 1 != 0);
        libc::munmap(pop, page);
    }

    // 10. Untouched non-populated anonymous mapping is not resident
    let unpop = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut unpop_not_resident = false;
    if unpop != libc::MAP_FAILED {
        let mut vec = [0u8; 1];
        let rc = libc::mincore(unpop, page, vec.as_mut_ptr());
        unpop_not_resident = rc == 0 && (vec[0] & 1 == 0);
        libc::munmap(unpop, page);
    }

    report!(
        mmap_no_type_einval = no_type_einval,
        mmap_both_types_einval = both_types_einval,
        mmap_len_zero_einval = len_zero_einval,
        mmap_unaligned_offset_einval = unaligned_offset_einval,
        mmap_invalid_prot_result = invalid_prot_result,
        mmap_fixed_unaligned_einval = fixed_unaligned_einval,
        mmap_fixed_noreplace_eexist = noreplace_existing_eexist,
        mmap_fixed_noreplace_unmapped_ok = noreplace_unmapped_ok,
        mmap_populate_resident = pop_resident,
        mmap_unpopulated_not_resident = unpop_not_resident,
    );
}

unsafe fn test_mprotect_matrix(page: usize) {
    let map_rw = |pages: usize| {
        libc::mmap(
            core::ptr::null_mut(),
            page * pages,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    // Each subcase owns its mapping and process. A crash or wedge therefore
    // becomes one exact row instead of truncating the rest of the probe.
    let unaligned_einval = run_bounded_bool_child(|| {
        let p = map_rw(1);
        if p == libc::MAP_FAILED {
            return false;
        }
        let rc = libc::mprotect((p as *mut u8).add(1).cast(), page, libc::PROT_READ);
        let ok = rc == -1 && errno() == libc::EINVAL;
        libc::munmap(p, page);
        ok
    });

    let len_zero_ok = run_bounded_bool_child(|| {
        let p = map_rw(1);
        if p == libc::MAP_FAILED {
            return false;
        }
        let ok = libc::mprotect(p, 0, libc::PROT_READ) == 0;
        libc::munmap(p, page);
        ok
    });

    let inv_prot_einval = run_bounded_bool_child(|| {
        let p = map_rw(1);
        if p == libc::MAP_FAILED {
            return false;
        }
        let rc = libc::mprotect(p, page, 1 << 28);
        let ok = rc == -1 && errno() == libc::EINVAL;
        libc::munmap(p, page);
        ok
    });

    let unmapped_enomem = run_bounded_bool_child(|| {
        let unmapped = get_unmapped_page(page);
        if unmapped.is_null() {
            return false;
        }
        let rc = libc::mprotect(unmapped, page, libc::PROT_READ);
        rc == -1 && errno() == libc::ENOMEM
    });

    let transitions_preserved = run_bounded_bool_child(|| {
        let p = map_rw(1);
        if p == libc::MAP_FAILED {
            return false;
        }
        let b = p as *mut u8;
        *b = 0xA5;
        *b.add(page - 1) = 0x5A;

        let rc_none = libc::mprotect(p, page, libc::PROT_NONE);
        let rc_read = libc::mprotect(p, page, libc::PROT_READ);
        let read_intact = rc_read == 0 && *b == 0xA5 && *b.add(page - 1) == 0x5A;
        let rc_rw = libc::mprotect(p, page, libc::PROT_READ | libc::PROT_WRITE);
        if rc_rw == 0 {
            *b = 0xB6;
            *b.add(page - 1) = 0x6B;
        }
        let write_intact = rc_rw == 0 && *b == 0xB6 && *b.add(page - 1) == 0x6B;
        let ok = rc_none == 0 && rc_read == 0 && read_intact && write_intact;
        libc::munmap(p, page);
        ok
    });

    let split_ok = run_bounded_bool_child(|| {
        let p = map_rw(3);
        if p == libc::MAP_FAILED {
            return false;
        }
        let p0 = p as *mut u8;
        let p1 = p0.add(page);
        let p2 = p0.add(page * 2);
        *p0 = 0x11;
        *p1 = 0x22;
        *p2 = 0x33;

        let split_rc = libc::mprotect(p1.cast(), page, libc::PROT_READ);
        let mut ok = split_rc == 0;
        *p0 = 0x14;
        *p2 = 0x36;
        if *p0 != 0x14 || *p1 != 0x22 || *p2 != 0x36 {
            ok = false;
        }
        let restore_rc = libc::mprotect(p1.cast(), page, libc::PROT_READ | libc::PROT_WRITE);
        if restore_rc != 0 {
            ok = false;
        } else {
            *p1 = 0x25;
            if *p0 != 0x14 || *p1 != 0x25 || *p2 != 0x36 {
                ok = false;
            }
        }
        libc::munmap(p, page * 3);
        ok
    });

    report!(
        mprotect_unaligned_einval = unaligned_einval,
        mprotect_len_zero_ok = len_zero_ok,
        mprotect_invalid_prot_einval = inv_prot_einval,
        mprotect_unmapped_enomem = unmapped_enomem,
        mprotect_transitions_preserved = transitions_preserved,
        mprotect_partial_split_preserved = split_ok,
    );
}

unsafe fn test_madvise_matrix(page: usize) {
    let p = libc::mmap(
        core::ptr::null_mut(),
        page * 2,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        report!(
            madvise_unaligned_einval = false,
            madvise_len_zero_ok = false,
            madvise_invalid_advice_einval = false,
            madvise_unmapped_enomem = false,
            madvise_hints_matrix_ok = false,
            madvise_dontneed_zeroes_anon = false,
            madvise_wipeonfork_lifecycle = false,
            madvise_dontfork_dofork_lifecycle = false,
        );
        return;
    }

    // 1. Unaligned address -> EINVAL
    let unaligned_rc = libc::madvise((p as *mut u8).add(1).cast(), page, libc::MADV_NORMAL);
    let unaligned_einval = unaligned_rc == -1 && errno() == libc::EINVAL;

    // 2. Length == 0 -> 0 (success)
    let len_zero_rc = libc::madvise(p, 0, libc::MADV_NORMAL);
    let len_zero_ok = len_zero_rc == 0;

    // 3. Invalid advice value -> EINVAL
    let inv_adv_rc = libc::madvise(p, page, 9999);
    let inv_adv_einval = inv_adv_rc == -1 && errno() == libc::EINVAL;

    // 4. madvise on unmapped address -> ENOMEM
    let unmapped = get_unmapped_page(page);
    let unmapped_rc = libc::madvise(unmapped, page, libc::MADV_DONTNEED);
    let unmapped_enomem = unmapped_rc == -1 && errno() == libc::ENOMEM;

    // 5. Table of standard advisory hints all succeed
    let hints = [
        libc::MADV_NORMAL,
        libc::MADV_RANDOM,
        libc::MADV_SEQUENTIAL,
        libc::MADV_WILLNEED,
        libc::MADV_DONTDUMP,
        libc::MADV_DODUMP,
    ];
    let mut hints_ok = true;
    for &h in &hints {
        if libc::madvise(p, page, h) != 0 {
            hints_ok = false;
            break;
        }
    }

    // 6. MADV_DONTNEED re-zeroes dirty anonymous memory
    let b = p as *mut u8;
    core::ptr::write_bytes(b, 0xCC, page);
    let dontneed_rc = libc::madvise(p, page, libc::MADV_DONTNEED);
    let mut dontneed_zeroes = dontneed_rc == 0;
    if dontneed_zeroes {
        let slice = core::slice::from_raw_parts(b as *const u8, page);
        dontneed_zeroes = slice.iter().all(|&byte| byte == 0);
    }

    // 7. MADV_WIPEONFORK / MADV_KEEPONFORK lifecycle
    let wipe_page = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut wipe_lifecycle_ok = false;
    if wipe_page != libc::MAP_FAILED {
        let wb = wipe_page as *mut u8;
        *wb = 0x55;
        let rc_wipe = libc::madvise(wipe_page, page, MADV_WIPEONFORK);
        let child1_wiped = rc_wipe == 0
            && run_in_child(|| {
                let val = *wb;
                val == 0
            });
        let parent_still_has_val = *wb == 0x55;

        let rc_keep = libc::madvise(wipe_page, page, MADV_KEEPONFORK);
        *wb = 0x66;
        let child2_kept = rc_keep == 0
            && run_in_child(|| {
                let val = *wb;
                val == 0x66
            });

        wipe_lifecycle_ok =
            rc_wipe == 0 && child1_wiped && parent_still_has_val && rc_keep == 0 && child2_kept;
        libc::munmap(wipe_page, page);
    }

    // 8. MADV_DONTFORK / MADV_DOFORK lifecycle
    let df_page = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut df_lifecycle_ok = false;
    if df_page != libc::MAP_FAILED {
        let dfb = df_page as *mut u8;
        *dfb = 0x77;
        let rc_df = libc::madvise(df_page, page, libc::MADV_DONTFORK);
        let child1_unmapped = rc_df == 0
            && run_in_child(|| {
                let mut vec = [0u8; 1];
                let r = libc::mincore(df_page, page, vec.as_mut_ptr());
                r == -1 && errno() == libc::ENOMEM
            });

        let rc_dofork = libc::madvise(df_page, page, libc::MADV_DOFORK);
        let child2_mapped = rc_dofork == 0
            && run_in_child(|| {
                let mut vec = [0u8; 1];
                let r = libc::mincore(df_page, page, vec.as_mut_ptr());
                r == 0 && *dfb == 0x77
            });

        df_lifecycle_ok = rc_df == 0 && child1_unmapped && rc_dofork == 0 && child2_mapped;
        libc::munmap(df_page, page);
    }

    libc::munmap(p, page * 2);

    report!(
        madvise_unaligned_einval = unaligned_einval,
        madvise_len_zero_ok = len_zero_ok,
        madvise_invalid_advice_einval = inv_adv_einval,
        madvise_unmapped_enomem = unmapped_enomem,
        madvise_hints_matrix_ok = hints_ok,
        madvise_dontneed_zeroes_anon = dontneed_zeroes,
        madvise_wipeonfork_lifecycle = wipe_lifecycle_ok,
        madvise_dontfork_dofork_lifecycle = df_lifecycle_ok,
    );
    test_partial_dontfork_matrix(page);
}

unsafe fn test_mincore_matrix(page: usize) {
    let p = libc::mmap(
        core::ptr::null_mut(),
        page * 3,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        report!(
            mincore_unaligned_einval = false,
            mincore_len_zero_ok = false,
            mincore_null_vec_efault = false,
            mincore_invalid_vec_efault = false,
            mincore_unmapped_enomem = false,
            mincore_lifecycle_transitions = false,
            mincore_sparse_multipage = false,
        );
        return;
    }

    // 1. Unaligned address -> EINVAL
    let mut vec1 = [0u8; 1];
    let unaligned_rc = libc::mincore((p as *mut u8).add(1).cast(), page, vec1.as_mut_ptr());
    let unaligned_einval = unaligned_rc == -1 && errno() == libc::EINVAL;

    // 2. Length == 0 -> 0 (success on Linux)
    let len_zero_rc = libc::mincore(p, 0, vec1.as_mut_ptr());
    let len_zero_ok = len_zero_rc == 0;

    // 3. NULL vector pointer -> EFAULT
    let null_rc = libc::mincore(p, page, core::ptr::null_mut());
    let null_efault = null_rc == -1 && errno() == libc::EFAULT;

    // 4. Invalid vector pointer -> EFAULT
    let inv_ptr_rc = libc::mincore(p, page, 1 as *mut u8);
    let inv_ptr_efault = inv_ptr_rc == -1 && errno() == libc::EFAULT;

    // 5. Unmapped address -> ENOMEM
    let unmapped = get_unmapped_page(page);
    let unmapped_rc = libc::mincore(unmapped, page, vec1.as_mut_ptr());
    let unmapped_enomem = unmapped_rc == -1 && errno() == libc::ENOMEM;

    // 6. Lifecycle transitions: untouched -> touch -> dontneed -> touch
    let single = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut transitions_ok = false;
    if single != libc::MAP_FAILED {
        let mut v = [0u8; 1];
        let rc0 = libc::mincore(single, page, v.as_mut_ptr());
        let step0_untouched = rc0 == 0 && (v[0] & 1 == 0);

        *(single as *mut u8) = 0x42;
        let rc1 = libc::mincore(single, page, v.as_mut_ptr());
        let step1_touched = rc1 == 0 && (v[0] & 1 != 0);

        libc::madvise(single, page, libc::MADV_DONTNEED);
        let rc2 = libc::mincore(single, page, v.as_mut_ptr());
        let step2_evicted = rc2 == 0 && (v[0] & 1 == 0);

        *(single as *mut u8) = 0x43;
        let rc3 = libc::mincore(single, page, v.as_mut_ptr());
        let step3_retouched = rc3 == 0 && (v[0] & 1 != 0);

        transitions_ok = step0_untouched && step1_touched && step2_evicted && step3_retouched;
        libc::munmap(single, page);
    }

    // 7. Sparse multi-page residency: 3 pages, touch page 0 and page 2 only
    let mut vec3 = [0u8; 3];
    let p0 = p as *mut u8;
    let p2 = p0.add(page * 2);
    *p0 = 0xAA;
    *p2 = 0xBB;
    let sparse_rc = libc::mincore(p, page * 3, vec3.as_mut_ptr());
    let sparse_ok =
        sparse_rc == 0 && (vec3[0] & 1 != 0) && (vec3[1] & 1 == 0) && (vec3[2] & 1 != 0);

    libc::munmap(p, page * 3);

    report!(
        mincore_unaligned_einval = unaligned_einval,
        mincore_len_zero_ok = len_zero_ok,
        mincore_null_vec_efault = null_efault,
        mincore_invalid_vec_efault = inv_ptr_efault,
        mincore_unmapped_enomem = unmapped_enomem,
        mincore_lifecycle_transitions = transitions_ok,
        mincore_sparse_multipage = sparse_ok,
    );
}

unsafe fn test_mremap_matrix(page: usize) {
    let p = libc::mmap(
        core::ptr::null_mut(),
        page * 2,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        report!(
            mremap_unaligned_old_einval = false,
            mremap_new_len_zero_einval = false,
            mremap_old_len_zero_einval = false,
            mremap_invalid_flags_einval = false,
            mremap_fixed_without_maymove_einval = false,
            mremap_fixed_unaligned_target_einval = false,
            mremap_unmapped_efault = false,
            mremap_fixed_relocation_intact = false,
            mremap_dontunmap_semantics = false,
        );
        return;
    }

    // 1. Unaligned old_address -> EINVAL
    let unaligned_r = libc::mremap(
        (p as *mut u8).add(1).cast(),
        page,
        page * 2,
        libc::MREMAP_MAYMOVE,
    );
    let unaligned_old_einval = unaligned_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 2. new_size == 0 -> EINVAL
    let new_zero_r = libc::mremap(p, page, 0, 0);
    let new_zero_einval = new_zero_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 3. old_size == 0 (without MREMAP_MAYMOVE | MREMAP_FIXED) -> EINVAL
    let old_zero_r = libc::mremap(p, 0, page * 2, 0);
    let old_zero_einval = old_zero_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 4. Invalid flag bit -> EINVAL
    let inv_flag_r = libc::mremap(p, page, page * 2, 1 << 30);
    let inv_flag_einval = inv_flag_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 5. MREMAP_FIXED without MREMAP_MAYMOVE -> EINVAL
    let target = get_unmapped_page(page);
    let fixed_nomove_r = libc::mremap(p, page, page, libc::MREMAP_FIXED, target);
    let fixed_nomove_einval = fixed_nomove_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 6. MREMAP_FIXED | MREMAP_MAYMOVE with unaligned target address -> EINVAL
    let fixed_unaligned_r = libc::mremap(
        p,
        page,
        page,
        libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
        (target as *mut u8).add(1),
    );
    let fixed_unaligned_einval = fixed_unaligned_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 7. mremap on unmapped address -> EFAULT on Linux (distinct from ENOMEM)
    let unmapped = get_unmapped_page(page);
    let unmapped_r = libc::mremap(unmapped, page, page * 2, libc::MREMAP_MAYMOVE);
    let unmapped_efault = unmapped_r == libc::MAP_FAILED && errno() == libc::EFAULT;

    libc::munmap(p, page * 2);

    // 8. MREMAP_FIXED | MREMAP_MAYMOVE valid relocation replacing destination
    let src = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let dst = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut fixed_reloc_ok = false;
    if src != libc::MAP_FAILED && dst != libc::MAP_FAILED {
        *(src as *mut u8) = 0x44;
        *(src as *mut u8).add(page - 1) = 0x45;
        *(dst as *mut u8) = 0x88;

        let res = libc::mremap(
            src,
            page,
            page,
            libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
            dst,
        );
        let dst_updated =
            res == dst && *(dst as *const u8) == 0x44 && *(dst as *const u8).add(page - 1) == 0x45;

        // Old source address must be unmapped (mincore returns ENOMEM)
        let mut v = [0u8; 1];
        let src_unmapped =
            libc::mincore(src, page, v.as_mut_ptr()) == -1 && errno() == libc::ENOMEM;

        fixed_reloc_ok = dst_updated && src_unmapped;
        libc::munmap(dst, page);
        if !src_unmapped {
            libc::munmap(src, page);
        }
    } else {
        if src != libc::MAP_FAILED {
            libc::munmap(src, page);
        }
        if dst != libc::MAP_FAILED {
            libc::munmap(dst, page);
        }
    }

    // 9. MREMAP_DONTUNMAP (Linux 5.7+): moves data to new address and retains
    // the source address mapped as fresh zero-filled anonymous memory.
    let du_src = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut dontunmap_semantics = false;
    if du_src != libc::MAP_FAILED {
        let sub = du_src as *mut u8;
        *sub = 0x33;
        let q = libc::mremap(du_src, page, page, libc::MREMAP_MAYMOVE | MREMAP_DONTUNMAP);
        if q != libc::MAP_FAILED {
            let q_b = q as *mut u8;
            let q_has_data = *q_b == 0x33;
            let src_still_mapped_zeroed = *sub == 0;
            dontunmap_semantics = q != du_src && q_has_data && src_still_mapped_zeroed;
            libc::munmap(q, page);
        }
        libc::munmap(du_src, page);
    }

    report!(
        mremap_unaligned_old_einval = unaligned_old_einval,
        mremap_new_len_zero_einval = new_zero_einval,
        mremap_old_len_zero_einval = old_zero_einval,
        mremap_invalid_flags_einval = inv_flag_einval,
        mremap_fixed_without_maymove_einval = fixed_nomove_einval,
        mremap_fixed_unaligned_target_einval = fixed_unaligned_einval,
        mremap_unmapped_efault = unmapped_efault,
        mremap_fixed_relocation_intact = fixed_reloc_ok,
        mremap_dontunmap_semantics = dontunmap_semantics,
    );
}

fn main() {
    let page = page_size();
    unsafe {
        test_mmap_matrix(page);
        test_mprotect_matrix(page);
        test_madvise_matrix(page);
        test_mincore_matrix(page);
        test_mremap_matrix(page);
    }
}

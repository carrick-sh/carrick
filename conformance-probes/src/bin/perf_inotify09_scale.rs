// SPDX-License-Identifier: Apache-2.0 OR MIT
// This is an independent probe of the public Linux syscall interface. It does
// not contain source copied from the GPL-licensed LTP implementation.
//! Performance decomposition of LTP `inotify09`.
//!
//! The upstream test races `inotify_add_watch` + `inotify_rm_watch` against
//! `write(64)` + `lseek(SEEK_SET)`. This probe measures those components alone,
//! then measures their serial composition and concurrent composition at growing
//! iteration counts. Output is consumed as performance evidence and is not
//! line-diffed as conformance output.

use conformance_probes::{arm_alarm_ms, disarm_alarm};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};

const SCALES: [usize; 5] = [1, 32, 1024, 8192, 65536];
// The contract's runtime binding requires at least 20 independent samples;
// keep an odd count so the reported median is an observed sample.
const SAMPLES: usize = 21;
const PAYLOAD: [u8; 64] = [0x5a; 64];
const IN_MODIFY: u32 = 0x0000_0002;
const IN_NONBLOCK: i32 = 0o0004_000;
const IN_CLOEXEC: i32 = 0o2000_000;

#[cfg(target_os = "linux")]
type SyscallNumber = libc::c_long;
#[cfg(not(target_os = "linux"))]
type SyscallNumber = libc::c_int;

#[cfg(target_arch = "aarch64")]
const SYS_INOTIFY_INIT1: SyscallNumber = 26;
#[cfg(target_arch = "aarch64")]
const SYS_INOTIFY_ADD_WATCH: SyscallNumber = 27;
#[cfg(target_arch = "aarch64")]
const SYS_INOTIFY_RM_WATCH: SyscallNumber = 28;

#[cfg(target_arch = "x86_64")]
const SYS_INOTIFY_INIT1: SyscallNumber = 294;
#[cfg(target_arch = "x86_64")]
const SYS_INOTIFY_ADD_WATCH: SyscallNumber = 254;
#[cfg(target_arch = "x86_64")]
const SYS_INOTIFY_RM_WATCH: SyscallNumber = 255;

#[cfg(target_arch = "aarch64")]
fn counter() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mrs {value}, cntvct_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[cfg(target_arch = "aarch64")]
fn frequency() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mrs {value}, cntfrq_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[cfg(not(target_arch = "aarch64"))]
fn counter() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos() as u64
}

#[cfg(not(target_arch = "aarch64"))]
fn frequency() -> u64 {
    1_000_000_000
}

fn watch_cycle(ifd: i32, path: &CString) -> bool {
    let wd = raw_inotify_add_watch(ifd, path, IN_MODIFY);
    wd >= 0 && raw_inotify_rm_watch(ifd, wd) == 0
}

fn raw_inotify_init1(flags: i32) -> i32 {
    unsafe { libc::syscall(SYS_INOTIFY_INIT1, flags) as i32 }
}

fn raw_inotify_add_watch(ifd: i32, path: &CString, mask: u32) -> i32 {
    unsafe { libc::syscall(SYS_INOTIFY_ADD_WATCH, ifd, path.as_ptr(), mask) as i32 }
}

fn raw_inotify_rm_watch(ifd: i32, wd: i32) -> i32 {
    unsafe { libc::syscall(SYS_INOTIFY_RM_WATCH, ifd, wd) as i32 }
}

fn write_seek_cycle(fd: i32) -> bool {
    unsafe {
        libc::write(fd, PAYLOAD.as_ptr().cast(), PAYLOAD.len()) == PAYLOAD.len() as isize
            && libc::lseek(fd, 0, libc::SEEK_SET) == 0
    }
}

fn measure(scale: usize, mut operation: impl FnMut() -> bool) -> Option<u64> {
    let start = counter();
    for _ in 0..scale {
        if !operation() {
            return None;
        }
    }
    Some(counter().wrapping_sub(start))
}

fn median_ns_per_iteration(mut samples: Vec<u64>, scale: usize, freq: u64) -> u64 {
    samples.sort_unstable();
    let ticks = samples[samples.len() / 2] as u128;
    ((ticks * 1_000_000_000_u128) / (freq as u128 * scale as u128)) as u64
}

fn report_phase(phase: &str, scale: usize, samples: Vec<Option<u64>>, freq: u64) -> bool {
    let complete = samples.iter().all(Option::is_some);
    let ticks = samples.into_iter().flatten().collect::<Vec<_>>();
    let p50 = if complete {
        median_ns_per_iteration(ticks, scale, freq)
    } else {
        0
    };
    println!(
        "phase={phase} scale={scale} samples={SAMPLES} p50_ns_per_iter={p50} complete={}",
        u8::from(complete)
    );
    complete
}

fn contract_scale() -> Result<Option<usize>, ()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return Ok(None);
    }
    if args.len() != 2 || args[0] != "contract-scale" {
        return Err(());
    }
    let scale = args[1].parse::<usize>().map_err(|_| ())?;
    [1, 8, 32, 128].contains(&scale).then_some(scale).ok_or(())
        .map(Some)
}

fn concurrent_sample(ifd: i32, fd: i32, path: &CString, scale: usize) -> Option<u64> {
    let barrier = Arc::new(Barrier::new(3));
    let ok = Arc::new(AtomicBool::new(true));
    let path = Arc::new(path.clone());

    let watch_barrier = Arc::clone(&barrier);
    let watch_ok = Arc::clone(&ok);
    let watch_path = Arc::clone(&path);
    let watch = std::thread::spawn(move || {
        watch_barrier.wait();
        for _ in 0..scale {
            if !watch_cycle(ifd, &watch_path) {
                watch_ok.store(false, Ordering::Release);
                break;
            }
        }
    });

    let writer_barrier = Arc::clone(&barrier);
    let writer_ok = Arc::clone(&ok);
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for _ in 0..scale {
            if !write_seek_cycle(fd) {
                writer_ok.store(false, Ordering::Release);
                break;
            }
        }
    });

    let start = counter();
    barrier.wait();
    let joined = watch.join().is_ok() && writer.join().is_ok();
    let elapsed = counter().wrapping_sub(start);
    (joined && ok.load(Ordering::Acquire)).then_some(elapsed)
}

fn main() {
    unsafe { arm_alarm_ms(90_000) };
    let contract_scale = match contract_scale() {
        Ok(scale) => scale,
        Err(()) => {
            eprintln!("usage: perf_inotify09_scale [contract-scale <1|8|32|128>]");
            std::process::exit(2);
        }
    };
    let freq = frequency();
    if freq == 0 {
        std::process::exit(2);
    }

    let path = CString::new(format!(
        "/tmp/carrick-perf-inotify09-scale-{}",
        std::process::id()
    ))
    .expect("path has no NUL");
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        )
    };
    let ifd = raw_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if fd < 0 || ifd < 0 {
        std::process::exit(2);
    }

    let mut complete = true;
    if let Some(scale) = contract_scale {
        let mut completed = 0usize;
        for _ in 0..scale {
            let wd = raw_inotify_add_watch(ifd, &path, IN_MODIFY);
            if wd < 0 || !write_seek_cycle(fd) || raw_inotify_rm_watch(ifd, wd) != 0 {
                complete = false;
                break;
            }
            completed += 1;
        }
        complete &= unsafe { libc::close(ifd) } == 0;
        complete &= unsafe { libc::close(fd) } == 0;
        complete &= unsafe { libc::unlink(path.as_ptr()) } == 0;
        println!("contract_scale={scale}");
        println!("completed_iterations={completed}");
        println!("probe_complete={}", u8::from(complete));
        unsafe { disarm_alarm() };
        if !complete {
            std::process::exit(1);
        }
        return;
    }
    for scale in SCALES {
        complete &= report_phase(
            "watch_churn",
            scale,
            (0..SAMPLES)
                .map(|_| measure(scale, || watch_cycle(ifd, &path)))
                .collect(),
            freq,
        );
        complete &= report_phase(
            "write_seek",
            scale,
            (0..SAMPLES)
                .map(|_| measure(scale, || write_seek_cycle(fd)))
                .collect(),
            freq,
        );

        let persistent_wd = raw_inotify_add_watch(ifd, &path, IN_MODIFY);
        let persistent_samples = if persistent_wd >= 0 {
            (0..SAMPLES)
                .map(|_| measure(scale, || write_seek_cycle(fd)))
                .collect()
        } else {
            vec![None; SAMPLES]
        };
        complete &= report_phase(
            "persistent_watch_write_seek",
            scale,
            persistent_samples,
            freq,
        );
        if persistent_wd >= 0 {
            complete &= raw_inotify_rm_watch(ifd, persistent_wd) == 0;
        }

        complete &= report_phase(
            "serial_full",
            scale,
            (0..SAMPLES)
                .map(|_| {
                    measure(scale, || {
                        let wd = raw_inotify_add_watch(ifd, &path, IN_MODIFY);
                        wd >= 0 && write_seek_cycle(fd) && raw_inotify_rm_watch(ifd, wd) == 0
                    })
                })
                .collect(),
            freq,
        );
        complete &= report_phase(
            "concurrent_components",
            scale,
            (0..SAMPLES)
                .map(|_| concurrent_sample(ifd, fd, &path, scale))
                .collect(),
            freq,
        );
    }

    complete &= unsafe { libc::close(ifd) } == 0;
    complete &= unsafe { libc::close(fd) } == 0;
    complete &= unsafe { libc::unlink(path.as_ptr()) } == 0;
    println!("probe_complete={}", u8::from(complete));
    unsafe { disarm_alarm() };
    if !complete {
        std::process::exit(1);
    }
}

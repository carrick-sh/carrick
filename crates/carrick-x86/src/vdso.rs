//! Shared x86_64 vDSO clock-page (vvar) calibration.
//!
//! Lowered out of the KVM backend so EVERY x86 VMM (KVM/bhyve/NVMM) gets the
//! userspace clock fast path with no per-backend calibration code. The guest's
//! `__vdso_clock_gettime` reads `tsc/freq` nanoseconds plus a stamped offset
//! from the shared vvar page; this module computes and writes that page.
//!
//! Backend-neutral by construction: it writes through [`X86Vmm::write_gpa`] and
//! reads the guest TSC through the optional [`X86Vcpu::read_msr`] hook. Without
//! that hook the host TSC is used, which is correct whenever the backend runs
//! the guest with a zero TSC offset; a backend whose guest TSC is offset
//! overrides `read_msr` to read `IA32_TSC` precisely. The shared engine calls
//! [`populate_vdso_vvar`] at construction, fork, and execve — so a new backend
//! inherits the fast path without touching its bring-up.

use carrick_hal::TrapError;
use carrick_mem::vdso::{
    LINUX_VVAR_BASE, LINUX_VVAR_SIZE, VVAR_OFF_FREQ, VVAR_OFF_MONOTONIC_OFF_NS,
    VVAR_OFF_REALTIME_OFF_NS,
};

use crate::vmm::{X86Vcpu, X86Vmm};

/// `IA32_TSC` — the guest timestamp counter MSR the vvar offsets are relative to.
pub const MSR_IA32_TSC: u32 = 0x10;

/// The `(realtime_off, monotonic_off)` nanosecond values the vDSO adds to
/// `guest_tsc/freq` nanoseconds to recover host wall/monotonic time. Pure — the
/// unit of correctness for the whole fast path.
fn vvar_offsets(freq_hz: u64, guest_tsc: u64, realtime_ns: u64, monotonic_ns: u64) -> (u64, u64) {
    let tsc_ns = ((guest_tsc as u128) * 1_000_000_000u128 / (freq_hz as u128)) as u64;
    (
        realtime_ns.wrapping_sub(tsc_ns),
        monotonic_ns.wrapping_sub(tsc_ns),
    )
}

/// Host monotonic reference for the vvar offset. The guest reads `CLOCK_MONOTONIC`
/// from the fast path; we calibrate against the closest non-NTP-adjusted host
/// clock available per host OS (raw monotonic on Linux/macOS, plain monotonic on
/// the BSDs where `_RAW` is absent).
#[cfg(any(target_os = "linux", target_os = "android"))]
const MONOTONIC_REF: libc::clockid_t = libc::CLOCK_MONOTONIC_RAW;
#[cfg(target_os = "macos")]
const MONOTONIC_REF: libc::clockid_t = libc::CLOCK_UPTIME_RAW;
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
const MONOTONIC_REF: libc::clockid_t = libc::CLOCK_MONOTONIC;

/// Read a host clock as nanoseconds since its epoch, or `None` on failure.
fn host_clock_ns(clock: libc::clockid_t) -> Option<u64> {
    // SAFETY: `ts` is a valid, fully-owned timespec; clock_gettime writes it.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(clock, &mut ts) } != 0 {
        return None;
    }
    Some(
        (ts.tv_sec as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(ts.tv_nsec as u64),
    )
}

/// The host timestamp counter (serializing `lfence` + `rdtsc`). On a non-x86
/// host (e.g. the aarch64 dev box, which never runs an x86 backend) there is no
/// TSC, so this returns 0 and calibration becomes a no-op.
#[cfg(target_arch = "x86_64")]
fn host_rdtsc() -> u64 {
    // SAFETY: both intrinsics are unconditionally available on x86_64.
    unsafe {
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    }
}
#[cfg(not(target_arch = "x86_64"))]
fn host_rdtsc() -> u64 {
    0
}

/// Calibrate the host TSC frequency in Hz by timing a short `rdtsc` delta. The
/// fallback when the backend cannot report the guest TSC frequency directly.
fn calibrate_host_tsc_hz() -> Option<u64> {
    let start_tsc = host_rdtsc();
    if start_tsc == 0 {
        return None; // non-x86 host: no TSC to calibrate
    }
    let start = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let elapsed = start.elapsed().as_nanos();
    if elapsed == 0 {
        return None;
    }
    let delta = host_rdtsc().wrapping_sub(start_tsc) as u128;
    Some((delta * 1_000_000_000u128 / elapsed) as u64)
}

/// Calibrate and write the shared x86_64 vDSO vvar page so the guest's
/// `__vdso_clock_gettime` serves `CLOCK_REALTIME`/`CLOCK_MONOTONIC` from
/// userspace instead of trapping a `clock_gettime` syscall per read.
///
/// Best-effort and idempotent: a no-op when the vvar page is not mapped yet
/// (e.g. a unit-test backend) or the TSC frequency is unknown, so it is safe to
/// call from the shared engine at construction, fork, and execve. Re-running it
/// (sibling vCPUs, post-fork RAM divergence, a fresh execve image) re-derives
/// the same offsets against the live host clock.
pub fn populate_vdso_vvar<V: X86Vmm>(vm: &V, vcpu: &V::Vcpu) -> Result<(), TrapError> {
    if vm
        .host_ptr(LINUX_VVAR_BASE, LINUX_VVAR_SIZE as usize)
        .is_none()
    {
        return Ok(());
    }
    let Some(freq) = vm.tsc_hz().or_else(calibrate_host_tsc_hz) else {
        return Ok(());
    };
    if freq == 0 {
        return Ok(());
    }
    // Prefer the precise guest TSC (the backend's optional read_msr hook); fall
    // back to the host TSC, which is correct whenever the guest runs with a zero
    // TSC offset.
    let guest_tsc = vcpu.read_msr(MSR_IA32_TSC).unwrap_or_else(|_| host_rdtsc());
    let realtime_ns = host_clock_ns(libc::CLOCK_REALTIME).unwrap_or(0);
    let monotonic_ns = host_clock_ns(MONOTONIC_REF).unwrap_or(0);
    let (realtime_off, monotonic_off) = vvar_offsets(freq, guest_tsc, realtime_ns, monotonic_ns);

    // Write through the VA-consistent `host_ptr` the guest itself uses, NOT
    // `write_gpa`: the engine's memory model is keyed on the guest VA, and
    // backends resolve it differently (KVM identity GPA==VA; bhyve a VA→GPA
    // window table). `write_gpa` takes a literal GPA, so writing the vvar's high
    // VA (LINUX_VVAR_BASE) through it lands on an unbacked GPA on a folded-segment
    // backend. `host_ptr(va)` resolves the VA on every backend.
    write_vvar_field(
        vm,
        LINUX_VVAR_BASE + VVAR_OFF_FREQ as u64,
        &freq.to_le_bytes(),
    )?;
    write_vvar_field(
        vm,
        LINUX_VVAR_BASE + VVAR_OFF_REALTIME_OFF_NS as u64,
        &realtime_off.to_le_bytes(),
    )?;
    write_vvar_field(
        vm,
        LINUX_VVAR_BASE + VVAR_OFF_MONOTONIC_OFF_NS as u64,
        &monotonic_off.to_le_bytes(),
    )?;
    Ok(())
}

/// Write a vvar field through the backend's VA-keyed `host_ptr` (the same path
/// the guest's vDSO reads it back through), so calibration lands correctly on
/// both identity (KVM) and VA→GPA-window (bhyve) memory models.
fn write_vvar_field<V: X86Vmm>(vm: &V, va: u64, bytes: &[u8]) -> Result<(), TrapError> {
    let dst = vm
        .host_ptr(va, bytes.len())
        .ok_or_else(|| TrapError::Hypervisor(format!("vdso vvar host_ptr 0x{va:x} unmapped")))?;
    // SAFETY: `host_ptr` proved `[dst, dst + bytes.len())` is a live guest window.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_recover_host_time_from_guest_tsc() {
        // freq 1 GHz, guest tsc = 5e9 ticks => tsc_ns = 5_000_000_000.
        // The vDSO computes time = tsc_ns + off, so off must be (now - tsc_ns).
        let freq = 1_000_000_000u64;
        let tsc = 5_000_000_000u64;
        let realtime = 1_700_000_000_000_000_000u64;
        let monotonic = 42_000_000_000u64;
        let (rt_off, mono_off) = vvar_offsets(freq, tsc, realtime, monotonic);
        // Reconstructing: tsc_ns + off == the host clock we calibrated against.
        let tsc_ns = 5_000_000_000u64;
        assert_eq!(
            tsc_ns.wrapping_add(rt_off),
            realtime,
            "realtime reconstructs"
        );
        assert_eq!(
            tsc_ns.wrapping_add(mono_off),
            monotonic,
            "monotonic reconstructs"
        );
    }

    #[test]
    fn offsets_scale_with_frequency() {
        // 2 GHz => the same tsc value is half the nanoseconds, so the offset is
        // larger by tsc_ns/2 for the same wall clock.
        let (rt_2ghz, _) = vvar_offsets(2_000_000_000, 4_000_000_000, 1_000_000_000, 0);
        // tsc_ns = 4e9 * 1e9 / 2e9 = 2e9 ; off = 1e9 - 2e9 = -1e9 (wrapping).
        assert_eq!(rt_2ghz, 1_000_000_000u64.wrapping_sub(2_000_000_000));
    }
}

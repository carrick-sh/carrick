//! `sysinfo(2)` must fill `struct sysinfo` in the exact Linux aarch64 layout:
//! after the eight u64 fields and `procs:u16`, the kernel writes an explicit
//! `pad:u16`@82, then (with natural alignment, 4 bytes of implicit pad @84)
//! `totalhigh:u64`@88, `freehigh:u64`@96, `mem_unit:u32`@104. The total
//! kernel-written size is 112 bytes. The musl `struct sysinfo` the probe
//! compiles against has exactly these offsets (mem_unit@104, totalhigh@88,
//! freehigh@96) plus a trailing `__reserved[256]`; we zero the whole thing so
//! any byte carrick fails to write reads as 0 (deterministic).
//!
//! carrick's `LinuxSysinfo` is `#[repr(C, packed)]` and inserts an 8-byte
//! `_padding` after `procs` (carrick-abi/src/lib.rs:809-810) instead of the
//! 2-byte explicit pad + 4-byte implicit alignment pad. In the packed buffer
//! totalhigh lands @90, freehigh @98, mem_unit @106, and the total written
//! size is 110 bytes (ABI_SIZE == size_of for a packed struct). The guest's
//! naturally-aligned view reads `mem_unit` from offset 104, which in carrick's
//! packed buffer is [freehigh hi-2-bytes=0x0000, mem_unit lo-2-bytes=0x0001]
//! little-endian = 0x0001_0000 == 65536.
//!
//! INVARIANT (deterministic, machine-independent): on 64-bit aarch64 the
//! kernel never scales the *ram fields (`__kernel_ulong_t` is 64-bit, so the
//! `do_sysinfo` bit-scaling loop never runs), hence `mem_unit==1`, and there
//! is no highmem zone so `totalhigh==0`/`freehigh==0`. `procs>=1` and
//! `totalram!=0` always hold. The 2-byte shift makes carrick's `mem_unit`
//! read 65536, so the booleans below diverge from Linux exactly on the layout
//! bug. No raw byte counts, sizes, times, pids, or addresses are printed.

use conformance_probes::{errno, report};

fn main() {
    unsafe {
        // Zero-init the entire libc struct (incl. its __reserved[256] tail) so
        // any field carrick fails to write reads as 0, keeping the diff
        // deterministic across machines.
        let mut si: libc::sysinfo = core::mem::zeroed();
        let rc = libc::sysinfo(&mut si);

        if rc != 0 {
            // Both Linux and carrick succeed; if not, surface the errno so the
            // diff still pinpoints the failure rather than reading garbage.
            report!(sysinfo_rc_zero = false, sysinfo_errno = errno());
            return;
        }

        // Copy fields into locals before comparing (libc::sysinfo is naturally
        // aligned so this is not strictly required, but keeps the comparisons
        // value-based and robust if the struct ever changes).
        let mem_unit = si.mem_unit;
        let totalhigh = si.totalhigh;
        let freehigh = si.freehigh;
        let totalram = si.totalram;
        let procs = si.procs;

        report!(
            sysinfo_rc_zero = rc == 0,
            // Linux on 64-bit aarch64: mem_unit == 1 (bytes). The 2-byte field
            // shift makes carrick read 65536 here — the load-bearing line.
            mem_unit_is_one = mem_unit == 1,
            // Defense-in-depth: mem_unit must never be the 65536 the shift
            // produces.
            mem_unit_not_65536 = mem_unit != 65536,
            // aarch64 has no highmem zone: both must be 0.
            totalhigh_zero = totalhigh == 0,
            freehigh_zero = freehigh == 0,
            // Sanity: a populated report.
            totalram_nonzero = totalram != 0,
            procs_at_least_one = procs >= 1,
        );
    }
}
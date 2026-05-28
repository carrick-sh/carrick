//! Isolates the obstacle behind live MAP_SHARED-file coherence: does a
//! POST-BOOT hv_vm_map (carrick's high-VA `MapHostAlias` path) work inside a
//! FORKED child of the multi-process runtime? A guest mmap(MAP_FIXED) at a
//! high VA (>= 1 TiB) routes through that path. We do it in the parent first
//! (baseline), then in a forked child, and report whether each mapping is
//! usable (write then read back). Deterministic booleans; if the forked-child
//! post-boot hv_vm_map crashes carrick, the child line never prints.

const HIGH_VA: u64 = 0x100_0000_0000; // 1 TiB — is_high_va() threshold
const LEN: usize = 0x4000; // one HVF granule

unsafe fn map_fixed_high(va: u64) -> bool {
    let p = libc::mmap(
        va as *mut libc::c_void,
        LEN,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        return false;
    }
    // Write then read back through the mapping.
    let q = p as *mut u64;
    std::ptr::write_volatile(q, 0xFEED_BEEF_1234_5678);
    std::ptr::read_volatile(q) == 0xFEED_BEEF_1234_5678
}

fn main() {
    unsafe {
        // Baseline: post-boot hv_vm_map in the top process.
        let parent_ok = map_fixed_high(HIGH_VA);
        println!("parent_highva_map_ok={parent_ok}");

        // The real test: the same in a forked child.
        let pid = libc::fork();
        if pid == 0 {
            let child_ok = map_fixed_high(HIGH_VA + LEN as u64);
            // Use the exit code to report (stdout may be lost on a crash).
            libc::_exit(if child_ok { 0 } else { 1 });
        }
        let mut st = 0i32;
        while libc::wait4(pid, &mut st, 0, std::ptr::null_mut()) < 0 {}
        let child_ok = libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0;
        let child_signalled = libc::WIFSIGNALED(st);
        println!("child_highva_map_ok={child_ok}");
        println!("child_died_by_signal={child_signalled}");
    }
}

//! Empirical probe: does `minherit(addr, len, VM_INHERIT_SHARE)` make an
//! anonymous MAP_PRIVATE region SHARED across `fork(2)` on this host (Apple
//! Silicon)? If so it is the clean primitive for vfork/CLONE_VM sharing — mark
//! the guest regions VM_INHERIT_SHARE before the fork, no buffer copy, same
//! physical pages (so the child's re-`hv_vm_map` resolves to the parent's RAM).
//!
//! Run: `cargo test -p carrick-runtime --test minherit_probe -- --nocapture`

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

#[test]
fn minherit_share_survives_fork() {
    // mach/vm_inherit.h: SHARE=0, COPY=1, NONE=2.
    const VM_INHERIT_SHARE: libc::c_int = 0;
    const VM_INHERIT_COPY: libc::c_int = 1;
    unsafe extern "C" {
        fn minherit(
            addr: *mut libc::c_void,
            len: libc::size_t,
            inherit: libc::c_int,
        ) -> libc::c_int;
    }

    let len = 16 * 1024;
    let map = || {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED, "mmap");
        p.cast::<u8>()
    };

    // Case 1: VM_INHERIT_SHARE — child's write should be visible to the parent.
    let p = map();
    unsafe { p.write_volatile(0x11) };
    let rc = unsafe { minherit(p.cast(), len, VM_INHERIT_SHARE) };
    println!(
        "PROBE-MINHERIT minherit(SHARE) rc={rc} ({})",
        std::io::Error::last_os_error()
    );
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        unsafe { p.write_volatile(0x22) };
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    let seen_share = unsafe { p.read_volatile() };

    // Case 2: default (no minherit) — child's write must NOT be visible (COW).
    let q = map();
    unsafe { q.write_volatile(0x11) };
    let pid2 = unsafe { libc::fork() };
    assert!(pid2 >= 0, "fork2");
    if pid2 == 0 {
        unsafe { q.write_volatile(0x22) };
        unsafe { libc::_exit(0) };
    }
    let mut st2 = 0;
    unsafe { libc::waitpid(pid2, &mut st2, 0) };
    let seen_default = unsafe { q.read_volatile() };

    // Case 3: VM_INHERIT_COPY — explicitly COW; child's write must NOT be visible.
    let r = map();
    unsafe { r.write_volatile(0x11) };
    let rc3 = unsafe { minherit(r.cast(), len, VM_INHERIT_COPY) };
    let pid3 = unsafe { libc::fork() };
    assert!(pid3 >= 0, "fork3");
    if pid3 == 0 {
        unsafe { r.write_volatile(0x22) };
        unsafe { libc::_exit(0) };
    }
    let mut st3 = 0;
    unsafe { libc::waitpid(pid3, &mut st3, 0) };
    let seen_copy = unsafe { r.read_volatile() };

    println!("PROBE-MINHERIT SHARE  : parent sees 0x{seen_share:02x} (0x22 => SHARED)");
    println!("PROBE-MINHERIT default: parent sees 0x{seen_default:02x} (0x11 => COW-isolated)");
    println!("PROBE-MINHERIT COPY rc={rc3}: parent sees 0x{seen_copy:02x} (0x11 => COW-isolated)");
    println!(
        "PROBE-MINHERIT VERDICT: {}",
        if seen_share == 0x22 && seen_default == 0x11 {
            "minherit(VM_INHERIT_SHARE) SHARES across fork while default stays COW -> clean per-region vfork primitive"
        } else if seen_share == 0x22 {
            "SHARE shares, but default ALSO shared (unexpected) -> investigate"
        } else {
            "VM_INHERIT_SHARE did NOT share across fork -> minherit is NOT the vfork primitive"
        }
    );

    unsafe {
        libc::munmap(p.cast(), len);
        libc::munmap(q.cast(), len);
        libc::munmap(r.cast(), len);
    }
}

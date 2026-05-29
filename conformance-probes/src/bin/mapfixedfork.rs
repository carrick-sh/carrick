//! MAP_FIXED|MAP_PRIVATE over a shared page, then fork — the OPPOSITE order to
//! `mapfixed.rs` (which repoints in the child). Here the PARENT repoints a
//! shared-aperture VA to a private mapping and writes a private value BEFORE
//! forking. Linux semantics for a MAP_PRIVATE page across fork:
//!   - the child inherits the parent's pre-fork private content (0xBB), then
//!   - each side's later writes are isolated (COW): the child's write never
//!     reaches the parent and the parent's write never reaches the child.
//!
//! This exercises carrick's per-process private overlay aperture being
//! fork-snapshotted AND the stage-1 repoint being inherited via the cloned
//! page tables. Run under `--fs host`. Bidirectional cross-fork sentinels.

use conformance_probes::report;

fn main() {
    unsafe {
        let len = 4096;
        let p = libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            report!(setup_ok = false);
            return;
        }
        let cell = p as *mut u8;
        *cell = 0xAA;

        // PARENT repoints the shared VA to a private mapping, then writes 0xBB.
        let q = libc::mmap(
            p,
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        let fixed_ok = q == p;
        if fixed_ok {
            *cell = 0xBB;
        }

        // c2p: child -> parent; p2c: parent -> child (a 1-byte handshake each).
        let mut c2p = [0i32; 2];
        let mut p2c = [0i32; 2];
        libc::pipe(c2p.as_mut_ptr());
        libc::pipe(p2c.as_mut_ptr());

        let pid = libc::fork();
        if pid == 0 {
            let child_saw = *cell; // expect 0xBB (inherited parent's private value)
            *cell = 0xCC; // child's private write
            let b = [child_saw];
            libc::write(c2p[1], b.as_ptr() as *const libc::c_void, 1);
            // Wait for the parent to do its post-fork write (0xDD).
            let mut g = [0u8; 1];
            libc::read(p2c[0], g.as_mut_ptr() as *mut libc::c_void, 1);
            let child_after = *cell; // expect still 0xCC (parent's 0xDD didn't leak)
            let b2 = [child_after];
            libc::write(c2p[1], b2.as_ptr() as *const libc::c_void, 1);
            libc::_exit(0);
        }

        // Parent: read child_saw, observe its own page is unaffected by the
        // child's write, then write 0xDD and let the child re-check.
        let mut child_saw = [0u8; 1];
        libc::read(c2p[0], child_saw.as_mut_ptr() as *mut libc::c_void, 1);
        let parent_before = *cell; // expect 0xBB (child's 0xCC didn't leak in)
        *cell = 0xDD;
        let go = [1u8];
        libc::write(p2c[1], go.as_ptr() as *const libc::c_void, 1);
        let mut child_after = [0u8; 1];
        libc::read(c2p[0], child_after.as_mut_ptr() as *mut libc::c_void, 1);
        let mut st = 0;
        while libc::wait4(pid, &mut st, 0, core::ptr::null_mut()) < 0 {}
        let parent_final = *cell; // expect 0xDD

        report!(
            setup_ok = true,
            fixed_ok = fixed_ok,
            // Child inherited the parent's pre-fork private value.
            child_inherited_private = child_saw[0] == 0xBB,
            // Child's write did not leak into the parent.
            parent_isolated_from_child = parent_before == 0xBB,
            // Parent's write did not leak into the child.
            child_isolated_from_parent = child_after[0] == 0xCC,
            parent_keeps_own_write = parent_final == 0xDD,
        );
    }
}

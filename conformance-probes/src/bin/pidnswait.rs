//! pidnswait: a process in a PID namespace forks two children and reaps them.
//! wait4 must return each child's ns-local pid (the same value fork returned),
//! and kill(child, 0) must succeed for a live child while a clearly-foreign
//! pid is ESRCH. Asserts the fork-return == wait-return identity and the
//! membership check, all as deterministic booleans (docs/namespaces-design.md
//! §5.3).
use conformance_probes::{report, reap};
fn main() {
    unsafe {
        let a = libc::fork();
        if a == 0 {
            // brief work then exit; parent reaps.
            libc::_exit(0);
        }
        let b = libc::fork();
        if b == 0 {
            libc::_exit(0);
        }
        // Both children are live (or zombies); kill(pid,0) probes existence.
        let a_alive = libc::kill(a, 0) == 0;
        let b_alive = libc::kill(b, 0) == 0;
        // A foreign pid that is not a namespace member → ESRCH. 999999 is well
        // beyond any ns-local pid this tiny tree allocates.
        let foreign = libc::kill(999_999, 0);
        let foreign_esrch = foreign == -1 && conformance_probes::errno() == libc::ESRCH;
        let (ra, _) = reap(a);
        let (rb, _) = reap(b);
        report!(
            both_children_alive = a_alive && b_alive,
            foreign_pid_esrch = foreign_esrch,
            wait_a_eq_fork_a = ra == a,
            wait_b_eq_fork_b = rb == b,
            // children get distinct, small ns-local pids
            children_distinct = a != b,
        );
    }
}

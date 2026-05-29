//! sched_getattr(pid, attr, size, flags): read a task's scheduling attributes.
//! carrick was ENOSYS (LTP sched_getattr02 TFAILed). Now: pid 0/self →
//! success with a zeroed SCHED_OTHER sched_attr (size field set); flags!=0 /
//! size<SCHED_ATTR_SIZE_VER0(48) / NULL attr → EINVAL; a non-existent pid →
//! ESRCH. Raw syscall so musl can't pre-validate. Deterministic vs Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        let mut attr = [0u8; 48];
        let p = attr.as_mut_ptr() as i64;

        // self (pid 0), valid → success; the kernel fills size and policy.
        let r1 = libc::syscall(libc::SYS_sched_getattr, 0i64, p, 48i64, 0i64);
        println!("getattr_self_ok={}", r1 == 0);
        let sz = u32::from_le_bytes(attr[0..4].try_into().unwrap());
        let pol = u32::from_le_bytes(attr[4..8].try_into().unwrap());
        println!("getattr_size_48={}", sz == 48);
        println!("getattr_policy_sched_other={}", pol == 0);

        // NULL attr → EINVAL.
        let r2 = libc::syscall(libc::SYS_sched_getattr, 0i64, 0i64, 48i64, 0i64);
        println!("getattr_null_einval={}", r2 == -1 && errno() == libc::EINVAL);

        // size < 48 → EINVAL.
        let r3 = libc::syscall(libc::SYS_sched_getattr, 0i64, p, 47i64, 0i64);
        println!("getattr_small_size_einval={}", r3 == -1 && errno() == libc::EINVAL);

        // unknown flags → EINVAL.
        let r4 = libc::syscall(libc::SYS_sched_getattr, 0i64, p, 48i64, 1000i64);
        println!("getattr_bad_flags_einval={}", r4 == -1 && errno() == libc::EINVAL);

        // non-existent pid → ESRCH.
        let r5 = libc::syscall(libc::SYS_sched_getattr, 4_000_000i64, p, 48i64, 0i64);
        println!("getattr_bad_pid_esrch={}", r5 == -1 && errno() == libc::ESRCH);

        let _ = errno;
    }
}

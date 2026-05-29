//! semctl(SETVAL) value-range validation (LTP semctl05): a semaphore value
//! must be in [0, SEMVMX(32767)]; a negative or too-large value → ERANGE.
//! carrick forwarded to the host semctl, which doesn't enforce the Linux
//! bound, so out-of-range values wrongly succeeded. Deterministic, line-exact.

use conformance_probes::errno;

fn main() {
    unsafe {
        let semid = libc::semget(libc::IPC_PRIVATE, 1, 0o600 | libc::IPC_CREAT);
        if semid < 0 {
            println!("semget_ok=false");
            return;
        }

        // SETVAL with a negative value → ERANGE.
        let r1 = libc::semctl(semid, 0, libc::SETVAL, -1i32);
        println!("setval_neg_erange={}", r1 == -1 && errno() == libc::ERANGE);

        // SETVAL with a value > SEMVMX(32767) → ERANGE.
        let r2 = libc::semctl(semid, 0, libc::SETVAL, 300000i32);
        println!("setval_toobig_erange={}", r2 == -1 && errno() == libc::ERANGE);

        // SETVAL with a valid value → success.
        let r3 = libc::semctl(semid, 0, libc::SETVAL, 5i32);
        println!("setval_ok={}", r3 == 0);

        libc::semctl(semid, 0, libc::IPC_RMID);
        let _ = errno;
    }
}

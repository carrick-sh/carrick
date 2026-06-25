//! SysV semctl(IPC_STAT) struct translation: the returned aarch64 semid64_ds
//! must carry the real ipc64_perm (mode @20, owner ids @4/@8/@12) plus
//! sem_nsems @64 and a nonzero sem_ctime @56 — carrick was returning an
//! all-zero buffer with only sem_nsems filled, so sem_perm.mode/uid/gid and the
//! times all read back zero. Stands in for LTP semctl01.
//!
//! Deterministic booleans only: the requested mode constant, the requested
//! nsems, and relationships (owner ids == geteuid/getegid, ctime != 0). No raw
//! uid/gid/time values (non-deterministic across hosts) ever reach stdout.


fn main() {
    unsafe {
        // Create a private 3-semaphore set with perms 0o642.
        let id = libc::semget(libc::IPC_PRIVATE, 3, libc::IPC_CREAT | 0o642);
        if id < 0 {
            println!("semget_ok=false");
            println!("sem_mode_lo9=ERR");
            println!("sem_nsems=ERR");
            println!("sem_uid_is_euid=false");
            println!("sem_gid_is_egid=false");
            println!("sem_cuid_is_euid=false");
            println!("sem_ctime_nonzero=false");
            return;
        }
        println!("semget_ok=true");

        // aarch64 semid64_ds is 88 bytes; the kernel ipc64_perm is the first 48:
        // key@0(i32), uid@4(u32), gid@8(u32), cuid@12(u32), cgid@16(u32),
        // mode@20(u32), seq@24(u16). Then sem_otime@48(u64), sem_ctime@56(u64),
        // sem_nsems@64(u64).
        let mut buf = [0u8; 88];
        let rc = libc::semctl(id, 0, libc::IPC_STAT, buf.as_mut_ptr() as *mut libc::c_void);
        if rc != 0 {
            println!("semctl_stat_ok=false");
            println!("sem_mode_lo9=ERR");
            println!("sem_nsems=ERR");
            println!("sem_uid_is_euid=false");
            println!("sem_gid_is_egid=false");
            println!("sem_cuid_is_euid=false");
            println!("sem_ctime_nonzero=false");
            libc::semctl(id, 0, libc::IPC_RMID);
            return;
        }
        println!("semctl_stat_ok=true");

        let perm_uid = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let perm_gid = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let perm_cuid = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let perm_mode = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        let sem_ctime = u64::from_le_bytes(buf[56..64].try_into().unwrap());
        let sem_nsems = u64::from_le_bytes(buf[64..72].try_into().unwrap());

        let euid = libc::geteuid();
        let egid = libc::getegid();

        // The permission low 9 bits are the constant we requested (0o642) and the
        // set size is the constant we requested (3) — deterministic. Owner ids and
        // ctime are compared as RELATIONSHIPS so no raw value reaches stdout.
        println!("sem_mode_lo9={}", perm_mode & 0o777);
        println!("sem_nsems={}", sem_nsems);
        println!("sem_uid_is_euid={}", perm_uid == euid);
        println!("sem_gid_is_egid={}", perm_gid == egid);
        println!("sem_cuid_is_euid={}", perm_cuid == euid);
        println!("sem_ctime_nonzero={}", sem_ctime != 0);

        libc::semctl(id, 0, libc::IPC_RMID);
    }
}

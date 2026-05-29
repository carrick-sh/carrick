//! SysV msgctl(IPC_STAT) struct translation: the returned msqid64_ds must carry
//! the ipc64_perm fields (key @0, mode @20) — carrick was leaving them zero
//! because it only filled the msg_* fields. Stands in for LTP msgctl01.
//! Deterministic booleans, diffed line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        let key: i32 = 0x4321;
        let id = libc::msgget(key, 0o660 | libc::IPC_CREAT);
        if id < 0 {
            println!("msgget_ok=false");
            println!("msg_perm_key_matches=false");
            println!("msg_perm_mode_0660=false");
            return;
        }
        println!("msgget_ok=true");
        // msqid64_ds is 120 bytes on aarch64; the kernel ipc64_perm is the
        // first 48: key@0 (i32), mode@20 (u32).
        let mut buf = [0u8; 120];
        let rc = libc::msgctl(id, libc::IPC_STAT, buf.as_mut_ptr() as *mut _);
        let perm_key = i32::from_le_bytes(buf[0..4].try_into().unwrap());
        let perm_mode = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        println!("msgctl_stat_ok={}", rc == 0);
        println!("msg_perm_key_matches={}", perm_key == key);
        println!("msg_perm_mode_0660={}", perm_mode == 0o660);
        let _ = errno;
        libc::msgctl(id, libc::IPC_RMID, std::ptr::null_mut());
    }
}

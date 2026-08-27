//! container_gate: Gate B reducer for "many containers in one carrier".
//!
//! Run DIRECTLY as the container command (it must be ns-pid 1), once per
//! container, with one host directory bind-mounted at `/gate` in BOTH:
//!
//!     /tmp/p <role: alpha|beta> <mode: solo|paired>
//!
//! INVARIANTS (one `key=value` line each, to stdout AND `/gate/<role>.report`):
//!   getpid=1                   — this container's init is pid 1 of its own ns
//!   hostname=<uname nodename>  — the harness sets a distinct one per container
//!   own_marker_written=true    — `/etc/carrick-gate-<role>` written into THIS rootfs
//!   foreign_marker_visible=false — the peer's marker is not in this rootfs
//!   child_comm_visible=true    — a forked child renamed `gate-<role>` shows in /proc
//!   foreign_proc_visible=false — no `gate-<peer>` task is visible in this /proc
//!   peer_ready=true            — (paired) the peer was alive when /proc was scanned
//! `paired` rendezvous through `/gate/<role>.ready` / `.scanned` so both
//! containers scan `/proc` while the other's child is alive. Exits 7 (alpha)
//! or 9 (beta) so the harness can prove independent exit statuses.
use conformance_probes::reap;
use std::io::Write;

const READY_TIMEOUT_MS: u64 = 60_000;

fn role_code(role: &str) -> i32 {
    match role {
        "alpha" => 7,
        "beta" => 9,
        _ => 3,
    }
}

fn peer_of(role: &str) -> &'static str {
    if role == "alpha" {
        "beta"
    } else {
        "alpha"
    }
}

fn wait_for(path: &str) -> bool {
    let mut waited = 0;
    while waited < READY_TIMEOUT_MS {
        if std::path::Path::new(path).exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        waited += 100;
    }
    false
}

fn proc_comms() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(dir) = std::fs::read_dir("/proc") {
        for entry in dir.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if let Ok(comm) = std::fs::read_to_string(format!("/proc/{name}/comm")) {
                out.push(comm.trim().to_string());
            }
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).map(String::as_str).unwrap_or("alpha");
    let paired = args.get(2).map(String::as_str) == Some("paired");
    let peer = peer_of(role);
    let my_comm = format!("gate-{role}");
    let peer_comm = format!("gate-{peer}");

    let pid = unsafe { libc::getpid() };
    let mut host = [0 as libc::c_char; 256];
    unsafe { libc::gethostname(host.as_mut_ptr(), host.len() - 1) };
    let hostname = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .into_owned();

    let own_marker = format!("/etc/carrick-gate-{role}");
    let peer_marker = format!("/etc/carrick-gate-{peer}");
    let own_marker_written = std::fs::write(&own_marker, b"1\n").is_ok();

    // A child with a distinctive comm, alive while the peer scans /proc.
    let child = unsafe { libc::fork() };
    if child == 0 {
        let name = std::ffi::CString::new(my_comm.clone()).unwrap();
        unsafe {
            libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0);
        }
        loop {
            unsafe { libc::pause() };
        }
    }
    let child_forked = child > 0;
    if paired {
        let _ = std::fs::write(format!("/gate/{role}.ready"), b"1\n");
    }
    let peer_ready = !paired || wait_for(&format!("/gate/{peer}.ready"));
    let comms = proc_comms();
    let child_comm_visible = comms.iter().any(|c| c == &my_comm);
    let foreign_proc_visible = comms.iter().any(|c| c == &peer_comm);
    let foreign_marker_visible = std::path::Path::new(&peer_marker).exists();
    if paired {
        let _ = std::fs::write(format!("/gate/{role}.scanned"), b"1\n");
        let _ = wait_for(&format!("/gate/{peer}.scanned"));
    }
    if child_forked {
        unsafe {
            libc::kill(child, libc::SIGKILL);
            let _ = reap(child);
        }
    }
    let lines = format!(
        "role={role}\ngetpid={pid}\nhostname={hostname}\nown_marker_written={own_marker_written}\n\
         foreign_marker_visible={foreign_marker_visible}\nchild_comm_visible={child_comm_visible}\n\
         foreign_proc_visible={foreign_proc_visible}\npeer_ready={peer_ready}\n"
    );
    print!("{lines}");
    if let Ok(mut file) = std::fs::File::create(format!("/gate/{role}.report")) {
        let _ = file.write_all(lines.as_bytes());
    }
    std::process::exit(role_code(role));
}

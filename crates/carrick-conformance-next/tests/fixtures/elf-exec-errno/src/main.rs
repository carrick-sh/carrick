//! Clean-room ELF fixtures from elf(5) and the System V ABI, without sections.
//! Record both execve errno and death after the exec no-return boundary.
use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn elf(interpreter: bool) -> Vec<u8> {
    let mut bytes = vec![0; 0x1000 + 12];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&183_u16.to_le_bytes()); // EM_AARCH64
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&(if interpreter { 2_u16 } else { 1 }).to_le_bytes());
    let load = if interpreter {
        bytes[64..68].copy_from_slice(&3_u32.to_le_bytes()); // PT_INTERP
        bytes[72..80].copy_from_slice(&176_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&6_u64.to_le_bytes()); // excludes NUL
        bytes[176..183].copy_from_slice(b"/ld.so\0");
        120
    } else {
        64
    };
    bytes[load..load + 4].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
    bytes[load + 4..load + 8].copy_from_slice(&5_u32.to_le_bytes()); // PF_R | PF_X
    bytes[load + 8..load + 16].copy_from_slice(&0x1000_u64.to_le_bytes());
    bytes[load + 16..load + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[load + 32..load + 40].copy_from_slice(&12_u64.to_le_bytes());
    bytes[load + 40..load + 48].copy_from_slice(&0x1000_u64.to_le_bytes());
    bytes[load + 48..load + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
    // mov x0, #0; mov x8, #93; svc #0: a valid static exit(0) control.
    for (offset, instruction) in [0xd2800000_u32, 0xd2800ba8, 0xd4000001]
        .into_iter()
        .enumerate()
    {
        bytes[0x1000 + offset * 4..0x1004 + offset * 4].copy_from_slice(&instruction.to_le_bytes());
    }
    bytes
}

fn observe(name: &str, bytes: &[u8]) {
    let path = format!("/tmp/elf-exec-errno-{name}");
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path_c = CString::new(path.as_str()).unwrap();
    // SAFETY: all buffers and C strings are live; fds/pid are checked and reaped.
    unsafe {
        let mut fds = [-1; 2];
        assert_eq!(libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC), 0);
        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            libc::close(fds[0]);
            let argv = [path_c.as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null()];
            libc::execve(path_c.as_ptr(), argv.as_ptr(), envp.as_ptr());
            let error = *libc::__errno_location();
            assert_eq!(libc::write(fds[1], (&error as *const i32).cast(), 4), 4);
            libc::_exit(0);
        }
        libc::close(fds[1]);
        let mut pollfd = libc::pollfd {
            fd: fds[0],
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(libc::poll(&mut pollfd, 1, 5000), 1, "exec pipe timeout");
        let mut error = -1_i32; // EOF: exec did not return an errno.
        let count = libc::read(fds[0], (&mut error as *mut i32).cast(), 4);
        assert!(count == 0 || count == 4);
        libc::close(fds[0]);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut status = 0;
        loop {
            let waited = libc::waitpid(pid, &mut status, libc::WNOHANG);
            if waited == pid {
                break;
            }
            assert_eq!(waited, 0);
            if Instant::now() >= deadline {
                libc::kill(pid, libc::SIGKILL);
                panic!("exec child timeout");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let signal = if libc::WIFSIGNALED(status) {
            libc::WTERMSIG(status)
        } else {
            0
        };
        let exit = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        println!("{name}_errno={error}");
        println!("{name}_signal={signal}");
        println!("{name}_exit={exit}");
    }
    std::fs::remove_file(path).unwrap();
}

fn main() {
    assert_eq!(std::env::consts::ARCH, "aarch64");
    println!(
        "fixture_source_sha256={}",
        env!("CARRICK_ELF_FIXTURE_SOURCE_SHA256")
    );
    // Avoid a core artifact if Linux kills a child after the no-return point.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &limit), 0);
    }
    observe("valid", &elf(false));
    let mut relocatable = elf(false);
    relocatable[16..18].copy_from_slice(&1_u16.to_le_bytes()); // ET_REL
    observe("et_rel", &relocatable);
    let mut oversized = elf(false);
    oversized[104..112].copy_from_slice(&11_u64.to_le_bytes()); // p_memsz < p_filesz
    observe("filesz_gt_memsz", &oversized);
    observe("unterminated_interp", &elf(true));
}

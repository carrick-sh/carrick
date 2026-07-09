use super::errno;
use super::report::{ProbeReport, Status};

const TEST_ADDR: usize = 0x7000_0000_0000;
const TEST_LEN: usize = 0x4000;

pub fn page_size() -> Result<ProbeReport, String> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Ok(ProbeReport::new("page-size", Status::Fail)
            .field("sysconf", page_size)
            .field("errno", errno()));
    }

    let status = if page_size == 4096 {
        Status::Pass
    } else {
        Status::Fail
    };

    Ok(ProbeReport::new("page-size", status)
        .field("host_page_size", page_size)
        .field("linux_guest_page_size", 4096))
}

pub fn fixed_map_child() -> Result<ProbeReport, String> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Ok(ProbeReport::new("fixed-map", Status::Fail).field("fork_errno", errno()));
    }

    if pid == 0 {
        let ptr = unsafe {
            libc::mmap(
                TEST_ADDR as *mut libc::c_void,
                TEST_LEN,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            unsafe { libc::_exit(71) };
        }
        if ptr as usize != TEST_ADDR {
            unsafe { libc::_exit(72) };
        }
        unsafe {
            libc::munmap(ptr, TEST_LEN);
            libc::_exit(0);
        }
    }

    let mut status_word = 0;
    let wait = unsafe { libc::waitpid(pid, &mut status_word, 0) };
    if wait != pid {
        return Ok(ProbeReport::new("fixed-map", Status::Fail)
            .field("waitpid", wait)
            .field("errno", errno()));
    }

    if libc::WIFEXITED(status_word) {
        let code = libc::WEXITSTATUS(status_word);
        let status = if code == 0 {
            Status::Pass
        } else {
            Status::Fail
        };
        return Ok(ProbeReport::new("fixed-map", status)
            .field("addr", format!("0x{TEST_ADDR:x}"))
            .field("len", TEST_LEN)
            .field("child_exit", code));
    }

    Ok(ProbeReport::new("fixed-map", Status::Fail)
        .field("addr", format!("0x{TEST_ADDR:x}"))
        .field("status_word", status_word))
}

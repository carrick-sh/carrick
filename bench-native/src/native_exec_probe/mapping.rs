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

pub fn subpage_protect() -> Result<ProbeReport, String> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Ok(ProbeReport::new("subpage-protect", Status::Fail)
            .field("sysconf", page_size)
            .field("errno", errno()));
    }
    let page_size = page_size as usize;
    let len = page_size;
    if len < 16_384 {
        return Ok(ProbeReport::new("subpage-protect", Status::Pass)
            .field("host_page_size", page_size)
            .field("host_supports_4k_pages", page_size == 4096)
            .field("result", "host_page_smaller_than_16k"));
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Ok(ProbeReport::new("subpage-protect", Status::Fail).field("fork_errno", errno()));
    }
    if pid == 0 {
        child_subpage_protect(len);
    }

    let mut status_word = 0;
    let wait = unsafe { libc::waitpid(pid, &mut status_word, 0) };
    if wait != pid {
        return Ok(ProbeReport::new("subpage-protect", Status::Fail)
            .field("waitpid", wait)
            .field("errno", errno()));
    }

    let code = if libc::WIFEXITED(status_word) {
        libc::WEXITSTATUS(status_word)
    } else {
        128
    };
    let status = match code {
        0 | 94 | 95 => Status::Pass,
        _ => Status::Fail,
    };
    Ok(ProbeReport::new("subpage-protect", status)
        .field("host_page_size", page_size)
        .field("child_exit", code)
        .field("meaning", subpage_exit_meaning(code)))
}

fn child_subpage_protect(len: usize) -> ! {
    unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            libc::_exit(92);
        }
        std::ptr::write_volatile(ptr.cast::<u8>(), 1);
        std::ptr::write_volatile(ptr.cast::<u8>().add(4096), 2);
        if libc::mprotect(ptr.cast::<u8>().add(4096).cast(), 4096, libc::PROT_NONE) != 0 {
            libc::munmap(ptr, len);
            libc::_exit(93);
        }

        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = subpage_fault_handler as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()) != 0 {
            libc::_exit(96);
        }
        if libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut()) != 0 {
            libc::_exit(97);
        }

        let _neighbor = std::ptr::read_volatile(ptr.cast::<u8>());
        let _target = std::ptr::read_volatile(ptr.cast::<u8>().add(4096));
        libc::munmap(ptr, len);
        libc::_exit(95);
    }
}

extern "C" fn subpage_fault_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _uap: *mut libc::c_void,
) {
    unsafe {
        libc::_exit(94);
    }
}

fn subpage_exit_meaning(code: i32) -> &'static str {
    match code {
        0 => "exact_4k_subpage_protection",
        92 => "mmap_failed",
        93 => "mprotect_rejected_subpage_range",
        94 => "neighbor_or_target_faulted_after_subpage_mprotect",
        95 => "target_subpage_access_succeeded",
        96 => "sigsegv_handler_install_failed",
        97 => "sigbus_handler_install_failed",
        _ => "unexpected_child_status",
    }
}

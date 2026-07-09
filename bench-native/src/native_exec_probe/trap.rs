use super::errno;
use super::report::{ProbeReport, Status};

const MOV_W0_77_RET: [u8; 8] = [
    0xa0, 0x09, 0x80, 0x52, // mov w0, #77
    0xc0, 0x03, 0x5f, 0xd6, // ret
];

type GatewayFn = extern "C" fn() -> u32;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UcontextSnapshot {
    x: [u64; 9],
    sp: u64,
    pc: u64,
}

unsafe extern "C" {
    fn carrick_snapshot_ucontext(uap: *mut libc::c_void, out: *mut UcontextSnapshot)
        -> libc::c_int;
    fn carrick_probe_clear_icache(start: *mut libc::c_void, len: usize);
}

pub fn brk_trap() -> Result<ProbeReport, String> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Ok(ProbeReport::new("brk-trap", Status::Fail).field("fork_errno", errno()));
    }

    if pid == 0 {
        child_brk_trap();
    }

    let mut status_word = 0;
    let wait = unsafe { libc::waitpid(pid, &mut status_word, 0) };
    if wait != pid {
        return Ok(ProbeReport::new("brk-trap", Status::Fail)
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
        return Ok(ProbeReport::new("brk-trap", status).field("child_exit", code));
    }

    Ok(ProbeReport::new("brk-trap", Status::Fail).field("status_word", status_word))
}

fn child_brk_trap() -> ! {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = brk_handler as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTRAP, &action, std::ptr::null_mut()) != 0 {
            libc::_exit(80);
        }

        std::arch::asm!(
            "mov x0, #123",
            "mov x8, #172",
            "brk #0xf000",
            options(nostack)
        );

        libc::_exit(81);
    }
}

extern "C" fn brk_handler(_sig: libc::c_int, _info: *mut libc::siginfo_t, uap: *mut libc::c_void) {
    let mut snapshot = UcontextSnapshot::default();
    let rc = unsafe { carrick_snapshot_ucontext(uap, &mut snapshot) };
    let ok = rc == 0 && snapshot.x[0] == 123 && snapshot.x[8] == 172 && snapshot.pc != 0;
    unsafe {
        libc::_exit(if ok { 0 } else { 82 });
    }
}

pub fn branch_gateway() -> Result<ProbeReport, String> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Ok(ProbeReport::new("branch-gateway", Status::Fail).field("page_size", page_size));
    }

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Ok(ProbeReport::new("branch-gateway", Status::Fail).field("mmap_errno", errno()));
    }

    let base = ptr as usize;
    let guest_pc = base;
    let gateway_pc = base + 64;
    let Some(branch) = encode_b(guest_pc, gateway_pc) else {
        unsafe {
            libc::munmap(ptr, page_size as usize);
        }
        return Ok(ProbeReport::new("branch-gateway", Status::Fail).field("reason", "branch_range"));
    };

    unsafe {
        std::ptr::write_unaligned(ptr.cast::<u32>(), branch);
        std::ptr::copy_nonoverlapping(
            MOV_W0_77_RET.as_ptr(),
            ptr.cast::<u8>().add(64),
            MOV_W0_77_RET.len(),
        );
        carrick_probe_clear_icache(ptr, 72);
    }

    let protect =
        unsafe { libc::mprotect(ptr, page_size as usize, libc::PROT_READ | libc::PROT_EXEC) };
    if protect != 0 {
        let err = errno();
        unsafe {
            libc::munmap(ptr, page_size as usize);
        }
        return Ok(ProbeReport::new("branch-gateway", Status::Fail).field("mprotect_errno", err));
    }

    let func: GatewayFn = unsafe { std::mem::transmute(ptr) };
    let value = func();

    unsafe {
        libc::munmap(ptr, page_size as usize);
    }

    let status = if value == 77 {
        Status::Pass
    } else {
        Status::Fail
    };
    Ok(ProbeReport::new("branch-gateway", status)
        .field("return", value)
        .field("branch_word", format!("0x{branch:08x}")))
}

fn encode_b(from: usize, to: usize) -> Option<u32> {
    let byte_delta = (to as isize).checked_sub(from as isize)?;
    if byte_delta % 4 != 0 {
        return None;
    }

    let instruction_delta = byte_delta / 4;
    if !(-(1 << 25)..(1 << 25)).contains(&instruction_delta) {
        return None;
    }

    Some(0x1400_0000 | ((instruction_delta as u32) & 0x03ff_ffff))
}

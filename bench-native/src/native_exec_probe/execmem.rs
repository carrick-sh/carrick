use super::errno;
use super::report::{ProbeReport, Status};

const MOV_W0_42_RET: [u8; 8] = [
    0x40, 0x05, 0x80, 0x52, // mov w0, #42
    0xc0, 0x03, 0x5f, 0xd6, // ret
];

type ProbeFn = extern "C" fn() -> u32;

pub fn execmem() -> Result<ProbeReport, String> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Ok(ProbeReport::new("execmem", Status::Fail).field("page_size", page_size));
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
        return Ok(ProbeReport::new("execmem", Status::Fail).field("mmap_errno", errno()));
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            MOV_W0_42_RET.as_ptr(),
            ptr.cast::<u8>(),
            MOV_W0_42_RET.len(),
        );
    }

    let protect =
        unsafe { libc::mprotect(ptr, page_size as usize, libc::PROT_READ | libc::PROT_EXEC) };
    if protect != 0 {
        let err = errno();
        unsafe {
            libc::munmap(ptr, page_size as usize);
        }
        return Ok(ProbeReport::new("execmem", Status::Fail).field("mprotect_errno", err));
    }

    let func: ProbeFn = unsafe { std::mem::transmute(ptr) };
    let value = func();

    unsafe {
        libc::munmap(ptr, page_size as usize);
    }

    let status = if value == 42 {
        Status::Pass
    } else {
        Status::Fail
    };
    Ok(ProbeReport::new("execmem", status)
        .field("mode", "rw-to-rx")
        .field("return", value))
}

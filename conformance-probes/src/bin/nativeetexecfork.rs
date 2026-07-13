//! A low-address static `ET_EXEC` must preserve Linux guest coordinates when
//! Carrick executes it through biased DSR.  Observe an architectural PC and a
//! static-data pointer on both sides of `fork(2)` without formatting or
//! allocating in the child, then report only deterministic boolean witnesses.

const FOUR_GIB: usize = 1usize << 32;
static STATIC_SENTINEL: u64 = 0x4341_5252_4943_4b21;

#[repr(C)]
struct ChildWitness {
    function_pc: usize,
    static_data: usize,
    static_value: u64,
}

#[inline(never)]
fn function_pc() -> usize {
    let pc: usize;
    unsafe {
        core::arch::asm!(
            "adr {pc}, .",
            pc = out(reg) pc,
            options(nomem, nostack, preserves_flags)
        );
    }
    pc
}

unsafe fn write_witness(fd: i32, witness: &ChildWitness) -> bool {
    let bytes = core::slice::from_raw_parts(
        witness as *const ChildWitness as *const u8,
        core::mem::size_of::<ChildWitness>(),
    );
    let mut written = 0;
    while written < bytes.len() {
        let rc = libc::write(
            fd,
            bytes[written..].as_ptr() as *const libc::c_void,
            bytes.len() - written,
        );
        if rc <= 0 {
            return false;
        }
        written += rc as usize;
    }
    true
}

unsafe fn read_witness(fd: i32, witness: &mut ChildWitness) -> bool {
    let bytes = core::slice::from_raw_parts_mut(
        witness as *mut ChildWitness as *mut u8,
        core::mem::size_of::<ChildWitness>(),
    );
    let mut read = 0;
    while read < bytes.len() {
        let rc = libc::read(
            fd,
            bytes[read..].as_mut_ptr() as *mut libc::c_void,
            bytes.len() - read,
        );
        if rc <= 0 {
            return false;
        }
        read += rc as usize;
    }
    true
}

fn main() {
    let parent_function_pc = function_pc();
    let parent_static_data = core::ptr::addr_of!(STATIC_SENTINEL) as usize;
    let mut child = ChildWitness {
        function_pc: 0,
        static_data: 0,
        static_value: 0,
    };
    let mut child_reported = false;
    let mut child_exit_zero = false;

    unsafe {
        let mut pipe_fds = [-1_i32; 2];
        if libc::pipe(pipe_fds.as_mut_ptr()) == 0 {
            let pid = libc::fork();
            if pid == 0 {
                libc::close(pipe_fds[0]);
                let witness = ChildWitness {
                    function_pc: function_pc(),
                    static_data: core::ptr::addr_of!(STATIC_SENTINEL) as usize,
                    static_value: core::ptr::read_volatile(core::ptr::addr_of!(STATIC_SENTINEL)),
                };
                let wrote = write_witness(pipe_fds[1], &witness);
                libc::close(pipe_fds[1]);
                libc::_exit(if wrote && witness.static_value == STATIC_SENTINEL {
                    0
                } else {
                    1
                });
            }

            libc::close(pipe_fds[1]);
            if pid > 0 {
                child_reported = read_witness(pipe_fds[0], &mut child);
                let mut status = 0_i32;
                let waited = loop {
                    let rc = libc::wait4(pid, &mut status, 0, core::ptr::null_mut());
                    if rc == -1 && conformance_probes::errno() == libc::EINTR {
                        continue;
                    }
                    break rc;
                };
                child_exit_zero =
                    waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            }
            libc::close(pipe_fds[0]);
        }
    }

    println!(
        "parent_function_pc_below_4g={} parent_static_data_below_4g={} child_function_pc_same={} child_static_data_same={} child_static_value_retained={} child_exit_zero={}",
        parent_function_pc < FOUR_GIB,
        parent_static_data < FOUR_GIB,
        child_reported && child.function_pc == parent_function_pc,
        child_reported && child.static_data == parent_static_data,
        child_reported && child.static_value == STATIC_SENTINEL,
        child_exit_zero,
    );
}

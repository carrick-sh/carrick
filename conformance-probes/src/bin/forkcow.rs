//! Fork memory-isolation probe. After fork(), a child's writes to its own
//! address space MUST NOT be visible in the parent (copy-on-write). Tests a
//! .data global, a .bss global, a brk/heap allocation, and an mmap region —
//! the four backing kinds carrick maps. The conformance harness runs this
//! identical static binary under carrick and real Linux and diffs; on real
//! Linux every line is `_isolated=true`. A `false` under carrick pinpoints a
//! fork that shares guest memory instead of COWing it.
//!
//! Deterministic: booleans only.

static mut DATA_GLOBAL: u64 = 0x1111_1111;
static mut BSS_GLOBAL: u64 = 0; // .bss (zero-initialized)

fn main() {
    // mmap an anonymous page and seed it.
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let mmap_ok = page != libc::MAP_FAILED;
    if mmap_ok {
        unsafe { *(page as *mut u64) = 0x2222_2222 };
    }
    // A heap allocation (brk/malloc-backed).
    let mut heap = vec![0x3333_3333_u64; 1];

    unsafe {
        DATA_GLOBAL = 0x1111_1111;
        BSS_GLOBAL = 0x4444_4444;
    }

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child clobbers every region, then exits without flushing anything.
        unsafe {
            DATA_GLOBAL = 0xDEAD_DEAD;
            BSS_GLOBAL = 0xDEAD_DEAD;
            if mmap_ok {
                *(page as *mut u64) = 0xDEAD_DEAD;
            }
        }
        heap[0] = 0xDEAD_DEAD;
        unsafe { libc::_exit(0) };
    }

    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    // Parent must still see its own pre-fork values (COW isolation).
    println!("data_isolated={}", unsafe { DATA_GLOBAL } == 0x1111_1111);
    println!("bss_isolated={}", unsafe { BSS_GLOBAL } == 0x4444_4444);
    println!("heap_isolated={}", heap[0] == 0x3333_3333);
    if mmap_ok {
        println!("mmap_isolated={}", unsafe { *(page as *const u64) } == 0x2222_2222);
    } else {
        println!("mmap_isolated=skip");
    }
}

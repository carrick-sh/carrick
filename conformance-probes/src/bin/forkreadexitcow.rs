//! A forked child's first write into an inherited page must not deadlock
//! against a sibling's exit. This is LTP `fork07`'s shape: the parent fills a
//! file, then forks a hundred children in a row; each child `read`s ONE byte
//! through the inherited (shared-offset) descriptor into a stack buffer and
//! `_exit`s with what it saw.
//!
//! The page holding that buffer (a static the child otherwise never touches)
//! was written by the parent before the fork, so it is copy-on-write in every
//! child and the `read` is the child's first store into it: the kernel
//! materialises the child's private copy in the middle of servicing
//! `read(2)`, while the previous child is retiring —
//! closing its copy of the same open file description — under the process
//! exit path. Linux orders the file-table teardown of an exiting task before
//! anything that could exclude a sibling's page fault, so the two never wait
//! on each other. A runtime that takes a process-wide retirement lock and
//! THEN closes the exiting task's descriptors, while a sibling holds the
//! description lock and waits for the same retirement lock to copy its page,
//! wedges both — `ltp-fork07` hung deterministically at its ninth child.
//!
//! Output (deterministic): the byte each child returned via its exit status,
//! reaped in fork order, and the shared file offset afterwards — every child
//! consumed exactly one byte through the one description.

const CHILDREN: usize = 100;
const FILL: u8 = b'a';

/// The read buffer. Two pages wide so the byte in the middle sits on a page
/// no other static shares; the child stores nothing else before its `read`
/// (no allocation, no `println!`), so the syscall's copy-in is the first
/// write into the inherited copy-on-write page.
static mut BUF: [u8; 8192] = [0; 8192];
const BUF_OFFSET: usize = 4096;

fn main() {
    unsafe {
        let path = c"/tmp/forkreadexitcow";
        let fd = libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if fd < 0 {
            println!("setup=false errno={}", *libc::__errno_location());
            return;
        }
        let fill = [FILL; CHILDREN];
        let written = libc::write(fd, fill.as_ptr().cast(), fill.len());
        let seek = libc::lseek(fd, 0, libc::SEEK_SET);
        println!("setup=true written={written} seek={seek}");

        let mut pids = Vec::with_capacity(CHILDREN);
        for child in 0..CHILDREN {
            // Touched by the parent before every fork so the page is dirty
            // and shared copy-on-write with the child; the child's `read`
            // then stores into it for the first time.
            let slot = std::ptr::addr_of_mut!(BUF).cast::<u8>().add(BUF_OFFSET);
            std::ptr::write_volatile(slot, 0);
            let pid = libc::fork();
            if pid == 0 {
                let n = libc::read(fd, slot.cast(), 1);
                let code = if n == 1 {
                    std::ptr::read_volatile(slot) as i32
                } else {
                    0xff
                };
                libc::_exit(code);
            }
            if pid < 0 {
                println!("child={child} fork=false");
                break;
            }
            pids.push((child, pid));
        }

        for (child, pid) in pids {
            let mut status = 0i32;
            let rc = libc::waitpid(pid, &mut status, 0);
            let outcome = if rc != pid {
                format!("waitpid_errno{}", *libc::__errno_location())
            } else if libc::WIFSIGNALED(status) {
                format!("sig{}", libc::WTERMSIG(status))
            } else {
                let code = libc::WEXITSTATUS(status);
                if code == FILL as i32 {
                    "byte=fill".to_string()
                } else {
                    format!("byte={code}")
                }
            };
            println!("child={child} {outcome}");
        }

        let offset = libc::lseek(fd, 0, libc::SEEK_CUR);
        println!("offset={offset}");
        libc::close(fd);
        libc::unlink(path.as_ptr());
    }
}

//! inotify MODIFY is published only after positive write completion.
//! Failed and empty writes must not consume an IN_ONESHOT watch.
use std::ffi::CString;

fn events(fd: i32) -> (isize, i32, Vec<u32>) {
    let mut buffer = [0u8; 256];
    let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    let error = if count < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    } else {
        0
    };
    let mut masks = Vec::new();
    let mut cursor = 0;
    while count > 0 && cursor + 16 <= count as usize {
        let mask = u32::from_ne_bytes(buffer[cursor + 4..cursor + 8].try_into().unwrap());
        let len = u32::from_ne_bytes(buffer[cursor + 12..cursor + 16].try_into().unwrap()) as usize;
        masks.push(mask);
        cursor += 16 + len;
    }
    (count, error, masks)
}
fn main() {
    unsafe {
        let path = CString::new(format!("/tmp/carrick-inotifywrite-{}", libc::getpid())).unwrap();
        let writer = libc::open(
            path.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        );
        assert!(writer >= 0);
        let reader = libc::open(path.as_ptr(), libc::O_RDONLY);
        assert!(reader >= 0);
        let watcher = libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC);
        assert!(watcher >= 0);
        assert!(
            libc::inotify_add_watch(watcher, path.as_ptr(), libc::IN_MODIFY | libc::IN_ONESHOT)
                >= 0
        );
        let rejected = libc::write(reader, b"x".as_ptr().cast(), 1);
        let rejected_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        println!("rejected_write={rejected}");
        println!("rejected_errno={rejected_errno}");
        println!("after_rejected={:?}", events(watcher));
        println!(
            "empty_write={}",
            libc::write(writer, b"".as_ptr().cast(), 0)
        );
        println!("after_empty={:?}", events(watcher));
        println!(
            "successful_write={}",
            libc::write(writer, b"x".as_ptr().cast(), 1)
        );
        println!("after_success={:?}", events(watcher));
        println!("drained={:?}", events(watcher));
        assert_eq!(libc::close(reader), 0);
        assert_eq!(libc::close(writer), 0);
        assert_eq!(libc::close(watcher), 0);
        assert_eq!(libc::unlink(path.as_ptr()), 0);
    }
}

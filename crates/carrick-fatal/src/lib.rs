//! Single fatal sink for carrier invariant violations (`carrick_fatal!`).
//!
//! Provides non-allocating crash reporting and recording for fatal carrier
//! assertions, formatting directly into stack buffers and recording into
//! `CARRICK_LAST_FATAL` so post-mortem core dumps retain the exact domain and
//! reason.

use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

pub const CARRICK_FATAL_MAGIC: u64 = 0x4341_5252_4641_544c; // "CARRFATL"
pub const MAX_DOMAIN_LEN: usize = 64;
pub const MAX_MESSAGE_LEN: usize = 1024;

/// A fixed-size record preserved in `.data` so post-mortem debuggers (`lldb`)
/// can read the failure reason out of a core dump even with no debug symbols.
#[repr(C)]
pub struct LastFatalRecord {
    pub magic: u64,
    pub length: usize,
    pub domain_len: usize,
    pub domain: [u8; MAX_DOMAIN_LEN],
    pub message: [u8; MAX_MESSAGE_LEN],
}

impl LastFatalRecord {
    pub const fn empty() -> Self {
        Self {
            magic: 0,
            length: 0,
            domain_len: 0,
            domain: [0u8; MAX_DOMAIN_LEN],
            message: [0u8; MAX_MESSAGE_LEN],
        }
    }

    pub fn domain_str(&self) -> &str {
        let len = self.domain_len.min(MAX_DOMAIN_LEN);
        core::str::from_utf8(&self.domain[..len]).unwrap_or_default()
    }

    pub fn message_str(&self) -> &str {
        let len = self.length.min(MAX_MESSAGE_LEN);
        core::str::from_utf8(&self.message[..len]).unwrap_or_default()
    }
}

/// Transparent wrapper around `UnsafeCell` to grant interior mutability and `Sync`
/// to the static `CARRICK_LAST_FATAL` record.
#[repr(transparent)]
pub struct FatalStorage(pub core::cell::UnsafeCell<LastFatalRecord>);

unsafe impl Sync for FatalStorage {}

impl core::ops::Deref for FatalStorage {
    type Target = LastFatalRecord;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.0.get() }
    }
}

#[unsafe(no_mangle)]
pub static CARRICK_LAST_FATAL: FatalStorage =
    FatalStorage(core::cell::UnsafeCell::new(LastFatalRecord::empty()));

pub type FatalHook = fn(&'static str, &str);

static FATAL_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static FATAL_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Register an optional callback invoked on the fatal crash path before aborting.
///
/// Typically used by the runtime to record the fatal event into the event ring.
/// The registered hook is called at most once.
pub fn set_hook(hook: FatalHook) {
    FATAL_HOOK.store(hook as *mut (), Ordering::Release);
}

struct SliceWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> SliceWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    fn write_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let remaining = self.buf.len().saturating_sub(self.len);
        let to_copy = bytes.len().min(remaining);
        self.buf[self.len..self.len + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.len += to_copy;
    }

    fn truncate_valid_utf8(&mut self) {
        if let Err(e) = core::str::from_utf8(&self.buf[..self.len]) {
            self.len = e.valid_up_to();
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }
}

impl<'a> core::fmt::Write for SliceWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.write_str(s);
        Ok(())
    }
}

/// Format the fatal message and line into fixed buffers without allocating.
/// Returns `(msg_len, line_len)`.
#[doc(hidden)]
pub fn format_fatal_parts(
    domain: &'static str,
    args: core::fmt::Arguments<'_>,
    msg_buf: &mut [u8; MAX_MESSAGE_LEN],
    line_buf: &mut [u8; 1280],
) -> (usize, usize) {
    let mut msg_writer = SliceWriter::new(msg_buf);
    let _ = core::fmt::write(&mut msg_writer, args);
    msg_writer.truncate_valid_utf8();
    let msg_str = msg_writer.as_str();

    let mut line_writer = SliceWriter::new(line_buf);
    line_writer.write_str("carrick fatal [");
    line_writer.write_str(domain);
    line_writer.write_str("]: ");
    line_writer.write_str(msg_str);
    line_writer.write_str("\n");

    (msg_writer.len, line_writer.len)
}

fn write_stderr(mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(2, bytes.as_ptr().cast(), bytes.len()) };
        if written > 0 {
            if let Ok(w) = usize::try_from(written) {
                bytes = &bytes[w..];
                continue;
            }
            break;
        }
        if written < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
}

/// One fatal sink for carrier invariant violations.
///
/// Formats into a fixed stack buffer without heap allocation, writes
/// `carrick fatal [<domain>]: <msg>\n` to fd 2 with `libc::write`, records the
/// crash into `CARRICK_LAST_FATAL`, calls any registered hook at most once, and
/// then terminates the process with `std::process::abort()`.
pub fn fatal(domain: &'static str, args: core::fmt::Arguments<'_>) -> ! {
    if FATAL_ACTIVE
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        loop {
            unsafe { libc::sched_yield() };
        }
    }

    let mut msg_buf = [0u8; MAX_MESSAGE_LEN];
    let mut line_buf = [0u8; 1280];
    let (msg_len, line_len) = format_fatal_parts(domain, args, &mut msg_buf, &mut line_buf);

    write_stderr(&line_buf[..line_len]);

    let msg_bytes = &msg_buf[..msg_len];
    let msg_str = core::str::from_utf8(msg_bytes).unwrap_or_default();

    let record = unsafe { &mut *CARRICK_LAST_FATAL.0.get() };
    record.magic = CARRICK_FATAL_MAGIC;
    let dom_bytes = domain.as_bytes();
    let dom_len = dom_bytes.len().min(MAX_DOMAIN_LEN);
    record.domain_len = dom_len;
    record.domain[..dom_len].copy_from_slice(&dom_bytes[..dom_len]);
    record.domain[dom_len..].fill(0);

    record.length = msg_len;
    record.message[..msg_len].copy_from_slice(msg_bytes);
    record.message[msg_len..].fill(0);

    let hook_ptr = FATAL_HOOK.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !hook_ptr.is_null() {
        let hook: FatalHook = unsafe { core::mem::transmute(hook_ptr) };
        hook(domain, msg_str);
    }

    std::process::abort();
}

#[macro_export]
macro_rules! carrick_fatal {
    ($domain:literal, $($arg:tt)*) => {
        $crate::fatal($domain, ::core::format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static THREAD_ALLOC_COUNT: Cell<usize> = const { Cell::new(0) };
    }

    struct CountingAllocator;

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            THREAD_ALLOC_COUNT.with(|c| c.set(c.get() + 1));
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    fn thread_allocations() -> usize {
        THREAD_ALLOC_COUNT.with(|c| c.get())
    }

    #[test]
    fn formatting_never_allocates() {
        let mut msg_buf = [0u8; MAX_MESSAGE_LEN];
        let mut line_buf = [0u8; 1280];

        let before = thread_allocations();
        let (msg_len, line_len) = format_fatal_parts(
            "test_domain",
            format_args!("test value {} string {}", 12345, "abc"),
            &mut msg_buf,
            &mut line_buf,
        );
        let after = thread_allocations();
        assert_eq!(before, after, "formatting must not allocate on the heap");
        let msg = core::str::from_utf8(&msg_buf[..msg_len]).unwrap();
        assert_eq!(msg, "test value 12345 string abc");
        assert_eq!(
            &line_buf[..line_len],
            b"carrick fatal [test_domain]: test value 12345 string abc\n"
        );
    }

    #[test]
    fn overlong_message_is_truncated_not_panicked() {
        let mut msg_buf = [0u8; MAX_MESSAGE_LEN];
        let mut line_buf = [0u8; 1280];

        let long_str = "x".repeat(3000);
        let before = thread_allocations();
        let (msg_len, line_len) = format_fatal_parts(
            "trunc_domain",
            format_args!("prefix: {}", long_str),
            &mut msg_buf,
            &mut line_buf,
        );
        let after = thread_allocations();
        assert_eq!(
            before, after,
            "formatting must not allocate even when truncated"
        );
        let msg = core::str::from_utf8(&msg_buf[..msg_len]).unwrap();
        assert_eq!(msg.len(), MAX_MESSAGE_LEN);
        assert!(msg.starts_with("prefix: xxxx"));
        assert!(line_len <= 1280);
        assert_eq!(line_buf[line_len - 1], b'\n');
    }

    #[test]
    fn child_process_fatal_abort_and_stderr() {
        if std::env::var("CARRICK_FATAL_TEST_MODE").as_deref() == Ok("normal") {
            carrick_fatal!("child_domain", "invariant violated: code {}", 99);
        }
        if std::env::var("CARRICK_FATAL_TEST_MODE").as_deref() == Ok("overlong") {
            let long_str = "A".repeat(2000);
            carrick_fatal!("long_domain", "overlong msg: {}", long_str);
        }
        if std::env::var("CARRICK_FATAL_TEST_MODE").as_deref() == Ok("hook") {
            set_hook(|dom, msg| {
                if dom == "hook_domain" && msg.contains("hook test") {
                    unsafe { libc::write(1, b"HOOK_OK\n".as_ptr().cast(), 8) };
                }
            });
            carrick_fatal!("hook_domain", "hook test: {}", 1);
        }

        let current_exe = std::env::current_exe().expect("current exe");

        // 1. Normal fatal abort assertion
        let output = std::process::Command::new(&current_exe)
            .arg("--exact")
            .arg("tests::child_process_fatal_abort_and_stderr")
            .env("CARRICK_FATAL_TEST_MODE", "normal")
            .output()
            .expect("run child");

        assert!(!output.status.success(), "child must fail with abort");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(output.status.signal(), Some(libc::SIGABRT));
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr,
            "carrick fatal [child_domain]: invariant violated: code 99\n"
        );

        // 2. Overlong fatal abort assertion
        let output_overlong = std::process::Command::new(&current_exe)
            .arg("--exact")
            .arg("tests::child_process_fatal_abort_and_stderr")
            .env("CARRICK_FATAL_TEST_MODE", "overlong")
            .output()
            .expect("run child overlong");

        assert!(!output_overlong.status.success());
        let stderr_long = String::from_utf8_lossy(&output_overlong.stderr);
        assert!(stderr_long.starts_with("carrick fatal [long_domain]: overlong msg: AAA"));
        assert!(stderr_long.ends_with('\n'));

        // 3. Hook invocation assertion
        let output_hook = std::process::Command::new(&current_exe)
            .arg("--exact")
            .arg("tests::child_process_fatal_abort_and_stderr")
            .env("CARRICK_FATAL_TEST_MODE", "hook")
            .output()
            .expect("run child hook");

        assert!(!output_hook.status.success());
        let stdout_hook = String::from_utf8_lossy(&output_hook.stdout);
        assert!(stdout_hook.contains("HOOK_OK\n"));
    }
}

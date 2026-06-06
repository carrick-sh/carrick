//! macOS/FreeBSD CrossProcessFutex implementation.

use carrick_hal::futex::CrossProcessFutex;

pub struct BsdFutex;

impl CrossProcessFutex for BsdFutex {
    fn wait(&self, host_addr: usize, expected: u32, timeout_us: u32) -> i64 {
        carrick_host::ulock::wait(host_addr, expected, timeout_us)
    }

    fn wake(&self, host_addr: usize, all: bool) -> i64 {
        carrick_host::ulock::wake(host_addr, all)
    }
}

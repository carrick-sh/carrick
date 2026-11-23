//! Large zeroed, page-aligned backing that costs only the pages its user
//! touches.
//!
//! A product crate (it holds no test-only behaviour), so the host-test
//! fixtures that product crates such as `carrick-el1-linux` export can reach
//! it without depending on `carrick-test-support`, which the carrier-only
//! process invariant keeps out of every product dependency graph.
//! `carrick-test-support` re-exports both types.
//!
//! VM-free tests back carrier-sized ABI areas (the 128 MiB EL1 region, the
//! IPC directory and its pools) with zeroed memory. `alloc_zeroed` does not
//! keep such an area lazy: the standard library's system allocator serves an
//! alignment above its minimum (16 bytes) with an aligned allocation it then
//! fills with zeroes, so every page is committed before the test reads one.
//! A 128 MiB region then costs 128 MiB of resident memory per fixture, and a
//! suite of such fixtures grew to 10 GB (carrick#2822).
//!
//! [`ZeroedPages`] maps fresh anonymous memory instead. The kernel supplies
//! zero pages on first touch, so resident memory follows what the test
//! writes, and dropping the owner unmaps the whole range. On Linux it opts
//! out of transparent huge pages, which would commit 2 MiB per touch.

use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

/// An owned, page-aligned, zero-filled anonymous mapping.
pub struct ZeroedPages {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: the mapping is plain memory owned by this value; it is not tied to
// the creating thread.
unsafe impl Send for ZeroedPages {}
// SAFETY: shared access hands out only raw pointers; callers synchronize the
// bytes they place there.
unsafe impl Sync for ZeroedPages {}

impl ZeroedPages {
    /// Map `len` zeroed read-write bytes, aligned to the host page size.
    ///
    /// # Panics
    ///
    /// When `len` is zero or the host refuses the mapping.
    pub fn new(len: usize) -> Self {
        assert!(len > 0, "ZeroedPages needs a nonzero length");
        // SAFETY: a fresh private anonymous mapping replaces nothing.
        let mapped = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert!(
            mapped != libc::MAP_FAILED,
            "anonymous mapping of {len} bytes failed: {}",
            std::io::Error::last_os_error()
        );
        // With transparent huge pages enabled, one touch would commit 2 MiB;
        // a sparse fixture would then cost hundreds of times what it writes.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: advice on exactly the mapping made above.
        unsafe {
            libc::madvise(mapped, len, libc::MADV_NOHUGEPAGE);
        }
        Self {
            ptr: NonNull::new(mapped.cast()).unwrap(),
            len,
        }
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub fn as_non_null(&self) -> NonNull<u8> {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        false
    }
}

impl Drop for ZeroedPages {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly the mapping this value owns; no view
        // outlives the owner.
        let unmapped = unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
        debug_assert_eq!(unmapped, 0);
    }
}

/// An owned, lazily committed `T` whose all-zero bytes are a valid value.
///
/// The `Box` of a large zeroed record without its resident cost.
pub struct ZeroedBox<T> {
    pages: ZeroedPages,
    _value: PhantomData<T>,
}

// SAFETY: owns its `T` exactly as `Box<T>` does.
unsafe impl<T: Send> Send for ZeroedBox<T> {}
// SAFETY: shares its `T` exactly as `Box<T>` does.
unsafe impl<T: Sync> Sync for ZeroedBox<T> {}

impl<T> ZeroedBox<T> {
    /// # Safety
    ///
    /// All-zero bytes must be a valid `T`.
    pub unsafe fn new_zeroed() -> Self {
        assert!(
            align_of::<T>() <= page_size(),
            "a page-aligned mapping cannot hold this alignment"
        );
        Self {
            pages: ZeroedPages::new(size_of::<T>().max(1)),
            _value: PhantomData,
        }
    }

    /// Keep the value for the rest of the process, as `Box::leak` does.
    ///
    /// The pages a test touched stay resident until the process exits;
    /// prefer an owner that drops with the test.
    pub fn leak(this: Self) -> &'static mut T {
        let ptr = this.pages.as_ptr().cast::<T>();
        core::mem::forget(this);
        // SAFETY: a valid, never-unmapped `T`, exclusively handed out here.
        unsafe { &mut *ptr }
    }
}

impl<T> Deref for ZeroedBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: aligned, sized and zero-valid per `new_zeroed`.
        unsafe { &*self.pages.as_ptr().cast::<T>() }
    }
}

impl<T> DerefMut for ZeroedBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`, and `&mut self` is exclusive.
        unsafe { &mut *self.pages.as_ptr().cast::<T>() }
    }
}

impl<T> Drop for ZeroedBox<T> {
    fn drop(&mut self) {
        // SAFETY: the value is valid and dropped once; `pages` unmaps after.
        unsafe { core::ptr::drop_in_place(self.pages.as_ptr().cast::<T>()) };
    }
}

fn page_size() -> usize {
    // SAFETY: sysconf reads a constant of this process.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_are_zeroed_page_aligned_and_writable() {
        let pages = ZeroedPages::new(1 << 20);
        assert_eq!(pages.as_ptr() as usize % 4096, 0);
        // SAFETY: the range is this mapping's.
        let bytes = unsafe { core::slice::from_raw_parts_mut(pages.as_ptr(), pages.len()) };
        assert!(bytes.iter().all(|&b| b == 0));
        bytes[pages.len() - 1] = 7;
        assert_eq!(bytes[pages.len() - 1], 7);
    }

    #[test]
    fn a_zeroed_box_drops_its_value_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct Counted(#[allow(dead_code)] [u64; 4]);
        impl Drop for Counted {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }
        // SAFETY: all-zero is a valid `Counted`.
        let mut value = unsafe { ZeroedBox::<Counted>::new_zeroed() };
        assert_eq!(value.0, [0; 4]);
        value.0[3] = 9;
        drop(value);
        assert_eq!(DROPS.load(Ordering::Relaxed), 1);
    }
}

//! Guest user memory for VM-free tests that drive the in-guest kernel on the
//! host.
//!
//! Hosted EL1/CPL0 tests run the kernel's user-copy paths with guest user
//! virtual addresses that are host addresses. Those paths refuse, correctly,
//! any range not wholly below [`USER_CEILING`]. A host pointer to a test's
//! stack, heap or static data is therefore not a guest user VA: macOS
//! happens to place them below 2^47, but a Linux aarch64 PIE test binary and
//! its heap live near `0xaaaa_aaaa_xxxx`, above it, and every such copy is
//! EFAULT there.
//!
//! [`GuestUserBuffer`] owns zeroed bytes mapped exactly, without replacing
//! any mapping, inside [`GUEST_USER_WINDOW`], a per-host window below the
//! ceiling. It hands out typed [`UserVa`]s and offers typed reads and
//! writes, so tests never turn a host pointer into a guest address.
//!
//! Every live buffer is registered. [`assert_guest_args`] is the harness
//! check: a syscall argument that is readable host memory outside every
//! registered buffer is a host pointer posing as a guest user VA, and it
//! fails the test on every host, including macOS, where "below the ceiling"
//! alone would not catch it.

use carrick_guest_arch::{USER_CEILING, UserVa};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// The guest user window buffers are allocated from, `[start, end)`.
///
/// Both hosts' windows are wholly below [`USER_CEILING`].
///
/// - macOS 27 refuses user allocations below `0x70_0000_0000` and places
///   its own malloc regions just above that, so its window sits at 16 TiB,
///   clear of both.
/// - Linux places a PIE test binary, its heap and its mappings near the top
///   of the user address space (`0xaaaa_xxxx_xxxx`, `0xffff_xxxx_xxxx` with
///   48-bit VAs), so its window sits low, below even a 39-bit kernel's
///   `0x80_0000_0000` user limit.
#[cfg(target_os = "macos")]
pub const GUEST_USER_WINDOW: core::ops::Range<u64> = 0x1000_0000_0000..0x1100_0000_0000;
#[cfg(not(target_os = "macos"))]
pub const GUEST_USER_WINDOW: core::ops::Range<u64> = 0x70_0000_0000..0x7c_0000_0000;

const _: () = assert!(GUEST_USER_WINDOW.end <= USER_CEILING);

/// Buffers start on this stride, which covers either host's page size.
const STRIDE: u64 = 0x1_0000;

/// Live buffers, keyed by start address, valued by mapped length.
fn registry() -> &'static Mutex<BTreeMap<u64, u64>> {
    static LIVE: OnceLock<Mutex<BTreeMap<u64, u64>>> = OnceLock::new();
    LIVE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Whether `[address, address + len)` lies inside one live buffer.
pub fn is_guest_user_range(address: u64, len: u64) -> bool {
    let Some(end) = address.checked_add(len) else {
        return false;
    };
    let live = registry().lock().unwrap();
    live.range(..=address)
        .next_back()
        .is_some_and(|(&start, &mapped)| end <= start + mapped)
}

/// Map `len` zeroed read-write bytes at exactly `address`, or `None` when
/// any part of the range is already mapped. Never replaces a mapping.
fn map_exact_unreplaced(address: u64, len: usize) -> Option<*mut u8> {
    #[cfg(target_os = "macos")]
    {
        let mut at = address as libc::vm_address_t;
        // SAFETY: a fixed allocation in this task fails rather than
        // replacing anything already mapped.
        #[allow(deprecated)]
        let status = unsafe {
            libc::vm_allocate(libc::mach_task_self(), &mut at, len, libc::VM_FLAGS_FIXED)
        };
        (status == libc::KERN_SUCCESS).then_some(at as *mut u8)
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: MAP_FIXED_NOREPLACE fails rather than replacing a mapping.
        let mapped = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        (mapped != libc::MAP_FAILED && mapped as u64 == address).then_some(mapped.cast())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    {
        // A plain hint never replaces a mapping; keep it only where the
        // kernel placed it exactly.
        // SAFETY: a fresh anonymous mapping, unmapped again when it landed
        // elsewhere.
        let mapped = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return None;
        }
        if mapped as u64 != address {
            // SAFETY: unmaps only the mapping made above.
            unsafe { libc::munmap(mapped, len) };
            return None;
        }
        Some(mapped.cast())
    }
}

fn unmap(address: *mut u8, len: usize) {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: releases exactly the allocation this buffer owns.
        #[allow(deprecated)]
        unsafe {
            libc::vm_deallocate(libc::mach_task_self(), address as libc::vm_address_t, len);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        // SAFETY: releases exactly the mapping this buffer owns.
        unsafe {
            libc::munmap(address.cast(), len);
        }
    }
}

/// Zeroed guest user memory at a [`UserVa`] in [`GUEST_USER_WINDOW`].
///
/// The tests' kernel paths read and write it by its guest address while the
/// test owns it; the test reads and writes it through the typed accessors,
/// never through a host pointer it might hand to the kernel instead.
pub struct GuestUserBuffer {
    base: *mut u8,
    mapped: usize,
    len: usize,
}

// SAFETY: the buffer exclusively owns its mapping; access goes through
// `&self`/`&mut self` like any owned byte array.
unsafe impl Send for GuestUserBuffer {}
// SAFETY: shared access only reads through `&self`.
unsafe impl Sync for GuestUserBuffer {}

impl GuestUserBuffer {
    /// `len` zeroed bytes (at least one page is mapped, even for zero).
    pub fn zeroed(len: usize) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(GUEST_USER_WINDOW.start);
        let mapped = len.max(1).next_multiple_of(STRIDE as usize);
        loop {
            let address = NEXT.fetch_add(mapped as u64, Ordering::Relaxed);
            assert!(
                address + mapped as u64 <= GUEST_USER_WINDOW.end,
                "guest user window {GUEST_USER_WINDOW:#x?} is exhausted"
            );
            if let Some(base) = map_exact_unreplaced(address, mapped) {
                registry()
                    .lock()
                    .unwrap()
                    .insert(base as u64, mapped as u64);
                return Self { base, mapped, len };
            }
        }
    }

    /// A buffer holding a copy of `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut buffer = Self::zeroed(bytes.len());
        buffer.as_mut_bytes().copy_from_slice(bytes);
        buffer
    }

    /// A buffer holding `value`.
    pub fn from_value<T: Copy>(value: T) -> Self {
        Self::from_values(core::slice::from_ref(&value))
    }

    /// A buffer holding `values` back to back, as a guest array of `T`.
    pub fn from_values<T: Copy>(values: &[T]) -> Self {
        let mut buffer = Self::zeroed(core::mem::size_of_val(values));
        for (index, value) in values.iter().enumerate() {
            buffer.set(index, *value);
        }
        buffer
    }

    /// The buffer's guest user address.
    pub fn va(&self) -> UserVa {
        UserVa::new(self.base as u64)
    }

    /// The guest user address `offset` bytes in; one past the end is allowed.
    pub fn va_at(&self, offset: usize) -> UserVa {
        assert!(
            offset <= self.len,
            "offset {offset} past {} bytes",
            self.len
        );
        UserVa::new(self.base as u64 + offset as u64)
    }

    /// The guest user address of element `index` of a `T` array.
    pub fn va_of<T>(&self, index: usize) -> UserVa {
        self.va_at(index * core::mem::size_of::<T>())
    }

    /// The buffer's guest user address as a raw syscall argument.
    pub fn arg(&self) -> u64 {
        user_arg(self.va())
    }

    /// The guest user address `offset` bytes in, as a raw syscall argument.
    pub fn arg_at(&self, offset: usize) -> u64 {
        user_arg(self.va_at(offset))
    }

    /// The buffer's length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `len <= mapped` bytes are mapped read-write and owned.
        unsafe { core::slice::from_raw_parts(self.base, self.len) }
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        // SAFETY: `len <= mapped` bytes are mapped read-write and owned.
        unsafe { core::slice::from_raw_parts_mut(self.base, self.len) }
    }

    /// The `T` at byte `offset`, read unaligned.
    pub fn read<T: Copy>(&self, offset: usize) -> T {
        self.check(offset, core::mem::size_of::<T>());
        // SAFETY: bounds checked above; `T: Copy` is read bytewise.
        unsafe { self.base.add(offset).cast::<T>().read_unaligned() }
    }

    /// Write `value` at byte `offset`, unaligned.
    pub fn write<T: Copy>(&mut self, offset: usize, value: T) {
        self.check(offset, core::mem::size_of::<T>());
        // SAFETY: bounds checked above.
        unsafe { self.base.add(offset).cast::<T>().write_unaligned(value) }
    }

    /// Element `index` of a `T` array.
    pub fn get<T: Copy>(&self, index: usize) -> T {
        self.read(index * core::mem::size_of::<T>())
    }

    /// Set element `index` of a `T` array.
    pub fn set<T: Copy>(&mut self, index: usize, value: T) {
        self.write(index * core::mem::size_of::<T>(), value);
    }

    /// The buffer as a `T` array, copied out.
    pub fn values<T: Copy>(&self) -> Vec<T> {
        (0..self.len / core::mem::size_of::<T>())
            .map(|index| self.get(index))
            .collect()
    }

    fn check(&self, offset: usize, size: usize) {
        assert!(
            offset.checked_add(size).is_some_and(|end| end <= self.len),
            "{size} bytes at offset {offset} past {} bytes",
            self.len
        );
    }
}

impl Drop for GuestUserBuffer {
    fn drop(&mut self) {
        registry().lock().unwrap().remove(&(self.base as u64));
        unmap(self.base, self.mapped);
    }
}

impl core::fmt::Debug for GuestUserBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuestUserBuffer")
            .field("va", &self.va())
            .field("len", &self.len)
            .finish()
    }
}

/// One `T` in guest user memory: a typed view of a [`GuestUserBuffer`] for
/// the common single-operand case (a status word, a `sigset_t`, a
/// `stack_t`).
pub struct GuestUserValue<T> {
    buffer: GuestUserBuffer,
    value: core::marker::PhantomData<T>,
}

impl<T: Copy> GuestUserValue<T> {
    pub fn new(value: T) -> Self {
        Self {
            buffer: GuestUserBuffer::from_value(value),
            value: core::marker::PhantomData,
        }
    }

    pub fn get(&self) -> T {
        self.buffer.get(0)
    }

    pub fn set(&mut self, value: T) {
        self.buffer.set(0, value);
    }

    /// The value's guest user address.
    pub fn va(&self) -> UserVa {
        self.buffer.va()
    }

    /// The value's guest user address as a raw syscall argument.
    pub fn arg(&self) -> u64 {
        self.buffer.arg()
    }
}

impl<T> core::fmt::Debug for GuestUserValue<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("GuestUserValue").field(&self.buffer).finish()
    }
}

/// A guest user pointer as a raw syscall argument. `va` must lie in a live
/// [`GuestUserBuffer`]; a deliberately bad pointer is written as its raw
/// value instead.
pub fn user_arg(va: UserVa) -> u64 {
    assert!(
        is_guest_user_range(va.raw(), 0) || is_guest_user_range(va.raw().wrapping_sub(1), 1),
        "{va:?} is not inside a live GuestUserBuffer"
    );
    va.raw()
}

/// Whether one byte at `address` is readable host memory, probed without
/// faulting: the kernel copies it into a pipe or reports EFAULT.
fn host_readable(address: u64) -> bool {
    static PROBE: OnceLock<Mutex<[libc::c_int; 2]>> = OnceLock::new();
    let probe = PROBE.get_or_init(|| {
        let mut fds = [0; 2];
        // SAFETY: `fds` is a two-element array for the new descriptors.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "probe pipe");
        Mutex::new(fds)
    });
    let fds = probe.lock().unwrap();
    // SAFETY: the kernel validates `address` and fails with EFAULT rather
    // than faulting this process.
    let wrote = unsafe { libc::write(fds[1], address as *const libc::c_void, 1) };
    if wrote != 1 {
        return false;
    }
    let mut byte = 0u8;
    // SAFETY: drains the one byte just written into a local.
    let read = unsafe { libc::read(fds[0], (&raw mut byte).cast(), 1) };
    assert_eq!(read, 1, "probe pipe drain");
    true
}

/// Initialise the harness's own state before a test measures allocations.
///
/// The live-buffer registry and the host-readable probe are lazily built
/// statics, and on macOS std's `Mutex` allocates its pthread mutex the first
/// time it is locked (Linux's futex mutex does not). Whichever test locks
/// them first pays those allocations, so a zero-allocation window that
/// reaches [`assert_guest_args`] or [`user_arg`] would count harness work,
/// not kernel work, depending on test order. Call this once before taking
/// the baseline of any allocation-counting window; it builds both statics
/// and takes both locks, leaving later calls allocation-free.
pub fn warm() {
    drop(registry().lock().unwrap());
    // Address 0 is never readable: this builds the probe pipe and takes its
    // lock without needing a mapped byte.
    assert!(!host_readable(0), "address 0 must not be host-readable");
}

/// The harness check for raw syscall arguments a test feeds the kernel.
///
/// Each argument is a scalar, a deliberately invalid address, or a guest
/// user VA inside a live [`GuestUserBuffer`]. An argument that is readable
/// host memory outside every buffer is a host pointer posing as a guest
/// user VA: it panics, on every host.
pub fn assert_guest_args(args: &[u64]) {
    for (index, &arg) in args.iter().enumerate() {
        if arg == 0 || is_guest_user_range(arg, 1) {
            continue;
        }
        assert!(
            !host_readable(arg),
            "syscall argument {index} = {arg:#x} is a host pointer, not a guest user VA; \
             put the operand in a carrick_test_support::GuestUserBuffer"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffers_live_in_the_window_and_round_trip_typed_values() {
        let mut buffer = GuestUserBuffer::from_values(&[1u32, 2, 3]);
        let va = buffer.va().raw();
        assert!(GUEST_USER_WINDOW.contains(&va));
        assert!(carrick_guest_arch::lower_half_range(
            va,
            buffer.len() as u64
        ));
        assert_eq!(buffer.values::<u32>(), [1, 2, 3]);
        buffer.set(1, 7u32);
        assert_eq!(buffer.get::<u32>(1), 7);
        assert_eq!(buffer.va_of::<u32>(2).raw(), va + 8);
        assert_eq!(user_arg(buffer.va_at(12)), va + 12);
        assert!(is_guest_user_range(va, 12));
        drop(buffer);
        assert!(!is_guest_user_range(va, 1), "a dropped buffer deregisters");
        let mut value = GuestUserValue::new(5u64);
        value.set(value.get() + 1);
        assert_eq!(value.get(), 6);
        assert!(is_guest_user_range(value.arg(), 8));
    }

    #[test]
    fn buffers_never_overlap() {
        let a = GuestUserBuffer::zeroed(1);
        let b = GuestUserBuffer::zeroed(STRIDE as usize + 1);
        let c = GuestUserBuffer::zeroed(0);
        let mut spans = [&a, &b, &c].map(|buffer| (buffer.va().raw(), buffer.mapped as u64));
        spans.sort_unstable();
        assert!(
            spans
                .windows(2)
                .all(|pair| pair[0].0 + pair[0].1 <= pair[1].0)
        );
    }

    #[test]
    fn the_harness_check_admits_scalars_bad_addresses_and_buffers() {
        let buffer = GuestUserBuffer::zeroed(16);
        assert_guest_args(&[
            0,
            1,
            1024,
            u64::MAX,
            0xffff_ffff_ffff_f000,
            0x1000,
            buffer.va().raw(),
            buffer.va_at(15).raw(),
        ]);
    }

    #[test]
    #[should_panic(expected = "is a host pointer, not a guest user VA")]
    fn the_harness_check_refuses_a_host_stack_pointer() {
        let local = [0u64; 2];
        assert_guest_args(&[0, local.as_ptr() as u64]);
    }

    #[test]
    #[should_panic(expected = "is a host pointer, not a guest user VA")]
    fn the_harness_check_refuses_a_host_heap_pointer() {
        let heap = Box::new([0u8; 64]);
        assert_guest_args(&[heap.as_ptr() as u64]);
    }

    #[test]
    #[should_panic(expected = "is not inside a live GuestUserBuffer")]
    fn user_arg_refuses_a_host_pointer() {
        let local = 0u64;
        user_arg(UserVa::new(&raw const local as u64));
    }
}

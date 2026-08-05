//! Darwin mappings for the container-lifetime live translation arena.
//!
//! Code and control use distinct Mach memory-entry objects. Code is mapped
//! through separate permanently-RW and permanently-RX aliases; no returned or
//! retained live alias is both writable and executable. Darwin requires a
//! private, empty, constructor-only MAP_JIT bootstrap that is temporarily
//! nominal-RWX and unmapped before arena construction returns.

use carrick_dsr::host::{ForkChildJit, JitRegion, NativeHostJit};
use mach2::kern_return::{KERN_SUCCESS, kern_return_t};
use mach2::mach_port::{mach_port_deallocate, mach_port_mod_refs};
use mach2::memory_object_types::memory_object_size_t;
use mach2::port::{MACH_PORT_NULL, MACH_PORT_RIGHT_SEND, mach_port_t};
use mach2::traps::mach_task_self;
use mach2::vm::{
    mach_make_memory_entry_64, mach_vm_allocate, mach_vm_deallocate, mach_vm_map, mach_vm_protect,
    mach_vm_region,
};
use mach2::vm_inherit::VM_INHERIT_SHARE;
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_NONE, VM_PROT_READ, VM_PROT_WRITE, vm_prot_t};
use mach2::vm_region::{VM_REGION_BASIC_INFO_64, vm_region_basic_info_64};
use mach2::vm_statistics::VM_FLAGS_ANYWHERE;
use std::io;
use std::marker::PhantomData;
use std::ops::Range;
use std::ptr::NonNull;

pub const LIVE_ARENA_TRANSIT_SCHEMA_V1: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveArenaTransitV1 {
    pub schema: u32,
    pub code_len: u64,
    pub control_len: u64,
    pub nonce: [u8; 16],
}

/// Opaque, independently-owned send-right references for one exec handoff.
/// Raw Mach names remain private to this module.
pub struct LiveArenaTransitRights {
    _code: MachSendRight,
    _control: MachSendRight,
}

struct MachSendRight {
    name: mach_port_t,
}

impl MachSendRight {
    fn from_kernel(name: mach_port_t, operation: &'static str) -> io::Result<Self> {
        if name == MACH_PORT_NULL {
            return Err(io::Error::other(format!(
                "{operation}: returned a null send right"
            )));
        }
        Ok(Self { name })
    }

    fn duplicate(&self) -> io::Result<Self> {
        check_kr("mach_port_mod_refs duplicate send right", unsafe {
            mach_port_mod_refs(mach_task_self(), self.name, MACH_PORT_RIGHT_SEND, 1)
        })?;
        Ok(Self { name: self.name })
    }

    #[cfg(test)]
    fn name_for_test(&self) -> mach_port_t {
        self.name
    }
}

impl Drop for MachSendRight {
    fn drop(&mut self) {
        let _ = unsafe { mach_port_deallocate(mach_task_self(), self.name) };
    }
}

struct VmMapping {
    address: u64,
    len: u64,
}

impl VmMapping {
    fn allocate(len: usize) -> io::Result<Self> {
        let len = u64::try_from(len).map_err(|_| invalid_input("mapping length exceeds u64"))?;
        let mut address = 0;
        check_kr("mach_vm_allocate live arena backing", unsafe {
            mach_vm_allocate(mach_task_self(), &mut address, len, VM_FLAGS_ANYWHERE)
        })?;
        let mapping = Self { address, len };
        mapping.validate_address_and_size()?;
        Ok(mapping)
    }

    fn map_entry(entry: &MachSendRight, len: usize, protection: vm_prot_t) -> io::Result<Self> {
        if protection & VM_PROT_WRITE != 0 && protection & VM_PROT_EXECUTE != 0 {
            return Err(invalid_input(
                "live arena mapping may not be writable and executable",
            ));
        }
        let len = u64::try_from(len).map_err(|_| invalid_input("mapping length exceeds u64"))?;
        let mut address = 0;
        check_kr("mach_vm_map live arena alias", unsafe {
            mach_vm_map(
                mach_task_self(),
                &mut address,
                len,
                0,
                VM_FLAGS_ANYWHERE,
                entry.name,
                0,
                0,
                protection,
                protection,
                VM_INHERIT_SHARE,
            )
        })?;
        let mapping = Self { address, len };
        mapping.validate_address_and_size()?;
        mapping.validate_protections(protection, protection)?;
        Ok(mapping)
    }

    fn validate_address_and_size(&self) -> io::Result<()> {
        let page = host_page_size()?;
        if self.address == 0 || !self.address.is_multiple_of(page as u64) || self.len == 0 {
            return Err(io::Error::other(format!(
                "Mach returned invalid mapping address/size: address=0x{:x} size={}",
                self.address, self.len
            )));
        }
        let region = query_region(self.address)?;
        let region_end = region
            .address
            .checked_add(region.len)
            .ok_or_else(|| io::Error::other("Mach region end overflowed"))?;
        let mapping_end = self
            .address
            .checked_add(self.len)
            .ok_or_else(|| io::Error::other("Mach mapping end overflowed"))?;
        if region.address > self.address || region_end < mapping_end {
            return Err(io::Error::other(format!(
                "Mach mapping does not cover requested size: requested address=0x{:x} size={} returned region address=0x{:x} size={}",
                self.address, self.len, region.address, region.len
            )));
        }
        Ok(())
    }

    fn validate_protections(
        &self,
        expected_current: vm_prot_t,
        expected_max: vm_prot_t,
    ) -> io::Result<()> {
        let region = query_region(self.address)?;
        if region.current != expected_current || region.maximum != expected_max {
            return Err(io::Error::other(format!(
                "Mach mapping protections differ: current={} max={} expected_current={} expected_max={}",
                region.current, region.maximum, expected_current, expected_max
            )));
        }
        Ok(())
    }

    fn base(&self) -> usize {
        self.address as usize
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.len as usize
    }
}

impl Drop for VmMapping {
    fn drop(&mut self) {
        let _ = unsafe { mach_vm_deallocate(mach_task_self(), self.address, self.len) };
    }
}

/// Constructor-only MAP_JIT bootstrap required by Darwin to mint a single
/// memory entry that can later produce distinct RW and RX aliases. The map is
/// nominally RWX, but contains no published code and is always unmapped before
/// `DarwinLiveArena::new` returns; it never becomes a live arena alias.
struct OwnedMmap {
    address: *mut libc::c_void,
    len: usize,
}

impl OwnedMmap {
    fn from_successful_result(address: *mut libc::c_void, len: usize) -> Self {
        Self { address, len }
    }

    fn non_null(&self) -> io::Result<NonNull<libc::c_void>> {
        NonNull::new(self.address)
            .ok_or_else(|| io::Error::other("MAP_JIT bootstrap returned null"))
    }
}

impl Drop for OwnedMmap {
    fn drop(&mut self) {
        let _ = unsafe { libc::munmap(self.address, self.len) };
    }
}

struct MapJitBootstrap {
    mapping: OwnedMmap,
}

impl MapJitBootstrap {
    fn new(len: usize) -> io::Result<Self> {
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Self::from_owned(OwnedMmap::from_successful_result(mapped, len))
    }

    fn from_owned(mapping: OwnedMmap) -> io::Result<Self> {
        let address = mapping.non_null()?;
        let bootstrap = Self { mapping };
        let page = host_page_size()?;
        if !(address.as_ptr() as usize).is_multiple_of(page) {
            return Err(io::Error::other(
                "MAP_JIT bootstrap is not host-page aligned",
            ));
        }
        let region = query_region(address.as_ptr() as u64)?;
        let all = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
        if region.current != all || region.maximum != all {
            return Err(io::Error::other(format!(
                "MAP_JIT bootstrap protections differ: current={} max={} expected={all}",
                region.current, region.maximum
            )));
        }
        Ok(bootstrap)
    }

    fn address(&self) -> io::Result<NonNull<libc::c_void>> {
        self.mapping.non_null()
    }
}

struct RegionInfo {
    address: u64,
    len: u64,
    current: vm_prot_t,
    maximum: vm_prot_t,
}

fn query_region(address: u64) -> io::Result<RegionInfo> {
    let mut observed = address;
    let mut len = 0;
    let mut info = vm_region_basic_info_64::default();
    let mut count = vm_region_basic_info_64::count();
    let mut object_name = MACH_PORT_NULL;
    let result = unsafe {
        mach_vm_region(
            mach_task_self(),
            &mut observed,
            &mut len,
            VM_REGION_BASIC_INFO_64,
            (&raw mut info).cast::<i32>(),
            &mut count,
            &mut object_name,
        )
    };
    if object_name != MACH_PORT_NULL {
        let _ = unsafe { mach_port_deallocate(mach_task_self(), object_name) };
    }
    check_kr("mach_vm_region live arena mapping", result)?;
    Ok(RegionInfo {
        address: observed,
        len,
        current: info.protection,
        maximum: info.max_protection,
    })
}

fn create_control_memory_entry(len: usize) -> io::Result<MachSendRight> {
    let backing = VmMapping::allocate(len)?;
    let backing_region = query_region(backing.address)?;
    let permission = VM_PROT_READ | VM_PROT_WRITE;
    if backing_region.current != permission || backing_region.maximum & permission != permission {
        return Err(io::Error::other(format!(
            "Mach backing protections cannot create requested object: current={} max={} requested={permission}",
            backing_region.current, backing_region.maximum
        )));
    }

    let requested = u64::try_from(len).map_err(|_| invalid_input("entry length exceeds u64"))?;
    let mut returned: memory_object_size_t = requested;
    let mut raw = MACH_PORT_NULL;
    let result = unsafe {
        mach_make_memory_entry_64(
            mach_task_self(),
            &mut returned,
            backing.address,
            permission,
            &mut raw,
            MACH_PORT_NULL,
        )
    };
    if result != KERN_SUCCESS {
        if raw != MACH_PORT_NULL {
            let _ = unsafe { mach_port_deallocate(mach_task_self(), raw) };
        }
        return Err(mach_error("mach_make_memory_entry_64 live arena", result));
    }
    let entry = MachSendRight::from_kernel(raw, "mach_make_memory_entry_64 live arena")?;
    if returned != requested {
        return Err(io::Error::other(format!(
            "Mach memory entry size redirected: requested={requested} returned={returned}"
        )));
    }
    drop(backing);
    Ok(entry)
}

fn create_code_memory_entry(len: usize) -> io::Result<MachSendRight> {
    let backing = MapJitBootstrap::new(len)?;
    let requested = u64::try_from(len).map_err(|_| invalid_input("entry length exceeds u64"))?;
    let mut returned: memory_object_size_t = requested;
    let mut raw = MACH_PORT_NULL;
    let result = unsafe {
        mach_make_memory_entry_64(
            mach_task_self(),
            &mut returned,
            backing.address()?.as_ptr() as u64,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
            &mut raw,
            MACH_PORT_NULL,
        )
    };
    if result != KERN_SUCCESS {
        if raw != MACH_PORT_NULL {
            let _ = unsafe { mach_port_deallocate(mach_task_self(), raw) };
        }
        return Err(mach_error(
            "mach_make_memory_entry_64 live code arena",
            result,
        ));
    }
    let entry = MachSendRight::from_kernel(raw, "mach_make_memory_entry_64 live code arena")?;
    if returned != requested {
        return Err(io::Error::other(format!(
            "Mach code memory entry size redirected: requested={requested} returned={returned}"
        )));
    }
    drop(backing);
    Ok(entry)
}

pub struct DarwinLiveArena {
    code_entry: MachSendRight,
    control_entry: MachSendRight,
    code_rw: VmMapping,
    code_rx: VmMapping,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the arena owns this mapping for its full lifetime; Task 5 exposes typed control records"
        )
    )]
    control_rw: VmMapping,
    code_len: usize,
    control_len: usize,
    nonce: [u8; 16],
}

impl DarwinLiveArena {
    pub fn new(code_len: usize, control_len: usize) -> io::Result<Self> {
        validate_arena_len("code", code_len)?;
        validate_arena_len("control", control_len)?;

        let code_entry = create_code_memory_entry(code_len)?;
        let control_entry = create_control_memory_entry(control_len)?;
        let code_rw = VmMapping::map_entry(&code_entry, code_len, VM_PROT_READ | VM_PROT_WRITE)?;
        let code_rx = VmMapping::map_entry(&code_entry, code_len, VM_PROT_READ | VM_PROT_EXECUTE)?;
        let control_rw =
            VmMapping::map_entry(&control_entry, control_len, VM_PROT_READ | VM_PROT_WRITE)?;

        if code_rw.address == code_rx.address
            || code_rw.address == control_rw.address
            || code_rx.address == control_rw.address
        {
            return Err(io::Error::other(
                "Mach returned overlapping live arena aliases",
            ));
        }

        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce)
            .map_err(|error| io::Error::other(format!("generate live arena nonce: {error}")))?;
        Ok(Self {
            code_entry,
            control_entry,
            code_rw,
            code_rx,
            control_rw,
            code_len,
            control_len,
            nonce,
        })
    }

    pub fn transit_v1(&self) -> LiveArenaTransitV1 {
        LiveArenaTransitV1 {
            schema: LIVE_ARENA_TRANSIT_SCHEMA_V1,
            code_len: self.code_len as u64,
            control_len: self.control_len as u64,
            nonce: self.nonce,
        }
    }

    pub fn duplicate_transit_rights(&self) -> io::Result<LiveArenaTransitRights> {
        Ok(LiveArenaTransitRights {
            _code: self.code_entry.duplicate()?,
            _control: self.control_entry.duplicate()?,
        })
    }

    pub fn jit_region(&self, range: Range<usize>) -> io::Result<BorrowedLiveJitRegion<'_>> {
        let capacity = checked_range(&range, self.code_len, "JIT subregion")?;
        let write = self
            .code_rw
            .base()
            .checked_add(range.start)
            .and_then(|address| NonNull::new(address as *mut u8))
            .ok_or_else(|| invalid_input("JIT write address overflowed"))?;
        let exec = self
            .code_rx
            .base()
            .checked_add(range.start)
            .and_then(|address| NonNull::new(address as *mut u8))
            .ok_or_else(|| invalid_input("JIT exec address overflowed"))?;
        Ok(BorrowedLiveJitRegion {
            exec_base: exec,
            write_base: write,
            capacity,
            _arena: PhantomData,
        })
    }

    pub fn revoke_rx(&self, range: Range<usize>) -> io::Result<()> {
        self.protect_rx(range, VM_PROT_NONE)
    }

    #[cfg(test)]
    fn restore_rx_for_test(&self, range: Range<usize>) -> io::Result<()> {
        self.protect_rx(range, VM_PROT_READ | VM_PROT_EXECUTE)
    }

    fn protect_rx(&self, range: Range<usize>, protection: vm_prot_t) -> io::Result<()> {
        let len = checked_page_range(&range, self.code_len, "RX protection range")?;
        let address = self
            .code_rx
            .address
            .checked_add(range.start as u64)
            .ok_or_else(|| invalid_input("RX protection address overflowed"))?;
        check_kr("mach_vm_protect live arena RX alias", unsafe {
            mach_vm_protect(mach_task_self(), address, len as u64, 0, protection)
        })
    }
}

/// A checked view of matching RW/RX aliases whose lifetime is tied to its
/// arena. It intentionally cannot produce an owned [`JitRegion`]: reservation
/// authority and unique writer ranges come from the Task 2 allocation protocol,
/// while byte writes through the raw pointer remain unsafe.
///
/// ```compile_fail
/// use carrick_dsr::host::JitRegion;
/// use carrick_native_darwin::live_arena::DarwinLiveArena;
///
/// fn escape_owned_region(arena: &DarwinLiveArena) -> JitRegion {
///     arena
///         .jit_region(0..8)
///         .unwrap()
///         .sub_region(0, 8)
///         .unwrap()
/// }
/// ```
pub struct BorrowedLiveJitRegion<'a> {
    exec_base: NonNull<u8>,
    write_base: NonNull<u8>,
    capacity: usize,
    _arena: PhantomData<&'a DarwinLiveArena>,
}

impl BorrowedLiveJitRegion<'_> {
    pub fn exec_base(&self) -> BorrowedLiveJitPointer<'_> {
        BorrowedLiveJitPointer {
            pointer: self.exec_base,
            _region: PhantomData,
        }
    }

    pub fn write_base(&self) -> BorrowedLiveJitPointer<'_> {
        BorrowedLiveJitPointer {
            pointer: self.write_base,
            _region: PhantomData,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// A pointer token whose lifetime is bounded by a checked live-arena region.
/// It has no safe conversion to a raw pointer or owned [`JitRegion`].
pub struct BorrowedLiveJitPointer<'a> {
    pointer: NonNull<u8>,
    _region: PhantomData<&'a BorrowedLiveJitRegion<'a>>,
}

impl BorrowedLiveJitPointer<'_> {
    /// Exposes the checked alias pointer for low-level code emission or entry.
    ///
    /// # Safety
    ///
    /// The pointer must not be retained beyond this token's lifetime. This
    /// conversion does not establish exclusive write authority: a caller that
    /// writes through it must hold the unique range granted by the Task 2
    /// reservation protocol and obey the alias's current Mach protection.
    pub unsafe fn as_ptr(&self) -> *mut u8 {
        self.pointer.as_ptr()
    }
}

pub struct LiveArenaHostJit;

impl NativeHostJit for LiveArenaHostJit {
    fn supported(&self) -> Result<(), &'static str> {
        Ok(())
    }

    fn map_code_cache(&self, _capacity: usize) -> io::Result<JitRegion> {
        Err(io::Error::other(
            "live arena JIT regions are borrowed from DarwinLiveArena",
        ))
    }

    unsafe fn unmap(&self, _region: &JitRegion) {}

    fn begin_thread_write(&self) {}

    fn end_thread_write(&self) {}

    fn flush_icache(&self, exec_ptr: *const u8, len: usize) {
        crate::jit::clear_icache(exec_ptr, len);
    }

    fn remap_for_fork_child(&self, _prior: &JitRegion) -> io::Result<ForkChildJit> {
        Ok(ForkChildJit::Inherited)
    }
}

fn host_page_size() -> io::Result<usize> {
    let page = unsafe { mach2::vm_page_size::vm_page_size };
    if page == 0 || !page.is_power_of_two() {
        return Err(io::Error::other(format!("invalid Mach page size {page}")));
    }
    Ok(page)
}

fn validate_arena_len(label: &str, len: usize) -> io::Result<()> {
    let page = host_page_size()?;
    if len == 0 || !len.is_multiple_of(page) {
        return Err(invalid_input(format!(
            "{label} arena length {len} is not a nonzero multiple of host page size {page}"
        )));
    }
    u64::try_from(len).map_err(|_| invalid_input(format!("{label} arena length exceeds u64")))?;
    Ok(())
}

fn checked_range(range: &Range<usize>, capacity: usize, label: &str) -> io::Result<usize> {
    if range.start >= range.end || range.end > capacity {
        return Err(invalid_input(format!(
            "{label} {:?} is empty, reversed, or outside capacity {capacity}",
            range
        )));
    }
    range
        .end
        .checked_sub(range.start)
        .ok_or_else(|| invalid_input(format!("{label} length overflowed")))
}

fn checked_page_range(range: &Range<usize>, capacity: usize, label: &str) -> io::Result<usize> {
    let len = checked_range(range, capacity, label)?;
    let page = host_page_size()?;
    if !range.start.is_multiple_of(page) || !len.is_multiple_of(page) {
        return Err(invalid_input(format!(
            "{label} {:?} is not host-page aligned ({page})",
            range
        )));
    }
    Ok(len)
}

fn check_kr(operation: &'static str, result: kern_return_t) -> io::Result<()> {
    if result == KERN_SUCCESS {
        Ok(())
    } else {
        Err(mach_error(operation, result))
    }
}

fn mach_error(operation: &'static str, result: kern_return_t) -> io::Error {
    io::Error::other(format!("{operation}: kern_return={result}"))
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
const PIPE_EINTR_RETRY_LIMIT: usize = 8;

#[cfg(test)]
fn retry_one_byte_pipe_io(mut operation: impl FnMut() -> (libc::ssize_t, libc::c_int)) -> bool {
    let mut interrupted = 0;
    loop {
        let (result, errno) = operation();
        if result == 1 {
            return true;
        }
        if result != -1 || errno != libc::EINTR || interrupted == PIPE_EINTR_RETRY_LIMIT {
            return false;
        }
        interrupted += 1;
    }
}

#[cfg(test)]
fn read_pipe_byte(fd: libc::c_int) -> Option<u8> {
    let mut byte = 0;
    retry_one_byte_pipe_io(|| {
        let result = unsafe { libc::read(fd, (&raw mut byte).cast(), 1) };
        let errno = if result == -1 {
            unsafe { *libc::__error() }
        } else {
            0
        };
        (result, errno)
    })
    .then_some(byte)
}

#[cfg(test)]
fn write_pipe_byte(fd: libc::c_int, byte: u8) -> bool {
    retry_one_byte_pipe_io(|| {
        let result = unsafe { libc::write(fd, (&raw const byte).cast(), 1) };
        let errno = if result == -1 {
            unsafe { *libc::__error() }
        } else {
            0
        };
        (result, errno)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::host::NativeHostJit;
    use std::ops::Range;

    const CODE: Range<usize> = 0..8;

    fn page() -> usize {
        host_page_size().expect("valid Mach host page size")
    }

    fn return_immediate(value: u16) -> [u8; 8] {
        let mov_w0 = 0x5280_0000_u32 | (u32::from(value) << 5);
        let ret = 0xd65f_03c0_u32;
        let mut code = [0_u8; 8];
        code[..4].copy_from_slice(&mov_w0.to_le_bytes());
        code[4..].copy_from_slice(&ret.to_le_bytes());
        code
    }

    unsafe fn exec_ptr(region: &BorrowedLiveJitRegion<'_>) -> *mut u8 {
        unsafe { region.exec_base().as_ptr() }
    }

    unsafe fn write_ptr(region: &BorrowedLiveJitRegion<'_>) -> *mut u8 {
        unsafe { region.write_base().as_ptr() }
    }

    unsafe fn call_u32(region: &BorrowedLiveJitRegion<'_>) -> u32 {
        let entry: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(exec_ptr(region)) };
        unsafe { entry() }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn writer_and_rx_alias_execute_coherent_code() {
        let arena = DarwinLiveArena::new(page() * 2, page()).expect("create live arena");
        let region = arena.jit_region(CODE).expect("code subregion");
        let jit = LiveArenaHostJit;

        unsafe {
            std::ptr::copy_nonoverlapping(return_immediate(42).as_ptr(), write_ptr(&region), 8)
        };
        jit.flush_icache(unsafe { exec_ptr(&region) }, 8);
        assert_eq!(unsafe { call_u32(&region) }, 42);

        unsafe {
            std::ptr::copy_nonoverlapping(return_immediate(43).as_ptr(), write_ptr(&region), 8)
        };
        jit.flush_icache(unsafe { exec_ptr(&region) }, 8);
        assert_eq!(unsafe { call_u32(&region) }, 43);
    }

    #[test]
    fn memory_entry_maps_at_unrelated_addresses() {
        assert!(DarwinLiveArena::new(0, page()).is_err());
        assert!(DarwinLiveArena::new(page() + 1, page()).is_err());
        let arena = DarwinLiveArena::new(page() * 2, page()).expect("create live arena");
        assert_ne!(arena.code_entry.name, arena.control_entry.name);
        assert_ne!(arena.code_rw.base(), arena.code_rx.base());
        assert_ne!(arena.code_rw.base(), arena.control_rw.base());
        assert_ne!(arena.code_rx.base(), arena.control_rw.base());
        assert_eq!(arena.code_rw.len(), page() * 2);
        assert_eq!(arena.code_rx.len(), page() * 2);
        assert_eq!(arena.control_rw.len(), page());
        assert_eq!(
            mapping_protections_for_test(arena.code_rw.base()),
            Some((VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE))
        );
        assert_eq!(
            mapping_protections_for_test(arena.code_rx.base()),
            Some((
                VM_PROT_READ | VM_PROT_EXECUTE,
                VM_PROT_READ | VM_PROT_EXECUTE
            ))
        );
        assert_eq!(
            mapping_protections_for_test(arena.control_rw.base()),
            Some((VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE))
        );
        for address in [
            arena.code_rw.base(),
            arena.code_rx.base(),
            arena.control_rw.base(),
        ] {
            let (current, _) = mapping_protections_for_test(address).expect("mapped alias");
            assert_ne!(
                current & (VM_PROT_WRITE | VM_PROT_EXECUTE),
                VM_PROT_WRITE | VM_PROT_EXECUTE,
                "returned live alias must never be W+X"
            );
        }
        let transit = arena.transit_v1();
        assert_eq!(transit.schema, LIVE_ARENA_TRANSIT_SCHEMA_V1);
        assert_eq!(transit.code_len, (page() * 2) as u64);
        assert_eq!(transit.control_len, page() as u64);
    }

    #[test]
    fn successful_null_mmap_is_owned_before_rejection() {
        let owned = OwnedMmap::from_successful_result(std::ptr::null_mut(), page());
        assert!(MapJitBootstrap::from_owned(owned).is_err());
    }

    #[test]
    fn one_byte_pipe_io_retries_eintr_with_a_bound() {
        let mut attempts = 0;
        assert!(retry_one_byte_pipe_io(|| {
            attempts += 1;
            if attempts < 3 {
                (-1, libc::EINTR)
            } else {
                (1, 0)
            }
        }));
        assert_eq!(attempts, 3);

        attempts = 0;
        assert!(!retry_one_byte_pipe_io(|| {
            attempts += 1;
            (-1, libc::EINTR)
        }));
        assert_eq!(attempts, PIPE_EINTR_RETRY_LIMIT + 1);

        assert!(!retry_one_byte_pipe_io(|| (0, 0)));
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn task_local_rx_revoke_does_not_revoke_parent() {
        let arena = DarwinLiveArena::new(page() * 2, page()).expect("create live arena");
        let region = arena.jit_region(CODE).expect("code subregion");
        unsafe {
            std::ptr::copy_nonoverlapping(return_immediate(42).as_ptr(), write_ptr(&region), 8)
        };
        LiveArenaHostJit.flush_icache(unsafe { exec_ptr(&region) }, 8);

        let mut ready_pipe = [-1; 2];
        let mut restore_pipe = [-1; 2];
        assert_eq!(unsafe { libc::pipe(ready_pipe.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(restore_pipe.as_mut_ptr()) }, 0);
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            unsafe {
                libc::close(ready_pipe[0]);
                libc::close(restore_pipe[1]);
            }
            let mut status = 0;
            if arena.revoke_rx(0..page()).is_err()
                || mapping_protections_for_test(arena.code_rx.base())
                    != Some((VM_PROT_NONE, VM_PROT_READ | VM_PROT_EXECUTE))
            {
                status = 1;
            }

            if status == 0 {
                let fault_child = unsafe { libc::fork() };
                if fault_child < 0 {
                    status = 2;
                } else if fault_child == 0 {
                    unsafe {
                        libc::signal(libc::SIGBUS, libc::SIG_DFL);
                        libc::signal(libc::SIGSEGV, libc::SIG_DFL);
                        let _ = call_u32(&region);
                        libc::_exit(90);
                    }
                } else {
                    let mut fault_status = 0;
                    if unsafe { libc::waitpid(fault_child, &mut fault_status, 0) } != fault_child
                        || !libc::WIFSIGNALED(fault_status)
                        || libc::WTERMSIG(fault_status) != libc::SIGBUS
                    {
                        status = 3;
                    }
                }
            }

            if status == 0 && !write_pipe_byte(ready_pipe[1], 0xa5) {
                status = 4;
            }
            let restore = if status == 0 {
                read_pipe_byte(restore_pipe[0])
            } else {
                None
            };
            if status == 0 && restore.is_none() {
                status = 5;
            }
            if status == 0
                && (restore != Some(0x5a)
                    || arena.restore_rx_for_test(0..page()).is_err()
                    || mapping_protections_for_test(arena.code_rx.base())
                        != Some((
                            VM_PROT_READ | VM_PROT_EXECUTE,
                            VM_PROT_READ | VM_PROT_EXECUTE,
                        )))
            {
                status = 6;
            }
            unsafe {
                libc::close(ready_pipe[1]);
                libc::close(restore_pipe[0]);
            }
            unsafe { libc::_exit(status) };
        }

        unsafe {
            libc::close(ready_pipe[1]);
            libc::close(restore_pipe[0]);
        }
        let ready = read_pipe_byte(ready_pipe[0]);
        let parent_result = if ready == Some(0xa5) {
            Some(unsafe { call_u32(&region) })
        } else {
            None
        };
        let restore_delivered = ready.is_some() && write_pipe_byte(restore_pipe[1], 0x5a);
        unsafe {
            libc::close(ready_pipe[0]);
            // Close before waitpid on success and every delivery failure. If
            // the child is blocked in read, EOF makes it exit nonzero.
            libc::close(restore_pipe[1]);
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(ready, Some(0xa5));
        assert_eq!(parent_result, Some(42));
        assert!(restore_delivered);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn drop_deallocates_aliases_and_send_rights() {
        let arena = DarwinLiveArena::new(page() * 2, page()).expect("create live arena");
        let addresses = [
            arena.code_rw.base(),
            arena.code_rx.base(),
            arena.control_rw.base(),
        ];
        let object_ids = addresses.map(|address| {
            mapping_object_id_for_test(address).expect("live alias has Mach object identity")
        });
        assert_eq!(object_ids[0], object_ids[1]);
        assert_ne!(object_ids[0], object_ids[2]);
        let first = arena
            .duplicate_transit_rights()
            .expect("first fresh send rights");
        let second = arena
            .duplicate_transit_rights()
            .expect("second fresh send rights");
        let port_names = [
            second._code.name_for_test(),
            second._control.name_for_test(),
        ];
        drop(first);
        assert!(port_names.into_iter().all(send_right_exists_for_test));
        drop(second);
        drop(arena);

        for (address, old_object_id) in addresses.into_iter().zip(object_ids) {
            assert_ne!(
                mapping_object_id_for_test(address),
                Some(old_object_id),
                "the dropped alias's original Mach object must no longer occupy its VA"
            );
        }
        for name in port_names {
            assert!(!send_right_exists_for_test(name));
        }
    }

    #[test]
    fn subregion_exposes_matching_rw_and_rx_offsets() {
        let arena = DarwinLiveArena::new(page() * 2, page()).expect("create live arena");
        let range = page() + 32..page() + 96;
        let region = arena.jit_region(range.clone()).expect("code subregion");
        assert_eq!(region.capacity(), range.len());
        assert_eq!(
            unsafe { write_ptr(&region) } as usize - arena.code_rw.base(),
            range.start
        );
        assert_eq!(
            unsafe { exec_ptr(&region) } as usize - arena.code_rx.base(),
            range.start
        );
        assert!(arena.jit_region(page() * 2 - 4..page() * 2 + 4).is_err());
    }

    fn mapping_protections_for_test(address: usize) -> Option<(vm_prot_t, vm_prot_t)> {
        query_region(address as u64)
            .ok()
            .map(|region| (region.current, region.maximum))
    }

    fn mapping_object_id_for_test(address: usize) -> Option<u64> {
        let requested = address as u64;
        let mut depth = 0;
        loop {
            let mut observed = requested;
            let mut len = 0;
            let mut info = mach2::vm_region::vm_region_submap_info_64::default();
            let mut count = mach2::vm_region::vm_region_submap_info_64::count();
            let result = unsafe {
                mach2::vm::mach_vm_region_recurse(
                    mach_task_self(),
                    &mut observed,
                    &mut len,
                    &mut depth,
                    (&raw mut info).cast::<i32>(),
                    &mut count,
                )
            };
            if result != KERN_SUCCESS
                || observed > requested
                || requested >= observed.checked_add(len)?
            {
                return None;
            }
            if info.is_submap != 0 {
                depth = depth.checked_add(1)?;
                continue;
            }
            return Some(info.object_id_full);
        }
    }

    fn send_right_exists_for_test(name: mach_port_t) -> bool {
        const MACH_PORT_TYPE_SEND: u32 = 1 << 16;
        unsafe extern "C" {
            fn mach_port_type(task: mach_port_t, name: mach_port_t, port_type: *mut u32) -> i32;
        }
        let mut port_type = 0;
        (unsafe { mach_port_type(mach_task_self(), name, &mut port_type) == KERN_SUCCESS })
            && port_type & MACH_PORT_TYPE_SEND != 0
    }
}

use super::super::tests::{CountingMmapMemory, returned};
use super::*;
use crate::linux_abi::LINUX_PAGE_SIZE;

#[test]
fn brk_shrink_scrubs_backing_before_regrowth() {
    const SYS_BRK: u64 = 214;
    const PAGES: u64 = 3;

    let mut dispatcher = SyscallDispatcher::new();
    let initial = dispatcher.mem().lock().layout.heap_base;
    let grown = initial + PAGES * LINUX_PAGE_SIZE;
    dispatcher.mem().lock().brk_current = grown;

    let mut memory = CountingMmapMemory::new(initial, (PAGES * LINUX_PAGE_SIZE) as usize);
    memory.bytes.fill(0xa5);
    let reporter = CompatReporter::default();
    let shrink = SyscallRequest::new(SYS_BRK, SyscallArgs([initial, 0, 0, 0, 0, 0]));

    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            shrink,
            &mut memory,
            &reporter,
        )
        .expect("brk shrink dispatch should succeed");

    assert_eq!(returned(outcome), initial as i64);
    assert_eq!(memory.zero_backing_calls.get(), 1);
    assert!(
        memory.bytes.iter().all(|byte| *byte == 0),
        "a later brk growth must not re-expose stale heap bytes"
    );
}

struct HeapVmaTrackingMemory {
    base: u64,
    bytes: Vec<u8>,
    protections: carrick_guest_mem::protections::MemoryProtections,
    event_log: std::cell::RefCell<Vec<String>>,
}

impl HeapVmaTrackingMemory {
    fn new(base: u64, len: usize) -> Self {
        let protections = carrick_guest_mem::protections::MemoryProtections::default();
        protections.set_unmapped(base, len, true);
        Self {
            base,
            bytes: vec![0u8; len],
            protections,
            event_log: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn offset(&self, address: u64, length: usize) -> Result<usize, MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let offset =
            usize::try_from(offset).map_err(|_| MemoryError::OutOfBounds { address, length })?;
        let end = offset
            .checked_add(length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        Ok(offset)
    }
}

impl GuestMemory for HeapVmaTrackingMemory {
    fn protections(&self) -> Option<&carrick_guest_mem::protections::MemoryProtections> {
        Some(&self.protections)
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let off = self.offset(address, length)?;
        Ok(self.bytes[off..off + length].to_vec())
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let off = self.offset(address, bytes.len())?;
        self.bytes[off..off + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.event_log
            .borrow_mut()
            .push(format!("zero_backing({address:#x}, {len:#x})"));
        let off = self.offset(address, len)?;
        self.bytes[off..off + len].fill(0);
        Ok(())
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        self.event_log.borrow_mut().push(format!(
            "protect_range({address:#x}, {len:#x}, prot={prot})"
        ));
        Ok(())
    }

    fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
        self.event_log.borrow_mut().push(format!(
            "set_unmapped({address:#x}, {len:#x}, unmapped={unmapped})"
        ));
        self.protections.set_unmapped(address, len, unmapped);
    }

    fn set_mapping_protection(
        &mut self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
    ) {
        self.event_log.borrow_mut().push(format!(
            "set_mapping_protection({address:#x}, {len:#x}, no_acc={no_access}, no_wr={no_write})"
        ));
        self.protections
            .set_mapping_protection(address, len, no_access, no_write);
    }
}

impl CurrentMmMemory for HeapVmaTrackingMemory {}

#[test]
fn brk_heap_real_vma_page_transitions() {
    const SYS_BRK: u64 = 214;
    let mut dispatcher = SyscallDispatcher::new();
    let heap_base = dispatcher.mem().lock().layout.heap_base;
    let heap_size = dispatcher.mem().lock().layout.heap_size as usize;
    let mut memory = HeapVmaTrackingMemory::new(heap_base, heap_size);
    let reporter = CompatReporter::default();

    let call_brk = |dispatcher: &mut SyscallDispatcher,
                    memory: &mut HeapVmaTrackingMemory,
                    target: u64|
     -> i64 {
        let req = SyscallRequest::new(SYS_BRK, SyscallArgs([target, 0, 0, 0, 0, 0]));
        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                req,
                memory,
                &reporter,
            )
            .expect("brk dispatch");
        returned(outcome)
    };

    // 0. Initial state: brk is at heap_base, memory is unmapped
    assert_eq!(call_brk(&mut dispatcher, &mut memory, 0), heap_base as i64);
    assert!(
        memory.read_bytes(heap_base, 1).is_err(),
        "initial heap must reject syscall reads before growth"
    );

    // 1. Grow 1 page (0x1000)
    memory.event_log.borrow_mut().clear();
    let ret = call_brk(&mut dispatcher, &mut memory, heap_base + LINUX_PAGE_SIZE);
    assert_eq!(ret, (heap_base + LINUX_PAGE_SIZE) as i64);
    // Verified grow ordering: stage-1 protect_range RW then set_mapping_protection (clearing unmapped)
    let log = memory.event_log.borrow().clone();
    let prot_idx = log
        .iter()
        .position(|e| e.starts_with("protect_range") && e.contains("prot=3"));
    let set_map_idx = log.iter().position(|e| {
        e.starts_with("set_mapping_protection") && e.contains("no_acc=false, no_wr=false")
    });
    assert!(
        prot_idx.is_some() && set_map_idx.is_some(),
        "grow must call protect_range(RW) then set_mapping_protection: {log:?}"
    );
    assert!(
        prot_idx.unwrap() < set_map_idx.unwrap(),
        "grow ordering must be stage1-RW -> set_mapping_protection: {log:?}"
    );
    assert!(
        !memory.protections.range_unmapped(heap_base, 0x1000),
        "grown page must no longer be unmapped in MemoryProtections"
    );
    assert!(
        !memory.protections.range_no_access(heap_base, 0x1000),
        "grown page must no longer be no_access in MemoryProtections"
    );
    assert!(
        memory
            .protections
            .range_unmapped(heap_base + LINUX_PAGE_SIZE, 0x1000),
        "ungrown tail must remain unmapped"
    );
    // Grown page is readable and writable
    assert!(memory.write_bytes(heap_base, &[0xa5; 0x1000]).is_ok());
    let read_back = memory
        .read_bytes(heap_base, 0x1000)
        .expect("read back grown page");
    assert_eq!(read_back, vec![0xa5; 0x1000]);
    // Next page is still unmapped
    assert!(memory.read_bytes(heap_base + LINUX_PAGE_SIZE, 1).is_err());

    // 2. Unaligned break move within live page (e.g. heap_base + 0x800)
    memory.event_log.borrow_mut().clear();
    let ret2 = call_brk(&mut dispatcher, &mut memory, heap_base + 0x800);
    assert_eq!(ret2, (heap_base + 0x800) as i64);
    assert!(
        memory.event_log.borrow().is_empty(),
        "same-page move must not edit page tables or protections: {:?}",
        memory.event_log.borrow()
    );
    // Page remains accessible
    assert!(memory.read_bytes(heap_base, 0x1000).is_ok());

    // 3. Shrink to heap base
    memory.event_log.borrow_mut().clear();
    let ret3 = call_brk(&mut dispatcher, &mut memory, heap_base);
    assert_eq!(ret3, heap_base as i64);
    let shrink_log = memory.event_log.borrow().clone();
    // Verify restrictive ordering: protect_range PROT_NONE -> set_unmapped true -> zero_backing
    let prot_idx = shrink_log
        .iter()
        .position(|e| e.starts_with("protect_range") && e.contains("prot=0"));
    let unmap_idx = shrink_log.iter().position(|e| e.contains("unmapped=true"));
    let zero_idx = shrink_log
        .iter()
        .position(|e| e.starts_with("zero_backing"));
    assert!(
        prot_idx.is_some() && unmap_idx.is_some() && zero_idx.is_some(),
        "shrink must perform protect_range(0), set_unmapped(true), and zero_backing: {shrink_log:?}"
    );
    assert!(
        prot_idx.unwrap() < unmap_idx.unwrap() && unmap_idx.unwrap() < zero_idx.unwrap(),
        "shrink ordering must be stage1-invalid -> unmapped -> zero_backing: {shrink_log:?}"
    );
    // Now syscall read to heap_base fails
    assert!(memory.read_bytes(heap_base, 1).is_err());

    // 4. Re-grow 1 page: must be zeroed
    let ret4 = call_brk(&mut dispatcher, &mut memory, heap_base + LINUX_PAGE_SIZE);
    assert_eq!(ret4, (heap_base + LINUX_PAGE_SIZE) as i64);
    let regrown_bytes = memory
        .read_bytes(heap_base, 0x1000)
        .expect("read regrown page");
    assert!(
        regrown_bytes.iter().all(|&b| b == 0),
        "re-grown heap page must be zeroed"
    );
}

/// `brk` past the `RLIMIT_DATA` soft limit reports ENOMEM the way Linux does:
/// by returning the UNCHANGED break.
#[test]
fn brk_growth_past_rlimit_data_returns_the_unchanged_break() {
    const SYS_BRK: u64 = 214;
    let mut dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let initial = dispatcher.mem().lock().layout.heap_base;
    let data_now = super::super::data_va_bytes(&dispatcher.mem().lock());
    context
        .task()
        .replace_rlimit(carrick_abi::LinuxResource::Data, |_| {
            Ok::<_, std::convert::Infallible>(carrick_abi::LinuxRlimit::new(
                data_now + LINUX_PAGE_SIZE,
                LINUX_RLIM_INFINITY,
            ))
        })
        .expect("set RLIMIT_DATA");
    let mut memory = CountingMmapMemory::new(initial, (2 * LINUX_PAGE_SIZE) as usize);
    let reporter = CompatReporter::default();
    let grow = |to: u64| SyscallRequest::new(SYS_BRK, SyscallArgs([to, 0, 0, 0, 0, 0]));

    let one = dispatcher
        .dispatch(
            &context,
            grow(initial + LINUX_PAGE_SIZE),
            &mut memory,
            &reporter,
        )
        .expect("brk dispatch");
    assert_eq!(returned(one), (initial + LINUX_PAGE_SIZE) as i64);

    let two = dispatcher
        .dispatch(
            &context,
            grow(initial + 2 * LINUX_PAGE_SIZE),
            &mut memory,
            &reporter,
        )
        .expect("brk dispatch");
    assert_eq!(
        returned(two),
        (initial + LINUX_PAGE_SIZE) as i64,
        "brk past RLIMIT_DATA must report the unchanged break"
    );
    assert_eq!(
        dispatcher.mem().lock().brk_current,
        initial + LINUX_PAGE_SIZE
    );
}

//! Structural budgets for the per-call metadata work of `brk`, anonymous
//! private `mmap` and `munmap`.
//!
//! The 2026-09-24 EL1 census measured 52 µs of host CPU per `mmap`, 62 µs per
//! `munmap` and 125 µs per `brk` on go/cpython/node, where Linux answers in
//! low single-digit microseconds. A mapping syscall's own work scales with
//! the range it names; it must not scale with how many OTHER mappings the
//! process already holds. These tests hold everything about one call fixed
//! and vary only the unrelated population (live VMAs, first-touch tracked
//! extents, deferred-anonymous extents, free-list holes and file mappings),
//! then require the host-heap traffic of the call to be independent of it.
//!
//! Host-heap BYTES is the instrument because the defect shape it catches is
//! "rebuild the whole collection to cut one range": every such rebuild
//! allocates a fresh vector sized to the population. A splice-based edit
//! allocates at most a constant amount. The allocator counts only on the
//! test's own thread and only inside an explicit window.

use super::tests::{CountingMmapMemory, returned};
use super::*;
use crate::memory::LINUX_MMAP_BASE;

pub(crate) mod allocation_meter {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
    };

    thread_local! {
        static BYTES: Cell<Option<u64>> = const { Cell::new(None) };
        static CALLS: Cell<Option<u64>> = const { Cell::new(None) };
    }

    struct CountingAllocator;

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    fn record(bytes: usize) {
        let _ = BYTES.try_with(|count| {
            if let Some(total) = count.get() {
                count.set(Some(total.saturating_add(bytes as u64)));
            }
        });
        let _ = CALLS.try_with(|count| {
            if let Some(total) = count.get() {
                count.set(Some(total.saturating_add(1)));
            }
        });
    }

    // SAFETY: every call is forwarded unchanged to `System`; the const TLS
    // counter allocates nothing and observes only the current thread.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            record(layout.size());
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            record(layout.size());
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            record(new_size);
            unsafe { System.realloc(ptr, layout, new_size) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct AllocationStats {
        pub bytes: u64,
        pub calls: u64,
    }

    /// Host-heap allocations and bytes requested by this thread while `run` executes.
    pub(crate) fn measure_stats<T>(run: impl FnOnce() -> T) -> (T, AllocationStats) {
        BYTES.with(|count| count.set(Some(0)));
        CALLS.with(|count| count.set(Some(0)));
        let value = run();
        let bytes = BYTES.with(|count| count.replace(None)).unwrap_or(0);
        let calls = CALLS.with(|count| count.replace(None)).unwrap_or(0);
        (value, AllocationStats { bytes, calls })
    }

    /// Host-heap bytes requested by this thread while `run` executes.
    pub(super) fn measure<T>(run: impl FnOnce() -> T) -> (T, u64) {
        let (val, stats) = measure_stats(run);
        (val, stats.bytes)
    }
}

const SYS_BRK: u64 = 214;
const SYS_MUNMAP: u64 = 215;
const SYS_MMAP: u64 = 222;
const PAGE: u64 = LINUX_PAGE_SIZE;

/// Populations the budget compares. The large one is what a cpython or Go
/// process reaches (hundreds of shared-object segments, thousands of
/// allocator extents); the small one is a toy process.
const SMALL: usize = 32;
const LARGE: usize = 2048;

/// A constant-size call may still allocate a handful of fixed-size values
/// (an error string on a cold path, a two-element replacement vector). It
/// may not allocate anything proportional to the population: at `LARGE`
/// one rebuild of a 16-byte-per-row vector alone is 32 KiB.
const SLACK_BYTES: u64 = 2048;

/// The arena-backed test memory, plus a heap whose raw backing is a no-op:
/// the budget is about metadata, not about scrubbing bytes.
struct BudgetMemory(CountingMmapMemory);

impl GuestMemory for BudgetMemory {
    fn supports_lazy_anonymous_mmap(&self) -> bool {
        self.0.supports_lazy_anonymous_mmap()
    }
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.0.read_bytes_raw(address, length)
    }
    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.0.write_bytes_raw(address, bytes)
    }
    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        if self.0.range_offset(address, len).is_err() {
            return Ok(());
        }
        self.0.zero_backing(address, len)
    }
    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.0.unmap_range(address, len)
    }
    fn protect_range(&mut self, _address: u64, _len: usize, _prot: u64) -> Result<(), MemoryError> {
        Ok(())
    }
}

impl CurrentMmMemory for BudgetMemory {}

struct Process {
    dispatcher: SyscallDispatcher,
    context: crate::kernel::KernelContext,
    memory: BudgetMemory,
    reporter: CompatReporter,
}

impl Process {
    fn call(&mut self, number: u64, args: [u64; 6]) -> i64 {
        let outcome = self
            .dispatcher
            .dispatch(
                &self.context,
                SyscallRequest::new(number, SyscallArgs(args)),
                &mut self.memory,
                &self.reporter,
            )
            .expect("dispatch");
        returned(outcome)
    }

    fn mmap_anon(&mut self, prot: u64) -> u64 {
        let flags = LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS;
        self.call(SYS_MMAP, [0, PAGE, prot, flags, u64::MAX, 0]) as u64
    }

    fn munmap(&mut self, address: u64, len: u64) {
        assert_eq!(self.call(SYS_MUNMAP, [address, len, 0, 0, 0, 0]), 0);
    }
}

/// A process holding `population` live one-page anonymous mappings that do
/// not coalesce (alternating protection), `population` free-list holes
/// between them, and `population` file mappings elsewhere in the arena.
fn process_with_population(population: usize) -> Process {
    let dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().expect("task context");
    // Two pages per live mapping (the mapping and the hole after it) plus
    // headroom for the probe calls.
    let arena_pages = population * 2 + 64;
    let memory =
        CountingMmapMemory::new(LINUX_MMAP_BASE, arena_pages * PAGE as usize).with_defer_anon(true);
    let mut process = Process {
        dispatcher,
        context,
        memory: BudgetMemory(memory),
        reporter: CompatReporter::default(),
    };
    let mut holes = Vec::with_capacity(population);
    for index in 0..population {
        let prot = if index % 2 == 0 {
            LINUX_PROT_READ | LINUX_PROT_WRITE
        } else {
            LINUX_PROT_READ
        };
        let live = process.mmap_anon(prot);
        holes.push(process.mmap_anon(LINUX_PROT_READ | LINUX_PROT_WRITE));
        assert_eq!(
            live + PAGE,
            holes[index],
            "bump allocation stays contiguous"
        );
    }
    // Keep a live mapping above the last hole so the holes stay on the free
    // list instead of lowering the bump cursor.
    process.mmap_anon(LINUX_PROT_READ);
    for hole in holes {
        process.munmap(hole, PAGE);
    }
    {
        let mem_authority = process.dispatcher.mem();
        let mut mem = mem_authority.lock();
        assert!(mem.free_regions.len() >= population);
        // Shared-object segments of a dynamically linked process, far from
        // the anonymous churn below.
        let file_base = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        for index in 0..population as u64 {
            let start = file_base + index * 4 * PAGE;
            mem.core_file_mappings.push(crate::core_dump::FileMapping {
                start,
                end: start + 2 * PAGE,
                file_page_offset: index,
                path: format!("/usr/lib/libfixture{index}.so"),
            });
        }
    }
    process
}

/// Host-heap bytes of one probe after a warm-up of the same probe, so
/// amortized vector growth is excluded and only per-call rebuilds remain.
fn steady_state_bytes(process: &mut Process, probe: impl Fn(&mut Process)) -> u64 {
    probe(process);
    let ((), bytes) = allocation_meter::measure(|| probe(process));
    bytes
}

fn assert_population_independent(name: &str, probe: impl Fn(&mut Process) + Copy) {
    let small = steady_state_bytes(&mut process_with_population(SMALL), probe);
    let large = steady_state_bytes(&mut process_with_population(LARGE), probe);
    assert!(
        large <= small + SLACK_BYTES,
        "{name}: host-heap bytes per call grew with unrelated mappings: \
         {small} B with {SMALL} live mappings, {large} B with {LARGE}"
    );
}

/// One anonymous private `mmap` of a page, then its `munmap`. The grant
/// comes from the free list (a hole of the same size), so both the
/// allocator and every metadata set are exercised on the reuse path the
/// churning allocators of Go and cpython take.
#[test]
fn anonymous_mmap_munmap_pair_work_is_independent_of_mapping_population() {
    assert_population_independent("mmap+munmap", |process| {
        let address = process.mmap_anon(LINUX_PROT_READ | LINUX_PROT_WRITE);
        process.munmap(address, PAGE);
    });
}

/// `munmap` alone, of a live mapping in the middle of the population.
#[test]
fn anonymous_munmap_work_is_independent_of_mapping_population() {
    let probe_bytes = |population: usize| {
        let mut process = process_with_population(population);
        // Warm-up pair so vector capacities reach steady state.
        let warm = process.mmap_anon(LINUX_PROT_READ | LINUX_PROT_WRITE);
        process.munmap(warm, PAGE);
        let address = process.mmap_anon(LINUX_PROT_READ | LINUX_PROT_WRITE);
        let ((), bytes) = allocation_meter::measure(|| process.munmap(address, PAGE));
        bytes
    };
    let small = probe_bytes(SMALL);
    let large = probe_bytes(LARGE);
    assert!(
        large <= small + SLACK_BYTES,
        "munmap: host-heap bytes per call grew with unrelated mappings: \
         {small} B with {SMALL} live mappings, {large} B with {LARGE}"
    );
}

/// A `brk` grow and the matching shrink.
#[test]
fn brk_grow_shrink_work_is_independent_of_mapping_population() {
    assert_population_independent("brk", |process| {
        let current = process.call(SYS_BRK, [0; 6]) as u64;
        let grown = current + 4 * PAGE;
        assert_eq!(process.call(SYS_BRK, [grown, 0, 0, 0, 0, 0]) as u64, grown);
        assert_eq!(
            process.call(SYS_BRK, [current, 0, 0, 0, 0, 0]) as u64,
            current
        );
    });
}

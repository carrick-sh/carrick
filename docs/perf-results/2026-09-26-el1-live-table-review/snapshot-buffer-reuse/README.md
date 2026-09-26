# Actual snapshot-buffer allocation budget

Base: `33eafc56e`. Contract: `kernel.fork.stage1-image`.

The manager-pool miss counter does not count allocations inside a reused
manager. `make_live` dropped the owned arena vector; the next snapshot into
that recycled live manager allocated the arena buffer again. A test-only
System allocator wrapper, scoped to the calling thread and allocations at
least the root-arena size, observes 1/8/32/128 large allocations at the four
scale points even after warming the image. This is allocator observation,
not a new copy of the manager-pool counter.

Each arena now keeps at most one empty snapshot buffer when it becomes live.
The buffer length is zero and descriptor reads never consult it; live backing
remains the sole descriptor authority. An owned snapshot takes this capacity
back and overwrites its contents from the current source. Repeated conversion
therefore preserves capacity without preserving a readable software shadow.
This retains bounded memory per live/recycled image; it does not claim a memory
footprint reduction or an end-to-end runtime speedup.

The same allocator witness now observes 0/0/0/0 large allocations. All 83 MMU,
171 memory, and 74 AArch64 library tests pass. Targeted all-target Clippy and
the contract registry pass. Commands use `RUSTC_WRAPPER=`; exact outputs are
included here. The live descriptor visibility tests remain green.

Full CI running on integration checkpoint `899873310` does not cover this
follow-up until it is integrated and checked. Signed structural and workload
acceptance remain open; the nominal pool-miss counter alone is insufficient.

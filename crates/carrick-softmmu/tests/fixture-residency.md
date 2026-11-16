# SoftMMU fixture residency evidence (#2427)

Measured on the disposable Debian x86_64 worker, 2026-11-16. The unchanged
production baseline is the task's GitHub main. Only test storage changes.

The original 13 contract tests pass at **4,262,880 KiB** peak RSS. The same
binary with lazy backing, including the new regression guard, passes at
**42,752 KiB**. A warm `cargo test -p carrick-softmmu --test softmmu_contract`
peaks at **70,164 KiB** (the first compiling green invocation: 300,208 KiB).
All are below the requested 512 MiB after the fix.

The isolated Linux guard allocates the suite's largest span (2 GiB), probes
zero initialization and shared atomic writes at its start, midpoint and last
word, and retains both owners while measuring. Old fixture growth:
**2,097,784 KiB**, failing the **65,536 KiB** bound. New fixture growth:
**576 KiB**, passing. The child isolates the measurement from other tests'
allocations and frees, without serializing the suite.

## Individual contract tests

Peak RSS in KiB, each run by its exact name. These are direct test-binary
measurements, excluding Cargo/compiler RSS; all exit 0. The old binary is
saved before replacing the allocator. Separate Cargo-by-name logs were also
captured. Names below are abbreviated only for readability.

| Test | Eager backing | Lazy backing |
| --- | ---: | ---: |
| `linear_placement_enforces_alignment_bounds_and_mmio_holes` | 36,756 | 6,136 |
| `huge_page_authentication_2m_and_1g_at_zero_page_and_tail_offsets` | 2,117,784 | 6,140 |
| `invlpg_on_large_page_evicts_all_sibling_slots` | 20,560 | 4,204 |
| `red_first_non_present_precedence_ignored_nonleaf_bits_and_reserved_bits` | 20,480 | 3,996 |
| `cr_gating_smep_smap_wp_and_id_error_code_bit` | 20,692 | 4,156 |
| `fault_classes_non_canonical_gp_ss_mmio_non_fault_and_descriptor_load` | 20,540 | 4,244 |
| `hardware_accessed_and_dirty_bits_updated_via_cas` | 20,856 | 4,264 |
| `frame_keyed_code_page_alias_invalidation_and_retired_table_frame_refusal` | 20,796 | 6,632 |
| `parked_soft_vcpu_probe_and_walk_serve_retirement_and_refuse_foreign_or_terminal` | 37,256 | 4,664 |
| `permission_classes_not_present_write_cow_nx_and_upper_half_va` | 20,512 | 4,144 |
| `page_crossing_access_misses_tlb_and_validates_both_pages` | 20,452 | 4,444 |
| `concurrent_pte_writer_snapshot_consistency_and_structural_budgets` | 2,118,444 | 11,292 |
| `two_thread_invlpg_eviction_and_cr3_root_switch_flush_match_hardware` | 20,168 | 6,416 |

The huge-page test and concurrent PTE budget test each reserve 2 GiB.
Ordinary rigs reserve 16 MiB. Previously every word was written; the two
large allocations overlapped at default test concurrency. Spans, padding,
holes, extent authentication and all existing assertions are unchanged.

## Ownership and platform coverage

`alloc_zeroed` supplies aligned, initialized storage from the global allocator.
Zero is a valid `AtomicU64` representation. A boxed atomic slice owns the
allocation and deallocates with its array layout; `Arc` clones share that
single owner. Existing 4 KiB alignment padding remains in place.

The RSS regression is explicitly Linux-gated, not a runtime skip. The allocator
and all existing semantic contract tests compile and run on macOS as well;
macOS uses the same zeroed allocation path. No macOS RSS measurement was
performed on this Linux VM. The OS allocator controls lazy physical backing;
the Linux guard checks the resource property on the affected population lane.

## Reproduction and logs

Debian's `time` package was extracted under `/tmp/2427-time` because this VM
lacked `/usr/bin/time`. It was not built from external source.

- `/tmp/2427-time/usr/bin/time -v cargo test -p carrick-softmmu --test softmmu_contract`
- Per-test: `/tmp/2427-time/usr/bin/time -v <saved-test-binary> <name> --exact`
- Guard: `cargo test -p carrick-softmmu --test softmmu_contract largest_fixture_keeps_untouched_pages_nonresident -- --exact --nocapture`
- Ten concurrent `cargo test -p carrick-softmmu --no-fail-fast` runs, default threads.
- Then four concurrent `cargo test -p carrick-softcpu-x86 --no-fail-fast` runs, default threads.

Raw logs and exit records are under `/tmp/2427-evidence` on the task VM;
summary evidence is preserved here and in the PR because the VM is disposable.

## Population results

`carrick-softmmu`: 10/10 exit 0; failure sets empty; no retries.

Run IDs: `2427-carrick-softmmu-1` through `2427-carrick-softmmu-10`.

`carrick-softcpu-x86`: 4/4 exit 0; failure sets empty; no retries.

Run IDs: `2427-carrick-softcpu-x86-1` through `2427-carrick-softcpu-x86-4`.


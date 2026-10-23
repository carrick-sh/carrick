# EL1 image census and reclaim — 2026-10-23

Issue: #801. Initial baseline: GitHub main `9a9b4cd1f` (confirmed against GitHub
before measurement), Rust 1.96.0, Linux x86_64 worker ctb-w2. No Docker or
signed HVF execution is available on this worker.

Main advanced during verification. The initial-base measurements below are
retained as experimental evidence; the **Rebased main** section records the
fresh comparison on `0aa665ef5`, onto which the branch was rebased before its
final gates. The one implementation change was kept unchanged; none was
ported, dropped or replaced.

## Measurement boundary

The authoritative size is `_image_end - _image_start`, the same expression
stored in the CEL1 header and checked by `carrick-el1-image/build.rs` and
`carrick-el1-linux/link.ld`. It includes header, text, read-only data, data,
BSS and intervening/trailing alignment. The limit stays **1,048,576 bytes**.
DWARF, ELF symbol tables and ELF container overhead are not loaded. Stripping
DWARF would save **zero loaded bytes**. Host release settings are out of scope.

Reproduction (run from repository root, without compiler caching):

```sh
env -u RUSTC_WRAPPER CARRICK_SCCACHE=0 cargo build -p carrick-el1-image
env -u RUSTC_WRAPPER CARRICK_SCCACHE=0 cargo build -p carrick-el1-image --features allocator-test-control
# Select the matching build's OUT_DIR, as printed by cargo build -vv:
size -A target/debug/build/carrick-el1-image-*/out/el1-target/aarch64-unknown-none-softfloat/release/carrick-el1
nm -S --size-sort -C target/debug/build/carrick-el1-image-*/out/el1-target/aarch64-unknown-none-softfloat/release/carrick-el1
```

Crate totals below group demangled symbols by their leading crate prefix;
trait implementations use the implementing type's prefix. Primitive/generic
implementors remain separate. Text includes only `t/T`, data only `r/R/d/D/b/B`.
Identical `(address, size)` aliases count once. Anonymous constants, unnamed
strings, padding and inline code cannot be accurately assigned to their
source crate this way: these are symbol-prefix totals, not DWARF attribution.
The section census, rather than the symbol census, accounts for every loaded
byte. Repeated demangled names identify candidate monomorphizations, not proof
that the bodies are identical or removable.

## Initial main baseline

| Loaded component | Bytes |
|---|---:|
| `.header` | 32 |
| `.text` | 935,500 |
| `.rodata` | 76,632 |
| `.data` | 40 |
| `.bss` | 7,192 |
| Alignment between/after sections | 2,476 |
| **Loaded extent** | **1,021,872** |
| **Headroom** | **26,704** |

The default image build passes all twelve registered stack-path budgets;
maximum: **native wait copy, 11,919 / 12,288 bytes**, including the vector.
The size/stack constraints are the existing `kernel.fork.stage1-image`
structural boundary described in `docs/conformance-contracts.md`, together
with `docs/el1-stack-budget.md`. Size reclamation must preserve overflow
checks, panic publication, routing, concurrency and stack ceilings.

### Symbol attribution and largest functions

| Symbol crate prefix | Text bytes | Named data/BSS bytes |
|---|---:|---:|
| `carrick_el1_linux` | 235432 | 688 |
| `alloc` | 185628 | 0 |
| `carrick_core` | 150104 | 8 |
| `carrick_sched_core` | 98852 | 0 |
| `carrick_mmu_core` | 82388 | 0 |
| `carrick_personality_linux` | 58616 | 4096 |
| `carrick_el1` | 36060 | 6416 |
| `core` | 34520 | 0 |
| `carrick_el1_abi` | 20380 | 76 |
| `anonymous data` | 0 | 15638 |
| `carrick_core_abi` | 11928 | 0 |
| `carrick_pipe_core` | 3872 | 0 |
| `carrick_fd_core` | 3820 | 0 |
| `carrick_inotify_core` | 2648 | 0 |
| `carrick_signal_core` | 2556 | 33 |
| `&T as core` | 2576 | 0 |
| `unqualified/assembly` | 1412 | 8 |
| `compiler_builtins` | 1332 | 0 |
| `u64 as core` | 876 | 0 |
| `carrick_syscall_abi` | 736 | 0 |
| `u32 as core` | 568 | 0 |
| `__rustc` | 440 | 0 |
| `usize as core` | 224 | 0 |
| `[core` | 200 | 0 |
| `T as alloc` | 144 | 0 |
| `u8 as alloc` | 128 | 0 |
| `str as core` | 20 | 0 |
| `&str as core` | 16 | 0 |
| `&dyn core` | 12 | 0 |
| `&u64 as core` | 12 | 0 |

| Rank | Function (separate monomorphizations retained) | Bytes |
|---:|---|---:|
| 1 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::begin_closing` | 7256 |
| 2 | `carrick_core::mm::transaction::user_write::<impl carrick_core::mm::transaction::owner::MmPortal<P,Policy,Geometry,Venue,B,Context>>::write_user_bytes` | 6144 |
| 3 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::exit_with_status` | 5704 |
| 4 | `carrick_el1_linux::ipc::serve_ipc` | 5700 |
| 5 | `<carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S> as carrick_personality_linux::signal::ProcessSignals>::kill` | 5064 |
| 6 | `carrick_core::mm::reservation::root::Reservations<Policy,Geometry,C>::copy_in_order` | 4988 |
| 7 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::fork_publish` | 4956 |
| 8 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::resume_pending_lifecycle` | 4352 |
| 9 | `carrick_el1_linux::ipc::epoll::serve_with` | 4216 |
| 10 | `carrick_sched_core::process::exit::<impl carrick_sched_core::process::registry::ProcessRegistry<C,L,Z,R,Reservation,Retired,Group,Session,Failure>>::prepare_exit_topology` | 4204 |
| 11 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::drain_external_ingress` | 4160 |
| 12 | `carrick_core::mm::transaction::owner::serve_transfer` | 4112 |
| 13 | `<carrick_el1_linux::aarch64_process::Aarch64NativeProcessService<X> as carrick_el1_linux::native_process_runtime::NativeProcessService<carrick_sched_core::aarch64_context::Aarch64ParkedContext>>::prepare_mm` | 4104 |
| 14 | `carrick_el1_linux::cow_resolver::dispatch_fault` | 4056 |
| 15 | `carrick_personality_linux::identity::invoke` | 3664 |
| 16 | `carrick_sched_core::ZoneTables<C>::claim_for_host` | 3480 |
| 17 | `carrick_el1_linux::native_process_runtime::NativeProcessRuntime<M,C>::admit_fresh_root` | 3300 |
| 18 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::send_thread_signal` | 3252 |
| 19 | `carrick_sched_core::spaces::notification::<impl carrick_sched_core::ZoneTables<C>>::admit_space_notifications` | 3224 |
| 20 | `carrick_sched_core::ZoneTables<C>::wake_placed` | 3224 |
| 21 | `carrick_sched_core::spaces::notification::SpaceNotificationLease<C>::release_resource` | 3160 |
| 22 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::register_thread` | 3120 |
| 23 | `carrick_sched_core::ZoneTables<C>::place_in_guest` | 2980 |
| 24 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::fork_reserve` | 2948 |
| 25 | `carrick_personality_linux::signal::invoke` | 2820 |
| 26 | `carrick_core::mm::fork::PreparedOwnerFork<B>::publish` | 2796 |
| 27 | `carrick_personality_linux::dispatch::dispatch` | 2760 |
| 28 | `carrick_personality_linux::ipc::invoke` | 2724 |
| 29 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2712 |
| 30 | `carrick_el1::memory::serve_delegated_anonymous` | 2696 |
| 31 | `carrick_el1_linux::ipc::release_pin` | 2664 |
| 32 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2592 |
| 33 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2592 |
| 34 | `carrick_sched_core::ZoneTables<C>::place_in_guest` | 2584 |
| 35 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2512 |
| 36 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2512 |
| 37 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2512 |
| 38 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2512 |
| 39 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2492 |
| 40 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::rehome_entry` | 2456 |

| Repeated demangled function family | Instances | Total text bytes |
|---|---:|---:|
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Leaf>,alloc::collections::btree::node::marker::Edge>::insert_recursing` | 27 | 47960 |
| `alloc::collections::btree::remove::<impl alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Leaf>,alloc::collections::btree::node::marker::KV>>::remove_leaf_kv` | 24 | 25784 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 8 | 20436 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::descend` | 8 | 17684 |
| `alloc::collections::btree::node::BalancingContext<K,V>::bulk_steal_right` | 22 | 13484 |
| `alloc::collections::btree::node::BalancingContext<K,V>::bulk_steal_left` | 22 | 11932 |
| `alloc::collections::btree::node::BalancingContext<K,V>::do_merge` | 22 | 11404 |
| `<alloc::collections::btree::map::BTreeMap<K,V,A> as core::ops::drop::Drop>::drop` | 21 | 10436 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_live_table` | 8 | 9776 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::KV>::split` | 21 | 8784 |
| `alloc::collections::btree::remove::<impl alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::LeafOrInternal>,alloc::collections::btree::node::marker::KV>>::remove_kv_tracking` | 24 | 8364 |
| `alloc::collections::btree::map::BTreeMap<K,V,A>::remove` | 19 | 7072 |
| `carrick_sched_core::ZoneTables<C>::place_in_guest` | 2 | 5564 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::store` | 8 | 5428 |
| `carrick_core::mm::fork::PreparedOwnerFork<B>::publish` | 2 | 5168 |

## Reclaim investigation

The baseline inherits release optimization level 3, 16 codegen units and
Cargo's local thin LTO, with no cross-crate LTO. Full DWARF and overflow checks
are enabled; the bare-metal target already uses aborting panics. The panic
handler publishes sentinel, line, column and MM diagnostic detail, but does
not consume formatted panic messages. Cross-crate dead-code elimination may
therefore remove formatting reachability without changing panic publication.

The largest named immutable table is the 4,096-byte thread-lifecycle template;
the largest anonymous constant is 8,208 bytes. Neither is established dead.
Most BSS is the 6,416-byte global allocator. Removing any of these without an
ownership/initialization proof would change semantics. Unused ELF sections
are already subject to linker garbage collection.

The first candidates enable cross-crate LTO only in the nested EL1 image build,
retaining optimization level 3, frame pointers, overflow checks and DWARF.
Configurations that violate an existing stack-path or individual-frame budget
are rejected. The selected candidate then runs both image variants and the
requested host gates.

## Measured configuration alternatives

Each candidate used the real nested build and the unchanged frame/FP-SIMD
checks, not an independently linked approximation. Rejected candidates were
removed before the final verification. LTO and codegen-unit overrides were
experimental only; the committed change sets only the nested release
`opt-level` to `s`.

| Configuration | Loaded bytes | Reclaimed vs main | Result |
|---|---:|---:|---|
| Main: opt 3, default CGUs/local LTO | 1,021,872 | 0 | Pass |
| Cross-crate ThinLTO | 1,047,072 | -25,200 | Pass, larger: rejected |
| Cross-crate fat LTO | 973,120 | 48,752 | Rejected: missing retained `dispatch_syscall` frame |
| ThinLTO, one codegen unit | 977,024 | 44,848 | Rejected: missing retained `dispatch_entry` frame |
| **Opt s, default CGUs/local LTO** | **860,400** | **161,472** | **Pass** |

The passing choice exceeds the 65,536-byte reclaim target by **95,936 bytes**.
No source dispatch or scheduler path moved; no Forward fallback, dynamic
adapter, table deletion, panic-message edit or budget change was needed.
There is one independent reclaim commit, since one isolated profile setting
already exceeds the goal. Opt `z` was not necessary to meet the target; this
is not a claim that `s` is the globally smallest possible configuration.

The setting is applied via `CARGO_PROFILE_RELEASE_OPT_LEVEL=s` on the nested
Cargo command only, covering the image's freestanding dependency closure.
Host release optimization, full DWARF, overflow checks, frame pointers, panic
strategy, LTO and codegen-unit defaults are unchanged. Smaller code may change
runtime performance; this worker cannot establish the signed ARM runtime or
throughput result. The director must run the signed gate on the final artifact.

### Initial-base optimized default-image sections

| Loaded component | Before | After | Reclaimed |
|---|---:|---:|---:|
| `.header` | 32 | 32 | 0 |
| `.text` | 935,500 | 771,260 | 164,240 |
| `.rodata` | 76,632 | 79,048 | -2,416 |
| `.data` | 40 | 40 | 0 |
| `.bss` | 7,192 | 7,152 | 40 |
| Alignment | 2,476 | 2,868 | -392 |
| **Loaded extent** | **1,021,872** | **860,400** | **161,472** |
| **Headroom** | **26,704** | **188,176** | |

The reduction is principally compiler code sharing/inlining choices, not
stripped diagnostics. Text symbols containing `core::fmt` total 10,604 bytes
before and 10,372 after; `::panicking::` totals 672 and 700 bytes, respectively.
`unwrap_failed` remains 28 bytes. These overlapping name-based categories
are diagnostic clues, not additive accounting buckets. The panic handler
still publishes sentinel, line, column and MM detail. Named formatting functions
account for substantially less than 64 KiB; this census does not quantify their
inlined code or associated unnamed data. ARM `::descriptor_txn::`
text falls from 78,320 to 52,100 bytes without altering its generic API.

The final image's symbol attribution shifts when the compiler outlines code
previously inlined into callers: for example `alloc` increases while the
calling Carrick crates shrink. Therefore differences between per-crate totals
must not be interpreted as independent source deletions.

### Initial-base optimized symbol attribution and largest functions

| Symbol crate prefix | Text bytes | Named data/BSS bytes |
|---|---:|---:|
| `alloc` | 213456 | 0 |
| `carrick_el1_linux` | 178464 | 688 |
| `carrick_core` | 94252 | 8 |
| `carrick_sched_core` | 63016 | 0 |
| `carrick_personality_linux` | 52152 | 4096 |
| `carrick_mmu_core` | 49848 | 0 |
| `carrick_el1` | 32508 | 6416 |
| `core` | 29692 | 0 |
| `carrick_el1_abi` | 23188 | 40 |
| `carrick_core_abi` | 12264 | 0 |
| `anonymous data` | 0 | 9500 |
| `carrick_fd_core` | 4252 | 0 |
| `carrick_pipe_core` | 3524 | 0 |
| `carrick_inotify_core` | 2820 | 0 |
| `carrick_signal_core` | 2332 | 33 |
| `&T as core` | 2276 | 0 |
| `compiler_builtins` | 1332 | 0 |
| `unqualified/assembly` | 1320 | 8 |
| `u64 as core` | 876 | 0 |
| `carrick_syscall_abi` | 828 | 0 |
| `zerocopy` | 776 | 0 |
| `u32 as core` | 568 | 0 |
| `__rustc` | 348 | 0 |
| `usize as core` | 308 | 0 |
| `T as alloc` | 280 | 0 |
| `carrick_guest_arch` | 196 | 0 |
| `T as core` | 184 | 0 |
| `(U,T) as core` | 116 | 0 |
| `W as carrick_sched_core` | 24 | 0 |
| `str as core` | 20 | 0 |
| `&str as core` | 16 | 0 |
| `&dyn core` | 12 | 0 |
| `&u64 as core` | 12 | 0 |

| Rank | Function (separate monomorphizations retained) | Bytes |
|---:|---|---:|
| 1 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::begin_closing` | 4368 |
| 2 | `<carrick_el1_linux::aarch64_process::Aarch64NativeProcessService<X> as carrick_el1_linux::native_process_runtime::NativeProcessService<carrick_sched_core::aarch64_context::Aarch64ParkedContext>>::prepare_mm` | 4188 |
| 3 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::exit_with_status` | 4124 |
| 4 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::fork_publish` | 4076 |
| 5 | `carrick_el1_linux::native_process_runtime::NativeProcessRuntime<M,C>::admit_fresh_root` | 3656 |
| 6 | `carrick_personality_linux::identity::invoke` | 3236 |
| 7 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::register_thread` | 2996 |
| 8 | `carrick_personality_linux::signal::invoke` | 2932 |
| 9 | `<carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S> as carrick_personality_linux::signal::ProcessSignals>::kill` | 2908 |
| 10 | `carrick_sched_core::process::exit::<impl carrick_sched_core::process::registry::ProcessRegistry<C,L,Z,R,Reservation,Retired,Group,Session,Failure>>::prepare_exit_topology` | 2904 |
| 11 | `carrick_personality_linux::ipc::invoke` | 2468 |
| 12 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::rehome_entry` | 2416 |
| 13 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::fork_reserve` | 2412 |
| 14 | `carrick_core::mm::transaction::owner::MmPortal<P,Policy,Geometry,Venue,B,Context>::select` | 2268 |
| 15 | `carrick_core::mm::transaction::owner::MmPortal<P,Policy,Geometry,Venue,B,Context>::select` | 2236 |
| 16 | `carrick_el1_linux::ipc::epoll::serve_with` | 2108 |
| 17 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::send_thread_signal` | 2016 |
| 18 | `carrick_el1::fault::dispatch_classified_fault` | 1992 |
| 19 | `carrick_el1_linux::arm_signal::setup_arm_signal_frame` | 1920 |
| 20 | `carrick_el1::memory::serve_delegated_anonymous` | 1884 |
| 21 | `carrick_el1_linux::mm_portal::fork::serve_fork_hw` | 1828 |
| 22 | `carrick_core::mm::capacity::MetadataAllocatorCore::allocate_with_metrics` | 1812 |
| 23 | `carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxnSlot::claim_for_mm` | 1804 |
| 24 | `carrick_core::mm::fork::copy_entry` | 1764 |
| 25 | `carrick_el1_linux::ipc::run` | 1752 |
| 26 | `carrick_core::mm::fork::copy_entry` | 1728 |
| 27 | `<carrick_core::mm::transaction::owner::MmPortal<P,Policy,Geometry,Venue,B,Context> as carrick_el1_linux::mm_portal::fork::NativeForkPortal<P,B>>::prepare_fork` | 1680 |
| 28 | `<carrick_core::mm::transaction::owner::MmPortal<P,Policy,Geometry,Venue,B,Context> as carrick_el1_linux::mm_portal::fork::NativeForkPortal<P,B>>::prepare_fork` | 1680 |
| 29 | `carrick_personality_linux::lifecycle::serve_exit` | 1608 |
| 30 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::resume_ipc` | 1592 |
| 31 | `carrick_el1_linux::ipc::admit` | 1588 |
| 32 | `carrick_personality_linux::dispatch::dispatch` | 1552 |
| 33 | `carrick_core::mm::fork::PreparedOwnerFork<B>::publish` | 1544 |
| 34 | `carrick_personality_linux::sysinfo::LinuxSysinfo::to_bytes` | 1540 |
| 35 | `carrick_el1_linux::process_owner::GuestPendingExit<C,U,N,F>::publish` | 1540 |
| 36 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::admit_external_event` | 1492 |
| 37 | `carrick_el1_abi::ipc::epoll::<impl carrick_el1_abi::ipc::IpcRegion>::epoll_harvest` | 1484 |
| 38 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::register_root` | 1480 |
| 39 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::wait_query` | 1452 |
| 40 | `carrick_core::mm::cow::resolve_guest_cow` | 1448 |

| Repeated demangled function family | Instances | Total text bytes |
|---|---:|---:|
| `alloc::collections::btree::node::BalancingContext<K,V>::do_merge` | 42 | 21592 |
| `alloc::collections::btree::node::BalancingContext<K,V>::bulk_steal_right` | 21 | 11828 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Leaf>,alloc::collections::btree::node::marker::Edge>::insert` | 28 | 11400 |
| `alloc::collections::btree::remove::<impl alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Leaf>,alloc::collections::btree::node::marker::KV>>::remove_leaf_kv` | 23 | 11292 |
| `alloc::collections::btree::node::BalancingContext<K,V>::bulk_steal_left` | 21 | 11104 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Leaf>,alloc::collections::btree::node::marker::Edge>::insert_recursing` | 28 | 10184 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::Edge>::insert` | 28 | 8524 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::descend` | 6 | 7576 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::KV>::split` | 28 | 7380 |
| `alloc::collections::btree::remove::<impl alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::KV>>::remove_internal_kv` | 23 | 7184 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::Edge>::insert_fit` | 24 | 6480 |
| `alloc::collections::btree::map::entry::VacantEntry<K,V,A>::insert_entry` | 28 | 5956 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 6 | 5896 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,NodeType>,alloc::collections::btree::node::marker::KV>::split_leaf_data` | 24 | 5228 |
| `alloc::collections::btree::fix::<impl alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::LeafOrInternal>>::fix_node_through_parent` | 21 | 5040 |

## Initial-base image variants and stack envelopes

Both final builds exit zero, including the unchanged individual-frame,
retained-frame, FP/SIMD and loaded-image checks.

| Image variant | Main loaded bytes | Final loaded bytes | Reclaimed | Final headroom |
|---|---:|---:|---:|---:|
| Default | 1,021,872 | 860,400 | 161,472 | 188,176 |
| `allocator-test-control` | 1,025,968 | 860,416 | 165,552 | 188,160 |

The following final frame totals are identical for both variants. The maximum
is **10,064 / 12,288 bytes**, leaving 2,224 bytes below the budget and 6,320
below the physical stack size. These are the gate's conservative registered
chain envelopes, not a new whole-program stack proof.

| Registered stack path | Main bytes | Final bytes |
|---|---:|---:|
| Native admission | 7,967 | 7,600 |
| Native fork publication | 9,326 | 8,943 |
| Native fork descriptors | 9,950 | 9,263 |
| Native fork context | 2,847 | 4,048 |
| Native wait copy | 11,919 | 10,064 |
| Signal delivery copy | 10,383 | 8,416 |
| Signal terminal exit | 10,511 | 8,976 |
| Signal return | 5,759 | 5,888 |
| Anonymous munmap | 6,928 | 6,688 |
| Metadata grant | 7,472 | 6,912 |
| Backing retirement | 9,296 | 9,040 |
| Descriptor drain | 7,120 | 5,968 |

The native fork-context and signal-return envelopes grow, but remain within
the original limits. No frame-budget parser, required-symbol rule or ceiling
was modified to admit the configuration.

## Rebased main — authoritative final comparison

GitHub main advanced to `0aa665ef5` during the first host-gate run, adding
EL1 affinity/service-custody changes. The branch was rebased cleanly, the
single optimization override was temporarily removed to rebuild the new
baseline, then restored before rebuilding the candidate. Neither budget nor
compiler checks were changed. The earlier interrupted host-gate run is not
counted as final evidence (its fd-core, ABI and kernel binaries passed before
the kernel-semantics build was stopped for the rebase).

The final default image reclaims **161,552 bytes (157.8 KiB)**, exceeding the
64 KiB target by 96,016 bytes. It leaves **183,968 bytes of headroom**.

| Loaded component | Main opt 3 | Candidate opt s | Reclaimed |
|---|---:|---:|---:|
| `.header` | 32 | 32 | 0 |
| `.text` | 941,176 | 776,832 | 164,344 |
| `.rodata` | 76,824 | 79,168 | -2,344 |
| `.data` | 40 | 40 | 0 |
| `.bss` | 7,192 | 7,152 | 40 |
| Alignment | 896 | 1,384 | -488 |
| **Loaded extent** | **1,026,160** | **864,608** | **161,552** |
| **Headroom** | **22,416** | **183,968** | |

### Rebased main: symbol prefixes and top 40 functions

| Symbol crate prefix | Text bytes | Named data/BSS bytes |
|---|---:|---:|
| `carrick_el1_linux` | 231012 | 688 |
| `alloc` | 185388 | 0 |
| `carrick_core` | 147876 | 8 |
| `carrick_sched_core` | 102360 | 0 |
| `carrick_mmu_core` | 82388 | 0 |
| `carrick_personality_linux` | 59332 | 4096 |
| `carrick_el1` | 44948 | 6416 |
| `core` | 34136 | 0 |
| `carrick_el1_abi` | 20416 | 76 |
| `anonymous data` | 0 | 15662 |
| `carrick_core_abi` | 11928 | 0 |
| `carrick_pipe_core` | 3872 | 0 |
| `carrick_fd_core` | 3820 | 0 |
| `carrick_inotify_core` | 2648 | 0 |
| `carrick_signal_core` | 2556 | 33 |
| `&T as core` | 2576 | 0 |
| `unqualified/assembly` | 1412 | 8 |
| `compiler_builtins` | 1332 | 0 |
| `u64 as core` | 876 | 0 |
| `carrick_syscall_abi` | 736 | 0 |
| `u32 as core` | 568 | 0 |
| `__rustc` | 440 | 0 |
| `usize as core` | 224 | 0 |
| `T as alloc` | 144 | 0 |
| `u8 as alloc` | 128 | 0 |
| `str as core` | 20 | 0 |
| `&str as core` | 16 | 0 |
| `&dyn core` | 12 | 0 |
| `&u64 as core` | 12 | 0 |

| Rank | Function (separate monomorphizations retained) | Bytes |
|---:|---|---:|
| 1 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::begin_closing` | 7256 |
| 2 | `carrick_core::mm::transaction::user_write::<impl carrick_core::mm::transaction::owner::MmPortal<P,Policy,Geometry,Venue,B,Context>>::write_user_bytes` | 6144 |
| 3 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::exit_with_status` | 5704 |
| 4 | `<carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S> as carrick_personality_linux::signal::ProcessSignals>::kill` | 5064 |
| 5 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::fork_publish` | 5004 |
| 6 | `carrick_core::mm::reservation::root::Reservations<Policy,Geometry,C>::copy_in_order` | 4988 |
| 7 | `carrick_el1_linux::ipc::serve_ipc` | 4964 |
| 8 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::resume_pending_lifecycle` | 4352 |
| 9 | `carrick_sched_core::process::exit::<impl carrick_sched_core::process::registry::ProcessRegistry<C,L,Z,R,Reservation,Retired,Group,Session,Failure>>::prepare_exit_topology` | 4204 |
| 10 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::drain_external_ingress` | 4160 |
| 11 | `carrick_core::mm::transaction::owner::serve_transfer` | 4112 |
| 12 | `<carrick_el1_linux::aarch64_process::Aarch64NativeProcessService<X> as carrick_el1_linux::native_process_runtime::NativeProcessService<carrick_sched_core::aarch64_context::Aarch64ParkedContext>>::prepare_mm` | 4088 |
| 13 | `carrick_sched_core::spaces::notification::SpaceNotificationLease<C>::release_resource` | 3936 |
| 14 | `carrick_personality_linux::identity::invoke` | 3664 |
| 15 | `carrick_sched_core::ZoneTables<C>::claim_for_host` | 3480 |
| 16 | `carrick_el1_linux::native_process_runtime::NativeProcessRuntime<M,C>::admit_fresh_root` | 3412 |
| 17 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::send_thread_signal` | 3376 |
| 18 | `carrick_sched_core::spaces::notification::<impl carrick_sched_core::ZoneTables<C>>::admit_space_notifications` | 3292 |
| 19 | `carrick_sched_core::ZoneTables<C>::wake_placed` | 3284 |
| 20 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::register_thread` | 3120 |
| 21 | `carrick_el1::fault::dispatch_fault_with_descriptor_txns` | 3040 |
| 22 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::fork_reserve` | 2852 |
| 23 | `carrick_sched_core::ZoneTables<C>::place_in_guest` | 2848 |
| 24 | `carrick_personality_linux::signal::invoke` | 2820 |
| 25 | `carrick_core::mm::fork::PreparedOwnerFork<B>::publish` | 2796 |
| 26 | `carrick_personality_linux::dispatch::dispatch` | 2760 |
| 27 | `carrick_personality_linux::ipc::invoke` | 2724 |
| 28 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2712 |
| 29 | `carrick_el1::memory::serve_delegated_anonymous` | 2696 |
| 30 | `carrick_el1_linux::ipc::release_pin` | 2664 |
| 31 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2592 |
| 32 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2592 |
| 33 | `carrick_el1_linux::ipc::epoll::serve_with` | 2544 |
| 34 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2512 |
| 35 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2512 |
| 36 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2512 |
| 37 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2512 |
| 38 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 2492 |
| 39 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::rehome_entry` | 2456 |
| 40 | `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::descend` | 2412 |

| Repeated demangled function family | Instances | Total text bytes |
|---|---:|---:|
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Leaf>,alloc::collections::btree::node::marker::Edge>::insert_recursing` | 27 | 47960 |
| `alloc::collections::btree::remove::<impl alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Leaf>,alloc::collections::btree::node::marker::KV>>::remove_leaf_kv` | 24 | 25784 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 8 | 20436 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::descend` | 8 | 17684 |
| `alloc::collections::btree::node::BalancingContext<K,V>::bulk_steal_right` | 22 | 13484 |
| `alloc::collections::btree::node::BalancingContext<K,V>::bulk_steal_left` | 22 | 11932 |
| `alloc::collections::btree::node::BalancingContext<K,V>::do_merge` | 22 | 11404 |
| `<alloc::collections::btree::map::BTreeMap<K,V,A> as core::ops::drop::Drop>::drop` | 21 | 10436 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_live_table` | 8 | 9776 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::KV>::split` | 21 | 8784 |
| `alloc::collections::btree::remove::<impl alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::LeafOrInternal>,alloc::collections::btree::node::marker::KV>>::remove_kv_tracking` | 24 | 8364 |
| `alloc::collections::btree::map::BTreeMap<K,V,A>::remove` | 19 | 7072 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::store` | 8 | 5428 |
| `carrick_core::mm::fork::PreparedOwnerFork<B>::publish` | 2 | 5168 |
| `carrick_sched_core::ZoneTables<C>::place_in_guest` | 2 | 5100 |

### Rebased candidate: symbol prefixes and top 40 functions

| Symbol crate prefix | Text bytes | Named data/BSS bytes |
|---|---:|---:|
| `alloc` | 213624 | 0 |
| `carrick_el1_linux` | 180012 | 688 |
| `carrick_core` | 94684 | 8 |
| `carrick_sched_core` | 64316 | 0 |
| `carrick_personality_linux` | 52868 | 4096 |
| `carrick_mmu_core` | 49848 | 0 |
| `carrick_el1` | 33168 | 6416 |
| `core` | 30460 | 0 |
| `carrick_el1_abi` | 23188 | 40 |
| `carrick_core_abi` | 12244 | 0 |
| `anonymous data` | 0 | 9269 |
| `carrick_fd_core` | 4252 | 0 |
| `carrick_pipe_core` | 3524 | 0 |
| `carrick_inotify_core` | 2820 | 0 |
| `carrick_signal_core` | 2332 | 33 |
| `&T as core` | 2276 | 0 |
| `compiler_builtins` | 1332 | 0 |
| `unqualified/assembly` | 1320 | 8 |
| `u64 as core` | 876 | 0 |
| `carrick_syscall_abi` | 828 | 0 |
| `zerocopy` | 776 | 0 |
| `u32 as core` | 568 | 0 |
| `__rustc` | 348 | 0 |
| `usize as core` | 308 | 0 |
| `T as alloc` | 280 | 0 |
| `carrick_guest_arch` | 196 | 0 |
| `T as core` | 184 | 0 |
| `(U,T) as core` | 116 | 0 |
| `W as carrick_sched_core` | 24 | 0 |
| `str as core` | 20 | 0 |
| `&str as core` | 16 | 0 |
| `&dyn core` | 12 | 0 |
| `&u64 as core` | 12 | 0 |

| Rank | Function (separate monomorphizations retained) | Bytes |
|---:|---|---:|
| 1 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::begin_closing` | 4368 |
| 2 | `<carrick_el1_linux::aarch64_process::Aarch64NativeProcessService<X> as carrick_el1_linux::native_process_runtime::NativeProcessService<carrick_sched_core::aarch64_context::Aarch64ParkedContext>>::prepare_mm` | 4172 |
| 3 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::fork_publish` | 4132 |
| 4 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::exit_with_status` | 4124 |
| 5 | `carrick_el1_linux::native_process_runtime::NativeProcessRuntime<M,C>::admit_fresh_root` | 3652 |
| 6 | `carrick_personality_linux::identity::invoke` | 3236 |
| 7 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::register_thread` | 2996 |
| 8 | `carrick_personality_linux::signal::invoke` | 2932 |
| 9 | `<carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S> as carrick_personality_linux::signal::ProcessSignals>::kill` | 2908 |
| 10 | `carrick_sched_core::process::exit::<impl carrick_sched_core::process::registry::ProcessRegistry<C,L,Z,R,Reservation,Retired,Group,Session,Failure>>::prepare_exit_topology` | 2904 |
| 11 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::fork_reserve` | 2488 |
| 12 | `carrick_personality_linux::ipc::invoke` | 2468 |
| 13 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::rehome_entry` | 2416 |
| 14 | `carrick_core::mm::transaction::owner::MmPortal<P,Policy,Geometry,Venue,B,Context>::select` | 2268 |
| 15 | `carrick_core::mm::transaction::owner::MmPortal<P,Policy,Geometry,Venue,B,Context>::select` | 2236 |
| 16 | `carrick_el1_linux::ipc::epoll::serve_with` | 2108 |
| 17 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::send_thread_signal` | 2016 |
| 18 | `carrick_el1::fault::dispatch_classified_fault` | 1992 |
| 19 | `carrick_el1_linux::arm_signal::setup_arm_signal_frame` | 1920 |
| 20 | `carrick_el1::memory::serve_delegated_anonymous` | 1884 |
| 21 | `carrick_el1_linux::mm_portal::fork::serve_fork_hw` | 1828 |
| 22 | `carrick_core::mm::capacity::MetadataAllocatorCore::allocate_with_metrics` | 1812 |
| 23 | `carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxnSlot::claim_for_mm` | 1804 |
| 24 | `carrick_core::mm::fork::copy_entry` | 1764 |
| 25 | `carrick_el1_linux::ipc::run` | 1752 |
| 26 | `carrick_core::mm::fork::copy_entry` | 1728 |
| 27 | `<carrick_core::mm::transaction::owner::MmPortal<P,Policy,Geometry,Venue,B,Context> as carrick_el1_linux::mm_portal::fork::NativeForkPortal<P,B>>::prepare_fork` | 1680 |
| 28 | `<carrick_core::mm::transaction::owner::MmPortal<P,Policy,Geometry,Venue,B,Context> as carrick_el1_linux::mm_portal::fork::NativeForkPortal<P,B>>::prepare_fork` | 1680 |
| 29 | `carrick_personality_linux::lifecycle::serve_exit` | 1608 |
| 30 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::resume_ipc` | 1592 |
| 31 | `carrick_el1_linux::ipc::admit` | 1588 |
| 32 | `carrick_personality_linux::dispatch::dispatch` | 1552 |
| 33 | `carrick_core::mm::fork::PreparedOwnerFork<B>::publish` | 1544 |
| 34 | `carrick_personality_linux::sysinfo::LinuxSysinfo::to_bytes` | 1540 |
| 35 | `carrick_el1_linux::process_owner::GuestPendingExit<C,U,N,F>::publish` | 1540 |
| 36 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::admit_external_event` | 1492 |
| 37 | `carrick_el1_abi::ipc::epoll::<impl carrick_el1_abi::ipc::IpcRegion>::epoll_harvest` | 1484 |
| 38 | `carrick_el1_linux::native_process_runtime::NativeProcessRegistry<M,C>::register_root` | 1480 |
| 39 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::wait_query` | 1452 |
| 40 | `carrick_core::mm::cow::resolve_guest_cow` | 1448 |

| Repeated demangled function family | Instances | Total text bytes |
|---|---:|---:|
| `alloc::collections::btree::node::BalancingContext<K,V>::do_merge` | 42 | 21592 |
| `alloc::collections::btree::node::BalancingContext<K,V>::bulk_steal_right` | 21 | 11828 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Leaf>,alloc::collections::btree::node::marker::Edge>::insert` | 28 | 11400 |
| `alloc::collections::btree::remove::<impl alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Leaf>,alloc::collections::btree::node::marker::KV>>::remove_leaf_kv` | 23 | 11292 |
| `alloc::collections::btree::node::BalancingContext<K,V>::bulk_steal_left` | 21 | 11104 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Leaf>,alloc::collections::btree::node::marker::Edge>::insert_recursing` | 28 | 10184 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::Edge>::insert` | 28 | 8524 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::descend` | 6 | 7576 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::KV>::split` | 28 | 7380 |
| `alloc::collections::btree::remove::<impl alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::KV>>::remove_internal_kv` | 23 | 7184 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::Edge>::insert_fit` | 24 | 6480 |
| `alloc::collections::btree::map::entry::VacantEntry<K,V,A>::insert_entry` | 28 | 5956 |
| `carrick_mmu_core::aarch64::descriptor_txn::Executor<W,J>::visit_entry` | 6 | 5896 |
| `alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,NodeType>,alloc::collections::btree::node::marker::KV>::split_leaf_data` | 24 | 5228 |
| `alloc::collections::btree::fix::<impl alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Mut,K,V,alloc::collections::btree::node::marker::LeafOrInternal>>::fix_node_through_parent` | 21 | 5040 |

### Rebased image variants and stack envelopes

| Image variant | Main loaded bytes | Candidate loaded bytes | Reclaimed | Candidate headroom |
|---|---:|---:|---:|---:|
| Default | 1,026,160 | 864,608 | 161,552 | 183,968 |
| `allocator-test-control` | 1,034,352 | 868,720 | 165,632 | 179,856 |

Both before/after builds of both variants exit zero. The candidate's maximum
registered stack path is **10,080 / 12,288 bytes**, leaving 2,208 bytes below
the unchanged budget and 6,304 bytes below the physical stack size. Candidate
stack envelopes are identical for both image variants:

| Registered stack path | Rebased main bytes | Candidate bytes |
|---|---:|---:|
| Native admission | 8,079 | 7,600 |
| Native fork publication | 8,926 | 8,943 |
| Native fork descriptors | 10,062 | 9,263 |
| Native fork context | 2,959 | 4,048 |
| Native wait copy | 11,535 | 10,080 |
| Signal delivery copy | 9,983 | 8,416 |
| Signal terminal exit | 11,519 | 8,992 |
| Signal return | 5,871 | 5,888 |
| Anonymous munmap | 7,040 | 6,688 |
| Metadata grant | 7,584 | 6,912 |
| Backing retirement | 8,848 | 9,040 |
| Descriptor drain | 6,320 | 5,968 |

Independent review reproduced the initial ELF section arithmetic and every
symbol-census row and found no implementation defects. Its documentation
caveat about inlined formatting attribution was incorporated. Rebase kept the
implementation byte-for-byte unchanged; the image builds above re-prove its
size and stack witness against the new main source.

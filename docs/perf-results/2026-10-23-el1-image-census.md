# EL1 image census and reclaim — 2026-10-23

Issue: #801. Baseline: GitHub main `9a9b4cd1f` (confirmed against GitHub
before measurement), Rust 1.96.0, Linux x86_64 worker ctb-w2. No Docker or
signed HVF execution is available on this worker.

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

## Main baseline

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

Next measurement: enable cross-crate LTO only in the nested EL1 image build,
retaining optimization level 3, frame pointers, overflow checks and DWARF.
Reject configurations that violate an existing stack-path or individual-frame
budget. Follow with both image variants and the requested host gates.

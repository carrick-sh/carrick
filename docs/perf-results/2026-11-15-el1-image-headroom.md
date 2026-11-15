# EL1 image headroom census and reclaim — 2026-11-15

Issues: #691, unblocking #2353 (#2306). Base: GitHub main `80e9287b0`.
Toolchain: Rust 1.96.0. Measured on a Linux x86_64 worker VM, which cannot
run signed HVF.

## Result

The nested EL1 image build now uses the `el1-image` profile. It is release
plus `codegen-units = 1`. `EL1_IMAGE_SIZE` (1,572,864 bytes) and every
frame budget are unchanged.

| Image, build CI reports (clippy) | main | head | reclaimed |
|---|---:|---:|---:|
| `allocator-test-control` | 1,562,272 | 1,447,056 | 115,216 |
| production | 1,558,176 | 1,447,056 | 111,120 |

| Image, plain `cargo build` | main | head | reclaimed |
|---|---:|---:|---:|
| `allocator-test-control` | 1,562,960 | 1,439,536 | 123,424 |
| production | 1,558,928 | 1,431,344 | 127,584 |

CI's own `lint-clippy` lines for the PR head are quoted on the PR. Those
are the authoritative numbers.

## Measurement boundary and tooling

The tooling already exists, and this census reuses it:

- `crates/carrick-el1-image/build.rs` prints
  `EL1 image budget: <loaded> bytes loaded / <limit> bytes; <headroom>`.
  The loaded size is `_image_end - _image_start`, the same expression the
  CEL1 header stores. It covers header, text, read-only data, data, BSS
  and the alignment padding between them. DWARF is not loaded.
- `crates/carrick-el1-image/frame_budget.rs` is the compiled-frame gate.
- The symbol census follows the method of
  `docs/perf-results/2026-10-23-el1-image-census.md`: `llvm-nm -S` on the
  nested ELF, with each identical `(address, size)` pair counted once.

The ELF is at
`<OUT_DIR>/el1-target/aarch64-unknown-none-softfloat/el1-image/carrick-el1`.
Before this change the profile directory was `release`.

## Why CI's image is about 3.4 KB larger than a local build

For `allocator-test-control`, main's CI reports 1,566,400 bytes and a
local `cargo build` reports 1,562,960 bytes. The gap has three parts.

1. **CI measures inside `cargo clippy`.** The nested `cargo build` runs
   from a build script and inherits Cargo's `RUSTC_WORKSPACE_WRAPPER`. So
   under `just clippy` every workspace crate in the image is compiled by
   `clippy-driver`, and the code it produces differs. Reproduced locally
   with `cargo clippy -p carrick-embed --no-default-features --features
   syscall-shim,platform-linux --lib --bins --examples`, the `lint-clippy`
   command that reports this variant: main gives 1,562,272 bytes. That is
   688 bytes less than the plain build, and it matches running the nested
   build directly with `RUSTC_WORKSPACE_WRAPPER=clippy-driver`.
2. **The loaded size moves in whole pages.** `ThreadLifecyclePage` is
   `align(4096)`, and its `initialize_at` template is the first object in
   `.rodata` (`link.ld` sorts by alignment). So `.rodata` starts on the
   page after `.text` ends, and the padding before it ranges from 0 to
   4,095 bytes. Main's local clippy `allocator-test-control` text ends
   2,588 bytes below that page boundary. Production's ends 296 bytes below.
3. **A residual this worker could not reproduce.** CI's production image
   is 32 bytes larger than the local clippy build (1,558,208 vs 1,558,176).
   That is too small to cross the 296-byte text slack, so it sits in data.
   CI's `allocator-test-control` image is one page plus 32 bytes larger, so
   its text is at least 2,588 bytes longer. The same `lint-clippy`
   command, run locally with and without a cold `sccache` wrapper,
   reproduces 1,562,272 exactly. The rodata contains no host paths. CI
   compiles through a warm, shared R2 `sccache`. That cache is the
   remaining known difference, but this was not proven.

Because of (2) and (3), compare local numbers only with other local
numbers, and judge headroom from CI's own line.

## Section census (`allocator-test-control`, clippy build)

| Section | main | head | change |
|---|---:|---:|---:|
| `.text` | 1,447,364 | 1,347,192 | −100,172 |
| `.rodata` | 105,025 | 92,209 | −12,816 |
| `.data` | 48 | 48 | 0 |
| `.bss` | 7,200 | 7,200 | 0 |
| padding before `.rodata` | 2,588 | 360 | |
| **loaded** | **1,562,272** | **1,447,056** | **−115,216** |

## Top contributors

Text totals by leading crate of the symbol (trait impls count under the
implementing crate), `allocator-test-control`, clippy build:

| Crate (symbol prefix) | main | head | change |
|---|---:|---:|---:|
| `carrick_el1_linux` | 469,028 | 505,968 | +36,940 |
| `carrick_core` | 190,644 | 161,804 | −28,840 |
| `alloc` | 188,976 | 125,096 | −63,880 |
| `carrick_sched_core` | 143,672 | 107,400 | −36,272 |
| `carrick_personality_linux` | 93,872 | 94,908 | +1,036 |
| `carrick_mmu_core` | 85,168 | 80,456 | −4,712 |
| `core` | 63,892 | 79,956 | +16,064 |
| `carrick_el1` | 64,640 | 64,640 | 0 |
| `carrick_el1_abi` | 55,304 | 46,404 | −8,900 |
| `carrick_core_abi` | 34,240 | 34,148 | −92 |
| `carrick_fd_core` | 29,160 | 22,056 | −7,104 |
| all named text | 1,447,356 | 1,347,184 | −100,172 |

The number of emitted functions falls from 3,266 to 2,907. Small upstream
generic helpers (B-tree node handles, `BTreeMap` drop, scheduler and core
accessors) fold into their callers in `carrick_el1_linux`. That is why
that crate grows while every upstream prefix shrinks. Only 3,800 bytes on
main were exact same-symbol copies, so the saving comes from optimizing
each crate whole, not from deduplication alone.

Largest functions on head:

| Rank | Function | Bytes |
|---:|---|---:|
| 1 | `carrick_el1_linux::ipc::serve_ipc_with_signals` | 13,100 |
| 2 | `carrick_el1_linux::process_owner::GuestPendingExit<C,U,N,F>::publish` | 12,104 |
| 3 | `carrick_personality_linux::native_host_file::stage` | 10,524 |
| 4 | `carrick_el1::fault::dispatch_fault_with_descriptor_txns` | 9,268 |
| 5 | `carrick_el1_linux::process_owner::GuestProcessOwner<C,U,N,F>::seed_initial` | 9,016 |
| 6 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::fork_publish` | 8,092 |
| 7 | `carrick_el1_linux::native_process_runtime::NativeProcessEntry<M,C,S>::begin_closing` | 7,976 |
| 8 | `carrick_el1_linux::native_process_entry::publish_exit` | 7,860 |
| 9 | `drop_in_place<carrick_sched_core::object_wait::ObjectWaitGuard<…>>` | 6,720 |
| 10 | `carrick_core::mm::transaction::user_write::…::write_user_target` | 6,120 |

Repeated monomorphization families:

| Family | main copies / bytes | head copies / bytes |
|---|---:|---:|
| `btree::node::Handle<…Leaf…, Edge>::insert_recursing` | 25 / 44,248 | 0 / 0 (inlined) |
| `btree::remove::…::remove_leaf_kv` | 24 / 24,568 | 24 / 25,088 |
| `descriptor_txn::Executor<W,J>::visit_entry` | 8 / 23,312 | 8 / 23,312 |
| `El1PendingFamilies<…>::serve_owned_ipc_descriptor` | 4 / 17,120 | 4 / 17,280 |
| `descriptor_txn::Executor<W,J>::descend` | 8 / 16,528 | 8 / 16,032 |
| `sched_core::refusal::contend_cold` | 7 / 13,328 | 7 / 6,408 |
| `BTreeMap<K,V,A> as Drop>::drop` | 21 / 10,024 | 0 / 0 (inlined) |

Formatting machinery is small, and its size is the same on main and head:

- 5,752 bytes of `core::fmt` builders and padding;
- 3,984 bytes of `Debug` and `Display` impls;
- 2,043 bytes of `core::unicode` tables.

Removing it would mean removing the panic and `Debug` paths that use it,
so this change leaves it alone.

## What changed recently

On `lint-clippy`, the production image grew from 1,537,280 bytes at
`ace226052` (2026-11-13) to 1,558,208 at `80e9287b0`. That is 20,928 bytes
in two days, across 110 commits touching the image's crates. Most of them
are the lifecycle group-close work (`fix(lifecycle)`, 11 commits), the
wait/status-copy owner-contention fixes (`fix(wait)`), and the crossing
output declarations (`fix(crossing)`). No single commit dominates.

## Options measured (`allocator-test-control`, nested build through clippy-driver)

| Configuration | Loaded bytes | Reclaimed |
|---|---:|---:|
| release (main) | 1,562,272 | — |
| `lto = "fat"` | 1,531,232 | 31,040 |
| `lto = "fat"` + `codegen-units = 1` | 1,476,992 | 85,280 |
| `codegen-units = 1` | 1,451,152 | 111,120 |
| `codegen-units = 1` for `carrick-el1-linux` only (plain build; main 1,562,960) | 1,461,024 | 101,936 |
| `codegen-units = 1` except `carrick-el1-linux` (plain build) | 1,545,680 | 17,280 |

Fat LTO inlines across crates, which is what broke the exit frames in
#691's original attempt. It also reclaims less than one codegen unit. The
#801 `opt-level = "s"` option was already rejected by a signed A/B
(+28 to +39% on gettid, epoll and futex loops), and it was not
re-measured.

## Frame gate

One codegen unit changes LLVM's inlining, so the compiled-frame gate first
failed in five places. The first commit fixes each one without changing a
budget:

| Failure | Cause | Fix |
|---|---|---|
| missing frame `::prepare_mm::`, `::fork_fd_table::` | inlined into the fork caller | `#[inline(never)]`, which main already emits out of line |
| declined fault signal 13,296 / 12,288 | `dispatch_fault_with_descriptor_txns` joined the COW resolver's retained frame (544 → 2,400 bytes) | `#[inline(never)]` |
| resumed signal delivery copy 12,319 / 12,288 | `ZoneTables::steal` joined `Sched::idle`, which is retained beneath every resumed thread | `#[inline(never)]` |
| individual frame `GuestPendingExit::publish` 3,104 / 3,072 | a by-value copy of the removed `Box<GuestTask>` | move the two fields out of the box in place: 2,512 bytes |

With only the first commit, under today's 16 units, the
`allocator-test-control` image is byte-identical in size to main
(1,562,960 bytes, plain build).

Chain totals, main's CI line against head's clippy build
(`allocator-test-control`): 26 of the 29 registered chains shrink. Three
grow:

- native service signal delivery, +96;
- signal delivery copy, +96;
- native wait copy, +704, to 11,487.

The tightest chain, resumed signal delivery copy, goes from 12,255 to
12,127 of 12,288 bytes.

One gap in the gate stays as it was. On main, `copy_signal_frame` (224
bytes) is a separate frame in the signal-copy chains that no fragment
charges. Under one codegen unit it inlines into the charged
`deliver_signal_on_syscall_return` closure (96 → 272 bytes). So head's
chain totals count it, and main's understate it.

## Speed

One codegen unit trades no speed for size. It keeps opt-level 3 and gives
LLVM whole-crate visibility. This worker cannot run the EL1 image, so the
evidence here is static. It compares instructions and calls in the hot
entry and syscall paths of the clippy `allocator-test-control` builds,
main against head:

| Function | main insns / calls | head insns / calls |
|---|---:|---:|
| `carrick_el1_syscall` | 156 / 14 | 156 / 14 |
| `dispatch::dispatch_entry` | 97 / 6 | 57 / 4 |
| `dispatch::dispatch_syscall` (main: plus its closure) | 521 / 38 | 918 / 65 |
| `personality_linux::dispatch::dispatch` | 884 / 86 | 922 / 86 |
| `*::futex::*` (main 8, head 6 symbols) | 1,237 / 81 | 1,037 / 69 |
| `ipc::epoll::serve_with` | 1,860 / 107 | 1,370 / 103 |
| `identity::invoke` | 977 / 103 | 984 / 104 |

No hot-path call boundary that main inlines is outlined. The new
`#[inline(never)]` marks match boundaries main already has. This
**suggests** no regression. The signed, paired gettid, futex and epoll A/B
that #801 used is still owed on the PR head.

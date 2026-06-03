# WS-F3 — File-size splits, statics, tokio (design spec)

Status: design for the **highest-merge-risk** refactors in the roadmap. The
roadmap explicitly says WS-F rewrites large hot files and must be done as
"focused, separately-reviewed efforts." This spec fixes the target module layout
so each split lands as a mechanical, behavior-preserving move with green tests,
and is safe to interleave with the parallel Rosetta branch (which churns several
of these same files).

The entry-point half of F3 is **done** (commit `94ace48`: `finish_and_run_image`
extracted from the 11 `run_*` entry points). What remains:

## A. Split the four oversized files

All splits follow the same safe recipe (the precedent set by carrick-host /
carrick-hvf): `git mv` cohesive groups into a submodule directory, bump the
moved items' visibility to `pub(crate)`/`pub(super)` as needed, and `pub use`
them back from the original module so every call site is unchanged. No logic
edits in the same commit as a move. Verify with `cargo test --lib`/`integration`
+ `runtime_loop` after each extraction.

### `dispatch/fs.rs` (5,416 lines) → `dispatch/fs/`

Already has `mod state`. The file is one `impl SyscallDispatcher` of handwritten
helpers (lines 32–1997) + one `define_syscall!` block (1998–end). Split the
handwritten impl by subsystem into `dispatch/fs/{path.rs, openclose.rs,
readwrite.rs, stat.rs, dirent.rs, link.rs, xattr.rs, splice.rs}` as
`impl SyscallDispatcher` blocks (Rust allows inherent-impl blocks across files in
the same crate). The `define_syscall!` table stays in `fs/mod.rs` (it is the
dispatch surface and should remain one readable table).

### `dispatch/mod.rs` (4,463 lines) → keep as the dispatch core, peel helpers

This is the dispatcher's heart (the `normalized_dispatch!` table, `DispatchOutcome`,
the subsystem locks). Peel only the clearly-separable: the constant `use` block
(→ `dispatch/abi_imports.rs`), the `EPOLL_INMEM_KQUEUES` epoll-shim helpers
(→ `dispatch/epoll_shim.rs`), and the membarrier/misc helpers. Leave the table
and lock structure in `mod.rs`.

### `trap.rs` (3,568 lines, carrick-hvf) → `trap/`

Split by concern: `trap/sysreg.rs` (the EL1 sysreg read/write trap decode),
`trap/page_table_edit.rs` (the stage-1 lazy-init + coalescing edit path, incl.
the recently-fixed `get_or_insert_with`), `trap/fault.rs` (data/instruction abort
handling), leaving `trap/mod.rs` with `HvfTrapEngine` + the `SyscallTrap` impl.
Highest Rosetta-collision risk — coordinate / do when that branch settles.

### `runtime.rs` (2,721 lines) → `runtime/`

Split the run loops (`run_combined_syscall_loop_with_dispatcher`,
`run_vcpu_until_exit`, the `SplitView` adapter) into `runtime/run_loop.rs`, the
signal-delivery cycle (`deliver_pending_signal` + helpers) into
`runtime/signal_delivery.rs`, leaving the `run_*` entry points + `finish_and_run_image`
in `runtime/mod.rs`.

## B. Reduce global statics

- `EPOLL_INMEM_KQUEUES` (`dispatch/mod.rs:800`, a `Mutex<Vec<i32>>` registry of
  in-memory epoll kqueue fds): move into per-dispatcher state (the dispatcher is
  already a shared `Arc<KernelState>` post-BKL-retirement), so it is scoped to a
  guest rather than process-global. Removes cross-guest fd-namespace bleed.
- `VCPU_LIVE` (`trap.rs:377`, an `AtomicI64` count of live vCPUs): this one is
  legitimately process-global (it gates the coalesce-safety decision across all
  vCPUs of the process) — keep it, but document the invariant at the definition.
  Not every global is a smell; this is shared hypervisor state.

## C. Drop tokio (evaluation → conclusion)

`tokio` is used in exactly three places, all in the image/CLI layer, none in the
runtime hot path: `carrick-image/src/lib.rs` (`tokio::fs` + the async
`oci-client` pull) and `carrick-cli` (`main.rs`, `runtime_util.rs` — the async
entry wrapper). `oci-client` is async-only, so tokio can't be dropped outright
without replacing the registry client. **Conclusion:** scope tokio to a single
`#[tokio::main]`-style block-on at the CLI image-pull boundary (it is already
nearly there), and gate the `tokio`/`oci-client` deps behind an `image-pull`
cargo feature so a runtime-only build (tests, embedders) compiles without the
async stack. Do not attempt to remove tokio while `oci-client` is the registry
client — that is a separate "replace the OCI client" project.

## Verification (every split commit)

`cargo build --workspace`, `cargo clippy --workspace` (no-panic gate), `cargo
test --lib` + `--test integration` + `--test runtime_loop`, and a `run-elf`
guest smoke. Because each split is a pure move + re-export, green tests are a
sufficient gate; any behavior change means the move wasn't pure and must be
backed out.

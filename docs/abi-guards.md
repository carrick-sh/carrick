# Shared guest layout and assembly guards

The `layout_manifest` unit tests pin the current wire layouts with literal
record sizes/alignments and every field's offset, size and alignment. They live
in each type's defining module, including private fields and the definitions
re-exported by `carrick-el1-abi`. Exhaustive field patterns also reject an added
field that fits existing padding. The expected values were captured from
`3fd7862be` on a 64-bit host; moving code must preserve them.

Run the VM-free layout guards:

```sh
cargo test -p carrick-el1-abi -p carrick-sched-core -p carrick-core-abi \
  -p carrick-personality-linux -p carrick-mmu-core -p carrick-mem \
  --lib layout_manifest
```

Compare assembly between committed revisions:

```sh
just xtask asm-diff --base BASE --head HEAD
# Protect x86 assembly as well:
just xtask asm-diff --base BASE --head HEAD --arch all
```

`--arch aarch64` is the default. `syn` extracts each `asm!`/`global_asm!`
invocation from `carrick-el1`, `carrick-el1-abi`, `carrick-x86-cpl0`,
`carrick-x86`, `carrick-mmu-core`, and HVF's `trap/sysreg.rs`. Keys contain
crate, module path, enclosing function (including impl/trait owner), and
ordinal. The command reads Git blobs without changing the checkout; it runs
on stable Rust on Linux and macOS without compiling or executing guest code.

Decoded literal instruction strings and operand/specification tokens (including
options and clobbers) must match. Enclosing `cfg`/`cfg_attr` stacks are compared
by their evaluated reachability in the default aarch64 mode.
Rust whitespace, comments and equivalent raw/escaped string spelling are
ignored. Identical relocated blocks report `MOVED` and pass; duplicates are
matched one-for-one. Aarch64-reachable additions, removals or changes fail
with a nonzero exit. Provably excluded x86 blocks report `ADDED-X86`,
`REMOVED-X86` or `CHANGED-X86` and pass in the default mode. The x86 ISA crates
and modules named `x86` or `x86_*` are treated as x86-only.

Cfg evaluation uses the guest image target (`target_os="none"`,
`target_arch="aarch64"`, no test harness), with package feature declarations
and default activation read from each Git revision's Cargo manifest. It also
protects the optional `allocator-test-control` image variant built by
`carrick-el1-image/build.rs`. For HVF's `sysreg.rs`, the target is aarch64 macOS.
Package-local feature activation is resolved; missing metadata, undeclared
features, dependency feature forwarding and other unsupported predicates stay
unknown. This guard does not run Cargo's full feature resolver.

Unchanged instructions and operands with provably equal target reachability
report `CFG-RESPELLED` and pass, including relocated blocks. Losing or gaining
reachability in either image profile fails as `CFG-CHANGED`. Unknown conditions
keep blocks guarded and cannot establish equivalence for a changed cfg stack.
Duplicate instruction blocks cannot mask a same-site reachability change.
`--arch all` retains strict cfg spelling checks. Summary output counts moves,
cfg respellings, excluded changes and failures.

Parent module and file cfg attributes are included. Conditional module
implementations retain separate invocations.
Unexpanded macro bodies are scanned too. Non-literal instruction templates
are rejected rather than silently comparing an unresolved `include_str!`.
This is a source guard: it does not expand macros, evaluate operand constants,
or compare generated machine code. Guest/runtime verification remains a
separate gate.

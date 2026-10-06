# X1 second re-review controls

Base of this review is `6051e19a2`, rebased on `56bf8c0ca`. These Linux
VM-free/KVM results do not confer signed/HVF or whole-X1 acceptance.

## Initialized shared sidecars

`boot_shared` now accepts a setup callback returning a complete `ContextBinding`.
Its retained storage remains `MaybeUninit` until the production
`initialize_context_binding` writer publishes that value. The host-release
fixture also returns a valid sidecar rather than leaving one zeroed.

The committed `shared_binding_initialization_never_borrows_zero_validity` test
executes that exact production writer. The scoped Miri harness includes the
production `cpl0_scheduler.rs` source and depends only on the production
`carrick-guest-arch` and `carrick-sched-core` paths. It is in `/tmp/x1-miri` on
carrick-vm; its manifest/source and outputs are retained in the review receipts.
Command:

```sh
MIRIFLAGS=-Zmiri-recursive-validation cargo +nightly miri test --manifest-path /tmp/x1-miri/Cargo.toml shared_binding_initialization_never_borrows_zero_validity
```

Restoring the historical borrow-before-write pattern (assume_init_mut followed
by assignment) fails before setup with `constructing invalid value ...
context.address.mm ... encountered 0`. The green writer passes. Recursive
validation is required: ordinary Miri does not recurse into that reference.
The flag is experimental, as documented by [Miri](https://github.com/rust-lang/miri).
This is a type-validity witness, paired with both real KVM suites on the newly
built image, not a substitute for hardware execution. Receipts:
`target/x1-review/review2-init-{miri-red,miri-green,image,kvm-green,x86,clippy,fmt}.log`.

## Installed native root

`shared_admission_installs_the_issued_hardware_root` publishes MM11 with
retained root 0x680000 while bootstrap starts at 0x600000. Both hardware roots
map the same user VA to distinguishable real bytes (0x42 vs 0x41), using the
existing PML4 builder for physical preparation. The first ordinary syscall
must authenticate and install the issued root before returning to user code.
Restoring the missing installation yields byte 65 instead of 66 while shared
admission reports success. No host callback applies a semantic owner edit.
Both KVM suites are green on the rebuilt image. Receipts:
`target/x1-review/review2-root-{old-image,red,image,green,clippy,fmt}.log`.

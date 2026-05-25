# Carrick Fuzz Targets

Install `cargo-fuzz`, then run from the repository root:

```sh
cargo fuzz run elf_load_plan
```

The target feeds arbitrary bytes through ELF metadata inspection and AArch64
load-plan construction. It treats parse errors and unsupported-machine errors
as valid outcomes; the useful signal is a panic, abort, or timeout.

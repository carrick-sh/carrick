# Allocator signed red: maintenance routing

Source: `981c1e09091ae7c4cfee4c546ccb6a14ce2e2d34`.
The focused signed allocator test exited 1; its unentitled negative control
passed and both original run scopes had zero remaining processes.
The exact signed executable is frozen at the path in `identity.json`.

The basic phase failed before allocator completion. Three LLDB reproductions
on the unchanged executable reached the executor failure/retirement paths.
`lldb-value.log` reads the original executor error directly: syndrome
`0x5a000001` was rejected as not an AArch64 SVC. That syndrome is the
existing HVC #1 maintenance-completion marker. The new HAL classifier
excluded maintenance from syscalls, but the HVF run loop rejected non-syscalls
before its existing HVC maintenance decoder.

The correction admits maintenance to that decoder without labeling it a
syscall or changing any budget. `cargo check -p carrick-vmm-hvf` passes.
Signed verification of the correction remains pending. Allocator growth,
return, denial, lifecycle, first-touch and checkpoint acceptance remain open.
LLDB observations are diagnostic and are not timing evidence.

# Image entrypoint resolution

`runtime.image-entrypoint` owns the initial container command's PATH and
shebang resolution. The production run boundary must route every ISA through
`carrick_kernel::exec_helpers::resolve_entrypoint_program`, under the launch
task's credentials. Guest `execve` keeps its separate full-path ABI semantics.

The local-image KVM witness uses a deliberately nonstandard image PATH with a
missing first directory, two bare executable names and an image ENTRYPOINT
script plus CMD. Its static payload prints `hello` and exits seven, so language
runtime defects cannot mask initial resolution. Existing x86 CLI tests compare
that same payload with native Linux.

The implementation retains the existing linear PATH search and four-level
shebang bound. No timing claim is made. Signed ARM/HVF and Docker remain
unavailable on this worker; actual language scoreboard outcomes must distinguish
successful loading from later syscall or loader failures.

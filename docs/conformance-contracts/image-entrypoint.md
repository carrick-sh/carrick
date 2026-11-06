# Image entrypoint resolution

`runtime.image-entrypoint` owns the initial container command's PATH and
shebang resolution. The production run boundary must route every ISA through
`carrick_kernel::exec_helpers::resolve_entrypoint_program`, under the launch
task's credentials. Guest `execve` keeps its separate full-path ABI semantics.

The local-image KVM witness uses a deliberately nonstandard image PATH with a
missing first directory, two bare executable names and an image ENTRYPOINT
script plus CMD. Its static payload prints the trailing argv and exits seven,
so language runtime defects cannot mask initial resolution. The witness checks
the interpreter option, script pathname and CMD order against native Linux.

The implementation retains the existing linear PATH search and four-level
shebang bound. No timing claim is made. Signed ARM/HVF and Docker remain
unavailable on this worker; actual language scoreboard outcomes must distinguish
successful loading from later syscall or loader failures.

Initial executable preparation is owned by `execute::prepare_initial_entrypoint`:
resolution, retained `ExecSource` acquisition, byte read, and executable identity
binding occur in the same order for ARM and KVM. The caller keeps its captured
launch context; KVM also uses it while reading the ELF's PT_INTERP. Carrier
construction and machine-specific ELF loading stay outside the helper.

The CLI witness also checks that `./python3` never searches PATH and that a
missing bare command and missing PT_INTERP return 127. A directory, a non-ELF
file, an invalid interpreter, and an ELF entry outside executable memory return
126. These launch failures use the
shared runtime classifier rather than becoming backend refusals (125).

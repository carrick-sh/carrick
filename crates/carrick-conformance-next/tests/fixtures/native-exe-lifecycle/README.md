# Native executable lifecycle

Six scenarios run the actual guest program through in-process embed. The
root driver starts two real fork children, which exec distinct copies: one
relative pathname and one final symlink. Both children read their own
`/proc/self/exe` using `SYS_readlinkat`, then remain live on bounded pipe
handshakes. No executable object is supplied by the host test.

Separate scenarios add real fork inheritance; shared-MM
`CLONE_VM | CLONE_VFORK | SIGCHLD` (a private child stack avoids returning
twice through a Rust frame); a real second thread kept live while its leader
also reads; failed exec followed by the caller's readlink; and root-issued
rename/unlink of both files while both holders remain live. Renamed paths
must update, and unlink must append ` (deleted)`. Every scenario reports
the initial population and completion, so an early death cannot pass.

The native Linux x86_64 known-answer outputs in `oracle.json` qualify the
fixture and are source-hash checked. They are explicitly pending the
director's native ARM64 Linux bless. They are not Carrick execution proof.

The signed runner builds the AArch64 musl fixture and stamps its source
hash; the guest output must agree with the current source and oracle. The
test logs the executable SHA-256. On the director's Mac:

```sh
CARGO_BUILD_JOBS=3 CARRICK_TEST_TARGET=native_exe_lifecycle just test-conformance-next case_native_exe_lifecycle --include-ignored --nocapture
```

Run that once on the unmodified head. Then temporarily replace the
production `physical.sources.bind_executable(executable)` in
`carrick-vmm-hvf/src/trap/execve_rebuild.rs::prepare_native_exec_successor`
with `drop(executable)` (not the separate cancellation-fixture binding).
Rebuild through the same signed recipe and retain every test's failure.
Each initial native child's first read should report Linux errno **38**,
and every selected case must fail. Restore and rerun the signed recipe.
The capability's loader/preparation is
`NativeExecHostService::prepare for NativeExecCapability` in
`runtime/exec.rs`; the binding into successor MM custody occurs in the
physical preparation function above. There is no method literally named
`NativeExecCapability::prepare_exec`.

The Linux worker cannot execute that macOS/AArch64 path. Neither native
Linux fixture runs nor cross-check-macos prove the binding mutation red.

To build/check the fixture on Linux, set `CARRICK_NATIVE_EXE_SOURCE_SHA256`
to the SHA-256 of `src/main.rs`, then use `cargo build --locked
--manifest-path <fixture>/Cargo.toml`. Run the absolute binary path with
each of `populations fork vfork thread failed mutations`, under
`timeout 10`. No Docker or Carrick guest is started in those controls.

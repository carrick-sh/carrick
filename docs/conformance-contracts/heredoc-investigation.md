# Heredoc subshell investigation (#1399)

The reported ARM/HVF hang remains undiagnosed. The Linux x86 KVM attempt
does not reproduce that hang, but it also does not execute the workload
successfully. Do not interpret either its exit status or the VM-free control
below as acceptance of #1399.

## Dispatcher control

`carrick-kernel-example::fork_pipe_wait::subshell_local_pipe_redirect_reads_bytes_then_eof_without_writer_exit`
exercises the public production dispatcher. A child creates its own pipe,
writes `a\n`, closes the writer, duplicates the reader onto stdin, closes the
original reader and reads one byte at a time through EOF. Its parent stays
alive and has not created a pipe. The test checks both bytes, the child's
wait status, and exactly three read dispatches. The backend's existing
five-second wait bound applies unchanged.

This control passes on the admitted main. It is **not a red-first witness**
and makes no claim that a particular shell uses this syscall sequence. It
checks the pipe/descriptor semantics covered by `kernel.el1.ipc-fd-authority`;
it does not exercise native ring entry, the shell, or VMM scheduling.

## Live KVM attempt

Build with `just build`, then run with `CARRICK_REQUIRE_KVM=1`, a unique
`CARRICK_RUN_ID`, stdin from `/dev/null`, and bounded scoped cleanup:

```sh
carrick run --json ubuntu:24.04 /bin/sh -c '(while read l; do
  printf "%s\n" "$l"
done <<EOF
a
EOF
); :'
```

On this worker, Ubuntu exits 127 with empty output. The simpler control
`printf "CONTROL\n"` also exits 127. The JSON execution witness identifies
`kvm-x86-cpl0`, 29 guest entries and one `root_exit` crossing for the control.
The heredoc loop has not been established as reached.

Alpine 3.20 exits 0 with empty output for the original shape. That is not a
pass: the trailing `:` discards the subshell status. Use an explicit content
and completion check:

```sh
carrick run --json alpine:3.20 /bin/sh -c '(n=0
while read l; do
  test "$l" = a || exit 39
  n=$((n+1))
done <<EOF
a
EOF
test "$n" -eq 0 && exit 38
test "$n" -eq 1 || exit 40
exit 37
); s=$?; :; exit "$s"'
```

This exits 38, not the success sentinel 37: no line was consumed. A separate
Alpine control, `printf "CONTROL\n"; exit 23`, returns 23 but also has empty
output. These are earlier correctness failures, not evidence of the reported
hang or its cause. The admitted main also lacks the native-child `pipe2`
bridge under review in #1379; do not silently import that unmerged work to
change the investigation's base.

## Evidence still needed

Docker and bpftrace are absent on this worker. `carrick trace` fails with
`requires a host libdtrace implementation`. The director's Mac evidence
directory is unavailable. Consequently the shell's actual heredoc mechanism
(pipe versus temporary file), the blocking syscall, and the retained endpoint
population remain unverified. No runtime implementation was changed.

Continue on the director's original image and artifact (or an explicitly
admitted successor containing its prerequisites): capture the syscall shape
with bpftrace inside the Docker oracle, then inspect the carrier event ring
or bounded `carrick trace`. Keep the counted completion check so an empty
loop followed by `:` cannot appear green. Obtain a red witness through the
production path before selecting a shared-layer correction. Signed smoke,
the embed/probe and ecosystem gates, and an uninstrumented Docker comparison
remain outstanding.

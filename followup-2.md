title: x86 KVM: a fork child's write to a `$(…)` pipe returns EIO (node rows' next stop after #2266)
parent: #2266

**What happens (real KVM, head of #2266 `059752685`).** The fork child now survives its first write (#2226). Its stdout write into the shell's command-substitution pipe fails:

```
carrick run --rm --entrypoint /bin/sh node:22-slim -c '(echo sub-stdout); echo a | cat; x=$(printf p); echo "printf [$x]"'
sub-stdout
/bin/sh: 1: echo: echo: I/O error
/bin/sh: 1: cat: Function not implemented
/bin/sh: 1: printf: printf: I/O error
printf []
```

- A subshell writing to the inherited terminal works (`sub-stdout`).
- Any fork child writing into a pipe gets `EIO`.
- A fork child's `execve` gets ENOSYS, which is #1093.

In `node:22-slim`'s `docker-entrypoint.sh`, `$(command -v "$1")` therefore comes back empty, the script falls through to `exec node "$@"` in the root, and that returns ENOSYS (#2142). `node-version` and `node-child` exit 126.

**Not root-caused here.** x86 has no in-ring pipe venue yet (#1756), but the child gets EIO, not a counted ENOSYS. So the write is likely forwarded somewhere that answers with EIO. Check that against #1756 and #2181 (root `kill()` of a fork child also returns EIO) before filing separately.

**Acceptance.** A red-first KVM witness: a two-process pipe where the fork child writes and the parent reads, matching native byte for byte. The node rows then reach #2142.

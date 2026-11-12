# followup-6: the ring's fstat(fd) on a root-opened file does not see a host-side change

Part of #2157. Observed in the metadata fixture: after `fchmodat(AT_FDCWD, "f", 0600)` crossed to
the host and changed the file (the host file shows 0600), `fstat(fd)` on the descriptor the
root's staged `openat` returned still reports 0644, while `newfstatat("f")` by path reports
0600. The retained host-file description serves stat from a stale view. B1's witness checks
mutations by path for that reason. Native Linux shows the change on both. This is a
coherence gap between the ring venue and host-crossing mutations (shared, not x86 specific;
check ARM before filing).

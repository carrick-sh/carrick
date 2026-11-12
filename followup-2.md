# Follow-up 2: the rest of #2067: fork-child fchmodat, fchmod and fchmodat2 are still ENOSYS (case_09)

PR #2214 lands #2067's `fchdir` half. `chmod` in a forked child still fails with `chmod: changing permissions of 'm': Function not implemented` (case_09, run 43246641703, line 582). `HostFileCall::decode` has no FCHMODAT, FCHMOD or FCHMODAT2 arm, so the call is an unclaimed native syscall: counted ENOSYS for ForkChild (`crates/carrick-el1-linux/src/dispatch.rs:799`).

**Shape of the fix:** follow the mkdir extraction (`ac2efa8a0`). `FsView::chmod_at` (`crates/carrick-kernel/src/dispatch/fs/attr.rs`) needs a `KernelContext` and guest memory today. Split it into a path-and-mode core that takes `Option<&KernelContext>`, as `mkdir_path` does. Then add `HostFileOp::Chmod` (path) and `Fchmod` (descriptor) on the venue. Keep fchmodat2's EOPNOTSUPP-on-symlink rule in the shared core.

**Note:** coreutils 9.x `chmod -R` uses fts, so it calls `fchmodat(dirfd, name)`. That also needs follow-up 3.

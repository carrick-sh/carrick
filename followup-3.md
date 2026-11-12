# Follow-up 3: a relative *at path through a real directory fd is ENOSYS for fork children

`crates/carrick-personality-linux/src/native_host_file.rs:745` (`Staging::path_base`): a relative path with a `dirfd` other than `AT_FDCWD` that names a host-backed directory answers ENOSYS ("a later slice serves"). This affects `openat`, `newfstatat`, `statx`, `mkdirat`, `unlinkat`, `linkat`, `renameat`, `symlinkat`, `utimensat` and `faccessat` from every fork child. fts-based tools (`rm -r`, `chmod -R`, `find`, `du`), Python's `os.fwalk` and `shutil.rmtree`, and Go's `os.RemoveAll` all hit it.

PR #2214's carrier half already resolves a pinned directory description to its path (`FsView::fchdir_target`). The same resolution could seed the base for these calls: the carrier resolves `path` against the pinned description's directory under the caller's access context. Errno order must match Linux: EBADF, then ENOTDIR, then the lookup.

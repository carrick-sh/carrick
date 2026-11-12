# followup-7: legacy x86-only syscall numbers are not remapped

Part of #2157. x86_64 programs that use the pre-`*at` calls reach the table as Unknown (ENOSYS):
open, creat, mkdir, rmdir, unlink, rename, link, symlink, readlink, chmod, chown, lchown,
mknod, utime, utimes, futimesat, getdents (stat/lstat have private canonical numbers but the
crossing table aliases only fstat and newfstatat). `access` is already normalised to faccessat.
(Verify each against `syscall_x86_64.rs` before filing.) B1 flips the canonical crossings; a legacy-number normalisation (to the `*at` forms) is the
remaining x86-specific step before a C library that still emits them gets the same results.

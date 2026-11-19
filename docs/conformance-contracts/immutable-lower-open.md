# Immutable-lower open

`kernel.vfs.immutable-lower-open` covers read-only absolute `openat` on
an immutable host-backed lower and a sparse upper. Linux follows an
intermediate symlink before applying `..`. A missing component still
returns `ENOENT`, a regular file before `..` returns `ENOTDIR`, and
a trailing slash or terminal `/.` requires a directory.
[Linux pathname resolution](https://man7.org/linux/man-pages/man7/path_resolution.7.html)

The macOS immutable-lower fast open must decline these shapes before
opening any host component. The layered resolver then owns the result.
The backend witness bounds the lower attempt to zero host opens and
exercises a regular-file positive control. The dispatcher witness checks
the exact bytes or errno from the layered fixture. The Linux-host run
exercises the resolver because the immutable-lower fast open is macOS-only.

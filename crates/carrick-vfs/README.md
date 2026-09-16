# carrick-vfs

The Carrick filesystem model, extracted from `carrick-runtime`. It answers one
question for every guest path — *who owns this path?* — and owns everything
behind that answer: the `Vfs` trait and its longest-prefix mount table
(`VfsMounts`), the value types that cross the dispatcher↔mount boundary
(`Metadata`, `DirEnt`, `OpenFlags`, `VfsHandle`, `OpenContext`), the dentry
cache and its inode identities, the writable `FsBackend`s (host-APFS and the
optional in-memory one), the immutable OCI `RootFs` with its overlay and layer
cache, the path codec, and the single-file/bind mounts (`BindVfs`,
`ResolvConfVfs`, `EtcServicesVfs`). It names no kernel, carrier or VMM type.

## What it deliberately excludes

The **kernel-view filesystems stay in `carrick-runtime`**: `/proc` (`ProcVfs`),
`/sys` (`SysVfs`), `/dev` (`DevVfs`) and `/dev/pts` (`DevptsVfs`). They are not
filesystems in the sense this crate models — they *render kernel state* (the
task graph, credentials, the network namespace, the pty table), so they live
with the kernel that owns that state and implement this crate's `Vfs` trait from
above.

## The `FsCaller` / `FsNetworkView` seam

A synthetic mount sometimes needs to know something about the task doing the
open that this crate does not model: its user-namespace id maps and capability
sets, or the links its network namespace advertises. Rather than naming the
kernel's types, `OpenContext` carries `Arc<dyn FsCaller>` and
`Arc<dyn FsNetworkView>` — two small traits defined here whose method sets are
exactly what the `/proc` renderer reads. The kernel implements them; the VFS
only calls them. The same rule covers the console handed back by a `/dev` mount
(`VirtualConsoleDevice`): the trait is here, the object is above.

## Stability

Experimental. **No semver**, no stability guarantee, and the API changes
without notice — this crate exists to split Carrick's build graph, not to be a
general-purpose VFS library. It is not published to crates.io (no crate in this
workspace is). If you depend on it, pin an exact git rev.

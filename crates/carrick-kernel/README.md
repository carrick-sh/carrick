# carrick-kernel

The Carrick kernel, extracted from `carrick-runtime`. It is the half of Carrick
that answers syscalls: the kernel object graph (`kernel/` — task and process
identity, address-space authority, file descriptions, wait sets, continuations,
the scheduler view), the syscall dispatcher and its subsystems (`dispatch/` —
fs, mem, signal, net, futex, creds, sysv, time, …), the namespaces
(`namespace/`), the in-zone network (`network/`), the file authority
(`file_authority/`), the observation/sandbox policy (`observe/`), the
kernel-view filesystems (`vfs/` — `/proc`, `/sys`, `/dev`, `/dev/pts`) over the
`carrick-vfs` filesystem model, and the single-file subsystems the guest
reaches through them (containers, seccomp, inotify/fanotify, the keyring,
core dumps, ptys, the event ring, the syslog, …).

## What it deliberately excludes

The **execution lane stays in `carrick-runtime`**: the HVPatch VM carrier, the
vCPU loop, the threaded loop, image preparation and the run lifecycle, the
supervisors, and the bins. This crate names no carrier module and no
`carrick-vmm-*` crate. What it needs from the lane arrives through `carrick-hal`
traits the carrier implements — `SyscallTrap`, `CarrierProcess`,
`Stage1MmProjection`, `HostSignalBridge`, `GuestTimerBridge` — and what it needs
from the host arrives through the leaf crates (`carrick-host`, `carrick-mem`,
`carrick-thread`, `carrick-host-bsd`/`-linux`).

It also selects no backend: there are no `platform-*` features here. The host
event multiplexer and the host errno table are chosen by `cfg(target_os)`
dependency tables, exactly as in `carrick-vfs`; backend selection lives above,
in `carrick-runtime`.

## Stability

Experimental. **No semver**, no stability guarantee, and the API changes
without notice — this crate exists to split Carrick's build graph and to let an
execution backend other than the HVPatch carrier reuse the kernel, not to be a
general-purpose library. It is not published to crates.io (no crate in this
workspace is). If you depend on it, pin an exact git rev.

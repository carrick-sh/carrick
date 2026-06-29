# Shared guest memory on bhyve (MAP_SHARED / SysV-shm / cross-process futex)

## The problem

Carrick host-forks one real host process per guest `clone(2)` — **one Linux
process = one host process** is a core invariant (host signals, the host
scheduler, real isolation). On KVM (`mmap MAP_PRIVATE`) and HVF
(clonefile/mach) the host fork is **COW**, so guest memory that two processes
are supposed to share (a `MAP_SHARED` mapping, a SysV-shm segment, a futex word
on shared memory) stays coherent across the fork for free — both host processes'
VMs map the same physical pages.

bhyve has no COW for guest sysmem (kernel-owned `OBJT_SWAP`, dual-vmspace). Its
fork runs `EagerCopy`
(`freeze_ram` → `rebuild_child_vm`): the child gets a **separate VM with copied
RAM**. So every guest page two processes should share diverges. The current
`map_host_alias` copies a `MAP_SHARED` file into private sysmem and resyncs only
at the fork/exit/reap barriers — enough for coherence observed *across a
fork+wait barrier* (`forkshared`, `mapfixed`, SysV-shm pass) but not for
within-process two-map coherence or live cross-process sharing.

## Two rejected approaches (and why) — both kept as documented fallbacks

**1. Patch the FreeBSD kernel (`vmm.ko`).** A host-process `mmap(MAP_FIXED)`
overlaid on guest physical memory does **not** reach the guest — it rebinds only
the host page table, not the guest EPT (proven empirically: a guest CPU read the
original swap page, not the overlay). The guest EPT resolves from the memseg's
backing `vm_object`. Two VMs *can* share one `OBJT_SWAP` object coherently (the
FreeBSD VM subsystem already supports multi-pmap object sharing with no COW
shadow — validated), but the userspace `VM_ALLOC_MEMSEG` ABI always allocates a
*fresh* per-VM object. A small (~30–50 LOC), ABI-preserving `vmm.ko` patch that
backs a memseg with a caller-supplied POSIX-shm fd's object **was written and
proven** (VM B's guest CPU read VM A's write through one shared page; red
baseline diverges; patch + experiment archived).
→ **Rejected as the primary path** because it makes carrick-on-bhyve depend on a
patched/custom kernel module — a deployment burden. Kept as a fallback: the
validated patch is the right move *if/when* max `MAP_SHARED` throughput matters
(it's a clean upstream candidate; upstreaming would remove the dependency).

**2. One shared bhyve VM, per-process `CR3` contexts.** Run all guest processes
as vCPUs in a single VM (shared sysmem → shared memory for free), each with its
own guest page tables; "fork" = a new `CR3` context. Fully coherent, userspace,
no kernel patch — and it's how a real OS runs processes.
→ **Rejected** because it breaks the **one-Linux-process = one-host-process**
invariant we want to preserve (it collapses to one host process multiplexing
vCPUs, losing host-level process isolation/signals). Kept as a fallback if that
invariant is ever relaxed for bhyve.

## The chosen approach — userspace coherence at syscall boundaries (separate VMs)

Keep separate VMs / separate host processes. The insight: the guest's shared
memory only has to be coherent **at the points the guest is observable** —
within a process, or across a syscall (carrick traps every guest syscall).

- **Host backing = source of truth.** Every shared region (a `MAP_SHARED` file,
  a `MAP_SHARED|MAP_ANON` region — backed by a host `O_TMPFILE`/shm — or a SysV
  segment) has a single host file/shm mapping, inherited across `libc::fork`
  (host memory survives fork for free, on every OS). The guest's VM-GPA pages for
  that region are a **working copy**.
- **Within-process coherence → GPA-aliasing (free).** Repeated
  `mmap(MAP_SHARED, same fd+offset)` in one process aliases the **same** guest
  GPA instead of a fresh per-mapping copy → the two views are the same physical
  guest page → coherent with zero syncing. (Closes `memmap`'s
  `two_shared_maps_coherent` / `shared_write_without_msync`.)
- **Cross-process coherence → sync at the syscall boundary.** On VM-exit (every
  guest syscall) flush the dirty aperture pages → the host backing; on VM-resume
  refresh the aperture ← the host backing; `read`/`write`/`msync`/`futex`
  operate on the host backing (the live shared state). Coherence is then
  guaranteed at syscall granularity: any write before a syscall is visible after
  the other side's next syscall. (Closes `telemetrymap`, `futexsharedalias`,
  `ltpcheckpoint`-futex — those rendezvous *at* `futex_wait`/`wake` — and
  `memmap`'s read/write-visibility fields.)

KVM/HVF are untouched — they keep their free COW path; all of this lives behind
the bhyve `X86Vmm` impl.

### The one genuine residual: `futexshare`

`futexshare` lock-free *polls* a shared word with **no syscall on either side**,
so there is no boundary to hook — the poller reads its own VM's working copy and
never refreshes it. Closing it needs shared EPT (fallback #1, the kernel patch)
or per-access trapping (prohibitive). It remains a **documented bhyve floor**
(bhyve baseline overlay, not a global gap — KVM/HVF pass it via OS COW).

### Trade-off

The per-syscall flush/refresh is a real cost (a memcpy of the — typically small —
aperture per syscall), strictly more expensive than the free COW KVM/HVF get.
Acceptable for bhyve as a bring-up lane; dirty-page tracking (bhyve exposes EPT
dirty bits for live migration) can optimize it later. The private region keeps
the cheap `EagerCopy`-bounded-to-high-water path.

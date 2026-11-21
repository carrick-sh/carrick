# x86 initial user layout (#2722)

Contract: `kernel.el1.anonymous-reservations`, over the image laid out by
`x86.mm.initial-image`.

Linux authority: mmap(2), brk(2), fork(2), and the layout a native x86-64
process shows in `/proc/self/maps`. A `PROT_NONE|MAP_NORESERVE` mapping of any
size that fits the user address space succeeds (subject to `RLIMIT_AS`); the
stack sits at the top of the user half, far above the image, the break and
every mapping. Linux randomizes the exact addresses, so the contract is the
ordering and the room, not the numbers.

Carrick invariant: the x86 initial stack top is the Linux personality's one
stack placement, `carrick_mem::memory::LINUX_STACK_TOP` (just under 1 TiB),
the same constant ARM uses. It is above every image base (`ET_EXEC` at
4 MiB, PIE at 544 GiB, the interpreter at 560 GiB), so
`initial_reservation_layout` gives a low image the whole `LINUX_MMAP_SIZE`
(32 GiB) arena after its heap. Before #2722 the stack was parked at 2 GiB and
clipped a low image's arena to `[1 GiB, 2 GiB - 8 MiB)`, 1015.9 MiB: a 1 GiB
reservation found no gap and returned `ENOMEM` from inside the ring, with
nothing counted.

Cost: the stack's page-table branch no longer shares the image's 512 GiB
slot, so a low image takes one more table page (an exec successor's demand
goes from 9 to 10). Reservations stay lazy: a `PROT_NONE` range takes no
frames and no tables until it is committed and touched.

Witnesses, each run natively on Linux first and then through the production
KVM pool (`cpl0_initial_mm`, fixture `native_child_mprotect_shapes.S`):

- a forked child and the run root each reserve 1 GiB, commit 1 MiB inside it
  and write every page;
- a 4 GiB reservation committed 3 GiB in;
- the root reserves 4 GiB, grows `brk` by 1 MiB, touches the stack 1 MiB
  down and forks; both live processes keep their own copy of the committed
  page and the child reserves 1 GiB more;
- the 16 MiB and 256 MiB sizes, green before and after.

The layout unit tests in `carrick-x86-cpl0-host` pin `arena.len() ==
LINUX_MMAP_SIZE` for every low break and keep the clip only for a break
directly under the stack.

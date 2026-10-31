# Fork stage-1 image example

The pending owner-fork table is runtime metadata, initialized once in place on
the EL1 metadata heap before ARM entry routing. Its publication state alone
must fit in one page of the code image
(`pending_fork_image_storage_fits_one_page`);
`concurrent_initialization_retains_one_table_and_slot_locks` proves concurrent
bring-up retains one empty table and does not reset or share slot locks.
Initialization visits each CPU slot once; later entries load one pointer.
The image build reports CEL1's loaded footprint (including `.bss`) and headroom
under the unchanged 1 MiB ABI limit. These VM-free structural witnesses do not
replace the signed ARM fork binding.

The fork image's identity/control publication uses a named kernel window,
not Linux user-copy authority. VM-free witnesses exercise copied-child identity,
shared-MM gate closure and parent handback, exact live MM translation, retained
physical writer custody, and refusal of user/image windows or stale translations.
The scoped signed bindings include fork/exec shared backing and inotify09 vfork.

`kernel.fork.stage1-image` also requires owner-selected physical custody to
authenticate the selected IPA through the carrier's exact extent record, VM
generation and logical-owner generation. A carrier-MM alias index is not the
extent authority; guest VAs cannot substitute for physical selections. The
VM-free binding
`owner_fork_retains_live_structural_capacity_without_carrier_mm_alias_index`
retains two real structural records for a bounded copy with an empty legacy
index. `owner_selected_same_va_in_two_mms_retains_exact_physical_frames` guards
same-VA isolation. Lookup work follows the physical extent index and selected
records, without scanning other MM populations. Signed fork acceptance remains
required.

Fresh physical-grant inventory mappings start at their own initial generation;
the carrier allocation generation remains with physical backing custody.
Shared `StagedPhysicalGrants` owns initialization and accepts no generation
from a backend. `native_child_empty_supply_resumes_cow_without_changing_parent`
and `native_backing_reply_observes_a_competing_valid_publication` compose
carrier generations 5, 6 and 7 with fresh inventory publications, USED
settlement and neutral physical retirement. The former was red when carrier
generation 5 was submitted as the fresh mapping's generation. The existing
two-grant refill and bounded page-copy assertions remain unchanged.

Native USED receipts authenticate completed ring publications, not descriptors
that must remain installed until host settlement. MAP_FIXED and unmap may
replace those descriptors while the physical grant remains retained. The
shared physical owner settles exact grant epoch, MM and live inventory identity
without a backend page-table verdict. The two-live-process witness
`native_child_fixed_over_cow_preserves_parent_bytes_and_retires` replaces a
COW-shared page at a sub-16K offset, checks both processes' bytes and returns
stock through terminal retirement; a foreign MM cannot settle the receipt.
Final-MM root retirement consumes its deferred-return journal together with
its tree, under retained whole-MM physical custody. Host and native exits
use that same neutral operation; ordinary retirement still refuses owed
returns. Refusal must leave the journal intact.

Native backing selection must exclude live or prepared inherited neighbors,
even when the child's lazy-grant residency table has no row for them.
`native_child_backing_selection_excludes_inherited_live_neighbor` forks an
actual child from a two-page reservation with one resident parent page and
requires the first supply window to contain only the absent page. The neutral
grant owner selects the contiguous available span under the exact MM editor,
using the same predicate that authenticates publication. Work is bounded by
the selected window (at most 512 pages, four descriptor loads per page), not
the MM population. The adapter submits that exact window and never crops a
decoded transaction or changes its receipt digest.

The KVM vfork VM rebuild also publishes each selected shadow pointer to the
host-side window descriptor under its write lock. The real-KVM binding
`vfork_rebuild_host_reads_shadow_bytes` reads distinct child bytes through
`GuestRam` after rebuilding, while a shared window retains its original bytes.
The pre-fix host read returned the parent's private bytes. This publication
visits each window once and adds no backing copy; the retained shadow remains
the source for both host reads and guest memslots. Full vfork/exec and signed
acceptance remain the existing higher-layer bindings.

Native fork stock reserves that same physical custody before child publication.
`native_stock_reserve_refuses_retiring_stage2_record_and_rolls_back_earlier_pin`
drives the HVF stock crossing and the stage-2 retirement owner without booting a
VM: retirement before Reserve refuses admission, drops earlier row pins, and
permits a clean Abort and subsequent fork; retirement after Reserve cannot
revoke the admitted child's pin. Commit only consumes that reservation, never
reconstructs custody. The HAL binding
`unreserved_commit_cannot_bypass_physical_custody_admission` rejects the former
inline-Commit path. ARM settlement keeps the child space closed on a typed
Commit refusal, failed crossing, or missing acknowledgment; these are invariant
faults after publication, not successful forks. These host witnesses do not
replace signed guest or KVM acceptance.

Physical-custody destruction must not retain the grant-accounting lock (#569).
`child_reclaim_and_terminal_finalization_do_not_invert_accounting_lock` drives
that same neutral stock owner against a second executor finalizing a directory
entry. The bounded witness rejects the ledger-to-directory edge captured on
hardware. The HVF accounting authority exposes only completed accounting
operations to fork callers, never a guard or a callback under the guard.
Exact terminal receipt publication remains serialized with IPA reuse inside
the accounting implementation; it does not admit or reclaim fork custody.

Custody arrays may be allocated in either the fixed EL1 bootstrap/heap region
or a retained dynamic metadata grant. The dynamic path shares the lifecycle
record venue, rather than imposing a fixed-region-only allocation limit.
`native_stock_reserve_accepts_custody_in_dynamic_metadata` drives the production
stock service with its four-word custody array in a dynamic grant, including
retirement refusal, rollback and successful subsequent Reserve/Commit.

Owner-selected fork leaves retain the parent's exact physical inventory extent
once per extent, independent of the selected leaf count. A 4 KiB semantic leaf
must not shrink a 16 KiB compound's custody to 4 KiB: child bootstrap COW and
exec retirement need that exact record. Guest access stays limited by the
owner's stage-1 leaves. The VM-free binding
`owner_selected_fork_leaf_retains_vvar_compound_for_child_bootstrap` runs the
production owner projection, child inventory staging, privileged RNG COW and
old-MM exec retirement while the parent's backing remains live and unchanged.
It requires one inherited inventory mapping for the selected parent extent,
a bounded compound copy, and zero retirement of parent-owned physical leases.
The owner's table capacity has no bootstrap guest-VA alias. Bootstrap COW
resolves the manager's actual physical root through the current MM's arena
resolver, and a second owner fork retains the refreshed overlay's exact extent.
Linux authority is [fork(2)](https://man7.org/linux/man-pages/man2/fork.2.html)
and [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html).

`kernel.fork.stage1-image` is the first contract whose structural budget lives
entirely in the VMM layer. Every forked child owns a private stage-1
page-table software image (a 1.75 MiB arena set) for its lifetime; `ltp-fork14`
creates 16k children this way, and allocating a fresh image per fork produced
~28 GiB of host `mmap`/`madvise(MADV_FREE_REUSABLE)` churn. The fixture is
`forkserial <n>`: `n` serial fork/`_exit(0)`/`waitpid` rounds from one parent.

- Linux authority: `man 2 fork`, `man 2 wait4`. Every child exits 0 and each
  `waitpid` returns its own child's pid.
- Structural invariant: `task_admissions` is exactly one per fork, and
  `page_table_image_allocations` (fresh image allocations, counted where the
  parent clones its image for the child) is bounded by the number of
  concurrently live child images, `2 + 0·n`, never by the fork count. Retired
  images return to the process tree's bounded `Stage1ImagePool` and the next
  fork clones into a recycled buffer. `host_mapping_allocations` (fresh host
  `mmap`s for the child's per-mm backing) is `0 + 1·n`: the root tables come
  from the carrier's pre-mapped root-slot pool and only the child's private
  EL1 kernel-state page is still a per-fork host mapping.
  `fork_projection_rows_visited` is `32 + 24·n`: the COW projection scans the
  process's own rows, and rows superseded by earlier COW splits (the parent's
  post-fork stack and data writes) are pruned before the scan, so the work per
  fork never grows with the forks already performed (before the prune the
  fixture visited 15455 rows at 128 forks; after it, 2430).
- Layers: the VM-free binding has no stage-1 projection, so it proves the
  semantics and the admission budget and reports the image metric as an
  exact zero. The signed embed structural binding runs the probe on the
  runtime's own work scope at 1, 8, 32 and 128 forks. The timing binding reads
  the probe's per-fork p50 from an uninstrumented signed run against the
  pinned same-image Docker measurement recorded beside the binding.
- Status (2026-09-20): structural bindings green at 1/8/32/128. The timing
  binding is red: 205 µs per serial fork under the signed carrier versus
  88 µs under Docker (2.33x against the 2.0x policy), and `ltp-fork14` sits at
  3.41x (5.6 s versus 1.6 s; it was 15.4x), `ltp-epoll-ltp` (the same serial
  fork shape: 12,468 clone/exit/wait rounds) at 3.07x from 11.5x, and
  `ltp-fork09` at 1.63x from 3.2x, each measured alone on a quiet host. The root-slot pool is now created at VM
  creation and an exec'd image's root table is drawn from it too, so the
  `sh -c` launch shape every harness LTP row uses no longer pays a 2 MiB host
  `mmap` per fork (the `via_shell` structural binding proves it). Named
  remaining levers: the executor boundary audit issues about five
  `pthread_sigmask` and four `thread_selfusage` host calls per fork, and the
  parent's post-fork COW splits cost about 15% of carrier CPU. The timing
  gate stays red until the ratio meets policy; it is not widened.
- A pre-mapped carrier pool owns its whole IPA range. Once the root-slot pool
  is created at VM creation, every consumer of that arena — a forked child's
  root table, an exec'd image's root table, and a live stage-1 extension
  arena — must take its slot from the pool, and a retiring owner must hand
  the slot back at its retirement proof rather than at its last reference.
  A missed consumer maps private backing over the pre-map, and that
  `HV_ERROR` reaches the guest as a SIGSEGV: CPython's
  `test_compiler_recursion_limit` died that way while Docker passed. The
  `pagetablegrow` probe and the `kernel.fork.stage1-image` bindings are the
  standing guards; `scripts/dtrace/hvpatch-stage1-faults.d` names the exact
  refused mapping when one slips through.
- The next pathology class above the fork family is the guest syscall floor,
  not another algorithm. `ltp-inotify09` issues about 15 million syscalls
  (2.99 million each of `inotify_add_watch`, `inotify_rm_watch`, `lseek`,
  `clock_gettime` and `write`; LTP's fuzzy-sync helpers use raw syscalls, so
  `clock_gettime` never reaches the vDSO) and spends 5.5 microseconds per
  syscall against Docker's 0.69. No per-operation budget is violated there,
  so a contract for that class must budget the syscall round trip itself.

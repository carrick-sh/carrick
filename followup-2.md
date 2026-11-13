# x86 CPL0 host: MM editor contention at a COW/Prepare host crossing is still a carrier fault

Labels: follow-up, x86, kvm, mm

**What happens.** Several x86 host crossings take the MM editor exclusion
with `CowPause::new`, which turns `ExclusionRefusal::Busy` into a fatal
`owner COW editor exclusion refused: Busy`:

- `supply_cow_grant` (the COW supply crossing);
- `settle_cow_grant` (the COW completion crossing);
- the read-only table plan inside `prepare_backing_grant` (the Prepare
  supply crossing).

The guest lane drops its editor before it crosses (`linux_personality.rs`
`supply_user_fault`). A sibling on the other vCPU can take the editor in
that gap. The host then refuses the exclusion and the carrier dies. It is
the same class as #2141, "MM contention is fatal", on the host side of
the crossing.

**Why it is not fixed in #2263.** #2263 is scoped to the two review P0s.
Those cover contention *after* the supply crossing returns, in the guest.
#2263 does add the non-fatal pattern this needs:
`try_excluding_editor` returns `None` on Busy, and the withdrawn-Prepare
path keeps custody until a later crossing. The crossings above still need a
cause-qualified "not now" answer back to the lane. The lane then parks on
the Editor release and reruns, as the native lane does
(`prepare_native_backing_grant` returns a `PortalOwnerWait`).

Acceptance: a two-vCPU KVM witness where a sibling holds the editor across
each crossing. It fails on main with the fatal above, and on the fix it
parks once and completes.

**Live evidence (2026-11-13, #2263 working tree).** A fork child's two threads
COW-faulting concurrently hit the supply crossing's fatal. The child's main
thread made its first post-fork stack push while its cloned worker ran on
the other vCPU. In 5 of 12 runs (`r2-dbg5-*`) the carrier died with
`owner COW editor exclusion refused: Busy`, raised from `supply_cow_grant` for
the child's MM. Two of ten earlier population runs (`r2-green-2`,
`r2-green-6`) failed the same way. This is a `flaky` main defect: the verdict
depends on vCPU interleaving. #2263's raw-exit witness breaks the stack COW
before the clone, so that it tests only its own claim.

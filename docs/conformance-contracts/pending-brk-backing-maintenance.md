# Pending heap retirement backing maintenance (open)

`kernel.mm.pending-brk-backing-maintenance` covers heap shrink and later
regrowth: removed pages must become inaccessible before their physical bytes
are scrubbed, and regrowth must not expose the old bytes. The existing
`brk_shrink_scrubs_backing_before_regrowth` and restrictive-ordering tests
cover the host semantic sequence. An admitted root additionally requires a
typed maintenance operation tied to its exact pending retirement, carrier/MM
incarnation, live descriptor output and retained physical owner. It cannot
select ordinary UserWrite or wait for its own transaction's Gate. Wrong-MM,
stale request/physical generation, reused VA, and fork-shared physical pages
must not authorize a scrub. Selection and cleanup scale with touched backing,
not carrier-wide mappings; no lock spans host I/O or a scheduler wait.

The signed red is `el1_anonymous_reservations_stay_in_guest` on `083a815f7`:
4 KiB heap contraction reaches PREPARE and receives its own Gate wait before
aborting. A VM-free reproduction and its failing assertion are preserved in
the 2026-10-05 backing-maintenance handoff. The typed production binding now
uses `PortalBackingMaintenance` and the existing retained physical grant pool:
EL1 authenticates the pending heap retirement, replaces each backed invalid
leaf with private zero backing, and leaves it invalid until regrowth. The
VM-free witness checks the original Gate red, ordinary user-copy exclusion,
request corruption and VA reuse, a live COW peer, adjacent bytes, and bounded
descriptor work. Signed green remains pending; this contract is not accepted.

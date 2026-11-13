# Follow-up: #1742's `Mm(Stale)` at native-fork Prepare/Publish shape is unreproduced

#1742 originally also recorded `Mm(Stale)` refusals at native-fork `Prepare`/`Publish`
on the old #1733 branch. The current main scoreboard fatal is ForkCustodyRefused only,
which PR "fix(hal): authenticate a paused stopped lane" addresses. If a signed
population shows the Prepare/Publish `Mm(Stale)` shape again, treat it as a separate
EL1 portal identity check: `mm_portal/fork.rs` `prepare_fork`, and `PreparedOwnerFork::publish`
in `carrick-core/src/mm/fork.rs`.

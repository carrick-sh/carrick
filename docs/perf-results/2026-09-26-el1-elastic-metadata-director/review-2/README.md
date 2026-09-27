# Allocator review round 2: real guest path remains incomplete

Candidate dc2b83706 (exact identity in candidate.json), clean when reviewed.
All eight prescribed host checks independently pass; results and raw logs are
in verification/. An unchanged-core screen confirms alignment64 and grant
sizing are corrected (exit0). These close the two earlier narrow findings.

The standalone Linux fixture cross-build exits101 on an undeclared
carrick_el1_abi dependency. This is a compilation failure, not semantic red.

An unchanged HostApertureState screen exits101: a1114112-byte grant occupies
only bitmap slot0; next free slot1 begins at524288, inside that extent. The
screen uses the production grant-size arithmetic and selection/publication
methods without executing any hypervisor calls. Source snapshots and hashes
are retained. Concurrent admission additionally separates selection from
reservation; source review identifies that race, not a reproduced guest race.

Further source findings and required corrections are in review.md: bootstrap
has no initialization caller, only maintenance-root mapping was added, x3 token
is omitted from guest asm and zero accepted by host, ownership/lifetime and
failed return remain incomplete, and failpoint ordering prevents the supposed
growth/recovery fixture from succeeding. No signed candidate was run.

Same worker received review round2 as turn3. One review round remains after
this response. No allocator implementation is integrated or accepted.

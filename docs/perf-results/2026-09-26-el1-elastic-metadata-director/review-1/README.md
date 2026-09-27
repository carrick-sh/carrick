# Allocator review round 1 — acceptance withheld

Candidate: ae6c3a17b (full identity in candidate.json), clean when reviewed.
All eight original prescribed commands independently exit zero; exact commands
and raw logs are in verification/. Two unchanged-core screens still fail with
exit 101: requested pointer alignment64 yields remainder32, and a payload-only
65536-byte grant cannot supply its 65536-byte payload plus block overhead.
These are behavioral reds, not compilation errors. The in-progress source
snapshot was re-extracted from this final candidate before reproduction.

Read review.md for production corrections: actual stage-1 accessible mapping
and owner lifetime, reusable aperture/failed-return handling, installed guest
allocator, Linux syscall preservation, genuine growth/refusal/concurrency
witness, and measured structural bounds. Worker documentation also describes
fields and structures absent from source; its claims are not accepted evidence.

The same el1-elastic-metadata conversation received review round1 as turn2.
No worker implementation is integrated. Director retains signed execution.

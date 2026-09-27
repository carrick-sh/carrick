# Metadata-refusal review 1: rejected

Reviewed worker commit `32b0ad50f`. All five prescribed host verification
commands pass independently (results.json and 0..4.log). No integration of
this worker implementation is accepted.

A temporary director regression test using the real allocation-refusal
wrapper proves that try_coalesce ignores the failed parent write and still
frees the linked child. Translation changes from Some(412318957568) to None,
while coalesced=true. Cargo exits 101 on the semantic assertion. The precise
test-only diff and raw output are retained; the worker checkout was restored
to its committed source before review round 1 was dispatched.

findings.md also records missing live/refusal and adapter bindings, allocating
error lowering, admission growth and red-evidence provenance gaps. The same
worker is correcting these on turn 2, review round 1 of the three-round cap.

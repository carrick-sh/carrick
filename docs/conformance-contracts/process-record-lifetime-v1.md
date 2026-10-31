# process-record-lifetime-v1

Surface: shared process-record lookup for PID namespace translation, child
wait/ptrace classification and `/proc` run-state rendering. An owned read must
contain fields from one published process generation; release or same-PID slot
reuse during the read returns typed `Stale` (mapped to absence by lookup APIs).
This is the arena binding of the existing exact-task identity rule, rather than
a promise of transactional snapshots of ordinary metadata changes within one
live generation.

Retirement invalidates the state and generation, then fences before clearing
body fields. Readers acquire publication, copy owned values, fence, and validate
both generation and published identity after their last body load. Borrowed
record references cannot escape the higher-ranked read callback. Mutation paths
that can act on foreign records hold the existing record transition claim and
revalidate identity before reading and acting.

VM-free bindings: `prefork_registration::observation_cannot_mix_publication_with_reap`,
`observation_rejects_reuse_even_with_the_same_host_pid`,
`observation_rejects_release_in_another_host_process`,
`namespace::pid::tests::member_read_rejects_release_between_identity_and_parent`,
`run_state::tests::published_rejects_reuse_after_identity_read`, and
`guest_cpu::tests::child_read_rejects_reuse_after_identity_read`.
The fill-hook fork test separately proves incomplete initialization stays hidden.
The storm retains 200 children per run and immediate record reuse.

Structural budget: one callback invocation and one trailing validation per
published slot, zero retries; scans visit at most `PROCESS_RECORDS` slots.
There is no observer lock, cross-record serialization, deadline or sleep.
These bindings use real shared arena memory and host fork where applicable,
without guest execution. Signed guest composition and Docker timing are not
claimed by this VM-free lane and remain the director's batch acceptance work.

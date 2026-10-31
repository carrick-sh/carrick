# Carrier birth source prerequisite

The birth-identity prerequisite of `kernel.el1.signal-delivery-owner`,
`kernel.el1.thread-lifecycle`, `core.lifecycle.publication` and
`process.native.arm-admission` also has VM-free word bindings in
`carrick-sched-core`: `zero_valid_issuer_burns_unpublished_births_and_never_wraps`,
`issuer_imports_reserved_births_idempotently_including_terminal_value`,
`shared_issuer_reserves_before_publication`,
`shared_issuer_concurrent_borrowers_have_one_complete_population`, and
`zone_birth_issuer_is_shared_by_borrows_and_isolated_between_carriers`.
One checked atomic RMW issues a birth, with contention-dependent retries;
rollback never returns a serial. The negative control
`late_observation_cannot_repair_independently_issued_tickets` proves that
post-allocation cursor advancement cannot merge independent live sources.
Production source bindings additionally exercise the actual host registry and
native fork paths: `process_receiver_survives_internal_task_id_reuse`,
`process_receiver_reserved_before_admission_and_native_unpublished_before_host_supply`,
`carrier_births_cover_reserved_unpublished_replenished_and_two_roots`,
`initial_birth_handoff_captures_burned_values_and_refuses_live_join`, and
`shared_birth_transfer_revokes_only_old_handle_and_partial_exhaustion_burns`.
The two-root native fork witness checks distinct carrier births. Full boot
export controls cover exclusive and shared sources; physical source controls
cover retained bytes with revoked custody and independent generation-one owners.
Host issuance costs also include its registry read lock and the backend custody
mutex or revocation read guard. Signed, cross-host and final runtime acceptance
remain required. See [the integration handoff](../design/carrier-birth-issuer-handoff.md).

# Anonymous editor publication during a host pause

The `kernel.el1.anonymous-permissions`, `kernel.el1.anonymous-munmap`
and `kernel.el1.anonymous-reservations` policies retain the exact-MM
`SpaceEditor` until descriptor mutation, local invalidation and publication
have completed. A host pause can raise the admission gate while waiting for
that editor. The admitted operation must publish through its existing guard;
requesting a fresh open-gate grant after mutation can turn contention into a
fatal binding error.

`admitted_mprotect_publishes_through_pause_then_next_edit_succeeds` drives
the production policy, raises the gate inside the admitted descriptor step,
and requires one publication before editor release and another successful
edit after the pause lowers. It was red at publication 0 versus expected 1.
Publication is one atomic increment per successful descriptor operation,
including the full-journal handback, with no new wait or retry.

The hardware editor still completes its local invalidation before policy
publication. Publication deliberately does not acknowledge slot coverage;
the next entry must consume the published generation through the existing
per-vCPU invalidation protocol. This conservative extra invalidation does
not establish synchronous completion on an already-running sibling vCPU.
That P1 review finding remains open, as does signed verification of the
changed head. The earlier signed population evidence belongs to its original
artifact and does not establish a result for this change.

`slot_cow_coverage_survives_rebinding_and_rejects_retired_asid_identity`
drives `ZoneTables::cover_cow` on two slots, resetting and rebinding a slot
to a replacement vCPU, switching that slot through a
second live MM, then retiring the first MM and publishing a new MM with the
same numeric root/ASID and publication generation. Coverage must remain
local to both the slot and MM identity. This is a scheduler lifecycle witness,
not proof of hardware ASID-retirement completion.

A successful `reset_slot` clears local coverage together with the timer
cache because a new mailbox lease can name a different vCPU. The reset
witness was red (`None` instead of `Some(1)` owed) before clearing these
fields. A refused reset preserves the still-owned slot.

# EL1 clock transport phase discovery (`kernel.el1.gic`)

Kick normalization must classify the clock handler without publishing code or
requiring a scratch page. `mailbox_clock_layout_matches_every_emitted_variant`
was red on the signal stack: metadata discovery invoked the guarded installer
on zero-filled storage and panicked at vector offset `0xc20`. Layout discovery
now runs the same emitter without a byte sink; real installation retains its
NOP-only overwrite guard. The VM-free binding compares start, completion and
end across both fd-ceiling settings, EL1 settings and IRQ modes, and checks
handler classification boundaries. Emission and guest instruction placement
are unchanged. The signed EL1 suite remains the integration acceptance gate.

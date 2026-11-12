# Follow-up: scrub the tables of a built-but-refused x86 successor (slice d)

From #2190 (#1093 S4c slice b).

`X86PrepareCross` runs the successor build before the consuming crossing
and refuses `Stale` when the built root is not the sealed one. At that
point the editor has written descriptors into reserved stock tables. The
VM-free witness shows the refusal precedes the crossing and the dropped
slot frees the space. Nothing yet scrubs or quarantines the edited stock
tables before they return through `ForkStock::return_successor_tables`.

Acceptance: the cancel crossing (slice d) scrubs the edited tables, or
quarantines them as fork does (`abandon_loan`), before they re-enter the
stock. Witness it with a dirty-table check, as fork stock settlement does
with `tables_are_zero`.

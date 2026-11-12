# Follow-up: where an x86 exec successor's data frames live (slice c)

From #2190 (#1093 S4c slice b).

`carrick_x86_carrier::initial_boot::build_x86_successor` runs the editor
over reserved stock tables. They need no new alias: they sit inside the
admitted `TABLE_START..TABLE_END` span that `InitialWords` already licenses.
The editor also writes the data frames (`InitialFrameSource::copy_guest_data`
and `write_data`). Boot reaches its data frames through the initial extent's
supervisor alias (`extent_va`). The design does not yet say which CPL0 alias
an exec successor's data frames, staged file bytes and strings use.

The options are a reserved suffix of the initial extent, staged through the
same `InitialInventory::stage` (it already takes any frame list, see
`successor_inventory_stages_stock_tables_and_data_frames_in_runs`), or a new
retained alias. Slice c (the host Exec service) must settle this before it
can supply a production `X86SuccessorBuild`.

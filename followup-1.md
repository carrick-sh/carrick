# Follow-up: an ARM caller for the shared successor image validator

From #2190 (#1093 S4c slice b).

`carrick_core_abi::successor_image::validate_image_rows` is ISA-neutral (the
geometry is a parameter), but only x86 calls it today, through
`install_initial_image`. ARM's exec successor image is built on the host by
HVF (`carrick-vmm-hvf/src/trap/execve_rebuild.rs::prepare_native_exec_successor`
from a `GuestMappingPlan`), and there is no row list to validate on the guest
side.

Acceptance: add an AArch64 `ImageGeometry` and validate ARM's successor rows
(the plan's mappings and `lazy_regions`) with the same function before
staging. Then refuse a malformed or overlapping ARM image with the same
typed error the x86 witness pins. This needs a Mac (`cargo test -p
carrick-vmm-hvf --lib`).

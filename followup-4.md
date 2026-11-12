# Follow-up: retire the host ELF prep's own overlap check

From #2190 (#1093 S4c slice b).

`carrick-mem/src/x86_initial_image.rs::prepare_x86_elf` still checks region
alignment, the user half and overlap itself, before the rows reach the
shared `validate_image_rows` in the guest editor. `carrick-mem` does not
depend on `carrick-core-abi`. Either add the dependency and call the shared
validator from host staging (`load_guest_mm`, and the slice c Exec
service), or keep the host check as an early refusal and record why. Two
copies of one rule drift.

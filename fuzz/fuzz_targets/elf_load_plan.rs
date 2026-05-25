#![no_main]

use carrick_runtime::elf::{inspect_elf_bytes, plan_elf_load_bytes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = inspect_elf_bytes(data);
    let _ = plan_elf_load_bytes(data);
});

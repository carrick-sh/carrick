fn main() {
    // Assemble the DSR gateway trampoline. Needed only for an x86_64 host
    // (the only place translated x86 execution runs); elsewhere the crate
    // uses the fail-closed `enter_translated` stub and links no asm.
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_arch == "x86_64" {
        println!("cargo:rerun-if-changed=src/gateway_x86_64.S");
        cc::Build::new()
            .file("src/gateway_x86_64.S")
            .compile("carrick_dsr_x86_gateway");
    }
}

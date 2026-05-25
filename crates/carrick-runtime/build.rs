fn main() {
    // Compile the C shim that performs the ABI-correct
    // hv_vcpu_set_simd_fp_reg call (see csrc/carrick_shim.c). Only needed on
    // the macOS/aarch64 HVF path; elsewhere it's a no-op.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        println!("cargo:rerun-if-changed=csrc/carrick_shim.c");
        cc::Build::new()
            .file("csrc/carrick_shim.c")
            .compile("carrick_shim");
    }
}

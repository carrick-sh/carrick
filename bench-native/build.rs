fn main() {
    println!("cargo:rerun-if-changed=native_exec_probe/ucontext_arm64.c");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os == "macos" && target_arch == "aarch64" {
        cc::Build::new()
            .file("native_exec_probe/ucontext_arm64.c")
            .warnings(true)
            .compile("native_exec_probe_ucontext");
    }
}

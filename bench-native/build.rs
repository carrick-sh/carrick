fn main() {
    cc::Build::new()
        .file("native_exec_probe/ucontext_arm64.c")
        .warnings(true)
        .compile("native_exec_probe_ucontext");
}

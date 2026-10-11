fn main() {
    if std::env::var("TARGET").is_ok_and(|target| target == "x86_64-unknown-none") {
        let directory = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        println!("cargo:rustc-link-arg=-T{directory}/link.ld");
        println!("cargo:rustc-link-arg=-no-pie");
    }
    println!("cargo:rerun-if-changed=link.ld");
}

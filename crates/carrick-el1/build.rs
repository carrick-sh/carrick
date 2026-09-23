fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("none") {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        println!("cargo:rustc-link-arg=-T{manifest_dir}/link.ld");
    }
    println!("cargo:rerun-if-changed=link.ld");
}

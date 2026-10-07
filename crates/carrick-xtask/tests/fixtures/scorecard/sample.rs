//! Sample module for scorecard testing

// Single line comment
   // Indented comment
pub fn test_fn() -> usize {
    let a = 1; // inline comment
    /* block comment */ let b = 2;
    let c = 3; /* inline block */
    /*
     * multi-line
     * block /* nested */ comment
     */
    let s = "// not a comment /* still code */";
    let raw = r#"
// comment syntax inside raw string
/* block syntax inside raw string */
"#;
    #[cfg(target_arch = "aarch64")]
    let x = 10;
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    let y = 20;
    #[cfg_attr(target_arch = "x86_64", inline(always))]
    let z = if cfg!(target_arch = "aarch64") { 1 } else { 2 };
    // #[cfg(target_arch = "aarch64")] commented out cfg
    a + b + c + s.len() + raw.len() + x + y + z
}

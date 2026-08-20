use host_authority_escape_syntax::{Finding, scan_source};

fn shapes(source: &str) -> Vec<(&'static str, String)> {
    scan_source(source)
        .expect("fixture must tokenize")
        .into_iter()
        .map(|finding| (finding.kind.as_str(), finding.detail))
        .collect()
}

#[test]
fn recursively_finds_macro_body_escape_paths_and_assembly() {
    let findings = shapes(
        r#"
macro_rules! outer {
    () => {{
        macro_rules! inner {
            () => {{
                unsafe { libc::syscall(1); }
                core::arch::asm!("nop");
                global_asm!(".text");
            }};
        }
    }};
}

"#,
    );
    assert_eq!(
        findings,
        vec![
            ("libc_syscall", "libc::syscall".into()),
            ("assembly", "core::arch::asm!".into()),
            ("assembly", "global_asm!".into()),
        ]
    );
}

#[test]
fn unterminated_use_fragment_cannot_mask_later_macro_tokens() {
    let findings = shapes(
        r#"
macro_rules! unexpanded_tokens {
    () => {{ use ignored libc::syscall(1) }};
}
"#,
    );
    assert_eq!(findings, vec![("libc_syscall", "libc::syscall".into())]);
}

#[test]
fn finds_direct_grouped_leading_and_aliased_watched_imports() {
    let findings = shapes(
        r#"
use ::libc::syscall as raw_syscall;
pub use libc::{dlopen as load, dlsym};
use core::arch::{asm as carrier_asm, global_asm};
"#,
    );
    assert_eq!(
        findings,
        vec![
            ("libc_syscall", "use ::libc::syscall".into()),
            ("libc_dlopen", "use libc::dlopen".into()),
            ("libc_dlsym", "use libc::dlsym".into()),
            ("assembly", "use core::arch::asm".into()),
            ("assembly", "use core::arch::global_asm".into()),
        ]
    );
}

#[test]
fn finds_default_named_unwind_and_link_name_externs_in_groups() {
    let findings = shapes(
        r#"
unsafe extern { fn waitpid(pid: i32) -> i32; }
unsafe extern "C" { #[link_name = "kill"] fn carrier_signal(pid: i32); }
macro_rules! declare {
    () => { unsafe extern "C-unwind" { fn open(path: *const i8) -> i32; } };
}
"#,
    );
    assert_eq!(
        findings,
        vec![
            ("extern", "extern fn waitpid".into()),
            ("extern", "link_name kill".into()),
            ("extern", "extern fn open".into()),
        ]
    );
}

#[test]
fn comments_literals_labels_lifetimes_and_traits_are_atomic_or_safe() {
    let findings = shapes(
        r###"
// libc::syscall(1); unsafe extern "C" { fn waitpid(); }
/* core::arch::asm!("nop"); */
const NORMAL: &str = "libc::dlsym(0, 0)";
const RAW: &str = r##"global_asm!(".text")"##;
const BYTES: &[u8] = br#"#[link_name = "kill"]"#;
const C: &core::ffi::CStr = c"extern { fn open(); }";
fn labelled<'asm>(value: &'asm str) {
    'libc: loop { break 'libc; }
    let _ = ('x', b'x', value);
}
trait Safe { fn waitpid(&self, pid: i32) -> i32; }
macro_rules! docs { () => {{ "libc::syscall(1)" }}; }
"###,
    );
    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
}

#[test]
fn finding_renderers_are_deterministic() {
    let finding = Finding {
        kind: host_authority_escape_syntax::FindingKind::LibcSyscall,
        line: 7,
        column: 3,
        detail: "libc::syscall".into(),
    };
    assert_eq!(
        finding.render_json("crates/example/src/lib.rs"),
        r#"{"path":"crates/example/src/lib.rs","line":7,"column":3,"kind":"libc_syscall","detail":"libc::syscall"}"#
    );
    assert_eq!(
        finding.render_text("crates/example/src/lib.rs"),
        "crates/example/src/lib.rs:7:3: libc_syscall: libc::syscall"
    );
}

use host_authority_escape_syntax::{
    CarrierProcessFindingKind, Finding, scan_carrier_process_source, scan_source,
};

fn shapes(source: &str) -> Vec<(&'static str, String)> {
    scan_source(source)
        .expect("fixture must tokenize")
        .into_iter()
        .map(|finding| (finding.kind.as_str(), finding.detail))
        .collect()
}

#[test]
fn carrier_process_scan_resolves_aliases_and_skips_cfg_test_items() {
    let source = r#"
use libc::fork as birth;
use std::process::Command as HostCommand;

fn production() {
    let _ = unsafe { birth() };
    let _ = HostCommand::new("helper");
    let _ = unsafe { libc::kill(7, 0) };
}

#[cfg(test)]
mod tests {
    fn fixture() {
        let _ = unsafe { libc::fork() };
        let _ = std::process::Command::new("fixture");
    }
}
"#;
    let findings = scan_carrier_process_source(source).unwrap();
    let kinds: Vec<_> = findings.iter().map(|finding| finding.kind).collect();
    assert_eq!(
        kinds,
        vec![
            CarrierProcessFindingKind::Fork,
            CarrierProcessFindingKind::ProcessCommand,
            CarrierProcessFindingKind::KillProbe,
        ]
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.enclosing_item == "production")
    );
}

#[test]
fn carrier_process_scan_finds_all_direct_process_boundaries() {
    let source = r#"
fn production() {
    unsafe {
        libc::vfork();
        libc::posix_spawn(0 as _, 0 as _, 0 as _, 0 as _, 0 as _, 0 as _);
        libc::kill(1, 9);
        libc::killpg(1, 9);
        libc::waitpid(1, 0 as _, 0);
        libc::wait4(1, 0 as _, 0, 0 as _);
        libc::waitid(0, 0, 0 as _, 0);
        libc::setpgid(0, 0);
        libc::setsid();
    }
}
"#;
    let findings = scan_carrier_process_source(source).unwrap();
    let kinds: Vec<_> = findings.iter().map(|finding| finding.kind).collect();
    assert_eq!(
        kinds,
        vec![
            CarrierProcessFindingKind::Vfork,
            CarrierProcessFindingKind::PosixSpawn,
            CarrierProcessFindingKind::Kill,
            CarrierProcessFindingKind::Killpg,
            CarrierProcessFindingKind::Waitpid,
            CarrierProcessFindingKind::Wait4,
            CarrierProcessFindingKind::Waitid,
            CarrierProcessFindingKind::Setpgid,
            CarrierProcessFindingKind::Setsid,
        ]
    );
}

#[test]
fn carrier_process_scan_does_not_hide_mixed_cfg_or_macro_bodies() {
    let source = r#"
#[cfg(any(test, feature = "product"))]
fn mixed_configuration_is_product() {
    unsafe { libc::fork(); }
}

macro_rules! product_birth {
    () => {{ unsafe { libc::vfork() } }};
}

#[cfg(all(unix, test))]
fn provably_test_only() {
    unsafe { libc::posix_spawn(0 as _, 0 as _, 0 as _, 0 as _, 0 as _, 0 as _); }
}

mod tests {
    fn a_name_is_not_a_cfg() {
        unsafe { libc::killpg(1, 9); }
    }
}
"#;
    let findings = scan_carrier_process_source(source).unwrap();
    let kinds: Vec<_> = findings.iter().map(|finding| finding.kind).collect();
    assert_eq!(
        kinds,
        vec![
            CarrierProcessFindingKind::Fork,
            CarrierProcessFindingKind::Vfork,
            CarrierProcessFindingKind::Killpg,
        ]
    );
}

#[test]
fn carrier_process_scan_omits_cfg_test_statement_blocks_inside_macros() {
    let source = r#"
macro_rules! syscall_table {
    () => {{
        #[cfg(not(test))]
        return 0;
        #[cfg(test)]
        {
            unsafe { libc::wait4(1, 0 as _, 0, 0 as _); }
        }
    }};
}
"#;
    let findings = scan_carrier_process_source(source).unwrap();
    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
}

#[test]
fn carrier_process_scan_omits_cfg_test_impl_macro_bodies() {
    let source = r#"
#[cfg(test)]
impl Dispatcher {
    define_syscall! {
        fn legacy_wait() {
            unsafe { libc::wait4(7, core::ptr::null_mut(), 0, core::ptr::null_mut()); }
        }
    }
}
"#;
    let findings = scan_carrier_process_source(source).unwrap();
    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
}

#[test]
fn carrier_process_scan_resolves_imports_declared_after_the_call_site() {
    let source = r#"
fn production() {
    let _ = unsafe { late_birth() };
    let _ = LateCommand::new("helper");
}

use libc::fork as late_birth;
use std::process::Command as LateCommand;
"#;
    let findings = scan_carrier_process_source(source).unwrap();
    let kinds: Vec<_> = findings.iter().map(|finding| finding.kind).collect();
    assert_eq!(
        kinds,
        vec![
            CarrierProcessFindingKind::Fork,
            CarrierProcessFindingKind::ProcessCommand,
        ]
    );
}

#[test]
fn carrier_process_scan_descends_into_impl_item_macro_bodies() {
    let source = r#"
impl Dispatcher {
    define_syscall! {
        fn legacy_wait() {
            unsafe { libc::wait4(7, core::ptr::null_mut(), 0, core::ptr::null_mut()); }
        }
    }
}
"#;
    let findings = scan_carrier_process_source(source).unwrap();
    assert_eq!(findings.len(), 1, "unexpected findings: {findings:?}");
    assert_eq!(findings[0].kind, CarrierProcessFindingKind::Wait4);
}

#[test]
fn carrier_process_scan_resolves_aliases_inside_impl_item_macros() {
    let source = r#"
use libc as host;
use std::process as process_alias;
impl Dispatcher {
    define_syscall! {
        fn legacy_wait() {
            unsafe { host::wait4(7, core::ptr::null_mut(), 0, core::ptr::null_mut()); }
            let _ = process_alias::Command::new("helper");
        }
    }
}
"#;
    let findings = scan_carrier_process_source(source).unwrap();
    let kinds: Vec<_> = findings.iter().map(|finding| finding.kind).collect();
    assert_eq!(
        kinds,
        vec![
            CarrierProcessFindingKind::ProcessCommand,
            CarrierProcessFindingKind::Wait4,
        ]
    );
}

#[test]
fn carrier_process_scan_resolves_grouped_and_extern_crate_namespaces() {
    let source = r#"
extern crate libc as raw_host;
use libc::{self as grouped_host};
use std::process::{self as grouped_process};

fn production() {
    unsafe {
        raw_host::forkx_np(0);
        raw_host::fexecve(3, core::ptr::null(), core::ptr::null());
        grouped_host::wait3(core::ptr::null_mut(), 0, core::ptr::null_mut());
    }
    let _ = grouped_process::Command::new("helper");
}
"#;
    let findings = scan_carrier_process_source(source).unwrap();
    let kinds: Vec<_> = findings.iter().map(|finding| finding.kind).collect();
    assert_eq!(
        kinds,
        vec![
            CarrierProcessFindingKind::Fork,
            CarrierProcessFindingKind::ProcessCommand,
            CarrierProcessFindingKind::Exec,
            CarrierProcessFindingKind::Wait,
        ]
    );
}

#[test]
fn carrier_process_scan_omits_current_cfg_test_dispatch_proc_host_control() {
    let source = include_str!("../../../../crates/carrick-runtime/src/dispatch/proc.rs");
    let findings = scan_carrier_process_source(source).unwrap();
    assert!(
        findings.is_empty(),
        "all remaining host wait/ptrace compatibility is cfg(test): {findings:?}"
    );
}

#[test]
fn carrier_process_scan_resolves_namespace_glob_and_type_aliases() {
    let source = r#"
use libc as host;
use libc::*;
use std::process as process_alias;
use std::process::*;
type HostCommand = std::process::Command;

fn production() {
    unsafe { host::fork(); }
    unsafe { vfork(); }
    let _ = process_alias::Command::new("one");
    let _ = Command::new("two");
    let _ = HostCommand::new("three");
}
"#;
    let findings = scan_carrier_process_source(source).unwrap();
    let kinds: Vec<_> = findings.iter().map(|finding| finding.kind).collect();
    assert_eq!(
        kinds,
        vec![
            CarrierProcessFindingKind::Fork,
            CarrierProcessFindingKind::Vfork,
            CarrierProcessFindingKind::ProcessCommand,
            CarrierProcessFindingKind::ProcessCommand,
            CarrierProcessFindingKind::ProcessCommand,
        ]
    );
}

#[test]
fn carrier_process_scan_finds_extern_link_names_and_extended_process_apis() {
    let source = r#"
unsafe extern "C" {
    #[link_name = "fork"]
    fn hidden_birth() -> i32;
}

fn production() {
    unsafe {
        libc::clone(core::ptr::null_mut(), core::ptr::null_mut(), 0, core::ptr::null_mut());
        libc::forkpty(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut());
        libc::system(core::ptr::null());
        libc::popen(core::ptr::null(), core::ptr::null());
        libc::daemon(0, 0);
        libc::execve(core::ptr::null(), core::ptr::null(), core::ptr::null());
        libc::wait(core::ptr::null_mut());
        libc::ptrace(0, 0, core::ptr::null_mut(), 0);
        libc::pthread_kill(core::mem::zeroed(), 1);
        carrick_portable::ptrace(0, 7, 0, 0);
    }
}
"#;
    let findings = scan_carrier_process_source(source).unwrap();
    let kinds: Vec<_> = findings.iter().map(|finding| finding.kind).collect();
    assert_eq!(
        kinds,
        vec![
            CarrierProcessFindingKind::Fork,
            CarrierProcessFindingKind::Clone,
            CarrierProcessFindingKind::Forkpty,
            CarrierProcessFindingKind::System,
            CarrierProcessFindingKind::Popen,
            CarrierProcessFindingKind::Daemon,
            CarrierProcessFindingKind::Exec,
            CarrierProcessFindingKind::PthreadKill,
            CarrierProcessFindingKind::Wait,
            CarrierProcessFindingKind::Ptrace,
            CarrierProcessFindingKind::Ptrace,
        ]
    );
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

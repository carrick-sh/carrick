//! carrick-capture's witnesses: the script rules over `scripts/`, the
//! argument allowlist, the installed-script checks and the exec shape, plus
//! the built binary refusing every other argument shape.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use carrick_capture::{
    BPFTRACE, DEFAULT_SECONDS, GRACE_SECONDS, MAX_SECONDS, PathMode, REFUSAL, REFUSED_SHAPE,
    Request, SCRIPTS, Script, TIMEOUT, command, parse, verify_directory_chain, verify_installed,
};
use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

// ---- Script rules ---------------------------------------------------------
//
// A capture script runs as root, so it may only print the tracepoint record
// and the current task's identity. The rules are an allowlist, not a list of
// bad functions: anything not named here is refused.
//
// - Probes: `BEGIN`, `END`, `tracepoint:<category>:<name>` and
//   `interval:s:<n>` only. No kprobe/kfunc/uprobe/usdt/rawtracepoint, no
//   wildcards, no `config`, `import`, `fn` or `#include`.
// - Functions: `printf`, `time`, `exit` and `clear`. So no `cat()`,
//   `system()`, `str()`, `buf()`, `kptr()`, `uptr()`, `signal()`,
//   `override()` or stack walks.
// - Values: the builtins below, maps, `$1` (the capture length) and
//   `args->FIELD`/`args.FIELD` one level deep. No `curtask`, no casts, no
//   `*` dereference and no `[]` indexing, so no pointer is ever followed.
// - Each script bounds itself: an `interval:s:1` probe and `exit()` keyed on
//   `$1`.

const PROBES_WITHOUT_ARGS: &[&str] = &["BEGIN", "END"];
const FUNCTIONS: &[&str] = &["printf", "time", "exit", "clear"];
const KEYWORDS: &[&str] = &["if", "else"];
const BUILTINS: &[&str] = &[
    "pid", "tid", "comm", "uid", "gid", "nsecs", "elapsed", "cpu", "args",
];
/// Characters with no allowed use outside strings and comments.
const FORBIDDEN_CHARS: &[char] = &['#', '*', '[', ']', '\\', '`', '\''];

/// Replace comments with a space and each string literal with `"`.
fn code_of(source: &str) -> Result<String, String> {
    let mut code = String::new();
    let mut chars = source.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'/') => {
                while chars.peek().is_some_and(|&next| next != '\n') {
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut previous = ' ';
                loop {
                    match chars.next() {
                        None => return Err("unterminated comment".into()),
                        Some('/') if previous == '*' => break,
                        Some(next) => previous = next,
                    }
                }
                code.push(' ');
            }
            '"' => {
                loop {
                    match chars.next() {
                        None | Some('\n') => return Err("unterminated string".into()),
                        Some('\\') => {
                            chars.next();
                        }
                        Some('"') => break,
                        Some(_) => {}
                    }
                }
                code.push('"');
            }
            _ => code.push(c),
        }
    }
    Ok(code)
}

#[derive(Debug, PartialEq)]
enum Token {
    Ident(String),
    Number,
    Positional(String),
    Map,
    Str,
    Arrow,
    Dot,
    Open,
    Other(char),
}

fn tokens(code: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let word = |start: usize| {
        let mut end = start;
        while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
            end += 1;
        }
        (chars[start..end].iter().collect::<String>(), end)
    };
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if FORBIDDEN_CHARS.contains(&c) {
            return Err(format!("`{c}` is not allowed"));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let (text, end) = word(i);
            out.push(Token::Ident(text));
            i = end;
        } else if c.is_ascii_digit() {
            let (text, end) = word(i);
            if !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("`{text}` is not a plain decimal number"));
            }
            out.push(Token::Number);
            i = end;
        } else if c == '$' || c == '@' {
            let (text, end) = word(i + 1);
            if text.is_empty() {
                return Err(format!("bare `{c}`"));
            }
            out.push(if c == '$' {
                Token::Positional(text)
            } else {
                Token::Map
            });
            i = end;
        } else if c == '-' && chars.get(i + 1) == Some(&'>') {
            out.push(Token::Arrow);
            i += 2;
        } else {
            out.push(match c {
                '"' => Token::Str,
                '.' => Token::Dot,
                '(' => Token::Open,
                other => Token::Other(other),
            });
            i += 1;
        }
    }
    Ok(out)
}

/// The rules for a predicate or an action block.
fn check_expression(code: &str) -> Result<(), String> {
    let tokens = tokens(code)?;
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            Token::Ident(name) if name == "args" => {
                let field = matches!(tokens.get(i + 1), Some(Token::Arrow | Token::Dot))
                    && matches!(tokens.get(i + 2), Some(Token::Ident(_)))
                    && !matches!(
                        tokens.get(i + 3),
                        Some(Token::Arrow | Token::Dot | Token::Open)
                    );
                if !field {
                    return Err("`args` is only read as `args->FIELD`, one level deep".into());
                }
                i += 3;
                continue;
            }
            Token::Ident(name) => {
                let call = tokens.get(i + 1) == Some(&Token::Open);
                let allowed = if call {
                    FUNCTIONS.contains(&name.as_str()) || KEYWORDS.contains(&name.as_str())
                } else {
                    BUILTINS.contains(&name.as_str()) || KEYWORDS.contains(&name.as_str())
                };
                if !allowed {
                    return Err(format!(
                        "`{name}`{} is not allowed",
                        if call { "()" } else { "" }
                    ));
                }
            }
            Token::Positional(name) if name != "1" => {
                return Err(format!("`${name}`: only `$1` (the capture length) exists"));
            }
            Token::Arrow | Token::Dot => {
                return Err("member access outside `args->FIELD`".into());
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

fn attach_point_allowed(point: &str) -> bool {
    let name = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    if PROBES_WITHOUT_ARGS.contains(&point) {
        return true;
    }
    match point.split(':').collect::<Vec<_>>().as_slice() {
        ["tracepoint", category, event] => name(category) && name(event),
        ["interval", "s", count] => !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit()),
        _ => false,
    }
}

/// Every top-level item is `attach[, attach...] [/predicate/] { actions }`.
fn check_script(source: &str) -> Result<(), String> {
    let code = code_of(source)?;
    let (mut depth, mut header, mut body) = (0usize, String::new(), String::new());
    let mut bounded = false;
    for c in code.chars() {
        match (c, depth) {
            ('{', 0) => {
                let (attach, predicate) = match (header.find('/'), header.rfind('/')) {
                    (Some(first), Some(last)) if first < last => {
                        if !header[last + 1..].trim().is_empty() {
                            return Err("text between the predicate and the block".into());
                        }
                        (&header[..first], Some(&header[first + 1..last]))
                    }
                    (None, None) => (header.as_str(), None),
                    _ => return Err("unbalanced predicate".into()),
                };
                let points: Vec<&str> = attach.split(',').map(str::trim).collect();
                for point in &points {
                    if !attach_point_allowed(point) {
                        return Err(format!("probe `{point}` is not allowed"));
                    }
                }
                bounded |= points.contains(&"interval:s:1");
                if let Some(predicate) = predicate {
                    check_expression(predicate)?;
                }
                header.clear();
                depth = 1;
            }
            ('}', 0) => return Err("unbalanced `}`".into()),
            ('{', _) => {
                body.push(c);
                depth += 1;
            }
            ('}', 1) => {
                check_expression(&body)?;
                body.clear();
                depth = 0;
            }
            ('}', _) => {
                body.push(c);
                depth -= 1;
            }
            (_, 0) => header.push(c),
            (_, _) => body.push(c),
        }
    }
    if depth != 0 || !header.trim().is_empty() {
        return Err("text outside a probe block".into());
    }
    if !bounded || !code.contains("$1") || !code.contains("exit") {
        return Err("no `interval:s:1` probe that exits after `$1` ticks".into());
    }
    Ok(())
}

const BOUND: &str = "interval:s:1 { @s = @s + 1; if (@s >= $1) { exit(); } }";

#[test]
fn script_directory_is_exactly_the_allowlist_and_every_script_passes_the_rules() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts");
    let mut found: Vec<String> = std::fs::read_dir(&dir)
        .expect("scripts directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("name")
        })
        .collect();
    found.sort();
    let mut listed: Vec<String> = SCRIPTS
        .iter()
        .map(|script| format!("{}.bt", script.name))
        .collect();
    listed.sort();
    assert_eq!(
        found, listed,
        "scripts/ and SCRIPTS must name the same files"
    );
    for script in SCRIPTS {
        assert!(
            script
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "{}",
            script.name
        );
        let on_disk =
            std::fs::read_to_string(dir.join(format!("{}.bt", script.name))).expect("script file");
        assert_eq!(on_disk, script.source);
        check_script(script.source).unwrap_or_else(|reason| {
            panic!("{}.bt breaks the script rules: {reason}", script.name)
        });
    }
}

#[test]
fn script_rules_refuse_reads_beyond_the_record_and_unbounded_scripts() {
    // The control passes: the same bound plus a record-only probe.
    let control = "tracepoint:signal:signal_generate /args->sig == 9 && args.pid != 1/ { time(\"%H \"); printf(\"%d %s %d\\n\", pid, comm, args->pid); }";
    check_script(&format!("{BOUND}\n{control}")).expect("control script");
    // Comments and strings are inert: neither can smuggle code past the rules.
    check_script(&format!(
        "// cat(\"/etc/shadow\") kprobe:x\n/* system(\"id\") */\n{BOUND}\nBEGIN {{ printf(\"str(arg0) *p #include\\\"\\n\"); }}"
    ))
    .expect("comments and strings");
    for bad in [
        // Arbitrary file and command access.
        "BEGIN { printf(\"%s\", cat(\"/etc/shadow\")); }",
        "BEGIN { system(\"id\"); }",
        // User and kernel memory reads.
        "tracepoint:syscalls:sys_enter_openat { printf(\"%s\", str(args->filename)); }",
        "tracepoint:syscalls:sys_enter_write { printf(\"%r\", buf(args->buf, 64)); }",
        "tracepoint:signal:signal_generate { printf(\"%d\", kptr(args->pid)); }",
        "tracepoint:signal:signal_generate { printf(\"%d\", uptr(args->pid)); }",
        "tracepoint:signal:signal_generate { printf(\"%d\", curtask->mm); }",
        "tracepoint:signal:signal_generate { printf(\"%d\", args->task->pid); }",
        "tracepoint:signal:signal_generate { printf(\"%d\", args.task.pid); }",
        "tracepoint:signal:signal_generate { printf(\"%c\", args->comm[0]); }",
        "BEGIN { printf(\"%d\", *(uint64 *)0xffffffff81000000); }",
        "BEGIN { printf(\"%s\", ((struct task_struct *)0)->comm); }",
        "tracepoint:signal:signal_generate { printf(\"%s\", kstack); }",
        "tracepoint:signal:signal_generate { printf(\"%s\", ustack); }",
        "BEGIN { printf(\"%d\", arg0); }",
        "BEGIN { printf(\"%d\", reg(\"ip\")); }",
        // Side effects.
        "BEGIN { signal(9); }",
        "tracepoint:signal:signal_generate { override(1); }",
        // Probe types that can read arbitrary memory, and wildcards.
        "kprobe:do_exit { exit(); }",
        "kretprobe:do_exit { exit(); }",
        "kfunc:vmlinux:do_exit { exit(); }",
        "fentry:do_exit { exit(); }",
        "uprobe:/bin/bash:readline { exit(); }",
        "usdt:/usr/bin/python3:function__entry { exit(); }",
        "rawtracepoint:sched_switch { exit(); }",
        "tracepoint:syscalls:sys_enter_* { exit(); }",
        "t:signal:signal_generate { exit(); }",
        // Includes, configuration and other top-level items.
        "#include <linux/sched.h>\nBEGIN { exit(); }",
        "config = { unsafe = 1 }\nBEGIN { exit(); }",
        "import \"x\";\nBEGIN { exit(); }",
        "fn f(): int64 { return 1; }",
        "BEGIN { exit(); } stray",
        "BEGIN { exit(); }}",
        // Positional parameters other than the capture length.
        "BEGIN { printf(\"%s\", $2); }",
        "BEGIN { $x = 1; }",
    ] {
        let script = format!("{BOUND}\n{bad}");
        assert!(check_script(&script).is_err(), "rules admitted:\n{script}");
    }
    // A script must bound itself on $1.
    for unbounded in [
        "BEGIN { printf(\"x\"); }",
        "interval:s:5 { exit(); }",
        "interval:s:1 { exit(); }",
        "interval:s:1 { @s = @s + 1; if (@s >= 60) { printf(\"%d\", $1); } }",
    ] {
        assert!(check_script(unbounded).is_err(), "unbounded:\n{unbounded}");
    }
}

// ---- Argument allowlist ---------------------------------------------------

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn script(name: &str) -> &'static Script {
    SCRIPTS
        .iter()
        .find(|script| script.name == name)
        .expect("script")
}

#[test]
fn parse_admits_a_script_name_and_an_optional_length_only() {
    let kill = script("signal-kill-sender");
    for (given, seconds) in [
        (vec!["signal-kill-sender"], DEFAULT_SECONDS),
        (vec!["signal-kill-sender", "--seconds", "1"], 1),
        (vec!["signal-kill-sender", "--seconds", "45"], 45),
        (vec!["signal-kill-sender", "--seconds", "3600"], MAX_SECONDS),
    ] {
        assert_eq!(
            parse(&os(&given)),
            Ok(Request {
                script: kill,
                seconds
            }),
            "{given:?}"
        );
    }
}

/// Every other shape; the binary test below also runs them.
const REFUSED: &[&[&str]] = &[
    &[],
    &["-e", "BEGIN { exit(); }"],
    &["signal-kill-sender", "-e", "BEGIN { exit(); }"],
    &["-f", "/tmp/x.bt"],
    &["/tmp/x.bt"],
    &["/usr/local/lib/carrick-capture/signal-kill-sender.bt"],
    &["signal-kill-sender.bt"],
    &["../signal-kill-sender"],
    &["./signal-kill-sender"],
    &["SIGNAL-KILL-SENDER"],
    &["signal-kill-sender "],
    &["signal-kill-sender\0"],
    &["no-such-script"],
    &["--seconds", "5", "signal-kill-sender"],
    &["signal-kill-sender", "--seconds"],
    &["signal-kill-sender", "--seconds=5"],
    &["signal-kill-sender", "--seconds", "0"],
    &["signal-kill-sender", "--seconds", "05"],
    &["signal-kill-sender", "--seconds", "3601"],
    &["signal-kill-sender", "--seconds", "99999"],
    &["signal-kill-sender", "--seconds", "-1"],
    &["signal-kill-sender", "--seconds", "+5"],
    &["signal-kill-sender", "--seconds", "5s"],
    &["signal-kill-sender", "--seconds", " 5"],
    &["signal-kill-sender", "--seconds", ""],
    &["signal-kill-sender", "--seconds", "5", "--seconds", "5"],
    &["signal-kill-sender", "--seconds", "5", "extra"],
    &["signal-kill-sender", "-o", "/etc/sudoers.d/x"],
    &["signal-kill-sender", "--unsafe"],
    &["signal-kill-sender", "-c", "/bin/sh"],
    &["signal-kill-sender", "-I", "/root"],
    &["signal-kill-sender", "extra"],
    &["signal-kill-sender", "signal-kill-sender"],
    &["-l", "tracepoint:*"],
    &["--version"],
    &["--help"],
];

#[test]
fn parse_refuses_every_other_shape() {
    for given in REFUSED {
        assert!(parse(&os(given)).is_err(), "parse admitted {given:?}");
    }
    // Non-UTF-8 bytes never match a name.
    use std::os::unix::ffi::OsStringExt;
    let mut name = b"signal-kill-sender".to_vec();
    name.push(0xff);
    assert!(parse(&[OsString::from_vec(name)]).is_err());
}

#[test]
fn binary_refuses_every_other_shape_before_running_anything() {
    for given in REFUSED {
        let args: Vec<&str> = given
            .iter()
            .copied()
            .filter(|arg| !arg.contains('\0'))
            .collect();
        let output = Command::new(env!("CARGO_BIN_EXE_carrick-capture"))
            .args(&args)
            .env_clear()
            .output()
            .expect("run carrick-capture");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(REFUSED_SHAPE),
            "{args:?}: {stderr}"
        );
        assert!(stderr.starts_with(REFUSAL), "{args:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

// ---- Installed-script checks ----------------------------------------------

struct Installed {
    _root: tempfile::TempDir,
    root: std::path::PathBuf,
    dir: std::path::PathBuf,
    owner: u32,
}

/// A root-only-shaped install owned by the test user: `root/lib/<name>.bt`.
fn install() -> Installed {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().to_path_buf();
    std::fs::set_permissions(&root, PermissionsExt::from_mode(0o755)).expect("root mode");
    let dir = root.join("lib");
    std::fs::create_dir(&dir).expect("dir");
    std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o755)).expect("dir mode");
    for script in SCRIPTS {
        let path = dir.join(format!("{}.bt", script.name));
        std::fs::write(&path, script.source).expect("script");
        std::fs::set_permissions(&path, PermissionsExt::from_mode(0o644)).expect("mode");
    }
    let owner = std::fs::metadata(&root).expect("meta").uid();
    Installed {
        _root: temp,
        root,
        dir,
        owner,
    }
}

#[test]
fn verify_installed_admits_only_the_reviewed_root_only_copy() {
    let kill = script("signal-kill-sender");
    let set_mode = |path: &Path, mode: u32| {
        std::fs::set_permissions(path, PermissionsExt::from_mode(mode)).expect("mode");
    };
    let check = |at: &Installed| verify_installed(&at.dir, &at.root, at.owner, kill);

    let at = install();
    assert_eq!(check(&at), Ok(at.dir.join("signal-kill-sender.bt")));
    // Another owner.
    assert!(verify_installed(&at.dir, &at.root, at.owner + 1, kill).is_err());
    // Not under the trusted root (the walk reaches a directory it cannot trust).
    assert!(verify_installed(&at.dir, Path::new("/nonexistent"), at.owner, kill).is_err());

    // Edited, truncated or extended content.
    let file = at.dir.join("signal-kill-sender.bt");
    for content in [
        kill.source.replace("== 9", "!= 0"),
        kill.source[..kill.source.len() - 1].to_owned(),
        format!("{}BEGIN {{ }}\n", kill.source),
        String::new(),
    ] {
        std::fs::write(&file, &content).expect("edit");
        assert!(check(&at).is_err(), "admitted edited content");
    }
    std::fs::write(&file, kill.source).expect("restore");
    assert!(check(&at).is_ok());

    // Group- or world-writable script, directory or ancestor.
    for (path, mode, restore) in [
        (file.clone(), 0o664, 0o644),
        (file.clone(), 0o646, 0o644),
        (at.dir.clone(), 0o775, 0o755),
        (at.dir.clone(), 0o757, 0o755),
        (at.root.clone(), 0o777, 0o755),
    ] {
        set_mode(&path, mode);
        assert!(
            check(&at).is_err(),
            "admitted {} at {mode:o}",
            path.display()
        );
        set_mode(&path, restore);
    }
    assert!(check(&at).is_ok());

    // A symlinked script, a symlinked directory and a missing script.
    let elsewhere = at.root.join("elsewhere.bt");
    std::fs::write(&elsewhere, kill.source).expect("copy");
    std::fs::remove_file(&file).expect("remove");
    assert!(check(&at).is_err(), "admitted a missing script");
    symlink(&elsewhere, &file).expect("symlink");
    assert!(check(&at).is_err(), "admitted a symlinked script");

    let linked = install();
    let real = linked.root.join("real");
    std::fs::rename(&linked.dir, &real).expect("move");
    symlink(&real, &linked.dir).expect("symlink dir");
    assert!(check(&linked).is_err(), "admitted a symlinked directory");
}

/// A fake `lstat` over `(path, st_mode, uid)` rows; unknown paths fail.
fn fake_lstat(
    rows: &[(&'static str, u32, u32)],
    walked: &mut Vec<String>,
) -> impl FnMut(&Path) -> Result<PathMode, String> {
    let rows = rows.to_vec();
    move |path: &Path| {
        walked.push(path.display().to_string());
        rows.iter()
            .find(|(known, _, _)| Path::new(known) == path)
            .map(|&(_, mode, uid)| PathMode { mode, uid })
            .ok_or_else(|| format!("{}: no such file", path.display()))
    }
}

#[test]
fn directory_chain_walks_to_the_trusted_root_and_refuses_any_untrusted_parent() {
    const DIR: u32 = 0o040_755;
    let good = [
        ("/", DIR, 0),
        ("/usr", DIR, 0),
        ("/usr/local", DIR, 0),
        ("/usr/local/sbin", DIR, 0),
    ];
    let chain = |rows: &[(&'static str, u32, u32)], walked: &mut Vec<String>| {
        verify_directory_chain(
            Path::new("/usr/local/sbin"),
            Path::new("/"),
            0,
            fake_lstat(rows, walked),
        )
    };
    let mut walked = Vec::new();
    assert_eq!(chain(&good, &mut walked), Ok(()));
    assert_eq!(walked, ["/usr/local/sbin", "/usr/local", "/usr", "/"]);

    // Each row replaces one parent: wrong owner, group-writable,
    // world-writable (also sticky), symlinked, a regular file, a socket.
    for (path, mode, uid) in [
        ("/usr/local/sbin", DIR, 1000),
        ("/usr/local", 0o040_775, 0),
        ("/usr", 0o040_757, 0),
        ("/", 0o041_777, 0),
        ("/usr/local/sbin", 0o120_777, 0),
        ("/usr/local", 0o120_755, 0),
        ("/usr", 0o100_755, 0),
        ("/usr/local", 0o140_755, 0),
    ] {
        let rows = good.map(|row| {
            if row.0 == path {
                (path, mode, uid)
            } else {
                row
            }
        });
        let refused = chain(&rows, &mut Vec::new());
        assert!(
            refused
                .as_ref()
                .is_err_and(|reason| reason.starts_with(path)),
            "{path} at {mode:o} uid {uid} gave {refused:?}"
        );
    }

    // A missing parent, and a directory outside the trusted root.
    assert!(chain(&good[1..], &mut Vec::new()).is_err());
    assert!(
        verify_directory_chain(
            Path::new("/usr/local/sbin"),
            Path::new("/opt"),
            0,
            fake_lstat(&good, &mut Vec::new()),
        )
        .is_err()
    );
}

// ---- Exec shape -----------------------------------------------------------

#[test]
fn command_runs_bpftrace_on_the_fixed_path_under_a_hard_deadline_and_nothing_else() {
    let request = Request {
        script: script("signal-kill-sender"),
        seconds: 45,
    };
    let path = Path::new("/usr/local/lib/carrick-capture/signal-kill-sender.bt");
    let command = command(&request, path);
    assert_eq!(command.get_program(), TIMEOUT);
    let deadline = (45 + GRACE_SECONDS).to_string();
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [
            "--foreground",
            "--signal=INT",
            "--kill-after=5",
            deadline.as_str(),
            BPFTRACE,
            "-B",
            "line",
            "/usr/local/lib/carrick-capture/signal-kill-sender.bt",
            "45",
        ]
    );
    assert_eq!(command.get_current_dir(), Some(Path::new("/")));
    assert_eq!(
        command.get_envs().collect::<Vec<_>>(),
        [("PATH".as_ref(), Some("/usr/sbin:/usr/bin".as_ref()))]
    );
    // std exposes the cleared environment only through Debug (`env -i`).
    let shown = format!("{command:?}");
    assert!(
        shown.starts_with("cd \"/\" && env -i PATH=\"/usr/sbin:/usr/bin\" \"/usr/bin/timeout\""),
        "{shown}"
    );
}

//! P5 enforcement: a source-level ratchet that keeps blocking-capable host I/O
//! off the big-kernel-lock path.
//!
//! A guest blocking syscall must never block a vCPU thread inside libc while
//! the dispatcher lock is held — that starves every sibling thread (the
//! GIL/server-worker starvation the WaitOnFds + per-thread kqueue design
//! fixes). So every raw blocking-capable `libc` I/O call in the dispatcher must
//! be made non-blocking, by one of:
//!
//!   * `MSG_DONTWAIT` on the call (recv/send family),
//!   * `set_host_nonblocking` on the fd just before (read/write helpers),
//!   * routing through the `blocking_io` chokepoint (accept/connect),
//!
//! or, when a site is *intentionally* allowed to block (e.g. a write to the
//! user's controlling tty), it must carry an explicit `BLOCKING-IO-OK: <why>`
//! marker. A new raw call without any of these fails this test — forcing the
//! author to route it through the lockless wait or justify the exception.

use std::path::PathBuf;

/// Files that issue host I/O on behalf of guest syscalls.
const DISPATCH_FILES: &[&str] = &[
    "src/dispatch/net.rs",
    "src/dispatch/fs.rs",
    "src/dispatch/mod.rs",
];

/// Raw `libc` calls that can block on a blocking fd.
const BLOCKING_CALLS: &[&str] = &[
    "libc::recv(",
    "libc::recvfrom(",
    "libc::recvmsg(",
    "libc::send(",
    "libc::sendto(",
    "libc::sendmsg(",
    "libc::accept(",
    "libc::connect(",
    "libc::read(",
    "libc::write(",
];

/// Tokens within the preceding window that prove the call won't block.
const SAFE_TOKENS: &[&str] = &[
    "MSG_DONTWAIT",
    "set_host_nonblocking",
    "blocking_io",
    "BLOCKING-IO-OK",
];

/// How many lines above a call we scan for a safe token. Wide enough to cover
/// a `host_flags = … | MSG_DONTWAIT` / `blocking_io(…)` opened a dozen-plus
/// lines before the actual call (e.g. the two-branch recvfrom in recvfrom).
const WINDOW: usize = 24;

/// Line indices that fall inside a `#[cfg(test)]` block. The guard targets the
/// production kernel-lock path; inline test modules legitimately open localhost
/// sockets / blocking pipes and are NOT that path, so they are excluded. Brace
/// balance is naive (it ignores braces inside strings/chars), which is fine for
/// these dispatch files where `#[cfg(test)]` only guards `mod`/`fn` items.
fn cfg_test_line_set(lines: &[&str]) -> std::collections::HashSet<usize> {
    let mut in_test = std::collections::HashSet::new();
    let mut depth: i32 = 0;
    let mut pending = false; // saw #[cfg(test)], awaiting the item's opening brace
    let mut test_depth: Option<i32> = None; // brace depth at which the test block opened
    for (i, line) in lines.iter().enumerate() {
        if test_depth.is_some() {
            in_test.insert(i);
        }
        if line.trim_start().starts_with("#[cfg(test)]") {
            pending = true;
        }
        if pending && test_depth.is_none() {
            if line.contains('{') {
                test_depth = Some(depth);
                pending = false;
            } else if line.contains(';') {
                pending = false; // a non-block #[cfg(test)] item (use/const)
            }
        }
        depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
        if let Some(td) = test_depth
            && depth <= td
        {
            test_depth = None;
        }
    }
    in_test
}

#[test]
fn no_unguarded_blocking_host_io_in_dispatch() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut violations: Vec<String> = Vec::new();

    for rel in DISPATCH_FILES {
        let path = root.join(rel);
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let lines: Vec<&str> = src.lines().collect();
        let test_lines = cfg_test_line_set(&lines);

        for (i, line) in lines.iter().enumerate() {
            // Test code (inline #[cfg(test)] modules) is not the kernel-lock path.
            if test_lines.contains(&i) {
                continue;
            }
            // Skip comments and doc text — we only care about real call sites.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            let Some(call) = BLOCKING_CALLS.iter().find(|c| line.contains(**c)) else {
                continue;
            };
            // Look at the call line itself plus the preceding window.
            let start = i.saturating_sub(WINDOW);
            let context = lines[start..=i].join("\n");
            if SAFE_TOKENS.iter().any(|t| context.contains(t)) {
                continue;
            }
            violations.push(format!(
                "{}:{}: `{}` is not made non-blocking (no MSG_DONTWAIT / \
                 set_host_nonblocking / blocking_io within {WINDOW} lines, and no \
                 `BLOCKING-IO-OK:` marker)\n    {}",
                rel,
                i + 1,
                call.trim_end_matches('('),
                line.trim()
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "blocking-capable host I/O on the kernel-lock path:\n{}",
        violations.join("\n")
    );
}

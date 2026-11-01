//! Live transcripts in the Actions step log (#1229). While a coordinator or
//! worker runs, the files it writes are followed and their complete lines
//! are printed to the step's stdout, so a round can be watched as it runs.
//!
//! The repository and its run logs are public, and a live line skips the
//! artifact scan. So every known secret is registered with the runner
//! (`::add-mask::`) before any line, and the stream runs inside
//! `::stop-commands::<random>`, which is what keeps transcript text (`::`,
//! `##[`) from acting as a workflow command; the `[label]` prefix is only
//! for reading. Each line has control characters removed, is masked the
//! same way artifacts are (`agent_loop::masked`), then capped. A partial
//! line waits for its newline and is never printed in pieces.
//! `CARRICK_DISPATCH_LIVE_LOG=0` turns streaming off.
use std::cell::RefCell;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::FileExt;

/// Longest printed line, in characters.
const LINE_CHARS: usize = 2000;
/// Most bytes read from one source per tick, so one chatty file cannot
/// stall the serve loop.
const READ_BYTES: usize = 64 * 1024;
/// Longest partial line kept while waiting for its newline. A longer one
/// is dropped, never printed in pieces: a cut could split a token across
/// two prints that masking each sees only half of.
const PARTIAL_BYTES: usize = 16 * 1024;
/// Most bytes the final drain reads after a writer exits.
const DRAIN_BYTES: usize = 4 * 1024 * 1024;
const DROPPED: &[u8] = b"[line over 16 KiB dropped]\n";
/// Most bytes one source streams; the rest is only in the artifacts.
const STREAM_BYTES: usize = 8 * 1024 * 1024;

/// A followed file, read through one held handle, never reopened by name:
/// the agent account could replace the path with a link to a secret, and a
/// reopen would stream it into the public log. A file the agent creates
/// itself is opened once, when it first appears ([`follow`]).
struct Source {
    label: String,
    file: Option<File>,
    /// Until `file` is open: the path the agent will create, and the
    /// account that must own it.
    pending: Option<(std::path::PathBuf, libc::uid_t)>,
    offset: u64,
    partial: Vec<u8>,
    /// Inside an over-long line: discard until its newline.
    dropping: bool,
    /// Bytes streamed so far, against [`STREAM_BYTES`].
    streamed: usize,
}
impl Source {
    /// Take new bytes; return the complete lines ready to print.
    fn absorb(&mut self, mut text: Vec<u8>) -> Vec<u8> {
        let mut ready = Vec::new();
        if self.dropping {
            match text.iter().position(|b| *b == b'\n') {
                Some(end) => {
                    text.drain(..=end);
                    self.dropping = false;
                }
                None => return ready,
            }
        }
        self.partial.append(&mut text);
        if let Some(end) = self.partial.iter().rposition(|b| *b == b'\n') {
            let rest = self.partial.split_off(end + 1);
            ready = std::mem::replace(&mut self.partial, rest);
        }
        if self.partial.len() > PARTIAL_BYTES {
            self.partial.clear();
            self.dropping = true;
            ready.extend_from_slice(DROPPED);
        }
        ready
    }
}

#[derive(Default)]
struct Live {
    token: String,
    sources: Vec<Source>,
    /// Every secret seen so far. It only grows: deleting a credential file
    /// later can't unmask anything.
    secrets: Vec<String>,
    /// The subset already registered with the runner (`::add-mask::`).
    registered: Vec<String>,
    /// While streaming, workflow commands are suspended with
    /// `::stop-commands::<this>`; `::<this>::` resumes them.
    resume: Option<String>,
    #[cfg(test)]
    sink: Option<std::rc::Rc<RefCell<Vec<u8>>>>,
}

thread_local! {
    static LIVE: RefCell<Live> = RefCell::default();
}

fn enabled() -> bool {
    std::env::var("CARRICK_DISPATCH_LIVE_LOG").map_or(true, |v| v != "0")
}

/// The job token, masked in every line on top of the shared redaction.
pub(crate) fn set_token(token: &str) {
    LIVE.with(|live| live.borrow_mut().token = token.to_owned());
}

/// Register every secret not yet masked with the runner (`::add-mask::`,
/// so it also masks the forms it derives), then suspend workflow commands
/// for the stream, so no transcript line can act as one (`::`, `##[`).
/// Commands are briefly resumed to register a newly minted secret.
/// `false` when the stream can't be guarded; nothing may then be printed.
fn guard(live: &mut Live) -> bool {
    // Later captures can only add (newly minted tokens); the snapshot taken
    // in `create` is what an agent can't have touched.
    let token = live.token.clone();
    let captured = crate::dispatch_redaction::DiagnosticSecrets::capture()
        .map(|c| c.values().to_vec())
        .unwrap_or_default();
    remember(live, std::iter::once(token).chain(captured).collect());
    let fresh: Vec<String> = live
        .secrets
        .iter()
        .filter(|s| !live.registered.contains(s))
        .cloned()
        .collect();
    if fresh.is_empty() && live.resume.is_some() {
        return true;
    }
    let Some(next) = stop_token() else {
        // Fail closed: stop streaming this round and say so.
        live.sources.clear();
        let mut notice = String::new();
        if let Some(resume) = live.resume.take() {
            notice.push_str(&format!("::{resume}::\n"));
        }
        notice.push_str(
            "[live transcripts stopped: no randomness for stop-commands; see the run artifacts]\n",
        );
        raw(live, notice.as_bytes());
        return false;
    };
    let mut commands = String::new();
    if let Some(resume) = live.resume.take() {
        commands.push_str(&format!("::{resume}::\n"));
    }
    for secret in &fresh {
        for line in secret.lines().filter_map(maskable) {
            // Workflow-command data escaping: `%` first.
            let data = line.replace('%', "%25");
            commands.push_str(&format!("::add-mask::{data}\n"));
        }
    }
    live.registered.extend(fresh);
    commands.push_str(&format!("::stop-commands::{next}\n"));
    live.resume = Some(next);
    raw(live, commands.as_bytes());
    true
}

/// A line worth registering with `::add-mask::`. Some captured files are
/// agent-writable, so a line with a control character (a lone `\r` could
/// start a second command), one starting with `::`, or one too short to
/// be a credential (masking `e` would garble the log) is never sent.
fn maskable(line: &str) -> Option<&str> {
    let line = line.trim();
    (line.chars().count() >= 8 && !line.starts_with("::") && !line.chars().any(char::is_control))
        .then_some(line)
}

/// Add secrets to the known set; it never shrinks.
fn remember(live: &mut Live, secrets: Vec<String>) {
    for secret in secrets {
        if secret.trim().len() >= 8 && !live.secrets.contains(&secret) {
            live.secrets.push(secret);
        }
    }
}

/// Resume workflow commands once nothing streams any more.
fn release(live: &mut Live) {
    if live.sources.is_empty()
        && let Some(resume) = live.resume.take()
    {
        raw(live, format!("::{resume}::\n").as_bytes());
    }
}

/// An unguessable `stop-commands` token, so transcript text can't resume
/// commands early.
/// `None` when no randomness can be read: then streaming stops, because a
/// guessable token would let transcript text resume commands.
fn stop_token() -> Option<String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Create a child's output file at `path` (truncated, never through a link)
/// and follow it under `label`. Returns the handle to give the child; the
/// stream reads a clone of the same open file.
pub(crate) fn create(label: &str, path: &std::path::Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    register(label, Some(file.try_clone()?), None);
    Ok(file)
}

/// Follow a transcript the agent account creates itself at `path` (#1292:
/// the coordinator and worker write theirs under `runtime/`, and their
/// stdout stays empty). The file is opened once, on the first tick that
/// finds it, with no link at any agent-owned step of the path; it must be
/// a regular file with one link, owned by `owner`, so it can't be a link
/// to anything the agent didn't write.
pub(crate) fn follow(label: &str, path: &std::path::Path, owner: libc::uid_t) {
    register(label, None, Some((path.to_owned(), owner)));
}

fn register(label: &str, file: Option<File>, pending: Option<(std::path::PathBuf, libc::uid_t)>) {
    if !enabled() {
        return;
    }
    // Snapshot the secret set now, before the child runs: some of the files
    // it reads are writable by the agent account once it starts. Without a
    // snapshot nothing is followed (fail closed), and the log says so.
    let snapshot = match crate::dispatch_redaction::DiagnosticSecrets::capture() {
        Ok(capture) => capture.values().to_vec(),
        Err(error) => {
            notice(&format!("[{label}] not streamed live: {error}\n"));
            return;
        }
    };
    LIVE.with(|live| {
        let mut live = live.borrow_mut();
        remember(&mut live, snapshot);
        live.sources.retain(|s| s.label != label);
        live.sources.push(Source {
            label: label.to_owned(),
            file,
            pending,
            offset: 0,
            partial: Vec::new(),
            dropping: false,
            streamed: 0,
        });
    });
}

/// Open a pending source once its file exists: `Ok(false)` while it
/// doesn't. A file that fails the checks ends the source, and the reason
/// is returned for the log.
fn open_pending(source: &mut Source) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    if source.file.is_some() {
        return Ok(true);
    }
    let Some((path, owner)) = source.pending.clone() else {
        return Ok(false);
    };
    let opened = crate::safe_copy::open_text(&path).and_then(|file| {
        let meta = file.metadata()?;
        if meta.uid() != owner || meta.nlink() != 1 {
            return Err(std::io::Error::other("not the agent's own transcript"));
        }
        Ok(file)
    });
    match opened {
        Ok(file) => {
            source.file = Some(file);
            source.pending = None;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            source.pending = None;
            Err(format!("not streamed live: {error}\n"))
        }
    }
}

/// A plain line for the reader; it carries no agent text.
fn notice(text: &str) {
    LIVE.with(|live| raw(&live.borrow(), text.as_bytes()));
}

/// Print what is left under `label`, including a final unterminated line
/// now that its writer has exited, and stop following it.
pub(crate) fn unfollow(label: &str) {
    LIVE.with(|live| {
        let mut live = live.borrow_mut();
        let Some(index) = live.sources.iter().position(|s| s.label == label) else {
            return;
        };
        let mut source = live.sources.remove(index);
        let token = live.token.clone();
        let mut ready = Vec::new();
        let mut drained = 0;
        loop {
            let mut text = Vec::new();
            if drained >= DRAIN_BYTES || !read_more(&mut source, &mut text) {
                break;
            }
            drained += text.len();
            ready.extend(source.absorb(text));
        }
        // A drain cut at its limit leaves a cut line: a token prefix in it
        // would pass both exact and shape masking, so it's dropped.
        if !source.dropping && !source.partial.is_empty() && drained < DRAIN_BYTES {
            ready.append(&mut source.partial);
            ready.push(b'\n');
        }
        if drained >= DRAIN_BYTES {
            ready.extend_from_slice(b"[output truncated; see the run artifacts]\n");
        }
        if source.streamed < STREAM_BYTES && !ready.is_empty() && guard(&mut live) {
            emit(&live, &source.label, &ready, &token);
        }
        release(&mut live);
    });
}

/// Print the complete lines every followed file gained since the last tick.
pub(crate) fn pump() {
    LIVE.with(|live| {
        let mut live = live.borrow_mut();
        if live.sources.is_empty() {
            return;
        }
        let token = live.token.clone();
        let mut batches = Vec::new();
        for source in &mut live.sources {
            if source.streamed >= STREAM_BYTES {
                continue;
            }
            let mut text = Vec::new();
            read_more(source, &mut text);
            let mut ready = source.absorb(text);
            source.streamed += ready.len();
            if source.streamed >= STREAM_BYTES {
                ready.extend_from_slice(b"[live output limit reached; see the run artifacts]\n");
            }
            if !ready.is_empty() {
                batches.push((source.label.clone(), ready));
            }
        }
        if batches.is_empty() {
            return;
        }
        if !guard(&mut live) {
            return;
        }
        for (label, text) in batches {
            emit(&live, &label, &text, &token);
        }
    });
}

/// Read up to [`READ_BYTES`] new bytes; `false` once nothing more is there.
fn read_more(source: &mut Source, into: &mut Vec<u8>) -> bool {
    match open_pending(source) {
        Ok(true) => {}
        Ok(false) => return false,
        Err(reason) => {
            into.extend_from_slice(reason.as_bytes());
            return true;
        }
    }
    let Some(file) = &source.file else {
        return false;
    };
    let mut buffer = vec![0; READ_BYTES];
    match file.read_at(&mut buffer, source.offset) {
        Ok(read) if read > 0 => {
            into.extend_from_slice(&buffer[..read]);
            source.offset += read as u64;
            true
        }
        _ => false,
    }
}

#[cfg(test)]
fn render(label: &str, text: &[u8], token: &str) -> String {
    render_with(label, text, token, &[])
}

fn render_with(label: &str, text: &[u8], token: &str, secrets: &[String]) -> String {
    // Normalize first, then mask: removing a control character after
    // masking could join a token that masking never saw whole.
    let cleaned: String = String::from_utf8_lossy(text)
        .lines()
        .map(|line| {
            line.chars()
                .filter(|c| *c == '\t' || !c.is_control())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");
    // The frozen set first, then the live capture and credential shapes.
    let mut frozen = cleaned;
    for secret in secrets {
        frozen = frozen.replace(secret.as_str(), "[REDACTED]");
    }
    let masked = super::agent_loop::masked(&frozen, token);
    let mut out = String::new();
    for line in masked.lines() {
        let capped: String = line.chars().take(LINE_CHARS).collect();
        out.push_str(&format!("[{label}] {capped}\n"));
    }
    out
}

fn emit(live: &Live, label: &str, text: &[u8], token: &str) {
    if text.is_empty() {
        return;
    }
    let lines = render_with(label, text, token, &live.secrets);
    #[cfg(test)]
    if let Some(sink) = &live.sink {
        sink.borrow_mut().extend_from_slice(lines.as_bytes());
        return;
    }
    let _ = live;
    // A closed step log must not end the round.
    let _ = std::io::stdout().lock().write_all(lines.as_bytes());
}

/// Workflow commands for the runner, written unprefixed.
fn raw(live: &Live, bytes: &[u8]) {
    #[cfg(test)]
    if let Some(sink) = &live.sink {
        sink.borrow_mut().extend_from_slice(bytes);
        return;
    }
    let _ = live;
    let _ = std::io::stdout().lock().write_all(bytes);
}

#[cfg(test)]
pub(crate) fn capture() -> std::rc::Rc<RefCell<Vec<u8>>> {
    let sink = std::rc::Rc::new(RefCell::new(Vec::new()));
    LIVE.with(|live| live.borrow_mut().sink = Some(sink.clone()));
    sink
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    /// A secret minted while streaming is registered before any line that
    /// could hold it: commands resume for exactly that, then stop again
    /// under a new token.
    #[test]
    fn a_mid_stream_secret_is_masked_before_the_next_line() {
        let dir = tempfile::tempdir().unwrap();
        let sink = super::capture();
        super::set_token("first-secret-1");
        let mut out = super::create("loop", &dir.path().join("out")).unwrap();
        use std::io::Write as _;
        writeln!(out, "one").unwrap();
        super::pump();
        super::set_token("second-secret-2");
        writeln!(out, "two second-secret-2").unwrap();
        super::pump();
        super::unfollow("loop");
        let all = String::from_utf8(sink.borrow().clone()).unwrap();
        let lines: Vec<&str> = all.lines().collect();
        let stops: Vec<&str> = lines
            .iter()
            .filter_map(|l| l.strip_prefix("::stop-commands::"))
            .collect();
        assert_eq!(stops.len(), 2, "{all}");
        assert_ne!(stops[0], stops[1]);
        assert_eq!(
            lines,
            [
                "::add-mask::first-secret-1",
                &format!("::stop-commands::{}", stops[0]),
                "[loop] one",
                &format!("::{}::", stops[0]),
                "::add-mask::second-secret-2",
                &format!("::stop-commands::{}", stops[1]),
                "[loop] two [REDACTED]",
                &format!("::{}::", stops[1]),
            ],
            "{all}"
        );
    }

    /// #1292: the agents' transcripts are files they create after launch,
    /// so a followed path streams once it appears, and only when it's the
    /// agent's own single-link regular file.
    #[test]
    fn a_followed_transcript_streams_once_it_appears_and_only_if_it_is_the_agents() {
        use std::io::Write as _;
        let me = unsafe { libc::geteuid() };
        let dir = tempfile::tempdir().unwrap();
        let sink = super::capture();
        super::set_token("fixture-token");
        let log = dir.path().join("runtime/dispatch/worker.log");
        super::follow("worker", &log, me);
        super::pump();
        assert!(sink.borrow().is_empty(), "nothing before the file exists");
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        let mut out = std::fs::File::create(&log).unwrap();
        writeln!(out, "first event").unwrap();
        super::pump();
        writeln!(out, "second event").unwrap();
        super::unfollow("worker");
        let all = String::from_utf8(sink.borrow().clone()).unwrap();
        let lines: Vec<&str> = all.lines().filter(|l| !l.starts_with("::")).collect();
        assert_eq!(
            lines,
            ["[worker] first event", "[worker] second event"],
            "{all}"
        );

        let secret = dir.path().join("secret");
        std::fs::write(&secret, "SECRET-SENTINEL\n").unwrap();
        let refused = |name: &str, path: &std::path::Path, owner: libc::uid_t| {
            sink.borrow_mut().clear();
            super::follow(name, path, owner);
            super::pump();
            super::unfollow(name);
            let all = String::from_utf8(sink.borrow().clone()).unwrap();
            assert!(!all.contains("SECRET-SENTINEL"), "{name}: {all}");
            assert!(
                all.contains(&format!("[{name}] not streamed live:")),
                "{name}: {all}"
            );
        };
        // A link in the agent's place, to a file it didn't write.
        let link = dir.path().join("link.log");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        refused("symlink", &link, me);
        // A second name for someone else's file.
        let hard = dir.path().join("hard.log");
        std::fs::hard_link(&secret, &hard).unwrap();
        refused("hardlink", &hard, me);
        // A file the agent account doesn't own.
        std::fs::remove_file(&hard).unwrap();
        refused("owner", &secret, me.wrapping_add(1));
    }

    #[test]
    fn rendered_lines_are_masked_labelled_and_inert() {
        let out = super::render(
            "worker agy/m",
            b"uses fixture-token here\n::stop-commands::x\nbell\x07 \x1b[31mred\n",
            "fixture-token",
        );
        assert_eq!(
            out,
            "[worker agy/m] uses [REDACTED] here\n[worker agy/m] ::stop-commands::x\n[worker agy/m] bell [31mred\n"
        );
        assert!(out.lines().all(|l| l.starts_with("[worker agy/m] ")));
        // Agent-writable capture lines can't inject or garble commands.
        assert_eq!(super::maskable("  ghs_abcdefgh  "), Some("ghs_abcdefgh"));
        assert_eq!(super::maskable("ghs_abc\r::warning::x"), None);
        assert_eq!(super::maskable("::stop-commands::abcdefgh"), None);
        assert_eq!(super::maskable("{"), None);
        // A control character inside a token must not hide it from masking.
        let split = super::render("loop", b"fixture-\x07token\n", "fixture-token");
        assert_eq!(split, "[loop] [REDACTED]\n");
        // An endless line is dropped, not buffered or printed in pieces.
        let mut source = super::Source {
            label: "loop".into(),
            file: Some(tempfile::tempfile().unwrap()),
            pending: None,
            offset: 0,
            partial: Vec::new(),
            dropping: false,
            streamed: 0,
        };
        assert!(source.absorb(vec![b'a'; 10_000]).is_empty());
        assert_eq!(source.absorb(vec![b'a'; 10_000]), super::DROPPED);
        assert!(source.partial.is_empty() && source.dropping);
        assert!(source.absorb(vec![b'a'; 100_000]).is_empty());
        assert_eq!(source.absorb(b"aaa\nnext\n".to_vec()), b"next\n");
        let long = super::render("loop", "x".repeat(5000).as_bytes(), "");
        assert_eq!(
            long.trim_end().chars().count(),
            "[loop] ".len() + super::LINE_CHARS
        );
    }
}

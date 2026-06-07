//! `POST /build`: the legacy (non-BuildKit) Docker Engine image-build endpoint.
//!
//! Unlike the buffered container endpoints, this streams an NDJSON response body
//! as the build runs. The request body is a gzipped tar of the build context; we
//! unpack it to a temp dir and shell out to `carrick build` (kaniko-as-guest) via
//! `current_exe()`, then forward kaniko's output line-by-line as
//! `{"stream":"<line>\n"}` frames, ending in a success aux frame or an error
//! frame. The guest fork happens in the spawned `carrick build` → `carrick run`
//! process, never in the server's tokio runtime (the no-tokio-before-fork
//! invariant).

use std::collections::BTreeMap;
use std::path::{Component, Path};

use futures_util::stream::Stream;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::{Response, StatusCode};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

/// The parsed `POST /build` query string. Docker's legacy build protocol passes
/// the Dockerfile name, tags (repeatable `t`), build args (a URL-encoded JSON
/// object), and the no-cache flag as query parameters.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct BuildQuery {
    /// `?dockerfile=` — path of the Dockerfile inside the context. Default
    /// `Dockerfile`.
    pub dockerfile: String,
    /// `?t=` — every tag (the key may repeat for multiple tags).
    pub tags: Vec<String>,
    /// `?buildargs=` — decoded from a URL-encoded JSON object into key/value
    /// pairs (sorted for determinism).
    pub build_args: Vec<(String, String)>,
    /// `?nocache=1` / `?nocache=true`.
    pub nocache: bool,
}

/// Percent-decode an `application/x-www-form-urlencoded` query component:
/// `%XX` hex escapes become their byte, `+` becomes a space, everything else is
/// literal. Lenient — a malformed `%` escape is passed through verbatim rather
/// than erroring (Docker clients send well-formed escapes; we never want to
/// reject a build over a stray `%`).
pub(crate) fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    // The decoded bytes are expected to be UTF-8 (tags, JSON); lossy keeps us
    // panic-free on malformed input.
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the raw `POST /build` query string. This is the endpoint's OWN parser
/// (the shared `query_param` helper cannot handle repeated keys or the
/// URL-encoded JSON in `?buildargs=`): it URL-decodes every value and collects
/// repeated `t` keys.
pub(crate) fn parse_build_query(query: &str) -> BuildQuery {
    let mut out = BuildQuery {
        dockerfile: "Dockerfile".to_string(),
        ..BuildQuery::default()
    };
    let mut buildargs_raw: Option<String> = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, raw_val) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let value = url_decode(raw_val);
        match key {
            "dockerfile" if !value.is_empty() => out.dockerfile = value,
            "t" if !value.is_empty() => out.tags.push(value),
            "buildargs" => buildargs_raw = Some(value),
            "nocache" => out.nocache = matches!(value.as_str(), "1" | "true" | "True"),
            _ => {}
        }
    }
    if let Some(raw) = buildargs_raw {
        // `buildargs` is a JSON object `{"KEY":"VALUE",...}`. Parse it into a
        // sorted map (deterministic argv order); a malformed/empty value yields
        // no args rather than failing the parse.
        if let Ok(map) = serde_json::from_str::<BTreeMap<String, String>>(&raw) {
            out.build_args = map.into_iter().collect();
        }
    }
    out
}

/// Unpack a gzipped tar of the build context into `dest`. Guards against path
/// traversal: an entry whose path escapes `dest` (absolute, or containing `..`)
/// is rejected. `dest` must already exist.
fn unpack_context(gz_tar: &[u8], dest: &Path) -> std::io::Result<()> {
    let decoder = flate2::read::GzDecoder::new(gz_tar);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if !is_safe_relative(&path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsafe tar entry path: {}", path.display()),
            ));
        }
        let target = dest.join(&path);
        // Defense in depth: confirm the joined target stays under dest.
        if !target.starts_with(dest) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tar entry escapes context: {}", path.display()),
            ));
        }
        entry.unpack(&target)?;
    }
    Ok(())
}

/// A relative path is safe to extract iff it has no root/prefix and no `..`
/// component (only `Normal`/`CurDir` parts).
fn is_safe_relative(path: &Path) -> bool {
    path.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// One NDJSON frame: `serde_json`-serialise `value` and append a trailing
/// newline, as Docker's build stream does.
fn ndjson_frame(value: &serde_json::Value) -> Bytes {
    let mut s = value.to_string();
    s.push('\n');
    Bytes::from(s)
}

/// Build the streaming `POST /build` response. Returns immediately with a body
/// that streams as the background task runs; the build itself happens in the
/// spawned `carrick build` child.
///
/// `body_bytes` is the (already-buffered) gzipped-tar request body. On any setup
/// failure (bad tar, temp-dir error, spawn error) we still return a 200 with a
/// single error frame, matching Docker, which reports build problems in-band on
/// the stream rather than via the HTTP status.
pub(crate) fn build_response(
    query: &str,
    body_bytes: Bytes,
) -> Response<BoxBody<Bytes, std::io::Error>> {
    let parsed = parse_build_query(query);
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(64);

    tokio::spawn(async move {
        run_build_streaming(parsed, body_bytes, tx).await;
    });

    let stream = ReceiverStream { rx };
    let body = StreamBody::new(stream).boxed();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        // hyper sets Transfer-Encoding: chunked automatically for a streaming
        // body without a Content-Length.
        .body(body)
        .unwrap_or_else(|_| {
            Response::new(
                http_body_util::Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed(),
            )
        })
}

/// Drive the build: unpack the context, spawn `carrick build`, forward its
/// stdout/stderr line-by-line as `{"stream":...}` frames, and emit a terminal
/// aux/error frame. Sends frames into `tx`; the body stream ends when `tx` (and
/// thus the receiver) closes.
async fn run_build_streaming(
    parsed: BuildQuery,
    body_bytes: Bytes,
    tx: mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
) {
    // A helper to push a JSON object as one NDJSON frame; a send error means the
    // client hung up — stop quietly.
    async fn send_json(
        tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
        value: serde_json::Value,
    ) -> bool {
        tx.send(Ok(Frame::data(ndjson_frame(&value)))).await.is_ok()
    }

    async fn send_error(tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>, msg: &str) {
        let _ = send_json(
            tx,
            serde_json::json!({
                "errorDetail": { "message": msg },
                "error": msg,
            }),
        )
        .await;
    }

    // 1. Unpack the gzipped-tar context into a fresh temp dir.
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            send_error(&tx, &format!("failed to create build temp dir: {e}")).await;
            return;
        }
    };
    let ctx_dir = tmp.path().join("context");
    if let Err(e) = std::fs::create_dir_all(&ctx_dir) {
        send_error(&tx, &format!("failed to create context dir: {e}")).await;
        return;
    }
    // Unpacking can be CPU/IO heavy; do it on a blocking thread. The closure
    // owns the (in-memory) gz-tar bytes and unpacks them through the gz/tar
    // decoders directly.
    let ctx_for_unpack = ctx_dir.clone();
    let unpack =
        tokio::task::spawn_blocking(move || unpack_context(&body_bytes, &ctx_for_unpack)).await;
    match unpack {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            send_error(&tx, &format!("failed to unpack build context: {e}")).await;
            return;
        }
        Err(e) => {
            send_error(&tx, &format!("build context unpack task failed: {e}")).await;
            return;
        }
    }

    // 2. Build the `carrick build` argv.
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            send_error(&tx, &format!("failed to resolve carrick binary: {e}")).await;
            return;
        }
    };
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("build");
    // `carrick build` accepts a single `-t`; pass the first tag. Additional tags
    // are not applied (documented limitation — the wrapper is single-tag).
    let primary_tag = parsed.tags.first().cloned();
    if let Some(t) = &primary_tag {
        cmd.arg("-t").arg(t);
    }
    cmd.arg("-f").arg(&parsed.dockerfile);
    for (k, v) in &parsed.build_args {
        cmd.arg("--build-arg").arg(format!("{k}={v}"));
    }
    if parsed.nocache {
        cmd.arg("--no-cache");
    }
    cmd.arg(&ctx_dir);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdin(std::process::Stdio::null());
    // nosemgrep: rust.lang.security.args.command-injection -- the server spawns
    // itself (current_exe) with build inputs as separate argv entries, never a
    // shell; a CLI that re-execs itself is the established serve pattern.
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            send_error(&tx, &format!("failed to spawn carrick build: {e}")).await;
            return;
        }
    };

    // 3. Forward stdout + stderr line-by-line as `{"stream":...}` frames. kaniko
    // writes its build progress to stderr and our wrapper prints "Successfully
    // built/tagged" to stdout, so merge both into the one Docker stream.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    if let Some(out) = stdout {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if !send_json(&tx, serde_json::json!({ "stream": format!("{line}\n") })).await {
                break;
            }
        }
    }
    if let Some(err) = stderr {
        let mut lines = BufReader::new(err).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if !send_json(&tx, serde_json::json!({ "stream": format!("{line}\n") })).await {
                break;
            }
        }
    }

    // 4. Terminal frame: aux ID on success, error on failure.
    match child.wait().await {
        Ok(status) if status.success() => {
            let tag = primary_tag.unwrap_or_else(|| "carrick-build:latest".to_string());
            let _ = send_json(
                &tx,
                serde_json::json!({ "stream": format!("Successfully built {tag}\n") }),
            )
            .await;
            // An `aux` frame carrying the (tag-as-)ID lets bollard's build stream
            // surface a build result; we don't have the digest handy here, so use
            // the tag as a stable identifier.
            let _ = send_json(&tx, serde_json::json!({ "aux": { "ID": tag } })).await;
        }
        Ok(status) => {
            send_error(
                &tx,
                &format!("build failed (carrick build exited with {status})"),
            )
            .await;
        }
        Err(e) => {
            send_error(&tx, &format!("failed to wait for carrick build: {e}")).await;
        }
    }
    // tmp (and the unpacked context) is dropped here, cleaning up the temp dir.
    drop(tmp);
}

/// Minimal `Stream` adapter over an mpsc receiver — avoids a `tokio-stream`
/// dependency. Yields each received frame result until the channel closes.
pub(crate) struct ReceiverStream {
    pub(crate) rx: mpsc::Receiver<Result<Frame<Bytes>, std::io::Error>>,
}

impl Stream for ReceiverStream {
    type Item = Result<Frame<Bytes>, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_tag_and_default_dockerfile() {
        let q = parse_build_query("t=app:latest");
        assert_eq!(q.tags, vec!["app:latest".to_string()]);
        assert_eq!(q.dockerfile, "Dockerfile");
        assert!(!q.nocache);
        assert!(q.build_args.is_empty());
    }

    #[test]
    fn collects_repeated_t_tags() {
        let q = parse_build_query("t=app:latest&t=app:1.0&t=registry.example.com/app:dev");
        assert_eq!(
            q.tags,
            vec![
                "app:latest".to_string(),
                "app:1.0".to_string(),
                "registry.example.com/app:dev".to_string(),
            ]
        );
    }

    #[test]
    fn url_decodes_buildargs_json() {
        // {"FOO":"bar","BAZ":"qux value"} URL-encoded.
        let raw = "buildargs=%7B%22FOO%22%3A%22bar%22%2C%22BAZ%22%3A%22qux+value%22%7D";
        let q = parse_build_query(raw);
        // BTreeMap sorts keys: BAZ before FOO.
        assert_eq!(
            q.build_args,
            vec![
                ("BAZ".to_string(), "qux value".to_string()),
                ("FOO".to_string(), "bar".to_string()),
            ]
        );
    }

    #[test]
    fn parses_custom_dockerfile_and_nocache() {
        let q = parse_build_query("dockerfile=docker%2FDockerfile.prod&nocache=1&t=x:1");
        assert_eq!(q.dockerfile, "docker/Dockerfile.prod");
        assert!(q.nocache);
        assert_eq!(q.tags, vec!["x:1".to_string()]);
    }

    #[test]
    fn nocache_true_variants() {
        assert!(parse_build_query("nocache=true").nocache);
        assert!(parse_build_query("nocache=1").nocache);
        assert!(!parse_build_query("nocache=0").nocache);
        assert!(!parse_build_query("nocache=false").nocache);
        assert!(!parse_build_query("").nocache);
    }

    #[test]
    fn malformed_buildargs_is_ignored_not_fatal() {
        let q = parse_build_query("buildargs=not-json&t=x:1");
        assert!(q.build_args.is_empty());
        assert_eq!(q.tags, vec!["x:1".to_string()]);
    }

    #[test]
    fn empty_query_uses_defaults() {
        let q = parse_build_query("");
        assert_eq!(q.dockerfile, "Dockerfile");
        assert!(q.tags.is_empty());
        assert!(q.build_args.is_empty());
        assert!(!q.nocache);
    }

    #[test]
    fn rejects_traversal_paths() {
        assert!(!is_safe_relative(Path::new("../escape")));
        assert!(!is_safe_relative(Path::new("a/../../b")));
        assert!(!is_safe_relative(Path::new("/abs/path")));
        assert!(is_safe_relative(Path::new("Dockerfile")));
        assert!(is_safe_relative(Path::new("sub/dir/file")));
        assert!(is_safe_relative(Path::new("./rel")));
    }

    #[test]
    fn unpack_extracts_a_gzipped_tar() {
        // Build a tiny gzipped tar in-process and confirm it unpacks.
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let content = b"FROM alpine:3.20\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "Dockerfile", &content[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut gz = Vec::new();
        {
            use std::io::Write;
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            enc.write_all(&tar_buf).unwrap();
            enc.finish().unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        unpack_context(&gz, dir.path()).unwrap();
        let dockerfile = std::fs::read_to_string(dir.path().join("Dockerfile")).unwrap();
        assert_eq!(dockerfile, "FROM alpine:3.20\n");
    }

    #[test]
    fn ndjson_frame_appends_newline() {
        let f = ndjson_frame(&serde_json::json!({ "stream": "hi" }));
        assert_eq!(&f[..], b"{\"stream\":\"hi\"}\n" as &[u8]);
        assert_eq!(f[f.len() - 1], b'\n');
    }
}

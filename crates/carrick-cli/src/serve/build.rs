//! `POST /build`: the legacy (non-BuildKit) Docker Engine image-build endpoint.
//!
//! Unlike the buffered container endpoints, this streams an NDJSON response body
//! as the build runs. The request body is a gzipped tar of the build context; we
//! unpack it to a temp dir and run `carrick build` in-process on a blocking
//! worker, then forward its output as NDJSON frames. The build enters the
//! carrier directly; it does not spawn a CLI child.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use futures_util::stream::Stream;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::{Response, StatusCode};
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

pub(crate) const MAX_BUILD_CONTEXT_COMPRESSED_BYTES: usize = 16 * 1024 * 1024;
const MAX_BUILD_CONTEXT_DECOMPRESSED_BYTES: u64 = 32 * 1024 * 1024;
const MAX_BUILD_CONTEXT_ENTRIES: usize = 10_000;

fn invalid_context(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Resolve a link target against the canonical context root. Existing path
/// components are canonicalized, so an earlier symlink cannot hide an escape;
/// missing suffixes are retained for links to files created later in the tar.
fn resolved_link_target(base: &Path, link: &Path) -> io::Result<PathBuf> {
    let mut resolved = if link.is_absolute() {
        PathBuf::from("/")
    } else {
        base.to_path_buf()
    };
    for component in link.components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::Normal(name) => {
                resolved.push(name);
                if std::fs::symlink_metadata(&resolved).is_ok() {
                    resolved = std::fs::canonicalize(&resolved)?;
                }
            }
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Prefix(_) => return Err(invalid_context("unsupported link prefix")),
        }
    }
    Ok(resolved)
}

fn reject_symlink_parent(dest: &Path, path: &Path) -> io::Result<()> {
    let mut parent = dest.to_path_buf();
    if let Some(components) = path.parent() {
        for component in components.components() {
            if let Component::Normal(name) = component {
                parent.push(name);
                match std::fs::symlink_metadata(&parent) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(invalid_context("tar entry parent is a symlink"));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Ok(())
}

/// Unpack a bounded gzipped tar into an existing context directory. The tar
/// entry API performs its own canonical containment check via `unpack_in`.
fn unpack_context(gz_tar: &[u8], dest: &Path) -> std::io::Result<()> {
    if gz_tar.len() > MAX_BUILD_CONTEXT_COMPRESSED_BYTES {
        return Err(invalid_context("compressed build context is too large"));
    }
    let dest = std::fs::canonicalize(dest)?;
    let decoder = flate2::read::GzDecoder::new(gz_tar);
    let mut limited = decoder.take(MAX_BUILD_CONTEXT_DECOMPRESSED_BYTES + 1);
    {
        let mut archive = tar::Archive::new(&mut limited);
        let mut count = 0_usize;
        for entry in archive.entries()? {
            let mut entry = entry?;
            count += 1;
            if count > MAX_BUILD_CONTEXT_ENTRIES {
                return Err(invalid_context("build context has too many entries"));
            }
            let path = entry.path()?.into_owned();
            if !is_safe_relative(&path) {
                return Err(invalid_context(format!(
                    "unsafe tar entry path: {}",
                    path.display()
                )));
            }
            reject_symlink_parent(&dest, &path)?;
            let kind = entry.header().entry_type();
            if kind.is_symlink() || kind.is_hard_link() {
                let link = entry
                    .link_name()?
                    .ok_or_else(|| invalid_context("tar link has no target"))?;
                let base = if kind.is_symlink() {
                    dest.join(path.parent().unwrap_or_else(|| Path::new("")))
                } else {
                    dest.clone()
                };
                let target = resolved_link_target(&base, &link)?;
                if !target.starts_with(&dest) {
                    return Err(invalid_context("tar link escapes build context"));
                }
            } else if !kind.is_file() && !kind.is_dir() {
                return Err(invalid_context("unsupported tar entry type"));
            }
            if entry.size() > MAX_BUILD_CONTEXT_DECOMPRESSED_BYTES {
                return Err(invalid_context("build context entry is too large"));
            }
            if !entry.unpack_in(&dest)? {
                return Err(invalid_context("tar entry was not unpacked"));
            }
        }
    }
    io::copy(&mut limited, &mut io::sink())?;
    if limited.limit() == 0 {
        return Err(invalid_context("expanded build context is too large"));
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

fn build_error_response(status: StatusCode, message: &str) -> Response<BoxBody<Bytes, io::Error>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(
            Full::new(Bytes::from(
                serde_json::json!({ "message": message }).to_string(),
            ))
            .map_err(|never| match never {})
            .boxed(),
        )
        .unwrap_or_else(|_| {
            Response::new(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
        })
}

/// Validate and unpack the context before returning HTTP 200. Bad archive
/// entries are request errors; only the admitted build streams NDJSON.
pub(crate) async fn build_response(
    query: &str,
    body_bytes: Bytes,
) -> Response<BoxBody<Bytes, std::io::Error>> {
    let tmp = match tempfile::tempdir() {
        Ok(tmp) => tmp,
        Err(error) => {
            return build_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let ctx_dir = tmp.path().join("context");
    if let Err(error) = std::fs::create_dir(&ctx_dir) {
        return build_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let unpack = tokio::task::spawn_blocking(move || unpack_context(&body_bytes, &ctx_dir)).await;
    match unpack {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return build_error_response(
                StatusCode::BAD_REQUEST,
                &format!("invalid build context: {error}"),
            );
        }
        Err(error) => {
            return build_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    }
    let parsed = parse_build_query(query);
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(64);

    tokio::spawn(async move {
        run_build_streaming(parsed, tmp, tx).await;
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

/// Drive the admitted build, forward its
/// stdout/stderr line-by-line as `{"stream":...}` frames, and emit a terminal
/// aux/error frame. Sends frames into `tx`; the body stream ends when `tx` (and
/// thus the receiver) closes.
async fn run_build_streaming(
    parsed: BuildQuery,
    tmp: tempfile::TempDir,
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

    let ctx_dir = tmp.path().join("context");
    // Run the build in-process. `run_build` enters the unified carrier
    // directly; the API server never creates an intermediate CLI helper.
    let primary_tag = parsed.tags.first().cloned();
    let build_args = parsed
        .build_args
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    let tag_for_result = primary_tag
        .clone()
        .unwrap_or_else(|| "carrick-build:latest".to_owned());
    let _ = send_json(
        &tx,
        serde_json::json!({ "stream": format!("Building {tag_for_result} in the Carrick carrier\n") }),
    )
    .await;
    let build = tokio::task::spawn_blocking(move || {
        crate::commands::run_build(crate::commands::BuildArgs {
            store: &carrick_image::ImageStore::default_for_user(),
            tag: primary_tag,
            file: std::path::PathBuf::from(parsed.dockerfile),
            build_arg: build_args,
            no_cache: parsed.nocache,
            cache: false,
            cache_repo: None,
            platform: None,
            output: None,
            push: false,
            context: ctx_dir,
        })
    })
    .await;
    match build {
        Ok(Ok(())) => {
            let _ = send_json(
                &tx,
                serde_json::json!({ "stream": format!("Successfully built {tag_for_result}\n") }),
            )
            .await;
            let _ = send_json(&tx, serde_json::json!({ "aux": { "ID": tag_for_result } })).await;
        }
        Ok(Err(error)) => send_error(&tx, &format!("build failed: {error:#}")).await,
        Err(error) => send_error(&tx, &format!("build task failed: {error}")).await,
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
    use std::io::{Read, Write};

    fn gzip_tar(append: impl FnOnce(&mut tar::Builder<&mut Vec<u8>>)) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            append(&mut builder);
            builder.finish().unwrap();
        }
        let mut gz = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        encoder.write_all(&tar_buf).unwrap();
        encoder.finish().unwrap();
        gz
    }

    fn append_link(
        builder: &mut tar::Builder<&mut Vec<u8>>,
        name: &str,
        target: &Path,
        hard: bool,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(if hard {
            tar::EntryType::Link
        } else {
            tar::EntryType::Symlink
        });
        header.set_size(0);
        header.set_mode(0o644);
        header.set_link_name(target).unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, name, std::io::empty())
            .unwrap();
    }

    #[test]
    fn rejects_symlink_parent_escape_without_writing_outside() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("context");
        let outside = root.path().join("outside");
        std::fs::create_dir(&dest).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let gz = gzip_tar(|builder| {
            append_link(builder, "sub", &outside, false);
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "sub/x", &b"x"[..])
                .unwrap();
        });
        assert!(unpack_context(&gz, &dest).is_err());
        assert!(!outside.join("x").exists());
    }

    #[test]
    fn rejects_hardlink_to_file_outside_context() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("context");
        std::fs::create_dir(&dest).unwrap();
        let outside = root.path().join("host-file");
        std::fs::write(&outside, b"host").unwrap();
        let gz = gzip_tar(|builder| append_link(builder, "copied", &outside, true));
        assert!(unpack_context(&gz, &dest).is_err());
        assert!(!dest.join("copied").exists());
        assert_eq!(std::fs::read(&outside).unwrap(), b"host");
    }

    #[tokio::test]
    async fn outside_link_is_an_http_bad_request() {
        let root = tempfile::tempdir().unwrap();
        let gz = gzip_tar(|builder| append_link(builder, "sub", root.path(), false));
        let response = build_response("", Bytes::from(gz)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn accepts_links_wholly_inside_context() {
        let gz = gzip_tar(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, "file", &b"x"[..]).unwrap();
            append_link(builder, "hard", Path::new("file"), true);
            append_link(builder, "soft", Path::new("file"), false);
        });
        let dest = tempfile::tempdir().unwrap();
        unpack_context(&gz, dest.path()).unwrap();
        assert_eq!(std::fs::read(dest.path().join("hard")).unwrap(), b"x");
        assert_eq!(std::fs::read(dest.path().join("soft")).unwrap(), b"x");
    }

    #[test]
    fn rejects_gzip_expansion_past_context_cap() {
        let gz = gzip_tar(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_size(32 * 1024 * 1024 + 1);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "bomb",
                    std::io::repeat(0).take(32 * 1024 * 1024 + 1),
                )
                .unwrap();
        });
        let dest = tempfile::tempdir().unwrap();
        assert!(unpack_context(&gz, dest.path()).is_err());
    }

    #[test]
    fn rejects_context_entry_count_past_cap() {
        let gz = gzip_tar(|builder| {
            for index in 0..=MAX_BUILD_CONTEXT_ENTRIES {
                let mut header = tar::Header::new_gnu();
                header.set_size(0);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("file-{index}"), std::io::empty())
                    .unwrap();
            }
        });
        let dest = tempfile::tempdir().unwrap();
        assert!(unpack_context(&gz, dest.path()).is_err());
        assert!(
            !dest
                .path()
                .join(format!("file-{MAX_BUILD_CONTEXT_ENTRIES}"))
                .exists()
        );
    }

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

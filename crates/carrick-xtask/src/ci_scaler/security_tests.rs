#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

const SYNTHETIC_SECRET: &str = "synthetic-never-a-real-credential";

fn http_fixture() -> (String, std::thread::JoinHandle<String>) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/fixture", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "curl did not reach local fixture"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = vec![];
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let mut chunk = [0; 4096];
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0 && request.len() < 16384);
            request.extend_from_slice(&chunk[..count]);
        }
        let body = "{\"data\":{\"ok\":true}}";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        String::from_utf8(request).unwrap()
    });
    (url, worker)
}

fn ambient_trace(dir: &Path) -> PathBuf {
    let trace = dir.join("ambient.trace");
    std::fs::write(
        dir.join(".curlrc"),
        format!("trace-ascii = \"{}\"\n", trace.display()),
    )
    .unwrap();
    trace
}

#[test]
fn serial_host_authenticated_curl_controller_ignores_ambient_trace() {
    let dir = tempfile::tempdir().unwrap();
    let trace = ambient_trace(dir.path());
    let token = Token {
        id: "synthetic".into(),
        secret: SYNTHETIC_SECRET.into(),
    };
    // Control proves curl loads this ambient config and exposes the synthetic
    // Authorization header when its default-config loading is left enabled.
    let (url, server) = http_fixture();
    let mut control = pve_curl(&PveCall::Get, &url);
    let args: Vec<_> = control
        .get_args()
        .filter(|arg| *arg != "--disable")
        .map(|arg| arg.to_owned())
        .collect();
    control = Command::new("curl");
    control
        .args(args)
        .env("CURL_HOME", dir.path())
        .env("NO_PROXY", "127.0.0.1");
    execute(
        &mut control,
        request_config(&token, &PveCall::Get).unwrap().as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(server.join().unwrap().contains(SYNTHETIC_SECRET));
    let leaked: String = std::fs::read_to_string(&trace)
        .unwrap()
        .lines()
        .map(|line| {
            if line.len() >= 6
                && line.as_bytes()[..4].iter().all(u8::is_ascii_hexdigit)
                && &line[4..6] == ": "
            {
                &line[6..]
            } else {
                line
            }
        })
        .collect();
    assert!(leaked.contains(SYNTHETIC_SECRET));
    std::fs::remove_file(&trace).unwrap();
    for call in [
        PveCall::Get,
        PveCall::Post(json!({})),
        PveCall::Put(json!({})),
        PveCall::Delete,
    ] {
        let (url, server) = http_fixture();
        let mut command = pve_curl(&call, &url);
        command
            .env("CURL_HOME", dir.path())
            .env("NO_PROXY", "127.0.0.1");
        let response = execute(
            &mut command,
            request_config(&token, &call).unwrap().as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(pve_response(&response).unwrap()["ok"], true);
        assert!(server.join().unwrap().contains(SYNTHETIC_SECRET));
        assert!(
            !trace.exists(),
            "ambient config wrote the Authorization header"
        );
        assert_eq!(command.get_args().next().unwrap(), "--disable");
    }
}

#[test]
fn serial_host_authenticated_curl_template_ignores_ambient_trace() {
    let dir = tempfile::tempdir().unwrap();
    let trace = ambient_trace(dir.path());
    let token_path = dir.path().join("synthetic-token.json");
    std::fs::write(
        &token_path,
        json!({"full-tokenid":"synthetic","value":SYNTHETIC_SECRET}).to_string(),
    )
    .unwrap();
    let source = include_str!("../../../../scripts/ci/build-template-debian.sh");
    let function = source
        .split("pve_call() {\n")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    let (url, server) = http_fixture();
    let origin = url.strip_suffix("/fixture").unwrap();
    let function = function
        .replace("/root/carrick-ci-token.json", token_path.to_str().unwrap())
        .replace("https://willow.atxconsulting.com:8006/api2/json", origin);
    let script =
        format!("set -euo pipefail\npve_call() {{\n{function}\n}}\npve_call POST /fixture\n");
    execute(
        Command::new("/bin/bash")
            .args(["-c", &script])
            .env("CURL_HOME", dir.path())
            .env("NO_PROXY", "127.0.0.1"),
        &[],
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(server.join().unwrap().contains(SYNTHETIC_SECRET));
    assert!(
        !trace.exists(),
        "template curl loaded ambient trace configuration"
    );
    assert!(
        function.contains("curl --disable "),
        "--disable must be curl's first argument"
    );
}

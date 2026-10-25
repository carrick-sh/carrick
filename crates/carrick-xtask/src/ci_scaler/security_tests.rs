#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use std::os::unix::process::CommandExt;

const SYNTHETIC_SECRET: &str = "synthetic-never-a-real-credential";

#[test]
fn template_9000_destructive_permissions_are_rejected_in_every_site_profile() {
    for lane in [CloneLane::Kvm, CloneLane::Agent] {
        let site = site::CONTABO.for_lane(lane).unwrap();
        let result = verify_protected_vms(site, |vm| {
            Ok(if vm == 9000 {
                serde_json::json!({"/vms/9000": {"VM.PowerMgmt": 1}})
            } else {
                serde_json::json!({})
            })
        });
        assert!(
            result.is_err(),
            "destructive template rights admitted for {lane:?}"
        );
    }
}

#[test]
fn template_9000_clone_rights_never_license_other_protected_workers() {
    for lane in [CloneLane::Kvm, CloneLane::Agent] {
        let site = site::CONTABO.for_lane(lane).unwrap();
        assert!(
            verify_protected_vms(site, |vm| {
                Ok(if vm == 9000 {
                    serde_json::json!({"/vms/9000": {"VM.Audit": 1, "VM.Clone": 1}})
                } else {
                    serde_json::json!({})
                })
            })
            .is_ok()
        );
        assert!(
            verify_protected_vms(site, |vm| {
                Ok(serde_json::json!({format!("/vms/{vm}"): {"VM.Clone": 1}}))
            })
            .is_err()
        );
    }
}

#[test]
fn serial_host_execute_truncation_never_retains_partial_opaque_credential() {
    const CHILD: &str = "CARRICK_TEST_OPAQUE_STDERR_CHILD";
    const SECRET: &str = "opaque-fixture-secret-unknown-format";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ci_scaler::live::security_tests::serial_host_execute_truncation_never_retains_partial_opaque_credential",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("GH_TOKEN", SECRET)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "opaque credential fixture failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let err = execute(
        Command::new("/bin/sh").args([
            "-c",
            "printf 'useful diagnostic\\n' >&2; head -c 16358 /dev/zero | tr '\\000' x >&2; printf '%s' \"$GH_TOKEN\" >&2; exit 42",
        ]),
        &[],
        Duration::from_secs(60),
    )
    .unwrap_err();
    let rendered = format!("{err} {err:?}");
    assert!(rendered.contains("useful diagnostic"));
    assert!(
        !rendered.contains("opaque-f"),
        "stderr exposed an opaque credential fragment"
    );
}

fn request_complete(request: &[u8]) -> Option<usize> {
    let header_end = request.windows(4).position(|part| part == b"\r\n\r\n")? + 4;
    let headers = std::str::from_utf8(&request[..header_end]).ok()?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    Some(header_end + content_length)
}

fn http_fixture() -> (String, std::thread::JoinHandle<String>) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/fixture", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
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
        // BSD accept(2) copies O_NONBLOCK from the listener, so without this
        // a read before curl's request arrives fails with EAGAIN instead of
        // waiting for the read timeout below.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut request = vec![];
        while request_complete(&request).is_none_or(|total| request.len() < total) {
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
        stream.flush().unwrap();
        let _ = stream.shutdown(std::net::Shutdown::Write);
        String::from_utf8(request).unwrap()
    });
    (url, worker)
}

fn isolate_curl_env<'a>(command: &'a mut Command, dir: &Path) -> &'a mut Command {
    for var in [
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(var);
    }
    command
        .current_dir(dir)
        .env("HOME", dir)
        .env("CURL_HOME", dir)
        .env("TMPDIR", dir)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
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
    let mut control = pve_curl(
        &PveCall::Get,
        &super::site::WILLOW.api_resolve(),
        None,
        &url,
    );
    let args: Vec<_> = control
        .get_args()
        .filter(|arg| *arg != "--disable")
        .map(|arg| arg.to_owned())
        .collect();
    control = Command::new("curl");
    isolate_curl_env(control.args(args), dir.path());
    execute(
        &mut control,
        request_config(&token, &PveCall::Get).unwrap().as_bytes(),
        Duration::from_secs(60),
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
        let mut command = pve_curl(&call, &super::site::WILLOW.api_resolve(), None, &url);
        isolate_curl_env(&mut command, dir.path());
        let response = execute(
            &mut command,
            request_config(&token, &call).unwrap().as_bytes(),
            Duration::from_secs(60),
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
    // The endpoint comes from the site row; a silent no-op replacement would
    // send the synthetic secret nowhere and pass vacuously.
    const ENDPOINT: &str = "https://$api_host:8006/api2/json";
    assert!(function.contains(ENDPOINT) && function.contains("/root/carrick-ci-token.json"));
    let function = function
        .replace("/root/carrick-ci-token.json", token_path.to_str().unwrap())
        .replace(ENDPOINT, origin);
    let script = format!(
        "set -euo pipefail\napi_host=site.invalid\napi_ca_args=()\npve_call() {{\n{function}\n}}\npve_call POST /fixture\n"
    );
    let mut bash = Command::new("/bin/bash");
    isolate_curl_env(bash.args(["-c", &script]), dir.path());
    execute(&mut bash, &[], Duration::from_secs(60)).unwrap();
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

#[derive(Copy, Clone, PartialEq)]
enum Interruption {
    AfterStop,
    AfterRunnerRemoval,
}
struct MockTeardown {
    vm: Option<Vm>,
    stopped: bool,
    registered: bool,
    name: String,
    interruption: Option<Interruption>,
    events: Vec<&'static str>,
}
impl TeardownApi for MockTeardown {
    fn present(&mut self, _: &Record) -> Result<bool, ScalerError> {
        Ok(self.vm.is_some())
    }
    fn stop(&mut self, row: &Record, _: &Path) -> Result<Option<String>, ScalerError> {
        row.guard(self.vm.as_ref().unwrap())?;
        if self.stopped {
            return Ok(None);
        }
        self.stopped = true;
        self.events.push("stop");
        if self.interruption == Some(Interruption::AfterStop) {
            self.interruption = None;
            return Err(ScalerError::External("fixture interruption after VM stop"));
        }
        Ok(Some("stop-task".into()))
    }
    fn destroy(&mut self, row: &Record) -> Result<String, ScalerError> {
        row.guard(self.vm.as_ref().unwrap())?;
        assert!(self.stopped);
        self.events.push("destroy");
        self.vm = None;
        Ok("destroy-task".into())
    }
    fn wait_task(&mut self, _: &str) -> Result<(), ScalerError> {
        Ok(())
    }
    fn remove_runner(&mut self, row: &Record) -> Result<(), ScalerError> {
        assert_eq!(row.name, self.name);
        assert!(
            self.vm.is_none(),
            "registration was removed before VM teardown"
        );
        if self.registered {
            self.events.push("remove runner");
            self.registered = false;
            if self.interruption == Some(Interruption::AfterRunnerRemoval) {
                self.interruption = None;
                return Err(ScalerError::External(
                    "fixture interruption after runner removal",
                ));
            }
        }
        Ok(())
    }
}
fn teardown_fixture(dir: &Path) -> (Ledger, Record, MockTeardown, PathBuf) {
    let mut ledger = Ledger::default();
    let mut row = ledger
        .reserve(
            JobKey {
                run: RunId(1),
                attempt: 1,
                job: JobId(2),
            },
            &[],
            0,
            Concurrency::ONE,
        )
        .unwrap();
    row.state = State::Reaping;
    row.runner = Some(RunnerId(30));
    // No actual assignment was observed, as in the review's leaked clone.
    ledger.rows[0] = row.clone();
    let path = dir.join("ledger.json");
    ledger.save(&path).unwrap();
    let api = MockTeardown {
        vm: Some(Vm {
            id: 308,
            name: row.name.clone(),
            pool: POOL.into(),
            template: false,
        }),
        stopped: false,
        registered: true,
        name: row.name.clone(),
        interruption: None,
        events: vec![],
    };
    (ledger, row, api, path)
}

#[test]
fn teardown_resumes_actual_crashes_after_vm_stop_and_runner_removal() {
    for interruption in [Interruption::AfterStop, Interruption::AfterRunnerRemoval] {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, mut row, mut api, path) = teardown_fixture(dir.path());
        api.interruption = Some(interruption);
        assert!(continue_teardown(&mut api, &mut ledger, &mut row, dir.path(), &path).is_err());
        let mut ledger = Ledger::load(&path).unwrap();
        let mut row = ledger.rows[0].clone();
        assert_eq!(row.state, State::Reaping);
        assert!(row.assigned.is_none());
        let recovery = recovery_decision(
            &row,
            api.vm.is_some(),
            if row.task.is_some() {
                TaskState::Succeeded
            } else {
                TaskState::Absent
            },
            1,
        );
        assert_eq!(
            recovery,
            if api.vm.is_some() {
                Recovery::ResumeReaping
            } else {
                Recovery::FinishAbsent
            }
        );
        assert!(continue_teardown(&mut api, &mut ledger, &mut row, dir.path(), &path).unwrap());
        assert_eq!(api.events, ["stop", "destroy", "remove runner"]);
        assert!(!api.registered && api.vm.is_none());
        assert_eq!(Ledger::load(&path).unwrap().rows[0].state, State::Destroyed);
    }
}

#[test]
fn teardown_resumes_legacy_runner_removal_with_vm_still_present() {
    for stopped in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, mut row, mut api, path) = teardown_fixture(dir.path());
        api.registered = false;
        api.stopped = stopped;
        assert!(continue_teardown(&mut api, &mut ledger, &mut row, dir.path(), &path).unwrap());
        assert!(api.vm.is_none());
        assert_eq!(api.events.last(), Some(&"destroy"));
        assert_eq!(Ledger::load(&path).unwrap().rows[0].state, State::Destroyed);
    }
}

#[test]
fn teardown_requires_durable_license_and_all_ownership_guards() {
    let dir = tempfile::tempdir().unwrap();
    let (mut ledger, mut row, mut api, path) = teardown_fixture(dir.path());
    row.state = State::Running;
    assert!(continue_teardown(&mut api, &mut ledger, &mut row, dir.path(), &path).is_err());
    row.state = State::Reaping;
    let unwritable_ledger = dir.path().join("missing-parent/ledger.json");
    assert!(
        continue_teardown(
            &mut api,
            &mut ledger,
            &mut row,
            dir.path(),
            &unwritable_ledger
        )
        .is_err()
    );
    assert!(
        api.events.is_empty(),
        "failed durable publication allowed side effects"
    );
    for vm in [
        Vm {
            id: 105,
            name: row.name.clone(),
            pool: POOL.into(),
            template: false,
        },
        Vm {
            id: 308,
            name: row.name.clone(),
            pool: "other".into(),
            template: false,
        },
        Vm {
            id: 308,
            name: "different-owner".into(),
            pool: POOL.into(),
            template: false,
        },
        Vm {
            id: 308,
            name: row.name.clone(),
            pool: POOL.into(),
            template: true,
        },
    ] {
        api.vm = Some(vm);
        assert!(continue_teardown(&mut api, &mut ledger, &mut row, dir.path(), &path).is_err());
        assert!(api.events.is_empty());
    }
}

#[test]
fn http_fixture_drains_split_post_body_before_closing_connection() {
    let (url, server) = http_fixture();
    let addr = url
        .strip_prefix("http://")
        .unwrap()
        .strip_suffix("/fixture")
        .unwrap();
    let mut client = std::net::TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    write!(
        client,
        "POST /fixture HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: PVEAPIToken=synthetic={SYNTHETIC_SECRET}\r\nContent-Length: 2\r\n\r\n"
    )
    .unwrap();
    client.flush().unwrap();
    std::thread::sleep(Duration::from_millis(25));
    client.write_all(b"{}").unwrap();
    client.flush().unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.contains("HTTP/1.1 200 OK"));
    let captured = server.join().unwrap();
    assert!(
        captured.ends_with("\r\n\r\n{}"),
        "fixture closed before reading Content-Length body: {captured:?}"
    );
}

#[test]
fn serial_host_execute_retains_bounded_redacted_stderr_and_strips_library_paths() {
    let token = Token {
        id: "synthetic-id".into(),
        secret: SYNTHETIC_SECRET.into(),
    };
    let config = request_config(&token, &PveCall::Get).unwrap();
    let absent_secret = "absent-from-input-secret";
    let script = format!(
        "printf 'Authorization: Bearer {absent_secret}\\n'; printf 'curl: (22) permission denied\\nAuthorization: Bearer {absent_secret}\\nPVEAPIToken=synthetic-id={SYNTHETIC_SECRET}\\n' >&2; exit 22"
    );
    let err = execute(
        Command::new("/bin/sh").args(["-c", &script]),
        config.as_bytes(),
        Duration::from_secs(60),
    )
    .unwrap_err();
    let rendered = format!("{err} | {err:?}");
    assert!(err.to_string().contains("sh exited with code 22"));
    assert!(err.to_string().contains("curl: (22) permission denied"));
    assert!(
        !rendered.contains(SYNTHETIC_SECRET) && !rendered.contains(absent_secret),
        "error included credentials: {rendered}"
    );

    let sig_err = execute(
        Command::new("/bin/sh").args([
            "-c",
            &format!(
                "printf 'runner stopped\\nAuthorization: Bearer {absent_secret}\\n' >&2; kill -9 $$"
            ),
        ]),
        &[],
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert!(sig_err.to_string().contains("sh killed by signal 9"));
    assert!(sig_err.to_string().contains("runner stopped"));
    assert!(!format!("{sig_err:?}").contains(absent_secret));

    let mut readiness_pipe = TestPipe::new().unwrap();
    let readiness_write_fd = readiness_pipe.write_fd;

    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        &format!(
            "printf 'waiting for runner\\nAuthorization: Bearer {absent_secret}\\n' >&2; printf ready >&3; exec sleep 5"
        ),
    ]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(readiness_write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let timeout_err =
        execute_with_readiness(&mut command, &[], Duration::from_millis(50), |_child_pid| {
            readiness_pipe.close_write();
            wait_for_pipe_readiness(readiness_pipe.read_fd, Duration::from_secs(60))
        })
        .unwrap_err();
    assert!(timeout_err.to_string().contains("sh timed out after 50ms"));
    assert!(timeout_err.to_string().contains("waiting for runner"));
    assert!(!format!("{timeout_err:?}").contains(absent_secret));

    let bounded_err = execute(
        Command::new("/bin/sh").args([
            "-c",
            "printf 'runner diagnostic\\n' >&2; head -c 131072 /dev/zero >&2; exit 23",
        ]),
        &[],
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert!(bounded_err.to_string().contains("runner diagnostic"));
    assert!(bounded_err.to_string().len() <= 17 * 1024);

    // Writing > 64 KiB to stderr must not SIGPIPE the child.
    let large_stderr = execute(
        Command::new("/bin/sh").args(["-c", "head -c 131072 /dev/zero >&2; printf ok"]),
        &[],
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(large_stderr, b"ok");

    let out = execute(
        Command::new("/bin/sh")
            .args([
                "-c",
                "printf '%s%s%s' \"${LD_LIBRARY_PATH:-}\" \"${DYLD_LIBRARY_PATH:-}\" \"${DYLD_FALLBACK_LIBRARY_PATH:-}\"",
            ])
            .env("LD_LIBRARY_PATH", "/nonexistent/cargo/target/debug/deps")
            .env("DYLD_LIBRARY_PATH", "/nonexistent/cargo/target/debug/deps")
            .env(
                "DYLD_FALLBACK_LIBRARY_PATH",
                "/nonexistent/cargo/target/debug/deps",
            ),
        &[],
        Duration::from_secs(60),
    )
    .unwrap();
    assert!(
        out.is_empty(),
        "execute must strip ambient LD/DYLD library paths for external binaries"
    );
}

struct TestPipe {
    read_fd: libc::c_int,
    write_fd: libc::c_int,
}

impl TestPipe {
    fn new() -> Result<Self, ScalerError> {
        let mut fds = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(ScalerError::Io(std::io::Error::last_os_error()));
        }
        let make_fd = |raw_fd: libc::c_int| -> Result<libc::c_int, ScalerError> {
            let high_fd = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD, 10) };
            if high_fd < 0 {
                return Err(ScalerError::Io(std::io::Error::last_os_error()));
            }
            unsafe {
                libc::fcntl(high_fd, libc::F_SETFD, libc::FD_CLOEXEC);
                libc::close(raw_fd);
            }
            Ok(high_fd)
        };
        let read_fd = make_fd(fds[0])?;
        let write_fd = make_fd(fds[1])?;
        Ok(Self { read_fd, write_fd })
    }

    fn close_write(&mut self) {
        if self.write_fd >= 0 {
            unsafe { libc::close(self.write_fd) };
            self.write_fd = -1;
        }
    }

    fn close_read(&mut self) {
        if self.read_fd >= 0 {
            unsafe { libc::close(self.read_fd) };
            self.read_fd = -1;
        }
    }
}

impl Drop for TestPipe {
    fn drop(&mut self) {
        self.close_read();
        self.close_write();
    }
}

fn wait_for_pipe_readiness(read_fd: libc::c_int, limit: Duration) -> Result<(), ScalerError> {
    let mut pollfd = libc::pollfd {
        fd: read_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = libc::c_int::try_from(limit.as_millis()).unwrap_or(libc::c_int::MAX);
    let ret = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
    if ret < 0 {
        return Err(ScalerError::Io(std::io::Error::last_os_error()));
    }
    if ret == 0 {
        return Err(ScalerError::External("readiness signal timed out"));
    }
    let mut buf = [0u8; 1];
    let n = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        return Err(ScalerError::Io(std::io::Error::last_os_error()));
    }
    if n == 0 {
        return Err(ScalerError::External("child exited before readiness"));
    }
    Ok(())
}

#[test]
fn serial_host_execute_timeout_retains_stderr_when_child_is_descheduled_before_first_write() {
    let absent_secret = "absent-from-input-secret";
    let mut readiness_pipe = TestPipe::new().unwrap();
    let mut gate_pipe = TestPipe::new().unwrap();
    let readiness_write_fd = readiness_pipe.write_fd;
    let gate_read_fd = gate_pipe.read_fd;

    // Hold the child behind an event-driven gate before its first write, so
    // that descheduling the child (SIGSTOP) and keeping it stopped for longer
    // than the timeout limit proves that deadline execution is synchronized
    // on readiness rather than racing against host scheduling delays.
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        &format!(
            "read dummy <&4 || true; printf 'waiting for runner\\nAuthorization: Bearer {absent_secret}\\n' >&2; printf ready >&3; exec sleep 5"
        ),
    ]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(readiness_write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(gate_read_fd, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let timeout_err =
        execute_with_readiness(&mut command, &[], Duration::from_millis(50), |child_pid| {
            readiness_pipe.close_write();
            gate_pipe.close_read();
            let pid = i32::try_from(child_pid).unwrap();
            unsafe {
                assert_eq!(libc::kill(pid, libc::SIGSTOP), 0);
            }
            // Open the gate while the child is stopped. The child cannot
            // proceed until SIGCONT is delivered.
            gate_pipe.close_write();
            // Keep the child stopped longer than the 50ms command limit to
            // prove no timeout fires prematurely.
            std::thread::sleep(Duration::from_millis(150));
            unsafe {
                assert_eq!(libc::kill(pid, libc::SIGCONT), 0);
            }
            wait_for_pipe_readiness(readiness_pipe.read_fd, Duration::from_secs(60))
        })
        .unwrap_err();
    assert!(timeout_err.to_string().contains("sh timed out after 50ms"));
    assert!(timeout_err.to_string().contains("waiting for runner"));
    assert!(!format!("{timeout_err:?}").contains(absent_secret));
}

fn startup_fixture(agents: bool, pooled: bool, rights: Value) -> Result<(), ScalerError> {
    let mut inventory = pool_inventory(
        &json!({"poolid":"carrick-ci", "members":[
            {"type":"qemu","node":"carrick-ctb","vmid":300,"template":1}
        ]}),
        "carrick-ctb",
    )
    .unwrap();
    if pooled {
        inventory.push(PoolMember {
            id: 9000,
            pool: POOL.into(),
            template: true,
        });
    }
    let lanes = if agents {
        vec![CloneLane::Kvm, CloneLane::Agent]
    } else {
        vec![CloneLane::Kvm]
    };
    let mut firewalls = Vec::new();
    let result = verify_startup(
        site::CONTABO,
        &lanes,
        &inventory,
        |path| {
            Ok(match path {
                "/nodes/carrick-ctb/qemu/300/config" => json!({
                    "template":1,"cpu":"host","cores":8,"memory":"16384","allow-ksm":0,
                    "scsi0":"local:300/base-300-disk-0.qcow2,size=100G",
                    "net0":"virtio,bridge=vmbr1,firewall=1"
                }),
                "/nodes/carrick-ctb/qemu/9000/config" if agents => json!({
                    "template":1,"cpu":"host","cores":8,"memory":"20480","allow-ksm":0,
                    "scsi0":"local:9000/base-9000-disk-0.qcow2,size=100G",
                    "net0":"virtio,bridge=vmbr1,firewall=1"
                }),
                "/access/permissions?path=/vms/9000" => rights.clone(),
                "/access/permissions?path=/vms/101"
                | "/access/permissions?path=/vms/102"
                | "/access/permissions?path=/vms/103"
                | "/access/permissions?path=/vms/104" => json!({}),
                _ => panic!("unexpected startup request: {path}"),
            })
        },
        |vm| {
            firewalls.push(vm);
            Ok(())
        },
    );
    if result.is_ok() {
        assert_eq!(firewalls, if agents { vec![300, 9000] } else { vec![300] });
    }
    result
}

#[test]
fn startup_agent_source_outside_pool() {
    startup_fixture(
        true,
        false,
        json!({"/vms/9000":{"VM.Audit":1,"VM.Clone":1}}),
    )
    .unwrap();
}

#[test]
fn startup_agent_source_inside_pool_refused() {
    let error = startup_fixture(
        true,
        true,
        json!({"/vms/9000":{
            "VM.Audit":1,"VM.Clone":1,"VM.PowerMgmt":1,"VM.Config.CPU":1
        }}),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            ScalerError::Guard("agent template must be outside carrick-ci")
        ),
        "{error}"
    );
}

#[test]
fn startup_kvm_only_unchanged() {
    startup_fixture(false, false, json!({})).unwrap();
    startup_fixture(
        false,
        false,
        json!({"/vms/9000":{"VM.Audit":1,"VM.Clone":1}}),
    )
    .unwrap();
}

#[test]
fn startup_agent_source_requires_both_rights() {
    for rights in [
        json!({}),
        json!({"/vms/9000":{"VM.Audit":1}}),
        json!({"/vms/9000":{"VM.Clone":1}}),
    ] {
        assert!(matches!(
            startup_fixture(true, false, rights),
            Err(ScalerError::Guard(
                "token has unexpected protected-VM rights"
            ))
        ));
    }
}

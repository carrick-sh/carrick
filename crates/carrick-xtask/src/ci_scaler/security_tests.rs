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

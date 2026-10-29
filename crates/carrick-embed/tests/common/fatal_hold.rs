//! Fatal-hold policy for the signed embed harness. Kept dependency-free so
//! its unit tests also run in the portable xtask test suite.
pub(super) fn arm_from_env(arm_debugger_hold: impl FnOnce(u32)) {
    let value = std::env::var("CARRICK_FATAL_HOLD_SECS").ok();
    arm(value.as_deref(), arm_debugger_hold);
}

fn arm(value: Option<&str>, arm_debugger_hold: impl FnOnce(u32)) {
    if let Some(value) = value
        && let Ok(secs) = value.trim().parse::<u32>()
        && secs > 0
    {
        arm_debugger_hold(secs);
    }
}

#[cfg(test)]
mod serial_host {
    #![allow(clippy::unwrap_used, clippy::panic)]
    #[test]
    fn harness_reads_hold_environment() {
        if std::env::var_os("CARRICK_FATAL_HOLD_TEST_CHILD").is_some() {
            let mut armed = None;
            super::arm_from_env(|secs| armed = Some(secs));
            let expected = std::env::var("CARRICK_FATAL_HOLD_TEST_EXPECTED")
                .ok()
                .and_then(|value| value.parse::<u32>().ok());
            assert_eq!(armed, expected);
            return;
        }
        for value in [None, Some("60")] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .arg("harness_reads_hold_environment")
                .arg("--nocapture")
                .env("CARRICK_FATAL_HOLD_TEST_CHILD", "1")
                .env_remove("CARRICK_FATAL_HOLD_SECS")
                .env_remove("CARRICK_FATAL_HOLD_TEST_EXPECTED");
            if let Some(value) = value {
                command
                    .env("CARRICK_FATAL_HOLD_SECS", value)
                    .env("CARRICK_FATAL_HOLD_TEST_EXPECTED", value);
            }
            let mut child = command.spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let reap_deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(1);
                    while std::time::Instant::now() < reap_deadline {
                        if child.try_wait().unwrap().is_some() {
                            break;
                        }
                        std::thread::yield_now();
                    }
                    panic!("environment test child exceeded deadline");
                }
                // External child status observation, no guest coordination.
                const CHILD_OBSERVATION: std::time::Duration = std::time::Duration::from_millis(10);
                std::thread::sleep(CHILD_OBSERVATION);
            }
        }
    }

    #[test]
    fn harness_arms_hold_only_with_positive_env_value() {
        for (value, expected) in [
            (None, None),
            (Some("0"), None),
            (Some("invalid"), None),
            (Some("-1"), None),
            (Some("4294967296"), None),
            (Some(" 60 "), Some(60)),
        ] {
            let mut armed = None;
            super::arm(value, |secs| armed = Some(secs));
            assert_eq!(armed, expected, "CARRICK_FATAL_HOLD_SECS={value:?}");
        }
    }
}

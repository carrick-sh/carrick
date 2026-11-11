use std::os::unix::fs::PermissionsExt;

fn raw_pair(dir: &std::path::Path) {
    let script = dir.join("tool");
    // ruleid: carrick-test-executable-write-then-exec
    std::fs::write(&script, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn raw_copy(from: &std::path::Path, dir: &std::path::Path) {
    let copy = dir.join("copy");
    // ruleid: carrick-test-executable-write-then-exec
    std::fs::copy(from, &copy).unwrap();
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn helper(dir: &std::path::Path) {
    let script = dir.join("tool");
    // ok: carrick-test-executable-write-then-exec
    carrick_test_support::executable::write_executable(&script, "#!/bin/sh\n");
}

fn data_file(dir: &std::path::Path) {
    let policy = dir.join("policy");
    // ok: carrick-test-executable-write-then-exec
    std::fs::write(&policy, "data").unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();
}

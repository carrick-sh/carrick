use std::os::unix::fs::PermissionsExt;
fn raw(path: &std::path::Path) {
    std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    // ruleid: carrick-no-raw-executable-fixture
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::process::Command::new(path).status().unwrap();
}
fn alias(path: &std::path::Path) {
    use std::fs;
    fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    // ruleid: carrick-no-raw-executable-fixture
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    std::process::Command::new(path).status().unwrap();
}
fn safe(path: &std::path::Path) {
    // ok: carrick-no-raw-executable-fixture
    carrick_test_support::write_executable(path, "#!/bin/sh\nexit 0\n", 0o700).unwrap();
    std::process::Command::new(path).status().unwrap();
}
fn data(path: &std::path::Path) {
    std::fs::write(path, "data").unwrap();
    // ok: carrick-no-raw-executable-fixture
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

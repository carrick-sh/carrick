use assert_cmd::Command;

#[test]
fn serve_help_lists_docker_api_flag() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args(["serve", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--docker-api"));
}

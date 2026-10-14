use carrick_xtask::cli;
use carrick_xtask::commit_trailers::validate_commit_message;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn canonical_claude_trailers_pass() {
    let cases = [
        "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
        "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>",
        "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>",
        "Co-Authored-By: Claude <noreply@anthropic.com>",
        "Co-Authored-By: Anthropic Assistant <noreply@anthropic.com>",
    ];

    for case in cases {
        let msg = format!("feat(core): update kernel\n\nWhy: testing\n\n{case}\n");
        let violations = validate_commit_message("test-commit", &msg);
        assert!(
            violations.is_empty(),
            "expected '{case}' to pass, got violations: {violations:?}"
        );
    }
}

#[test]
fn canonical_openai_trailers_pass() {
    let cases = [
        "Co-Authored-By: Codex <noreply@openai.com>",
        "Co-Authored-By: GPT-6 <noreply@openai.com>",
        "Co-Authored-By: GPT-6.1 Sol <noreply@openai.com>",
        "Co-Authored-By: OpenAI Codex <noreply@openai.com>",
        "Co-Authored-By: ChatGPT <noreply@openai.com>",
    ];

    for case in cases {
        let msg = format!("feat(core): update kernel\n\nWhy: testing\n\n{case}\n");
        let violations = validate_commit_message("test-commit", &msg);
        assert!(
            violations.is_empty(),
            "expected '{case}' to pass, got violations: {violations:?}"
        );
    }
}

#[test]
fn canonical_google_trailers_pass() {
    let cases = [
        "Co-Authored-By: Gemini <noreply@google.com>",
        "Co-Authored-By: Gemini 4 Argon <noreply@google.com>",
        "Co-Authored-By: Gemini 3.8 Flash <noreply@google.com>",
        "Co-Authored-By: Antigravity <noreply@google.com>",
        "Co-Authored-By: Google Antigravity <noreply@google.com>",
    ];

    for case in cases {
        let msg = format!("feat(core): update kernel\n\nWhy: testing\n\n{case}\n");
        let violations = validate_commit_message("test-commit", &msg);
        assert!(
            violations.is_empty(),
            "expected '{case}' to pass, got violations: {violations:?}"
        );
    }
}

#[test]
fn canonical_human_coauthors_pass() {
    let cases = [
        "Co-Authored-By: Timothy J Fontaine <tjfontaine@atxconsulting.com>",
        "Co-Authored-By: Alice Smith <alice.smith@example.org>",
        "Co-Authored-By: Bob Jones <bob@developer.net>",
        "Co-Authored-By: Someone <person@company.co.uk>",
    ];

    for case in cases {
        let msg = format!("docs: improve guide\n\nExplanation here.\n\n{case}\n");
        let violations = validate_commit_message("test-commit", &msg);
        assert!(
            violations.is_empty(),
            "expected human co-author '{case}' to pass, got: {violations:?}"
        );
    }
}

#[test]
fn commit_without_trailers_passes() {
    let msg = "chore: clean up whitespace\n\nWhy: tidiness\n\nWhat: remove spaces\n";
    let violations = validate_commit_message("test-commit", msg);
    assert!(
        violations.is_empty(),
        "clean commit without trailers should pass"
    );
}

#[test]
fn commit_with_other_trailers_and_multiple_coauthors_passes() {
    let msg = "feat(vfs): add devpts\n\nWhy: pty support\n\nSigned-off-by: Dev <dev@company.com>\nCloses #123\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\nCo-Authored-By: Gemini <noreply@google.com>\n";
    let violations = validate_commit_message("test-commit", msg);
    assert!(
        violations.is_empty(),
        "valid multi-trailer commit should pass"
    );
}

#[test]
fn prose_mentioning_coauthor_is_ignored() {
    let msg = "docs: update contributor guide\n\n- Make the Co-Authored-By rule tool-neutral\n- Remember to add Co-Authored-By trailers\n\nCo-Authored-By: Antigravity <noreply@google.com>\n";
    let violations = validate_commit_message("test-commit", msg);
    assert!(
        violations.is_empty(),
        "bullet points mentioning Co-Authored-By should not trigger violations"
    );
}

#[test]
fn comments_in_commit_msg_are_ignored() {
    let msg = "# Please enter the commit message for your changes.\n# Co-authored-by: Ignored <bad@bad.com>\nfeat(test): valid title\n\nCo-Authored-By: Antigravity <noreply@google.com>\n";
    let violations = validate_commit_message("test-commit", msg);
    assert!(
        violations.is_empty(),
        "comment lines starting with # should be ignored"
    );
}

#[test]
fn bad_form_co_authored_by_casing_fails() {
    let bad_cases = [
        "Co-authored-by: Claude Opus 5.5 <noreply@anthropic.com>",
        "co-authored-by: Codex <noreply@openai.com>",
        "CO-AUTHORED-BY: Gemini <noreply@google.com>",
        "Co-Authored-by: Antigravity <noreply@google.com>",
        "Co-authored-by: <noreply@google.com>",
        "Co-authored-by",
    ];

    for line in bad_cases {
        let msg = format!("feat: bad key casing\n\n{line}\n");
        let violations = validate_commit_message("test-sha", &msg);
        assert_eq!(
            violations.len(),
            1,
            "expected '{line}' to fail casing check, got: {violations:?}"
        );
        let v = &violations[0];
        assert_eq!(v.commit_id, "test-sha");
        assert_eq!(v.offending_line, line);
        assert!(
            v.expected.contains("Co-Authored-By"),
            "expected expected string to specify exact Co-Authored-By, got: {}",
            v.expected
        );
    }
}

#[test]
fn bad_form_codex_at_openai_fails() {
    let msg = "fix: test\n\nCo-Authored-By: Codex <codex@openai.com>\n";
    let violations = validate_commit_message("test-sha", msg);
    assert_eq!(violations.len(), 1);
    let v = &violations[0];
    assert_eq!(v.offending_line, "Co-Authored-By: Codex <codex@openai.com>");
    assert!(
        v.expected.contains("noreply@openai.com"),
        "expected noreply@openai.com in expected, got: {}",
        v.expected
    );
}

#[test]
fn bad_form_agy_at_google_fails() {
    let msg = "fix: test\n\nCo-Authored-By: Antigravity <agy@google.com>\n";
    let violations = validate_commit_message("test-sha", msg);
    assert_eq!(violations.len(), 1);
    let v = &violations[0];
    assert_eq!(
        v.offending_line,
        "Co-Authored-By: Antigravity <agy@google.com>"
    );
    assert!(
        v.expected.contains("noreply@google.com"),
        "expected noreply@google.com in expected, got: {}",
        v.expected
    );
}

#[test]
fn bad_form_antigravity_at_google_fails() {
    let msg = "fix: test\n\nCo-Authored-By: Antigravity <antigravity@google.com>\n";
    let violations = validate_commit_message("test-sha", msg);
    assert_eq!(violations.len(), 1);
    let v = &violations[0];
    assert_eq!(
        v.offending_line,
        "Co-Authored-By: Antigravity <antigravity@google.com>"
    );
    assert!(
        v.expected.contains("noreply@google.com"),
        "expected noreply@google.com in expected, got: {}",
        v.expected
    );
}

#[test]
fn bad_form_gemini_at_google_fails() {
    let msg = "fix: test\n\nCo-Authored-By: Gemini <gemini@google.com>\n";
    let violations = validate_commit_message("test-sha", msg);
    assert_eq!(violations.len(), 1);
    let v = &violations[0];
    assert_eq!(
        v.offending_line,
        "Co-Authored-By: Gemini <gemini@google.com>"
    );
    assert!(
        v.expected.contains("noreply@google.com"),
        "expected noreply@google.com in expected, got: {}",
        v.expected
    );
}

#[test]
fn bad_form_noreply_at_example_fails() {
    // Both vendor agent and human using noreply@example.com fail
    let cases = [
        (
            "Co-Authored-By: Claude <noreply@example.com>",
            "noreply@anthropic.com",
        ),
        (
            "Co-Authored-By: Someone <noreply@example.com>",
            "personal email",
        ),
    ];

    for (line, expected_needle) in cases {
        let msg = format!("fix: test\n\n{line}\n");
        let violations = validate_commit_message("test-sha", &msg);
        assert_eq!(violations.len(), 1, "expected '{line}' to fail");
        let v = &violations[0];
        assert_eq!(v.offending_line, line);
        assert!(
            v.expected.contains(expected_needle),
            "expected '{expected_needle}' in '{}'",
            v.expected
        );
    }
}

#[test]
fn bad_form_support_at_openai_fails() {
    let msg = "fix: test\n\nCo-Authored-By: Support Agent <support@openai.com>\n";
    let violations = validate_commit_message("test-sha", msg);
    assert_eq!(violations.len(), 1);
    let v = &violations[0];
    assert_eq!(
        v.offending_line,
        "Co-Authored-By: Support Agent <support@openai.com>"
    );
    assert!(
        v.expected.contains("noreply@openai.com"),
        "expected noreply@openai.com in expected, got: {}",
        v.expected
    );
}

#[test]
fn bad_form_bare_noreply_fails() {
    let cases = [
        "Co-Authored-By: Codex <noreply>",
        "Co-Authored-By: Jane Doe <noreply>",
    ];

    for line in cases {
        let msg = format!("fix: test\n\n{line}\n");
        let violations = validate_commit_message("test-sha", &msg);
        assert_eq!(violations.len(), 1, "expected '{line}' to fail");
        let v = &violations[0];
        assert_eq!(v.offending_line, line);
    }
}

#[test]
fn bad_form_empty_name_fails() {
    let cases = [
        "Co-Authored-By: <noreply@google.com>",
        "Co-Authored-By:   <noreply@google.com>",
    ];

    for line in cases {
        let msg = format!("fix: test\n\n{line}\n");
        let violations = validate_commit_message("test-sha", &msg);
        assert_eq!(violations.len(), 1, "expected '{line}' to fail");
        let v = &violations[0];
        assert_eq!(v.offending_line, line);
        assert!(v.expected.contains("non-empty name"));
    }
}

#[test]
fn cli_check_message_valid_file_passes() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        "feat(core): good commit\n\nWhy: test\n\nCo-Authored-By: Gemini <noreply@google.com>\n"
    )
    .unwrap();

    let mut out = Vec::new();
    let res = cli::run_with_writer(
        [
            "carrick-xtask",
            "commit-trailers",
            "check-message",
            file.path().to_str().unwrap(),
        ],
        &mut out,
    );
    assert!(res.is_ok(), "check-message should succeed on valid file");
}

#[test]
fn cli_check_message_invalid_file_fails_with_details() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        "feat(core): bad commit\n\nWhy: test\n\nCo-Authored-By: Codex <codex@openai.com>\n"
    )
    .unwrap();

    let mut out = Vec::new();
    let res = cli::run_with_writer(
        [
            "carrick-xtask",
            "commit-trailers",
            "check-message",
            file.path().to_str().unwrap(),
        ],
        &mut out,
    );
    assert!(res.is_err(), "check-message must fail on invalid file");
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("offending line 'Co-Authored-By: Codex <codex@openai.com>'"),
        "error should contain offending line: {err}"
    );
    assert!(
        err.contains("expected 'Co-Authored-By: Codex <noreply@openai.com>'"),
        "error should contain expected form: {err}"
    );
}

#[test]
fn cli_check_range_invalid_range_fails() {
    let mut out = Vec::new();
    let res = cli::run_with_writer(
        [
            "carrick-xtask",
            "commit-trailers",
            "check-range",
            "nonexistent-ref-a..nonexistent-ref-b",
        ],
        &mut out,
    );
    assert!(res.is_err(), "check-range must fail on non-existent refs");
}

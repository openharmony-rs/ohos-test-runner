use std::process::Command;

#[test]
fn prints_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_ohos-test-runner"))
        .arg("--version")
        .output()
        .expect("failed to run ohos-test-runner");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        format!("ohos-test-runner {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn prints_help() {
    for flag in ["--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ohos-test-runner"))
            .arg(flag)
            .output()
            .expect("failed to run ohos-test-runner");
        assert!(output.status.success(), "`{flag}` failed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Usage:"), "`{flag}` output: {stdout}");
        assert!(
            stdout.contains("OHOS_TEST_RUNNER_HDC_TARGET"),
            "`{flag}` output: {stdout}"
        );
    }
}

#[test]
fn fails_without_a_binary_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_ohos-test-runner"))
        .output()
        .expect("failed to run ohos-test-runner");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
}

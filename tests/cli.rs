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
        assert!(
            stdout.contains("OHOS_TEST_RUNNER_RUNTIME_LIBRARIES"),
            "`{flag}` output: {stdout}"
        );
    }
}

#[test]
fn warns_about_unknown_env_vars() {
    let output = Command::new(env!("CARGO_BIN_EXE_ohos-test-runner"))
        .arg("--version")
        .env("OHOS_TEST_RUNNER_HDC_TARGETT", "typo")
        .env("OHOS_TEST_RUNNER_HDC_TARGET", "device")
        .output()
        .expect("failed to run ohos-test-runner");
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`OHOS_TEST_RUNNER_HDC_TARGETT` is not known"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("`OHOS_TEST_RUNNER_HDC_TARGET` is not known"),
        "stderr: {stderr}"
    );
}

/// A stand-in for `hdc` which answers every command like the real one does when it cannot reach
/// its server: with a message on stderr, and exit status 0.
#[cfg(unix)]
struct UnreachableServerHdc {
    dir: std::path::PathBuf,
}

#[cfg(unix)]
impl UnreachableServerHdc {
    fn new(name: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;

        // Not the system temp dir, which may not allow executing files.
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "ohos-test-runner-cli-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let hdc = dir.join("hdc");
        std::fs::write(
            &hdc,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\necho 'Connect server failed' >&2\n",
                dir.join("invocations").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&hdc, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { dir }
    }

    /// The runner, with this `hdc` first on its `PATH`.
    fn runner(&self) -> Command {
        let path = std::env::join_paths(std::iter::once(self.dir.clone()).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))
        .unwrap();
        let mut runner = Command::new(env!("CARGO_BIN_EXE_ohos-test-runner"));
        runner.env("PATH", path);
        runner
    }

    /// The arguments of every invocation, one line each.
    fn invocations(&self) -> String {
        std::fs::read_to_string(self.dir.join("invocations")).unwrap_or_default()
    }
}

#[cfg(unix)]
impl Drop for UnreachableServerHdc {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
#[test]
fn reports_an_unreachable_hdc_server() {
    let hdc = UnreachableServerHdc::new("unreachable");
    let output = hdc
        .runner()
        .arg(env!("CARGO_BIN_EXE_ohos-test-runner"))
        .env_remove("OHOS_TEST_RUNNER_HDC_TARGET")
        .output()
        .expect("failed to run ohos-test-runner");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot reach the hdc server"),
        "stderr: {stderr}"
    );
    assert_eq!(hdc.invocations().trim(), "list targets");
}

#[test]
fn fails_without_a_binary_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_ohos-test-runner"))
        .output()
        .expect("failed to run ohos-test-runner");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
}

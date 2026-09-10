use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_OHOS_TARGET: &str = "aarch64-unknown-linux-ohos";
const FIXTURE_PASSING_CASE: &str = "smoke_passes";
const FIXTURE_FAILING_CASE: &str = "smoke_fails";
const EXPECTED_FAILING_EXIT_CODE: &str = "Binary exited with Non-zero code: 101";

#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, and a connected device"]
fn runs_ohos_smoke_binary_via_runner() -> Result<(), Box<dyn std::error::Error>> {
    let project = TempProject::new()?;
    write_smoke_test_fixture(project.path())?;

    let run = run_fixture_test_case(project.path(), FIXTURE_PASSING_CASE)?;
    assert!(
        run.status.success(),
        "cargo test through ohos-test-runner failed for `{FIXTURE_PASSING_CASE}`\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    Ok(())
}

#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, and a connected device"]
fn propagates_failing_test_exit_code_via_runner() -> Result<(), Box<dyn std::error::Error>> {
    let project = TempProject::new()?;
    write_smoke_test_fixture(project.path())?;

    let run = run_fixture_test_case(project.path(), FIXTURE_FAILING_CASE)?;
    assert!(
        !run.status.success(),
        "expected cargo test through ohos-test-runner to fail for `{FIXTURE_FAILING_CASE}`\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&run.stderr).contains(EXPECTED_FAILING_EXIT_CODE),
        "expected propagated failing test exit code in runner stderr\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    Ok(())
}

/// Every hdc invocation of the runner must address the configured server. Unless the tests are
/// configured for a server already, the server named here is the local one, by its loopback
/// address, and an `hdc` in front of the real one fails every invocation which does not name a
/// server: those would reach the local server by default, and pass here while failing against a
/// server on another machine.
#[cfg(unix)]
#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, and a connected device"]
fn runs_through_an_explicit_hdc_server() -> Result<(), Box<dyn std::error::Error>> {
    let project = TempProject::new()?;
    write_smoke_test_fixture(project.path())?;
    let hdc = ServerCheckingHdc::new(project.path())?;
    let server = std::env::var("OHOS_TEST_RUNNER_HDC_SERVER").unwrap_or_else(|_| {
        let port = std::env::var("OHOS_HDC_SERVER_PORT").unwrap_or_else(|_| "8710".to_owned());
        format!("127.0.0.1:{port}")
    });

    let run = run_fixture_test_case_with_env(
        project.path(),
        FIXTURE_PASSING_CASE,
        &[
            ("PATH", &hdc.path()?),
            ("OHOS_TEST_RUNNER_HDC_SERVER", &server),
        ],
    )?;
    assert!(
        run.status.success(),
        "cargo test through ohos-test-runner failed for `{FIXTURE_PASSING_CASE}`\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        hdc.invocations_without_server(),
        "",
        "hdc invocations which do not address the server"
    );

    Ok(())
}

/// An `hdc` which forwards the invocations naming a server (`-s`) to the real hdc, and records
/// and fails the others.
#[cfg(unix)]
struct ServerCheckingHdc {
    dir: PathBuf,
}

#[cfg(unix)]
impl ServerCheckingHdc {
    fn new(project_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let real_hdc = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join("hdc"))
            .find(|hdc| hdc.is_file())
            .ok_or("hdc is not on PATH")?;
        let dir = project_dir.join("hdc-bin");
        fs::create_dir_all(&dir)?;
        let hdc = dir.join("hdc");
        fs::write(
            &hdc,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = -s ]; then exec '{}' \"$@\"; fi\n\
                 printf '%s\\n' \"$*\" >> '{}'\n\
                 echo 'hdc invoked without -s' >&2\n\
                 exit 1\n",
                real_hdc.display(),
                dir.join("invocations-without-server").display()
            ),
        )?;
        fs::set_permissions(&hdc, fs::Permissions::from_mode(0o755))?;
        Ok(Self { dir })
    }

    /// `PATH`, with this `hdc` in front of the real one.
    fn path(&self) -> Result<String, Box<dyn std::error::Error>> {
        let path = std::env::join_paths(std::iter::once(self.dir.clone()).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))?;
        Ok(path.into_string().map_err(|_| "PATH is not utf-8")?)
    }

    fn invocations_without_server(&self) -> String {
        fs::read_to_string(self.dir.join("invocations-without-server")).unwrap_or_default()
    }
}

fn run_fixture_test_case(
    project_dir: &Path,
    test_filter: &str,
) -> Result<Output, Box<dyn std::error::Error>> {
    run_fixture_test_case_with_env(project_dir, test_filter, &[])
}

fn run_fixture_test_case_with_env(
    project_dir: &Path,
    test_filter: &str,
    extra_env: &[(&str, &str)],
) -> Result<Output, Box<dyn std::error::Error>> {
    let target = std::env::var("OHOS_TEST_RUNNER_INTEGRATION_TARGET")
        .unwrap_or_else(|_| DEFAULT_OHOS_TARGET.to_owned());
    let runner_env_var = cargo_target_runner_env_var(&target);
    let linker_env_var = cargo_target_linker_env_var(&target);
    let linker = std::env::var(&linker_env_var).map_err(|_| {
        format!("required linker environment variable `{linker_env_var}` is not set")
    })?;
    let fixture_test_name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}_fixture"))
        .ok_or("failed to derive fixture test name from temp project directory")?;

    let mut cargo = Command::new("cargo");
    cargo.envs(extra_env.iter().copied());
    let run = cargo
        .arg("test")
        .arg("--quiet")
        .arg("--target")
        .arg(&target)
        .arg("--test")
        .arg(&fixture_test_name)
        .arg("--")
        .arg(test_filter)
        .arg("--nocapture")
        .env(&runner_env_var, env!("CARGO_BIN_EXE_ohos-test-runner"))
        .env(&linker_env_var, linker)
        .env("RUST_LOG", "debug")
        .current_dir(project_dir)
        .output()?;
    Ok(run)
}

fn write_smoke_test_fixture(project_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(project_dir.join("tests"))?;
    let fixture_package_name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}-fixture"))
        .ok_or("failed to derive fixture package name from temp project directory")?;
    let fixture_test_name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}_fixture"))
        .ok_or("failed to derive fixture test name from temp project directory")?;
    fs::write(
        project_dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{fixture_package_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
        ),
    )?;
    fs::write(
        project_dir.join("tests").join(format!("{fixture_test_name}.rs")),
        format!(
            "#[test]\nfn {FIXTURE_PASSING_CASE}() {{\n    println!(\"runner smoke test executed\");\n}}\n\n#[test]\nfn {FIXTURE_FAILING_CASE}() {{\n    panic!(\"intentional smoke-test failure\");\n}}\n"
        ),
    )?;
    Ok(())
}

fn cargo_target_runner_env_var(target: &str) -> String {
    format!(
        "CARGO_TARGET_{}_RUNNER",
        target.replace('-', "_").to_ascii_uppercase()
    )
}

fn cargo_target_linker_env_var(target: &str) -> String {
    format!(
        "CARGO_TARGET_{}_LINKER",
        target.replace('-', "_").to_ascii_uppercase()
    )
}

struct TempProject {
    path: PathBuf,
}

impl TempProject {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let unique = format!(
            "ohos-test-runner-smoke-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

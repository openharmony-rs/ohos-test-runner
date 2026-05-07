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

fn run_fixture_test_case(
    project_dir: &Path,
    test_filter: &str,
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

    let run = Command::new("cargo")
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

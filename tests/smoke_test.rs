use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_OHOS_TARGET: &str = "aarch64-unknown-linux-ohos";
const FIXTURE_NAME: &str = "smoke-test";
const FIXTURE_ARG: &str = "integration-smoke";

#[test]
fn runs_ohos_smoke_binary_via_runner() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::var("OHOS_TEST_RUNNER_INTEGRATION_TARGET")
        .unwrap_or_else(|_| DEFAULT_OHOS_TARGET.to_owned());
    let project = TempProject::new()?;
    write_smoke_test_fixture(project.path())?;

    let target_dir = project.path().join("target");
    let build = Command::new("cargo")
        .arg("build")
        .arg("--quiet")
        .arg("--target")
        .arg(&target)
        .env("CARGO_TARGET_DIR", &target_dir)
        .current_dir(project.path())
        .output()?;
    assert!(
        build.status.success(),
        "failed to build smoke-test fixture for target `{target}`\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    let bin_path = target_dir.join(&target).join("debug").join(FIXTURE_NAME);
    assert!(
        bin_path.is_file(),
        "expected built smoke-test binary at `{}`",
        bin_path.display()
    );

    let run = Command::new(env!("CARGO_BIN_EXE_ohos-test-runner"))
        .arg(&bin_path)
        .arg(FIXTURE_ARG)
        .output()?;
    assert!(
        run.status.success(),
        "runner failed for `{}`\nstdout:\n{}\nstderr:\n{}",
        bin_path.display(),
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    Ok(())
}

fn write_smoke_test_fixture(project_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(project_dir.join("src"))?;
    fs::write(
        project_dir.join("Cargo.toml"),
        format!("[package]\nname = \"{FIXTURE_NAME}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    )?;
    fs::write(
        project_dir.join("src/main.rs"),
        format!(
            "fn main() {{\n    let arg = std::env::args().nth(1);\n    if arg.as_deref() != Some(\"{FIXTURE_ARG}\") {{\n        eprintln!(\"unexpected arg: {{:?}}\", arg);\n        std::process::exit(17);\n    }}\n}}\n"
        ),
    )?;
    Ok(())
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

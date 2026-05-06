use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_OHOS_TARGET: &str = "aarch64-unknown-linux-ohos";
const FIXTURE_PACKAGE_NAME: &str = "ohos-test-runner-smoke-fixture";
const FIXTURE_TEST_NAME: &str = "ohos_test_runner_md5_fallback_smoke_regression";
const EXPECTED_MD5_LOG: &str = "The md5sum hash on the device is";

#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, and a connected device"]
fn runs_ohos_smoke_binary_via_runner() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::var("OHOS_TEST_RUNNER_INTEGRATION_TARGET")
        .unwrap_or_else(|_| DEFAULT_OHOS_TARGET.to_owned());
    let expected_hash_kind = std::env::var("OHOS_TEST_RUNNER_EXPECT_HASH_KIND").ok();
    let project = TempProject::new()?;
    write_smoke_test_fixture(project.path())?;

    let runner_env_var = cargo_target_runner_env_var(&target);
    let linker_env_var = cargo_target_linker_env_var(&target);
    let linker = std::env::var(&linker_env_var).map_err(|_| {
        format!("required linker environment variable `{linker_env_var}` is not set")
    })?;

    let run = Command::new("cargo")
        .arg("test")
        .arg("--quiet")
        .arg("--target")
        .arg(&target)
        .arg("--test")
        .arg(FIXTURE_TEST_NAME)
        .arg("--")
        .arg("--nocapture")
        .env(&runner_env_var, env!("CARGO_BIN_EXE_ohos-test-runner"))
        .env(&linker_env_var, linker)
        .env("RUST_LOG", "debug")
        .current_dir(project.path())
        .output()?;
    assert!(
        run.status.success(),
        "cargo test through ohos-test-runner failed for target `{target}`\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    if expected_hash_kind.as_deref() == Some("md5sum") {
        assert!(
            String::from_utf8_lossy(&run.stderr).contains(EXPECTED_MD5_LOG),
            "expected md5 fallback log in runner stderr\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
    }

    Ok(())
}

fn write_smoke_test_fixture(project_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(project_dir.join("tests"))?;
    fs::write(
        project_dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{FIXTURE_PACKAGE_NAME}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
        ),
    )?;
    fs::write(
        project_dir
            .join("tests")
            .join(format!("{FIXTURE_TEST_NAME}.rs")),
        "#[test]\nfn smoke() {\n    println!(\"runner smoke test executed\");\n}\n",
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

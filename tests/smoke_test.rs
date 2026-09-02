use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    write_smoke_test_fixture_with_marker(project_dir, "")
}

/// `marker` changes the contents of the built binary, and with it the directory it is
/// transferred to.
fn write_smoke_test_fixture_with_marker(
    project_dir: &Path,
    marker: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
            "#[test]\nfn {FIXTURE_PASSING_CASE}() {{\n    println!(\"runner smoke test executed {marker}\");\n}}\n\n#[test]\nfn {FIXTURE_FAILING_CASE}() {{\n    panic!(\"intentional smoke-test failure\");\n}}\n"
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

    /// The prefix the on-device binaries of every fixture of this project share.
    fn device_bin_prefix(&self) -> Option<String> {
        self.path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.replace('-', "_"))
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        // The fixtures of every run have a name of their own, so the runner never prunes the
        // build directory of a previous run: they have to be removed here, or they pile up on
        // the device.
        if let Some(prefix) = self.device_bin_prefix() {
            if let Ok(dirs) = build_dirs_starting_with(&prefix) {
                for dir in dirs {
                    let _ = hdc_shell(&["rm", "-rf", &format!("{TEST_BIN_DIR}/{dir}")]);
                }
            }
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// The directory the runner uses on the device. Kept in sync with `src/main.rs` by hand, since
/// integration tests cannot see the internals of a binary crate.
const TEST_BIN_DIR: &str = "/data/local/tmp/ohos-test-runner";
/// Names for the entries the collection test plants on the device. Hex, like the directories
/// the runner creates, but not a hash any build has.
const STALE_BUILD_DIR: &str = "aaaaaaaaaaaaaaaa";
const FRESH_BUILD_DIR: &str = "bbbbbbbbbbbbbbbb";
/// A pid no invocation can have, so the other smoke tests never own this file.
const STALE_EXIT_CODE_FILE: &str = "exit_code-4294967295";
const PARALLEL_TEST_COUNT: usize = 16;
/// Enough padding for the transfer of the fixture to take long enough to overlap the invocations
/// which follow it. The runner before per-invocation exit code files fails this test reliably at
/// this size, and passes it at a tenth of it.
const PARALLEL_FIXTURE_PADDING: usize = 24_000_000;
const PARALLEL_JOBS: &str = "8";
/// How long the exit code files of the other smoke tests, which run concurrently with this one,
/// are given to disappear.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Concurrent invocations of the runner must not overwrite each other's files on the device.
///
/// `cargo nextest` spawns one runner process per test, so this is the configuration in which the
/// invocations of a single test run overlap. The test also covers the second half of the
/// contract: the binary is transferred once for all of them, and a new build replaces the
/// directory of the previous one.
#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, a connected device, and cargo-nextest"]
fn parallel_nextest_runs_share_one_transfer() -> Result<(), Box<dyn std::error::Error>> {
    if !cargo_nextest_available() {
        return Err("cargo-nextest is not installed".into());
    }
    let project = TempProject::new()?;
    let test_target = parallel_fixture_test_target(project.path())?;

    write_parallel_fixture(project.path(), "first build")?;
    let first_run = run_fixture_with_nextest(project.path(), &test_target)?;
    assert!(
        first_run.status.success(),
        "parallel run through ohos-test-runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first_run.stdout),
        String::from_utf8_lossy(&first_run.stderr)
    );

    // All the invocations of the run shared a single transferred binary, ...
    let first_build_dirs = build_dirs_of(&test_target)?;
    assert_eq!(
        first_build_dirs.len(),
        1,
        "expected the {PARALLEL_TEST_COUNT} test invocations to share one build directory"
    );
    // ... and none of them left a half-transferred binary next to it.
    let entries = entries_in(&format!("{TEST_BIN_DIR}/{}", first_build_dirs[0]))?;
    assert_eq!(
        entries.len(),
        1,
        "expected only the test binary in the build directory, found: {entries:?}"
    );

    // A rebuild has different contents, so it lands in a new directory and prunes the old one.
    write_parallel_fixture(project.path(), "second build")?;
    let second_run = run_fixture_with_nextest(project.path(), &test_target)?;
    assert!(
        second_run.status.success(),
        "parallel run of the rebuilt fixture failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second_run.stdout),
        String::from_utf8_lossy(&second_run.stderr)
    );

    let second_build_dirs = build_dirs_of(&test_target)?;
    assert!(
        !second_build_dirs.contains(&first_build_dirs[0]),
        "the directory `{}` of the previous build was not pruned",
        first_build_dirs[0]
    );
    assert_eq!(
        second_build_dirs.len(),
        1,
        "expected one build directory after the rebuild, found: {second_build_dirs:?}"
    );

    wait_until_no_exit_code_files_are_left()?;

    Ok(())
}

/// Builds which have gone unused, and the files of invocations which were killed, are removed
/// once the device directory is about to grow again.
#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, and a connected device"]
fn unused_builds_are_collected() -> Result<(), Box<dyn std::error::Error>> {
    let project = TempProject::new()?;
    write_smoke_test_fixture(project.path())?;
    let first_run = run_fixture_test_case(project.path(), FIXTURE_PASSING_CASE)?;
    assert!(
        first_run.status.success(),
        "the first run of the fixture failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first_run.stdout),
        String::from_utf8_lossy(&first_run.stderr)
    );

    // A build nobody has used for a while, a fresh build holding an interrupted transfer, and
    // the exit code file of an invocation which was killed before it could read it.
    let stale_build = format!("{TEST_BIN_DIR}/{STALE_BUILD_DIR}");
    let fresh_build = format!("{TEST_BIN_DIR}/{FRESH_BUILD_DIR}");
    let stale_exit_code = format!("{TEST_BIN_DIR}/{STALE_EXIT_CODE_FILE}");
    let stale_incoming = format!("{fresh_build}/killed-transfer.incoming");
    hdc_shell(&[&format!(
        "mkdir -p {stale_build} {fresh_build}; touch {stale_incoming} {stale_exit_code}; \
         touch -d '2020-01-01 00:00:00' {stale_build} {stale_incoming} {stale_exit_code}"
    )])?;

    // Changing the fixture gives the next run a binary of its own, so it has to transfer - which
    // is when the collection runs.
    write_smoke_test_fixture_with_marker(project.path(), "collected")?;
    let second_run = run_fixture_test_case(project.path(), FIXTURE_PASSING_CASE)?;
    assert!(
        second_run.status.success(),
        "the run after the rebuild failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second_run.stdout),
        String::from_utf8_lossy(&second_run.stderr)
    );

    let entries = entries_in(TEST_BIN_DIR)?;
    assert!(
        !entries.contains(&STALE_BUILD_DIR.to_owned()),
        "the unused build was not collected, {TEST_BIN_DIR} holds: {entries:?}"
    );
    // Only the planted file: the other smoke tests run concurrently and have exit code files of
    // their own in flight.
    assert!(
        !entries.contains(&STALE_EXIT_CODE_FILE.to_owned()),
        "the exit code file of a killed invocation was not collected: {entries:?}"
    );
    // A build which is still in use stays, but the interrupted transfer inside it does not.
    assert!(
        entries.contains(&FRESH_BUILD_DIR.to_owned()),
        "a build in use was collected, {TEST_BIN_DIR} holds: {entries:?}"
    );
    assert!(
        entries_in(&fresh_build)?.is_empty(),
        "the interrupted transfer was not collected: {:?}",
        entries_in(&fresh_build)?
    );

    let _ = hdc_shell(&["rm", "-rf", &fresh_build]);
    Ok(())
}

fn cargo_nextest_available() -> bool {
    Command::new("cargo")
        .args(["nextest", "--version"])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn parallel_fixture_test_target(project_dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}_parallel"))
        .ok_or_else(|| "failed to derive fixture test name from temp project directory".into())
}

/// Writes a fixture whose tests overlap in time, so the runner invocations do too. `marker`
/// changes the contents of the built binary, and with it the directory it is transferred to.
fn write_parallel_fixture(
    project_dir: &Path,
    marker: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(project_dir.join("tests"))?;
    let package_name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}-fixture"))
        .ok_or("failed to derive fixture package name from temp project directory")?;
    let test_target = parallel_fixture_test_target(project_dir)?;
    fs::write(
        project_dir.join("Cargo.toml"),
        format!("[package]\nname = \"{package_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    )?;
    // The padding widens the window in which the invocations overlap, since a transfer takes
    // long enough to be interrupted by the next invocation.
    let mut fixture = format!(
        "static PAD: [u8; {PARALLEL_FIXTURE_PADDING}] = [7u8; {PARALLEL_FIXTURE_PADDING}];\n\n"
    );
    for case in 0..PARALLEL_TEST_COUNT {
        fixture.push_str(&format!(
            "#[test]\nfn parallel_case_{case}() {{\n    assert_eq!(PAD[{case}], 7);\n    \
             println!(\"{marker}\");\n    \
             std::thread::sleep(std::time::Duration::from_millis(300));\n}}\n\n"
        ));
    }
    fs::write(
        project_dir.join("tests").join(format!("{test_target}.rs")),
        fixture,
    )?;
    Ok(())
}

fn run_fixture_with_nextest(
    project_dir: &Path,
    test_target: &str,
) -> Result<Output, Box<dyn std::error::Error>> {
    let target = std::env::var("OHOS_TEST_RUNNER_INTEGRATION_TARGET")
        .unwrap_or_else(|_| DEFAULT_OHOS_TARGET.to_owned());
    let runner_env_var = cargo_target_runner_env_var(&target);
    let linker_env_var = cargo_target_linker_env_var(&target);
    let linker = std::env::var(&linker_env_var).map_err(|_| {
        format!("required linker environment variable `{linker_env_var}` is not set")
    })?;

    let run = Command::new("cargo")
        .args(["nextest", "run", "--target"])
        .arg(&target)
        .arg("--test")
        .arg(test_target)
        .arg("--test-threads")
        .arg(PARALLEL_JOBS)
        .env(&runner_env_var, env!("CARGO_BIN_EXE_ohos-test-runner"))
        .env(&linker_env_var, linker)
        .current_dir(project_dir)
        .output()?;
    Ok(run)
}

/// The directories under [`TEST_BIN_DIR`] holding a build of `test_target`.
///
/// Selecting by the binary name keeps the other smoke tests, which run concurrently and use the
/// same device directory, out of the result.
fn build_dirs_of(test_target: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // Cargo builds a test target into a file with the dashes of its name replaced by underscores,
    // and appends its own metadata hash.
    build_dirs_starting_with(&format!("{}-", test_target.replace('-', "_")))
}

/// The directories under [`TEST_BIN_DIR`] holding a binary whose name starts with `bin_prefix`.
fn build_dirs_starting_with(bin_prefix: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let stdout = hdc_shell(&["ls", "-1", &format!("{TEST_BIN_DIR}/*/{bin_prefix}*")])?;
    let prefix = format!("{TEST_BIN_DIR}/");
    let mut dirs = stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix(&prefix)?.split('/').next())
        .map(str::to_owned)
        .collect::<Vec<String>>();
    dirs.sort();
    dirs.dedup();
    Ok(dirs)
}

fn entries_in(dir: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(hdc_shell(&["ls", "-1", dir])?
        .lines()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect())
}

/// The runner removes its exit code file as it reads it, so none may outlive the runs.
///
/// The other smoke tests share [`TEST_BIN_DIR`] and run concurrently with this one, hence the
/// wait rather than a single look.
fn wait_until_no_exit_code_files_are_left() -> Result<(), Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + CLEANUP_TIMEOUT;
    loop {
        let leftovers = entries_in(TEST_BIN_DIR)?
            .into_iter()
            .filter(|entry| entry.starts_with("exit_code-"))
            .collect::<Vec<String>>();
        if leftovers.is_empty() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("exit code files left in {TEST_BIN_DIR}: {leftovers:?}").into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn hdc_shell(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let mut command = Command::new("hdc");
    if let Ok(device) = std::env::var("OHOS_TEST_RUNNER_HDC_TARGET") {
        if !device.trim().is_empty() {
            command.args(["-t", device.trim()]);
        }
    }
    let output = command.arg("shell").args(args).output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

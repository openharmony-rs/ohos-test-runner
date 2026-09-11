use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_OHOS_TARGET: &str = "aarch64-unknown-linux-ohos";
const FIXTURE_PASSING_CASE: &str = "smoke_passes";
const FIXTURE_FAILING_CASE: &str = "smoke_fails";
/// A test which runs long enough to be interrupted.
const FIXTURE_WAITING_CASE: &str = "smoke_waits";
/// Keeps the builds of a run on the device, for the tests which look at them after the run.
const KEEP_BUILDS: (&str, &str) = ("OHOS_TEST_RUNNER_KEEP_BUILDS", "1");
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
    // The watcher of the run uses hdc too, once the run has ended.
    let bin_prefix = project.device_bin_prefix().ok_or("no binary name")?;
    wait_until("the build of the run is removed", CLEANUP_TIMEOUT, || {
        Ok(build_dirs_starting_with(&bin_prefix)?.is_empty())
    })?;
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
    Ok(fixture_test_command(project_dir, test_filter, extra_env)?.output()?)
}

/// `cargo test` of the fixture in `project_dir`, through the runner.
fn fixture_test_command(
    project_dir: &Path,
    test_filter: &str,
    extra_env: &[(&str, &str)],
) -> Result<Command, Box<dyn std::error::Error>> {
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
    cargo
        .envs(extra_env.iter().copied())
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
        .current_dir(project_dir);
    Ok(cargo)
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
            "#[test]\nfn {FIXTURE_PASSING_CASE}() {{\n    println!(\"runner smoke test executed {marker}\");\n}}\n\n#[test]\nfn {FIXTURE_FAILING_CASE}() {{\n    panic!(\"intentional smoke-test failure\");\n}}\n\n#[test]\nfn {FIXTURE_WAITING_CASE}() {{\n    std::thread::sleep(std::time::Duration::from_secs(30));\n}}\n"
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
                    remove_device_dir(&dir);
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
const FIXTURE_READING_CASE: &str = "reads_the_files_it_declared";
const FIXTURE_CONTENTS: &str = "hello from the package";
const PARALLEL_TEST_COUNT: usize = 16;
/// Enough padding for the transfer of the fixture to take long enough to overlap the invocations
/// which follow it. The runner before per-invocation exit code files fails this test reliably at
/// this size, and passes it at a tenth of it.
const PARALLEL_FIXTURE_PADDING: usize = 24_000_000;
const PARALLEL_JOBS: &str = "8";
/// How long the device is given to be cleaned up after a run: the builds of the run to be removed,
/// or the exit code files of the other smoke tests, which run concurrently, to disappear.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
/// How long building and transferring a fixture may take.
const BUILD_TIMEOUT: Duration = Duration::from_secs(120);

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
    let first_run = run_fixture_with_nextest(project.path(), &test_target, &[KEEP_BUILDS])?;
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
    let second_run = run_fixture_with_nextest(project.path(), &test_target, &[KEEP_BUILDS])?;
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

/// The listing invocations nextest starts for a test binary find the device without the build at
/// the same moment. One transfers it, and the others wait for that transfer.
#[cfg(unix)]
#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, a connected device, and cargo-nextest"]
fn a_fresh_build_is_transferred_once() -> Result<(), Box<dyn std::error::Error>> {
    if !cargo_nextest_available() {
        return Err("cargo-nextest is not installed".into());
    }
    let project = TempProject::new()?;
    let test_target = parallel_fixture_test_target(project.path())?;
    write_parallel_fixture(project.path(), "transferred once")?;
    let hdc = SendLoggingHdc::new(project.path())?;

    let run = run_fixture_with_nextest(project.path(), &test_target, &[("PATH", &hdc.path()?)])?;
    assert!(
        run.status.success(),
        "parallel run through ohos-test-runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let bin_name = test_target.replace('-', "_");
    let sends = hdc.sends();
    assert_eq!(
        sends
            .lines()
            .filter(|send| send.contains(&bin_name))
            .count(),
        1,
        "expected a single transfer of the binary, hdc sent: {sends}"
    );
    Ok(())
}

/// An `hdc` in front of the real one, which records the files it is asked to send.
#[cfg(unix)]
struct SendLoggingHdc {
    dir: PathBuf,
}

#[cfg(unix)]
impl SendLoggingHdc {
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
                 case \"$*\" in *'file send'*) printf '%s\\n' \"$*\" >> '{}';; esac\n\
                 exec '{}' \"$@\"\n",
                dir.join("sends").display(),
                real_hdc.display(),
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

    /// The arguments of every `hdc file send`, one line each.
    fn sends(&self) -> String {
        fs::read_to_string(self.dir.join("sends")).unwrap_or_default()
    }
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

/// A test may read files from its package, if it declares them.
#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, and a connected device"]
fn declared_fixtures_are_readable_from_the_test() -> Result<(), Box<dyn std::error::Error>> {
    let project = TempProject::new()?;
    let fixture_file = write_fixture_reading_project(project.path())?;

    // Without the declaration the runner has no way to know about the file, and the test fails
    // on the device exactly as the README describes.
    let undeclared = run_fixture_test_case(project.path(), FIXTURE_READING_CASE)?;
    assert!(
        !undeclared.status.success(),
        "the test read a file which was never sent to the device\nstdout:\n{}",
        String::from_utf8_lossy(&undeclared.stdout)
    );

    let run = run_fixture_test_case_with_env(
        project.path(),
        FIXTURE_READING_CASE,
        &[("OHOS_TEST_RUNNER_FIXTURES", "tests/data"), KEEP_BUILDS],
    )?;
    assert!(
        run.status.success(),
        "the test could not read the files it declared\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    // The mirror is a directory of its own, next to the build directories.
    let mirrors = device_dirs_holding(&fixture_file)?;
    assert_eq!(
        mirrors.len(),
        1,
        "expected one mirror of the package files, found: {mirrors:?}"
    );

    for dir in mirrors {
        remove_device_dir(&dir);
    }
    Ok(())
}

/// When a run ends, its builds and the mirror of its package files leave the device, unless the
/// run keeps them.
#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, and a connected device"]
fn builds_are_removed_when_the_run_ends() -> Result<(), Box<dyn std::error::Error>> {
    let project = TempProject::new()?;
    let fixture_file = write_fixture_reading_project(project.path())?;
    let bin_prefix = project.device_bin_prefix().ok_or("no binary name")?;
    let fixtures = ("OHOS_TEST_RUNNER_FIXTURES", "tests/data");

    let run = run_fixture_test_case_with_env(project.path(), FIXTURE_READING_CASE, &[fixtures])?;
    assert!(
        run.status.success(),
        "the run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    wait_until("the builds of the run are removed", CLEANUP_TIMEOUT, || {
        Ok(build_dirs_starting_with(&bin_prefix)?.is_empty()
            && device_dirs_holding(&fixture_file)?.is_empty())
    })?;

    // The same build again, keeping its builds this time: they stay for the collection of unused
    // builds.
    let kept = run_fixture_test_case_with_env(
        project.path(),
        FIXTURE_READING_CASE,
        &[fixtures, KEEP_BUILDS],
    )?;
    assert!(
        kept.status.success(),
        "the run keeping its builds failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&kept.stdout),
        String::from_utf8_lossy(&kept.stderr)
    );
    // Long enough for a cleanup which should not happen to have happened.
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        build_dirs_starting_with(&bin_prefix)?.len(),
        1,
        "the build was not kept"
    );
    let mirrors = device_dirs_holding(&fixture_file)?;
    assert_eq!(mirrors.len(), 1, "the mirror was not kept");

    // The project removes the builds when it goes, but not the mirror.
    for dir in mirrors {
        remove_device_dir(&dir);
    }
    Ok(())
}

/// The invocations of a nextest run share its builds, which leave the device once the whole run
/// ends.
#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, a connected device, and cargo-nextest"]
fn builds_are_removed_when_a_nextest_run_ends() -> Result<(), Box<dyn std::error::Error>> {
    if !cargo_nextest_available() {
        return Err("cargo-nextest is not installed".into());
    }
    let project = TempProject::new()?;
    let test_target = parallel_fixture_test_target(project.path())?;
    write_parallel_fixture(project.path(), "removed")?;

    let run = run_fixture_with_nextest(project.path(), &test_target, &[])?;
    assert!(
        run.status.success(),
        "parallel run through ohos-test-runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    wait_until("the build of the run is removed", CLEANUP_TIMEOUT, || {
        Ok(build_dirs_of(&test_target)?.is_empty())
    })
}

/// Ctrl-C interrupts the whole process group of a command in a terminal, which must not take the
/// removal of the builds with it.
#[cfg(unix)]
#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, and a connected device"]
fn builds_are_removed_after_an_interrupted_run() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let project = TempProject::new()?;
    write_smoke_test_fixture(project.path())?;
    let bin_prefix = project.device_bin_prefix().ok_or("no binary name")?;

    let mut run = fixture_test_command(project.path(), FIXTURE_WAITING_CASE, &[])?
        .process_group(0)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let interrupt = |signal: &str| {
        Command::new("kill")
            .args([signal, "--", &format!("-{}", run.id())])
            .status()
    };
    // Building the fixture comes first, and takes a while. The binary is renamed into place
    // after its transfer, right before the test starts.
    let waited = wait_until("the binary arrives on the device", BUILD_TIMEOUT, || {
        Ok(!installed_binaries_starting_with(&bin_prefix)?.is_empty())
    });
    if let Err(err) = waited {
        let _ = interrupt("-KILL");
        return Err(err);
    }
    std::thread::sleep(Duration::from_secs(1));
    assert!(interrupt("-INT")?.success(), "failed to interrupt the run");
    assert!(!run.wait()?.success(), "the interrupted run succeeded");

    wait_until(
        "the build of the interrupted run is removed",
        CLEANUP_TIMEOUT,
        || Ok(build_dirs_starting_with(&bin_prefix)?.is_empty()),
    )
}

/// The unit tests of a library and its integration tests are two binaries reading the same files,
/// which the listing invocations of nextest send to the device at the same time. The mirror has to
/// end up with every file in its place, not with a copy nested inside another.
#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, a connected device, and cargo-nextest"]
fn fixtures_shared_by_two_binaries_are_mirrored_once() -> Result<(), Box<dyn std::error::Error>> {
    if !cargo_nextest_available() {
        return Err("cargo-nextest is not installed".into());
    }
    let project = TempProject::new()?;
    let fixture_file = write_fixture_reading_project(project.path())?;
    fs::create_dir_all(project.path().join("src"))?;
    fs::write(
        project.path().join("src/lib.rs"),
        format!(
            "#[test]\nfn {FIXTURE_READING_CASE}() {{\n    \
             let contents = std::fs::read_to_string(\"{fixture_file}\").unwrap();\n    \
             assert_eq!(contents.trim(), \"{FIXTURE_CONTENTS}\");\n}}\n"
        ),
    )?;

    let run = run_nextest(
        project.path(),
        &[],
        &[("OHOS_TEST_RUNNER_FIXTURES", "tests/data"), KEEP_BUILDS],
    )?;
    assert!(
        run.status.success(),
        "the tests could not read the files they declared\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let mirrors = device_dirs_holding(&fixture_file)?;
    assert_eq!(mirrors.len(), 1, "expected one mirror, found: {mirrors:?}");
    let nested = hdc_shell(&[
        "find",
        &format!("{TEST_BIN_DIR}/{}", mirrors[0]),
        "-path",
        "*/data/data*",
    ])?;
    assert_eq!(nested.trim(), "", "files nested inside the mirror");

    for dir in mirrors {
        remove_device_dir(&dir);
    }
    Ok(())
}

/// A build directory which has gone unused for longer than the collection allows, and lost its
/// binary, e.g. to a transfer which was interrupted, is filled again rather than collected from
/// under the transfer.
#[test]
#[ignore = "requires an OpenHarmony target toolchain, linker setup, hdc, and a connected device"]
fn a_stale_build_directory_is_filled_again() -> Result<(), Box<dyn std::error::Error>> {
    let project = TempProject::new()?;
    write_smoke_test_fixture(project.path())?;
    let bin_prefix = project.device_bin_prefix().ok_or("no binary name")?;

    let first =
        run_fixture_test_case_with_env(project.path(), FIXTURE_PASSING_CASE, &[KEEP_BUILDS])?;
    assert!(first.status.success(), "the first run failed");
    let dirs = build_dirs_starting_with(&bin_prefix)?;
    assert_eq!(
        dirs.len(),
        1,
        "expected one build directory, found: {dirs:?}"
    );
    let dir = format!("{TEST_BIN_DIR}/{}", dirs[0]);
    hdc_shell(&[&format!(
        "rm -f {dir}/{bin_prefix}*; touch -d '2020-01-01 00:00:00' {dir}"
    )])?;

    // Keeping the builds, since the marker of a session refreshes the directory in passing.
    let second =
        run_fixture_test_case_with_env(project.path(), FIXTURE_PASSING_CASE, &[KEEP_BUILDS])?;
    assert!(
        second.status.success(),
        "the run into the stale build directory failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    Ok(())
}

/// Waits for `done` to hold, looking again every 200 ms.
fn wait_until(
    what: &str,
    timeout: Duration,
    mut done: impl FnMut() -> Result<bool, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + timeout;
    while !done()? {
        if std::time::Instant::now() >= deadline {
            return Err(format!("timed out waiting until {what}").into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

/// Writes a package whose test reads a file from the package, and returns that file's path
/// relative to the package root.
fn write_fixture_reading_project(project_dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    fs::create_dir_all(project_dir.join("tests/data"))?;
    let name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("failed to derive a name from the temp project directory")?;
    let data_file = format!("tests/data/{name}.txt");
    fs::write(
        project_dir.join("Cargo.toml"),
        format!("[package]\nname = \"{name}-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    )?;
    fs::write(project_dir.join(&data_file), FIXTURE_CONTENTS)?;
    fs::write(
        project_dir.join("tests").join(format!("{name}_fixture.rs")),
        format!(
            "#[test]\nfn {FIXTURE_READING_CASE}() {{\n    \
             let relative = std::fs::read_to_string(\"{data_file}\")\n        \
             .expect(\"a relative path resolves against the package root\");\n    \
             assert_eq!(relative.trim(), \"{FIXTURE_CONTENTS}\");\n    \
             let manifest_dir = std::env::var(\"CARGO_MANIFEST_DIR\")\n        \
             .expect(\"CARGO_MANIFEST_DIR is set at runtime\");\n    \
             let absolute = std::fs::read_to_string(\n        \
             std::path::Path::new(&manifest_dir).join(\"{data_file}\"),\n    )\n    \
             .expect(\"CARGO_MANIFEST_DIR points at the package root\");\n    \
             assert_eq!(absolute.trim(), \"{FIXTURE_CONTENTS}\");\n}}\n"
        ),
    )?;
    Ok(data_file)
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
    extra_env: &[(&str, &str)],
) -> Result<Output, Box<dyn std::error::Error>> {
    run_nextest(
        project_dir,
        &["--test", test_target, "--test-threads", PARALLEL_JOBS],
        extra_env,
    )
}

/// `cargo nextest run` of the fixture in `project_dir`, through the runner.
fn run_nextest(
    project_dir: &Path,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> Result<Output, Box<dyn std::error::Error>> {
    let target = std::env::var("OHOS_TEST_RUNNER_INTEGRATION_TARGET")
        .unwrap_or_else(|_| DEFAULT_OHOS_TARGET.to_owned());
    let runner_env_var = cargo_target_runner_env_var(&target);
    let linker_env_var = cargo_target_linker_env_var(&target);
    let linker = std::env::var(&linker_env_var).map_err(|_| {
        format!("required linker environment variable `{linker_env_var}` is not set")
    })?;

    let run = Command::new("cargo")
        .envs(extra_env.iter().copied())
        .args(["nextest", "run", "--target"])
        .arg(&target)
        .args(args)
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
    device_dirs_holding(&format!("{bin_prefix}*"))
}

/// The binaries under [`TEST_BIN_DIR`] whose name starts with `bin_prefix`, which are in place,
/// as opposed to on their way there.
fn installed_binaries_starting_with(
    bin_prefix: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(
        hdc_shell(&["ls", "-1", &format!("{TEST_BIN_DIR}/*/{bin_prefix}*")])?
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with(TEST_BIN_DIR) && !line.ends_with(".incoming"))
            .map(str::to_owned)
            .collect(),
    )
}

/// The directories under [`TEST_BIN_DIR`] which hold `relative`, a path inside one of them.
fn device_dirs_holding(relative: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let stdout = hdc_shell(&["ls", "-1", &format!("{TEST_BIN_DIR}/*/{relative}")])?;
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

/// Removes the directory `name` from [`TEST_BIN_DIR`], with the markers of the sessions which used
/// it, like the runner does.
fn remove_device_dir(name: &str) {
    let _ = hdc_shell(&[&format!(
        "rm -rf {TEST_BIN_DIR}/{name} {TEST_BIN_DIR}/.sessions/*/{name}"
    )]);
}

/// Runs `hdc shell` against the device the runner uses. Unlike the runner, this passes
/// `OHOS_TEST_RUNNER_HDC_SERVER` on as it is, so it has to be a numeric address.
fn hdc_shell(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let mut command = Command::new("hdc");
    if let Ok(server) = std::env::var("OHOS_TEST_RUNNER_HDC_SERVER") {
        if !server.trim().is_empty() {
            command.args(["-s", server.trim()]);
        }
    }
    if let Ok(device) = std::env::var("OHOS_TEST_RUNNER_HDC_TARGET") {
        if !device.trim().is_empty() {
            command.args(["-t", device.trim()]);
        }
    }
    let output = command.arg("shell").args(args).output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

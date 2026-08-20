//! A simple Cargo target runner for running tests or benchmarks on OpenHarmony devices
//!
//! ## Example
//!
//! After installing ohos-test-runner, configure your project to use the custom
//! target runner, for the relevant target triple, e.g.
//!
//! ```sh
//! # Setup ohos-test-runner as the target runner for aarch64 OpenHarmony.
//! export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_RUNNER=ohos-test-runner
//! # Optional: Select the device, if multiple devices are attached.
//! export OHOS_TEST_RUNNER_HDC_TARGET=<connect-key>
//! # Run cargo test (more environment variables might be needed, depending on your project)
//! cargo test --target aarch64-unknown-linux-ohos
//! ```

use anyhow::{bail, Context};
use log::debug;
use md5::Md5;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_BIN_DIR: &str = "/data/local/tmp/ohos-test-runner";

/// Nextest's per-attempt identifier. Unique for each process-per-test invocation,
/// including retries. Not set when the runner is invoked by `cargo test`.
const NEXTEST_ATTEMPT_ID_ENV_VAR: &str = "NEXTEST_ATTEMPT_ID";

/// Environment variable to select the device (hdc connect-key) to run the binary on.
const HDC_TARGET_ENV_VAR: &str = "OHOS_TEST_RUNNER_HDC_TARGET";

const ENV_VAR_PREFIX: &str = "OHOS_TEST_RUNNER";

/// The user-facing environment variables of this tool. Variables with the [`ENV_VAR_PREFIX`]
/// which are neither listed here nor in [`INTERNAL_ENV_VARS`] are reported to the user
/// as unknown.
const KNOWN_ENV_VARS: &[&str] = &[HDC_TARGET_ENV_VAR];

/// Internal environment variables, which are recognized to avoid spurious warnings,
/// but not advertised to users.
const INTERNAL_ENV_VARS: &[&str] = &[
    // Only used by the integration tests of this crate, but inherited by the runner.
    "OHOS_TEST_RUNNER_INTEGRATION_TARGET",
];

/// The hdc invocation, including the device selection (`-t`) if configured.
struct Hdc {
    target: Option<String>,
}

impl Hdc {
    fn from_env() -> Self {
        let target = std::env::var(HDC_TARGET_ENV_VAR)
            .ok()
            .map(|target| target.trim().to_owned())
            .filter(|target| !target.is_empty());
        Self { target }
    }

    fn command(&self) -> Command {
        let mut command = Command::new("hdc");
        if let Some(target) = &self.target {
            command.args(["-t", target]);
        }
        command
    }

    fn shell(&self, args: &[&str]) -> anyhow::Result<Output> {
        self.command()
            .arg("shell")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn hdc shell")?
            .wait_with_output()
            .context("Failed to wait for hdc shell")
    }
}

/// Remote directory, binary, and exit-code file for a single runner invocation.
///
/// Concurrent nextest invocations of the same host binary previously shared
/// `{TEST_BIN_DIR}/{bin_name}` and `{TEST_BIN_DIR}/last_exit_code-{bin_name}`,
/// so they could overwrite each other. Each invocation now gets its own
/// subdirectory under [`TEST_BIN_DIR`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteInvocation {
    dir: String,
    bin_path: String,
    exit_code_file: String,
}

impl RemoteInvocation {
    fn new(bin_name: &str, invocation_id: &str) -> Self {
        let id = sanitize_path_component(invocation_id);
        let dir = format!("{TEST_BIN_DIR}/{id}");
        Self {
            bin_path: format!("{dir}/{bin_name}"),
            exit_code_file: format!("{dir}/exit_code"),
            dir,
        }
    }
}

/// Best-effort removal of an invocation directory on the device.
struct RemoteCleanup<'a> {
    hdc: &'a Hdc,
    dir: String,
}

impl Drop for RemoteCleanup<'_> {
    fn drop(&mut self) {
        if let Err(err) = self.hdc.shell(&["rm", "-rf", &self.dir]) {
            log::warn!(
                "Failed to clean up remote invocation directory {}: {err}",
                self.dir
            );
        }
    }
}

fn sanitize_path_component(s: &str) -> String {
    let sanitized: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        "inv".to_owned()
    } else {
        sanitized
    }
}

fn short_hex_hash(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    hex::encode(&digest[..8])
}

/// Filesystem-safe identifier unique to this runner invocation.
///
/// Prefer nextest's per-attempt ID when present (hashed so `$`, `:`, and long
/// test names stay within `NAME_MAX`). Otherwise use the process id plus a
/// unique suffix so parallel `cargo test` invocations still get distinct paths.
fn invocation_id(nextest_attempt_id: Option<&str>, pid: u32, unique_suffix: &str) -> String {
    if let Some(attempt_id) = nextest_attempt_id
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        format!("nx-{}", short_hex_hash(attempt_id))
    } else {
        format!("p{pid}-{}", sanitize_path_component(unique_suffix))
    }
}

fn generate_unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos}-{seq}")
}

fn current_invocation_id() -> String {
    let nextest_attempt_id = std::env::var(NEXTEST_ATTEMPT_ID_ENV_VAR).ok();
    invocation_id(
        nextest_attempt_id.as_deref(),
        std::process::id(),
        &generate_unique_suffix(),
    )
}

fn hash_file<D: Digest>(local_bin_path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(local_bin_path)?;
    let mut hasher = D::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buf)
            .context("Failed to read the binary while hashing on the host")?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn ensure_hdc_shell_success(output: &Output, context: &str) -> anyhow::Result<()> {
    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "{context} failed (status: {}). Stdout: {} Stderr: {}",
        output.status,
        stdout.trim(),
        stderr.trim()
    );
}

fn parse_device_hash_output(output: &str) -> anyhow::Result<&str> {
    let hash = output
        .split_whitespace()
        .next()
        .context("Malformed hash output from the device")?;
    if !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Malformed hash output from the device: {output}");
    }
    match hash.len() {
        64 | 32 => Ok(hash),
        other => bail!("Unexpected device hash length: {other}"),
    }
}

fn hash_tool_missing(output: &str, hash_tool: &str) -> bool {
    output.contains(&format!("Unknown command {hash_tool}"))
        || output.contains(&format!("{hash_tool}: not found"))
        || output.contains(&format!("{hash_tool}: inaccessible"))
}

fn compute_device_hash(
    hdc: &Hdc,
    hash_tool: &str,
    on_device_bin_path: &str,
) -> anyhow::Result<Option<String>> {
    let output = hdc.shell(&[hash_tool, on_device_bin_path])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{stdout}{stderr}");

    if hash_tool_missing(&combined_output, hash_tool) {
        return Ok(None);
    }

    if output.status.success() {
        let hash = parse_device_hash_output(&stdout)?;
        return Ok(Some(hash.to_owned()));
    }

    bail!(
        "Failed to run {hash_tool} on the device (status: {}). Output: {}",
        output.status,
        combined_output.trim()
    );
}

/// Sends the binary at `local_bin_path` to the device.
fn send_bin_to_device(
    hdc: &Hdc,
    local_bin_path: &Path,
    remote_dir: &str,
    on_device_bin_path: &str,
) -> anyhow::Result<()> {
    let output = hdc.shell(&["mkdir", "-p", remote_dir])?;
    ensure_hdc_shell_success(&output, "Failed to create test directory on device")?;

    let mut hdc_cmd = hdc.command();
    hdc_cmd
        .args(["file", "send"])
        .arg(local_bin_path)
        .arg(remote_dir);
    let res = hdc_cmd
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to run hdc")
        .wait_with_output()
        .expect("Failed to get output of hdc");
    assert!(res.status.success());
    if !res.stdout.starts_with(b"FileTransfer finish") {
        // Don't bail for now, we still verify the file hash below anyway.
        log::warn!("Unexpected output from hdc. File transfer may have failed.");
    }

    let output = hdc.shell(&["chmod", "+x", on_device_bin_path])?;
    ensure_hdc_shell_success(&output, "Failed to mark test binary executable on device")?;

    let sha256_hash = hash_file::<Sha256>(local_bin_path)?;
    let md5_hash = hash_file::<Md5>(local_bin_path)?;
    debug!("The local sha256 hash is {sha256_hash:?}");
    debug!("The local md5 hash is {md5_hash:?}");

    let device_hash = if let Some(hash) = compute_device_hash(hdc, "sha256sum", on_device_bin_path)?
    {
        ("sha256sum", sha256_hash, hash)
    } else if let Some(hash) = compute_device_hash(hdc, "md5sum", on_device_bin_path)? {
        ("md5sum", md5_hash, hash)
    } else {
        bail!("Neither sha256sum nor md5sum is available on the device");
    };
    let (hash_kind, expected_hash, on_device_hash) = device_hash;
    debug!("The {hash_kind} hash on the device is {on_device_hash}");
    if on_device_hash != expected_hash {
        bail!(
            "Hash mismatch. Local {hash_kind}: {expected_hash}. On device {hash_kind} output: {on_device_hash}"
        );
    }
    Ok(())
}

/// Checks that the requested device - or the only connected device, if none was requested -
/// is available.
fn check_device_selection(
    targets_stdout: &str,
    requested_target: Option<&str>,
) -> anyhow::Result<()> {
    let targets = targets_stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<&str>>();
    if targets.is_empty() || targets.contains(&"[Empty]") {
        bail!("No HDC devices found");
    }
    match requested_target {
        Some(target) if !targets.contains(&target) => bail!(
            "The device `{target}` selected via {HDC_TARGET_ENV_VAR} is not connected. \
             Connected devices: {targets:?}"
        ),
        None if targets.len() != 1 => bail!(
            "Found {} hdc devices: {targets:?}\nSet {HDC_TARGET_ENV_VAR} to the connect-key of \
             the device to use.",
            targets.len()
        ),
        _ => Ok(()),
    }
}

fn unknown_env_vars<I: IntoIterator<Item = String>>(names: I) -> Vec<String> {
    let mut unknown = names
        .into_iter()
        .filter(|name| {
            name.starts_with(ENV_VAR_PREFIX)
                && !KNOWN_ENV_VARS.contains(&name.as_str())
                && !INTERNAL_ENV_VARS.contains(&name.as_str())
        })
        .collect::<Vec<String>>();
    unknown.sort();
    unknown
}

/// Warns about environment variables which look like they are meant for this tool, but are
/// not known to this version. Those are either typos, or configuration for a newer version.
fn warn_about_unknown_env_vars() {
    let names = std::env::vars_os().filter_map(|(name, _)| name.into_string().ok());
    for name in unknown_env_vars(names) {
        eprintln!(
            "warning: The environment variable `{name}` is not known to {} {}. Please check the \
             spelling, or update to a newer version if the variable was added in a later release. \
             Known variables: {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            KNOWN_ENV_VARS.join(", ")
        );
    }
}

fn print_help() {
    println!(
        "\
{name} {version}
{description}

Usage:
    {name} <BINARY> [ARGS]...
    {name} --version | --help

Cargo invokes the runner with the cross-compiled binary as the first argument, and forwards
[ARGS] to the binary running on the device.

Options:
    -h, --help       Print this help
    -V, --version    Print version information

Environment variables:
    {HDC_TARGET_ENV_VAR}
        The hdc connect-key (`hdc -t`) of the device to run the binary on. Required if
        multiple devices are attached, optional otherwise. Use `hdc list targets` to list
        the connect-keys of the attached devices.
    RUST_LOG
        Log level of the runner itself, e.g. `debug`.

Environment variables starting with `{ENV_VAR_PREFIX}` which are not listed above are reported
as unknown, since they are likely typos or configuration for a newer version of this tool.

Example:
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_RUNNER={name}
    cargo test --target aarch64-unknown-linux-ohos",
        name = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION"),
        description = env!("CARGO_PKG_DESCRIPTION"),
    );
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    warn_about_unknown_env_vars();
    let hdc = Hdc::from_env();
    if let Some(target) = &hdc.target {
        debug!("Using the hdc device `{target}` selected via {HDC_TARGET_ENV_VAR}");
    }
    let mut args = std::env::args_os().skip(1);
    let Some(bin_path) = args.next() else {
        print_help();
        bail!("Missing the path to the binary to run on the device");
    };
    // Cargo always passes the binary as the first argument, so flags can only be intended
    // for the runner itself if they appear in this position.
    match bin_path.to_str() {
        Some("--version" | "-V") => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--help" | "-h") => {
            print_help();
            return Ok(());
        }
        _ => {}
    }
    // potentially remaining args should be passed through to the test executable.
    let remaining_args = args
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    let bin_path = Path::new(&bin_path);
    if !bin_path.exists() {
        bail!("Binary not found: {}", bin_path.display());
    }
    let bin_name = bin_path
        .file_name()
        .expect("Test bin must have a filename")
        .to_str()
        .expect("utf-8");
    let remote = RemoteInvocation::new(bin_name, &current_invocation_id());
    debug!("Bin_path: {:?}", bin_path);
    debug!(
        "Remote invocation dir: {}, binary: {}, exit code file: {}",
        remote.dir, remote.bin_path, remote.exit_code_file
    );

    let targets = Command::new("hdc")
        .args(["list", "targets"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn `hdc list targets`")?
        .wait_with_output()
        .context("Failed to wait for `hdc list targets`")?;
    ensure_hdc_shell_success(&targets, "Failed to list HDC targets")?;
    let targets_stdout = String::from_utf8_lossy(&targets.stdout);
    check_device_selection(&targets_stdout, hdc.target.as_deref())?;

    let _cleanup = RemoteCleanup {
        hdc: &hdc,
        dir: remote.dir.clone(),
    };

    send_bin_to_device(&hdc, bin_path, &remote.dir, &remote.bin_path)
        .context("Failed to send binary to device")?;

    let output = hdc.shell(&["rm", "-f", &remote.exit_code_file])?;
    ensure_hdc_shell_success(&output, "Failed to clear device exit code file")?;

    // We don't really know how long the test program would run, so we can't set a reasonable
    // timeout. We just fallback to using hdc shell as a command again.
    let mut command = format!(
        "cd {} && {}",
        shell_quote(&remote.dir),
        shell_quote(&remote.bin_path)
    );
    for arg in &remaining_args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }
    command.push_str("; printf '%s' \"$?\" > ");
    command.push_str(&shell_quote(&remote.exit_code_file));

    let res = hdc
        .command()
        .arg("shell")
        .arg(&command)
        .spawn()
        .expect("Failed to run hdc")
        .wait()
        .expect("Failed to get output of hdc");
    if !res.success() {
        bail!("Non zero exit code from hdc: {res}");
    }

    let mut hdc_cmd = hdc.command();
    let res = hdc_cmd
        .arg("shell")
        .arg("cat")
        .arg(&remote.exit_code_file)
        .stdout(Stdio::piped())
        .spawn()
        .context("Failed to spawn hdc shell")?
        .wait_with_output()
        .context("Failed to wait for hdc shell")?;
    if !res.status.success() {
        bail!("Non zero exit code from hdc: {res:?}");
    }
    let stdout = String::from_utf8_lossy(&res.stdout);
    if stdout.trim() != "0" {
        bail!("Binary exited with Non-zero code: {stdout}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        check_device_selection, generate_unique_suffix, hash_tool_missing, invocation_id,
        parse_device_hash_output, sanitize_path_component, unknown_env_vars, RemoteInvocation,
        TEST_BIN_DIR,
    };
    use std::collections::HashSet;

    #[test]
    fn detects_unknown_env_vars() {
        let names = [
            "PATH",
            "OHOS_TEST_RUNNER_HDC_TARGET",
            "OHOS_TEST_RUNNER_HDC_TARGETT",
            "OHOS_TEST_RUNNER_FUTURE_OPTION",
            "OHOS_TEST_RUNNER_INTEGRATION_TARGET",
            "OHOS_SDK_NATIVE",
        ]
        .map(str::to_owned);
        assert_eq!(
            unknown_env_vars(names),
            [
                "OHOS_TEST_RUNNER_FUTURE_OPTION",
                "OHOS_TEST_RUNNER_HDC_TARGETT"
            ]
        );
    }

    #[test]
    fn accepts_single_device_without_selection() {
        assert!(check_device_selection("7001005458323933328a01e9a4bb3900\n", None).is_ok());
    }

    #[test]
    fn rejects_multiple_devices_without_selection() {
        let targets = "127.0.0.1:5555\n7001005458323933328a01e9a4bb3900\n";
        let err = check_device_selection(targets, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("OHOS_TEST_RUNNER_HDC_TARGET"), "{err}");
    }

    #[test]
    fn accepts_selected_device_among_multiple() {
        let targets = "127.0.0.1:5555\n7001005458323933328a01e9a4bb3900\n";
        assert!(check_device_selection(targets, Some("127.0.0.1:5555")).is_ok());
    }

    #[test]
    fn rejects_selected_device_that_is_not_connected() {
        let targets = "127.0.0.1:5555\n";
        let err = check_device_selection(targets, Some("127.0.0.1:5556"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("127.0.0.1:5556"), "{err}");
    }

    #[test]
    fn rejects_empty_target_list() {
        assert!(check_device_selection("[Empty]\n", Some("127.0.0.1:5555")).is_err());
        assert!(check_device_selection("", None).is_err());
    }

    #[test]
    fn parses_md5_device_hash_output() {
        let output = "0123456789abcdef0123456789abcdef  /tmp/bin\n";
        assert_eq!(
            parse_device_hash_output(output).unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn detects_toybox_missing_hash_tool() {
        let output = "toybox: Unknown command sha256sum (see \"toybox --help\")\n";
        assert!(hash_tool_missing(output, "sha256sum"));
    }

    fn assert_disjoint_remote_invocations(a: &RemoteInvocation, b: &RemoteInvocation) {
        assert_ne!(a.dir, b.dir);
        assert_ne!(a.bin_path, b.bin_path);
        assert_ne!(a.exit_code_file, b.exit_code_file);

        let a_prefix = format!("{}/", a.dir);
        let b_prefix = format!("{}/", b.dir);
        assert!(
            a.bin_path.starts_with(&a_prefix) && a.exit_code_file.starts_with(&a_prefix),
            "{a:?}"
        );
        assert!(
            b.bin_path.starts_with(&b_prefix) && b.exit_code_file.starts_with(&b_prefix),
            "{b:?}"
        );
        assert!(
            !a.bin_path.starts_with(&b_prefix) && !a.exit_code_file.starts_with(&b_prefix),
            "first invocation reused second dir: {a:?} {b:?}"
        );
        assert!(
            !b.bin_path.starts_with(&a_prefix) && !b.exit_code_file.starts_with(&a_prefix),
            "second invocation reused first dir: {a:?} {b:?}"
        );

        for path in [
            &a.dir,
            &a.bin_path,
            &a.exit_code_file,
            &b.dir,
            &b.bin_path,
            &b.exit_code_file,
        ] {
            assert!(
                path.starts_with(&format!("{TEST_BIN_DIR}/")),
                "path {path} is not under {TEST_BIN_DIR}"
            );
            assert!(
                !path.split('/').any(|component| component == ".."),
                "path {path} contains a parent-directory component"
            );
        }
    }

    #[test]
    fn generated_unique_suffixes_are_distinct() {
        let suffixes: Vec<String> = (0..64).map(|_| generate_unique_suffix()).collect();
        let unique: HashSet<&String> = suffixes.iter().collect();
        assert_eq!(unique.len(), suffixes.len());
    }

    #[test]
    fn fallback_invocation_ids_differ_by_pid_or_suffix() {
        assert_ne!(
            invocation_id(None, 11, "aaa"),
            invocation_id(None, 12, "aaa")
        );
        assert_ne!(
            invocation_id(None, 11, "aaa"),
            invocation_id(None, 11, "bbb")
        );
    }

    #[test]
    fn nextest_attempt_ids_produce_distinct_invocation_ids() {
        let attempt_a = "55459fda-13fe-406a-b4e3-0230fd52bb03:pkg::bin$mod::test_a";
        let attempt_b = "55459fda-13fe-406a-b4e3-0230fd52bb03:pkg::bin$mod::test_b";
        assert_ne!(
            invocation_id(Some(attempt_a), 1, "same"),
            invocation_id(Some(attempt_b), 1, "same")
        );
    }

    #[test]
    fn invocation_id_is_path_safe() {
        let id = invocation_id(Some("run:bin$foo::bar/../baz#2"), 7, "suffix");
        assert!(!id.contains('/'));
        assert!(!id.contains('$'));
        assert!(!id.contains(':'));
        assert_ne!(id, ".");
        assert_ne!(id, "..");
        assert_eq!(id, sanitize_path_component(&id));
    }

    #[test]
    fn sanitize_path_component_rejects_parent_and_empty() {
        assert_eq!(sanitize_path_component(".."), "inv");
        assert_eq!(sanitize_path_component("."), "inv");
        assert_eq!(sanitize_path_component(""), "inv");
        assert_eq!(sanitize_path_component("foo$bar"), "foo_bar");
    }

    #[test]
    fn remote_paths_are_unique_per_invocation_for_the_same_binary() {
        let first = RemoteInvocation::new("crate-tests", &invocation_id(None, 11, "aaa"));
        let second = RemoteInvocation::new("crate-tests", &invocation_id(None, 12, "bbb"));
        assert_disjoint_remote_invocations(&first, &second);
        assert!(first.bin_path.ends_with("/crate-tests"));
        assert!(second.bin_path.ends_with("/crate-tests"));
        assert!(first.exit_code_file.ends_with("/exit_code"));
        assert!(second.exit_code_file.ends_with("/exit_code"));
    }

    #[test]
    fn nextest_parallel_attempts_do_not_share_remote_files() {
        let run = "55459fda-13fe-406a-b4e3-0230fd52bb03";
        let first = RemoteInvocation::new(
            "crate-tests",
            &invocation_id(Some(&format!("{run}:pkg::bin$mod::test_one")), 1, "x"),
        );
        let second = RemoteInvocation::new(
            "crate-tests",
            &invocation_id(Some(&format!("{run}:pkg::bin$mod::test_two")), 1, "x"),
        );
        assert_disjoint_remote_invocations(&first, &second);
    }
}

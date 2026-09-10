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
use std::ffi::OsStr;
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const TEST_BIN_DIR: &str = "/data/local/tmp/ohos-test-runner";

/// Printed to stderr by the hdc client when it cannot reach the hdc server. hdc exits with
/// status 0 all the same, so the failure is only visible in its output.
const HDC_SERVER_UNREACHABLE: &str = "Connect server failed";

/// Printed to stdout by the hdc client, with exit status 0, when it does not accept the address
/// passed to `-s`.
const HDC_SERVER_REJECTED: &[&str] = &["-s content IP incorrect.", "-s content port incorrect."];

/// Environment variable to select the device (hdc connect-key) to run the binary on.
const HDC_TARGET_ENV_VAR: &str = "OHOS_TEST_RUNNER_HDC_TARGET";

/// Environment variable naming the hdc server (`hdc -s`) to use, as `<host>:<port>`, for a
/// device attached to another machine.
const HDC_SERVER_ENV_VAR: &str = "OHOS_TEST_RUNNER_HDC_SERVER";

/// Environment variable listing shared libraries which the binary needs at runtime and which
/// the device does not provide, in the platform's `PATH` format. `cargo-ohos` sets it when the
/// toolchain carries its own C++ runtime.
const RUNTIME_LIBRARIES_ENV_VAR: &str = "OHOS_TEST_RUNNER_RUNTIME_LIBRARIES";

const ENV_VAR_PREFIX: &str = "OHOS_TEST_RUNNER";

/// The user-facing environment variables of this tool. Variables with the [`ENV_VAR_PREFIX`]
/// which are neither listed here nor in [`INTERNAL_ENV_VARS`] are reported to the user
/// as unknown.
const KNOWN_ENV_VARS: &[&str] = &[
    HDC_TARGET_ENV_VAR,
    HDC_SERVER_ENV_VAR,
    RUNTIME_LIBRARIES_ENV_VAR,
];

/// Internal environment variables, which are recognized to avoid spurious warnings,
/// but not advertised to users.
const INTERNAL_ENV_VARS: &[&str] = &[
    // Only used by the integration tests of this crate, but inherited by the runner.
    "OHOS_TEST_RUNNER_INTEGRATION_TARGET",
];

/// The hdc invocation, including the server (`-s`) and the device selection (`-t`) if
/// configured.
struct Hdc {
    /// The server address in the form `hdc -s` accepts: a numeric IP address and a port.
    server: Option<String>,
    target: Option<String>,
}

impl Hdc {
    fn from_env() -> anyhow::Result<Self> {
        let server = non_empty_env_var(HDC_SERVER_ENV_VAR)
            .map(|server| resolve_server(&server))
            .transpose()?;
        let target = non_empty_env_var(HDC_TARGET_ENV_VAR);
        Ok(Self { server, target })
    }

    /// An hdc command addressing the server, but no particular device.
    fn server_command(&self) -> Command {
        let mut command = Command::new("hdc");
        if let Some(server) = &self.server {
            command.args(["-s", server]);
        }
        command
    }

    /// An hdc command addressing the selected device.
    fn command(&self) -> Command {
        let mut command = self.server_command();
        if let Some(target) = &self.target {
            command.args(["-t", target]);
        }
        command
    }

    fn shell(&self, args: &[&str]) -> anyhow::Result<Output> {
        self.output(self.command().arg("shell").args(args))
    }

    /// Runs the hdc `command` to completion and captures its output, failing if hdc could not
    /// reach its server.
    fn output(&self, command: &mut Command) -> anyhow::Result<Output> {
        let output = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn hdc")?
            .wait_with_output()
            .context("Failed to wait for hdc")?;
        let reported =
            |message| reports(&output.stdout, message) || reports(&output.stderr, message);
        if reported(HDC_SERVER_UNREACHABLE) {
            bail!(self.unreachable_server_error());
        }
        if let Some(message) = HDC_SERVER_REJECTED
            .iter()
            .copied()
            .find(|message| reported(message))
        {
            bail!(
                "hdc does not accept the server address `{}` (`{message}`). Check \
                 {HDC_SERVER_ENV_VAR}.",
                self.server.as_deref().unwrap_or_default()
            );
        }
        Ok(output)
    }

    /// The connect-keys of the devices attached to the server.
    fn list_targets(&self) -> anyhow::Result<String> {
        let output = self.output(self.server_command().args(["list", "targets"]))?;
        ensure_hdc_shell_success(&output, "Failed to list HDC targets")?;
        let targets = String::from_utf8_lossy(&output.stdout).into_owned();
        // A server without devices answers `[Empty]`. No answer at all comes from something
        // which accepts the connection and closes it, e.g. an SSH tunnel without an hdc server
        // at its other end.
        if targets.trim().is_empty() {
            bail!(self.silent_server_error());
        }
        Ok(targets)
    }

    fn unreachable_server_error(&self) -> String {
        match &self.server {
            None => format!(
                "hdc cannot reach the hdc server (`{HDC_SERVER_UNREACHABLE}`). Check that the \
                 server is running, e.g. with `hdc list targets`."
            ),
            Some(server) => format!(
                "hdc cannot reach the hdc server at {server}, selected via {HDC_SERVER_ENV_VAR} \
                 (`{HDC_SERVER_UNREACHABLE}`). Check that the server is running on that machine, \
                 that it listens on an address reachable from here (a server started with \
                 `-s 127.0.0.1:<port>` only accepts connections from its own machine, or through \
                 a tunnel), and that no firewall blocks the port. `hdc -s {server} list targets` \
                 tries the same connection."
            ),
        }
    }

    fn silent_server_error(&self) -> String {
        match &self.server {
            None => "The hdc server closed the connection without answering. Check that it is \
                     the same hdc version as this client, with `hdc checkserver`."
                .to_owned(),
            Some(server) => format!(
                "The hdc server at {server}, selected via {HDC_SERVER_ENV_VAR}, closed the \
                 connection without answering. Either it is a different hdc version than this \
                 client - `hdc -s {server} checkserver` shows both - or what accepts connections \
                 there is not an hdc server: with an SSH tunnel, check that the hdc server is \
                 running on the machine with the device, and that the tunnel forwards to its port."
            ),
        }
    }
}

fn non_empty_env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Resolves a `<host>:<port>` server address into the form `hdc -s` accepts, which takes neither
/// host names nor the bracketed form of IPv6 addresses. IPv4 is preferred, since that is the
/// form hdc servers listen on by default.
fn resolve_server(server: &str) -> anyhow::Result<String> {
    let addresses = server
        .to_socket_addrs()
        .with_context(|| {
            format!(
                "Cannot resolve the hdc server `{server}` from {HDC_SERVER_ENV_VAR}. Expected \
                 `<host>:<port>`, e.g. `192.168.1.20:8710`."
            )
        })?
        .collect::<Vec<SocketAddr>>();
    let address = addresses
        .iter()
        .find(|address| address.is_ipv4())
        .or(addresses.first())
        .with_context(|| {
            format!("The hdc server `{server}` from {HDC_SERVER_ENV_VAR} resolves to no address")
        })?;
    // hdc rejects port 0, and accepts an unspecified address like 0.0.0.0 - which is where a
    // server listens, and reaches the server on this machine instead of the one meant.
    if address.port() == 0 || address.ip().is_unspecified() {
        bail!(
            "The hdc server `{server}` from {HDC_SERVER_ENV_VAR} names no particular machine or \
             port. Use the address of the machine the device is attached to, and the port its \
             server listens on, e.g. `192.168.1.20:8710`."
        );
    }
    Ok(format!("{}:{}", address.ip(), address.port()))
}

/// Whether hdc printed `message` on a line of its own. The lines of `hdc shell` end in CRLF.
fn reports(output: &[u8], message: &str) -> bool {
    String::from_utf8_lossy(output)
        .lines()
        .any(|line| line.trim() == message)
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

/// The shared libraries the binary needs on the device, as configured by
/// [`RUNTIME_LIBRARIES_ENV_VAR`].
fn runtime_libraries() -> Vec<PathBuf> {
    match std::env::var_os(RUNTIME_LIBRARIES_ENV_VAR) {
        Some(value) => parse_runtime_libraries(&value),
        None => Vec::new(),
    }
}

fn parse_runtime_libraries(value: &OsStr) -> Vec<PathBuf> {
    std::env::split_paths(value)
        .filter(|path| !path.as_os_str().is_empty())
        .collect()
}

/// Sends the runtime libraries next to the binary, so `LD_LIBRARY_PATH` finds them there.
///
/// The libraries are identical for every binary of a `cargo test` run, so skip the transfer
/// when the device already holds the same file.
fn send_runtime_libraries_to_device(hdc: &Hdc, libraries: &[PathBuf]) -> anyhow::Result<()> {
    for library in libraries {
        if !library.is_file() {
            bail!(
                "Runtime library not found: {}. Check {RUNTIME_LIBRARIES_ENV_VAR}.",
                library.display()
            );
        }
        let name = library
            .file_name()
            .expect("A runtime library must have a filename")
            .to_str()
            .context("Runtime library names must be utf-8")?;
        let on_device_path = format!("{TEST_BIN_DIR}/{name}");
        if device_file_matches(hdc, library, &on_device_path)? {
            debug!("The device already has an identical {name}, skipping the transfer");
            continue;
        }
        send_file_to_device(hdc, library, &on_device_path, false)
            .with_context(|| format!("Failed to send the runtime library {name} to the device"))?;
    }
    Ok(())
}

/// Whether the device holds a file with the same contents as `local_path`.
///
/// `hdc shell` reports success even when the command it ran failed, so anything which does not
/// parse as a hash - a missing file, a missing hash tool - counts as "no" and leads to a
/// transfer.
fn device_file_matches(hdc: &Hdc, local_path: &Path, on_device_path: &str) -> anyhow::Result<bool> {
    let output = hdc.shell(&["sha256sum", on_device_path])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Ok(device_hash) = parse_device_hash_output(&stdout) else {
        return Ok(false);
    };
    Ok(device_hash == hash_file::<Sha256>(local_path)?)
}

/// Sends the binary at `local_bin_path` to the device.
fn send_bin_to_device(
    hdc: &Hdc,
    local_bin_path: &Path,
    on_device_bin_path: &str,
) -> anyhow::Result<()> {
    send_file_to_device(hdc, local_bin_path, on_device_bin_path, true)
}

fn send_file_to_device(
    hdc: &Hdc,
    local_bin_path: &Path,
    on_device_bin_path: &str,
    executable: bool,
) -> anyhow::Result<()> {
    let output = hdc.shell(&["mkdir", "-p", TEST_BIN_DIR])?;
    ensure_hdc_shell_success(&output, "Failed to create test directory on device")?;

    let res = hdc.output(
        hdc.command()
            .args(["file", "send"])
            .arg(local_bin_path)
            .arg(TEST_BIN_DIR),
    )?;
    assert!(res.status.success());
    // Captured to recognize an unreachable server, but meant for the user.
    eprint!("{}", String::from_utf8_lossy(&res.stderr));
    if !res.stdout.starts_with(b"FileTransfer finish") {
        // Don't bail for now, we still verify the file hash below anyway.
        log::warn!("Unexpected output from hdc. File transfer may have failed.");
    }

    if executable {
        let output = hdc.shell(&["chmod", "+x", on_device_bin_path])?;
        ensure_hdc_shell_success(&output, "Failed to mark test binary executable on device")?;
    }

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
    {HDC_SERVER_ENV_VAR}
        The hdc server (`hdc -s`) to use, as `<host>:<port>`, when the device is attached to
        another machine. Unlike `hdc -s`, a host name is accepted. By default, hdc uses the
        server on this machine. `hdc -s <ip>:<port> list targets` lists the connect-keys of
        the devices attached to the other machine.
    {RUNTIME_LIBRARIES_ENV_VAR}
        Shared libraries the binary needs but the device does not provide, separated like
        `PATH`. They are sent next to the binary and found via `LD_LIBRARY_PATH`.
        `cargo-ohos` sets this when the toolchain carries its own C++ runtime.
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
    let hdc = Hdc::from_env()?;
    if let Some(server) = &hdc.server {
        debug!("Using the hdc server {server} selected via {HDC_SERVER_ENV_VAR}");
    }
    if let Some(target) = &hdc.target {
        debug!("Using the hdc device `{target}` selected via {HDC_TARGET_ENV_VAR}");
    }
    // potentially remaining args should be passed through to the test executable.
    let remaining_args = args
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    let bin_path = Path::new(&bin_path);
    if !bin_path.exists() {
        bail!("Binary not found: {}", bin_path.display());
    }
    let bin_name = bin_path.file_name().expect("Test bin must have a filename");
    let on_device_bin_path = format!("{TEST_BIN_DIR}/{}", bin_name.to_str().expect("utf-8"));
    debug!("Bin_path: {:?}", bin_path);

    let targets = hdc.list_targets()?;
    check_device_selection(&targets, hdc.target.as_deref())?;

    send_bin_to_device(&hdc, bin_path, &on_device_bin_path)
        .context("Failed to send binary to device")?;

    let runtime_libraries = runtime_libraries();
    send_runtime_libraries_to_device(&hdc, &runtime_libraries)?;

    let exit_code_file = format!(
        "{}/last_exit_code-{}",
        TEST_BIN_DIR,
        bin_name.to_str().expect("utf-8")
    );
    let output = hdc.shell(&["rm", "-f", &exit_code_file])?;
    ensure_hdc_shell_success(&output, "Failed to clear device exit code file")?;

    // We don't really know how long the test program would run, so we can't set a reasonable
    // timeout. We just fallback to using hdc shell as a command again.
    let mut command = format!("cd {} && ", shell_quote(TEST_BIN_DIR));
    if !runtime_libraries.is_empty() {
        // The binary needs libraries the device does not provide, and musl searches neither
        // the working directory nor the directory of the binary.
        command.push_str(&format!("LD_LIBRARY_PATH={} ", shell_quote(TEST_BIN_DIR)));
    }
    command.push_str(&shell_quote(&on_device_bin_path));
    for arg in &remaining_args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }
    command.push_str("; printf '%s' \"$?\" > ");
    command.push_str(&shell_quote(&exit_code_file));

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

    let res = hdc.shell(&["cat", &exit_code_file])?;
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
        check_device_selection, hash_tool_missing, parse_device_hash_output,
        parse_runtime_libraries, reports, resolve_server, unknown_env_vars, Hdc,
        HDC_SERVER_REJECTED, HDC_SERVER_UNREACHABLE,
    };
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn parses_runtime_libraries() {
        let joined =
            std::env::join_paths([PathBuf::from("/a/libc++.so"), PathBuf::from("/b/x.so")])
                .expect("joinable");

        assert_eq!(
            parse_runtime_libraries(&joined),
            [PathBuf::from("/a/libc++.so"), PathBuf::from("/b/x.so")]
        );
    }

    #[test]
    fn ignores_empty_runtime_library_entries() {
        let separator = if cfg!(windows) { ";" } else { ":" };
        let value = OsString::from(format!("{separator}/a/libc++.so{separator}"));

        assert_eq!(
            parse_runtime_libraries(&value),
            [PathBuf::from("/a/libc++.so")]
        );
    }

    #[test]
    fn detects_unknown_env_vars() {
        let names = [
            "PATH",
            "OHOS_TEST_RUNNER_HDC_TARGET",
            "OHOS_TEST_RUNNER_HDC_TARGETT",
            "OHOS_TEST_RUNNER_RUNTIME_LIBRARIES",
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
    fn detects_an_unreachable_server() {
        assert!(reports(b"Connect server failed\n", HDC_SERVER_UNREACHABLE));
        assert!(reports(
            b"Connect server failed\r\n",
            HDC_SERVER_UNREACHABLE
        ));
        assert!(!reports(b"", HDC_SERVER_UNREACHABLE));
        assert!(!reports(b"127.0.0.1:5555\n", HDC_SERVER_UNREACHABLE));
        for message in HDC_SERVER_REJECTED {
            assert!(reports(format!("{message}\n").as_bytes(), message));
        }
    }

    #[test]
    fn resolves_the_server_into_the_form_hdc_accepts() {
        assert_eq!(
            resolve_server("192.168.1.20:8710").unwrap(),
            "192.168.1.20:8710"
        );
        // hdc rejects host names, and IPv4 is what an hdc server listens on by default.
        assert_eq!(resolve_server("localhost:8710").unwrap(), "127.0.0.1:8710");
        // hdc rejects the bracketed form.
        assert_eq!(resolve_server("[::1]:8710").unwrap(), "::1:8710");
        assert!(resolve_server("8710").is_err());
        assert!(resolve_server("192.168.1.20").is_err());
        // hdc rejects port 0, and an unspecified address reaches the server on this machine.
        assert!(resolve_server("localhost:0").is_err());
        assert!(resolve_server("0.0.0.0:8710").is_err());
        assert!(resolve_server("[::]:8710").is_err());
    }

    #[test]
    fn the_server_precedes_the_device_selection() {
        let hdc = Hdc {
            server: Some("127.0.0.1:8710".to_owned()),
            target: Some("127.0.0.1:5555".to_owned()),
        };
        assert_eq!(
            hdc.command().get_args().collect::<Vec<_>>(),
            ["-s", "127.0.0.1:8710", "-t", "127.0.0.1:5555"]
        );
        // Listing the devices addresses the server only.
        assert_eq!(
            hdc.server_command().get_args().collect::<Vec<_>>(),
            ["-s", "127.0.0.1:8710"]
        );

        let local = Hdc {
            server: None,
            target: None,
        };
        assert_eq!(local.command().get_args().count(), 0);
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
}

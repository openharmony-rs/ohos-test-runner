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
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod session;

use session::Session;

const TEST_BIN_DIR: &str = "/data/local/tmp/ohos-test-runner";

/// Printed to stderr by the hdc client when it cannot reach the hdc server. hdc exits with
/// status 0 all the same, so the failure is only visible in its output.
const HDC_SERVER_UNREACHABLE: &str = "Connect server failed";

/// Printed to stdout by the hdc client, with exit status 0, when it does not accept the address
/// passed to `-s`.
const HDC_SERVER_REJECTED: &[&str] = &["-s content IP incorrect.", "-s content port incorrect."];

/// Written to the exit code file when the device turned out not to hold the test binary.
///
/// The presence check runs in the same command as the test, so that nothing can collect the
/// binary between the two. Reporting the miss through the exit code file, which is read anyway,
/// keeps the output of the test itself untouched.
const BIN_MISSING: &str = "missing";

/// Marks a build directory, so that the pruning of old builds tells them from the directories
/// holding the files a test reads.
const BUILD_MARKER: &str = ".build";

/// Marks a fixture directory whose transfer finished. A directory without it was left behind by
/// an invocation which was killed, and is transferred again.
const FIXTURES_MARKER: &str = ".ready";

/// Echoed by the probe of the miss path for the parts the device already has.
const HAVE_BIN_MARKER: &str = "OHOS_TEST_RUNNER_HAVE_BIN";
const HAVE_FIXTURES_MARKER: &str = "OHOS_TEST_RUNNER_HAVE_FIXTURES";

/// How long a build stays on the device after its last use, in minutes.
///
/// The cache only has to survive one `cargo test` or `cargo nextest run`, which invokes the same
/// binary many times over seconds to minutes. Anything longer only fills up the device.
const DEFAULT_CACHE_TTL_MINUTES: u64 = 30;

/// Environment variable to select the device (hdc connect-key) to run the binary on.
const HDC_TARGET_ENV_VAR: &str = "OHOS_TEST_RUNNER_HDC_TARGET";

/// Environment variable naming the hdc server (`hdc -s`) to use, as `<host>:<port>`, for a
/// device attached to another machine.
const HDC_SERVER_ENV_VAR: &str = "OHOS_TEST_RUNNER_HDC_SERVER";

/// Environment variable listing the files and directories a test reads at runtime, relative to
/// the package root, in the platform's `PATH` format.
const FIXTURES_ENV_VAR: &str = "OHOS_TEST_RUNNER_FIXTURES";

/// Environment variable overriding [`DEFAULT_CACHE_TTL_MINUTES`].
const CACHE_TTL_ENV_VAR: &str = "OHOS_TEST_RUNNER_CACHE_TTL_MINUTES";

/// Environment variable which keeps the builds of a run on the device after the run ends.
const KEEP_BUILDS_ENV_VAR: &str = "OHOS_TEST_RUNNER_KEEP_BUILDS";

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
    FIXTURES_ENV_VAR,
    CACHE_TTL_ENV_VAR,
    KEEP_BUILDS_ENV_VAR,
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

/// The device-side paths of a single runner invocation.
///
/// The binary lives in a directory named after its contents, so that concurrent invocations of
/// the same build share it, and an invocation of a different build never overwrites a binary
/// another invocation is currently executing. The exit code file is per process, since a pid is
/// unique among the invocations which are alive at the same time.
struct RemotePaths {
    bin_dir: String,
    bin: String,
    exit_code_file: String,
    /// The mirror of the package root, when the test reads files from it. Also the working
    /// directory of the test, so that its relative paths resolve.
    fixtures_dir: Option<String>,
}

impl RemotePaths {
    fn new(bin_name: &str, local_sha256: &str, pid: u32, fixtures_sha256: Option<&str>) -> Self {
        let bin_dir = format!("{TEST_BIN_DIR}/{}", content_id(local_sha256));
        Self {
            bin: format!("{bin_dir}/{bin_name}"),
            bin_dir,
            exit_code_file: format!("{TEST_BIN_DIR}/exit_code-{pid}"),
            fixtures_dir: fixtures_sha256
                .map(|hash| format!("{TEST_BIN_DIR}/{}", content_id(hash))),
        }
    }

    /// The name the binary is transferred under, before it is renamed into place.
    fn incoming_bin(&self, pid: u32) -> String {
        format!("{}.{pid}.incoming", self.bin)
    }

    fn build_marker(&self) -> String {
        format!("{}/{BUILD_MARKER}", self.bin_dir)
    }

    fn fixtures_marker(&self) -> Option<String> {
        self.fixtures_dir
            .as_ref()
            .map(|dir| format!("{dir}/{FIXTURES_MARKER}"))
    }

    /// The directories of this invocation: the build, and the mirror of the package root.
    fn dirs(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.bin_dir.as_str()).chain(self.fixtures_dir.as_deref())
    }

    /// The working directory of the test: the mirror of the package root if there is one, and
    /// the shared directory otherwise, which is where the runtime libraries live.
    fn working_dir(&self) -> &str {
        self.fixtures_dir.as_deref().unwrap_or(TEST_BIN_DIR)
    }
}

/// The part of a hash which names a directory on the device. Long enough that the builds and
/// fixture sets of one device never collide.
fn content_id(sha256: &str) -> &str {
    sha256.get(..16).unwrap_or(sha256)
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
        let local_sha256 = hash_file::<Sha256>(library)?;
        if device_file_matches(hdc, &local_sha256, &on_device_path)? {
            debug!("The device already has an identical {name}, skipping the transfer");
            continue;
        }
        send_file_to_device(hdc, library, &on_device_path)
            .and_then(|()| verify_device_file(hdc, library, &on_device_path, &local_sha256))
            .with_context(|| format!("Failed to send the runtime library {name} to the device"))?;
    }
    Ok(())
}

/// Whether the device holds a file with the same contents as the local file hashing to
/// `local_sha256`.
///
/// `hdc shell` reports success even when the command it ran failed, so anything which does not
/// parse as a hash - a missing file, a missing hash tool - counts as "no" and leads to a
/// transfer.
fn device_file_matches(
    hdc: &Hdc,
    local_sha256: &str,
    on_device_path: &str,
) -> anyhow::Result<bool> {
    let output = hdc.shell(&["sha256sum", on_device_path])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Ok(device_hash) = parse_device_hash_output(&stdout) else {
        return Ok(false);
    };
    Ok(device_hash == local_sha256)
}

/// The files and directories a test reads at runtime, from [`FIXTURES_ENV_VAR`].
///
/// They are mirrored on the device under the package root's relative layout, and the test runs
/// with that mirror as its working directory, so that its relative paths resolve.
struct Fixtures {
    /// The package root on the host, which the device directory mirrors.
    manifest_dir: PathBuf,
    /// The declared entries, relative to `manifest_dir`.
    entries: Vec<PathBuf>,
}

impl Fixtures {
    /// The declaration, or `None` when the tests need no files of their own.
    fn from_env() -> anyhow::Result<Option<Self>> {
        let Some(value) = std::env::var_os(FIXTURES_ENV_VAR) else {
            return Ok(None);
        };
        let entries = parse_fixture_entries(&value)?;
        if entries.is_empty() {
            return Ok(None);
        }
        let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .with_context(|| {
                format!(
                    "CARGO_MANIFEST_DIR is unset, so the relative paths in {FIXTURES_ENV_VAR} \
                     cannot be resolved. Cargo sets it when it runs the target runner."
                )
            })?;
        Ok(Some(Self {
            manifest_dir,
            entries,
        }))
    }
}

/// The entries must stay inside the mirror, so absolute paths and `..` are rejected. An absolute
/// path could not be reproduced on the device anyway: its root filesystem is read-only.
fn parse_fixture_entries(value: &OsStr) -> anyhow::Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    for entry in std::env::split_paths(value).filter(|path| !path.as_os_str().is_empty()) {
        if entry.is_absolute() {
            bail!(
                "{FIXTURES_ENV_VAR} takes paths relative to the package root, but `{}` is \
                 absolute. The device cannot reproduce an absolute host path.",
                entry.display()
            );
        }
        if entry
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            bail!(
                "{FIXTURES_ENV_VAR} takes paths inside the package root, but `{}` leaves it.",
                entry.display()
            );
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// The path of `relative` inside the mirror. The device separates its path components with `/`,
/// whatever the host does.
fn device_relative_path(relative: &Path) -> anyhow::Result<String> {
    let mut components = Vec::new();
    for component in relative.components() {
        let part = component
            .as_os_str()
            .to_str()
            .context("Fixture paths must be utf-8")?;
        components.push(part);
    }
    Ok(components.join("/"))
}

/// The content id of the whole fixture set: every relative path and the contents behind it, so
/// that an edit or a rename lands in a directory of its own.
fn hash_fixtures(fixtures: &Fixtures) -> anyhow::Result<String> {
    let mut files = Vec::new();
    for entry in &fixtures.entries {
        collect_fixture_files(&fixtures.manifest_dir, entry, &mut files)?;
    }
    files.sort();
    files.dedup();

    let mut hasher = Sha256::new();
    for relative in &files {
        hasher.update(device_relative_path(relative)?.as_bytes());
        hasher.update([0]);
        hasher.update(hash_file::<Sha256>(&fixtures.manifest_dir.join(relative))?.as_bytes());
        hasher.update([0]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn collect_fixture_files(
    manifest_dir: &Path,
    relative: &Path,
    files: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    let path = manifest_dir.join(relative);
    let metadata = std::fs::metadata(&path).with_context(|| {
        format!(
            "Cannot read `{}` from {FIXTURES_ENV_VAR}: {} does not exist",
            relative.display(),
            path.display()
        )
    })?;
    if metadata.is_file() {
        files.push(relative.to_owned());
        return Ok(());
    }
    for child in std::fs::read_dir(&path)
        .with_context(|| format!("Failed to read the fixture directory {}", path.display()))?
    {
        let child = child?;
        collect_fixture_files(manifest_dir, &relative.join(child.file_name()), files)?;
    }
    Ok(())
}

/// Mirrors the fixtures on the device, and marks the directory complete once every entry
/// arrived. A directory without the marker was left behind by an invocation which was killed,
/// and is transferred again.
fn install_fixtures(hdc: &Hdc, fixtures: &Fixtures, remote: &RemotePaths) -> anyhow::Result<()> {
    let (fixtures_dir, marker) = remote
        .fixtures_dir
        .as_ref()
        .zip(remote.fixtures_marker())
        .expect("The fixtures have a directory on the device");

    // `hdc file send` creates the directories a transferred directory needs, but not the ones a
    // single file needs, so create every parent up front - in one command, whatever the number
    // of entries.
    let mut parents = BTreeSet::from([fixtures_dir.to_owned()]);
    let mut targets = Vec::new();
    for entry in &fixtures.entries {
        let relative = device_relative_path(entry)?;
        let target = format!("{fixtures_dir}/{relative}");
        if let Some((parent, _)) = target.rsplit_once('/') {
            parents.insert(parent.to_owned());
        }
        targets.push((fixtures.manifest_dir.join(entry), target));
    }
    let mkdir = format!(
        "mkdir -p {}",
        parents
            .iter()
            .map(|dir| shell_quote(dir))
            .collect::<Vec<String>>()
            .join(" ")
    );
    ensure_hdc_shell_success(
        &hdc.shell(&[&mkdir])?,
        "Failed to create the fixture directories on device",
    )?;

    for (local, target) in &targets {
        send_file_to_device(hdc, local, target).with_context(|| {
            format!(
                "Failed to send the fixture {} to the device",
                local.display()
            )
        })?;
    }

    ensure_hdc_shell_success(
        &hdc.shell(&["touch", &marker])?,
        "Failed to mark the fixtures complete on device",
    )
}

/// What the device is still missing, having created the directories the transfers need.
struct DeviceState {
    has_bin: bool,
    has_fixtures: bool,
}

fn probe_device(
    hdc: &Hdc,
    remote: &RemotePaths,
    session: Option<&Session>,
) -> anyhow::Result<DeviceState> {
    let output = hdc.shell(&[&probe_command(remote, session)])?;
    ensure_hdc_shell_success(&output, "Failed to inspect the device")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(DeviceState {
        has_bin: has_marker(&stdout, HAVE_BIN_MARKER),
        has_fixtures: remote.fixtures_dir.is_none() || has_marker(&stdout, HAVE_FIXTURES_MARKER),
    })
}

/// Creates the directories the transfers need, marked as used by the session before anything
/// arrives in them, so that the end of another session cannot remove them during the transfer.
fn probe_command(remote: &RemotePaths, session: Option<&Session>) -> String {
    let mut command = format!("mkdir -p {}", shell_quote(&remote.bin_dir));
    if let Some(dir) = &remote.fixtures_dir {
        command.push(' ');
        command.push_str(&shell_quote(dir));
    }
    for dir in remote.dirs() {
        if let Some(session) = session {
            command.push_str(" && ");
            command.push_str(&session.mark_command(dir));
        }
    }
    command.push_str(&format!(
        "; [ -x {} ] && echo {HAVE_BIN_MARKER}",
        shell_quote(&remote.bin)
    ));
    if let Some(marker) = remote.fixtures_marker() {
        command.push_str(&format!(
            "; [ -e {} ] && echo {HAVE_FIXTURES_MARKER}",
            shell_quote(&marker)
        ));
    }
    command
}

/// `hdc shell` reports success even when the command it ran failed, so the answer is the output.
fn has_marker(stdout: &str, marker: &str) -> bool {
    stdout.lines().any(|line| line.trim() == marker)
}

/// The command which runs the test binary on the device, if the device still has it.
///
/// The presence check, the `touch` which marks the build as still in use, and the test itself
/// are one command, so that the garbage collection of another invocation cannot remove the
/// binary in between. A test which is already running survives its build directory being
/// removed, since the device keeps the file open.
fn run_command(
    remote: &RemotePaths,
    args: &[String],
    with_runtime_libraries: bool,
    session: Option<&Session>,
) -> String {
    let mut present = format!("[ -x {} ]", shell_quote(&remote.bin));
    let mut touch = format!("touch {}", shell_quote(&remote.bin_dir));
    if let (Some(dir), Some(marker)) = (&remote.fixtures_dir, remote.fixtures_marker()) {
        present.push_str(&format!(" && [ -e {} ]", shell_quote(&marker)));
        touch.push(' ');
        touch.push_str(&shell_quote(dir));
    }
    if let Some(session) = session {
        for dir in remote.dirs() {
            touch.push_str(" && ");
            touch.push_str(&session.mark_command(dir));
        }
    }

    let mut run = format!("{touch} && cd {} && ", shell_quote(remote.working_dir()));
    if with_runtime_libraries {
        // The binary needs libraries the device does not provide, and musl searches neither
        // the working directory nor the directory of the binary.
        run.push_str(&format!("LD_LIBRARY_PATH={} ", shell_quote(TEST_BIN_DIR)));
    }
    if let Some(dir) = &remote.fixtures_dir {
        // Tests which read CARGO_MANIFEST_DIR at runtime find the mirror. The `env!` form bakes
        // the host path into the binary and cannot be helped: the device's root filesystem is
        // read-only, so that path can never exist there.
        run.push_str(&format!("CARGO_MANIFEST_DIR={} ", shell_quote(dir)));
    }
    run.push_str(&shell_quote(&remote.bin));
    for arg in args {
        run.push(' ');
        run.push_str(&shell_quote(arg));
    }
    let exit_code_file = shell_quote(&remote.exit_code_file);
    format!(
        "if {present}; then {run}; printf '%s' \"$?\" > {exit_code_file}; \
         else mkdir -p {bin_dir}; printf '%s' {missing} > {exit_code_file}; fi",
        bin_dir = shell_quote(&remote.bin_dir),
        missing = shell_quote(BIN_MISSING),
    )
}

/// Removes the builds which have not been used for `ttl_minutes`, and the files left behind by
/// invocations which were killed.
///
/// Called only before a transfer, so that the device directory is collected whenever it is about
/// to grow. Best-effort: a failure here costs space, not correctness.
fn collect_garbage(hdc: &Hdc, ttl_minutes: u64) {
    let command = collect_garbage_command(ttl_minutes);
    match hdc.shell(&[&command]) {
        Ok(output) if !output.status.success() => log::warn!(
            "Failed to collect old builds on the device: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(err) => log::warn!("Failed to collect old builds on the device: {err}"),
        Ok(_) => {}
    }
}

fn collect_garbage_command(ttl_minutes: u64) -> String {
    format!(
        "find {TEST_BIN_DIR} -mindepth 1 -maxdepth 1 -type d -mmin +{ttl_minutes} \
         -exec rm -rf {{}} + ; \
         find {TEST_BIN_DIR} -mindepth 1 -maxdepth 1 -name 'exit_code-*' -mmin +{ttl_minutes} \
         -exec rm -f {{}} + ; \
         find {TEST_BIN_DIR} -mindepth 2 -maxdepth 2 -name '*.incoming' -mmin +{ttl_minutes} \
         -exec rm -f {{}} +"
    )
}

/// Whether the builds of the run stay on the device after it, from [`KEEP_BUILDS_ENV_VAR`].
fn keep_builds() -> bool {
    non_empty_env_var(KEEP_BUILDS_ENV_VAR).is_some_and(|value| value != "0")
}

/// How long an unused build stays on the device, from [`CACHE_TTL_ENV_VAR`].
fn cache_ttl_minutes() -> u64 {
    parse_cache_ttl(std::env::var_os(CACHE_TTL_ENV_VAR).as_deref())
}

fn parse_cache_ttl(value: Option<&OsStr>) -> u64 {
    let Some(value) = value else {
        return DEFAULT_CACHE_TTL_MINUTES;
    };
    match value.to_str().map(str::trim).map(str::parse::<u64>) {
        Some(Ok(minutes)) => minutes,
        _ => {
            eprintln!(
                "warning: `{CACHE_TTL_ENV_VAR}` is not a number of minutes, using \
                 {DEFAULT_CACHE_TTL_MINUTES}"
            );
            DEFAULT_CACHE_TTL_MINUTES
        }
    }
}

/// Installs the binary at `remote.bin`.
///
/// The binary is transferred under a temporary name and then renamed into place, because a
/// concurrent invocation may be executing the file at `remote.bin`: overwriting a running binary
/// fails with `Text file busy`, while replacing it by a rename is fine.
fn install_bin_on_device(
    hdc: &Hdc,
    local_bin_path: &Path,
    remote: &RemotePaths,
    local_sha256: &str,
    pid: u32,
) -> anyhow::Result<()> {
    let incoming = remote.incoming_bin(pid);
    send_file_to_device(hdc, local_bin_path, &incoming)?;

    let command = format!(
        "chmod +x {} && touch {}",
        shell_quote(&incoming),
        shell_quote(&remote.build_marker())
    );
    let output = hdc.shell(&[&command])?;
    ensure_hdc_shell_success(&output, "Failed to mark test binary executable on device")?;

    verify_device_file(hdc, local_bin_path, &incoming, local_sha256)?;

    let output = hdc.shell(&["mv", "-f", &incoming, &remote.bin])?;
    ensure_hdc_shell_success(
        &output,
        "Failed to move the test binary into place on device",
    )
}

/// Removes the directories holding other builds of the same binary.
///
/// Only called after a transfer, i.e. once per build, and best-effort: an invocation of a build
/// which is pruned while it runs keeps its already running processes, and transfers the binary
/// again for the next test.
fn prune_other_builds(hdc: &Hdc, bin_name: &str, remote: &RemotePaths) {
    let command = prune_other_builds_command(bin_name, remote);
    match hdc.shell(&[&command]) {
        Ok(output) if !output.status.success() => log::warn!(
            "Failed to remove the directories of other builds of {bin_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(err) => {
            log::warn!("Failed to remove the directories of other builds of {bin_name}: {err}")
        }
        Ok(_) => {}
    }
}

fn prune_other_builds_command(bin_name: &str, remote: &RemotePaths) -> String {
    // The marker keeps the directories mirroring the files a test reads out of this: one of
    // them could well hold a file named like the test binary.
    format!(
        "for dir in {TEST_BIN_DIR}/*/; do \
         if [ \"$dir\" != {} ] && [ -e \"$dir\"{} ] && [ -e \"$dir\"{} ]; \
         then rm -rf \"$dir\"; fi; done",
        shell_quote(&format!("{}/", remote.bin_dir)),
        shell_quote(BUILD_MARKER),
        shell_quote(bin_name)
    )
}

/// Sends `local_path` to `on_device_path`. The parent directory must already exist.
fn send_file_to_device(hdc: &Hdc, local_path: &Path, on_device_path: &str) -> anyhow::Result<()> {
    let res = hdc.output(
        hdc.command()
            .args(["file", "send"])
            .arg(local_path)
            .arg(on_device_path),
    )?;
    assert!(res.status.success());
    // Captured to recognize an unreachable server, but meant for the user.
    eprint!("{}", String::from_utf8_lossy(&res.stderr));
    if !res.stdout.starts_with(b"FileTransfer finish") {
        // Don't bail for now, we still verify the file hash below anyway.
        log::warn!("Unexpected output from hdc. File transfer may have failed.");
    }
    Ok(())
}

/// Checks that the transferred file arrived intact, using the strongest hash tool the device has.
fn verify_device_file(
    hdc: &Hdc,
    local_path: &Path,
    on_device_path: &str,
    local_sha256: &str,
) -> anyhow::Result<()> {
    debug!("The local sha256 hash is {local_sha256:?}");
    let device_hash = if let Some(hash) = compute_device_hash(hdc, "sha256sum", on_device_path)? {
        ("sha256sum", local_sha256.to_owned(), hash)
    } else if let Some(hash) = compute_device_hash(hdc, "md5sum", on_device_path)? {
        ("md5sum", hash_file::<Md5>(local_path)?, hash)
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

/// Runs `command` on the device, letting the output of the test through to the caller.
///
/// We don't really know how long the test program would run, so we can't set a reasonable
/// timeout. We just fallback to using hdc shell as a command again.
fn run_on_device(hdc: &Hdc, command: &str) -> anyhow::Result<()> {
    let res = hdc
        .command()
        .arg("shell")
        .arg(command)
        .spawn()
        .expect("Failed to run hdc")
        .wait()
        .expect("Failed to get output of hdc");
    if !res.success() {
        bail!("Non zero exit code from hdc: {res}");
    }
    Ok(())
}

/// Reads the exit code the run left on the device, removing the file as it does.
///
/// Removing it here leaves the invocations which are killed before this point as the only ones
/// which leave anything behind.
fn read_exit_code(hdc: &Hdc, remote: &RemotePaths) -> anyhow::Result<String> {
    let exit_code_file = shell_quote(&remote.exit_code_file);
    let res = hdc.shell(&[&format!("cat {exit_code_file}; rm -f {exit_code_file}")])?;
    if !res.status.success() {
        bail!("Non zero exit code from hdc: {res:?}");
    }
    Ok(String::from_utf8_lossy(&res.stdout).into_owned())
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
    {FIXTURES_ENV_VAR}
        Files and directories the tests read at runtime, relative to the package root and
        separated like `PATH`. They are mirrored on the device in the same layout, and the
        test runs with that mirror as its working directory, so relative paths resolve.
        Tests which read `CARGO_MANIFEST_DIR` at runtime see the mirror as well; the
        `env!(CARGO_MANIFEST_DIR)` form bakes the host path into the binary and cannot
        be supported, since the device's root filesystem is read-only.
    {KEEP_BUILDS_ENV_VAR}
        Set to `1` to keep the builds on the device after the run. By default, the runner
        removes the builds and file mirrors of a `cargo test` or `cargo nextest run` from
        the device when that process exits, unless another run still uses them. Kept
        builds save the transfer when the same build runs again.
    {CACHE_TTL_ENV_VAR}
        How many minutes a build which outlives its run stays on the device after its last
        use ({ttl} by default). That is a kept build, and a build whose run could not remove
        it, e.g. because the run was killed or the device disconnected. It is collected
        once it goes unused for this long, when the next build is transferred.
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
        ttl = DEFAULT_CACHE_TTL_MINUTES,
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
        // Not for users: the first invocation of a run starts the runner like this, to remove
        // the builds of the run from the device once it ends.
        Some(session::WATCH_FLAG) => {
            let (Some(owner), Some(id)) = (args.next(), args.next()) else {
                bail!(
                    "{} takes the pid of the run and a session id",
                    session::WATCH_FLAG
                );
            };
            return session::watch(&owner.to_string_lossy(), &id.to_string_lossy());
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
    let bin_name = bin_path
        .file_name()
        .expect("Test bin must have a filename")
        .to_str()
        .expect("utf-8");
    let pid = std::process::id();
    let local_sha256 = hash_file::<Sha256>(bin_path)?;
    let fixtures = Fixtures::from_env()?;
    let fixtures_sha256 = fixtures.as_ref().map(hash_fixtures).transpose()?;
    let remote = RemotePaths::new(bin_name, &local_sha256, pid, fixtures_sha256.as_deref());
    debug!("Bin_path: {:?}", bin_path);
    debug!(
        "On device: {}, exit code file: {}",
        remote.bin, remote.exit_code_file
    );

    let targets = hdc.list_targets()?;
    check_device_selection(&targets, hdc.target.as_deref())?;

    let session = if keep_builds() { None } else { session::join() };

    let runtime_libraries = runtime_libraries();
    send_runtime_libraries_to_device(&hdc, &runtime_libraries)?;

    let command = run_command(
        &remote,
        &remaining_args,
        !runtime_libraries.is_empty(),
        session.as_ref(),
    );
    let mut transferred = false;
    let exit_code = loop {
        run_on_device(&hdc, &command)?;
        let exit_code = read_exit_code(&hdc, &remote)?;
        if exit_code.trim() != BIN_MISSING {
            break exit_code;
        }
        if transferred {
            bail!("The test binary disappeared from the device before it could be run");
        }
        let state = probe_device(&hdc, &remote, session.as_ref())?;
        collect_garbage(&hdc, cache_ttl_minutes());
        if !state.has_bin {
            debug!("The device does not have {}, transferring it", remote.bin);
            install_bin_on_device(&hdc, bin_path, &remote, &local_sha256, pid)
                .context("Failed to send binary to device")?;
            prune_other_builds(&hdc, bin_name, &remote);
        }
        if !state.has_fixtures {
            let fixtures = fixtures
                .as_ref()
                .expect("Only a declared fixture set can be missing");
            debug!("The device does not have the fixtures, transferring them");
            install_fixtures(&hdc, fixtures, &remote)
                .context("Failed to send the fixtures to device")?;
        }
        transferred = true;
    };

    if exit_code.trim() != "0" {
        bail!("Binary exited with Non-zero code: {exit_code}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        check_device_selection, collect_garbage_command, has_marker, hash_fixtures,
        hash_tool_missing, parse_cache_ttl, parse_device_hash_output, parse_fixture_entries,
        parse_runtime_libraries, probe_command, prune_other_builds_command, reports,
        resolve_server, run_command, unknown_env_vars, Fixtures, Hdc, RemotePaths, Session,
        BIN_MISSING, BUILD_MARKER, DEFAULT_CACHE_TTL_MINUTES, HDC_SERVER_REJECTED,
        HDC_SERVER_UNREACHABLE, TEST_BIN_DIR,
    };
    use std::ffi::{OsStr, OsString};
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

    const HASH_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const HASH_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #[test]
    fn remote_paths_are_shared_per_build_and_private_per_process() {
        let first = RemotePaths::new("crate-tests", HASH_A, 11, None);
        let second = RemotePaths::new("crate-tests", HASH_A, 12, None);
        let other_build = RemotePaths::new("crate-tests", HASH_B, 11, None);

        // Two invocations of the same build reuse the transferred binary ...
        assert_eq!(first.bin, second.bin);
        // ... but must not write each other's exit code.
        assert_ne!(first.exit_code_file, second.exit_code_file);
        // A different build is transferred next to it, never over it.
        assert_ne!(first.bin_dir, other_build.bin_dir);
        assert_ne!(first.bin, other_build.bin);
        assert_ne!(first.bin, first.incoming_bin(11));

        for path in [&first.bin_dir, &first.bin, &first.exit_code_file] {
            assert!(path.starts_with(&format!("{TEST_BIN_DIR}/")), "{path}");
        }
        assert!(first.bin.ends_with("/crate-tests"), "{}", first.bin);
    }

    #[test]
    fn the_run_command_checks_for_the_binary_and_runs_it_in_one_go() {
        let remote = RemotePaths::new("crate-tests", HASH_A, 11, None);
        let command = run_command(
            &remote,
            &["--exact".to_owned(), "a::b".to_owned()],
            false,
            None,
        );

        // Nothing may collect the binary between the check and the run, ...
        assert!(
            command.contains(&format!("if [ -x '{}' ]", remote.bin)),
            "{command}"
        );
        // ... and running it marks the build as still in use.
        assert!(
            command.contains(&format!("touch '{}'", remote.bin_dir)),
            "{command}"
        );
        assert!(command.contains("'--exact' 'a::b'"), "{command}");
        assert!(
            command.contains(&format!("> '{}'", remote.exit_code_file)),
            "{command}"
        );
        // A miss is reported through the exit code file, so that the output of the test itself
        // stays untouched - which means the shared directory has to exist by then.
        assert!(
            command.contains(&format!("mkdir -p '{}'", remote.bin_dir)),
            "{command}"
        );
        assert!(command.contains(&format!("'{BIN_MISSING}'")), "{command}");
        assert!(!command.contains("LD_LIBRARY_PATH"), "{command}");
    }

    #[test]
    fn the_run_command_sets_ld_library_path_for_runtime_libraries() {
        let remote = RemotePaths::new("crate-tests", HASH_A, 11, None);
        let command = run_command(&remote, &[], true, None);

        assert!(
            command.contains(&format!("LD_LIBRARY_PATH='{TEST_BIN_DIR}'")),
            "{command}"
        );
    }

    #[test]
    fn garbage_collection_covers_builds_and_the_files_of_killed_invocations() {
        let command = collect_garbage_command(30);

        assert!(command.contains("-type d -mmin +30"), "{command}");
        assert!(
            command.contains("-name 'exit_code-*' -mmin +30"),
            "{command}"
        );
        assert!(
            command.contains("-name '*.incoming' -mmin +30"),
            "{command}"
        );
        // The runtime libraries sit next to the build directories and are not collected.
        assert!(!command.contains("-name '*.so'"), "{command}");
    }

    #[test]
    fn the_cache_ttl_falls_back_to_the_default() {
        assert_eq!(parse_cache_ttl(Some(OsStr::new(" 5 "))), 5);
        assert_eq!(parse_cache_ttl(None), DEFAULT_CACHE_TTL_MINUTES);
        assert_eq!(
            parse_cache_ttl(Some(OsStr::new("half an hour"))),
            DEFAULT_CACHE_TTL_MINUTES
        );
        assert_eq!(
            parse_cache_ttl(Some(OsStr::new("-1"))),
            DEFAULT_CACHE_TTL_MINUTES
        );
    }

    #[test]
    fn fixture_entries_must_stay_inside_the_package() {
        assert_eq!(
            parse_fixture_entries(&std::env::join_paths(["tests/data", "fixture.json"]).unwrap())
                .unwrap(),
            [PathBuf::from("tests/data"), PathBuf::from("fixture.json")]
        );
        // The device's root filesystem is read-only, so an absolute host path is hopeless, and
        // a path leaving the package root has nowhere to land in the mirror.
        assert!(parse_fixture_entries(OsStr::new("/etc/hosts")).is_err());
        assert!(parse_fixture_entries(OsStr::new("../sibling/data")).is_err());
    }

    #[test]
    fn the_fixture_hash_ignores_the_order_of_the_entries() {
        let project = unit_fixture_project("order", &[("a/one.txt", "1"), ("b/two.txt", "2")]);
        let hash_of = |entries: Vec<PathBuf>| {
            hash_fixtures(&Fixtures {
                manifest_dir: project.clone(),
                entries,
            })
            .unwrap()
        };

        assert_eq!(
            hash_of(vec![PathBuf::from("a"), PathBuf::from("b")]),
            hash_of(vec![PathBuf::from("b"), PathBuf::from("a")])
        );
        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn the_fixture_hash_follows_the_contents_and_the_names() {
        let base = unit_fixture_project("contents", &[("data/one.txt", "1")]);
        let edited = unit_fixture_project("edited", &[("data/one.txt", "2")]);
        let renamed = unit_fixture_project("renamed", &[("data/uno.txt", "1")]);
        let hash_of = |dir: &PathBuf| {
            hash_fixtures(&Fixtures {
                manifest_dir: dir.clone(),
                entries: vec![PathBuf::from("data")],
            })
            .unwrap()
        };

        assert_ne!(hash_of(&base), hash_of(&edited), "an edit must be noticed");
        assert_ne!(
            hash_of(&base),
            hash_of(&renamed),
            "a rename must be noticed"
        );

        for dir in [base, edited, renamed] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn the_session_marks_the_directories_it_uses() {
        let session = Session::with_id("0123456789abcdef");
        let remote = RemotePaths::new("crate-tests", HASH_A, 11, Some(HASH_B));
        let fixtures_dir = remote.fixtures_dir.clone().expect("declared");
        let run = run_command(&remote, &[], false, Some(&session));
        let probe = probe_command(&remote, Some(&session));

        for command in [&run, &probe] {
            for dir in [&remote.bin_dir, &fixtures_dir] {
                assert!(
                    command.contains(&format!("touch '{dir}/.sessions/0123456789abcdef'")),
                    "{command}"
                );
            }
        }
        // The run marks the directories before the test starts, and the probe before anything
        // is transferred into them, so the end of another session cannot remove them meanwhile.
        let marked = |command: &str| command.find(".sessions/").expect("marked");
        assert!(marked(&run) < run.find("cd '").expect("cd"), "{run}");
        assert!(
            marked(&probe) < probe.find("echo OHOS_TEST_RUNNER_HAVE_BIN").expect("probe"),
            "{probe}"
        );

        assert!(!run_command(&remote, &[], false, None).contains(".sessions"));
        assert!(!probe_command(&remote, None).contains(".sessions"));
    }

    #[test]
    fn the_run_command_uses_the_fixtures_as_the_working_directory() {
        let remote = RemotePaths::new("crate-tests", HASH_A, 11, Some(HASH_B));
        let fixtures_dir = remote.fixtures_dir.clone().expect("declared");
        let command = run_command(&remote, &[], false, None);

        // The test only runs once the whole fixture set arrived, ...
        assert!(
            command.contains(&format!("[ -e '{fixtures_dir}/.ready' ]")),
            "{command}"
        );
        // ... its relative paths resolve against the mirror, ...
        assert!(
            command.contains(&format!("cd '{fixtures_dir}'")),
            "{command}"
        );
        assert!(
            command.contains(&format!("CARGO_MANIFEST_DIR='{fixtures_dir}'")),
            "{command}"
        );
        // ... and both directories count as in use.
        assert!(
            command.contains(&format!("touch '{}' '{fixtures_dir}'", remote.bin_dir)),
            "{command}"
        );
    }

    #[test]
    fn detects_a_probe_marker() {
        // hdc terminates the lines of a shell command with CRLF.
        assert!(has_marker("[Fail]a notice\r\nMARK\r\n", "MARK"));
        assert!(!has_marker("", "MARK"));
        assert!(!has_marker("sh: echo MARK: not found\r\n", "MARK"));
    }

    /// A package root holding `files`, given as (path relative to it, contents).
    fn unit_fixture_project(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ohos-test-runner-unit-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        for (path, contents) in files {
            let file = dir.join(path);
            std::fs::create_dir_all(file.parent().expect("a fixture file has a parent")).unwrap();
            std::fs::write(file, contents).unwrap();
        }
        dir
    }

    #[test]
    fn pruning_quotes_the_binary_name_and_keeps_the_current_build() {
        let remote = RemotePaths::new("odd name'; rm -rf /", HASH_A, 11, None);
        let command = prune_other_builds_command("odd name'; rm -rf /", &remote);

        assert!(command.contains(r"'odd name'\''; rm -rf /'"), "{command}");
        // A directory mirroring the files a test reads could hold a file named like the test
        // binary, so a build is recognized by its marker as well.
        assert!(command.contains(&format!("'{BUILD_MARKER}'")), "{command}");
        assert!(
            command.contains(&format!("!= '{}/'", remote.bin_dir)),
            "{command}"
        );
    }
}

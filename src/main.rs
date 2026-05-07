//! A simple Cargo target runner for running tests or benchmarks on OpenHarmony devices
//!
//! ## Example
//!
//! After installing ohos-test-runner, configure your project to use the custom
//! target runner, for the relevant target triple, e.g.
//!
//! ```
//! # Setup ohos-test-runner as the target runner for aarch64 OpenHarmony.
//! export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_RUNNER=ohos-test-runner
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

const TEST_BIN_DIR: &str = "/data/local/tmp/ohos-test-runner";

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

fn run_hdc_shell_command(args: &[&str]) -> anyhow::Result<Output> {
    Command::new("hdc")
        .arg("shell")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn hdc shell")?
        .wait_with_output()
        .context("Failed to wait for hdc shell")
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
    hash_tool: &str,
    on_device_bin_path: &str,
) -> anyhow::Result<Option<String>> {
    let output = run_hdc_shell_command(&[hash_tool, on_device_bin_path])?;
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
fn send_bin_to_device(local_bin_path: &Path, on_device_bin_path: &str) -> anyhow::Result<()> {
    let output = run_hdc_shell_command(&["mkdir", "-p", TEST_BIN_DIR])?;
    ensure_hdc_shell_success(&output, "Failed to create test directory on device")?;

    let mut hdc_cmd = Command::new("hdc");
    hdc_cmd
        .args(["file", "send"])
        .arg(local_bin_path)
        .arg(TEST_BIN_DIR);
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

    let output = run_hdc_shell_command(&["chmod", "+x", on_device_bin_path])?;
    ensure_hdc_shell_success(&output, "Failed to mark test binary executable on device")?;

    let sha256_hash = hash_file::<Sha256>(local_bin_path)?;
    let md5_hash = hash_file::<Md5>(local_bin_path)?;
    debug!("The local sha256 hash is {sha256_hash:?}");
    debug!("The local md5 hash is {md5_hash:?}");

    let device_hash = if let Some(hash) = compute_device_hash("sha256sum", on_device_bin_path)? {
        ("sha256sum", sha256_hash, hash)
    } else if let Some(hash) = compute_device_hash("md5sum", on_device_bin_path)? {
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
fn main() -> anyhow::Result<()> {
    env_logger::init();
    let mut args = std::env::args_os();
    let bin_path = args.nth(1).unwrap();
    // potentially remaining args should be passed through to the test executable.
    let remaining_args = args
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    let bin_path = Path::new(&bin_path);
    assert!(bin_path.exists(), "Binary not found");
    let bin_name = bin_path.file_name().expect("Test bin must have a filename");
    let on_device_bin_path = format!("{TEST_BIN_DIR}/{}", bin_name.to_str().expect("utf-8"));
    debug!("Bin_path: {:?}", bin_path);

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
    if targets_stdout.contains("[Empty]") {
        bail!("No HDC devices found");
    } else {
        let lines = targets_stdout.trim().lines().collect::<Vec<&str>>();
        if lines.len() != 1 {
            bail!(
                "Currently only a single hdc device is supported. We found {}:\n{:?}",
                lines.len(),
                lines
            );
        }
    }

    send_bin_to_device(bin_path, &on_device_bin_path).context("Failed to send binary to device")?;

    let exit_code_file = format!(
        "{}/last_exit_code-{}",
        TEST_BIN_DIR,
        bin_name.to_str().expect("utf-8")
    );
    let output = run_hdc_shell_command(&["rm", "-f", &exit_code_file])?;
    ensure_hdc_shell_success(&output, "Failed to clear device exit code file")?;

    // We don't really know how long the test program would run, so we can't set a reasonable
    // timeout. We just fallback to using hdc shell as a command again.
    let mut command = format!(
        "cd {} && {}",
        shell_quote(TEST_BIN_DIR),
        shell_quote(&on_device_bin_path)
    );
    for arg in &remaining_args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }
    command.push_str("; printf '%s' \"$?\" > ");
    command.push_str(&shell_quote(&exit_code_file));

    let res = Command::new("hdc")
        .arg("shell")
        .arg(&command)
        .spawn()
        .expect("Failed to run hdc")
        .wait()
        .expect("Failed to get output of hdc");
    if !res.success() {
        bail!("Non zero exit code from hdc: {res}");
    }

    let mut hdc_cmd = Command::new("hdc");
    let res = hdc_cmd
        .arg("shell")
        .arg("cat")
        .arg(exit_code_file)
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
    use super::{hash_tool_missing, parse_device_hash_output};

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

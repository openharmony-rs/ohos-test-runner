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
use rexpect::session::PtySession;
use rexpect::spawn;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::{Command, Stdio};
use log::debug;

const TEST_BIN_DIR: &str = "/data/local/tmp/ohos-test-runner";
const HDC_ERROR_NEED_CONNECT_KEY: &str = "[Fail]ExecuteCommand need connect-key?";

/// Sends the binary at `local_bin_path` to the device using the given hdc session
fn send_bin_to_device(
    mut p: PtySession,
    local_bin_path: &Path,
    on_device_bin_path: &str,
    prompt_regex: &str,
) -> anyhow::Result<()> {
    let cmd = format!("mkdir -p {TEST_BIN_DIR}");
    p.send_line(cmd.as_str())
        .context("hdc shell prompt disconnected?")?;
    let (unmatched, _matched) = p
        .exp_regex(prompt_regex)
        .context("Couldn't find prompt after trying to create directory")?;
    if unmatched.trim() != cmd {
        bail!("Expected to see command `{cmd}` echoed, but received `{unmatched}` instead");
    }

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
        // Don't bail for now, we still verify the sha256 hash below anyway.
        log::warn!("Unexpected output from hdc. File transfer may have failed.");
    }

    let cmd = format!("chmod +x {on_device_bin_path}");
    p.send_line(cmd.as_str())
        .context("hdc shell prompt disconnected?")?;
    let (unmatched, _matched) = p
        .exp_regex(prompt_regex)
        .context("Couldn't find prompt after chmod +x")?;
    debug_assert_eq!(
        unmatched.trim(),
        cmd,
        "Did not expect any other unmatched output from chmod +x"
    );

    let mut file = std::fs::File::open(local_bin_path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).context("Failed to hash the binary on the host")?;
    let hash = hasher.finalize();
    let hash = hex::encode(hash);
    debug!("The hash is {hash:?}");

    p.send_line(format!("sha256sum {on_device_bin_path}").as_str())
        .context("hdc shell prompt disconnected?")?;
    let sha256sum_regex = format!("\n[0-9a-f]{{64}}  {}", on_device_bin_path);
    let (_, on_device_hash_line) = p
        .exp_regex(&sha256sum_regex)
        .context("Couldn't find sha256sum output")?;
    // First character is \n
    let on_device_hash = &on_device_hash_line[1..65];
    debug!("The hash on the device is {on_device_hash}");
    if on_device_hash != hash.as_str() {
        bail!(
            "Hash mismatch. Local sha256sum: {hash}. On device sha256sum output: {on_device_hash}"
        );
    }
    p.exp_regex(prompt_regex)
        .context("Failed to find prompt after sha256sum")?;
    p.send_line("exit")
        .context("hdc shell prompt disconnected?")?;
    p.exp_eof().context("Should have quit")?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let mut args = std::env::args_os();
    let bin_path = args.nth(1).unwrap();
    // potentially remaining args should be passed through to the test executable.
    let remaining_args = args;

    let bin_path = Path::new(&bin_path);
    assert!(bin_path.exists(), "Binary not found");
    let bin_name = bin_path.file_name().expect("Test bin must have a filename");
    let on_device_bin_path = format!("{TEST_BIN_DIR}/{}", bin_name.to_str().expect("utf-8"));
    debug!("Bin_path: {:?}", bin_path);

    let mut p = spawn("hdc list targets", Some(1000)).expect("Failed to spawn hdc list");
    let targets = p.exp_eof().expect("Failed to run hdc list");
    if targets.contains("[Empty]") {
        bail!("No HDC devices found");
    } else {
        let lines = targets.trim().lines().collect::<Vec<&str>>();
        if lines.len() != 1 {
            bail!(
                "Currently only a single hdc device is supported. We found {}:\n{:?}",
                lines.len(),
                lines
            );
        }
    }

    let mut p = spawn("hdc shell", Some(5000)).expect("Failed to spawn hdc shell");
    let res = p
        .exp_regex(r"^([$#] |\[FAIL\])")
        .context("Unexpected output from hdc shell")?;
    if !res.0.is_empty() {
        bail!("Encountered unexpected unmatched output from hdc shell initial prompt.")
    }
    let prompt_regex = match res.1.as_str() {
        HDC_ERROR_NEED_CONNECT_KEY => bail!(
            "HDC server needs a connection key - Currently only a single device can be connected"
        ),
        "# " => r"\n# ",
        "$ " => r"\n\$ ",
        other => bail!("Unexpected hdc shell prompt: {}", other),
    };

    debug!("HDC shell prompt regex: `{}`", prompt_regex);
    send_bin_to_device(p, bin_path, &on_device_bin_path, prompt_regex)
        .context("Failed to send binary to device")?;

    let exit_code_file = format!("{}/last_exit_code", TEST_BIN_DIR);
    // We don't really know how long the test program would run, so we can't set a reasonable
    // timeout. We just fallback to using hdc shell as a command again.
    let mut hdc_cmd = Command::new("hdc");
    hdc_cmd
        .arg("shell")
        .args(["cd", TEST_BIN_DIR, "&&"].iter())
        .arg(on_device_bin_path)
        .args(remaining_args)
        .args([";", "echo", "$?", ">", &exit_code_file].iter());
    let res = hdc_cmd
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

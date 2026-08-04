# OpenHarmony test runner

A simple target runner to support running executables from `cargo test`, `cargo bench` and `cargo run` 
on a connected (Open-)HarmonyOS device.

### Example

After installing ohos-test-runner, configure your project to use the custom
target runner, for the relevant target triple, e.g.

```
# Install ohos-test-runner
cargo install --locked ohos-test-runner
# Setup ohos-test-runner as the target runner for e.g. aarch64 OpenHarmony.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_RUNNER=ohos-test-runner
# Run cargo test (more environment variables might be needed, depending on your project)
cargo test --target aarch64-unknown-linux-ohos
```

The example assumes that you already have a working build environment to cross-compile your project
for OpenHarmony.

### Selecting a device

If more than one device is attached, the device must be selected via the
`OHOS_TEST_RUNNER_HDC_TARGET` environment variable, which is passed to `hdc` as the `-t` argument.
Since cargo invokes the runner with the test binary and its arguments only, the device can't be
selected via a command line argument.

```
# List the connect-keys of the attached devices
hdc list targets
# Run the tests on a specific device
export OHOS_TEST_RUNNER_HDC_TARGET=<connect-key>
cargo test --target aarch64-unknown-linux-ohos
```

With a single attached device the variable is optional and can be left unset.

Environment variables starting with `OHOS_TEST_RUNNER` which are not known to the installed version
are reported with a warning, since they are likely typos, or configuration for a newer version of
this tool. Run `ohos-test-runner --help` for the list of supported variables.

### License 

Licensed under the Apache-2.0 license.
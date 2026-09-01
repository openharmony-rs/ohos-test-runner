# OpenHarmony test runner

A simple target runner to support running executables from `cargo test`, `cargo bench` and `cargo run` 
on a connected (Open-)HarmonyOS device.

## Integration with cargo-ohos

This test runner is also used by [cargo-ohos], where you can just conveniently use 
`cargo ohos test` to cross-compile and run tests on device. 
`cargo-ohos` handles the cross-compilation setup (i.e. `cargo ohos build` makes compiling for OpenHarmony "just work")
adn this crate handles the pushing and running on device step.

[cargo-ohos]: https://github.com/openharmony-rs/cargo-ohos/

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

### Limitations

Tests run on-device, which means that tests which have assumptions about the filesystem contents may break.
This is commonly the case for tests that reference resources from files checked in the local project, which
won't exist on the device. There is no way for a test runner to know about such files, but potentially in
the future we could add some configuration options to allow pushing some files or directories with the
executable onto the device, so relative paths referenced from tests can resolve.

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

### Using a device attached to another machine

The device does not have to be attached to the machine running `cargo test`. hdc runs a server
on the machine the device is attached to, and `OHOS_TEST_RUNNER_HDC_SERVER` points the runner at
it, like `hdc -s` does. Typically, that is the end of an SSH tunnel from that machine:

```
export OHOS_TEST_RUNNER_HDC_SERVER=127.0.0.1:8710
cargo test --target aarch64-unknown-linux-ohos
```

The runner sends everything the test needs from the machine it runs on, so the two machines
share no files. Unlike `hdc -s`, the variable accepts host names.

[docs/remote-device.md](docs/remote-device.md) describes the setup, including a build running in
a Docker container.

Environment variables starting with `OHOS_TEST_RUNNER` which are not known to the installed version
are reported with a warning, since they are likely typos, or configuration for a newer version of
this tool. Run `ohos-test-runner --help` for the list of supported variables.

### Running tests in parallel

Several runner invocations may target the same device at the same time. This is what
`cargo nextest` does, since it starts one process - and therefore one runner - per test.

Each invocation writes its exit code to a file of its own, and the test binary is transferred
into a directory named after its contents:

```
/data/local/tmp/ohos-test-runner/<hash of the binary>/<binary>
```

All the invocations of a build therefore share one transfer, instead of pushing the binary again
for every test, and the transfer of a new build never overwrites a binary another invocation is
currently executing. The directory of the previous build is removed once the new one arrives.

Versions up to 0.1.5 placed the binaries and their exit code files directly in
`/data/local/tmp/ohos-test-runner`, and never removed them. Those leftovers are not used anymore
and can be deleted with `hdc shell rm -f /data/local/tmp/ohos-test-runner/last_exit_code-*`.

### License 

Licensed under the Apache-2.0 license.
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

### Files the tests read

Tests run on-device, so a test which reads a file from the package finds nothing there unless the
file is sent along. The runner cannot know which files a test opens, so they are declared in
`OHOS_TEST_RUNNER_FIXTURES` - paths relative to the package root, separated like `PATH`, naming
files or whole directories:

```
export OHOS_TEST_RUNNER_FIXTURES=tests/data:benches/corpus
cargo test --target aarch64-unknown-linux-ohos
```

They are mirrored on the device in the same layout, and the test runs with that mirror as its
working directory, so relative paths such as `tests/data/input.json` resolve as they do on the
host. A test which reads `CARGO_MANIFEST_DIR` at runtime, with `std::env::var`, sees the mirror
too.

Two things cannot be supported. `env!("CARGO_MANIFEST_DIR")`, and any other absolute host path,
is baked into the binary at compile time and can never exist on the device, whose root filesystem
is read-only. And the mirror is for reading: a test which writes into its package root writes
into a copy, which is eventually collected.

The mirror is named after the contents of the files in it, so it is transferred once for a whole
test run and shared by every test, and editing a fixture gives the next run a mirror of its own.

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

### Removing the builds from the device

A build stays on the device for as long as the run using it: the `cargo test` or
`cargo nextest run` process which invokes the runner. The first invocation of a run starts a
small process of the runner in the background, which waits for the run to end and then removes
the builds and file mirrors of the run from the device - unless another run still uses them. It
survives Ctrl-C and tests which time out, so interrupted runs are cleaned up too. This requires a
Unix host.

Set `OHOS_TEST_RUNNER_KEEP_BUILDS=1` to keep the builds instead. Running the same build again,
e.g. with another test filter, then saves the transfer.

Builds which outlive their run anyway - kept builds, the builds of a run whose cleanup was killed
or could not reach the device, and the builds of runs on hosts other than Unix - are removed once
they have gone unused for 30 minutes, the next time a build is transferred. That also removes the
exit code files and half-finished transfers of invocations which were killed.
`OHOS_TEST_RUNNER_CACHE_TTL_MINUTES` changes that window.

Versions up to 0.1.5 placed the binaries and their exit code files directly in
`/data/local/tmp/ohos-test-runner`, and never removed them. Those leftovers are not used anymore
and can be deleted with `hdc shell rm -f /data/local/tmp/ohos-test-runner/last_exit_code-*`.

### License 

Licensed under the Apache-2.0 license.
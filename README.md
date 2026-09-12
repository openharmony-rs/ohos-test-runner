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

### Files used by tests

Tests run on-device and `ohos-test-runner` cannot know which files a test opens.
If your test or benchmark needs files, declare them in `OHOS_TEST_RUNNER_FIXTURES`. 
Paths should be relative to the package root and separated like `PATH`.
Both files and directories (including empty ones) are supported, but not the package root itself.

```
export OHOS_TEST_RUNNER_FIXTURES=tests/data:benches/corpus
cargo test --target aarch64-unknown-linux-ohos
```

`ohos-test-runner` will set the working directory, so relative paths such as `tests/data/input.json` 
resolve same when running tests on the host. 
Reading `CARGO_MANIFEST_DIR` at runtime, with `std::env::var` works too, however `env!("CARGO_MANIFEST_DIR")`,
and any other absolute host path can't be supported. 

Currently only reading files is supported, transferring potential output files back to the host is currently not
planned (but may be added if the need arises).

### Selecting a device

If more than one device is attached, the device must be selected via the
`OHOS_TEST_RUNNER_HDC_TARGET` environment variable, which is passed to `hdc` as the `-t` argument.

```
# List the connect-keys of the attached devices
hdc list targets
# Run the tests on a specific device
export OHOS_TEST_RUNNER_HDC_TARGET=<connect-key>
cargo test --target aarch64-unknown-linux-ohos
```

With a single attached device the variable is optional and can be left unset.

### Using a device attached to another machine

`hdc` runs a server on the machine the device is attached to, and `OHOS_TEST_RUNNER_HDC_SERVER` 
can be used to point the runner at this remote instance (internally uses `hdc -s`).
Typically, that would be a port forwarded via ssh, unless the remote machine is in the same network.

```
# Assuming a remote hdc port was forward to out 48710 port.
export OHOS_TEST_RUNNER_HDC_SERVER=127.0.0.1:48710
cargo test --target aarch64-unknown-linux-ohos
```

The runner sends everything the test needs from the machine it runs on, so the two machines
share no files. Unlike `hdc -s`, the variable accepts host names.

[docs/remote-device.md](docs/remote-device.md) describes the setup, including a build running in
a Docker container.

### Diagnostics

Environment variables starting with `OHOS_TEST_RUNNER` which are not known to the installed version
are reported with a warning, since they are likely typos, or configuration for a newer version of
this tool. Run `ohos-test-runner --help` for the list of supported variables.

### Running tests in parallel

Several runner invocations may run concurrently (concurrent test execution).
`ohos-test-runner` supports this, but as a trade-off disk utilization is increased,
due to preserving test executables on device (`cargo nextest` may invoke the same test binary
multiple times).
`ohos-test-runner` does best-effort to prune test files again and return disk space.
A small background process is spawned for this purpose to cleanup files after a while on
the device.
As a fallabck builds are removed once they have been unused for 30 minutes, 
the next time a build is transferred. 

Versions up to 0.1.5 placed the binaries and their exit code files directly in
`/data/local/tmp/ohos-test-runner`, and never removed them. Those leftovers are not used anymore.
To remove them, delete the whole directory while no tests run:
`hdc shell rm -rf /data/local/tmp/ohos-test-runner`.

### License 

Licensed under the Apache-2.0 license.
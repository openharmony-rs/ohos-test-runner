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

### License 

Licensed under the Apache-2.0 license.
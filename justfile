import 'emulator-action/justfile'

# Defaults: x86_64 to match the Oniro emulator. Override with `OHOS_TARGET=...`.
ohos_target := env_var_or_default("OHOS_TARGET", "x86_64-unknown-linux-ohos")

# Path to the OHOS SDK 'native/' directory (containing llvm/, sysroot/, ...).
# Example: ~/Library/OpenHarmony/Sdk/20/native
ohos_sdk_native := env_var_or_default("OHOS_SDK_NATIVE", "")

linker := ohos_sdk_native / "llvm/bin/x86_64-unknown-linux-ohos-clang"

_require-device:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v hdc >/dev/null 2>&1; then
      echo "Error: hdc is not on PATH." >&2
      exit 1
    fi
    hdc start >/dev/null 2>&1 || true
    if ! timeout 5s hdc wait >/dev/null 2>&1; then
      echo "Error: no hdc device. Run 'just emulator' first (or connect a device)." >&2
      exit 1
    fi

_require-sdk:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{ ohos_sdk_native }}" ]; then
      echo "Error: OHOS_SDK_NATIVE is unset. Point it at <SDK>/native, e.g." >&2
      echo "  export OHOS_SDK_NATIVE=\$HOME/Library/OpenHarmony/Sdk/20/native" >&2
      exit 1
    fi
    if [ ! -x "{{ linker }}" ]; then
      echo "Error: expected linker at {{ linker }}" >&2
      exit 1
    fi

# Run the integration smoke tests against a connected emulator/device.
test: _require-device _require-sdk
    OHOS_TEST_RUNNER_INTEGRATION_TARGET={{ ohos_target }} \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_OHOS_LINKER="{{ linker }}" \
        cargo test --test smoke_test -- --ignored

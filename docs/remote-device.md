# Running tests on a device attached to another machine

The device does not have to be attached to the machine that builds the tests. A common setup is
a Linux VM or container that builds, and a Windows PC with DevEco Studio that has the device on
USB. This guide calls the first the *build machine* and the second the *device host*.

## How it fits together

hdc is a client, a server and a daemon on the device:

```
build machine                              device host
  cargo test
    └─ ohos-test-runner
         └─ hdc client ──── TCP ────►  hdc server ──── USB ────►  device
```

Only the server needs the device. The runner talks to it with `hdc -s`, which it takes from
`OHOS_TEST_RUNNER_HDC_SERVER`. `hdc file send` reads the file on the client side, so the test
binary and everything else the runner sends come from the build machine, and the two machines
share no files.

There are two ways to connect them:

- **Direct**: the server listens on the network. This is the simplest option, but it has no
  authentication. Anyone who can reach the port controls the server: every device attached to
  it, and port forwards that make the server connect to other machines and to services that only
  listen on the device host's own loopback. Only use it on a network you trust.
- **SSH tunnel**: the server only accepts connections from its own machine, and the build machine
  reaches it through SSH. The device host needs an SSH server (on Windows, the *OpenSSH Server*
  optional feature).

## On the device host

The hdc server that hdc or DevEco Studio start on their own listens on `127.0.0.1:8710`, which is
all an SSH tunnel needs. Check that it runs and sees the device:

```sh
hdc list targets
```

The first time a device connects to a host, it asks on its screen to allow debugging, and it has
to be accepted there.

For the direct connection, replace that server with one that listens on the network, and leave
it running (`-m` keeps it in the foreground):

```sh
hdc kill
hdc -s 0.0.0.0:8710 -m
```

The firewall has to allow the port. On Windows, in an administrator PowerShell, limited to the
build machine:

```powershell
New-NetFirewallRule -DisplayName "hdc server" -Direction Inbound -Protocol TCP -LocalPort 8710 -RemoteAddress <build-machine-ip> -Action Allow
```

Windows may also ask whether to allow hdc on the network when the server starts. Either answer
creates a rule of its own for the hdc program, which applies to every remote address: allowing
makes the restriction above pointless, and cancelling blocks the build machine too. Check the
rules for hdc in *Windows Defender Firewall with Advanced Security* afterwards.

## On the build machine

The build machine needs an `hdc` of the same version as the device host's. It ships with the
OpenHarmony SDK, in `toolchains/`.

**Direct:**

```sh
export OHOS_TEST_RUNNER_HDC_SERVER=device-host:8710
```

**SSH tunnel:**

```sh
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18710:127.0.0.1:8710 user@device-host &
export OHOS_TEST_RUNNER_HDC_SERVER=127.0.0.1:18710
```

The tunnel uses a local port other than 8710 on purpose. If an hdc server is running on the build
machine, it holds `127.0.0.1:8710`, and a tunnel on the same port either fails to start or leaves
you talking to that local server, which has no devices. The tunnel names `127.0.0.1` for the same
reason: without it, ssh also listens on `::1`, and still starts when `127.0.0.1:18710` is taken.

Then run the tests as usual:

```sh
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_RUNNER=ohos-test-runner
cargo test --target aarch64-unknown-linux-ohos
```

If several devices are attached to the device host, select one with
`OHOS_TEST_RUNNER_HDC_TARGET`, as described in the README.

## Using hdc yourself

`hdc` itself does not read `OHOS_TEST_RUNNER_HDC_SERVER`, and `OHOS_HDC_SERVER_PORT` only changes
the port, so every command needs `-s`. Unlike the variable, `-s` only accepts a numeric IP
address:

```sh
hdc -s 192.168.1.20:8710 checkserver     # client and server version, must match
hdc -s 192.168.1.20:8710 list targets    # the connect-keys of the device host's devices
hdc -s 192.168.1.20:8710 shell
```

An alias saves repeating it: `alias hdc='hdc -s 192.168.1.20:8710'`.

## When something goes wrong

| symptom | cause |
| --- | --- |
| `cannot reach the hdc server at …` | The server is not running, the tunnel is down, the server listens on loopback only while you connect directly, or a firewall blocks the port. When nothing answers at the address, hdc takes about 12 seconds to give up. |
| `… closed the connection without answering` | Something accepts connections at the address, but it is not an hdc server. Typically the SSH tunnel is up, but no hdc server runs on the device host. |
| `Cannot resolve the hdc server …` | The host name does not resolve on the build machine, or the port is missing. |
| `No HDC devices found`, or the selected device is not connected | The server answers, but does not have the device. Check `hdc list targets` on the device host. With a tunnel, make sure you are not talking to a local server on the same port. |
| hangs, or vague connection errors | Most likely, client and server have different hdc versions. Compare them with `hdc -s <ip>:<port> checkserver`. |

# Running tests on a device attached to another machine

The device does not have to be attached to the machine that builds the tests. A common setup is
a Windows PC with DevEco Studio that has the device on USB, and a Linux VM or server that builds
the tests, possibly in a Docker container. This guide calls the first the *device host* and the
second the *build machine*.

## How it fits together

hdc is a client, a server and a daemon on the device. Only the server needs the device, so it
stays on the device host, and the device host forwards a port on the build machine to it over
SSH:

```
build machine (or a container on it)                    device host

  ohos-test-runner
    └─ hdc client ──► forwarded port ◄═══ ssh -R ═══════ hdc server ──── USB ────► device
```

The device host opens the SSH connection, so it needs no SSH server of its own and can sit behind
NAT. The build machine needs an SSH server. The hdc server keeps listening on the device host's
loopback only, so nothing is exposed to the network.

The runner finds the forwarded port through `OHOS_TEST_RUNNER_HDC_SERVER`, which it passes to
hdc as `-s`. `hdc file send` reads the file on the client side, so the test binary and everything
else the runner sends come from the build machine, and the two machines share no files.

## On the device host

The hdc server that hdc or DevEco Studio start on their own listens on `127.0.0.1:8710`. Check
that it runs and sees the device:

```sh
hdc list targets
```

The first time a device connects to a host, it asks on its screen to allow debugging, and it has
to be accepted there.

Then open the tunnel, and leave it running while testing:

```sh
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -R <address>:8710:127.0.0.1:8710 user@build-machine
```

`<address>` is where the forward listens on the build machine, which depends on where the tests
run: see the next section. `ExitOnForwardFailure` makes ssh stop when the forward cannot listen,
instead of carrying on without it, and `ServerAliveInterval` makes a dead connection end instead of
lingering. Windows ships the OpenSSH client since Windows 10 version 1809.

## Where the forward listens

### Tests running on the build machine

Listen on the build machine's loopback:

```sh
# device host
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -R 127.0.0.1:8710:127.0.0.1:8710 user@build-machine
# build machine
export OHOS_TEST_RUNNER_HDC_SERVER=127.0.0.1:8710
```

If the build machine runs an hdc server of its own, that server holds `127.0.0.1:8710`, and ssh
stops with `remote port forwarding failed`. Stop that server with `hdc kill` on the build machine,
or forward another port, e.g. `-R 127.0.0.1:18710:127.0.0.1:8710` with
`OHOS_TEST_RUNNER_HDC_SERVER=127.0.0.1:18710`.

### Tests running in a Docker container on the build machine

A container has a loopback of its own, so it cannot reach a forward listening on the build
machine's `127.0.0.1`. The forward has to listen on the address at which the container reaches
the build machine: the gateway of the container's network. Look it up in the container:

```sh
ip route show default    # default via 172.17.0.1 dev eth0
```

`172.17.0.1` is the gateway of Docker's default network. Containers on a network of their own,
as with Docker Compose or some devcontainers, have a different one, e.g. `172.18.0.1`. With
rootless Docker or Podman, the gateway may be an emulated address that does not lead to the
build machine at all, so try the connection before relying on it.

With `172.17.0.1`:

```sh
# device host
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -R 172.17.0.1:8710:127.0.0.1:8710 user@build-machine
# in the container
export OHOS_TEST_RUNNER_HDC_SERVER=172.17.0.1:8710
```

By default, sshd only lets a forward listen on loopback. Asked for another address, it listens on
loopback **without reporting an error**, even with `ExitOnForwardFailure`, and the container then
cannot connect. Allow the client to choose the address, on the build machine:

```sh
echo 'GatewayPorts clientspecified' | sudo tee /etc/ssh/sshd_config.d/10-gatewayports.conf
sudo sshd -t                  # checks the configuration; no output means it is fine
sudo systemctl reload ssh     # the unit is `sshd` on some distributions
```

sshd uses the first value it reads for a setting, and the `sshd_config` of Debian and Ubuntu
includes `sshd_config.d/` at its top, so this takes precedence over the main file. Prefer
`clientspecified` to `yes`, which would make every forward listen on all addresses, the network
included.

The setting applies to new connections only, so restart the ssh command on the device host. Then
check on the build machine that the forward listens on the gateway address:

```sh
ss -tln | grep 8710           # 172.17.0.1:8710, not 127.0.0.1:8710
```

Anything that can reach that address can use the hdc server, and with it the device: every
container on that network, and the processes of the build machine.

A container which shares the build machine's network (`docker run --network=host`) also shares
its loopback, and uses the setup of the previous section instead.

## On the build machine, or in the container

The runner needs `hdc` on the `PATH`, of the same version as the device host's. The versions are
compared exactly, and a mismatch makes hdc print nothing at all, which the runner reports as a
server that closed the connection without answering. Take both from the same OpenHarmony SDK
release, which comes for Windows, Linux and macOS, each with `hdc` in `toolchains/`.

Check the connection with the address from `OHOS_TEST_RUNNER_HDC_SERVER`:

```sh
hdc -s 172.17.0.1:8710 checkserver     # client and server version, must match
hdc -s 172.17.0.1:8710 list targets    # the connect-keys of the device host's devices
```

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
address. An alias saves repeating it:

```sh
alias hdc='hdc -s 172.17.0.1:8710'
```

With `-s`, `hdc kill` stops the server on the device host, which only the device host can start
again.

## When something goes wrong

| symptom | cause |
| --- | --- |
| `cannot reach the hdc server at …` | The tunnel is down, or the forward listens on another address than the one in `OHOS_TEST_RUNNER_HDC_SERVER`. With a container, check with `ss -tln` on the build machine that it does not listen on `127.0.0.1` (see `GatewayPorts` above). When nothing answers at the address at all, hdc takes about 12 seconds to give up. |
| `… closed the connection without answering` | Client and server are different hdc versions (compare them with `checkserver`), or the tunnel is up but no hdc server runs on the device host. |
| `No HDC devices found`, or the selected device is not connected | The server answers, but does not have the device. Check `hdc list targets` on the device host, and the prompt on the device's screen. |
| `Cannot resolve the hdc server …` | The host name does not resolve on the build machine, or the port is missing. |

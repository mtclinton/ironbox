<div align="center">
  <h1>ironbox</h1>

[![Build status][build-image]][build-url]
[![license][license-image]][license-url]

[build-url]: https://github.com/mtclinton/ironbox/actions
[build-image]: https://img.shields.io/github/actions/workflow/status/mtclinton/ironbox/ci.yml?branch=master&label=Build
[license-url]: https://github.com/mtclinton/ironbox/blob/master/LICENSE
[license-image]: https://img.shields.io/badge/license-Apache_2.0-blue.svg?label=License
</div>

## What is ironbox?

**ironbox** is a [containerd](https://containerd.io/) shim runtime built in Rust.
It implements the containerd shim v2 API, currently delegating container lifecycle operations to [runc](https://github.com/opencontainers/runc) via the [containerd rust-extensions](https://github.com/containerd/rust-extensions) crates.

The goal is to incrementally replace runc with a native Rust OCI runtime, learning the container stack from the shim layer down to namespaces, cgroups, and `pivot_root`.

## How do I use it?

> [!NOTE]
> ironbox requires a running [containerd](https://containerd.io/) daemon and [runc](https://github.com/opencontainers/runc) installed on the host.

### Build from source

```shell
cargo build --release
```

### Install

Copy the shim binary to a location in containerd's `PATH`:

```shell
sudo cp target/release/containerd-shim-ironbox-v1 /usr/local/bin/
```

### Run a container

```shell
sudo ctr run --runtime io.containerd.ironbox.v1 docker.io/library/alpine:latest test1 echo hello
```

### Run with Kubernetes

Configure the containerd runtime in `/etc/containerd/config.toml`:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.ironbox]
  runtime_type = "io.containerd.ironbox.v1"
```

Then restart containerd and create a `RuntimeClass`:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: ironbox
handler: ironbox
```

## How do I contribute?

All contributions are welcome!

Some ways to contribute include:

- Testing on different Linux distributions and reporting issues.
- Implementing native OCI runtime operations to replace the runc dependency.
- Adding support for additional container features (checkpointing, lazy pulling, etc.).
- Improving documentation and examples.

## Project roadmap

- **Phase 1** (current): Standalone containerd shim that delegates to runc.
- **Phase 2**: Replace `RuncFactory`/`RuncContainer` with custom Rust implementations.
- **Phase 3**: Build a minimal OCI runtime binary (`create`, `start`, `delete`, `state`) using namespaces, cgroups, and `pivot_root` directly.

## Dependencies

ironbox builds on top of the [containerd rust-extensions](https://github.com/containerd/rust-extensions) project:

- [`containerd-shim`](https://github.com/containerd/rust-extensions/tree/main/crates/shim) - Shim v2 API and TTRPC server
- [`runc`](https://github.com/containerd/rust-extensions/tree/main/crates/runc) - Rust client for the runc binary

## What does "ironbox" mean?

Iron is the metal most associated with Rust (the programming language), and a box is what a container is.
Put them together and you get **ironbox** &mdash; a container runtime forged in Rust.

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
It implements the containerd shim v2 API with a native OCI runtime that manages container lifecycles using Linux syscalls directly &mdash; no dependency on the runc binary.

Container creation uses `fork(2)`, `unshare(2)`, `pivot_root(2)`, and `mount(2)` to set up isolated namespaces and a new root filesystem. A double-fork ensures the container init process is PID 1. Process exec joins existing namespaces via `setns(2)`. Cgroup v2 resource limits, capability dropping, and loopback networking are all handled natively.

## Architecture

| Operation | Implementation |
|-----------|---------------|
| **create** | Native &mdash; double-fork, `unshare` namespaces, `pivot_root`, OCI mounts, cgroup v2 setup, capability drop, loopback up |
| **start** | Native &mdash; writes to sync pipe, init process (PID 1) execs the entrypoint |
| **kill** | Native &mdash; `kill(2)` syscall with process group support |
| **delete** | Native &mdash; kills cgroup processes, removes cgroup, unmounts rootfs |
| **exec** | Native &mdash; `setns(2)` into container namespaces, double-fork, `execvp` |
| **pause/resume** | Native &mdash; cgroup v2 `cgroup.freeze` |
| **stats/update** | Native &mdash; direct cgroup metrics and resource limits |
| **ps** | Native &mdash; reads PIDs from `cgroup.procs` |

### Module structure

```
src/
├── runtime/
│   ├── container.rs      — double-fork + namespace + pivot_root + mount + create/start/delete
│   ├── exec.rs           — setns into container namespaces + fork/exec
│   ├── rootfs.rs         — rootfs bind mount, pivot_root, OCI mounts, device nodes
│   ├── namespace.rs      — unshare/setns helpers, OCI namespace mapping
│   ├── cgroup.rs         — cgroup v2 create, resource limits, cleanup
│   ├── capabilities.rs   — Linux capability dropping per OCI spec
│   ├── network.rs        — loopback interface setup
│   └── io.rs             — Io trait, FIFO and NullIo for container stdio
├── ironbox_container.rs — IronboxFactory, lifecycle trait impls
├── service.rs         — containerd shim v2 service
├── task.rs            — task service (container CRUD over TTRPC)
├── container.rs       — generic container/process templates
└── processes.rs       — process lifecycle traits
```

## How do I use it?

> [!NOTE]
> ironbox requires a running [containerd](https://containerd.io/) daemon. No external OCI runtime (runc, crun, etc.) is needed.

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
- Adding seccomp and AppArmor support.
- Adding support for additional container features (checkpointing, lazy pulling, etc.).
- Improving documentation and examples.

## Project roadmap

- **Phase 1**: Standalone containerd shim that delegates to runc.
- **Phase 2**: Custom `IronboxFactory`/`IronboxContainer` types with native signal handling, cgroup management, and process listing.
- **Phase 3**: Fully native OCI runtime &mdash; container create/start/delete/exec use Linux syscalls directly, no runc binary required.
- **Phase 4** (current): Hardening &mdash; cgroup v2 resource limits, PID 1 via double-fork, capability dropping, loopback networking.
- **Phase 5**: Seccomp filters, AppArmor/SELinux profiles, console/PTY support.

## Dependencies

ironbox builds on top of the [containerd rust-extensions](https://github.com/containerd/rust-extensions) project:

- [`containerd-shim`](https://github.com/containerd/rust-extensions/tree/main/crates/shim) &mdash; Shim v2 API and TTRPC server

Core Linux interfaces are accessed via:

- [`nix`](https://crates.io/crates/nix) &mdash; Rust bindings for `unshare`, `setns`, `mount`, `pivot_root`, `kill`, `sethostname`
- [`oci-spec`](https://crates.io/crates/oci-spec) &mdash; OCI runtime specification parsing

## What does "ironbox" mean?

Iron is the metal most associated with Rust (the programming language), and a box is what a container is.
Put them together and you get **ironbox** &mdash; a container runtime forged in Rust.

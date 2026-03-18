use std::{
    os::{
        fd::{IntoRawFd, OwnedFd},
        unix::io::{AsRawFd, FromRawFd},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
};

use async_trait::async_trait;
use containerd_shim::{
    api::{CreateTaskRequest, ExecProcessRequest, Options, Status},
    io_error,
    other,
    protos::{
        api::ProcessInfo,
        cgroups::metrics::Metrics,
        protobuf::{CodedInputStream, Message},
    },
    util::{asyncify, mkdir, mount_rootfs, read_file_to_str, read_spec, write_options},
    Console, Error, ExitSignal, Result,
};
use log::{debug, error, warn};
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use oci_spec::runtime::LinuxResources;
use tokio::{
    fs::{remove_file, File, OpenOptions},
    io::{AsyncRead, AsyncWrite},
};

use crate::{
    console::ConsoleSocket,
    container::{ContainerFactory, ContainerTemplate, ProcessFactory},
    processes::{ProcessLifecycle, ProcessTemplate},
    common::{
        check_kill_error, get_spec_from_request, handle_file_open,
        receive_socket, ProcessIO, INIT_PID_FILE,
    },
    io::Stdio,
    runtime::{
        container::{create_container, delete_container, start_container, StdioPaths},
        exec::{exec_in_container, ExecStdio},
    },
};

pub type ExecProcess = ProcessTemplate<IronboxExecLifecycle>;
pub type InitProcess = ProcessTemplate<IronboxInitLifecycle>;

pub type IronboxContainer = ContainerTemplate<InitProcess, ExecProcess, IronboxExecFactory>;

#[derive(Clone, Default)]
pub(crate) struct IronboxFactory {}

#[async_trait]
impl ContainerFactory<IronboxContainer> for IronboxFactory {
    async fn create(
        &self,
        _ns: &str,
        req: &CreateTaskRequest,
    ) -> containerd_shim::Result<IronboxContainer> {
        let bundle = req.bundle();
        let mut opts = Options::new();
        if let Some(any) = req.options.as_ref() {
            let mut input = CodedInputStream::from_bytes(any.value.as_ref());
            opts.merge_from(&mut input)?;
        }
        if opts.compute_size() > 0 {
            debug!("create options: {:?}", &opts);
        }
        write_options(bundle, &opts).await?;

        let rootfs_vec = req.rootfs().to_vec();
        let rootfs = if !rootfs_vec.is_empty() {
            let tmp_rootfs = Path::new(bundle).join("rootfs");
            mkdir(&tmp_rootfs, 0o711).await?;
            tmp_rootfs
        } else {
            PathBuf::new()
        };

        for m in rootfs_vec {
            mount_rootfs(&m, rootfs.as_path()).await?
        }

        let id = req.id();
        let stdio = Stdio::new(req.stdin(), req.stdout(), req.stderr(), req.terminal());

        let mut init = InitProcess::new(
            id,
            stdio,
            IronboxInitLifecycle::new(opts.clone(), bundle),
        );

        self.do_create(&mut init).await?;
        let container = IronboxContainer {
            id: id.to_string(),
            bundle: bundle.to_string(),
            init,
            process_factory: IronboxExecFactory {
                bundle: bundle.to_string(),
                io_uid: opts.io_uid,
                io_gid: opts.io_gid,
            },
            processes: Default::default(),
        };
        Ok(container)
    }

    async fn cleanup(&self, _ns: &str, _c: &IronboxContainer) -> containerd_shim::Result<()> {
        Ok(())
    }
}

impl IronboxFactory {
    async fn do_create(&self, init: &mut InitProcess) -> Result<()> {
        let id = init.id.to_string();
        let bundle = init.lifecycle.bundle.clone();
        let pid_path = Path::new(&bundle).join(INIT_PID_FILE);
        let stdio_paths = StdioPaths {
            stdin: init.stdio.stdin.clone(),
            stdout: init.stdio.stdout.clone(),
            stderr: init.stdio.stderr.clone(),
            terminal: init.stdio.terminal,
        };

        // Read OCI spec
        let spec = read_spec(&bundle).await?;

        // Native container creation: fork, unshare, pivot_root, mounts
        let container_process = asyncify(move || {
            create_container(&id, &bundle, &spec, &pid_path, &stdio_paths)
        })
        .await?;

        init.pid = container_process.pid;

        // Store the start pipe and rootfs path in the lifecycle for later use
        {
            *init.lifecycle.start_pipe.lock().unwrap() = Some(container_process.start_pipe);
            *init.lifecycle.rootfs.lock().unwrap() = Some(container_process.rootfs);
            *init.lifecycle.cgroup_path.lock().unwrap() = Some(container_process.cgroup_path);
            *init.lifecycle.container_pid.lock().unwrap() = container_process.pid;
        }

        Ok(())
    }
}

pub struct IronboxExecFactory {
    bundle: String,
    io_uid: u32,
    io_gid: u32,
}

#[async_trait]
impl ProcessFactory<ExecProcess> for IronboxExecFactory {
    async fn create(&self, req: &ExecProcessRequest) -> Result<ExecProcess> {
        let p = get_spec_from_request(req)?;
        Ok(ExecProcess {
            state: Status::CREATED,
            id: req.exec_id.to_string(),
            stdio: Stdio {
                stdin: req.stdin.to_string(),
                stdout: req.stdout.to_string(),
                stderr: req.stderr.to_string(),
                terminal: req.terminal,
            },
            pid: 0,
            exit_code: 0,
            exited_at: None,
            wait_chan_tx: vec![],
            console: None,
            lifecycle: Arc::from(IronboxExecLifecycle {
                bundle: self.bundle.to_string(),
                container_id: req.id.to_string(),
                io_uid: self.io_uid,
                io_gid: self.io_gid,
                spec: p,
                exit_signal: Default::default(),
                container_pid: 0,
            }),
            stdin: Arc::new(StdMutex::new(None)),
        })
    }
}

pub struct IronboxInitLifecycle {
    opts: Options,
    bundle: String,
    exit_signal: Arc<ExitSignal>,
    start_pipe: StdMutex<Option<OwnedFd>>,
    rootfs: StdMutex<Option<PathBuf>>,
    cgroup_path: StdMutex<Option<PathBuf>>,
    container_pid: StdMutex<i32>,
}

#[async_trait]
impl ProcessLifecycle<InitProcess> for IronboxInitLifecycle {
    async fn start(&self, p: &mut InitProcess) -> containerd_shim::Result<()> {
        // Signal the container init process to exec via the start pipe
        let pipe = self.start_pipe.lock().unwrap().take();
        if let Some(pipe) = pipe {
            start_container(&pipe)?;
        } else {
            return Err(other!("no start pipe available"));
        }
        p.state = Status::RUNNING;
        Ok(())
    }

    async fn kill(
        &self,
        p: &mut InitProcess,
        signal: u32,
        all: bool,
    ) -> containerd_shim::Result<()> {
        if p.pid <= 0 {
            return Err(Error::FailedPreconditionError(
                "process not created".to_string(),
            ));
        }
        let sig = Signal::try_from(signal as i32)
            .map_err(|e| Error::InvalidArgument(format!("invalid signal {}: {}", signal, e)))?;

        if all {
            kill(Pid::from_raw(-p.pid), sig).map_err(|e| check_kill_error(e.to_string()))?;
        } else {
            kill(Pid::from_raw(p.pid), sig).map_err(|e| check_kill_error(e.to_string()))?;
        }
        Ok(())
    }

    async fn delete(&self, p: &mut InitProcess) -> containerd_shim::Result<()> {
        // Native delete: kill processes, unmount rootfs, clean up cgroup
        let rootfs = self.rootfs.lock().unwrap().clone().unwrap_or_default();
        let cgroup_path = self.cgroup_path.lock().unwrap().clone().unwrap_or_default();
        let pid = p.pid;
        if let Err(e) = asyncify(move || delete_container(pid, &rootfs, &cgroup_path, true)).await {
            warn!("delete container cleanup: {}", e);
        }
        self.exit_signal.signal();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn update(&self, p: &mut InitProcess, resources: &LinuxResources) -> Result<()> {
        if p.pid <= 0 {
            return Err(other!(
                "failed to update resources because init process is {}",
                p.pid
            ));
        }
        if is_zombie_process(p.pid) {
            return Err(other!(
                "failed to update resources because process {} is a zombie",
                p.pid
            ));
        }
        containerd_shim::cgroup::update_resources(p.pid as u32, resources)
    }

    #[cfg(not(target_os = "linux"))]
    async fn update(&self, _p: &mut InitProcess, _resources: &LinuxResources) -> Result<()> {
        Err(Error::Unimplemented("update resource".to_string()))
    }

    #[cfg(target_os = "linux")]
    async fn stats(&self, p: &InitProcess) -> Result<Metrics> {
        if p.pid <= 0 {
            return Err(other!(
                "failed to collect metrics because init process is {}",
                p.pid
            ));
        }
        if is_zombie_process(p.pid) {
            return Err(other!(
                "failed to collect metrics because process {} is a zombie",
                p.pid
            ));
        }
        containerd_shim::cgroup::collect_metrics(p.pid as u32)
    }

    #[cfg(not(target_os = "linux"))]
    async fn stats(&self, _p: &InitProcess) -> Result<Metrics> {
        Err(Error::Unimplemented("process stats".to_string()))
    }

    async fn ps(&self, p: &InitProcess) -> Result<Vec<ProcessInfo>> {
        let mut pids = Vec::new();

        #[cfg(target_os = "linux")]
        {
            let cgroup_pids = read_cgroup_pids(p.pid).await;
            match cgroup_pids {
                Ok(pid_list) => {
                    pids = pid_list;
                }
                Err(_) => {
                    pids.push(p.pid as usize);
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            pids.push(p.pid as usize);
        }

        Ok(pids
            .iter()
            .map(|&x| ProcessInfo {
                pid: x as u32,
                ..Default::default()
            })
            .collect())
    }

    #[cfg(target_os = "linux")]
    async fn pause(&self, p: &mut InitProcess) -> Result<()> {
        match p.state {
            Status::RUNNING => {
                p.state = Status::PAUSING;
                if let Err(e) = freeze_cgroup(p.pid, true).await {
                    p.state = Status::RUNNING;
                    return Err(other!("failed to pause container: {}", e));
                }
                p.state = Status::PAUSED;
                Ok(())
            }
            _ => Err(other!("cannot pause when in {:?} state", p.state)),
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn pause(&self, _p: &mut InitProcess) -> Result<()> {
        Err(Error::Unimplemented("pause".to_string()))
    }

    #[cfg(target_os = "linux")]
    async fn resume(&self, p: &mut InitProcess) -> Result<()> {
        match p.state {
            Status::PAUSED => {
                if let Err(e) = freeze_cgroup(p.pid, false).await {
                    return Err(other!("failed to resume container: {}", e));
                }
                p.state = Status::RUNNING;
                Ok(())
            }
            _ => Err(other!("cannot resume when in {:?} state", p.state)),
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn resume(&self, _p: &mut InitProcess) -> Result<()> {
        Err(Error::Unimplemented("resume".to_string()))
    }
}

impl IronboxInitLifecycle {
    pub fn new(opts: Options, bundle: &str) -> Self {
        Self {
            opts,
            bundle: bundle.to_string(),
            exit_signal: Default::default(),
            start_pipe: StdMutex::new(None),
            rootfs: StdMutex::new(None),
            cgroup_path: StdMutex::new(None),
            container_pid: StdMutex::new(0),
        }
    }
}

pub struct IronboxExecLifecycle {
    bundle: String,
    container_id: String,
    io_uid: u32,
    io_gid: u32,
    spec: oci_spec::runtime::Process,
    exit_signal: Arc<ExitSignal>,
    container_pid: i32,
}

#[async_trait]
impl ProcessLifecycle<ExecProcess> for IronboxExecLifecycle {
    async fn start(&self, p: &mut ExecProcess) -> containerd_shim::Result<()> {
        let bundle = self.bundle.to_string();
        let pid_path = Path::new(&bundle).join(format!("{}.pid", &p.id));

        // Find the container init PID to enter its namespaces
        let init_pid_path = Path::new(&bundle).join(INIT_PID_FILE);
        let container_pid = read_file_to_str(&init_pid_path)
            .await?
            .parse::<i32>()
            .map_err(|e| other!("parse init pid: {}", e))?;

        // Native exec: fork, setns into container namespaces, exec
        let spec = self.spec.clone();
        let pid_path_clone = pid_path.clone();
        let exec_stdio = ExecStdio {
            stdin: p.stdio.stdin.clone(),
            stdout: p.stdio.stdout.clone(),
            stderr: p.stdio.stderr.clone(),
        };
        let child_pid = asyncify(move || {
            exec_in_container(container_pid, &spec, Some(&pid_path_clone), Some(&exec_stdio))
        })
        .await?;

        if !p.stdio.stdin.is_empty() {
            let stdin_clone = p.stdio.stdin.clone();
            let stdin_w = p.stdin.clone();
            tokio::spawn(async move {
                if let Ok(stdin_w_file) = OpenOptions::new()
                    .write(true)
                    .open(stdin_clone.as_str())
                    .await
                {
                    let mut lock_guard = stdin_w.lock().unwrap();
                    *lock_guard = Some(stdin_w_file);
                }
            });
        }

        p.pid = child_pid;
        p.state = Status::RUNNING;
        Ok(())
    }

    async fn kill(
        &self,
        p: &mut ExecProcess,
        signal: u32,
        _all: bool,
    ) -> containerd_shim::Result<()> {
        if p.pid <= 0 {
            Err(Error::FailedPreconditionError(
                "process not created".to_string(),
            ))
        } else if p.exited_at.is_some() {
            Err(Error::NotFoundError("process already finished".to_string()))
        } else {
            let sig = Signal::try_from(signal as i32)
                .map_err(|e| Error::InvalidArgument(format!("invalid signal {}: {}", signal, e)))?;
            kill(Pid::from_raw(p.pid), sig).map_err(Into::into)
        }
    }

    async fn delete(&self, p: &mut ExecProcess) -> Result<()> {
        self.exit_signal.signal();
        let exec_pid_path = Path::new(self.bundle.as_str()).join(format!("{}.pid", p.id));
        remove_file(exec_pid_path).await.unwrap_or_default();
        Ok(())
    }

    async fn update(&self, _p: &mut ExecProcess, _resources: &LinuxResources) -> Result<()> {
        Err(Error::Unimplemented("exec update".to_string()))
    }

    async fn stats(&self, _p: &ExecProcess) -> Result<Metrics> {
        Err(Error::Unimplemented("exec stats".to_string()))
    }

    async fn ps(&self, _p: &ExecProcess) -> Result<Vec<ProcessInfo>> {
        Err(Error::Unimplemented("exec ps".to_string()))
    }

    async fn pause(&self, _p: &mut ExecProcess) -> Result<()> {
        Err(Error::Unimplemented("exec pause".to_string()))
    }

    async fn resume(&self, _p: &mut ExecProcess) -> Result<()> {
        Err(Error::Unimplemented("exec resume".to_string()))
    }
}

// --- Native Linux helpers ---

#[cfg(target_os = "linux")]
fn is_zombie_process(pid: i32) -> bool {
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
        for line in status.lines() {
            if line.starts_with("State:") && line.contains('Z') {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
async fn read_cgroup_pids(pid: i32) -> Result<Vec<usize>> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let content = tokio::fs::read_to_string(&cgroup_path)
        .await
        .map_err(io_error!(e, "read cgroup for pid {}", pid))?;

    let cgroup_rel = content
        .lines()
        .find_map(|line| {
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() == 3 {
                Some(parts[2].to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| other!("failed to parse cgroup path for pid {}", pid))?;

    let procs_path = format!("/sys/fs/cgroup{}/cgroup.procs", cgroup_rel);
    let procs_content = match tokio::fs::read_to_string(&procs_path).await {
        Ok(c) => c,
        Err(_) => {
            return Ok(vec![pid as usize]);
        }
    };

    let pids: Vec<usize> = procs_content
        .lines()
        .filter_map(|line| line.trim().parse::<usize>().ok())
        .collect();

    if pids.is_empty() {
        Ok(vec![pid as usize])
    } else {
        Ok(pids)
    }
}

#[cfg(target_os = "linux")]
async fn freeze_cgroup(pid: i32, freeze: bool) -> Result<()> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let content = tokio::fs::read_to_string(&cgroup_path)
        .await
        .map_err(io_error!(e, "read cgroup for pid {}", pid))?;

    let cgroup_rel = content
        .lines()
        .find_map(|line| {
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() == 3 {
                Some(parts[2].to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| other!("failed to parse cgroup path for pid {}", pid))?;

    let freeze_path = format!("/sys/fs/cgroup{}/cgroup.freeze", cgroup_rel);
    let value = if freeze { "1" } else { "0" };

    tokio::fs::write(&freeze_path, value)
        .await
        .map_err(io_error!(e, "write cgroup.freeze"))?;

    Ok(())
}

// --- IO helpers ---

async fn copy_console(
    console_socket: &ConsoleSocket,
    stdio: &Stdio,
    exit_signal: Arc<ExitSignal>,
) -> Result<Console> {
    debug!("copy_console: waiting for runtime to send console fd");
    let stream = console_socket.accept().await?;
    let fd = asyncify(move || -> Result<OwnedFd> { receive_socket(stream.as_raw_fd()) }).await?;
    let f = unsafe { File::from_raw_fd(fd.into_raw_fd()) };
    if !stdio.stdin.is_empty() {
        debug!("copy_console: pipe stdin to console");
        let console_stdin = f
            .try_clone()
            .await
            .map_err(io_error!(e, "failed to clone console file"))?;
        let stdin = handle_file_open(|| async {
            OpenOptions::new()
                .read(true)
                .open(stdio.stdin.as_str())
                .await
        })
        .await
        .map_err(io_error!(e, "failed to open stdin"))?;
        spawn_copy(stdin, console_stdin, exit_signal.clone(), None::<fn()>);
    }

    if !stdio.stdout.is_empty() {
        let console_stdout = f
            .try_clone()
            .await
            .map_err(io_error!(e, "failed to clone console file"))?;
        debug!("copy_console: pipe stdout from console");
        let stdout = OpenOptions::new()
            .write(true)
            .open(stdio.stdout.as_str())
            .await
            .map_err(io_error!(e, "open stdout"))?;
        let stdout_r = OpenOptions::new()
            .read(true)
            .open(stdio.stdout.as_str())
            .await
            .map_err(io_error!(e, "open stdout for read"))?;
        spawn_copy(
            console_stdout,
            stdout,
            exit_signal,
            Some(move || {
                drop(stdout_r);
            }),
        );
    }
    let console = Console {
        file: f.into_std().await,
    };
    Ok(console)
}

pub async fn copy_io(pio: &ProcessIO, stdio: &Stdio, exit_signal: Arc<ExitSignal>) -> Result<()> {
    if !pio.copy {
        return Ok(());
    };
    if let Some(io) = &pio.io {
        if let Some(w) = io.stdin() {
            debug!("copy_io: pipe stdin from {}", stdio.stdin.as_str());
            if !stdio.stdin.is_empty() {
                let stdin = handle_file_open(|| async {
                    OpenOptions::new()
                        .read(true)
                        .open(stdio.stdin.as_str())
                        .await
                })
                .await
                .map_err(io_error!(e, "open stdin"))?;
                spawn_copy(stdin, w, exit_signal.clone(), None::<fn()>);
            }
        }

        if let Some(r) = io.stdout() {
            debug!("copy_io: pipe stdout from to {}", stdio.stdout.as_str());
            if !stdio.stdout.is_empty() {
                let stdout = handle_file_open(|| async {
                    OpenOptions::new()
                        .write(true)
                        .open(stdio.stdout.as_str())
                        .await
                })
                .await
                .map_err(io_error!(e, "open stdout"))?;
                let stdout_r = handle_file_open(|| async {
                    OpenOptions::new()
                        .read(true)
                        .open(stdio.stdout.as_str())
                        .await
                })
                .await
                .map_err(io_error!(e, "open stdout for read"))?;
                spawn_copy(
                    r,
                    stdout,
                    exit_signal.clone(),
                    Some(move || {
                        drop(stdout_r);
                    }),
                );
            }
        }

        if let Some(r) = io.stderr() {
            if !stdio.stderr.is_empty() {
                debug!("copy_io: pipe stderr from to {}", stdio.stderr.as_str());
                let stderr = handle_file_open(|| async {
                    OpenOptions::new()
                        .write(true)
                        .open(stdio.stderr.as_str())
                        .await
                })
                .await
                .map_err(io_error!(e, "open stderr"))?;
                let stderr_r = handle_file_open(|| async {
                    OpenOptions::new()
                        .read(true)
                        .open(stdio.stderr.as_str())
                        .await
                })
                .await
                .map_err(io_error!(e, "open stderr for read"))?;
                spawn_copy(
                    r,
                    stderr,
                    exit_signal,
                    Some(move || {
                        drop(stderr_r);
                    }),
                );
            }
        }
    }

    Ok(())
}

fn spawn_copy<R, W, F>(from: R, to: W, exit_signal: Arc<ExitSignal>, on_close: Option<F>)
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    F: FnOnce() + Send + 'static,
{
    let mut src = from;
    let mut dst = to;
    tokio::spawn(async move {
        tokio::select! {
            _ = exit_signal.wait() => {
                debug!("container exit, copy task should exit too");
            },
            res = tokio::io::copy(&mut src, &mut dst) => {
               if let Err(e) = res {
                    error!("copy io failed {}", e);
                }
            }
        }
        if let Some(f) = on_close {
            f();
        }
    });
}

async fn copy_io_or_console<P>(
    p: &mut ProcessTemplate<P>,
    socket: Option<ConsoleSocket>,
    pio: Option<ProcessIO>,
    exit_signal: Arc<ExitSignal>,
) -> Result<()> {
    if p.stdio.terminal {
        if let Some(console_socket) = socket {
            let console_result = copy_console(&console_socket, &p.stdio, exit_signal).await;
            console_socket.clean().await;
            match console_result {
                Ok(c) => {
                    p.console = Some(c);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    } else if let Some(pio) = pio {
        copy_io(&pio, &p.stdio, exit_signal).await?;
    }
    Ok(())
}

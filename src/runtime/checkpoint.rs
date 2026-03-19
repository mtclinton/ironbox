use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use containerd_shim::{other, Error, Result};
use log::debug;

/// Options for checkpointing a container.
#[derive(Default)]
pub struct CheckpointOpts {
    /// Leave the container running after checkpoint (default: false — container is killed).
    pub leave_running: bool,
    /// Enable TCP connection checkpoint.
    pub tcp_established: bool,
    /// Enable external unix socket checkpoint.
    pub ext_unix_sk: bool,
    /// Enable shell job checkpoint (for processes with a controlling terminal).
    pub shell_job: bool,
}

/// Checkpoint a running container using CRIU.
///
/// Dumps the process tree rooted at `pid` to `image_dir`.
/// Requires the `criu` binary to be installed on the host.
pub fn checkpoint_container(
    pid: i32,
    image_dir: &Path,
    work_dir: &Path,
    opts: &CheckpointOpts,
) -> Result<()> {
    // Ensure image directory exists
    fs::create_dir_all(image_dir)
        .map_err(|e| other!("create checkpoint dir {}: {}", image_dir.display(), e))?;
    fs::create_dir_all(work_dir)
        .map_err(|e| other!("create checkpoint work dir {}: {}", work_dir.display(), e))?;

    let mut cmd = Command::new("criu");
    cmd.arg("dump")
        .arg("--tree").arg(pid.to_string())
        .arg("--images-dir").arg(image_dir)
        .arg("--work-dir").arg(work_dir)
        .arg("--manage-cgroups")
        .arg("--log-file").arg("dump.log");

    if opts.leave_running {
        cmd.arg("--leave-running");
    }
    if opts.tcp_established {
        cmd.arg("--tcp-established");
    }
    if opts.ext_unix_sk {
        cmd.arg("--ext-unix-sk");
    }
    if opts.shell_job {
        cmd.arg("--shell-job");
    }

    debug!("checkpoint: running {:?}", cmd);

    let output = cmd.output()
        .map_err(|e| other!("failed to run criu dump: {} (is criu installed?)", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Try to read CRIU's log for more detail
        let log_path = work_dir.join("dump.log");
        let log_content = fs::read_to_string(&log_path).unwrap_or_default();
        return Err(other!(
            "criu dump failed (exit {}): {}\nCRIU log: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim(),
            log_content.lines().rev().take(5).collect::<Vec<_>>().join("\n")
        ));
    }

    debug!("checkpoint: successfully dumped pid {} to {}", pid, image_dir.display());
    Ok(())
}

/// Restore a container from a CRIU checkpoint.
///
/// Restores the process tree from `image_dir` with `rootfs` as the root filesystem.
/// Returns the PID of the restored process.
pub fn restore_container(
    image_dir: &Path,
    rootfs: &Path,
    work_dir: &Path,
    pid_file: &Path,
) -> Result<i32> {
    fs::create_dir_all(work_dir)
        .map_err(|e| other!("create restore work dir: {}", e))?;

    let mut cmd = Command::new("criu");
    cmd.arg("restore")
        .arg("--images-dir").arg(image_dir)
        .arg("--work-dir").arg(work_dir)
        .arg("--root").arg(rootfs)
        .arg("--pidfile").arg(pid_file)
        .arg("--manage-cgroups")
        .arg("--log-file").arg("restore.log")
        .arg("--detach");

    debug!("restore: running {:?}", cmd);

    let output = cmd.output()
        .map_err(|e| other!("failed to run criu restore: {} (is criu installed?)", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let log_path = work_dir.join("restore.log");
        let log_content = fs::read_to_string(&log_path).unwrap_or_default();
        return Err(other!(
            "criu restore failed (exit {}): {}\nCRIU log: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim(),
            log_content.lines().rev().take(5).collect::<Vec<_>>().join("\n")
        ));
    }

    // Read restored PID from pid file
    let pid_str = fs::read_to_string(pid_file)
        .map_err(|e| other!("read restored pid: {}", e))?;
    let pid: i32 = pid_str.trim().parse()
        .map_err(|e| other!("parse restored pid: {}", e))?;

    debug!("restore: process restored with pid {}", pid);
    Ok(pid)
}

/// Get the default checkpoint image directory for a container.
pub fn checkpoint_image_dir(bundle: &str, checkpoint_id: &str) -> PathBuf {
    Path::new(bundle).join("checkpoints").join(checkpoint_id)
}

/// Get the work directory for CRIU operations.
pub fn checkpoint_work_dir(bundle: &str) -> PathBuf {
    Path::new(bundle).join("criu-work")
}

use std::{
    fs,
    path::{Path, PathBuf},
};

use containerd_shim::{other, Error, Result};
use log::debug;
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use oci_spec::runtime::Spec;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const IRONBOX_CGROUP: &str = "ironbox";

/// Create a cgroup v2 directory for a container and apply resource limits from the OCI spec.
/// Returns the path to the cgroup directory.
pub fn create_cgroup(id: &str, spec: &Spec) -> Result<PathBuf> {
    let cgroup_path = Path::new(CGROUP_ROOT)
        .join(IRONBOX_CGROUP)
        .join(id);

    // Create parent and container cgroup directories
    fs::create_dir_all(&cgroup_path)
        .map_err(|e| other!("create cgroup dir {}: {}", cgroup_path.display(), e))?;

    debug!("created cgroup: {}", cgroup_path.display());

    // Enable controllers in the parent cgroup so child can use them
    let parent = Path::new(CGROUP_ROOT).join(IRONBOX_CGROUP);
    enable_controllers(&parent)?;

    // Apply resource limits from OCI spec
    if let Some(linux) = spec.linux() {
        if let Some(resources) = linux.resources() {
            apply_resources(&cgroup_path, resources)?;
        }
    }

    Ok(cgroup_path)
}

/// Enable memory, cpu, and pids controllers in the parent cgroup.
fn enable_controllers(parent: &Path) -> Result<()> {
    let subtree_control = parent.join("cgroup.subtree_control");
    // Read currently available controllers
    let available = fs::read_to_string(parent.join("cgroup.controllers")).unwrap_or_default();

    let mut to_enable = Vec::new();
    for controller in &["memory", "cpu", "pids", "cpuset", "io"] {
        if available.contains(controller) {
            to_enable.push(format!("+{}", controller));
        }
    }

    if !to_enable.is_empty() {
        let content = to_enable.join(" ");
        fs::write(&subtree_control, &content).unwrap_or_else(|e| {
            debug!("enable controllers '{}': {} (non-fatal)", content, e);
        });
    }

    Ok(())
}

/// Apply OCI resource limits to a cgroup v2 directory.
fn apply_resources(
    cgroup_path: &Path,
    resources: &oci_spec::runtime::LinuxResources,
) -> Result<()> {
    // Memory limits (0 or negative means "no limit" — skip)
    if let Some(memory) = resources.memory() {
        if let Some(limit) = memory.limit() {
            if limit > 0 {
                write_cgroup_file(cgroup_path, "memory.max", &limit.to_string())?;
                debug!("set memory.max = {}", limit);
            }
        }
        if let Some(reservation) = memory.reservation() {
            if reservation > 0 {
                write_cgroup_file(cgroup_path, "memory.low", &reservation.to_string())?;
            }
        }
        if let Some(swap) = memory.swap() {
            let mem_limit = memory.limit().unwrap_or(0);
            if swap > 0 && swap > mem_limit {
                let swap_only = swap - mem_limit;
                write_cgroup_file(cgroup_path, "memory.swap.max", &swap_only.to_string())?;
            }
        }
    }

    // CPU limits
    if let Some(cpu) = resources.cpu() {
        let quota = cpu.quota();
        let period = cpu.period().unwrap_or(100_000); // default 100ms

        if let Some(q) = quota {
            if q > 0 {
                let value = format!("{} {}", q, period);
                write_cgroup_file(cgroup_path, "cpu.max", &value)?;
                debug!("set cpu.max = {}", value);
            }
        }

        if let Some(shares) = cpu.shares() {
            if shares > 0 {
                // cgroup v2 uses cpu.weight (1-10000), v1 uses shares (2-262144)
                let weight = 1 + ((shares.saturating_sub(2) * 9999) / 262142);
                write_cgroup_file(cgroup_path, "cpu.weight", &weight.to_string())?;
            }
        }

        // cpuset
        if let Some(cpus) = cpu.cpus() {
            if !cpus.is_empty() {
                write_cgroup_file(cgroup_path, "cpuset.cpus", cpus)?;
            }
        }
        if let Some(mems) = cpu.mems() {
            if !mems.is_empty() {
                write_cgroup_file(cgroup_path, "cpuset.mems", mems)?;
            }
        }
    }

    // PID limits
    if let Some(pids) = resources.pids() {
        let limit = pids.limit();
        let value = if limit <= 0 {
            "max".to_string()
        } else {
            limit.to_string()
        };
        write_cgroup_file(cgroup_path, "pids.max", &value)?;
        debug!("set pids.max = {}", value);
    }

    Ok(())
}

/// Add a process to a cgroup by writing its PID to cgroup.procs.
pub fn add_process_to_cgroup(cgroup_path: &Path, pid: i32) -> Result<()> {
    write_cgroup_file(cgroup_path, "cgroup.procs", &pid.to_string())?;
    debug!("added pid {} to cgroup {}", pid, cgroup_path.display());
    Ok(())
}

/// Delete a cgroup: kill all processes, then remove the directory.
pub fn delete_cgroup(cgroup_path: &Path) -> Result<()> {
    if !cgroup_path.exists() {
        return Ok(());
    }

    // Kill all processes in the cgroup
    let procs_path = cgroup_path.join("cgroup.procs");
    if let Ok(content) = fs::read_to_string(&procs_path) {
        for line in content.lines() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            }
        }
    }

    // Wait briefly for processes to die, then remove
    // cgroup dir can only be removed when empty (no processes)
    for _ in 0..10 {
        match fs::remove_dir(cgroup_path) {
            Ok(()) => {
                debug!("removed cgroup {}", cgroup_path.display());
                return Ok(());
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }

    // Final attempt
    fs::remove_dir(cgroup_path)
        .map_err(|e| other!("remove cgroup {}: {}", cgroup_path.display(), e))?;

    Ok(())
}

/// Helper: write a value to a cgroup control file.
fn write_cgroup_file(cgroup_path: &Path, filename: &str, value: &str) -> Result<()> {
    let path = cgroup_path.join(filename);
    fs::write(&path, value)
        .map_err(|e| other!("write {}: {}", path.display(), e))?;
    Ok(())
}

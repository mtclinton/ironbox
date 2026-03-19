use std::fs;
use std::path::Path;

use containerd_shim::{other, Error, Result};
use log::debug;
use oci_spec::runtime::Spec;

/// Apply AppArmor profile from the OCI spec.
///
/// Writes the profile name to /proc/self/attr/apparmor/exec (or the legacy
/// path /proc/self/attr/exec) so that the next exec transitions to the profile.
pub fn apply_apparmor(spec: &Spec) -> Result<()> {
    let process = match spec.process() {
        Some(p) => p,
        None => return Ok(()),
    };

    let profile = match process.apparmor_profile() {
        Some(p) if !p.is_empty() => p,
        _ => return Ok(()),
    };

    // Check if AppArmor is available on the system
    if !Path::new("/sys/kernel/security/apparmor").exists() {
        debug!("AppArmor not available, skipping profile {}", profile);
        return Ok(());
    }

    // Write "exec <profile>" to the appropriate attr file.
    // Try the newer path first, fall back to legacy.
    let exec_value = format!("exec {}", profile);

    let new_path = "/proc/self/attr/apparmor/exec";
    let legacy_path = "/proc/self/attr/exec";

    let path = if Path::new(new_path).exists() {
        new_path
    } else {
        legacy_path
    };

    fs::write(path, &exec_value)
        .map_err(|e| other!("set AppArmor profile '{}' via {}: {}", profile, path, e))?;

    debug!("AppArmor profile set to '{}' (via {})", profile, path);
    Ok(())
}

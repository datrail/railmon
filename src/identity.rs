use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetManifest {
    pub manifest_version: u8,
    pub sandbox: Sandbox,
    pub agents: Vec<Target>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    pub host_id: String,
    pub sandbox_name: String,
    pub access: Access,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub kind: String,
    pub container: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub agent_key: String,
    pub display_name: Option<String>,
    pub discovery: Discovery,
    pub scan: Option<Scan>,
    pub capture: Option<Capture>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub pid_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scan {
    #[serde(default)]
    pub config_roots: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub binary_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgentRef {
    pub host_id: String,
    pub sandbox_name: String,
    pub agent_key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessIncarnation {
    pub pid: u32,
    pub start_time_ticks: u64,
    pub session_id: u32,
    pub uid: u32,
}

impl ProcessIncarnation {
    pub fn is_live(self) -> bool {
        let stat = fs::read_to_string(format!("/proc/{}/stat", self.pid));
        let same_incarnation = matches!(
            stat.and_then(|value| {
                parse_proc_stat(self.pid, &value)
                    .map_err(|error| std::io::Error::other(error.to_string()))
            }),
            Ok((session, start)) if session == self.session_id && start == self.start_time_ticks
        );
        let same_uid =
            fs::metadata(format!("/proc/{}", self.pid)).is_ok_and(|meta| meta.uid() == self.uid);
        same_incarnation && same_uid
    }
}

impl TargetManifest {
    pub fn load(path: &Path) -> Result<Self> {
        validate_control_path(path, None)?;
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let value: Self = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("parsing {}", path.display()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.manifest_version != 1 {
            bail!(
                "unsupported target manifest version {}",
                self.manifest_version
            );
        }
        if self.sandbox.host_id.is_empty() || self.sandbox.sandbox_name.is_empty() {
            bail!("host_id and sandbox_name must be non-empty");
        }
        if self.sandbox.access.kind != "docker" || self.sandbox.access.container.is_empty() {
            bail!("sandbox access must name a non-empty docker container");
        }
        if self.agents.is_empty() {
            bail!("a target manifest must declare at least one agent");
        }
        let mut keys = HashSet::new();
        for target in &self.agents {
            validate_key(&target.agent_key)?;
            if target.agent_key == "default" {
                bail!("agent_key 'default' is reserved for the unkeyed compatibility path");
            }
            if !keys.insert(&target.agent_key) {
                bail!("duplicate agent_key '{}'", target.agent_key);
            }
            if !target.discovery.pid_file.is_absolute() {
                bail!(
                    "pid_file for '{}' must be an absolute path",
                    target.agent_key
                );
            }
            if target.display_name.as_deref().is_some_and(str::is_empty) {
                bail!("display_name for '{}' must not be empty", target.agent_key);
            }
            if let Some(scan) = &target.scan {
                if scan.config_roots.iter().any(|path| !path.is_absolute()) {
                    bail!("config_roots for '{}' must be absolute", target.agent_key);
                }
            }
        }
        Ok(())
    }

    pub fn agent_ref(&self, target: &Target) -> AgentRef {
        AgentRef {
            host_id: self.sandbox.host_id.clone(),
            sandbox_name: self.sandbox.sandbox_name.clone(),
            agent_key: target.agent_key.clone(),
        }
    }

    pub fn resolve_all(&self) -> Result<Vec<ProcessIncarnation>> {
        let supervisor_uid = unsafe { libc::geteuid() };
        let mut seen = HashSet::new();
        let mut sessions = HashSet::new();
        let mut agent_uids = HashSet::new();
        let mut out = Vec::with_capacity(self.agents.len());
        for target in &self.agents {
            let process = resolve_target(target, supervisor_uid)?;
            if process.uid == supervisor_uid {
                bail!(
                    "target '{}' runs as supervisor uid {}",
                    target.agent_key,
                    supervisor_uid
                );
            }
            if !seen.insert((process.pid, process.start_time_ticks)) {
                bail!("one process incarnation is claimed by multiple agent keys");
            }
            if !sessions.insert(process.session_id) {
                bail!(
                    "agents share process session {}; capture would be ambiguous",
                    process.session_id
                );
            }
            if !agent_uids.insert(process.uid) {
                bail!(
                    "agents share uid {}; same-UID processes are not an attribution boundary",
                    process.uid
                );
            }
            out.push(process);
        }
        Ok(out)
    }
}

fn resolve_target(target: &Target, supervisor_uid: u32) -> Result<ProcessIncarnation> {
    validate_control_path(&target.discovery.pid_file, None)?;
    let text = fs::read_to_string(&target.discovery.pid_file)
        .with_context(|| format!("reading locator for '{}'", target.agent_key))?;
    let pid: u32 = text
        .trim()
        .parse()
        .with_context(|| format!("invalid PID in {}", target.discovery.pid_file.display()))?;
    if pid == 0 {
        bail!("PID zero is not a process target");
    }
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    let stat_before = fs::read_to_string(proc_dir.join("stat"))
        .with_context(|| format!("reading process identity for pid {pid}"))?;
    let identity_before = parse_proc_stat(pid, &stat_before)?;
    let uid = fs::metadata(&proc_dir)
        .with_context(|| format!("target '{}' is not live", target.agent_key))?
        .uid();
    validate_control_path(&target.discovery.pid_file, Some(uid))?;
    if uid == supervisor_uid {
        bail!(
            "locator {} names a process owned by the supervisor",
            target.discovery.pid_file.display()
        );
    }
    let stat_after = fs::read_to_string(proc_dir.join("stat"))
        .with_context(|| format!("reading process identity for pid {pid}"))?;
    let identity_after = parse_proc_stat(pid, &stat_after)?;
    if identity_before != identity_after {
        bail!("pid {pid} changed incarnation while resolving target");
    }
    let (session_id, start_time_ticks) = identity_after;
    if session_id != pid {
        bail!(
            "target '{}' is not a process-session leader; a shared session is not an attribution boundary",
            target.agent_key
        );
    }
    Ok(ProcessIncarnation {
        pid,
        start_time_ticks,
        session_id,
        uid,
    })
}

fn parse_proc_stat(expected_pid: u32, stat: &str) -> Result<(u32, u64)> {
    let close = stat
        .rfind(')')
        .context("malformed /proc stat: missing command terminator")?;
    let parsed_pid: u32 = stat[..stat.find('(').context("malformed /proc stat")?]
        .trim()
        .parse()?;
    if parsed_pid != expected_pid {
        bail!("/proc stat PID changed while resolving target");
    }
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    if fields.len() < 20 {
        bail!("malformed /proc stat: too few fields");
    }
    Ok((fields[3].parse()?, fields[19].parse()?))
}

fn validate_control_path(path: &Path, monitored_uid: Option<u32>) -> Result<()> {
    if !path.is_absolute() {
        bail!("control path {} is not absolute", path.display());
    }
    let supervisor_uid = unsafe { libc::geteuid() };
    let mut cursor = Some(path);
    while let Some(candidate) = cursor {
        let meta = fs::symlink_metadata(candidate)
            .with_context(|| format!("inspecting control path {}", candidate.display()))?;
        if meta.file_type().is_symlink() {
            bail!("control path {} contains a symlink", candidate.display());
        }
        if meta.uid() != 0 && meta.uid() != supervisor_uid {
            bail!(
                "control path {} is not owned by root or the supervisor",
                candidate.display()
            );
        }
        if meta.mode() & 0o022 != 0 {
            bail!(
                "control path {} is group/other writable",
                candidate.display()
            );
        }
        if has_posix_acl(candidate)? {
            bail!(
                "control path {} has an extended POSIX ACL; effective writability cannot be proven",
                candidate.display()
            );
        }
        if monitored_uid.is_some_and(|uid| uid == meta.uid()) {
            bail!(
                "control path {} is owned by monitored uid {}",
                candidate.display(),
                meta.uid()
            );
        }
        cursor = candidate.parent().filter(|parent| *parent != candidate);
    }
    Ok(())
}

fn has_posix_acl(path: &Path) -> Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let name = c"system.posix_acl_access";
    let size = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size >= 0 {
        return Ok(size > 0);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(false),
        _ => bail!("cannot inspect POSIX ACL on {}", path.to_string_lossy()),
    }
}

fn validate_key(key: &str) -> Result<()> {
    if key.len() > 64
        || key.is_empty()
        || (!key.as_bytes()[0].is_ascii_lowercase() && !key.as_bytes()[0].is_ascii_digit())
        || !key.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
    {
        bail!("invalid agent_key '{key}'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comm_with_spaces_without_shifting_identity_fields() {
        let mut fields = vec!["S", "1", "2", "77"];
        fields.extend(std::iter::repeat_n("0", 15));
        fields.push("12345");
        assert_eq!(
            parse_proc_stat(42, &format!("42 (agent worker) {}", fields.join(" "))).unwrap(),
            (77, 12345)
        );
    }

    #[test]
    fn rejects_duplicate_reserved_and_noncanonical_keys() {
        for key in ["Planner", "", "a/b"] {
            assert!(validate_key(key).is_err());
        }
        assert!(validate_key("planner-2").is_ok());
    }
}

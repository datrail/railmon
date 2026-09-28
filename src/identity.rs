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
    pub pid_file: Option<PathBuf>,
    /// A non-delegated cgroup v2 directory: the agent's own uid has no write
    /// access to its `cgroup.procs`, so it cannot add or remove its own
    /// membership (design doc §4.1's "non-delegated cgroup" locator).
    /// Resolution reads exactly that file, the same control-path/ownership
    /// checks `pid_file` gets applied to it directly. Mutually exclusive
    /// with `pid_file` — `validate()` and the published JSON Schema both
    /// enforce exactly one locator per agent.
    pub cgroup: Option<PathBuf>,
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

/// Per-target discovery result. A manifest declares an agent whether or not
/// its process is live right now, so resolving one target's locator never
/// aborts resolution of the others — each gets exactly one of these outcomes
/// (design doc §4.2: discovery "never drops a declared agent just because
/// its process is down").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryOutcome {
    /// The locator names exactly one live, trustworthy, unambiguous process.
    Available(ProcessIncarnation),
    /// The locator could not be resolved to a live, trustworthy process
    /// right now — a missing or unreadable pid_file, a dead PID, or a
    /// locator/process that failed an ownership or writability check
    /// (including the same-owner-UID case). Retryable in principle; the
    /// reason names exactly why.
    NotFound(String),
    /// The locator resolved to a process, but that process (or its session,
    /// or its uid) is also claimed by another declared agent, so capture
    /// could not be attributed to one key over the other.
    Ambiguous(String),
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

/// One declared agent's discovery outcome, in the shape the Python scanner
/// consumes to run agent-scoped scanning once per key (M2): whether to scan
/// it at all, and the config roots to scope that scan to. `binary_path`
/// rides along for other/future consumers of this same contract (it is the
/// collector's own capture-scoping field, not something the Python scanner
/// reads); it is not manufactured here, only forwarded. Kept separate from
/// `DiscoveryOutcome` because it must serialize (a stable cross-process
/// contract) while `DiscoveryOutcome` carries a raw `ProcessIncarnation`
/// that has no reason to leave this process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedTargetSummary {
    pub agent_key: String,
    pub display_name: Option<String>,
    /// "available", "not_found", or "ambiguous" — `DiscoveryOutcome`'s three
    /// states, spelled as strings because this crosses a process boundary.
    pub status: String,
    pub reason: Option<String>,
    pub pid: Option<u32>,
    pub config_roots: Vec<String>,
    pub binary_path: Option<String>,
}

fn summarize_target(target: &Target, outcome: &DiscoveryOutcome) -> ResolvedTargetSummary {
    let (status, reason, pid) = match outcome {
        DiscoveryOutcome::Available(process) => ("available", None, Some(process.pid)),
        DiscoveryOutcome::NotFound(reason) => ("not_found", Some(reason.clone()), None),
        DiscoveryOutcome::Ambiguous(reason) => ("ambiguous", Some(reason.clone()), None),
    };
    ResolvedTargetSummary {
        agent_key: target.agent_key.clone(),
        display_name: target.display_name.clone(),
        status: status.to_string(),
        reason,
        pid,
        config_roots: target
            .scan
            .as_ref()
            .map(|scan| {
                scan.config_roots
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect()
            })
            .unwrap_or_default(),
        binary_path: target.capture.as_ref().and_then(|c| c.binary_path.clone()),
    }
}

impl TargetManifest {
    /// Every declared agent's outcome plus the scan-scoping fields the
    /// Python scanner needs, in manifest order — the resolved-target JSON
    /// contract `--print-resolved-targets` publishes on stdout.
    pub fn resolve_all_summary(&self) -> Vec<ResolvedTargetSummary> {
        self.agents
            .iter()
            .zip(self.resolve_all())
            .map(|(target, outcome)| summarize_target(target, &outcome))
            .collect()
    }

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
            match (&target.discovery.pid_file, &target.discovery.cgroup) {
                (Some(_), Some(_)) => bail!(
                    "'{}' declares both pid_file and cgroup; exactly one locator is required",
                    target.agent_key
                ),
                (None, None) => bail!(
                    "'{}' declares no discovery locator; pid_file or cgroup is required",
                    target.agent_key
                ),
                (Some(path), None) if !path.is_absolute() => bail!(
                    "pid_file for '{}' must be an absolute path",
                    target.agent_key
                ),
                (None, Some(path)) if !path.is_absolute() => {
                    bail!("cgroup for '{}' must be an absolute path", target.agent_key)
                }
                _ => {}
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

    /// One outcome per declared agent, in manifest order. A target that
    /// fails to resolve on its own never prevents the others from being
    /// tried; a target that resolves but collides with another (same
    /// process incarnation, session, or uid) is downgraded from `Available`
    /// to `Ambiguous` for every colliding key, not just dropped.
    pub fn resolve_all(&self) -> Vec<DiscoveryOutcome> {
        let supervisor_uid = unsafe { libc::geteuid() };
        let mut outcomes: Vec<DiscoveryOutcome> = self
            .agents
            .iter()
            .map(|target| resolve_target(target, supervisor_uid))
            .collect();
        mark_collisions(&mut outcomes);
        outcomes
    }
}

/// Downgrades every `Available` outcome that shares a process incarnation,
/// session, or uid with another `Available` outcome to `Ambiguous`, in
/// place. Pure and free of I/O so it can be exercised directly with
/// synthetic `ProcessIncarnation`s, without needing a second real uid.
fn mark_collisions(outcomes: &mut [DiscoveryOutcome]) {
    use std::collections::HashMap;

    let mut by_incarnation: HashMap<(u32, u64), Vec<usize>> = HashMap::new();
    let mut by_session: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut by_uid: HashMap<u32, Vec<usize>> = HashMap::new();
    for (index, outcome) in outcomes.iter().enumerate() {
        if let DiscoveryOutcome::Available(process) = outcome {
            by_incarnation
                .entry((process.pid, process.start_time_ticks))
                .or_default()
                .push(index);
            by_session
                .entry(process.session_id)
                .or_default()
                .push(index);
            by_uid.entry(process.uid).or_default().push(index);
        }
    }

    let mut ambiguous: HashMap<usize, String> = HashMap::new();
    for indices in by_incarnation.values().filter(|indices| indices.len() > 1) {
        for &index in indices {
            ambiguous.entry(index).or_insert_with(|| {
                "one process incarnation is claimed by multiple agent keys".to_string()
            });
        }
    }
    for indices in by_session.values().filter(|indices| indices.len() > 1) {
        for &index in indices {
            ambiguous.entry(index).or_insert_with(|| {
                "agents share a process session; capture would be ambiguous".to_string()
            });
        }
    }
    for indices in by_uid.values().filter(|indices| indices.len() > 1) {
        for &index in indices {
            ambiguous.entry(index).or_insert_with(|| {
                "agents share a uid; same-uid processes are not an attribution boundary".to_string()
            });
        }
    }
    for (index, reason) in ambiguous {
        outcomes[index] = DiscoveryOutcome::Ambiguous(reason);
    }
}

fn resolve_target(target: &Target, supervisor_uid: u32) -> DiscoveryOutcome {
    match try_resolve_target(target, supervisor_uid) {
        Ok(process) => DiscoveryOutcome::Available(process),
        Err(error) => DiscoveryOutcome::NotFound(error.to_string()),
    }
}

/// The locator path to run every ownership/writability check against.
/// `pid_file` names itself directly; `cgroup` names its `cgroup.procs` file —
/// that is what delegation actually gates (a uid without write access to it
/// cannot add or remove its own membership, the design's "non-delegated"
/// requirement), and checking it also walks every ancestor directory
/// (including the cgroup directory itself) via `validate_control_path`'s own
/// upward walk.
fn locator_path(target: &Target) -> Result<PathBuf> {
    if let Some(pid_file) = &target.discovery.pid_file {
        return Ok(pid_file.clone());
    }
    let cgroup = target
        .discovery
        .cgroup
        .as_deref()
        .context("target declares neither pid_file nor cgroup")?;
    Ok(cgroup.join("cgroup.procs"))
}

/// The pid(s) an already-validated locator currently names. `pid_file` holds
/// exactly one; `cgroup.procs` holds one PID per line, kernel-maintained.
fn read_pids(target: &Target, locator_path: &Path) -> Result<Vec<u32>> {
    let text = fs::read_to_string(locator_path)
        .with_context(|| format!("reading locator for '{}'", target.agent_key))?;
    if target.discovery.pid_file.is_some() {
        let pid: u32 = text
            .trim()
            .parse()
            .with_context(|| format!("invalid PID in {}", locator_path.display()))?;
        return Ok(vec![pid]);
    }
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.trim()
                .parse::<u32>()
                .with_context(|| format!("invalid PID in {}", locator_path.display()))
        })
        .collect()
}

fn try_resolve_target(target: &Target, supervisor_uid: u32) -> Result<ProcessIncarnation> {
    let locator_path = locator_path(target)?;
    validate_control_path(&locator_path, None)?;
    let pids = read_pids(target, &locator_path)?;
    let pid = match pids.as_slice() {
        [] => bail!("locator {} names no process", locator_path.display()),
        [pid] => *pid,
        many => bail!(
            "locator {} names {} processes; multi-process attribution is not supported yet",
            locator_path.display(),
            many.len()
        ),
    };
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
    validate_control_path(&locator_path, Some(uid))?;
    if uid == supervisor_uid {
        bail!(
            "locator {} names a process owned by the supervisor",
            locator_path.display()
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
    use std::os::unix::fs::PermissionsExt;

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

    fn target(key: &str, pid_file: &str) -> Target {
        Target {
            agent_key: key.to_string(),
            display_name: None,
            discovery: Discovery {
                pid_file: Some(PathBuf::from(pid_file)),
                cgroup: None,
            },
            scan: None,
            capture: None,
        }
    }

    fn target_with_cgroup(key: &str, cgroup: &str) -> Target {
        Target {
            agent_key: key.to_string(),
            display_name: None,
            discovery: Discovery {
                pid_file: None,
                cgroup: Some(PathBuf::from(cgroup)),
            },
            scan: None,
            capture: None,
        }
    }

    fn manifest(agents: Vec<Target>) -> TargetManifest {
        TargetManifest {
            manifest_version: 1,
            sandbox: Sandbox {
                host_id: "host-1".to_string(),
                sandbox_name: "sandbox-1".to_string(),
                access: Access {
                    kind: "docker".to_string(),
                    container: "container-1".to_string(),
                },
            },
            agents,
        }
    }

    fn error_message<T: std::fmt::Debug>(result: Result<T>) -> String {
        result
            .expect_err("expected the call to reject its input")
            .to_string()
    }

    /// `validate_control_path` walks every ancestor directory up to `/`, so a
    /// fixture under the default `/tmp` (mode 1777, world-writable) fails
    /// before the test's own assertion does. `$HOME` is owned by whichever
    /// account runs the tests (root here, the CI runner elsewhere) with a
    /// non-writable-by-others chain up to `/`, so it passes the same checks
    /// prod manifests are expected to satisfy.
    fn test_dir() -> tempfile::TempDir {
        let home = std::env::var("HOME").expect("HOME must be set to place safe test fixtures");
        tempfile::Builder::new()
            .prefix("railmon-identity-test-")
            .tempdir_in(home)
            .expect("create temp dir under $HOME")
    }

    #[test]
    fn accepts_a_well_formed_multi_agent_manifest() {
        let m = manifest(vec![
            target("planner", "/run/agents/planner.pid"),
            target("worker-2", "/run/agents/worker-2.pid"),
        ]);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn rejects_unsupported_manifest_version() {
        let mut m = manifest(vec![target("planner", "/run/agents/planner.pid")]);
        m.manifest_version = 2;
        assert!(error_message(m.validate()).contains("unsupported target manifest version"));
    }

    #[test]
    fn rejects_empty_host_id_or_sandbox_name() {
        let mut m = manifest(vec![target("planner", "/run/agents/planner.pid")]);
        m.sandbox.host_id.clear();
        assert!(error_message(m.validate()).contains("host_id and sandbox_name"));

        let mut m = manifest(vec![target("planner", "/run/agents/planner.pid")]);
        m.sandbox.sandbox_name.clear();
        assert!(error_message(m.validate()).contains("host_id and sandbox_name"));
    }

    #[test]
    fn rejects_non_docker_or_unnamed_access() {
        let mut m = manifest(vec![target("planner", "/run/agents/planner.pid")]);
        m.sandbox.access.kind = "vm".to_string();
        assert!(error_message(m.validate()).contains("docker container"));

        let mut m = manifest(vec![target("planner", "/run/agents/planner.pid")]);
        m.sandbox.access.container.clear();
        assert!(error_message(m.validate()).contains("docker container"));
    }

    #[test]
    fn rejects_a_manifest_with_no_agents() {
        let m = manifest(vec![]);
        assert!(error_message(m.validate()).contains("at least one agent"));
    }

    #[test]
    fn rejects_the_reserved_default_key_even_alone() {
        let m = manifest(vec![target("default", "/run/agents/default.pid")]);
        assert!(error_message(m.validate()).contains("reserved for the unkeyed compatibility"));
    }

    #[test]
    fn rejects_two_agents_sharing_a_key() {
        let m = manifest(vec![
            target("planner", "/run/agents/a.pid"),
            target("planner", "/run/agents/b.pid"),
        ]);
        assert!(error_message(m.validate()).contains("duplicate agent_key"));
    }

    #[test]
    fn rejects_an_invalid_key_inside_a_manifest() {
        let m = manifest(vec![target("Planner", "/run/agents/planner.pid")]);
        assert!(error_message(m.validate()).contains("invalid agent_key"));
    }

    #[test]
    fn rejects_a_relative_pid_file() {
        let m = manifest(vec![target("planner", "agents/planner.pid")]);
        assert!(error_message(m.validate()).contains("must be an absolute path"));
    }

    #[test]
    fn rejects_a_target_declaring_both_pid_file_and_cgroup() {
        let mut t = target("planner", "/run/agents/planner.pid");
        t.discovery.cgroup = Some(PathBuf::from("/sys/fs/cgroup/agents/planner"));
        let m = manifest(vec![t]);
        assert!(error_message(m.validate()).contains("exactly one locator is required"));
    }

    #[test]
    fn rejects_a_target_declaring_neither_pid_file_nor_cgroup() {
        let mut t = target("planner", "/run/agents/planner.pid");
        t.discovery.pid_file = None;
        let m = manifest(vec![t]);
        assert!(error_message(m.validate()).contains("discovery locator"));
    }

    #[test]
    fn rejects_a_relative_cgroup() {
        let m = manifest(vec![target_with_cgroup("planner", "agents/planner")]);
        assert!(error_message(m.validate()).contains("must be an absolute path"));
    }

    #[test]
    fn accepts_a_cgroup_locator_shaped_target() {
        let m = manifest(vec![target_with_cgroup(
            "planner",
            "/sys/fs/cgroup/agents/planner",
        )]);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn rejects_an_empty_display_name() {
        let mut t = target("planner", "/run/agents/planner.pid");
        t.display_name = Some(String::new());
        let m = manifest(vec![t]);
        assert!(error_message(m.validate()).contains("display_name"));
    }

    #[test]
    fn rejects_a_relative_config_root() {
        let mut t = target("planner", "/run/agents/planner.pid");
        t.scan = Some(Scan {
            config_roots: vec![PathBuf::from("relative/path")],
        });
        let m = manifest(vec![t]);
        assert!(error_message(m.validate()).contains("config_roots"));
    }

    #[test]
    fn accepts_a_private_self_owned_file() {
        let dir = test_dir();
        let path = dir.path().join("manifest.yaml");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_control_path(&path, None).is_ok());
    }

    #[test]
    fn rejects_a_group_writable_file() {
        let dir = test_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("manifest.yaml");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        assert!(error_message(validate_control_path(&path, None)).contains("group/other writable"));
    }

    #[test]
    fn rejects_an_other_writable_file() {
        let dir = test_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("manifest.yaml");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o602)).unwrap();
        assert!(error_message(validate_control_path(&path, None)).contains("group/other writable"));
    }

    #[test]
    fn rejects_a_writable_parent_directory_even_with_a_private_leaf() {
        let dir = test_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let path = dir.path().join("manifest.yaml");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(error_message(validate_control_path(&path, None)).contains("group/other writable"));
    }

    #[test]
    fn rejects_a_symlinked_control_path() {
        let dir = test_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let real = dir.path().join("real.yaml");
        fs::write(&real, b"x").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("manifest.yaml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(error_message(validate_control_path(&link, None)).contains("symlink"));
    }

    #[test]
    fn rejects_a_path_owned_by_the_monitored_uid() {
        let dir = test_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("planner.pid");
        fs::write(&path, b"1").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let self_uid = fs::metadata(&path).unwrap().uid();
        assert!(error_message(validate_control_path(&path, Some(self_uid)))
            .contains("owned by monitored uid"));
        assert!(validate_control_path(&path, Some(self_uid + 1)).is_ok());
    }

    #[test]
    fn rejects_a_relative_control_path() {
        assert!(
            error_message(validate_control_path(Path::new("relative.yaml"), None))
                .contains("not absolute")
        );
    }

    fn not_found_reason(outcome: &DiscoveryOutcome) -> &str {
        match outcome {
            DiscoveryOutcome::NotFound(reason) => reason,
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    // A single-uid test process can only ever create a pid_file it owns
    // itself, and can only ever point it at a live PID it also owns (itself,
    // or a child it spawned) — so `resolve_target`'s own supervisor-uid and
    // session-leader checks are unreachable here: `validate_control_path`'s
    // "owned by monitored uid" rejection always fires first, for any locator
    // this test can construct. That is itself the fail-closed same-owner-UID
    // property the design calls out explicitly ("must not be writable by any
    // monitored UID... including same-owner UID cases") — assert it
    // directly. The checks beyond it need genuinely distinct UIDs, which
    // only the root-only `tests/two_agent_acceptance.py` can provide; the
    // cross-target collision logic itself (`mark_collisions`) is pure and
    // gets exercised directly below with synthetic incarnations instead.
    #[test]
    fn resolve_target_reports_not_found_for_a_self_owned_pid_file_even_when_it_names_a_live_pid() {
        let dir = test_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let pid_file = dir.path().join("self.pid");
        fs::write(&pid_file, std::process::id().to_string()).unwrap();
        fs::set_permissions(&pid_file, fs::Permissions::from_mode(0o600)).unwrap();
        let t = target("planner", pid_file.to_str().unwrap());
        let outcome = resolve_target(&t, unsafe { libc::geteuid() } + 1);
        assert!(not_found_reason(&outcome).contains("owned by monitored uid"));
    }

    // A cgroup locator resolves via its `cgroup.procs` file instead of a
    // pid_file's own content, but shares every check downstream of that —
    // same self-owned-UID fail-closed property, asserted the same way.
    #[test]
    fn resolve_target_reports_not_found_for_a_self_owned_cgroup_even_when_it_names_a_live_pid() {
        let dir = test_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            dir.path().join("cgroup.procs"),
            std::process::id().to_string(),
        )
        .unwrap();
        fs::set_permissions(
            dir.path().join("cgroup.procs"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let t = target_with_cgroup("planner", dir.path().to_str().unwrap());
        let outcome = resolve_target(&t, unsafe { libc::geteuid() } + 1);
        assert!(not_found_reason(&outcome).contains("owned by monitored uid"));
    }

    #[test]
    fn resolve_target_reports_not_found_for_a_cgroup_with_no_member_processes() {
        let dir = test_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.path().join("cgroup.procs"), "").unwrap();
        fs::set_permissions(
            dir.path().join("cgroup.procs"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let t = target_with_cgroup("planner", dir.path().to_str().unwrap());
        let outcome = resolve_target(&t, unsafe { libc::geteuid() } + 1);
        assert!(not_found_reason(&outcome).contains("names no process"));
    }

    #[test]
    fn resolve_target_reports_not_found_for_a_cgroup_naming_multiple_processes() {
        // M2 doesn't yet attribute a multi-process cgroup to one incarnation
        // (that needs M3's supervisor/descendant model) — fails closed with a
        // named reason rather than guessing which PID is the agent.
        let dir = test_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let pid = std::process::id();
        fs::write(dir.path().join("cgroup.procs"), format!("{pid}\n{pid}")).unwrap();
        fs::set_permissions(
            dir.path().join("cgroup.procs"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let t = target_with_cgroup("planner", dir.path().to_str().unwrap());
        let outcome = resolve_target(&t, unsafe { libc::geteuid() } + 1);
        assert!(not_found_reason(&outcome).contains("multi-process attribution is not supported"));
    }

    #[test]
    fn resolve_all_reports_not_found_for_a_self_owned_pid_file_even_when_it_names_a_live_pid() {
        let dir = test_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let pid_file = dir.path().join("self.pid");
        fs::write(&pid_file, std::process::id().to_string()).unwrap();
        fs::set_permissions(&pid_file, fs::Permissions::from_mode(0o600)).unwrap();
        let m = manifest(vec![target("planner", pid_file.to_str().unwrap())]);
        let outcomes = m.resolve_all();
        assert_eq!(outcomes.len(), 1);
        assert!(not_found_reason(&outcomes[0]).contains("owned by monitored uid"));
    }

    #[test]
    fn resolve_all_keeps_resolving_later_targets_after_an_earlier_one_fails() {
        // The first agent's locator doesn't exist at all; the second agent's
        // locator exists but is (like every locator this single-uid test can
        // construct) self-owned. Both fail, for different reasons — proving
        // `resolve_all` tries every declared agent rather than stopping at
        // the first failure (design §4.2: never drop a declared agent just
        // because its process is down).
        let dir = test_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let missing_pid_file = dir.path().join("missing.pid");
        let present_pid_file = dir.path().join("present.pid");
        fs::write(&present_pid_file, std::process::id().to_string()).unwrap();
        fs::set_permissions(&present_pid_file, fs::Permissions::from_mode(0o600)).unwrap();
        let m = manifest(vec![
            target("planner", missing_pid_file.to_str().unwrap()),
            target("executor", present_pid_file.to_str().unwrap()),
        ]);
        let outcomes = m.resolve_all();
        assert_eq!(outcomes.len(), 2);
        assert!(not_found_reason(&outcomes[0]).contains("inspecting control path"));
        assert!(not_found_reason(&outcomes[1]).contains("owned by monitored uid"));
    }

    fn available(pid: u32, start_time_ticks: u64, session_id: u32, uid: u32) -> DiscoveryOutcome {
        DiscoveryOutcome::Available(ProcessIncarnation {
            pid,
            start_time_ticks,
            session_id,
            uid,
        })
    }

    #[test]
    fn mark_collisions_leaves_distinct_available_targets_alone() {
        let mut outcomes = vec![available(10, 100, 10, 1000), available(20, 200, 20, 2000)];
        mark_collisions(&mut outcomes);
        assert!(matches!(outcomes[0], DiscoveryOutcome::Available(_)));
        assert!(matches!(outcomes[1], DiscoveryOutcome::Available(_)));
    }

    #[test]
    fn mark_collisions_downgrades_both_sides_of_a_shared_incarnation() {
        let mut outcomes = vec![available(10, 100, 10, 1000), available(10, 100, 10, 1000)];
        mark_collisions(&mut outcomes);
        for outcome in &outcomes {
            match outcome {
                DiscoveryOutcome::Ambiguous(reason) => {
                    assert!(reason.contains("claimed by multiple agent keys"))
                }
                other => panic!("expected Ambiguous, got {other:?}"),
            }
        }
    }

    #[test]
    fn mark_collisions_downgrades_a_shared_session_even_with_distinct_pids() {
        let mut outcomes = vec![available(10, 100, 99, 1000), available(20, 200, 99, 2000)];
        mark_collisions(&mut outcomes);
        for outcome in &outcomes {
            match outcome {
                DiscoveryOutcome::Ambiguous(reason) => assert!(reason.contains("process session")),
                other => panic!("expected Ambiguous, got {other:?}"),
            }
        }
    }

    #[test]
    fn mark_collisions_downgrades_a_shared_uid_even_with_distinct_sessions() {
        let mut outcomes = vec![available(10, 100, 10, 1000), available(20, 200, 20, 1000)];
        mark_collisions(&mut outcomes);
        for outcome in &outcomes {
            match outcome {
                DiscoveryOutcome::Ambiguous(reason) => assert!(reason.contains("share a uid")),
                other => panic!("expected Ambiguous, got {other:?}"),
            }
        }
    }

    #[test]
    fn mark_collisions_does_not_let_a_collision_hide_a_not_found_target() {
        let mut outcomes = vec![
            available(10, 100, 10, 1000),
            available(10, 100, 10, 1000),
            DiscoveryOutcome::NotFound("no locator".to_string()),
        ];
        mark_collisions(&mut outcomes);
        assert!(matches!(outcomes[0], DiscoveryOutcome::Ambiguous(_)));
        assert!(matches!(outcomes[1], DiscoveryOutcome::Ambiguous(_)));
        assert_eq!(not_found_reason(&outcomes[2]), "no locator");
    }

    #[test]
    fn summarize_target_reports_available_with_scan_scope_and_pid() {
        let mut t = target("planner", "/run/agents/planner.pid");
        t.display_name = Some("Planning agent".to_string());
        t.scan = Some(Scan {
            config_roots: vec![PathBuf::from("/srv/planner")],
        });
        t.capture = Some(Capture {
            binary_path: Some("/usr/bin/python3".to_string()),
        });
        let summary = summarize_target(&t, &available(42, 100, 42, 1000));
        assert_eq!(summary.agent_key, "planner");
        assert_eq!(summary.display_name.as_deref(), Some("Planning agent"));
        assert_eq!(summary.status, "available");
        assert_eq!(summary.reason, None);
        assert_eq!(summary.pid, Some(42));
        assert_eq!(summary.config_roots, vec!["/srv/planner".to_string()]);
        assert_eq!(summary.binary_path.as_deref(), Some("/usr/bin/python3"));
    }

    #[test]
    fn summarize_target_reports_not_found_and_ambiguous_with_no_pid() {
        let t = target("executor", "/run/agents/executor.pid");
        let not_found = summarize_target(&t, &DiscoveryOutcome::NotFound("no locator".to_string()));
        assert_eq!(not_found.status, "not_found");
        assert_eq!(not_found.reason.as_deref(), Some("no locator"));
        assert_eq!(not_found.pid, None);

        let ambiguous = summarize_target(
            &t,
            &DiscoveryOutcome::Ambiguous("shares a uid with 'planner'".to_string()),
        );
        assert_eq!(ambiguous.status, "ambiguous");
        assert_eq!(ambiguous.pid, None);
    }

    #[test]
    fn summarize_target_defaults_scan_and_capture_fields_when_absent() {
        let t = target("executor", "/run/agents/executor.pid");
        let summary = summarize_target(&t, &available(7, 1, 7, 1000));
        assert!(summary.config_roots.is_empty());
        assert_eq!(summary.binary_path, None);
    }

    #[test]
    fn resolve_all_summary_is_one_entry_per_declared_agent_in_order() {
        let m = manifest(vec![
            target("planner", "/does/not/exist/planner.pid"),
            target("executor", "/does/not/exist/executor.pid"),
        ]);
        let summaries = m.resolve_all_summary();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].agent_key, "planner");
        assert_eq!(summaries[1].agent_key, "executor");
        assert_eq!(summaries[0].status, "not_found");
        assert_eq!(summaries[1].status, "not_found");
    }
}

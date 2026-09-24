use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
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
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub agent_key: String,
    pub discovery: Discovery,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub pid_file: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgentRef {
    pub host_id: String,
    pub sandbox_name: String,
    pub agent_key: String,
}

impl TargetManifest {
    pub fn load(path: &Path) -> Result<Self> {
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
            if target.discovery.pid_file.as_os_str().is_empty()
                || !target.discovery.pid_file.is_absolute()
            {
                bail!(
                    "pid_file for '{}' must be an absolute path",
                    target.agent_key
                );
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
}

fn validate_key(key: &str) -> Result<()> {
    if key.len() > 64
        || key.is_empty()
        || !key.as_bytes()[0].is_ascii_lowercase() && !key.as_bytes()[0].is_ascii_digit()
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

    fn manifest(keys: &[&str]) -> TargetManifest {
        TargetManifest {
            manifest_version: 1,
            sandbox: Sandbox {
                host_id: "host-1".into(),
                sandbox_name: "box".into(),
            },
            agents: keys
                .iter()
                .map(|key| Target {
                    agent_key: (*key).into(),
                    discovery: Discovery {
                        pid_file: format!("/run/{key}.pid").into(),
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn accepts_distinct_canonical_keys() {
        manifest(&["planner", "executor-2"]).validate().unwrap();
    }

    #[test]
    fn rejects_duplicate_reserved_and_noncanonical_keys() {
        for keys in [
            &["planner", "planner"][..],
            &["default"][..],
            &["Planner"][..],
        ] {
            assert!(manifest(keys).validate().is_err());
        }
    }
}

//! The destinations summary `railmon scan` reads as `RAIL_OBSERVED_FILE`
//! (DR-296).
//!
//! The collector already decodes every request it forwards. This keeps, per
//! destination host, how many requests went there and how many of those got
//! no response or an error status, and rewrites one small JSON file with
//! them. It's in the shape of the AgentSight snapshot the scanner's
//! `summarize_observed` reads: `network_targets[]` with `host`, `count` and
//! `error_count`. It holds host names and counts only, never a path, header,
//! body or tool argument.
//!
//! A host is one item, not a host and a path: a destination is what
//! `observed_destinations` reports, and a new path on a known host is not a
//! new destination.
//!
//! The file covers everything since `started_at`, the first time this file
//! was written, across collector restarts: it is read back at start. The
//! scanner reports `generated_at - started_at` as the runtime source's
//! `window_seconds`, so time the collector was stopped is inside the window.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// What the file says it is. A file with another value isn't ours and is
/// started over.
pub const SCHEMA_VERSION: &str = "railmon-observed/1";

/// Distinct hosts kept. Past it, a request to a host not yet kept is
/// counted in `uncounted_requests`, and the scanner reports the list as
/// PARTIAL.
pub const MAX_HOSTS: usize = 1024;

/// The longest host name DNS allows. A longer one is not a host.
const MAX_HOST_LEN: usize = 253;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Target {
    count: u64,
    error_count: u64,
}

pub struct ObservedSummary {
    path: PathBuf,
    started_at: String,
    targets: BTreeMap<String, Target>,
    uncounted_requests: u64,
    dirty: bool,
    interval: Duration,
    last_write: Instant,
}

impl ObservedSummary {
    /// Reads back the summary at `path` if it is one of ours, so the window
    /// goes on from its `started_at`, and writes it once, so the scanner
    /// sees that collection runs before the first request. A file that can't
    /// be read or written is logged, and capture goes on without it until a
    /// later write succeeds: the summary is one output among the others.
    pub fn open(path: &Path, interval: Duration) -> Self {
        let mut summary = Self {
            path: path.to_path_buf(),
            started_at: now(),
            targets: BTreeMap::new(),
            uncounted_requests: 0,
            dirty: true,
            interval,
            last_write: Instant::now(),
        };
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(previous) if summary.restore(&previous) => {
                    log::info!(
                        "destinations summary {}: continuing from {}",
                        path.display(),
                        summary.started_at
                    )
                }
                _ => log::warn!(
                    "destinations summary {} is not one this collector wrote; starting it over",
                    path.display()
                ),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => log::warn!(
                "reading destinations summary {}: {error}; starting it over",
                path.display()
            ),
        }
        summary.write_logged();
        summary
    }

    /// Takes `previous`'s window if it is a summary of ours.
    fn restore(&mut self, previous: &Value) -> bool {
        if previous.get("schema_version").and_then(Value::as_str) != Some(SCHEMA_VERSION) {
            return false;
        }
        let Some(started_at) = previous
            .get("started_at")
            .and_then(Value::as_str)
            .filter(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok())
        else {
            return false;
        };
        let Some(rows) = previous.get("network_targets").and_then(Value::as_array) else {
            return false;
        };
        let mut targets = BTreeMap::new();
        for row in rows {
            let (Some(host), Some(count)) = (
                row.get("host")
                    .and_then(Value::as_str)
                    .and_then(normalize_host),
                row.get("count").and_then(Value::as_u64),
            ) else {
                return false;
            };
            let error_count = row
                .get("error_count")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .min(count);
            if targets.len() < MAX_HOSTS {
                targets.insert(host, Target { count, error_count });
            }
        }
        self.started_at = started_at.to_string();
        self.targets = targets;
        self.uncounted_requests = previous
            .get("uncounted_requests")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        true
    }

    /// Counts one forwarded interaction: the legacy-http pair or the
    /// RuntimeInteraction row the collector emits. Anything else is skipped.
    pub fn note(&mut self, interaction: &Value) {
        let Some(request) = interaction.get("request").filter(|v| v.is_object()) else {
            return;
        };
        let destination = match request.get("destination").and_then(Value::as_str) {
            Some(destination) => destination.to_string(),
            None => crate::interaction::path_and_destination(Some(request)).1,
        };
        let Some(host) = normalize_host(&destination) else {
            return;
        };
        let status = interaction
            .get("response")
            .and_then(|r| r.get("status_code").or_else(|| r.get("status")))
            .and_then(|s| {
                s.as_i64()
                    .or_else(|| s.as_str().and_then(|t| t.trim().parse().ok()))
            });
        let failed = !matches!(status, Some(code) if (100..400).contains(&code));

        let full = self.targets.len() >= MAX_HOSTS;
        match self.targets.get_mut(&host) {
            Some(target) => bump(target, failed),
            None if full => self.uncounted_requests = self.uncounted_requests.saturating_add(1),
            None => {
                let mut target = Target::default();
                bump(&mut target, failed);
                self.targets.insert(host, target);
            }
        }
        self.dirty = true;
    }

    /// Rewrites the file when something changed and `interval` has passed
    /// since the last write. A failed write is logged and retried on a later
    /// call; capture goes on.
    pub fn write_if_due(&mut self) {
        if self.dirty && self.last_write.elapsed() >= self.interval {
            self.write_logged();
        }
    }

    /// Rewrites the file if anything changed since the last write.
    pub fn finish(&mut self) {
        if self.dirty {
            self.write_logged();
        }
    }

    fn write_logged(&mut self) {
        if let Err(error) = self.write() {
            log::warn!(
                "writing destinations summary {}: {error:#}",
                self.path.display()
            );
        }
    }

    fn document(&self) -> Value {
        let mut rows: Vec<(&String, &Target)> = self.targets.iter().collect();
        rows.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));
        json!({
            "schema_version": SCHEMA_VERSION,
            "source": "railmon collect",
            "started_at": self.started_at,
            "generated_at": now(),
            "network_targets": rows
                .into_iter()
                .map(|(host, target)| json!({
                    "host": host,
                    "count": target.count,
                    "error_count": target.error_count,
                }))
                .collect::<Vec<_>>(),
            "uncounted_requests": self.uncounted_requests,
        })
    }

    /// Written to a sibling temporary file and renamed over the summary, so
    /// the scanner never reads half a file.
    fn write(&mut self) -> Result<()> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        // Removed first and then created exclusively, so a link planted at
        // the temporary name is replaced rather than written through.
        match std::fs::remove_file(&tmp) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error).with_context(|| format!("removing {}", tmp.display()));
            }
            _ => {}
        }
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            file.write_all(serde_json::to_string(&self.document())?.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming {} to {}", tmp.display(), self.path.display()))?;
        self.dirty = false;
        self.last_write = Instant::now();
        Ok(())
    }
}

fn bump(target: &mut Target, failed: bool) {
    target.count = target.count.saturating_add(1);
    if failed {
        target.error_count = target.error_count.saturating_add(1);
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The host of an authority (`host`, `host:port`, `[v6]:port`), spelled as
/// the scanner's `url_host` (`urlsplit("//" + authority).hostname`) spells a
/// declared one, so `undeclared_destinations` compares like with like:
/// lowercased, cut at the first `:` (an IPv6 address only in brackets, which
/// it loses), and a trailing dot kept. `None` for what isn't a host: empty,
/// the collector's `unknown`, or text with characters no host name or
/// address has.
fn normalize_host(authority: &str) -> Option<String> {
    let authority = authority.trim();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, v6) = if let Some(rest) = authority.strip_prefix('[') {
        (rest.split_once(']')?.0, true)
    } else {
        (authority.split(':').next().unwrap_or(""), false)
    };
    let host = host.to_ascii_lowercase();
    let valid = !host.is_empty()
        && host != "unknown"
        && host.len() <= MAX_HOST_LEN
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') || (v6 && c == ':'));
    valid.then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy(host: &str, status: Option<i64>) -> Value {
        json!({
            "request": {"method": "POST", "path": "/v1/messages", "headers": {"Host": host}},
            "response": status.map(|s| json!({"status_code": s})).unwrap_or(Value::Null),
        })
    }

    fn read(path: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn hosts_are_spelled_as_the_scanner_spells_a_declared_one() {
        // Each as Python's urlsplit("//" + it).hostname reads it.
        for (authority, host) in [
            ("API.Example.com:443", Some("api.example.com")),
            ("api.example.com.", Some("api.example.com.")),
            ("api.example.com:abc", Some("api.example.com")),
            ("a:b:c", Some("a")),
            ("[::1]:8080", Some("::1")),
            ("::1", None),
            ("user@host.test", Some("host.test")),
            ("unknown", None),
            ("", None),
            ("evil.test/x", None),
        ] {
            assert_eq!(normalize_host(authority).as_deref(), host, "{authority}");
        }
        assert_eq!(normalize_host(&"a".repeat(254)), None);
    }

    #[test]
    fn a_fresh_summary_is_written_at_once_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        ObservedSummary::open(&path, Duration::ZERO);
        let doc = read(&path);
        assert_eq!(doc["schema_version"], SCHEMA_VERSION);
        assert_eq!(doc["network_targets"], json!([]));
        assert_eq!(doc["started_at"], doc["generated_at"]);
        assert!(!dir.path().join("observed.json.tmp").exists());
    }

    #[test]
    fn counts_each_host_and_its_failures_in_both_formats() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        let mut summary = ObservedSummary::open(&path, Duration::ZERO);
        summary.note(&legacy("api.example.com", Some(200)));
        summary.note(&legacy("api.example.com:443", Some(500)));
        summary.note(&legacy("api.example.com", None));
        summary.note(&json!({"request": {"destination": "mcp.test", "path": "/"}, "response": {"status": 204}}));
        summary.note(&json!({"request": {"path": "https://abs.test/x?q=1", "headers": {}}, "response": {"status_code": "302"}}));
        summary.note(
            &json!({"request": {"path": "/", "headers": {}}, "response": {"status_code": 200}}),
        );
        summary.note(&json!({"kind": "start"}));
        summary.write_if_due();
        let doc = read(&path);
        assert_eq!(
            doc["network_targets"],
            json!([
                {"host": "api.example.com", "count": 3, "error_count": 2},
                {"host": "abs.test", "count": 1, "error_count": 0},
                {"host": "mcp.test", "count": 1, "error_count": 0},
            ])
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("/v1/messages") && !text.contains("q=1"),
            "{text}"
        );
    }

    #[test]
    fn the_window_goes_on_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        std::fs::write(
            &path,
            json!({
                "schema_version": SCHEMA_VERSION,
                "started_at": "2026-11-20T08:00:00Z",
                "generated_at": "2026-11-20T09:00:00Z",
                "network_targets": [{"host": "api.example.com", "count": 4, "error_count": 9}],
                "uncounted_requests": 2,
            })
            .to_string(),
        )
        .unwrap();
        let mut summary = ObservedSummary::open(&path, Duration::ZERO);
        summary.note(&legacy("api.example.com", Some(200)));
        summary.finish();
        let doc = read(&path);
        assert_eq!(doc["started_at"], "2026-11-20T08:00:00Z");
        assert_eq!(
            doc["network_targets"],
            json!([{"host": "api.example.com", "count": 5, "error_count": 4}])
        );
        assert_eq!(doc["uncounted_requests"], 2);
    }

    #[test]
    fn a_file_that_is_not_ours_is_started_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        for content in [
            "not json".to_string(),
            json!({"schema_version": "agentsight/1", "started_at": "2026-11-20T08:00:00Z", "network_targets": []}).to_string(),
            json!({"schema_version": SCHEMA_VERSION, "started_at": "yesterday", "network_targets": []}).to_string(),
        ] {
            std::fs::write(&path, content).unwrap();
            ObservedSummary::open(&path, Duration::ZERO);
            let doc = read(&path);
            assert_eq!(doc["network_targets"], json!([]));
            assert_ne!(doc["started_at"], "2026-11-20T08:00:00Z");
        }
    }

    #[test]
    fn hosts_past_the_cap_are_counted_not_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        let mut summary = ObservedSummary::open(&path, Duration::ZERO);
        for i in 0..MAX_HOSTS + 3 {
            summary.note(&legacy(&format!("h{i}.test"), Some(200)));
        }
        summary.note(&legacy("h0.test", Some(200)));
        summary.finish();
        let doc = read(&path);
        assert_eq!(doc["network_targets"].as_array().unwrap().len(), MAX_HOSTS);
        assert_eq!(
            doc["network_targets"][0],
            json!({"host": "h0.test", "count": 2, "error_count": 0})
        );
        assert_eq!(doc["uncounted_requests"], 3);
    }

    #[test]
    fn a_link_at_the_temporary_name_is_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("observed.json.tmp")).unwrap();
        ObservedSummary::open(&path, Duration::ZERO);
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(read(&path)["schema_version"], SCHEMA_VERSION);
    }

    #[test]
    fn a_summary_that_cannot_be_written_does_not_stop_capture() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file"), "").unwrap();
        // Its parent is a file, so no write can succeed.
        let path = dir.path().join("file/observed.json");
        let mut summary = ObservedSummary::open(&path, Duration::ZERO);
        summary.note(&legacy("api.example.com", Some(200)));
        summary.write_if_due();
        summary.finish();
        assert!(summary.dirty);
    }

    #[test]
    fn writes_wait_for_the_interval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        let mut summary = ObservedSummary::open(&path, Duration::from_secs(3600));
        summary.note(&legacy("api.example.com", Some(200)));
        summary.write_if_due();
        assert_eq!(read(&path)["network_targets"], json!([]));
        summary.finish();
        assert_eq!(read(&path)["network_targets"][0]["count"], 1);
    }
}

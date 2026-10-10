//! Capture liveness for RailDash (DR-184, Data Guardrail §4.1).
//!
//! A collector posts captures but nothing while the agent is quiet, so on its
//! own RailDash can't tell an idle agent from a dead collector. While at least
//! one tap is attached the collector therefore posts a heartbeat every 60 s to
//! `/webhook/heartbeat` on the webhook's own receiver, carrying RailDash's
//! local write token. The count is the caller's attached taps, never process
//! liveness: in manifest mode the collector stays up with every target down,
//! and a heartbeat then would report capture that isn't happening.
//!
//! It also presents the webhook's `RAIL_AUTH_MODE` credential, so a RailDash
//! behind an authenticating proxy sees the same caller; a heartbeat whose
//! credential can't be produced is skipped, never sent without one (RM-F2).
//!
//! Best-effort, like a webhook batch: a failed heartbeat is logged when the
//! outcome changes, and it never stops capture. The POST runs off the capture
//! loop, so a hung receiver holds up no event reads. Logs name the URL without
//! its userinfo, query or fragment.

use crate::auth::RailDashToken;
use anyhow::{bail, Context, Result};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// RailDash treats a collector as gone after three minutes without one.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// RailDash's cap on `collector_id`.
const MAX_COLLECTOR_ID: usize = 128;

pub struct Heartbeat {
    url: String,
    /// `url` as logged: no userinfo, query or fragment.
    logged_url: String,
    client: reqwest::Client,
    token: RailDashToken,
    collector_id: String,
    interval: Duration,
    /// The last failure logged, `None` while heartbeats are delivered.
    last_failure: Arc<Mutex<Option<String>>>,
    in_flight: Option<tokio::task::JoinHandle<()>>,
}

impl Heartbeat {
    /// `client` is the webhook's, so the heartbeat has its timeout and its
    /// refusal to follow redirects.
    pub fn new(
        webhook: &str,
        client: reqwest::Client,
        token: RailDashToken,
        interval: Duration,
    ) -> Result<Self> {
        let url = heartbeat_url(webhook)?;
        Ok(Self {
            logged_url: redacted_url(&url),
            url,
            client,
            token,
            collector_id: collector_id(
                std::env::var("RAIL_HOST_ID").ok().as_deref(),
                std::fs::read_to_string("/proc/sys/kernel/hostname")
                    .ok()
                    .as_deref(),
                std::process::id(),
            ),
            interval,
            last_failure: Arc::new(Mutex::new(None)),
            in_flight: None,
        })
    }

    /// The heartbeat URL as it may be logged, without userinfo.
    pub fn logged_url(&self) -> &str {
        &self.logged_url
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn collector_id(&self) -> &str {
        &self.collector_id
    }

    /// Whether a heartbeat for `taps_attached` taps should go now: not with
    /// no tap attached, nor while the previous one is still in flight (only
    /// possible with a test interval under the 10 s timeout). The caller asks
    /// before producing a credential for it.
    pub fn due(&self, taps_attached: usize) -> bool {
        if !should_send(taps_attached) {
            return false;
        }
        if self
            .in_flight
            .as_ref()
            .is_some_and(|task| !task.is_finished())
        {
            log::debug!("previous heartbeat still in flight; skipping this one");
            return false;
        }
        true
    }

    /// Records a heartbeat that could not be sent, logged like a failed one.
    pub fn skipped(&self, reason: String) {
        note_outcome(&self.last_failure, &self.logged_url, Err(reason));
    }

    /// Posts one heartbeat for `taps_attached` taps in the background, with
    /// `authorization` (the webhook's `RAIL_AUTH_MODE` credential) when there
    /// is one. Sends nothing unless `due`.
    pub fn send(&mut self, taps_attached: usize, authorization: Option<&str>) {
        if !self.due(taps_attached) {
            return;
        }
        // Re-read on every heartbeat, so a rotated token needs no restart.
        let token = match self.token.value() {
            Ok(token) => token,
            Err(error) => {
                self.skipped(format!("{error:#}"));
                return;
            }
        };
        let mut request = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("X-RailDash-Token", token);
        if let Some(value) = authorization {
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        let request = request.body(heartbeat_body(
            &self.collector_id,
            taps_attached,
            chrono::Utc::now(),
        ));
        let last_failure = self.last_failure.clone();
        let url = self.logged_url.clone();
        self.in_flight = Some(tokio::spawn(async move {
            let outcome = match request.send().await {
                Ok(resp) if resp.status().is_success() => Ok(()),
                Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => Err(format!(
                    "returned {} (RailDash refused the token)",
                    resp.status()
                )),
                Ok(resp) => Err(format!("returned {}", resp.status())),
                // Without the URL: reqwest's would quote its userinfo.
                Err(error) => Err(format!("POST failed: {}", error.without_url())),
            };
            note_outcome(&last_failure, &url, outcome);
        }));
    }

    /// Waits for the heartbeat in flight, if any. Tests only: the capture
    /// loop never waits on one.
    #[cfg(test)]
    pub async fn settle(&mut self) {
        if let Some(task) = self.in_flight.take() {
            let _ = task.await;
        }
    }
}

/// The decision behind every tick: a heartbeat says capture is happening, so
/// none is sent without an attached tap.
fn should_send(taps_attached: usize) -> bool {
    taps_attached > 0
}

/// Logs a heartbeat outcome only when it differs from the last one, so a
/// receiver that is down for an hour costs one line, not sixty.
fn note_outcome(last_failure: &Mutex<Option<String>>, url: &str, outcome: Result<(), String>) {
    let mut last = last_failure.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(message) = outcome_change(&mut last, outcome) {
        match message {
            Ok(()) => log::info!("heartbeat to {url} delivered again"),
            Err(reason) => log::warn!(
                "heartbeat to {url} failed: {reason}; capture continues, and this is logged again only when it changes"
            ),
        }
    }
}

/// What to log for `outcome`, given the last one, and the new last one.
fn outcome_change(
    last: &mut Option<String>,
    outcome: Result<(), String>,
) -> Option<Result<(), String>> {
    let changed = match (&*last, &outcome) {
        (None, Ok(())) => false,
        (Some(previous), Err(reason)) => previous != reason,
        _ => true,
    };
    *last = outcome.as_ref().err().cloned();
    changed.then_some(outcome)
}

/// The heartbeat URL on the webhook's receiver: scheme, host and port kept.
/// RailDash's webhook is `/webhook/http-interactions`; when `--webhook` ends
/// with that, only the last segment becomes `heartbeat`, so a RailDash behind
/// a path prefix (`/raildash/webhook/http-interactions`) keeps it. Any other
/// path is replaced by `/webhook/heartbeat`. Query and fragment are dropped.
pub fn heartbeat_url(webhook: &str) -> Result<String> {
    // The URL is not quoted back: it can carry userinfo.
    let mut url = reqwest::Url::parse(webhook)
        .context("--webhook is not an absolute URL to derive the heartbeat URL from")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("--webhook must be an http(s) URL with a host to derive the heartbeat URL from");
    }
    let path = match url
        .path()
        .trim_end_matches('/')
        .strip_suffix("/webhook/http-interactions")
    {
        Some(prefix) => format!("{prefix}/webhook/heartbeat"),
        None => "/webhook/heartbeat".to_string(),
    };
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.into())
}

/// `url` with no userinfo, query or fragment, for logs. A URL that doesn't
/// parse is not quoted at all.
pub fn redacted_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.set_query(None);
            url.set_fragment(None);
            url.into()
        }
        Err(_) => "(the --webhook URL)".to_string(),
    }
}

/// Stable for the process: `RAIL_HOST_ID`, else the hostname, then `:` and
/// the PID, kept to printable ASCII and 128 characters. The PID survives the
/// cut, since two collectors on one host differ only there.
pub fn collector_id(host_id: Option<&str>, hostname: Option<&str>, pid: u32) -> String {
    let suffix = format!(":{pid}");
    let printable = |raw: &str| -> String {
        raw.trim()
            .chars()
            .filter(|c| (' '..='~').contains(c))
            .take(MAX_COLLECTOR_ID - suffix.len())
            .collect()
    };
    let base = [host_id, hostname]
        .into_iter()
        .flatten()
        .map(printable)
        .find(|base| !base.is_empty())
        .unwrap_or_else(|| "railmon".to_string());
    format!("{base}{suffix}")
}

/// Exactly these three fields; RailDash refuses any other.
pub fn heartbeat_body(
    collector_id: &str,
    taps_attached: usize,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "collector_id": collector_id,
        "taps_attached": taps_attached,
        "sent_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    }))
    .expect("serializing a serde_json::Value cannot fail")
}

/// `RAIL_HEARTBEAT_INTERVAL` in seconds, for tests; 60 s otherwise. A value
/// that is not a positive number is reported and ignored rather than turning
/// heartbeats off. Clamped to [0.1 s, 1 h], like `--flush-interval`.
pub fn interval_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Duration {
    let Some(raw) = lookup("RAIL_HEARTBEAT_INTERVAL").filter(|v| !v.trim().is_empty()) else {
        return HEARTBEAT_INTERVAL;
    };
    match raw.trim().parse::<f64>() {
        Ok(seconds) if seconds.is_finite() && seconds > 0.0 => {
            Duration::from_secs_f64(seconds.clamp(0.1, 3600.0))
        }
        _ => {
            log::warn!(
                "RAIL_HEARTBEAT_INTERVAL={raw:?} is not a positive number of seconds; using {}",
                HEARTBEAT_INTERVAL.as_secs()
            );
            HEARTBEAT_INTERVAL
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::Value;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    #[test]
    fn the_heartbeat_url_replaces_raildashs_webhook_path() {
        for (webhook, expected) in [
            (
                "http://raildash:8000/webhook/http-interactions",
                "http://raildash:8000/webhook/heartbeat",
            ),
            // A RailDash behind a path prefix keeps it.
            (
                "https://dash.example/raildash/webhook/http-interactions/",
                "https://dash.example/raildash/webhook/heartbeat",
            ),
            // Anything else is the receiver's origin.
            (
                "http://127.0.0.1:9/v1/interactions?x=1#f",
                "http://127.0.0.1:9/webhook/heartbeat",
            ),
            (
                "http://[::1]:8000/prefix/other",
                "http://[::1]:8000/webhook/heartbeat",
            ),
            ("http://host", "http://host/webhook/heartbeat"),
        ] {
            assert_eq!(heartbeat_url(webhook).unwrap(), expected, "{webhook}");
        }
    }

    #[test]
    fn the_logged_url_has_no_userinfo_query_or_fragment() {
        assert_eq!(
            redacted_url("http://alice:hunter2@127.0.0.1:9/webhook/heartbeat?k=v#f"),
            "http://127.0.0.1:9/webhook/heartbeat"
        );
        assert_eq!(redacted_url("https://bob@h/p"), "https://h/p");
        assert!(!redacted_url("not a url hunter2").contains("hunter2"));
        let heartbeat = Heartbeat::new(
            "http://alice:hunter2@127.0.0.1:9/webhook/http-interactions",
            reqwest::Client::new(),
            RailDashToken::Value("t".into()),
            HEARTBEAT_INTERVAL,
        )
        .unwrap();
        assert_eq!(
            heartbeat.logged_url(),
            "http://127.0.0.1:9/webhook/heartbeat"
        );
        // The request itself still carries the userinfo it was given.
        assert!(
            heartbeat.url.contains("alice:hunter2@"),
            "{}",
            heartbeat.url
        );
    }

    #[test]
    fn a_webhook_without_an_http_origin_is_refused_without_quoting_it() {
        for webhook in ["raildash:8000/webhook", "file:///tmp/x", "not a url s3cret"] {
            let message = format!("{:#}", heartbeat_url(webhook).unwrap_err());
            assert!(!message.contains("s3cret"), "{message}");
        }
    }

    #[test]
    fn collector_id_prefers_the_host_id_and_keeps_the_pid() {
        assert_eq!(collector_id(Some(" h-1 "), Some("box\n"), 42), "h-1:42");
        assert_eq!(collector_id(Some(""), Some("box\n"), 42), "box:42");
        assert_eq!(collector_id(None, None, 42), "railmon:42");
        assert_eq!(collector_id(Some("hé\u{7}st"), None, 7), "hst:7");
        assert_eq!(collector_id(Some("\u{e9}"), Some("box"), 7), "box:7");

        let long = collector_id(Some(&"a".repeat(500)), None, 123_456);
        assert_eq!(long.len(), 128);
        assert!(long.ends_with(":123456"), "{long}");
    }

    #[test]
    fn the_body_is_exactly_the_three_fields() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-10T01:02:03.456Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let body: Value = serde_json::from_slice(&heartbeat_body("h:1", 2, now)).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "collector_id": "h:1",
                "taps_attached": 2,
                "sent_at": "2026-10-10T01:02:03.456Z",
            })
        );
    }

    #[test]
    fn no_heartbeat_without_an_attached_tap() {
        assert!(!should_send(0));
        assert!(should_send(1));
        assert!(should_send(3));
    }

    #[test]
    fn a_failure_is_logged_once_until_the_outcome_changes() {
        let mut last = None;
        assert_eq!(outcome_change(&mut last, Ok(())), None);
        assert_eq!(
            outcome_change(&mut last, Err("returned 403".into())),
            Some(Err("returned 403".into()))
        );
        assert_eq!(outcome_change(&mut last, Err("returned 403".into())), None);
        assert_eq!(
            outcome_change(&mut last, Err("returned 500".into())),
            Some(Err("returned 500".into()))
        );
        assert_eq!(outcome_change(&mut last, Ok(())), Some(Ok(())));
        assert_eq!(outcome_change(&mut last, Ok(())), None);
    }

    #[test]
    fn the_interval_defaults_to_a_minute_and_ignores_nonsense() {
        let with = |value: &str| {
            let value = value.to_string();
            interval_from_lookup(move |_| Some(value.clone()))
        };
        assert_eq!(interval_from_lookup(|_| None), HEARTBEAT_INTERVAL);
        assert_eq!(with(""), HEARTBEAT_INTERVAL);
        assert_eq!(with("0.5"), Duration::from_millis(500));
        assert_eq!(with("0.001"), Duration::from_millis(100));
        for bad in ["0", "-1", "soon", "NaN", "inf"] {
            assert_eq!(with(bad), HEARTBEAT_INTERVAL, "{bad}");
        }
    }

    /// A receiver that answers each request with the next status and records
    /// the request it saw (headers lower-cased, then the body).
    /// Each request's head (lower-cased) and body.
    pub(crate) type Seen = Arc<Mutex<Vec<(String, String)>>>;

    pub(crate) fn fake_receiver(statuses: Vec<u16>) -> (String, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for status in statuses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    let lower = line.to_lowercase();
                    if let Some(value) = lower.strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                    head.push_str(&lower);
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                log.lock()
                    .unwrap()
                    .push((head, String::from_utf8(body).unwrap()));
                write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            }
        });
        (origin, seen)
    }

    #[tokio::test]
    async fn a_heartbeat_carries_the_token_and_the_tap_count() {
        let (origin, seen) = fake_receiver(vec![200, 403]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "first\n").unwrap();
        let mut heartbeat = Heartbeat::new(
            &format!("{origin}/webhook/http-interactions"),
            reqwest::Client::new(),
            RailDashToken::File(path.clone()),
            HEARTBEAT_INTERVAL,
        )
        .unwrap();

        heartbeat.send(0, Some("Bearer rc"));
        heartbeat.settle().await;
        assert!(seen.lock().unwrap().is_empty(), "sent with no tap attached");

        heartbeat.send(2, None);
        heartbeat.settle().await;
        // Rotated: the next heartbeat reads the file again.
        std::fs::write(&path, "second\n").unwrap();
        heartbeat.send(1, Some("Bearer rc-1"));
        heartbeat.settle().await;
        assert_eq!(
            heartbeat.last_failure.lock().unwrap().as_deref(),
            Some("returned 403 Forbidden (RailDash refused the token)")
        );

        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for ((head, body), (token, taps, authorization)) in requests
            .iter()
            .zip([("first", 2, None), ("second", 1, Some("bearer rc-1"))])
        {
            assert!(head.starts_with("post /webhook/heartbeat "), "{head}");
            assert!(
                head.contains(&format!("x-raildash-token: {token}\r\n")),
                "{head}"
            );
            match authorization {
                Some(value) => assert!(
                    head.contains(&format!("authorization: {value}\r\n")),
                    "{head}"
                ),
                None => assert!(!head.contains("authorization"), "{head}"),
            }
            let body: Value = serde_json::from_str(body).unwrap();
            assert_eq!(body["taps_attached"], taps);
            assert_eq!(body["collector_id"], heartbeat.collector_id());
        }
    }

    #[tokio::test]
    async fn an_unreadable_token_file_sends_nothing_and_says_which_variable() {
        let (origin, seen) = fake_receiver(vec![200]);
        let dir = tempfile::tempdir().unwrap();
        let mut heartbeat = Heartbeat::new(
            &origin,
            reqwest::Client::new(),
            RailDashToken::File(dir.path().join("missing")),
            HEARTBEAT_INTERVAL,
        )
        .unwrap();
        heartbeat.send(1, None);
        heartbeat.settle().await;
        assert!(seen.lock().unwrap().is_empty());
        let failure = heartbeat.last_failure.lock().unwrap().clone().unwrap();
        assert!(failure.contains("RAIL_RAILDASH_TOKEN_FILE"), "{failure}");
    }
}

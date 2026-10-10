//! Where interactions go: a JSONL file, a webhook, or both.
//!
//! The webhook batches, because one HTTP POST per captured interaction turns a
//! busy agent into a self-inflicted load test. A batch leaves when it is full
//! or when the flush interval expires, so a quiet agent's last few interactions
//! are not stranded in a buffer waiting for traffic that never comes.

use crate::auth::{Credential, RailDashToken};
use crate::heartbeat::Heartbeat;
use anyhow::{Context, Result};
use serde_json::Value;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

// RailDash accepts 16 MiB per request.  Count the JSON after escaping rather
// than the captured body size: one control byte can become six wire bytes.
// Rail Center also benefits from avoiding an unexpectedly huge batch.
const MAX_WEBHOOK_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_WEBHOOK_STRUCTURE_TOKENS: usize = 2_200_000;
const MAX_WEBHOOK_ITEMS: usize = 1_000;
const WEBHOOK_FLUSH_DEADLINE: Duration = Duration::from_secs(10);

pub struct Sink {
    file: Option<std::fs::File>,
    webhook: Option<Webhook>,
    heartbeat: Option<Heartbeat>,
    written: u64,
    /// Batch metadata Rail Center requires on the envelope.
    session_id: String,
    capture_start: String,
}

struct Webhook {
    url: String,
    client: reqwest::Client,
    batch: Vec<Value>,
    batch_size: usize,
    flush_interval: Duration,
    last_flush: Instant,
    failures: u64,
    credential: Credential,
    raildash_token: Option<RailDashToken>,
}

impl Sink {
    pub fn new(
        output: Option<&Path>,
        webhook: Option<&str>,
        batch_size: usize,
        flush_interval: Duration,
        session_id: &str,
        capture_start: &str,
    ) -> Result<Self> {
        let file = match output {
            Some(path) => {
                if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("creating {}", parent.display()))?;
                }
                Some(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .with_context(|| format!("opening {}", path.display()))?,
                )
            }
            None => None,
        };

        Ok(Self {
            file,
            webhook: webhook.map(|url| Webhook {
                url: url.to_string(),
                // Bounded on purpose. flush() is awaited from inside the
                // capture loop, so an unbounded POST to a hung receiver stalls
                // event reads, the flush timer and shutdown signals, and the
                // probe's stdout pipe then backs up behind it. The Python bounded this
                // at 10s; matching that.
                //
                // Redirects are not followed: reqwest keeps `Authorization`
                // across a same-host redirect even when it downgrades https to
                // http. A 3xx is a failed delivery like any other status.
                client: reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap_or_default(),
                batch: Vec::with_capacity(batch_size.max(1)),
                batch_size: batch_size.max(1),
                flush_interval,
                last_flush: Instant::now(),
                failures: 0,
                credential: Credential::None,
                raildash_token: None,
            }),
            heartbeat: None,
            written: 0,
            session_id: session_id.to_string(),
            capture_start: capture_start.to_string(),
        })
    }

    /// The credential every webhook batch presents (`RAIL_AUTH_MODE`). Without
    /// a webhook there is nothing to present it to.
    pub fn with_credential(mut self, credential: Credential) -> Self {
        if let Some(hook) = self.webhook.as_mut() {
            hook.credential = credential;
        }
        self
    }

    /// RailDash's local write token (DR-184): every webhook batch carries it
    /// in `X-RailDash-Token`, and a heartbeat goes to the webhook's receiver
    /// every `heartbeat_interval` while a tap is attached. `None` changes
    /// nothing; so does a sink without a webhook.
    pub fn with_raildash_token(
        mut self,
        token: Option<RailDashToken>,
        heartbeat_interval: Duration,
    ) -> Result<Self> {
        if let (Some(hook), Some(token)) = (self.webhook.as_mut(), token) {
            self.heartbeat = Some(Heartbeat::new(
                &hook.url,
                hook.client.clone(),
                token.clone(),
                heartbeat_interval,
            )?);
            hook.raildash_token = Some(token);
        }
        Ok(self)
    }

    /// How often the capture loop should call `heartbeat`, `None` when it
    /// should not.
    pub fn heartbeat_interval(&self) -> Option<Duration> {
        self.heartbeat.as_ref().map(Heartbeat::interval)
    }

    /// One heartbeat for `taps_attached` taps, off the capture loop; nothing
    /// with no tap attached or no token.
    pub fn heartbeat(&mut self, taps_attached: usize) {
        if let Some(heartbeat) = self.heartbeat.as_mut() {
            heartbeat.send(taps_attached);
        }
    }

    pub fn heartbeat_settings(&self) -> Option<&Heartbeat> {
        self.heartbeat.as_ref()
    }

    /// True when neither destination is configured — the caller warns rather
    /// than discovering later that a long capture went nowhere.
    pub fn is_silent(&self) -> bool {
        self.file.is_none() && self.webhook.is_none()
    }

    pub async fn emit(&mut self, event: &Value) -> Result<()> {
        if let Some(file) = self.file.as_mut() {
            // One JSON object per line, flushed each time: a capture that is
            // killed should leave every interaction it already reported.
            writeln!(file, "{}", serde_json::to_string(event)?)?;
            file.flush()?;
        }
        self.written += 1;

        if let Some(hook) = self.webhook.as_mut() {
            hook.batch.push(event.clone());
            if hook.batch.len() >= hook.batch_size {
                hook.flush(&self.session_id, &self.capture_start).await;
            }
        }
        Ok(())
    }

    /// Called on the timer, so a partial batch still leaves on a quiet link.
    pub async fn flush_if_due(&mut self) {
        if let Some(hook) = self.webhook.as_mut() {
            if !hook.batch.is_empty() && hook.last_flush.elapsed() >= hook.flush_interval {
                hook.flush(&self.session_id, &self.capture_start).await;
            }
        }
    }

    pub async fn shutdown(&mut self) {
        if let Some(hook) = self.webhook.as_mut() {
            hook.flush(&self.session_id, &self.capture_start).await;
            if hook.failures > 0 {
                log::warn!("{} webhook batch(es) failed to deliver", hook.failures);
            }
        }
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
    }

    pub fn written(&self) -> u64 {
        self.written
    }
}

impl Webhook {
    /// A failed batch is logged and dropped, never retried indefinitely and
    /// never fatal: the collector's job is to observe the agent, and it must
    /// not become the reason the host falls over when the sink is down.
    async fn flush(&mut self, session_id: &str, capture_start: &str) {
        if self.batch.is_empty() {
            return;
        }
        let interactions = std::mem::take(&mut self.batch);
        let batches = split_webhook_batches(
            interactions,
            session_id,
            capture_start,
            MAX_WEBHOOK_PAYLOAD_BYTES,
            MAX_WEBHOOK_STRUCTURE_TOKENS,
            MAX_WEBHOOK_ITEMS,
        );
        let batch_count = batches.len();
        let deadline = tokio::time::Instant::now() + WEBHOOK_FLUSH_DEADLINE;

        // One credential for the whole flush, inside the same deadline. One
        // that cannot be produced drops the batches rather than sending them
        // anonymously (RM-F2).
        let authorization = match tokio::time::timeout_at(deadline, self.credential.authorization())
            .await
        {
            Ok(Ok(authorization)) => authorization,
            Ok(Err(error)) => {
                self.failures += batch_count as u64;
                log::warn!(
                    "RAIL_AUTH_MODE={} could not produce a credential; dropping {batch_count} \
                     webhook batch(es) rather than sending them anonymously: {error:#}",
                    self.credential.mode()
                );
                self.last_flush = Instant::now();
                return;
            }
            Err(_) => {
                self.failures += batch_count as u64;
                log::warn!(
                    "RAIL_AUTH_MODE={} credential took over {}s; dropping {batch_count} webhook batch(es)",
                    self.credential.mode(),
                    WEBHOOK_FLUSH_DEADLINE.as_secs()
                );
                self.last_flush = Instant::now();
                return;
            }
        };

        // Read once per flush too, so a rotated file needs no restart. One
        // that can't be read drops the batches, as a credential does: a
        // capture without the token never counts toward a guardrail, and the
        // operator asked for one.
        let raildash_token = match self.raildash_token.as_ref().map(RailDashToken::value) {
            None => None,
            Some(Ok(token)) => Some(token),
            Some(Err(error)) => {
                self.failures += batch_count as u64;
                log::warn!(
                    "RailDash's write token could not be read; dropping {batch_count} webhook \
                     batch(es) rather than sending them without it: {error:#}"
                );
                self.last_flush = Instant::now();
                return;
            }
        };

        for (batch_index, interactions) in batches.into_iter().enumerate() {
            let count = interactions.len();
            let body = webhook_body(interactions, session_id, capture_start);
            if body.len() > MAX_WEBHOOK_PAYLOAD_BYTES {
                // A single interaction cannot be split without changing its
                // meaning. AgentSight's body caps keep normal interactions
                // below this; make an upstream contract violation visible.
                log::warn!(
                    "single webhook interaction is {} bytes (limit {})",
                    body.len(),
                    MAX_WEBHOOK_PAYLOAD_BYTES
                );
            }

            let mut request = self
                .client
                .post(&self.url)
                .header(reqwest::header::CONTENT_TYPE, "application/json");
            if let Some(value) = authorization.as_deref() {
                request = request.header(reqwest::header::AUTHORIZATION, value);
            }
            if let Some(token) = raildash_token.as_deref() {
                request = request.header("X-RailDash-Token", token);
            }
            let request = request.body(body).send();
            match tokio::time::timeout_at(deadline, request).await {
                Ok(Ok(resp)) if resp.status().is_success() => {
                    log::debug!("delivered {count} interaction(s)");
                }
                Ok(Ok(resp)) => {
                    self.failures += 1;
                    log::warn!(
                        "webhook returned {} for {count} interaction(s)",
                        resp.status()
                    );
                }
                Ok(Err(error)) => {
                    self.failures += 1;
                    log::warn!("webhook POST failed for {count} interaction(s): {error}");
                }
                Err(_) => {
                    let dropped = batch_count - batch_index;
                    self.failures += dropped as u64;
                    log::warn!(
                        "webhook flush exceeded {}s; dropping {dropped} remaining batch(es)",
                        WEBHOOK_FLUSH_DEADLINE.as_secs()
                    );
                    break;
                }
            }
        }
        self.last_flush = Instant::now();
    }
}

/// Split on the bytes serde will actually send, including JSON escaping.
fn split_webhook_batches(
    interactions: Vec<Value>,
    session_id: &str,
    capture_start: &str,
    max_bytes: usize,
    max_tokens: usize,
    max_items: usize,
) -> Vec<Vec<Value>> {
    let envelope_bytes = webhook_body(Vec::new(), session_id, capture_start).len();
    let envelope_tokens = value_structure_tokens(&serde_json::json!({
        "session_id": session_id,
        "agent": "railmon",
        "capture_start": capture_start,
        "interactions": [],
    }));
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_bytes = envelope_bytes;
    let mut current_tokens = envelope_tokens;

    for interaction in interactions {
        let item_bytes = serde_json::to_vec(&interaction)
            .expect("serializing a serde_json::Value cannot fail")
            .len();
        let item_tokens = value_structure_tokens(&interaction);
        let comma = usize::from(!current.is_empty());
        if !current.is_empty()
            && (current.len() >= max_items
                || current_bytes + comma + item_bytes > max_bytes
                || current_tokens + comma + item_tokens > max_tokens)
        {
            batches.push(std::mem::take(&mut current));
            current_bytes = envelope_bytes;
            current_tokens = envelope_tokens;
        }
        current_bytes += usize::from(!current.is_empty()) + item_bytes;
        current_tokens += usize::from(!current.is_empty()) + item_tokens;
        current.push(interaction);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// JSON punctuation outside strings, matching RailDash's allocation guard.
fn value_structure_tokens(value: &Value) -> usize {
    let mut tokens = 0;
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Array(items) => {
                tokens += 2 + items.len().saturating_sub(1);
                stack.extend(items);
            }
            Value::Object(map) => {
                // Braces, one colon per member, and commas between members.
                tokens += 2 + map.len() + map.len().saturating_sub(1);
                stack.extend(map.values());
            }
            _ => {}
        }
    }
    tokens
}

fn webhook_body(interactions: Vec<Value>, session_id: &str, capture_start: &str) -> Vec<u8> {
    // Rail Center's POST /v1/interactions takes an envelope —
    // InteractionBatchRequest, with session_id required — not a bare array.
    // RailDash accepts the same envelope for both paired and raw modes.
    serde_json::to_vec(&serde_json::json!({
        "session_id": session_id,
        "agent": "railmon",
        "capture_start": capture_start,
        "interactions": interactions,
    }))
    .expect("serializing a serde_json::Value cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn a_sink_with_no_destination_says_so() {
        let s = Sink::new(
            None,
            None,
            10,
            Duration::from_secs(2),
            "s-1",
            "2026-08-13T00:00:00Z",
        )
        .unwrap();
        assert!(s.is_silent());
    }

    #[tokio::test]
    async fn jsonl_is_one_object_per_line_and_appends() {
        let dir = std::env::temp_dir().join(format!("railmon-test-{}", std::process::id()));
        let path = dir.join("out.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut s = Sink::new(
            Some(&path),
            None,
            10,
            Duration::from_secs(2),
            "s-1",
            "2026-08-13T00:00:00Z",
        )
        .unwrap();
        s.emit(&json!({"interaction_id": "a"})).await.unwrap();
        s.emit(&json!({"interaction_id": "b"})).await.unwrap();
        s.shutdown().await;

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            serde_json::from_str::<Value>(lines[0]).unwrap()["interaction_id"],
            "a"
        );
        assert_eq!(s.written(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_missing_parent_directory_is_created_rather_than_failing_late() {
        let dir = std::env::temp_dir().join(format!("railmon-nested-{}", std::process::id()));
        let path = dir.join("deep").join("out.jsonl");
        let _ = std::fs::remove_dir_all(&dir);

        let mut s = Sink::new(
            Some(&path),
            None,
            10,
            Duration::from_secs(2),
            "s-1",
            "2026-08-13T00:00:00Z",
        )
        .unwrap();
        s.emit(&json!({"ok": true})).await.unwrap();
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn webhook_batches_split_on_serialized_bytes_and_preserve_order() {
        let interactions = vec![
            json!({"id": 1, "body": "\u{0001}".repeat(40)}),
            json!({"id": 2, "body": "\u{0001}".repeat(40)}),
            json!({"id": 3, "body": "\u{0001}".repeat(40)}),
        ];
        let one_item_limit =
            webhook_body(vec![interactions[0].clone()], "s-1", "2026-08-13T00:00:00Z").len();

        let batches = split_webhook_batches(
            interactions,
            "s-1",
            "2026-08-13T00:00:00Z",
            one_item_limit,
            usize::MAX,
            usize::MAX,
        );
        assert_eq!(batches.len(), 3);
        assert_eq!(
            batches
                .iter()
                .flat_map(|batch| batch.iter().map(|item| item["id"].as_u64().unwrap()))
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(batches.into_iter().all(|batch| {
            webhook_body(batch, "s-1", "2026-08-13T00:00:00Z").len() <= one_item_limit
        }));
    }

    #[test]
    fn webhook_batches_also_split_before_raildashs_structure_limit() {
        let interactions = vec![
            json!({"id": 1, "body": [{}, {}, {}]}),
            json!({"id": 2, "body": [{}, {}, {}]}),
        ];
        let one_item_tokens = value_structure_tokens(&serde_json::json!({
            "session_id": "s-1",
            "agent": "railmon",
            "capture_start": "start",
            "interactions": [interactions[0].clone()],
        }));
        let batches = split_webhook_batches(
            interactions,
            "s-1",
            "start",
            usize::MAX,
            one_item_tokens,
            usize::MAX,
        );
        assert_eq!(batches.len(), 2);
        assert!(batches.into_iter().all(|batch| {
            value_structure_tokens(
                &serde_json::from_slice::<Value>(&webhook_body(batch, "s-1", "start")).unwrap(),
            ) <= one_item_tokens
        }));
    }

    #[test]
    fn webhook_batches_never_exceed_raildashs_item_limit() {
        let interactions = (0..1_001).map(|id| json!({"id": id})).collect();
        let batches =
            split_webhook_batches(interactions, "s-1", "start", usize::MAX, usize::MAX, 1_000);
        assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), [1_000, 1]);
    }

    fn webhook_sink(url: &str) -> Sink {
        Sink::new(
            None,
            Some(url),
            1,
            Duration::from_secs(2),
            "s-1",
            "2026-08-13T00:00:00Z",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn without_a_raildash_token_batches_carry_no_header_and_no_heartbeat_goes() {
        let (origin, seen) = crate::heartbeat::tests::fake_receiver(vec![200]);
        let mut s = webhook_sink(&format!("{origin}/webhook/http-interactions"))
            .with_raildash_token(None, Duration::from_secs(60))
            .unwrap();
        assert_eq!(s.heartbeat_interval(), None);
        s.heartbeat(1);
        s.emit(&json!({"id": 1})).await.unwrap();
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .0
                .starts_with("post /webhook/http-interactions "),
            "{}",
            requests[0].0
        );
        assert!(
            !requests[0].0.contains("x-raildash-token"),
            "{}",
            requests[0].0
        );
    }

    #[tokio::test]
    async fn the_raildash_token_rides_beside_the_credential_and_is_reread() {
        let (origin, seen) = crate::heartbeat::tests::fake_receiver(vec![200, 200]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "dash-1\n").unwrap();
        let credential = Credential::from_lookup(|name| match name {
            "RAIL_AUTH_MODE" => Some("bearer".into()),
            "RAIL_AUTH_TOKEN" => Some("rc-1".into()),
            _ => None,
        })
        .unwrap();
        let mut s = webhook_sink(&format!("{origin}/webhook/http-interactions"))
            .with_credential(credential)
            .with_raildash_token(
                Some(RailDashToken::File(path.clone())),
                Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(s.heartbeat_interval(), Some(Duration::from_secs(60)));
        assert_eq!(
            s.heartbeat_settings().map(Heartbeat::url),
            Some(format!("{origin}/webhook/heartbeat").as_str())
        );

        s.emit(&json!({"id": 1})).await.unwrap();
        std::fs::write(&path, "dash-2\n").unwrap();
        s.emit(&json!({"id": 2})).await.unwrap();

        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for ((head, _), token) in requests.iter().zip(["dash-1", "dash-2"]) {
            assert!(
                head.contains(&format!("x-raildash-token: {token}\r\n")),
                "{head}"
            );
            assert!(head.contains("authorization: bearer rc-1\r\n"), "{head}");
        }
    }

    #[tokio::test]
    async fn an_unreadable_raildash_token_drops_the_batch_rather_than_sending_it_bare() {
        let (origin, seen) = crate::heartbeat::tests::fake_receiver(vec![200]);
        let dir = tempfile::tempdir().unwrap();
        let mut s = webhook_sink(&origin)
            .with_raildash_token(
                Some(RailDashToken::File(dir.path().join("missing"))),
                Duration::from_secs(60),
            )
            .unwrap();
        s.emit(&json!({"id": 1})).await.unwrap();
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(s.webhook.as_ref().unwrap().failures, 1);
    }

    #[tokio::test]
    async fn a_token_without_a_webhook_changes_nothing() {
        let s = Sink::new(
            None,
            None,
            10,
            Duration::from_secs(2),
            "s-1",
            "2026-08-13T00:00:00Z",
        )
        .unwrap()
        .with_raildash_token(
            Some(RailDashToken::Value("t".into())),
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(s.heartbeat_interval(), None);
    }
}

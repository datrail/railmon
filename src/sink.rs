//! Where interactions go: a JSONL file, a webhook, or both.
//!
//! The webhook batches, because one HTTP POST per captured interaction turns a
//! busy agent into a self-inflicted load test. A batch leaves when it is full
//! or when the flush interval expires, so a quiet agent's last few interactions
//! are not stranded in a buffer waiting for traffic that never comes.

use anyhow::{Context, Result};
use serde_json::Value;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

pub struct Sink {
    file: Option<std::fs::File>,
    webhook: Option<Webhook>,
    written: u64,
}

struct Webhook {
    url: String,
    client: reqwest::Client,
    batch: Vec<Value>,
    batch_size: usize,
    flush_interval: Duration,
    last_flush: Instant,
    failures: u64,
}

impl Sink {
    pub fn new(
        output: Option<&Path>,
        webhook: Option<&str>,
        batch_size: usize,
        flush_interval: Duration,
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
                client: reqwest::Client::new(),
                batch: Vec::with_capacity(batch_size.max(1)),
                batch_size: batch_size.max(1),
                flush_interval,
                last_flush: Instant::now(),
                failures: 0,
            }),
            written: 0,
        })
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
                hook.flush().await;
            }
        }
        Ok(())
    }

    /// Called on the timer, so a partial batch still leaves on a quiet link.
    pub async fn flush_if_due(&mut self) {
        if let Some(hook) = self.webhook.as_mut() {
            if !hook.batch.is_empty() && hook.last_flush.elapsed() >= hook.flush_interval {
                hook.flush().await;
            }
        }
    }

    pub async fn shutdown(&mut self) {
        if let Some(hook) = self.webhook.as_mut() {
            hook.flush().await;
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
    async fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        let payload = std::mem::take(&mut self.batch);
        let count = payload.len();

        match self.client.post(&self.url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                log::debug!("delivered {count} interaction(s)");
            }
            Ok(resp) => {
                self.failures += 1;
                log::warn!(
                    "webhook returned {} for {count} interaction(s)",
                    resp.status()
                );
            }
            Err(error) => {
                self.failures += 1;
                log::warn!("webhook POST failed for {count} interaction(s): {error}");
            }
        }
        self.last_flush = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn a_sink_with_no_destination_says_so() {
        let s = Sink::new(None, None, 10, Duration::from_secs(2)).unwrap();
        assert!(s.is_silent());
    }

    #[tokio::test]
    async fn jsonl_is_one_object_per_line_and_appends() {
        let dir = std::env::temp_dir().join(format!("railmon-test-{}", std::process::id()));
        let path = dir.join("out.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut s = Sink::new(Some(&path), None, 10, Duration::from_secs(2)).unwrap();
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

        let mut s = Sink::new(Some(&path), None, 10, Duration::from_secs(2)).unwrap();
        s.emit(&json!({"ok": true})).await.unwrap();
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

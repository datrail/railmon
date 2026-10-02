//! The credential the collector presents on its webhook (RM-F2…F5).
//!
//! A deployment lists the modes its control plane accepts
//! (`RAIL_AUTH_MODES_ACCEPTED` on Rail Center) and each component takes one of
//! them in `RAIL_AUTH_MODE`:
//!
//! - `none` (the default) sends nothing, by decision. A token set beside it is
//!   refused: it is an operator who set the credential and not the mode, and
//!   honouring the default would call a control plane anonymously that they
//!   meant to authenticate to.
//! - `bearer` sends `RAIL_AUTH_TOKEN`, or the contents of
//!   `RAIL_AUTH_TOKEN_FILE`. The file is re-read for every batch, so a rotated
//!   secret takes effect without a restart. Setting both is refused rather
//!   than letting one silently win.
//! - `gcp` mints an OIDC identity token for `RAIL_AUTH_AUDIENCE` from the
//!   workload's own service account through the metadata server, and keeps it
//!   only in memory until shortly before it expires. Nothing is stored and
//!   nothing is rotated by hand.
//!
//! **Never anonymous by accident.** The configuration is checked and a first
//! credential produced at startup, so a collector that cannot authenticate
//! stops there instead of running for days delivering nothing. A credential
//! that later cannot be produced (an emptied file, an unreachable metadata
//! server) drops that batch with a warning, like any other failed delivery; it
//! is never sent without one.
//!
//! No message here contains a credential: errors name the variable or the
//! offset, never the value.

use anyhow::{bail, Context, Result};
use base64::Engine;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The modes this collector implements — all of the ones the platform defines.
pub const AUTH_MODES: [&str; 3] = ["none", "bearer", "gcp"];

/// The metadata server's address when `GCE_METADATA_HOST` does not name one.
/// That variable is the one Google's own client libraries honour, which is
/// also what lets a test point the collector at a fake server.
const DEFAULT_METADATA_HOST: &str = "metadata.google.internal";

/// Refresh a minted identity token once less than this much of its life is
/// left. Metadata-server tokens last an hour; a batch POST is bounded at 10s.
const GCP_REFRESH_MARGIN: Duration = Duration::from_secs(300);

pub enum Credential {
    None,
    Bearer(BearerSource),
    Gcp(GcpIdentity),
}

pub enum BearerSource {
    Value(String),
    File(PathBuf),
}

pub struct GcpIdentity {
    audience: String,
    metadata_host: String,
    client: reqwest::Client,
    cached: Option<(String, SystemTime)>,
}

impl Credential {
    /// The credential the environment configures, or a refusal saying why.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let get = |name: &str| {
            lookup(name)
                .map(|v| v.trim().to_string())
                .unwrap_or_default()
        };
        let mode = get("RAIL_AUTH_MODE").to_lowercase();
        let token = get("RAIL_AUTH_TOKEN");
        let token_file = get("RAIL_AUTH_TOKEN_FILE");
        // Empty is not set: `RAIL_AUTH_TOKEN=${TOKEN:-}` is the ordinary shape
        // of a deployment that only sometimes uses a token.
        let token_set = if !token.is_empty() {
            Some("RAIL_AUTH_TOKEN")
        } else if !token_file.is_empty() {
            Some("RAIL_AUTH_TOKEN_FILE")
        } else {
            None
        };

        match mode.as_str() {
            "" | "none" => {
                if let Some(name) = token_set {
                    let configured = if mode.is_empty() {
                        "unset, which is none"
                    } else {
                        "none"
                    };
                    bail!(
                        "RAIL_AUTH_MODE is {configured} and sends no credential, but {name} is set; \
                         set RAIL_AUTH_MODE=bearer to use it, or unset {name} to mean none"
                    );
                }
                Ok(Self::None)
            }
            "bearer" => {
                if !token.is_empty() && !token_file.is_empty() {
                    bail!(
                        "RAIL_AUTH_MODE=bearer takes RAIL_AUTH_TOKEN or RAIL_AUTH_TOKEN_FILE, \
                         and both are set; unset one"
                    );
                }
                if !token_file.is_empty() {
                    return Ok(Self::Bearer(BearerSource::File(PathBuf::from(token_file))));
                }
                if token.is_empty() {
                    bail!("RAIL_AUTH_MODE=bearer requires RAIL_AUTH_TOKEN or RAIL_AUTH_TOKEN_FILE");
                }
                Ok(Self::Bearer(BearerSource::Value(header_safe(
                    &token,
                    "RAIL_AUTH_TOKEN",
                )?)))
            }
            "gcp" => {
                if let Some(name) = token_set {
                    bail!(
                        "RAIL_AUTH_MODE=gcp mints its own credential, but {name} is set; \
                         unset it, or set RAIL_AUTH_MODE=bearer to use it"
                    );
                }
                let audience = get("RAIL_AUTH_AUDIENCE");
                if audience.is_empty() {
                    bail!("RAIL_AUTH_MODE=gcp requires RAIL_AUTH_AUDIENCE");
                }
                let metadata_host = Some(get("GCE_METADATA_HOST"))
                    .filter(|h| !h.is_empty())
                    .unwrap_or_else(|| DEFAULT_METADATA_HOST.to_string());
                Ok(Self::Gcp(GcpIdentity {
                    audience,
                    metadata_host,
                    client: reqwest::Client::builder()
                        .timeout(Duration::from_secs(10))
                        .build()
                        .unwrap_or_default(),
                    cached: None,
                }))
            }
            other => bail!(
                "RAIL_AUTH_MODE must be one of {}, got: {other}",
                AUTH_MODES.join(", ")
            ),
        }
    }

    pub fn mode(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bearer(_) => "bearer",
            Self::Gcp(_) => "gcp",
        }
    }

    /// The `Authorization` header value to send, `None` for mode `none`.
    pub async fn authorization(&mut self) -> Result<Option<String>> {
        match self {
            Self::None => Ok(None),
            Self::Bearer(BearerSource::Value(token)) => Ok(Some(format!("Bearer {token}"))),
            Self::Bearer(BearerSource::File(path)) => {
                let raw = std::fs::read_to_string(&*path)
                    .with_context(|| format!("reading RAIL_AUTH_TOKEN_FILE {}", path.display()))?;
                Ok(Some(format!(
                    "Bearer {}",
                    header_safe(&raw, "RAIL_AUTH_TOKEN_FILE")?
                )))
            }
            Self::Gcp(identity) => Ok(Some(format!("Bearer {}", identity.token().await?))),
        }
    }
}

impl GcpIdentity {
    async fn token(&mut self) -> Result<String> {
        if let Some((token, expires)) = &self.cached {
            if SystemTime::now() + GCP_REFRESH_MARGIN < *expires {
                return Ok(token.clone());
            }
        }
        let url = format!(
            "http://{}/computeMetadata/v1/instance/service-accounts/default/identity",
            self.metadata_host
        );
        let response = self
            .client
            .get(&url)
            .query(&[("audience", self.audience.as_str())])
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .with_context(|| {
                format!(
                    "RAIL_AUTH_MODE=gcp: minting an identity token from the metadata server at {}",
                    self.metadata_host
                )
            })?;
        let status = response.status();
        if !status.is_success() {
            bail!(
                "RAIL_AUTH_MODE=gcp: the metadata server at {} returned {status} for an identity token",
                self.metadata_host
            );
        }
        let body = response
            .text()
            .await
            .context("RAIL_AUTH_MODE=gcp: reading the minted identity token")?;
        let token = header_safe(&body, "the metadata server's identity token")?;
        // An expiry we cannot read is not cached: minting per batch is slower
        // but never presents a token past its life.
        match jwt_expiry(&token) {
            Some(expires) => self.cached = Some((token.clone(), expires)),
            None => self.cached = None,
        }
        Ok(token)
    }
}

/// `raw` trimmed, or a refusal naming `name` and the offending offset.
///
/// Trailing whitespace is stripped because every ordinary way of writing a
/// secret into a file leaves a newline behind. Anything outside RFC 7230's
/// %x21–7E inside the value cannot go in a header; refusing it here keeps the
/// HTTP client from quoting the header, and so the secret, in its error.
fn header_safe(raw: &str, name: &str) -> Result<String> {
    let value = raw.trim();
    if value.is_empty() {
        bail!("{name} is empty");
    }
    if let Some((offset, ch)) = value
        .char_indices()
        .find(|(_, c)| !('\x21'..='\x7e').contains(c))
    {
        bail!(
            "{name} holds U+{:04X} at offset {offset}, which cannot go in a header value",
            ch as u32
        );
    }
    Ok(value.to_string())
}

/// The `exp` claim of a JWT, without verifying it — the token is ours, fresh
/// from the metadata server, and only its lifetime is wanted here.
fn jwt_expiry(token: &str) -> Option<SystemTime> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let exp = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("exp")?
        .as_u64()?;
    Some(UNIX_EPOCH + Duration::from_secs(exp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn from(vars: &[(&str, &str)]) -> Result<Credential> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Credential::from_lookup(|name| map.get(name).cloned())
    }

    fn refusal(vars: &[(&str, &str)]) -> String {
        match from(vars) {
            Ok(c) => panic!("expected a refusal, got mode {}", c.mode()),
            Err(e) => format!("{e:#}"),
        }
    }

    #[tokio::test]
    async fn unset_and_none_send_nothing() {
        for vars in [
            &[][..],
            &[("RAIL_AUTH_MODE", "none")][..],
            &[("RAIL_AUTH_MODE", " NONE ")][..],
        ] {
            let mut c = from(vars).unwrap();
            assert_eq!(c.mode(), "none");
            assert_eq!(c.authorization().await.unwrap(), None);
        }
        // An empty token is the `${TOKEN:-}` shape, not a token.
        assert_eq!(from(&[("RAIL_AUTH_TOKEN", "")]).unwrap().mode(), "none");
    }

    #[test]
    fn a_token_beside_none_is_refused_without_quoting_it() {
        let message = refusal(&[("RAIL_AUTH_TOKEN", "s3cret")]);
        assert!(message.contains("unset, which is none"), "{message}");
        assert!(!message.contains("s3cret"), "{message}");
        let message = refusal(&[
            ("RAIL_AUTH_MODE", "none"),
            ("RAIL_AUTH_TOKEN_FILE", "/run/t"),
        ]);
        assert!(message.contains("RAIL_AUTH_TOKEN_FILE is set"), "{message}");
    }

    #[test]
    fn an_unknown_mode_is_refused() {
        let message = refusal(&[("RAIL_AUTH_MODE", "basic")]);
        assert!(message.contains("none, bearer, gcp"), "{message}");
    }

    #[tokio::test]
    async fn bearer_presents_the_environment_token() {
        let mut c = from(&[("RAIL_AUTH_MODE", "bearer"), ("RAIL_AUTH_TOKEN", " t-1\n")]).unwrap();
        assert_eq!(
            c.authorization().await.unwrap().as_deref(),
            Some("Bearer t-1")
        );
    }

    #[test]
    fn bearer_without_a_token_or_with_both_forms_is_refused() {
        assert!(refusal(&[("RAIL_AUTH_MODE", "bearer")]).contains("requires RAIL_AUTH_TOKEN"));
        assert!(refusal(&[
            ("RAIL_AUTH_MODE", "bearer"),
            ("RAIL_AUTH_TOKEN", "a"),
            ("RAIL_AUTH_TOKEN_FILE", "/run/t"),
        ])
        .contains("both are set"));
    }

    #[test]
    fn a_token_that_cannot_go_in_a_header_is_refused_by_offset() {
        let message = refusal(&[("RAIL_AUTH_MODE", "bearer"), ("RAIL_AUTH_TOKEN", "ab\ncd")]);
        assert!(message.contains("U+000A at offset 2"), "{message}");
        assert!(!message.contains("ab"), "{message}");
    }

    #[tokio::test]
    async fn the_token_file_is_reread_so_rotation_needs_no_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "first\n").unwrap();
        let mut c = from(&[
            ("RAIL_AUTH_MODE", "bearer"),
            ("RAIL_AUTH_TOKEN_FILE", path.to_str().unwrap()),
        ])
        .unwrap();
        assert_eq!(
            c.authorization().await.unwrap().as_deref(),
            Some("Bearer first")
        );
        std::fs::write(&path, "second\n").unwrap();
        assert_eq!(
            c.authorization().await.unwrap().as_deref(),
            Some("Bearer second")
        );

        // Emptied or gone: an error, never an anonymous request.
        std::fs::write(&path, "\n").unwrap();
        assert!(c.authorization().await.is_err());
        std::fs::remove_file(&path).unwrap();
        let message = format!("{:#}", c.authorization().await.unwrap_err());
        assert!(message.contains("RAIL_AUTH_TOKEN_FILE"), "{message}");
    }

    #[test]
    fn gcp_needs_an_audience_and_no_static_token() {
        assert!(refusal(&[("RAIL_AUTH_MODE", "gcp")]).contains("RAIL_AUTH_AUDIENCE"));
        assert!(refusal(&[
            ("RAIL_AUTH_MODE", "gcp"),
            ("RAIL_AUTH_AUDIENCE", "https://rc.example"),
            ("RAIL_AUTH_TOKEN", "t"),
        ])
        .contains("mints its own credential"));
    }

    fn jwt(exp: u64) -> String {
        let enc = |v: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        format!(
            "{}.{}.sig",
            enc(r#"{"alg":"RS256"}"#),
            enc(&format!(r#"{{"exp":{exp}}}"#))
        )
    }

    /// A metadata server that answers each request with the next of `tokens`
    /// and records the request line and headers it saw.
    fn fake_metadata(tokens: Vec<(u16, String)>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for (status, body) in tokens {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    request.push_str(&line);
                }
                log.lock().unwrap().push(request);
                write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        (host, seen)
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn gcp_mints_for_the_audience_and_reuses_a_fresh_token() {
        let fresh = jwt(now() + 3600);
        let (host, seen) = fake_metadata(vec![(200, fresh.clone())]);
        let mut c = from(&[
            ("RAIL_AUTH_MODE", "gcp"),
            ("RAIL_AUTH_AUDIENCE", "https://rc.example/api"),
            ("GCE_METADATA_HOST", &host),
        ])
        .unwrap();
        let expected = format!("Bearer {fresh}");
        assert_eq!(
            c.authorization().await.unwrap().as_deref(),
            Some(expected.as_str())
        );
        // The fake answers once; a second mint would fail to connect.
        assert_eq!(
            c.authorization().await.unwrap().as_deref(),
            Some(expected.as_str())
        );

        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = requests[0].to_lowercase();
        assert!(request.starts_with(
            "get /computemetadata/v1/instance/service-accounts/default/identity?audience=https%3a%2f%2frc.example%2fapi "
        ), "{request}");
        assert!(request.contains("metadata-flavor: google"), "{request}");
    }

    #[tokio::test]
    async fn gcp_mints_again_once_the_token_is_near_expiry() {
        let stale = jwt(now() + 60);
        let fresh = jwt(now() + 3600);
        let (host, seen) = fake_metadata(vec![(200, stale.clone()), (200, fresh.clone())]);
        let mut c = from(&[
            ("RAIL_AUTH_MODE", "gcp"),
            ("RAIL_AUTH_AUDIENCE", "aud"),
            ("GCE_METADATA_HOST", &host),
        ])
        .unwrap();
        assert_eq!(
            c.authorization().await.unwrap(),
            Some(format!("Bearer {stale}"))
        );
        assert_eq!(
            c.authorization().await.unwrap(),
            Some(format!("Bearer {fresh}"))
        );
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn gcp_fails_rather_than_going_anonymous() {
        let (host, _) = fake_metadata(vec![(404, "no service account".into())]);
        let mut c = from(&[
            ("RAIL_AUTH_MODE", "gcp"),
            ("RAIL_AUTH_AUDIENCE", "aud"),
            ("GCE_METADATA_HOST", &host),
        ])
        .unwrap();
        let message = format!("{:#}", c.authorization().await.unwrap_err());
        assert!(message.contains("404"), "{message}");
    }

    #[test]
    fn jwt_expiry_reads_exp_and_tolerates_garbage() {
        assert_eq!(
            jwt_expiry(&jwt(1_900_000_000)),
            Some(UNIX_EPOCH + Duration::from_secs(1_900_000_000))
        );
        assert_eq!(jwt_expiry("not-a-jwt"), None);
        assert_eq!(jwt_expiry("a.!!!.c"), None);
    }
}

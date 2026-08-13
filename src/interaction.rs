//! Rail Center `RuntimeInteraction` formatting.
//!
//! A direct port of `collector/runtime_interaction.py`, kept faithful on
//! purpose: `interaction_id` is a hash of a canonical JSON seed, so any
//! difference in key order, separators or null handling silently changes every
//! id and breaks correlation against interactions already stored. The tests at
//! the bottom pin the two values that travel — the id and the agent_id.

use base64::Engine as _;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// Convert RailMon's legacy HTTP interaction into the Rail Center schema.
pub fn to_runtime_interaction(
    interaction: &Value,
    session_id: Option<&str>,
    capture_start: Option<&str>,
    capture_source: &str,
) -> Value {
    let request = interaction.get("request").filter(|v| v.is_object());
    let response = interaction.get("response").filter(|v| v.is_object());

    let method = request
        .and_then(|r| r.get("method"))
        .and_then(Value::as_str)
        .map(|s| s.to_uppercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "UNKNOWN".to_string());

    let (path, destination) = path_and_destination(request);
    let x_rail_header = header(request, "x-rail");
    let agent_id = agent_id_from_x_rail(x_rail_header.as_deref());
    let status = response.and_then(|r| r.get("status_code")).cloned();

    // `raw` carries the original interaction plus the session markers, exactly
    // as the Python does — Rail Center stores it verbatim.
    let mut raw = interaction.clone();
    if let Some(obj) = raw.as_object_mut() {
        obj.insert("railmon_session_id".into(), opt_str(session_id));
        obj.insert("railmon_capture_start".into(), opt_str(capture_start));
    }

    json!({
        "interaction_id": interaction_id(interaction, session_id, &method, &path, &destination, status.as_ref()),
        "agent_id": opt_string(agent_id),
        "x_rail_header": opt_string(x_rail_header),
        "timestamp": timestamp(interaction),
        "request": { "method": method, "path": path, "destination": destination },
        "response": { "status": status_code(status.as_ref()) },
        "latency_ms": latency_ms(interaction.get("latency_ms")),
        "capture_source": capture_source,
        "raw": raw,
    })
}

fn opt_str(v: Option<&str>) -> Value {
    v.map(|s| Value::String(s.to_string()))
        .unwrap_or(Value::Null)
}

fn opt_string(v: Option<String>) -> Value {
    v.map(Value::String).unwrap_or(Value::Null)
}

fn path_and_destination(request: Option<&Value>) -> (String, String) {
    let raw_path = request
        .and_then(|r| r.get("path"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string();

    // Only an absolute-form target supplies its own authority, and only when
    // the scheme is at the very start. Scanning for "://" anywhere lets the
    // monitored process choose what gets recorded: an ordinary OAuth
    // `?redirect_uri=https://evil.com/x` would otherwise be logged as a call to
    // evil.com. Python's urlsplit requires the leading scheme; so does this.
    if let Some((scheme, after)) = raw_path.split_once("://") {
        let is_scheme = !scheme.is_empty()
            && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if is_scheme && !after.is_empty() {
            let (netloc, rest) = match after.find(['/', '?', '#']) {
                Some(i) => (&after[..i], &after[i..]),
                None => (after, ""),
            };
            if !netloc.is_empty() {
                // urlsplit yields an empty path for `https://host?q=1`, and
                // the Python then substitutes "/" before re-attaching the
                // query — so the result is "/?q=1", not "?q=1".
                let rest_no_frag = rest.split('#').next().unwrap_or("");
                let path = if rest_no_frag.is_empty() {
                    "/".to_string()
                } else if let Some(query) = rest_no_frag.strip_prefix('?') {
                    format!("/?{query}")
                } else {
                    rest_no_frag.to_string()
                };
                return (path, netloc.to_string());
            }
        }
    }

    let destination = header(request, "host")
        .or_else(|| header(request, ":authority"))
        .unwrap_or_else(|| "unknown".to_string());
    (raw_path, destination)
}

/// Case-insensitive header lookup that skips empty values, matching the Python.
fn header(request: Option<&Value>, name: &str) -> Option<String> {
    let headers = request?.get("headers")?.as_object()?;
    let wanted = name.to_ascii_lowercase();
    for (key, value) in headers {
        if key.to_ascii_lowercase() == wanted {
            let text = match value {
                Value::Null => continue,
                Value::String(s) if s.is_empty() => continue,
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            return Some(text);
        }
    }
    None
}

/// The x-rail ticket is base64url JSON. Anything that does not decode to an
/// object carrying a real UUID yields no agent_id rather than a guess — an
/// interaction attributed to the wrong agent is worse than one attributed to
/// none.
fn agent_id_from_x_rail(x_rail: Option<&str>) -> Option<String> {
    let token = x_rail?.trim();
    if token.is_empty() {
        return None;
    }
    let mut padded = token.to_string();
    padded.push_str(&"=".repeat((4 - token.len() % 4) % 4));

    let decoded = base64::engine::general_purpose::URL_SAFE
        .decode(padded.as_bytes())
        .ok()?;
    let payload: Value = serde_json::from_slice(&decoded).ok()?;
    let candidate = payload.get("agent_id")?;
    let text = candidate
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| candidate.to_string());
    uuid::Uuid::parse_str(&text).ok().map(|u| u.to_string())
}

/// sha256 over a canonical JSON seed. `serde_json::Map` is a BTreeMap, so keys
/// are sorted and the encoding is compact, matching Python's
/// `sort_keys=True, separators=(",",":")`.
///
/// The seed is then escaped to pure ASCII, because Python's `json.dumps`
/// defaults to `ensure_ascii=True` and serde_json emits raw UTF-8. Without
/// that step a session id or path containing any non-ASCII character hashes
/// differently in the two implementations — `session_id="café"` gives Python
/// `12d2a3bc…` and raw UTF-8 `3ac5f451…` — and the ids silently stop
/// correlating for exactly the agents whose traffic is not plain ASCII.
fn interaction_id(
    interaction: &Value,
    session_id: Option<&str>,
    method: &str,
    path: &str,
    destination: &str,
    status: Option<&Value>,
) -> String {
    let mut seed = Map::new();
    seed.insert("session_id".into(), opt_str(session_id));
    seed.insert("timestamp_ns".into(), field(interaction, "timestamp_ns"));
    seed.insert("timestamp".into(), field(interaction, "timestamp"));
    seed.insert("pid".into(), field(interaction, "pid"));
    seed.insert("tid".into(), field(interaction, "tid"));
    seed.insert("method".into(), Value::String(method.to_string()));
    seed.insert("path".into(), Value::String(path.to_string()));
    seed.insert("destination".into(), Value::String(destination.to_string()));
    seed.insert("status".into(), status.cloned().unwrap_or(Value::Null));
    seed.insert("request_size".into(), field(interaction, "request_size"));
    seed.insert("response_size".into(), field(interaction, "response_size"));

    let encoded = serde_json::to_string(&Value::Object(seed)).unwrap_or_default();
    let digest = Sha256::digest(ensure_ascii(&encoded).as_bytes());
    format!("railmon-{}", &hex(&digest)[..40])
}

/// Escape every non-ASCII character as `\uXXXX`, the way Python's
/// `json.dumps(..., ensure_ascii=True)` does. Characters outside the basic
/// multilingual plane become a surrogate pair, which is also what Python emits.
fn ensure_ascii(encoded: &str) -> String {
    if encoded.is_ascii() {
        return encoded.to_string();
    }
    let mut out = String::with_capacity(encoded.len());
    for ch in encoded.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            let mut buf = [0u16; 2];
            for unit in ch.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

fn field(interaction: &Value, key: &str) -> Value {
    interaction.get(key).cloned().unwrap_or(Value::Null)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn timestamp(interaction: &Value) -> Value {
    match interaction.get("timestamp").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Value::String(s.to_string()),
        _ => Value::String(chrono::Utc::now().to_rfc3339()),
    }
}

fn status_code(value: Option<&Value>) -> Value {
    match value {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Number(n)) => n.as_i64().map(Value::from).unwrap_or(Value::Null),
        Some(Value::String(s)) => s
            .trim()
            .parse::<i64>()
            .map(Value::from)
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

fn latency_ms(value: Option<&Value>) -> Value {
    match value {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Number(n)) => n.as_f64().map(Value::from).unwrap_or(Value::Null),
        Some(Value::String(s)) => s
            .trim()
            .parse::<f64>()
            .map(Value::from)
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        json!({
            "timestamp": "2026-08-12T00:00:00+00:00",
            "timestamp_ns": 1_723_000_000_000_000_000u64,
            "pid": 4242,
            "tid": 4243,
            "request_size": 120,
            "response_size": 340,
            "latency_ms": 12.5,
            "request": {
                "method": "post",
                "path": "/v1/messages",
                "headers": {"Host": "api.anthropic.com", "X-Rail": ""}
            },
            "response": {"status_code": 200}
        })
    }

    #[test]
    fn method_is_upcased_and_destination_comes_from_host() {
        let out = to_runtime_interaction(&sample(), Some("s-1"), None, "railmon");
        assert_eq!(out["request"]["method"], "POST");
        assert_eq!(out["request"]["destination"], "api.anthropic.com");
        assert_eq!(out["request"]["path"], "/v1/messages");
        assert_eq!(out["response"]["status"], 200);
    }

    #[test]
    fn a_scheme_inside_a_query_cannot_choose_the_destination() {
        // The monitored process must not get to pick what we record. Values
        // taken from the Python: an OAuth redirect_uri leaves both fields alone.
        for (path, want_path, want_dest) in [
            (
                "/oauth/callback?redirect=https://evil.com/x",
                "/oauth/callback?redirect=https://evil.com/x",
                "api.anthropic.com",
            ),
            ("/a?b=c://d", "/a?b=c://d", "api.anthropic.com"),
        ] {
            let mut v = sample();
            v["request"]["path"] = json!(path);
            let out = to_runtime_interaction(&v, None, None, "railmon");
            assert_eq!(out["request"]["path"], want_path, "path for {path}");
            assert_eq!(out["request"]["destination"], want_dest, "dest for {path}");
        }
    }

    #[test]
    fn an_absolute_target_with_only_a_query_keeps_the_root_path() {
        let mut v = sample();
        v["request"]["path"] = json!("https://host?q=1");
        let out = to_runtime_interaction(&v, None, None, "railmon");
        assert_eq!(out["request"]["path"], "/?q=1");
        assert_eq!(out["request"]["destination"], "host");
    }

    #[test]
    fn the_id_matches_python_for_non_ascii_input() {
        // Values produced by the deleted runtime_interaction.py.
        for (sid, want) in [
            ("café", "railmon-7cf76655dbf2293397a04a1f4775d6d24e20c5ed"),
            ("日本語", "railmon-7829b954cc702eaf0f61be82ea46104067843a6b"),
        ] {
            let out = to_runtime_interaction(&sample(), Some(sid), None, "railmon");
            assert_eq!(out["interaction_id"], want, "session {sid}");
        }
    }

    #[test]
    fn an_absolute_target_supplies_its_own_authority() {
        let mut v = sample();
        v["request"]["path"] = json!("https://proxy.internal/v1/messages?beta=true");
        let out = to_runtime_interaction(&v, None, None, "railmon");
        assert_eq!(out["request"]["destination"], "proxy.internal");
        assert_eq!(out["request"]["path"], "/v1/messages?beta=true");
    }

    #[test]
    fn missing_host_is_unknown_rather_than_invented() {
        let mut v = sample();
        v["request"]["headers"] = json!({});
        let out = to_runtime_interaction(&v, None, None, "railmon");
        assert_eq!(out["request"]["destination"], "unknown");
    }

    #[test]
    fn agent_id_is_read_from_the_x_rail_ticket() {
        // base64url of {"agent_id": "550e8400-e29b-41d4-a716-446655440000"}
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"agent_id": "550e8400-e29b-41d4-a716-446655440000"}"#);
        let mut v = sample();
        v["request"]["headers"] = json!({"x-rail": token});
        let out = to_runtime_interaction(&v, None, None, "railmon");
        assert_eq!(out["agent_id"], "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn a_ticket_that_is_not_a_uuid_yields_no_agent_id() {
        let token =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"agent_id": "nope"}"#);
        let mut v = sample();
        v["request"]["headers"] = json!({"x-rail": token});
        let out = to_runtime_interaction(&v, None, None, "railmon");
        assert_eq!(out["agent_id"], Value::Null);
        assert_eq!(out["x_rail_header"], token);
    }

    #[test]
    fn garbage_in_the_header_does_not_panic() {
        for bad in ["!!!!", "", "   ", "e30", "bm90LWpzb24"] {
            let mut v = sample();
            v["request"]["headers"] = json!({"x-rail": bad});
            let out = to_runtime_interaction(&v, None, None, "railmon");
            assert_eq!(out["agent_id"], Value::Null, "input {bad:?}");
        }
    }

    #[test]
    fn the_id_matches_the_python_implementation_exactly() {
        // Not "some stable hash" — this literal is what
        // collector/runtime_interaction.py produced for `sample()` before the
        // port. The id is a content hash, so any drift in key order, separators
        // or null handling changes it, and interactions already stored in Rail
        // Center stop correlating with newly captured ones. If this assertion
        // fails, the seed encoding changed, not the test.
        let out = to_runtime_interaction(&sample(), Some("s-1"), None, "railmon");
        assert_eq!(
            out["interaction_id"],
            "railmon-86dc4343226e41845f18cd3befbcf37026b5fc86"
        );
    }

    #[test]
    fn the_id_changes_with_the_session() {
        let a = to_runtime_interaction(&sample(), Some("s-1"), None, "railmon");
        let b = to_runtime_interaction(&sample(), Some("s-2"), None, "railmon");
        assert_ne!(a["interaction_id"], b["interaction_id"]);
    }

    #[test]
    fn session_markers_are_attached_to_raw() {
        let out = to_runtime_interaction(
            &sample(),
            Some("s-1"),
            Some("2026-08-12T00:00:00Z"),
            "railmon",
        );
        assert_eq!(out["raw"]["railmon_session_id"], "s-1");
        assert_eq!(out["raw"]["railmon_capture_start"], "2026-08-12T00:00:00Z");
    }
}

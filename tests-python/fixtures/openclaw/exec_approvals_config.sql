-- exec_approvals_config as OpenClaw 2026.9.2 (3928bad) creates it in state/openclaw.sqlite,
-- after `openclaw exec-policy preset cautious`; see README.md. raw_json carries a placeholder
-- socket token in place of a real one.
CREATE TABLE exec_approvals_config (
  config_key TEXT NOT NULL PRIMARY KEY,
  raw_json TEXT NOT NULL,
  socket_path TEXT,
  has_socket_token INTEGER NOT NULL,
  default_security TEXT,
  default_ask TEXT,
  default_ask_fallback TEXT,
  auto_allow_skills INTEGER,
  agent_count INTEGER NOT NULL,
  allowlist_count INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
) STRICT;
INSERT INTO exec_approvals_config (config_key, raw_json, socket_path, has_socket_token, default_security, default_ask, default_ask_fallback, auto_allow_skills, agent_count, allowlist_count, updated_at_ms) VALUES ('current', '{"version":1,"socket":{"path":"/root/.openclaw/state/approvals.sock","token":"socket-token-placeholder"},"defaults":{"security":"allowlist","ask":"on-miss","askFallback":"deny"},"agents":{}}', NULL, 1, 'allowlist', 'on-miss', 'deny', NULL, 0, 0, 1794604721282);

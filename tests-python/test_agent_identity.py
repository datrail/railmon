"""Tests for the identity, secrets and ticket-handling rules of DR-8.

Stdlib only, to match the scanner itself — `make test` runs this with no
dependencies to install.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "tools" / "agent-environment-scanner" / "scan_agent_environment.py"

_spec = importlib.util.spec_from_file_location("scan_agent_environment", SCANNER)
scanner = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(scanner)

# Rail configuration in the developer's own shell is inherited by every
# subprocess test below, and it changes what the scanner does: RAIL_AUTH_MODE
# alone makes a registration fail before the network is ever touched, so a test
# named for the connection-refused path would pass without reaching it.
SCANNER_ENV_KEYS = (
    "RAIL_HOST_ID",
    "RAIL_AUTH_MODE",
    "RAIL_AUTH_TOKEN",
    "RAIL_CENTER_URL",
    "RAIL_FEATURE_OUTPUT",
    "RAIL_REGISTRATION_OUTPUT",
)


def clean_env(**overrides: str) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key not in SCANNER_ENV_KEYS}
    env.update(overrides)
    return env


def context(**overrides):
    base = {
        "mode": "docker",
        "env": {},
        "hostname": "host-from-hostname",
        "image": "img",
        "container_name": "agent-container",
        "container_id": "cid",
        "proc1_cmdline": "",
        "docker_inspect": {},
    }
    base.update(overrides)
    return base


class SandboxNameTest(unittest.TestCase):
    def test_label_wins_over_container_name(self):
        ctx = context(docker_inspect={"Config": {"Labels": {"rail.sandbox_name": "labelled"}}})
        self.assertEqual(scanner.detect_sandbox_name(ctx), ("labelled", "label"))

    def test_falls_back_to_container_name(self):
        self.assertEqual(scanner.detect_sandbox_name(context()), ("agent-container", "container_name"))

    def test_unmanaged_agent_still_gets_a_name(self):
        """An agent nobody onboarded has no label and no Rail config — it still needs a name."""
        ctx = context(container_name=None, docker_inspect={})
        self.assertEqual(scanner.detect_sandbox_name(ctx), ("host-from-hostname", "hostname"))

    def test_never_read_from_an_injected_env_var(self):
        ctx = context(
            container_name=None,
            hostname=None,
            env={"RAIL_SANDBOX_NAME": "injected", "SANDBOX_NAME": "injected"},
        )
        self.assertEqual(scanner.detect_sandbox_name(ctx), (None, "unset"))

    def test_truncated_to_the_storage_width(self):
        ctx = context(container_name="x" * 400)
        name, _ = scanner.detect_sandbox_name(ctx)
        self.assertEqual(len(name), scanner.SANDBOX_NAME_MAX)

    def test_a_blank_flag_is_not_a_name(self):
        self.assertEqual(scanner.detect_sandbox_name(context(), "  "), ("agent-container", "container_name"))


class HostIdTest(unittest.TestCase):
    def setUp(self):
        for key in scanner.HOST_ID_KEYS:
            os.environ.pop(key, None)

    def test_read_from_rail_host_id(self):
        os.environ["RAIL_HOST_ID"] = "h-1"
        self.addCleanup(os.environ.pop, "RAIL_HOST_ID", None)
        self.assertEqual(scanner.detect_host_id(context()), ("h-1", "env"))

    def test_no_invented_fallback(self):
        """A locally derived id would disagree with the other components on the host."""
        self.assertEqual(scanner.detect_host_id(context()), (None, "unset"))

    def test_explicit_flag_wins(self):
        ctx = context(env={"RAIL_HOST_ID": "h-1"})
        self.assertEqual(scanner.detect_host_id(ctx, "h-2"), ("h-2", "flag"))

    def test_a_blank_flag_is_not_a_value(self):
        ctx = context(env={"RAIL_HOST_ID": "h-1"})
        self.assertEqual(scanner.detect_host_id(ctx, "   "), ("h-1", "container_env"))

    def test_truncated_to_the_storage_width(self):
        host_id, _ = scanner.detect_host_id(context(env={"RAIL_HOST_ID": "h" * 200}))
        self.assertEqual(len(host_id), scanner.HOST_ID_MAX)

    def test_the_scanned_container_cannot_relabel_its_host(self):
        """In docker mode the container's env is the subject of the scan, not a
        source of truth about the host every other Rail component shares."""
        os.environ["RAIL_HOST_ID"] = "real-host"
        self.addCleanup(os.environ.pop, "RAIL_HOST_ID", None)
        ctx = context(env={"RAIL_HOST_ID": "spoofed-host"})
        self.assertEqual(scanner.detect_host_id(ctx), ("real-host", "env"))

    def test_an_onboarded_container_still_supplies_one(self):
        ctx = context(env={"RAIL_HOST_ID": "h-1"})
        self.assertEqual(scanner.detect_host_id(ctx), ("h-1", "container_env"))


class SecretHygieneTest(unittest.TestCase):
    def test_classifies_without_recording_a_value(self):
        env = {
            "OPENAI_API_KEY": "sk-supersecret",
            "VAULT_TOKEN": "projects/p/secrets/s/versions/1",
            "TLS_KEY": "/etc/ssl/private/agent.pem",
            "HOME": "/root",
        }
        entries = scanner.collect_secret_hygiene(env)
        by_key = {entry["key"]: entry for entry in entries}

        self.assertNotIn("HOME", by_key)
        self.assertEqual(by_key["OPENAI_API_KEY"]["secret_class"], "plaintext")
        self.assertEqual(by_key["OPENAI_API_KEY"]["secret_type"], "api_key")
        self.assertEqual(by_key["VAULT_TOKEN"]["secret_class"], "reference")
        self.assertIn(by_key["TLS_KEY"]["secret_class"], ("mount", "reference"))

        serialized = repr(entries)
        for value in env.values():
            self.assertNotIn(value, serialized)


class BaseUrlTest(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(scanner.classify_base_url("https://api.anthropic.com"), "canonical")
        self.assertEqual(scanner.classify_base_url("https://api.anthropic.com/v1"), "canonical")
        self.assertEqual(scanner.classify_base_url("http://localhost:11434/v1"), "local")
        self.assertEqual(scanner.classify_base_url("https://proxy.example.com/v1"), "unknown_proxy")
        self.assertEqual(scanner.classify_base_url(None), "unset")

    def test_a_lookalike_host_is_not_canonical(self):
        """Substring matching would call this canonical and silence the signal."""
        self.assertEqual(
            scanner.classify_base_url("https://evil-api.anthropic.com.attacker.net/v1"),
            "unknown_proxy",
        )

    def test_a_real_subdomain_is_canonical(self):
        self.assertEqual(scanner.classify_base_url("https://eu.api.openai.com/v1"), "canonical")

    def test_a_lookalike_local_host_is_not_local(self):
        """`ollama` and `localhost` appear inside plenty of hostile hostnames."""
        for url in (
            "https://ollama.attacker.net/v1",
            "https://prompt-proxy-llama.attacker.net/v1",
            "https://notlocalhost.attacker.net/v1",
            "https://api.anthropic.com.llama-mask.attacker.net/v1",
        ):
            self.assertEqual(scanner.classify_base_url(url), "unknown_proxy", url)

    def test_real_local_hosts_still_classify_as_local(self):
        for url in ("http://localhost:11434/v1", "http://ollama:11434", "http://127.0.0.1:8080"):
            self.assertEqual(scanner.classify_base_url(url), "local", url)

    def test_a_scheme_less_host_and_port_is_still_local(self):
        """`OLLAMA_HOST` is normally written without a scheme."""
        for value in ("127.0.0.1:11434", "localhost:11434", "ollama"):
            self.assertTrue(scanner.is_local_base_url(value), value)


class UrlRedactionTest(unittest.TestCase):
    """Gateways carry the key in the URL, and this file is persisted and shipped."""

    def test_userinfo_and_query_are_dropped(self):
        self.assertEqual(
            scanner.redact_url("https://user:hunter2@gw.example.com/v1?api_key=sk-live-1234567890"),
            "https://gw.example.com/v1?[redacted]",
        )

    def test_key_shaped_path_segment_is_redacted(self):
        self.assertEqual(
            scanner.redact_url("https://actions.zapier.com/mcp/sk-live-abc123def456ghi789/sse"),
            "https://actions.zapier.com/mcp/[redacted]/sse",
        )

    def test_ordinary_paths_survive(self):
        self.assertEqual(scanner.redact_url("https://api.anthropic.com/v1"), "https://api.anthropic.com/v1")

    def test_port_is_kept(self):
        self.assertEqual(scanner.redact_url("http://localhost:11434/v1"), "http://localhost:11434/v1")

    def test_a_key_without_a_digit_is_still_a_key(self):
        """The shape test used to require a digit, so an all-letter key rode through."""
        self.assertEqual(
            scanner.redact_url("https://gw.example.com/mcp/skliveabcdefghijklmnoqrstuv/sse"),
            "https://gw.example.com/mcp/[redacted]/sse",
        )

    def test_a_base64_key_is_redacted(self):
        """`+`, `/` and `=` fell outside the old character class."""
        redacted = scanner.redact_url("https://gw.example.com/mcp/YWJjZGVmZ2hpamtsbW5vcHFy+w==/sse")
        self.assertNotIn("YWJjZGVmZ2hpamtsbW5vcHFy", redacted)

    def test_a_short_vendor_prefixed_key_is_redacted(self):
        """`sk-live-abc12` is thirteen characters and still opens the account."""
        self.assertEqual(
            scanner.redact_url("https://gw.example.com/k/sk-live-abc12/sse"),
            "https://gw.example.com/k/[redacted]/sse",
        )

    def test_a_fragment_is_dropped(self):
        self.assertEqual(
            scanner.redact_url("https://gw.example.com/v1#access_token=sk-live-1234567890"),
            "https://gw.example.com/v1",
        )

    def test_redaction_is_idempotent(self):
        for url in (
            "https://actions.zapier.com/mcp/sk-live-abc123def456ghi789/sse?k=1",
            "https://user:pw@gw.example.com:8443/a/",
            "https://[2001:db8::1]:9000/x",
            "http://[::1]:8080/path",
            "not a url",
        ):
            once = scanner.redact_url(url)
            self.assertEqual(scanner.redact_url(once), once, url)

    def test_an_ipv6_host_stays_bracketed(self):
        """An unbracketed `::1:8080` makes the redactor crash on its own output."""
        self.assertEqual(scanner.redact_url("http://[::1]:8080/path"), "http://[::1]:8080/path")

    def test_an_unparseable_netloc_does_not_raise(self):
        self.assertEqual(scanner.redact_url("https://[2001:db8::1/x"), "[unparseable]")


class SkillEndpointRedactionTest(unittest.TestCase):
    """Skills-file endpoints reach the feature file *and* the registration POST."""

    def test_an_operator_supplied_endpoint_is_redacted(self):
        skill = scanner.normalize_skill(
            {
                "name": "zapier",
                "description": "hosted actions",
                "destination_endpoints": [
                    "https://actions.zapier.com/mcp/sk-live-abc123def456ghi789/sse",
                    "api.internal.example.com",
                ],
            },
            "test",
        )
        self.assertEqual(
            skill["destination_endpoints"],
            ["https://actions.zapier.com/mcp/[redacted]/sse", "api.internal.example.com"],
        )

    def test_a_bare_host_survives_intact(self):
        """Running a bare host through redact_url would report it as unparseable."""
        for host in ("api.internal.example.com", "ollama", "localhost:11434", "gw.example.com:8443"):
            self.assertEqual(scanner.redact_endpoint(host), host)

    def test_a_bare_token_pasted_where_a_host_belongs_is_redacted(self):
        """A skills file is operator-supplied; nothing stops a key landing here."""
        for token in ("sk-live-abcdef1234567890", "skliveabcdefghijklmnoqrstuv", "ghp_abcdefghijklmnop"):
            self.assertEqual(scanner.redact_endpoint(token), "[redacted]", token)

    def test_a_short_hyphenated_key_is_not_mistaken_for_a_host(self):
        """`sk-live-abc12` is a legal DNS label, so the host test must not run first."""
        for token in ("sk-live-abc12", "xoxb-shorttoken", "glpat-abc123"):
            self.assertEqual(scanner.redact_endpoint(token), "[redacted]", token)

    def test_a_key_in_the_name_or_description_is_redacted(self):
        """Both fields reach the feature file and the registration POST."""
        skill = scanner.normalize_skill(
            {
                "name": "key sk-live-NAMEISASECRET1234567890",
                "description": "run with sk-live-desckeyABCDEFG1234567890 to authenticate",
            },
            "test",
        )
        rendered = repr(skill)
        self.assertNotIn("NAMEISASECRET", rendered)
        self.assertNotIn("desckeyABCDEFG", rendered)
        self.assertIn("[redacted]", skill["description"])

    def test_an_ordinary_description_survives(self):
        skill = scanner.normalize_skill(
            {"name": "sk-learn helper", "description": "Fits a model with scikit-learn"},
            "test",
        )
        self.assertEqual(skill["name"], "sk-learn helper")
        self.assertEqual(skill["description"], "Fits a model with scikit-learn")

    def test_ordinary_words_that_open_like_a_key_survive(self):
        """`asia`, `akia` and `aiza` begin AWS and Google keys and ordinary words
        alike, so matching them as bare prefixes would delete real names."""
        for text in (
            "asian-markets-data-connector",
            "Streams asian-markets order book data",
            "npm_install_helper",
            "hf_dataset_loader",
            "sk_test_environment",
            "rk_reactor_kit",
            "xapp-deploy-tool",
            "risk-management-dashboard",
            "the aizawa attractor",
        ):
            self.assertEqual(scanner.redact_text(text), text)

    def test_hosts_that_open_like_a_key_survive(self):
        for host in (
            "asia.example.com",
            "asian-markets.example.com",
            "akiaki-service.example.com",
            "aizawa-metrics.internal.example.com",
        ):
            self.assertEqual(scanner.redact_endpoint(host), host)

    def test_real_vendor_keys_in_free_text_are_redacted(self):
        for text, secret in (
            ("use sk-live-DESCKEY1234567890abc now", "DESCKEY"),
            ("key AIzaSyD-1234567890abcdefghijklmnopqrstuv here", "AIzaSyD"),
            ("token ya29.a0AfH6SMBx1234567890abcdef", "a0AfH6SMBx"),
            ("aws AKIA1234567890ABCDEF", "AKIA1234567890ABCDEF"),
        ):
            self.assertNotIn(secret, scanner.redact_text(text), text)


class CmdlineRedactionTest(unittest.TestCase):
    """proc1_cmdline is POSTed to rail-center and printed to stdout."""

    def test_a_flag_carrying_a_key_is_redacted(self):
        for cmdline in (
            "myservice --api-key=sk-live-THISISASECRET1234567890",
            "myservice --token sk-live-THISISASECRET1234567890",
            "/bin/sh -c 'ANTHROPIC_API_KEY=sk-live-THISISASECRET1234567890 exec agent'",
            "myapp api_key=THISISASECRETvalue123456",
            "myapp Db_Password=THISISASECRETplus",
        ):
            self.assertNotIn("THISISASECRET", scanner.redact_cmdline(cmdline), cmdline)

    def test_an_ordinary_entrypoint_survives(self):
        self.assertEqual(
            scanner.redact_cmdline("/usr/bin/node /app/server.js --port 8080"),
            "/usr/bin/node /app/server.js --port 8080",
        )

    def test_an_empty_cmdline_is_passed_through(self):
        self.assertIsNone(scanner.redact_cmdline(None))
        self.assertEqual(scanner.redact_cmdline(""), "")


class RegistrationUrlTest(unittest.TestCase):
    def test_a_base_url_gains_the_endpoint(self):
        self.assertEqual(scanner.registration_url("https://center"), "https://center/v1/agents/register")
        self.assertEqual(scanner.registration_url("https://center/"), "https://center/v1/agents/register")

    def test_a_url_that_already_names_the_endpoint_is_left_alone(self):
        full = "https://center/v1/agents/register"
        self.assertEqual(scanner.registration_url(full), full)

    def test_a_query_string_does_not_get_the_endpoint_glued_after_it(self):
        self.assertEqual(
            scanner.registration_url("https://center/api?tenant=acme"),
            "https://center/api/v1/agents/register?tenant=acme",
        )


class McpCommandTest(unittest.TestCase):
    def test_an_inlined_invocation_loses_its_arguments(self):
        """Path(...).name only cuts at the last slash, so `--token …` rode through."""
        self.assertEqual(
            scanner.command_basename("/usr/local/bin/mcp-server --token sk-secret-123"),
            "mcp-server",
        )

    def test_a_plain_executable_is_unchanged(self):
        self.assertEqual(scanner.command_basename("/usr/local/bin/mcp-server"), "mcp-server")

    def test_a_missing_command_is_none(self):
        self.assertIsNone(scanner.command_basename(None))
        self.assertIsNone(scanner.command_basename("   "))

    def test_a_windows_path_keeps_its_separators(self):
        """POSIX splitting reads the separators as escapes and returns C:Usersnode.exe."""
        self.assertEqual(scanner.command_basename(r"C:\Users\foo\bin\node.exe"), "node.exe")

    def test_a_quoted_path_with_a_space(self):
        self.assertEqual(scanner.command_basename('"/opt/my tools/mcp-server" --token sk-1'), "mcp-server")

    def test_an_unbalanced_quote_falls_back(self):
        self.assertEqual(scanner.command_basename('/usr/bin/mcp-server --name "unclosed'), "mcp-server")


class TicketHandlingTest(unittest.TestCase):
    """RailScan is the registrar, and a registrar holds no credentials."""

    RESPONSE = {
        "status": 201,
        "body": {
            "agent": {"id": "a-1", "sandbox_id": "s-1", "host_id": "h-1", "sandbox_name": "sb"},
            "token": "x-rail-placeholder-token",
            "expires_at": "2026-08-03T00:00:00Z",
        },
    }

    def test_state_never_carries_the_token(self):
        state = scanner.build_registration_state("https://center", {"type": "personal"}, self.RESPONSE)
        self.assertEqual(state["agent_id"], "a-1")
        self.assertNotIn("token", state)
        self.assertNotIn("token", state["response"])
        self.assertNotIn("expires_at", state["response"])
        self.assertNotIn("x-rail-placeholder-token", repr(state))

    def test_a_response_without_a_token_is_still_fine(self):
        response = {"status": 201, "body": {"agent": {"id": "a-1"}}}
        self.assertEqual(scanner.build_registration_state("https://c", {}, response)["agent_id"], "a-1")

    def test_a_renamed_credential_field_does_not_ride_along(self):
        """An allowlist, so a field rail-center adds later cannot smuggle a ticket in."""
        response = {
            "status": 201,
            "body": {"agent": {"id": "a-1"}, "ticket": "x-rail-2", "refresh_token": "r-1"},
        }
        state = scanner.build_registration_state("https://c", {}, response)
        self.assertEqual(state["response"], {"agent": {"id": "a-1"}})
        self.assertNotIn("x-rail-2", repr(state))

    def test_a_credential_nested_in_the_agent_object_does_not_ride_along(self):
        """`agent` grows too, so keeping it whole would reopen the hole one level down."""
        response = {
            "status": 201,
            "body": {"agent": {"id": "a-1", "provisioning_token": "x-rail-3"}},
        }
        state = scanner.build_registration_state("https://c", {}, response)
        self.assertEqual(state["response"], {"agent": {"id": "a-1"}})
        self.assertNotIn("x-rail-3", repr(state))


class SecretMarkerGateTest(unittest.TestCase):
    def test_every_classified_type_can_reach_the_classifier(self):
        """A type marker the collection gate filters out is dead code."""
        for _name, markers in scanner.SECRET_TYPE_MARKERS:
            for marker in markers:
                env = {f"DB_{marker}": "value"}
                self.assertTrue(
                    scanner.collect_secret_hygiene(env),
                    f"{marker} is classified but never collected — SECRET_MARKERS filters it out",
                )


    def test_the_shells_own_pwd_is_not_a_secret(self):
        """PWD earns its marker through DB_PWD, but every shell sets PWD and OLDPWD."""
        env = {"PWD": "/home/agent/project", "OLDPWD": "/tmp", "DB_PWD": "hunter2"}
        keys = {entry["key"] for entry in scanner.collect_secret_hygiene(env)}
        self.assertEqual(keys, {"DB_PWD"})
        self.assertIn("PWD", scanner.safe_env_keys(env))
        self.assertNotIn("DB_PWD", scanner.safe_env_keys(env))


class McpInventoryTest(unittest.TestCase):
    def test_url_is_redacted_and_command_loses_its_arguments(self):
        import json
        import tempfile

        config = {
            "mcpServers": {
                "hosted": {"url": "https://actions.zapier.com/mcp/sk-live-abc123def456ghi789/sse"},
                "local": {"command": "/usr/local/bin/mcp-server", "args": ["--token", "sk-secret"]},
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".mcp.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            inventory = {entry["name"]: entry for entry in scanner.read_mcp_inventory(path)}

        self.assertEqual(inventory["hosted"]["url"], "https://actions.zapier.com/mcp/[redacted]/sse")
        self.assertEqual(inventory["hosted"]["transport"], "http")
        self.assertEqual(inventory["local"]["command"], "mcp-server")
        self.assertNotIn("sk-secret", repr(inventory))
        self.assertNotIn("sk-live-abc123def456ghi789", repr(inventory))

    def test_the_skills_view_of_the_same_file_is_redacted_too(self):
        """These skills are POSTed to the control plane, not just written locally."""
        import json
        import tempfile

        config = {
            "mcpServers": {
                "hosted": {"url": "https://actions.zapier.com/mcp/sk-live-abc123def456ghi789/sse"},
                "local": {"command": "/usr/local/bin/mcp-server", "args": ["--token", "sk-secret"]},
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".mcp.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            skills = scanner.read_mcp_config(path)

        rendered = repr(skills)
        self.assertNotIn("sk-live-abc123def456ghi789", rendered)
        self.assertNotIn("sk-secret", rendered)
        self.assertIn("https://actions.zapier.com/mcp/[redacted]/sse", rendered)


class AuthModeTest(unittest.TestCase):
    def setUp(self):
        for key in ("RAIL_AUTH_MODE", "RAIL_AUTH_TOKEN"):
            os.environ.pop(key, None)

    def test_default_sends_nothing(self):
        self.assertEqual(scanner.auth_headers(), {})

    def test_bearer_requires_a_token(self):
        with self.assertRaises(scanner.ScannerError):
            scanner.auth_headers("bearer")

    def test_bearer_sends_the_token(self):
        os.environ["RAIL_AUTH_TOKEN"] = "t-1"
        self.assertEqual(scanner.auth_headers("bearer"), {"Authorization": "Bearer t-1"})

    def test_gcp_fails_loudly_rather_than_degrading(self):
        with self.assertRaises(scanner.ScannerError):
            scanner.auth_headers("gcp")

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(scanner.ScannerError):
            scanner.auth_headers("magic")


class FeatureFileTest(unittest.TestCase):
    def test_covers_the_five_dimensions(self):
        args = argparse.Namespace(container=None, register=False, mcp_config=[])
        ctx = context(env={"OPENAI_API_KEY": "sk-1", "ANTHROPIC_BASE_URL": "https://api.anthropic.com"})
        identity = {
            "host_id": "h-1",
            "host_id_source": "env",
            "sandbox_name": "sb",
            "sandbox_name_source": "label",
            "host_class": "gce_vm",
            "registration_status": "unregistered",
            "mcp_servers": [{"name": "files", "transport": "stdio"}],
        }
        payload = {"owner": "me", "environment": {"sandbox_type": "openclaw"}, "skills": []}

        feature = scanner.build_feature_file(args, ctx, payload, identity)

        self.assertEqual(feature["schema_version"], scanner.FEATURE_SCHEMA_VERSION)
        for dimension in (
            "host_and_identity",
            "secrets_hygiene",
            "model_and_egress",
            "tool_and_mcp_reach",
            "skills",
        ):
            self.assertIn(dimension, feature)
        identity_section = feature["host_and_identity"]
        self.assertEqual(identity_section["host_class"], "gce_vm")
        self.assertEqual(identity_section["host_id"], "h-1")
        self.assertEqual(identity_section["host_id_source"], "env")
        self.assertEqual(identity_section["sandbox_name"], "sb")
        self.assertEqual(identity_section["sandbox_name_source"], "label")
        self.assertEqual(identity_section["sandbox_type"], "openclaw")
        self.assertEqual(identity_section["owner"], "me")
        self.assertEqual(feature["scan"]["registration_status"], "unregistered")
        self.assertEqual(feature["tool_and_mcp_reach"]["mcp_servers"], identity["mcp_servers"])
        self.assertEqual(feature["secrets_hygiene"]["secrets"][0]["key"], "OPENAI_API_KEY")
        self.assertEqual(feature["model_and_egress"]["base_url_class"], "canonical")
        self.assertNotIn("sk-1", repr(feature))


class ObservedReachTest(unittest.TestCase):
    """AgentSight has already parsed and aggregated; we classify, redact and diff."""

    SNAPSHOT = {
        "schema_version": 1,
        "generated_at": "2026-06-05T05:13:53Z",
        "summary": {"sessions": 2, "llm_calls": 31},
        "token_summary": [{"group": "claude-opus-4-6"}],
        "network_targets": [
            {"host": "api.anthropic.com", "path": "/v1/messages?beta=true", "count": 31, "error_count": 0},
            {"host": "exfil.attacker.net", "path": "/collect?key=sk-live-1234567890", "count": 4, "error_count": 1},
        ],
        "tool_calls": [{"tool_name": "Bash", "input": "cat /etc/shadow", "output": "root:x:..."}],
        "process_nodes": [{"argv": ["curl", "-H", "Authorization: Bearer sk-secret"]}],
    }

    def summary(self, declared=frozenset({"api.anthropic.com"})):
        return scanner.summarize_observed(self.SNAPSHOT, set(declared))

    def test_reached_but_never_declared_is_the_signal(self):
        self.assertEqual(self.summary()["undeclared_destinations"], ["exfil.attacker.net"])

    def test_destinations_are_classified_and_ranked(self):
        destinations = self.summary()["destinations"]
        self.assertEqual(destinations[0]["host"], "api.anthropic.com")
        self.assertEqual(destinations[0]["class"], "canonical")
        self.assertEqual(destinations[1]["class"], "unknown_proxy")
        self.assertEqual(destinations[1]["error_count"], 1)

    def test_query_strings_in_observed_paths_are_redacted(self):
        rendered = repr(self.summary())
        self.assertNotIn("sk-live-1234567890", rendered)
        self.assertIn("[redacted]", rendered)

    def test_conversation_and_command_contents_never_come_along(self):
        """tool_calls carry input/output and process_nodes carry argv — names only."""
        rendered = repr(self.summary())
        self.assertEqual(self.summary()["tools_used"], ["Bash"])
        self.assertNotIn("/etc/shadow", rendered)
        self.assertNotIn("root:x:", rendered)
        self.assertNotIn("sk-secret", rendered)

    def test_a_snapshot_larger_than_the_config_read_cap_still_parses(self):
        import json
        import tempfile

        big = dict(self.SNAPSHOT, filler=["x" * 1000] * 200)  # ~200 KB, past read_text's 64 KB
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(json.dumps(big), encoding="utf-8")
            self.assertEqual(scanner.load_snapshot(path)["schema_version"], 1)


class RegistrationStatusTest(unittest.TestCase):
    """A scorer reading "registered" off an agent that never reached the control
    plane would be reading a lie, so the status reports the outcome."""

    def test_failed_registration_is_not_reported_as_registered(self):
        import json
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            feature = Path(tmp) / "features.json"
            proc = subprocess.run(
                [
                    "python3",
                    str(SCANNER),
                    "--mode",
                    "self",
                    "--register",
                    # Port 1 refuses immediately, so this fails without waiting.
                    "--center-url",
                    "http://127.0.0.1:1",
                    "--feature-output",
                    str(feature),
                ],
                capture_output=True,
                text=True,
                env=clean_env(),
                timeout=120,
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertTrue(feature.exists(), "the feature file must survive a failed registration")
            written = json.loads(feature.read_text())
            self.assertEqual(written["scan"]["registration_status"], "registration_failed")
            self.assertEqual(feature.stat().st_mode & 0o777, 0o600)


class ArtifactPermissionsTest(unittest.TestCase):
    """Every artifact names an agent's tools, endpoints and plaintext secrets."""

    def test_the_payload_written_by_output_is_owner_only(self):
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "nested" / "payload.json"
            proc = subprocess.run(
                [
                    "python3",
                    str(SCANNER),
                    "--output",
                    str(payload),
                    "--no-feature-file",
                ],
                capture_output=True,
                text=True,
                env=clean_env(),
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(payload.stat().st_mode & 0o777, 0o600)

    def test_a_pre_existing_loose_file_is_tightened_before_the_write(self):
        """An upgrade meets files an earlier run created under the umask."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text("{}", encoding="utf-8")
            path.chmod(0o644)
            scanner.store_json(path, {"agent_id": "a-1"}, compact=False)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_a_failed_output_write_still_leaves_the_feature_file(self):
        """--output is not the primary artifact; the feature file is."""
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "blocker"
            blocker.write_text("not a directory", encoding="utf-8")
            feature = Path(tmp) / "features.json"
            proc = subprocess.run(
                [
                    "python3",
                    str(SCANNER),
                    "--output",
                    str(blocker / "payload.json"),
                    "--feature-output",
                    str(feature),
                ],
                capture_output=True,
                text=True,
                env=clean_env(),
                timeout=120,
            )
            self.assertEqual(proc.returncode, 2, proc.stdout)
            self.assertTrue(feature.exists(), "the feature file must survive a failed --output write")

    def test_an_unwritable_feature_file_fails_the_run(self):
        """It is the primary artifact, not a side effect, so it sets the exit code."""
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "blocker"
            blocker.write_text("not a directory", encoding="utf-8")
            proc = subprocess.run(
                ["python3", str(SCANNER), "--feature-output", str(blocker / "features.json")],
                capture_output=True,
                text=True,
                env=clean_env(),
                timeout=120,
            )
            self.assertEqual(proc.returncode, 2, proc.stdout)
            self.assertIn("could not write", proc.stderr)


class SecretClassFilesystemTest(unittest.TestCase):
    def test_a_mount_is_checked_against_the_filesystem_it_refers_to(self):
        """In docker mode a local check would call every mount a dangling reference."""
        self.assertEqual(scanner.classify_secret_class("/run/secrets/api.pem", lambda _path: True), "mount")
        self.assertEqual(scanner.classify_secret_class("/run/secrets/api.pem", lambda _path: False), "reference")

    def test_a_base64_key_beginning_with_a_slash_is_plaintext(self):
        """Calling one of these a mount would report a live key as a pointer."""
        self.assertEqual(
            scanner.classify_secret_class("/9Z6TAwq0WfpNoc8L6rTmmkyml3ebDhQ5Dt7UPOvFGU=", lambda _p: True),
            "plaintext",
        )

    def test_a_real_mount_path_is_still_a_mount(self):
        for path in ("/etc/ssl/private/agent.pem", "/run/secrets/api_key", "/var/lib/rail/creds.json"):
            self.assertEqual(scanner.classify_secret_class(path, lambda _p: True), "mount", path)

    def test_an_unstattable_path_is_still_a_mount_not_a_crash(self):
        def refuses(_path: str) -> bool:
            raise AssertionError("the local checker must not be consulted here")

        self.assertEqual(scanner.classify_secret_class("sk-plaintext", refuses), "plaintext")


if __name__ == "__main__":
    unittest.main()

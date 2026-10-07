"""Tests for the identity, secrets and ticket-handling rules of DR-8.

Stdlib only, to match the scanner itself — `make test` runs this with no
dependencies to install.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "tools" / "scan"
SCANNER = SCANNER_DIR / "scan_agent_environment.py"

_spec = importlib.util.spec_from_file_location("scan_agent_environment", SCANNER)
scanner = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(scanner)
_bundle_spec = importlib.util.spec_from_file_location("evidence_bundle", SCANNER_DIR / "evidence_bundle.py")
evidence_bundle = importlib.util.module_from_spec(_bundle_spec)
assert _bundle_spec.loader is not None
_bundle_spec.loader.exec_module(evidence_bundle)

_composer_spec = importlib.util.spec_from_file_location(
    "compose_evidence_bundle_v2", SCANNER_DIR / "compose_evidence_bundle_v2.py"
)
composer = importlib.util.module_from_spec(_composer_spec)
assert _composer_spec.loader is not None
_composer_spec.loader.exec_module(composer)

# This module's own lazy `import evidence_bundle` / `import
# compose_evidence_bundle_v2` / `import scan_agent_environment` (inside
# run_one_scan/run_one_collection and evidence_bundle.py's own functions)
# need to resolve to the exact objects loaded above, not a second copy, so
# `mock.patch.object(scanner, ...)` below actually takes effect where the
# lazy import looks. But `unittest discover` imports every test file's
# module-level code into one process before running any test, and
# `test_evidence_bundle.py` claims "scan_agent_environment" under sys.modules
# the same way — a bare unconditional/`setdefault` write here at import time
# would win or lose that race depending on file-name alphabetical order and
# corrupt whichever file loses it for its entire run. `setUpModule`/
# `tearDownModule` instead scope the registration to exactly this file's own
# test run (unittest calls them immediately before/after this module's
# tests), saving and restoring whatever was there before.
_PATCHED_MODULES = {
    "scan_agent_environment": scanner,
    "evidence_bundle": evidence_bundle,
    "compose_evidence_bundle_v2": composer,
}
_saved_modules: dict[str, Any] = {}


def setUpModule() -> None:
    for name, module in _PATCHED_MODULES.items():
        _saved_modules[name] = sys.modules.get(name)
        sys.modules[name] = module


def tearDownModule() -> None:
    for name, original in _saved_modules.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original
    _saved_modules.clear()

# Rail configuration in the developer's own shell is inherited by every
# subprocess test below, and it changes what the scanner does: RAIL_AUTH_MODE
# alone makes a registration fail before the network is ever touched, so a test
# named for the connection-refused path would pass without reaching it.
SCANNER_ENV_KEYS = (
    "RAIL_HOST_ID",
    "RAIL_AUTH_MODE",
    "RAIL_AUTH_TOKEN",
    "RAIL_AUTH_TOKEN_FILE",
    "RAIL_AUTH_AUDIENCE",
    "GCE_METADATA_HOST",
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


class LegacyDefaultPathTest(unittest.TestCase):
    """DR-161: the registration state moved from RailScan's
    `.datrail/rail-guardian/` to `.rail/railmon/`, and stays where an existing
    layout already keeps it."""

    def path_in(self, cwd: str) -> Path:
        args = scanner.make_parser().parse_args([])
        with contextlib.chdir(cwd), contextlib.redirect_stderr(io.StringIO()):
            return scanner.registration_output_path(args)

    def test_new_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.path_in(tmp), Path(".rail/railmon/registration.json"))

    def test_an_existing_rail_guardian_directory_is_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".datrail", "rail-guardian").mkdir(parents=True)
            self.assertEqual(self.path_in(tmp), Path(".datrail/rail-guardian/registration.json"))
            # The feature file creating .rail/railmon/ does not move it...
            Path(tmp, ".rail", "railmon").mkdir(parents=True)
            Path(tmp, ".rail", "railmon", "features.json").write_text("{}")
            self.assertEqual(self.path_in(tmp), Path(".datrail/rail-guardian/registration.json"))
            # ...a registration file there does, keyed per agent or not.
            Path(tmp, ".rail", "railmon", "registration.json.planner").write_text("{}")
            self.assertEqual(self.path_in(tmp), Path(".rail/railmon/registration.json"))


class TicketHandlingTest(unittest.TestCase):
    """`railmon scan` is the registrar, and a registrar holds no credentials."""

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

    def test_a_key_shaped_server_name_is_redacted(self):
        """The inventory's `name` is persisted (features.json) and shipped in the
        evidence bundle's `mcp_servers_declared` — same redact_text() treatment
        `normalize_skill` already gives a skill's name/description."""
        import json
        import tempfile

        config = {"mcpServers": {"sk-live-abc123def456ghi789": {"url": "http://127.0.0.1:1/mcp"}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".mcp.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            inventory = scanner.read_mcp_inventory(path)

        self.assertNotIn("sk-live-abc123def456ghi789", repr(inventory))

    def test_the_skills_view_of_the_same_file_is_redacted_too(self):
        """These skills are POSTed to the control plane, not just written locally.

        `hosted` points at a loopback port nothing listens on — connection
        refused immediately, no real network or timeout wait — so this stays
        the redaction test it always was rather than becoming a live probe of
        a real third party. `test_mcp_tool_discovery.py` covers the probe
        itself against a real local server.
        """
        import json
        import tempfile

        config = {
            "mcpServers": {
                "hosted": {"url": "http://127.0.0.1:1/mcp/sk-live-abc123def456ghi789/sse"},
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
        self.assertIn("http://127.0.0.1:1/mcp/[redacted]/sse", rendered)
        hosted = next(skill for skill in skills if skill["name"] == "hosted")
        self.assertEqual(hosted["description"], "MCP server configured via .mcp.json: unreachable")


class McpEnvInventoryTest(unittest.TestCase):
    """The per-server env convention (DR-123): `AGENT_MCP_NAME`/`AGENT_MCP_URL`, no config file."""

    def test_inventory_entry_is_redacted_and_marked_environment_sourced(self):
        env = {
            "AGENT_MCP_NAME": "delivery",
            "AGENT_MCP_URL": "http://proxy-delivery:8091/mcp/sk-live-abc123def456ghi789",
        }
        inventory = {entry["name"]: entry for entry in scanner.read_mcp_inventory_from_env(env)}

        self.assertEqual(inventory["delivery"]["url"], "http://proxy-delivery:8091/mcp/[redacted]")
        self.assertEqual(inventory["delivery"]["transport"], "http")
        self.assertEqual(inventory["delivery"]["source"], "environment")
        self.assertNotIn("sk-live-abc123def456ghi789", repr(inventory))

    def test_a_key_shaped_server_name_is_redacted(self):
        env = {"AGENT_MCP_NAME": "sk-live-abc123def456ghi789", "AGENT_MCP_URL": "http://127.0.0.1:1/mcp"}
        self.assertNotIn("sk-live-abc123def456ghi789", repr(scanner.read_mcp_inventory_from_env(env)))

    def test_missing_either_var_yields_nothing(self):
        self.assertEqual(scanner.read_mcp_inventory_from_env({"AGENT_MCP_NAME": "delivery"}), [])
        self.assertEqual(scanner.read_mcp_inventory_from_env({"AGENT_MCP_URL": "http://x:1/mcp"}), [])
        self.assertEqual(scanner.read_mcp_inventory_from_env({}), [])

    def test_collect_mcp_inventory_merges_env_with_file_derived_entries(self):
        import json
        import tempfile

        config = {"mcpServers": {"hosted": {"url": "https://actions.zapier.com/mcp/sse"}}}
        env = {"AGENT_MCP_NAME": "delivery", "AGENT_MCP_URL": "http://proxy-delivery:8091/mcp"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".mcp.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            names = {entry["name"] for entry in scanner.collect_mcp_inventory([path], env)}

        self.assertEqual(names, {"hosted", "delivery"})

    def test_collect_mcp_inventory_keeps_both_when_a_shared_name_has_different_urls(self):
        """A name collision alone must not drop a genuinely different server.

        DR-106 fixed exactly this class of silent loss for `collect_skills`
        (two servers sharing one tool name) by merging instead of dropping;
        `collect_mcp_inventory` dedupes on (name, url), so two entries that
        only share a name — a real possibility once a name can come from
        either a file or an operator-set env var — both survive.
        """
        import json
        import tempfile

        config = {"mcpServers": {"delivery": {"url": "https://file-configured.example/mcp"}}}
        env = {"AGENT_MCP_NAME": "delivery", "AGENT_MCP_URL": "http://proxy-delivery:8091/mcp"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".mcp.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            inventory = scanner.collect_mcp_inventory([path], env)

        sources = {entry["source"] for entry in inventory if entry["name"] == "delivery"}
        self.assertEqual(sources, {".mcp.json", "environment"})

    def test_collect_mcp_inventory_dedupes_a_true_duplicate_by_name_and_url(self):
        """The same server declared both ways (matching name *and* URL) is one entry, not two."""
        import json
        import tempfile

        config = {"mcpServers": {"delivery": {"url": "http://proxy-delivery:8091/mcp"}}}
        env = {"AGENT_MCP_NAME": "delivery", "AGENT_MCP_URL": "http://proxy-delivery:8091/mcp"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".mcp.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            inventory = [entry for entry in scanner.collect_mcp_inventory([path], env) if entry["name"] == "delivery"]

        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["source"], ".mcp.json")

    def test_skills_view_is_redacted_and_reachability_probed_same_as_a_file(self):
        env = {"AGENT_MCP_NAME": "delivery", "AGENT_MCP_URL": "http://127.0.0.1:1/mcp/sk-live-abc123def456ghi789"}
        skills = scanner.read_mcp_config_from_env(env)

        rendered = repr(skills)
        self.assertNotIn("sk-live-abc123def456ghi789", rendered)
        delivery = next(skill for skill in skills if skill["name"] == "delivery")
        self.assertEqual(delivery["description"], "MCP server configured via environment: unreachable")

    def test_collect_skills_includes_the_env_declared_server(self):
        env = {"AGENT_MCP_NAME": "delivery", "AGENT_MCP_URL": "http://127.0.0.1:1/mcp"}
        skills = scanner.collect_skills([], env)
        self.assertIn("delivery", {skill["name"] for skill in skills})


AUTH_ENV_KEYS = ("RAIL_AUTH_MODE", "RAIL_AUTH_TOKEN", "RAIL_AUTH_TOKEN_FILE", "RAIL_AUTH_AUDIENCE", "GCE_METADATA_HOST")


class AuthModeTest(unittest.TestCase):
    def setUp(self):
        for key in AUTH_ENV_KEYS:
            os.environ.pop(key, None)
        scanner._GCP_TOKENS.clear()

    def tearDown(self):
        for key in AUTH_ENV_KEYS:
            os.environ.pop(key, None)

    def test_default_sends_nothing(self):
        self.assertEqual(scanner.auth_headers(), {})

    def test_bearer_requires_a_token(self):
        with self.assertRaises(scanner.ScannerError):
            scanner.auth_headers("bearer")

    def test_bearer_sends_the_token(self):
        os.environ["RAIL_AUTH_TOKEN"] = "t-1"
        self.assertEqual(scanner.auth_headers("bearer"), {"Authorization": "Bearer t-1"})

    def test_gcp_without_an_audience_fails_loudly_rather_than_degrading(self):
        with self.assertRaises(scanner.ScannerError) as caught:
            scanner.auth_headers("gcp")
        self.assertIn("RAIL_AUTH_AUDIENCE", str(caught.exception))

    def test_a_token_beside_none_is_refused_without_quoting_it(self):
        os.environ["RAIL_AUTH_TOKEN"] = "s3cret"
        with self.assertRaises(scanner.ScannerError) as caught:
            scanner.auth_headers()
        self.assertIn("unset, which is none", str(caught.exception))
        self.assertNotIn("s3cret", str(caught.exception))

    def test_token_file_is_read_on_every_call_so_rotation_needs_no_restart(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "token"
            path.write_text("first\n")
            os.environ["RAIL_AUTH_TOKEN_FILE"] = str(path)
            self.assertEqual(scanner.auth_headers("bearer"), {"Authorization": "Bearer first"})
            path.write_text("second\n")
            self.assertEqual(scanner.auth_headers("bearer"), {"Authorization": "Bearer second"})
            # Emptied or unreadable: an error, never an anonymous call.
            path.write_text("")
            with self.assertRaises(scanner.ScannerError):
                scanner.auth_headers("bearer")
            path.unlink()
            with self.assertRaises(scanner.ScannerError) as caught:
                scanner.auth_headers("bearer")
            self.assertIn("RAIL_AUTH_TOKEN_FILE", str(caught.exception))

    def test_neither_token_form_wins_when_both_are_set(self):
        os.environ["RAIL_AUTH_TOKEN"] = "a"
        os.environ["RAIL_AUTH_TOKEN_FILE"] = "/run/t"
        with self.assertRaises(scanner.ScannerError) as caught:
            scanner.auth_headers("bearer")
        self.assertIn("both are set", str(caught.exception))

    def test_a_token_that_cannot_go_in_a_header_is_refused_by_offset(self):
        os.environ["RAIL_AUTH_TOKEN"] = "ab\ncd"
        with self.assertRaises(scanner.ScannerError) as caught:
            scanner.auth_headers("bearer")
        self.assertIn("U+000A at offset 2", str(caught.exception))


def _jwt(exp: int) -> str:
    import base64
    import json

    enc = lambda v: base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")  # noqa: E731
    return ".".join([enc('{"alg":"RS256"}'), enc(json.dumps({"exp": exp})), "sig"])


class FakeControlPlane:
    """Rail Center's register route plus the GCP metadata identity endpoint,
    recording what actually arrived."""

    def __init__(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        plane = self
        self.seen: list[tuple[str, str, str | None]] = []
        self.identities: list[tuple[int, str]] = []
        self.redirect: str | None = None

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                plane.seen.append(("POST", self.path, self.headers.get("Authorization")))
                if plane.redirect:
                    self.send_response(302)
                    self.send_header("Location", plane.redirect)
                    self.end_headers()
                    return
                body = b'{"agent_id":"550e8400-e29b-41d4-a716-446655440000","registration_status":"registered"}'
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                plane.seen.append(("GET", self.path, self.headers.get("Metadata-Flavor")))
                status, body = plane.identities.pop(0) if plane.identities else (500, "exhausted")
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.host = f"127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class GcpAndRedirectTest(unittest.TestCase):
    """DR-46 (RS-F14/F15) against a real local HTTP server, so the header that
    actually leaves the process is what gets asserted."""

    def setUp(self):
        for key in AUTH_ENV_KEYS:
            os.environ.pop(key, None)
        scanner._GCP_TOKENS.clear()
        self.plane = FakeControlPlane()
        self.addCleanup(self.plane.close)

    def tearDown(self):
        for key in AUTH_ENV_KEYS:
            os.environ.pop(key, None)

    def test_gcp_mints_for_the_audience_and_reuses_a_fresh_token(self):
        import time

        fresh = _jwt(int(time.time()) + 3600)
        self.plane.identities = [(200, fresh)]
        os.environ.update(RAIL_AUTH_AUDIENCE="https://rc.example/api", GCE_METADATA_HOST=self.plane.host)
        self.assertEqual(scanner.auth_headers("gcp"), {"Authorization": f"Bearer {fresh}"})
        self.assertEqual(scanner.auth_headers("gcp"), {"Authorization": f"Bearer {fresh}"})
        self.assertEqual(
            self.plane.seen,
            [
                (
                    "GET",
                    "/computeMetadata/v1/instance/service-accounts/default/identity"
                    "?audience=https%3A%2F%2Frc.example%2Fapi",
                    "Google",
                )
            ],
        )

    def test_gcp_mints_again_near_expiry(self):
        import time

        stale, fresh = _jwt(int(time.time()) + 60), _jwt(int(time.time()) + 3600)
        self.plane.identities = [(200, stale), (200, fresh)]
        os.environ.update(RAIL_AUTH_AUDIENCE="aud", GCE_METADATA_HOST=self.plane.host)
        self.assertEqual(scanner.auth_headers("gcp"), {"Authorization": f"Bearer {stale}"})
        self.assertEqual(scanner.auth_headers("gcp"), {"Authorization": f"Bearer {fresh}"})

    def test_gcp_without_an_identity_fails(self):
        self.plane.identities = [(404, "no service account")]
        os.environ.update(RAIL_AUTH_AUDIENCE="aud", GCE_METADATA_HOST=self.plane.host)
        with self.assertRaises(scanner.ScannerError) as caught:
            scanner.auth_headers("gcp")
        self.assertIn("returned 404", str(caught.exception))

    def test_registration_presents_the_minted_token(self):
        import time

        fresh = _jwt(int(time.time()) + 3600)
        self.plane.identities = [(200, fresh)]
        os.environ.update(RAIL_AUTH_AUDIENCE="aud", GCE_METADATA_HOST=self.plane.host)
        result = scanner.post_registration(f"http://{self.plane.host}", {"x": 1}, auth_mode="gcp")
        self.assertEqual(result["status"], 201)
        self.assertEqual(self.plane.seen[-1], ("POST", "/v1/agents/register", f"Bearer {fresh}"))

    def test_registration_does_not_follow_a_redirect_with_the_credential(self):
        self.plane.redirect = f"http://{self.plane.host}/elsewhere"
        os.environ["RAIL_AUTH_TOKEN"] = "t-1"
        with self.assertRaises(scanner.ScannerError) as caught:
            scanner.post_registration(f"http://{self.plane.host}", {"x": 1}, auth_mode="bearer")
        self.assertIn("HTTP 302", str(caught.exception))
        self.assertEqual(self.plane.seen, [("POST", "/v1/agents/register", "Bearer t-1")])

    def test_an_unproducible_credential_fails_registration_without_sending(self):
        """A failed registration, like any other: the feature file and other
        delivery targets are still attempted, and nothing reaches Rail Center."""
        import subprocess

        result = subprocess.run(
            [sys.executable, str(SCANNER), "--mode", "self", "--host-id", "h", "--register",
             "--center-url", f"http://{self.plane.host}", "--no-feature-file", "--no-evidence-bundle"],
            env=clean_env(RAIL_AUTH_MODE="bearer", RAIL_AUTH_TOKEN_FILE="/nonexistent/token"),
            capture_output=True, text=True, timeout=60,
        )
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("RAIL_AUTH_TOKEN_FILE", result.stderr)
        self.assertEqual(self.plane.seen, [])

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(scanner.ScannerError):
            scanner.auth_headers("magic")


class EvidenceBundleIngestUrlTest(unittest.TestCase):
    """DR-121: RailDash's `/v1/evidence-bundles` URL, mirroring RegistrationUrlTest."""

    def test_a_base_url_gains_the_endpoint(self):
        self.assertEqual(
            scanner.evidence_bundle_ingest_url("https://raildash"), "https://raildash/v1/evidence-bundles"
        )
        self.assertEqual(
            scanner.evidence_bundle_ingest_url("https://raildash/"), "https://raildash/v1/evidence-bundles"
        )

    def test_a_url_that_already_names_the_endpoint_is_left_alone(self):
        full = "https://raildash/v1/evidence-bundles"
        self.assertEqual(scanner.evidence_bundle_ingest_url(full), full)

    def test_no_agent_key_means_no_query_string(self):
        self.assertEqual(
            scanner.evidence_bundle_ingest_url("https://raildash", agent_key=None),
            "https://raildash/v1/evidence-bundles",
        )
        self.assertEqual(
            scanner.evidence_bundle_ingest_url("https://raildash", agent_key=""),
            "https://raildash/v1/evidence-bundles",
        )

    def test_agent_key_is_appended_as_a_query_param(self):
        self.assertEqual(
            scanner.evidence_bundle_ingest_url("https://raildash", agent_key="agent-7"),
            "https://raildash/v1/evidence-bundles?agent_key=agent-7",
        )

    def test_a_query_string_does_not_get_the_endpoint_glued_after_it(self):
        self.assertEqual(
            scanner.evidence_bundle_ingest_url("https://raildash/api?tenant=acme"),
            "https://raildash/api/v1/evidence-bundles?tenant=acme",
        )

    def test_an_existing_query_string_is_preserved_alongside_agent_key(self):
        self.assertEqual(
            scanner.evidence_bundle_ingest_url("https://raildash/api?tenant=acme", agent_key="agent-7"),
            "https://raildash/api/v1/evidence-bundles?tenant=acme&agent_key=agent-7",
        )

    def test_a_stale_agent_key_in_the_url_is_replaced_not_duplicated(self):
        self.assertEqual(
            scanner.evidence_bundle_ingest_url("https://raildash?agent_key=old", agent_key="new"),
            "https://raildash/v1/evidence-bundles?agent_key=new",
        )


class ConfiguredRaildashTargetTest(unittest.TestCase):
    """`--raildash-url`/`--agent-key` follow the exact `--center-url` convention:
    flag, then env, then unset — and unlike `--register`, an unset target is not
    an error: it just means this scan is not delivering to RailDash."""

    def setUp(self):
        for key in ("RAIL_RAILDASH_URL", "RAIL_AGENT_KEY"):
            os.environ.pop(key, None)

    def tearDown(self):
        for key in ("RAIL_RAILDASH_URL", "RAIL_AGENT_KEY"):
            os.environ.pop(key, None)

    def test_absent_by_default(self):
        args = argparse.Namespace(raildash_url=None, agent_key=None)
        self.assertIsNone(scanner.configured_raildash_url(args))
        self.assertIsNone(scanner.configured_agent_key(args))

    def test_env_fallback(self):
        os.environ["RAIL_RAILDASH_URL"] = "http://raildash.local"
        os.environ["RAIL_AGENT_KEY"] = "agent-env"
        args = argparse.Namespace(raildash_url=None, agent_key=None)
        self.assertEqual(scanner.configured_raildash_url(args), "http://raildash.local")
        self.assertEqual(scanner.configured_agent_key(args), "agent-env")

    def test_flag_beats_env(self):
        os.environ["RAIL_RAILDASH_URL"] = "http://env"
        os.environ["RAIL_AGENT_KEY"] = "env-key"
        args = argparse.Namespace(raildash_url="http://flag", agent_key="flag-key")
        self.assertEqual(scanner.configured_raildash_url(args), "http://flag")
        self.assertEqual(scanner.configured_agent_key(args), "flag-key")


class ConfiguredScanIntervalTest(unittest.TestCase):
    """DR-83: absent by default (existing single-shot callers unaffected);
    `--interval` beats `RAIL_SCAN_INTERVAL_IN_SECONDS`; a malformed env value
    falls back to the 3600s default rather than failing the scan."""

    def setUp(self):
        os.environ.pop("RAIL_SCAN_INTERVAL_IN_SECONDS", None)

    def tearDown(self):
        os.environ.pop("RAIL_SCAN_INTERVAL_IN_SECONDS", None)

    def test_absent_by_default(self):
        args = argparse.Namespace(interval=None)
        self.assertIsNone(scanner.configured_scan_interval(args))

    def test_flag_enables_and_sets_it(self):
        args = argparse.Namespace(interval=90.0)
        self.assertEqual(scanner.configured_scan_interval(args), 90.0)

    def test_env_var_enables_and_sets_it(self):
        os.environ["RAIL_SCAN_INTERVAL_IN_SECONDS"] = "120"
        args = argparse.Namespace(interval=None)
        self.assertEqual(scanner.configured_scan_interval(args), 120.0)

    def test_flag_beats_env(self):
        os.environ["RAIL_SCAN_INTERVAL_IN_SECONDS"] = "120"
        args = argparse.Namespace(interval=5.0)
        self.assertEqual(scanner.configured_scan_interval(args), 5.0)

    def test_malformed_env_value_falls_back_to_the_default(self):
        os.environ["RAIL_SCAN_INTERVAL_IN_SECONDS"] = "soon"
        args = argparse.Namespace(interval=None)
        self.assertEqual(scanner.configured_scan_interval(args), scanner.DEFAULT_SCAN_INTERVAL_SECONDS)


class MainIntervalLoopTest(unittest.TestCase):
    """DR-83: `main` stays running and scans again on the interval, an
    existing invocation without `--interval` still runs once and returns, and
    the loop's exit code is whatever the most recent scan returned (so a
    supervisor watching the process still sees a failing scan as a failure)."""

    def setUp(self):
        os.environ.pop("RAIL_SCAN_INTERVAL_IN_SECONDS", None)

    def tearDown(self):
        os.environ.pop("RAIL_SCAN_INTERVAL_IN_SECONDS", None)

    def test_no_interval_runs_once(self):
        from unittest import mock

        with mock.patch.object(scanner, "run_one_scan", return_value=0) as run_once, mock.patch.object(
            scanner, "time"
        ) as fake_time:
            code = scanner.main(["--no-feature-file", "--no-evidence-bundle"])
        run_once.assert_called_once()
        fake_time.sleep.assert_not_called()
        self.assertEqual(code, 0)

    def test_interval_scans_repeatedly_until_interrupted(self):
        from unittest import mock

        calls = {"n": 0}

        def fake_scan(args):
            calls["n"] += 1
            if calls["n"] >= 3:
                raise KeyboardInterrupt
            return 0

        with mock.patch.object(scanner, "run_one_scan", side_effect=fake_scan), mock.patch.object(
            scanner, "time"
        ) as fake_time:
            code = scanner.main(["--interval", "5", "--no-feature-file", "--no-evidence-bundle"])
        self.assertEqual(calls["n"], 3)
        self.assertEqual(fake_time.sleep.call_count, 2)
        fake_time.sleep.assert_called_with(5.0)
        self.assertEqual(code, 0)

    def test_loop_exit_code_is_the_most_recent_scan_s(self):
        from unittest import mock

        calls = {"n": 0}

        def fake_scan(args):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise KeyboardInterrupt
            return 2

        with mock.patch.object(scanner, "run_one_scan", side_effect=fake_scan), mock.patch.object(
            scanner, "time"
        ) as fake_time:
            code = scanner.main(["--interval", "1"])
        self.assertEqual(code, 2)


class _FakeHttpResponse:
    """A minimal stand-in for `http.client.HTTPResponse` as a context manager."""

    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class PostEvidenceBundleTest(unittest.TestCase):
    """POST construction and response handling, with `urlopen` mocked out —
    no live RailDash required."""

    def setUp(self):
        for key in ("RAIL_AUTH_MODE", "RAIL_AUTH_TOKEN"):
            os.environ.pop(key, None)

    def tearDown(self):
        for key in ("RAIL_AUTH_MODE", "RAIL_AUTH_TOKEN"):
            os.environ.pop(key, None)

    def test_the_raw_bytes_are_sent_unchanged(self):
        from unittest import mock

        data = b'{"bundle_id":"bnd-1","attributes":{}}'
        with mock.patch.object(
            scanner, "urlopen", return_value=_FakeHttpResponse(202, b'{"id":"asp-1","duplicate":false}')
        ) as mocked:
            result = scanner.post_evidence_bundle("http://raildash.local", data)

        req = mocked.call_args.args[0]
        self.assertEqual(req.full_url, "http://raildash.local/v1/evidence-bundles")
        self.assertEqual(req.data, data)
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.headers.get("Content-type"), "application/json")
        self.assertNotIn("Authorization", req.headers)
        self.assertEqual(result, {"status": 202, "body": {"id": "asp-1", "duplicate": False}})

    def test_no_raildash_token_header_without_one_configured(self):
        """No token configured -- no header, not an empty one."""
        from unittest import mock

        with mock.patch.object(scanner, "urlopen", return_value=_FakeHttpResponse(202, b"{}")) as mocked:
            scanner.post_evidence_bundle("http://raildash.local", b"{}")
        self.assertNotIn("X-raildash-token", mocked.call_args.args[0].headers)

    def test_raildash_token_is_forwarded_when_given(self):
        """RailDash's write-route guard (DR-120) requires this even on loopback --
        unlike rail-center's registration call, an `Authorization` header means
        nothing to RailDash and must never be sent here instead."""
        from unittest import mock

        with mock.patch.object(scanner, "urlopen", return_value=_FakeHttpResponse(202, b"{}")) as mocked:
            scanner.post_evidence_bundle("http://raildash.local", b"{}", raildash_token="t-1")
        headers = mocked.call_args.args[0].headers
        self.assertEqual(headers.get("X-raildash-token"), "t-1")
        self.assertNotIn("Authorization", headers)

    def test_configured_raildash_token_reads_the_env_var_only(self):
        """No `--raildash-token` CLI flag, deliberately (ps visibility) -- see
        the identical `RAIL_AUTH_TOKEN` convention."""
        args = argparse.Namespace()
        self.assertIsNone(scanner.configured_raildash_token(args))
        os.environ["RAIL_RAILDASH_TOKEN"] = "t-2"
        try:
            self.assertEqual(scanner.configured_raildash_token(args), "t-2")
        finally:
            os.environ.pop("RAIL_RAILDASH_TOKEN", None)

    def test_agent_key_rides_the_request_url(self):
        from unittest import mock

        with mock.patch.object(scanner, "urlopen", return_value=_FakeHttpResponse(202, b"{}")) as mocked:
            scanner.post_evidence_bundle("http://raildash.local", b"{}", agent_key="agent-7")
        self.assertTrue(mocked.call_args.args[0].full_url.endswith("?agent_key=agent-7"))

    def test_an_http_error_becomes_a_scanner_error_with_the_body(self):
        import io
        from unittest import mock
        from urllib.error import HTTPError

        def raise_it(req, timeout=None):
            raise HTTPError(req.full_url, 400, "Bad Request", None, io.BytesIO(b"bundle too large"))

        with mock.patch.object(scanner, "urlopen", side_effect=raise_it):
            with self.assertRaises(scanner.ScannerError) as ctx:
                scanner.post_evidence_bundle("http://raildash.local", b"{}")
        self.assertIn("HTTP 400", str(ctx.exception))
        self.assertIn("bundle too large", str(ctx.exception))

    def test_connection_refused_becomes_a_scanner_error_not_a_crash(self):
        from unittest import mock
        from urllib.error import URLError

        with mock.patch.object(scanner, "urlopen", side_effect=URLError("connection refused")):
            with self.assertRaises(scanner.ScannerError):
                scanner.post_evidence_bundle("http://127.0.0.1:1", b"{}")

    def test_a_non_json_response_body_is_a_scanner_error(self):
        from unittest import mock

        with mock.patch.object(scanner, "urlopen", return_value=_FakeHttpResponse(202, b"not json")):
            with self.assertRaises(scanner.ScannerError):
                scanner.post_evidence_bundle("http://raildash.local", b"{}")


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


class ListenersTest(unittest.TestCase):
    """listensnoop's JSON lines become a stable list of what the agent listens on (DR-125)."""

    @staticmethod
    def event(**fields):
        import json

        base = {"timestamp_ns": 1, "kind": "listen", "pid": 41, "tid": 41, "host_pid": 9041,
                "uid": 1000, "comm": "python3", "protocol": "tcp", "family": "ipv4",
                "addr": "127.0.0.1", "port": 8080, "ephemeral": False}
        base.update(fields)
        return json.dumps(base)

    def summary(self, *lines):
        return scanner.summarize_listeners(list(lines))

    def test_a_listening_socket_is_reported_without_pids_or_counts(self):
        listeners = self.summary(self.event(), self.event(timestamp_ns=2, pid=42))["listeners"]
        self.assertEqual(listeners, [{"protocol": "tcp", "addr": "127.0.0.1", "port": 8080, "process": "python3"}])

    def test_a_kernel_chosen_port_is_ephemeral_so_the_value_is_stable(self):
        first = self.summary(self.event(port=41234, ephemeral=True),
                             self.event(kind="autobind", protocol="udp", addr="0.0.0.0", port=40001, ephemeral=True))
        second = self.summary(self.event(port=50999, ephemeral=True),
                              self.event(kind="autobind", protocol="udp", addr="0.0.0.0", port=33333, ephemeral=True))
        self.assertEqual(first["listeners"], second["listeners"])
        self.assertEqual({entry["port"] for entry in first["listeners"]}, {"ephemeral"})

    def test_an_asked_for_port_stays_a_number_inside_the_ephemeral_range(self):
        # A covert listener on port 45000 must not pass as "ephemeral" just
        # because 45000 is a number the kernel could have picked.
        baseline = self.summary(self.event(port=40000))["listeners"]
        later = self.summary(self.event(port=40000), self.event(port=45000))["listeners"]
        self.assertEqual([entry["port"] for entry in later], [40000, 45000])
        self.assertNotEqual(baseline, later)

    def test_without_the_flag_only_an_autobind_is_known_to_be_chosen(self):
        old = dict(ephemeral=None)
        result = self.summary(self.event(port=41234, **old),
                              self.event(kind="autobind", protocol="udp", port=40001, **old))
        self.assertEqual(sorted(str(entry["port"]) for entry in result["listeners"]), ["41234", "ephemeral"])

    def test_a_heartbeat_says_whether_the_probe_is_still_running(self):
        from datetime import datetime, timezone

        now = datetime(2026, 10, 2, 9, 0, 0, tzinfo=timezone.utc)
        alive = '{"kind":"alive","time":"%s","every":60}'
        fresh = self.summary_at(now, alive % "2026-10-02T08:58:00Z", self.event())
        self.assertEqual((fresh["stale"], fresh["last_alive"]), (False, "2026-10-02T08:58:00Z"))
        # Three intervals is the grace; past it, the agent may have stopped it.
        stale = self.summary_at(now, alive % "2026-10-02T08:56:59Z")
        self.assertTrue(stale["stale"])
        # The newest heartbeat counts, wherever it sits in the file.
        newest = self.summary_at(now, alive % "2026-10-02T08:59:30Z", alive % "2026-10-02T08:00:00Z")
        self.assertFalse(newest["stale"])
        # No heartbeat at all (an older probe, or no -H): nothing to judge.
        self.assertIsNone(self.summary_at(now, self.event())["stale"])

    def test_start_records_count_attaches(self):
        from datetime import datetime, timezone

        now = datetime(2026, 10, 2, 9, 0, 0, tzinfo=timezone.utc)
        start = '{"kind":"start","time":"%s","every":%d}'
        once = self.summary_at(now, start % ("2026-10-02T08:59:00Z", 60), self.event())
        self.assertEqual((once["starts"], once["restarted"], once["stale"]), (1, False, False))
        twice = self.summary_at(now, start % ("2026-10-02T08:00:00Z", 60), self.event(),
                                start % ("2026-10-02T08:59:30Z", 60))
        self.assertEqual((twice["starts"], twice["restarted"]), (2, True))
        # Without -H there is no interval to judge staleness by.
        quiet = self.summary_at(now, start % ("2026-10-02T01:00:00Z", 0))
        self.assertEqual((quiet["starts"], quiet["stale"]), (1, None))
        none = self.summary_at(now, self.event())
        self.assertEqual((none["starts"], none["restarted"]), (0, False))

    def test_a_heartbeat_from_the_future_is_stale_too(self):
        # A clock stepped back would otherwise keep it "fresh" for as long.
        from datetime import datetime, timezone

        now = datetime(2026, 10, 2, 9, 0, 0, tzinfo=timezone.utc)
        ahead = self.summary_at(now, '{"kind":"start","time":"2026-10-02T10:00:00Z","every":60}')
        self.assertTrue(ahead["stale"])

    def test_a_malformed_heartbeat_is_counted_not_trusted(self):
        result = self.summary('{"kind":"alive","time":"yesterday","every":60}',
                              '{"kind":"alive","time":"2026-10-02T08:58:00Z","every":0}',
                              '{"kind":"start","time":"2026-10-02T08:58:00Z","every":true}')
        self.assertEqual((result["stale"], result["malformed"], result["starts"]), (None, 3, 0))

    def summary_at(self, now, *lines):
        return scanner.summarize_listeners(list(lines), now)

    def test_lost_records_are_summed(self):
        result = self.summary('{"kind":"lost","count":3}', '{"kind":"lost","count":4}', self.event())
        self.assertEqual(result["lost"], 7)

    def test_a_process_outside_listensnoops_namespace_is_counted_not_listed(self):
        result = self.summary(self.event(pid=0, port=22, comm="sshd"))
        self.assertEqual((result["listeners"], result["outside_namespace"]), ([], 1))

    def test_garbage_lines_are_counted_and_skipped(self):
        result = self.summary("not json", "[1]", self.event(port="80"), self.event(kind="unknown"),
                              self.event(ephemeral="yes"), "", self.event())
        self.assertEqual((len(result["listeners"]), result["malformed"]), (1, 5))

    def test_past_the_cap_listeners_are_counted_not_listed(self):
        lines = [self.event(port=port) for port in range(1000, 1000 + scanner.LISTENER_CAP + 5)]
        result = self.summary(*lines, self.event(port=1000))  # a repeat is never "past the cap"
        self.assertEqual((len(result["listeners"]), result["unlisted"]), (scanner.LISTENER_CAP, 5))

    def test_hostile_strings_cannot_carry_control_characters(self):
        listener, = self.summary(self.event(comm="evil\n\u001b[31m", addr="1.2.3.4\u001b[2J",
                                            protocol="tcp\r"))["listeners"]
        for field in ("process", "addr", "protocol"):
            self.assertTrue(listener[field].isprintable(), field)

    def test_the_file_is_streamed_and_an_unreadable_one_is_an_error(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "listen.jsonl"
            path.write_text("\n".join([self.event(), self.event(port=9090)]) + "\n", encoding="utf-8")
            self.assertEqual(len(scanner.load_listen_events(path)["listeners"]), 2)
            with self.assertRaises(scanner.ScannerError):
                scanner.load_listen_events(Path(tmp) / "missing.jsonl")

    def test_the_reader_never_holds_more_than_one_bounded_chunk(self):
        import io

        limit = scanner.MAX_LISTEN_LINE
        reads: list[int] = []

        class Recording(io.StringIO):
            def readline(self, size=-1):
                line = super().readline(size)
                reads.append(len(line))
                return line

        text = "a\n" + "x" * (limit * 3) + "\n" + "b" * (limit - 1) + "\n" + "c" * limit
        lines = list(scanner._bounded_lines(Recording(text)))
        self.assertEqual(lines, ["a\n", "\x00oversized", "b" * (limit - 1) + "\n", "\x00oversized"])
        self.assertLessEqual(max(reads), limit)

    def test_an_oversized_line_is_skipped_without_losing_its_neighbours(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "listen.jsonl"
            path.write_text(self.event() + "\n" + "x" * (scanner.MAX_LISTEN_LINE * 3) + "\n"
                            + self.event(port=9090) + "\n" + "y" * scanner.MAX_LISTEN_LINE,
                            encoding="utf-8")
            result = scanner.load_listen_events(path)
            self.assertEqual([entry["port"] for entry in result["listeners"]], [8080, 9090])
            self.assertEqual(result["malformed"], 2)


class PeersTest(unittest.TestCase):
    """listensnoop's peer events become a stable list of who connected in (DR-145)."""

    START = '{"kind":"start","time":"2026-10-02T08:00:00Z","every":0,"peers":true}'

    @staticmethod
    def peer(**fields):
        return ListenersTest.event(**{"kind": "peer", "peer": "8.8.4.4", **fields})

    def summary(self, *lines):
        return scanner.summarize_listeners(list(lines))

    def test_each_distinct_peer_per_listener_is_listed_once_with_its_scope(self):
        result = self.summary(self.START, self.peer(), self.peer(pid=42, timestamp_ns=9),
                              self.peer(peer="10.1.2.3"), self.peer(peer="127.0.0.1"),
                              self.peer(peer="fe80::1"), self.peer(peer="100.64.0.1"),
                              self.peer(peer="192.0.2.1"),  # documentation space: not private
                              self.peer(peer="2001:4860::8888", port=9090))
        self.assertEqual(
            [(p["port"], p["peer"], p["scope"]) for p in result["peers"]],
            [(8080, "8.8.4.4", "public"), (8080, "10.1.2.3", "private"),
             (8080, "100.64.0.1", "other"), (8080, "127.0.0.1", "loopback"),
             (8080, "192.0.2.1", "other"),
             (8080, "fe80::1", "link-local"), (9090, "2001:4860::8888", "public")])
        self.assertEqual(result["peers"][0]["process"], "python3")  # IPv4 first, numerically
        self.assertEqual(result["listeners"], [])  # a peer is not a new listener
        self.assertTrue(result["peers_reported"])

    def test_an_ipv4_mapped_peer_is_the_ipv4_peer(self):
        result = self.summary(self.peer(peer="::ffff:8.8.4.4"), self.peer())
        self.assertEqual([p["peer"] for p in result["peers"]], ["8.8.4.4"])

    def test_a_kernel_chosen_listener_port_is_ephemeral_here_too(self):
        first = self.summary(self.peer(port=41000, ephemeral=True))["peers"]
        second = self.summary(self.peer(port=52000, ephemeral=True))["peers"]
        self.assertEqual(first, second)
        self.assertEqual(first[0]["port"], "ephemeral")

    def test_the_newest_start_record_says_whether_peers_are_reported(self):
        old = '{"kind":"start","time":"2026-10-02T09:00:00Z","every":0}'
        self.assertFalse(self.summary(old)["peers_reported"])
        self.assertTrue(self.summary(old.replace("09:00", "07:00"), self.START)["peers_reported"])
        self.assertFalse(self.summary(self.START, old)["peers_reported"])
        self.assertFalse(self.summary(self.START.replace("true", '"yes"'))["peers_reported"])

    def test_a_peer_outside_the_namespace_or_malformed_is_counted_not_listed(self):
        result = self.summary(self.peer(pid=0), self.peer(peer="not-an-ip"), self.peer(peer=7),
                              self.peer(peer="1.2.3.4\u001b[2J"), ListenersTest.event(kind="peer"),
                              self.peer(peer="fe80::1%\u001b[31mX\n"))
        self.assertEqual((result["peers"], result["outside_namespace"], result["malformed"]), ([], 1, 5))

    def test_past_the_cap_peers_are_counted_not_listed(self):
        lines = [self.peer(peer=f"10.0.{i // 256}.{i % 256}") for i in range(scanner.PEER_CAP + 3)]
        result = self.summary(*lines, self.peer(peer="10.0.0.0"))  # a repeat is never past the cap
        self.assertEqual((len(result["peers"]), result["peers_unlisted"], result["unlisted"]),
                         (scanner.PEER_CAP, 3, 0))


class FileAccessTest(unittest.TestCase):
    """filesnoop's JSON lines become a stable list of the files the sandbox opened (DR-154)."""

    START = '{"kind":"start","time":"2026-10-03T08:00:00Z","every":0}'

    @staticmethod
    def event(**fields):
        import json

        # A line as filesnoop (ebpf-tls-tap 7b6da87) prints it.
        base = {"timestamp_ns": 1, "kind": "open", "pid": 41, "tid": 41, "host_pid": 9041,
                "uid": 1000, "comm": "python3", "path": "/etc/hosts", "read": True,
                "write": False, "exec": False, "creat": False, "trunc": False,
                "append": False, "dev": "0:52", "ino": 77}
        base.update(fields)
        return json.dumps(base)

    def summary(self, *lines, now=None):
        return scanner.summarize_file_access(list(lines), now)

    def entry(self, path="/etc/hosts", read=True, write=False, exec=False, layer=False):
        return {"path": path, "read": read, "write": write, "exec": exec, "layer": layer}

    def test_an_open_is_listed_without_pids_counts_or_process_names(self):
        # Another process, thread name and time: the same entry, so the
        # value does not churn with them.
        result = self.summary(self.START, self.event(),
                              self.event(pid=42, tid=43, comm="Thread-8 (reader)", timestamp_ns=9))
        self.assertEqual(result["files"], [self.entry()])
        self.assertEqual((result["source"], result["starts"], result["restarted"]), ("filesnoop", 1, False))

    def test_access_is_the_union_so_a_new_write_changes_the_entry(self):
        before = self.summary(self.START, self.event(path="/data/notes.txt"))
        after = self.summary(self.START, self.event(path="/data/notes.txt"),
                             self.event(path="/data/notes.txt", read=False, write=True, pid=50))
        self.assertEqual(before["files"], [self.entry("/data/notes.txt")])
        self.assertEqual(after["files"], [self.entry("/data/notes.txt", write=True)])

    def test_exec_and_read_write_are_kept_as_filesnoop_reports_them(self):
        result = self.summary(self.event(path="/usr/bin/curl", exec=True),
                              self.event(path="/tmp/db", write=True))
        self.assertEqual(result["files"], [self.entry("/tmp/db", write=True),
                                           self.entry("/usr/bin/curl", exec=True)])

    def test_a_layer_open_is_its_own_entry(self):
        # Its path is the layer's, so it must not merge with an open of the
        # overlay path that happens to read the same.
        result = self.summary(self.event(path="/secret"), self.event(path="/secret", layer=True))
        self.assertEqual(result["files"], [self.entry("/secret"), self.entry("/secret", layer=True)])

    def test_a_process_outside_filesnoops_namespace_is_counted_not_listed(self):
        result = self.summary(self.event(pid=0, path="/etc/shadow"))
        self.assertEqual((result["files"], result["outside_namespace"]), ([], 1))

    def test_an_unnamed_or_overlong_path_is_counted_as_a_gap(self):
        result = self.summary(self.event(path="", path_error=-36),
                              self.event(path="/" + "a" * scanner.FILE_PATH_MAX),
                              self.event(path="/" + "b" * (scanner.FILE_PATH_MAX - 1)))
        self.assertEqual(result["unnamed"], 2)
        self.assertEqual([len(e["path"]) for e in result["files"]], [scanner.FILE_PATH_MAX])

    def test_control_characters_in_a_path_are_not_carried(self):
        result = self.summary(self.event(path="/tmp/a\u001b[2J\nb"))
        self.assertEqual(result["files"], [self.entry("/tmp/a?[2J?b")])

    def test_garbage_lines_are_counted_and_skipped(self):
        result = self.summary("not json", "[1]", "\x00oversized", self.event(kind="close"),
                              self.event(read="yes"), self.event(layer=1), self.event(path=7),
                              self.event(pid="41"), self.event(pid=True), self.event(write=None),
                              "", self.event())
        self.assertEqual((result["files"], result["malformed"]), ([self.entry()], 10))

    def test_lost_and_probe_health_are_read_like_listensnoops(self):
        from datetime import datetime, timezone

        now = datetime(2026, 10, 3, 9, 0, 0, tzinfo=timezone.utc)
        result = self.summary('{"kind":"start","time":"2026-10-03T08:00:00Z","every":60}',
                              '{"kind":"start","time":"2026-10-03T08:10:00Z","every":60}',
                              '{"kind":"alive","time":"2026-10-03T08:20:00Z","every":60}',
                              '{"kind":"lost","count":3}', '{"kind":"lost","count":4}',
                              '{"kind":"alive","time":"later","every":60}', now=now)
        self.assertEqual((result["lost"], result["starts"], result["restarted"], result["stale"],
                          result["last_alive"], result["malformed"]),
                         (7, 2, True, True, "2026-10-03T08:20:00Z", 1))
        fresh = self.summary('{"kind":"alive","time":"2026-10-03T08:59:00Z","every":60}', now=now)
        self.assertEqual((fresh["stale"], fresh["starts"]), (False, 0))

    def test_past_the_cap_reads_go_first_and_every_write_and_exec_stays(self):
        cap = scanner.FILE_ACCESS_CAP
        reads = [self.event(path=f"/lib/{i:04d}.so") for i in range(cap)]
        writes = [self.event(path=f"/zz/out-{i}", read=False, write=True) for i in range(3)]
        runs = [self.event(path="/zz/bin/sh", exec=True)]
        result = self.summary(*reads, *writes, *runs)
        paths = [e["path"] for e in result["files"]]
        self.assertEqual(len(paths), cap)
        self.assertEqual(result["unlisted"], 4)
        self.assertEqual(paths[-4:], ["/zz/bin/sh", "/zz/out-0", "/zz/out-1", "/zz/out-2"])
        # Not the order of the lines: the same set is the same value.
        self.assertEqual(self.summary(*runs, *writes, *reversed(reads))["files"], result["files"])

    def test_tracking_is_bounded_and_the_rest_are_counted(self):
        # The cap is wider than the bound here, so only the bound can stop
        # the fourth and fifth file.
        with mock.patch.object(scanner, "FILE_ACCESS_TRACKED", 3), mock.patch.object(scanner, "FILE_ACCESS_CAP", 10):
            result = self.summary(*(self.event(path=f"/f{i}") for i in range(5)),
                                  self.event(path="/f0", write=True))  # a known file still merges
        self.assertEqual(result["files"], [self.entry("/f0", write=True), self.entry("/f1"), self.entry("/f2")])
        self.assertEqual(result["unlisted"], 2)

    def test_a_flood_of_reads_cannot_use_up_the_room_a_write_needs(self):
        # Reads tracked to the bound, then a write: the write is still kept,
        # and it outranks every read at the cap.
        with mock.patch.object(scanner, "FILE_ACCESS_TRACKED", 3):
            result = self.summary(*(self.event(path=f"/zzz/{i}") for i in range(10)),
                                  self.event(path="/home/a/.bashrc", read=False, write=True))
        self.assertIn(self.entry("/home/a/.bashrc", read=False, write=True), result["files"])
        self.assertEqual((result["unlisted"], result["unlisted_write_exec"]), (7, 0))

    def test_a_lost_write_is_counted_apart_from_lost_reads(self):
        with mock.patch.object(scanner, "FILE_ACCESS_TRACKED", 1):
            result = self.summary(self.event(path="/a", write=True), self.event(path="/b", write=True),
                                  self.event(path="/c"), self.event(path="/d"),
                                  self.event(path="/" + "x" * scanner.FILE_PATH_MAX, exec=True),
                                  self.event(path=""))
        self.assertEqual((result["unlisted"], result["unlisted_write_exec"]), (2, 1))
        self.assertEqual((result["unnamed"], result["unnamed_write_exec"]), (2, 1))
        with mock.patch.object(scanner, "FILE_ACCESS_CAP", 1):
            result = self.summary(self.event(path="/a", write=True), self.event(path="/b", exec=True),
                                  self.event(path="/c"))
        self.assertEqual((result["unlisted"], result["unlisted_write_exec"]), (2, 1))

    def test_the_value_has_a_byte_budget_whatever_the_paths_are(self):
        # 1000 non-ASCII characters render as ~6 KB each (ensure_ascii):
        # without a byte budget 512 of them would pass RailDash's 1 MiB bound.
        import json

        heavy = [self.event(path=f"/{i:03d}" + "\u00e9" * 1000, read=False, write=True) for i in range(512)]
        result = self.summary(*heavy, self.event(path="/short", read=False, write=True))
        rendered = len(json.dumps(result["files"], separators=(",", ":")))
        self.assertLessEqual(rendered, scanner.FILE_ACCESS_BYTES)
        self.assertGreater(result["unlisted"], 400)
        self.assertEqual(result["unlisted"], result["unlisted_write_exec"])
        # An entry too large to fit is skipped, not everything after it.
        self.assertIn(self.entry("/short", read=False, write=True), result["files"])

    def test_the_loader_reads_a_long_filesnoop_line(self):
        # A 4096-byte path, every byte escaped, is far past listensnoop's
        # line bound and must still parse (then count as unnamed).
        import io

        line = self.event(path="\u0001" * 4095) + "\n"
        self.assertGreater(len(line), scanner.MAX_LISTEN_LINE * 5)
        result = scanner.summarize_file_access(
            scanner._bounded_lines(io.StringIO(line + self.event() + "\n"), scanner.MAX_FILE_LINE))
        self.assertEqual((result["unnamed"], result["malformed"], result["files"]), (1, 0, [self.entry()]))


class EphemeralFileAccessTest(unittest.TestCase):
    """Randomly named temp files fold into one templated entry (DR-166)."""

    event = staticmethod(FileAccessTest.event)
    entry = FileAccessTest.entry

    def summary(self, *lines, temp_dirs=scanner.FILE_TEMP_DIRS):
        return scanner.summarize_file_access([FileAccessTest.START, *lines], temp_dirs=temp_dirs)

    def template(self, path, temp_dirs=scanner.FILE_TEMP_DIRS):
        return scanner.ephemeral_file_template(path, temp_dirs)

    def test_the_known_random_names_fold_into_their_templates(self):
        for path, expected in (
            # Python's tempfile: "tmp" and 8 of [a-z0-9_], with or without a suffix.
            ("/tmp/tmpk3j_9xq2", "/tmp/tmp*"),
            ("/tmp/tmpabcdefgh", "/tmp/tmp*"),
            ("/tmp/tmp0a1b2c3d.json", "/tmp/tmp*.json"),
            # And the name it probes the temp dir with, once per process.
            ("/tmp/0vuw8his", "/tmp/*"),
            ("/tmp/abcdefgh", "/tmp/*"),
            # mkstemp(3)'s XXXXXX after a separator, or after "tmp".
            ("/tmp/agent-Ab3dE9", "/tmp/agent-*"),
            ("/tmp/agent-AbCdEf", "/tmp/agent-*"),
            ("/tmp/tmpQ8zR1p", "/tmp/tmp*"),
            ("/var/tmp/cache.x7Yk2Q.lock", "/var/tmp/cache.*.lock"),
            # mktemp(1)'s default, and a Go CreateTemp("", "run-*").
            ("/tmp/tmp.h4Gq0ZtR2b", "/tmp/tmp.*"),
            ("/dev/shm/run-2147483647", "/dev/shm/run-*"),
            # Nested below a temp dir: the directory is kept as it is.
            ("/tmp/work/out/tmpk3j_9xq2", "/tmp/work/out/tmp*"),
            # Vim's swap file, whichever letter it got.
            ("/tmp/.notes.txt.swp", "/tmp/.notes.txt.sw*"),
            ("/tmp/.notes.txt.swo", "/tmp/.notes.txt.sw*"),
            # Even when the edited file's own name looks random.
            ("/tmp/.Report2.swp", "/tmp/.Report2.sw*"),
            ("/tmp/.Report2.swo", "/tmp/.Report2.sw*"),
            # Below a temp dir the prefix-less pattern does not apply, and the
            # next one still may.
            ("/tmp/work/a_b12345", "/tmp/work/a_*"),
        ):
            with self.subTest(path=path):
                self.assertEqual(self.template(path), expected)

    def test_a_name_that_is_not_random_is_never_folded(self):
        for path in (
            "/tmp/exfil.tar", "/tmp/build-output", "/tmp/secrets.json", "/tmp/notes",
            "/tmp/tmpfile", "/tmp/tmp", "/tmp/report-final.csv", "/tmp/agent-Ab3dE",
            "/tmp/tmpk3j_9xq2x", "/tmp/.swp", "/tmp/a.swz", "/tmp/", "/tmp/abcdefg",
            "/tmp/abcdefghi", "/tmp/0vuw8his.txt", "/tmp/Abcdefgh",
            # A directory merely named like one does not make its file random.
            "/tmp/tmpk3j_9xq2/out.json",
            # The prefix-less pattern only directly in a temp dir.
            "/tmp/work/abcdefgh", "/var/tmp/a/0vuw8his",
        ):
            with self.subTest(path=path):
                self.assertIsNone(self.template(path))

    def test_only_inside_a_temp_dir(self):
        for path in ("/workspace/tmpk3j_9xq2", "/etc/tmpk3j_9xq2", "/tmpx/tmpk3j_9xq2",
                     "/home/a/tmp/tmpk3j_9xq2", "tmp/tmpk3j_9xq2", "/var/tmpk3j_9xq2",
                     "/tmp/../etc/tmpk3j_9xq2", "/tmp/./tmpk3j_9xq2", "/tmp//tmpk3j_9xq2",
                     "/tmpk3j_9xq2"):
            with self.subTest(path=path):
                self.assertIsNone(self.template(path))

    def test_two_runs_with_different_random_names_give_the_same_value(self):
        def run(names):
            return self.summary(
                self.event(path="/workspace/config.json"),
                *(self.event(path=f"/tmp/{name}", read=False, write=True) for name in names),
                self.event(path=f"/tmp/{names[0]}", pid=50),  # read back
            )

        first = run(["tmpk3j_9xq2", "tmpa0b1c2d3", "app-Xy7Kq2"])
        second = run(["tmp9zz8yy7x", "tmpqwertyui", "app-P0o9I8"])
        expected = [self.entry("/tmp/app-*", read=False, write=True),
                    self.entry("/tmp/tmp*", read=True, write=True),
                    self.entry("/workspace/config.json")]
        self.assertEqual(first["files"], expected)
        self.assertEqual(second["files"], expected)
        self.assertEqual((first["collapsed"], second["collapsed"]), (3, 3))

    def test_a_new_fixed_name_in_tmp_is_still_its_own_entry(self):
        before = self.summary(self.event(path="/tmp/tmpk3j_9xq2", read=False, write=True))
        after = self.summary(self.event(path="/tmp/tmp9zz8yy7x", read=False, write=True),
                             self.event(path="/tmp/exfil.tar", read=False, write=True))
        self.assertEqual(before["files"], [self.entry("/tmp/tmp*", read=False, write=True)])
        self.assertEqual(after["files"], [self.entry("/tmp/exfil.tar", read=False, write=True),
                                          self.entry("/tmp/tmp*", read=False, write=True)])
        self.assertEqual(after["collapsed"], 1)

    def test_flags_are_unioned_per_template_and_layer_stays_apart(self):
        result = self.summary(self.event(path="/tmp/tmpk3j_9xq2"),
                              self.event(path="/tmp/tmp9zz8yy7x", read=False, exec=True),
                              self.event(path="/tmp/tmpqwertyui", layer=True))
        self.assertEqual(result["files"], [self.entry("/tmp/tmp*", exec=True),
                                           self.entry("/tmp/tmp*", layer=True)])
        self.assertEqual(result["collapsed"], 3)

    def test_a_fold_whose_entry_is_left_out_is_not_counted(self):
        # The note says files were folded only when a templated entry is listed.
        with mock.patch.object(scanner, "FILE_ACCESS_TRACKED", 1):
            result = self.summary(self.event(path="/a", read=False, write=True),
                                  self.event(path="/tmp/tmpk3j_9xq2", read=False, write=True))
        self.assertEqual((result["files"], result["collapsed"], result["unlisted"]),
                         ([self.entry("/a", read=False, write=True)], 0, 1))
        with mock.patch.object(scanner, "FILE_ACCESS_CAP", 1):
            result = self.summary(self.event(path="/a", read=False, write=True),
                                  self.event(path="/tmp/tmpk3j_9xq2"), self.event(path="/tmp/tmp9zz8yy7x"))
        self.assertEqual((result["files"], result["collapsed"], result["unlisted"]),
                         ([self.entry("/a", read=False, write=True)], 0, 1))

    def test_a_listed_fold_is_counted_after_the_count_stopped_growing(self):
        # The count is bounded; the note it drives must not be lost with it.
        with mock.patch.object(scanner, "FILE_ACCESS_TRACKED", 4), mock.patch.object(scanner, "FILE_ACCESS_CAP", 2):
            lines = [*(self.event(path=f"/var/tmp/z{i}/tmpk3j_9xq2") for i in range(4)),
                     self.event(path="/w1", read=False, write=True),
                     self.event(path="/tmp/tmpk3j_9xq2", read=False, write=True)]
            forward, backward = self.summary(*lines), self.summary(*reversed(lines))
        expected = [self.entry("/tmp/tmp*", read=False, write=True), self.entry("/w1", read=False, write=True)]
        self.assertEqual((forward["files"], backward["files"]), (expected, expected))
        self.assertGreaterEqual(min(forward["collapsed"], backward["collapsed"]), 1)

    def test_nothing_folded_counts_zero(self):
        result = self.summary(self.event(path="/tmp/exfil.tar"))
        self.assertEqual((result["files"], result["collapsed"]), ([self.entry("/tmp/exfil.tar")], 0))

    def test_folding_keeps_many_random_names_within_one_entry_of_the_cap(self):
        names = [f"/tmp/tmp{i:08d}" for i in range(scanner.FILE_ACCESS_CAP + 10)]
        result = self.summary(*(self.event(path=name, read=False, write=True) for name in names))
        self.assertEqual(result["files"], [self.entry("/tmp/tmp*", read=False, write=True)])
        self.assertEqual((result["unlisted"], result["collapsed"]), (0, len(names)))

    def test_the_scanned_tmpdir_is_a_temp_dir_and_a_bad_one_is_ignored(self):
        dirs = scanner.file_temp_dirs({"TMPDIR": "/scratch/tmp/", "HOME": "/home/a"})
        self.assertEqual(dirs, (*scanner.FILE_TEMP_DIRS, "/scratch/tmp"))
        self.assertEqual(self.template("/scratch/tmp/tmpk3j_9xq2", dirs), "/scratch/tmp/tmp*")
        self.assertEqual(self.template("/scratch/tmp/0vuw8his", dirs), "/scratch/tmp/*")
        self.assertIsNone(self.template("/scratch/tmpx/tmpk3j_9xq2", dirs))
        # The agent sets $TMPDIR, so only files directly in it fold.
        self.assertIsNone(self.template("/scratch/tmp/sub/tmpk3j_9xq2", dirs))
        # A $TMPDIR below /tmp folds below itself anyway, as part of /tmp.
        self.assertEqual(self.template("/tmp/a/b/tmpk3j_9xq2", scanner.file_temp_dirs({"TMPDIR": "/tmp/a"})),
                         "/tmp/a/b/tmp*")
        for value in ("/", "", "relative/tmp", "/a/../b", "/a//b", "/a/./b", "/a\nb", None, 7,
                      "/tmp", "/" + "a" * 300, "/etc", "/etc/x", "/usr/local/tmp", "/dev/x", "/proc/1",
                      "/home/a", "/home/a/", "/scratch/agent", "/home/a/.ssh", "/app", "/root",
                      "/workspace", "/opt", "/var/lib", "/run/x", "/libexec/tmp", "/etc/tmp",
                      "/usr/tmp", "/tmpdir/x", "/a/mytmp"):
            with self.subTest(value=value):
                self.assertEqual(scanner.file_temp_dirs({"TMPDIR": value, "HOME": "/home/a"}),
                                 scanner.FILE_TEMP_DIRS)
        for value in ("/home/a/tmp", "/home/a/.tmp", "/work/Temp", "/data/tmpdir", "/home/tmp"):
            with self.subTest(value=value):
                self.assertEqual(scanner.file_temp_dirs({"TMPDIR": value, "HOME": "/home/a"}),
                                 (*scanner.FILE_TEMP_DIRS, value))
        # A $TMPDIR that is the agent's $HOME is refused even when named like one.
        self.assertEqual(scanner.file_temp_dirs({"TMPDIR": "/tmp2/tmp", "HOME": "/tmp2/tmp/"}),
                         scanner.FILE_TEMP_DIRS)
        self.assertEqual(scanner.file_temp_dirs(None), scanner.FILE_TEMP_DIRS)
        self.assertIsNone(self.template("/scratch/agent/tmpk3j_9xq2"))


class FollowContainerProbeTest(unittest.TestCase):
    """`railmon files` reuses `listen`'s supervisor with --probe and --output (DR-154)."""

    def test_the_named_probe_appends_to_the_named_file_not_the_listen_file(self):
        import signal
        import subprocess
        import time

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_docker = tmp_path / "docker"
            fake_docker.write_text("#!/bin/sh\necho 4242\n")
            # nsenter -t PID -p -- PROBE ARGS: run the probe in place.
            fake_nsenter = tmp_path / "nsenter"
            fake_nsenter.write_text('#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n')
            probe = tmp_path / "filesnoop"
            probe.write_text('#!/bin/sh\necho "{\\"kind\\":\\"start\\",\\"args\\":\\"$*\\"}"\n'
                             "exec sleep 30\n")
            for script in (fake_docker, fake_nsenter, probe):
                script.chmod(0o755)
            files, listen = tmp_path / "files.jsonl", tmp_path / "listen.jsonl"
            env = {**os.environ, "RAIL_DOCKER": str(fake_docker), "RAIL_NSENTER": str(fake_nsenter),
                   "RAIL_LISTEN_FILE": str(listen)}
            supervisor = subprocess.Popen(
                [sys.executable, str(ROOT / "tools/listen/follow_container.py"), "--command", "files",
                 "--probe", str(probe),
                 "--output", str(files), "agent", "-n", "-H", "5"],
                env=env, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline and not (files.exists() and files.read_text()):
                    time.sleep(0.05)
            finally:
                supervisor.send_signal(signal.SIGTERM)
                _, stderr = supervisor.communicate(timeout=20)
            self.assertEqual(files.read_text().strip(), '{"kind":"start","args":"-n -H 5"}')
            self.assertFalse(listen.exists())
            self.assertIn("[railmon files] attaching to agent (pid 4242)", stderr)
            self.assertEqual(supervisor.returncode, 0)


_follow_spec = importlib.util.spec_from_file_location(
    "follow_container", ROOT / "tools/listen/follow_container.py")
follow_container = importlib.util.module_from_spec(_follow_spec)
_follow_spec.loader.exec_module(follow_container)


class AlreadyListeningTest(unittest.TestCase):
    """listensnoop misses sockets opened before it attaches; the supervisor
    reads them from the agent's socket table instead (DR-182)."""

    HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

    def fake_proc(self, root: Path) -> None:
        # Two processes in the agent's PID namespace, one outside it.
        for pid, nspid, namespace, comm, inodes in (
            (100, 1, "pid:[4026532001]", "agent", [14]),
            (101, 7, "pid:[4026532001]", "worker", [11, 14, 15, 16]),
            (200, 1, "pid:[4026532999]", "sidecar", [12]),
        ):
            base = root / str(pid)
            (base / "ns").mkdir(parents=True)
            (base / "fd").mkdir()
            os.symlink(namespace, base / "ns" / "pid")
            (base / "status").write_text(f"Name:\t{comm}\nNSpid:\t{pid}\t{nspid}\n")
            (base / "comm").write_text(comm + "\n")
            for fd, inode in enumerate(inodes, start=3):
                os.symlink(f"socket:[{inode}]", base / "fd" / str(fd))
            os.symlink("/dev/null", base / "fd" / "0")
        (root / "self").mkdir()
        net = root / "100" / "net"
        net.mkdir()

        def row(local: str, remote: str, state: str, inode: int) -> str:
            return f"   0: {local} {remote} {state} 00000000:00000000 00:00000000 00000000  1000 0 {inode} 1\n"

        (net / "tcp").write_text(self.HEADER
                                 + row("0100007F:2457", "00000000:0000", "0A", 11)  # 127.0.0.1:9303
                                 + row("00000000:0050", "00000000:0000", "0A", 12)  # the sidecar's :80
                                 + row("0100007F:9C40", "0100007F:2457", "01", 17)  # a connection
                                 + row("00000000:1F90", "00000000:0000", "0A", 99))  # nobody's
        (net / "tcp6").write_text(self.HEADER
                                  + row("00000000000000000000000000000000:20FB",
                                        "00000000000000000000000000000000:0000", "0A", 14))
        (net / "udp").write_text(self.HEADER
                                 + row("00000000:14E9", "00000000:0000", "07", 15)  # bound, 5353
                                 + row("0100007F:D431", "0100007F:0035", "01", 16))  # connected
        # No udp6: an IPv6-less kernel.

    def test_only_the_namespaces_listening_sockets_in_listensnoops_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.fake_proc(Path(tmp))
            records = follow_container.listening_sockets(100, proc=tmp)
        common = {"uid": 1000, "ephemeral": False, "snapshot": True}
        self.assertEqual(records, [
            {"kind": "listen", "pid": 7, "comm": "worker", "protocol": "tcp", "family": "ipv4",
             "addr": "127.0.0.1", "port": 9303, **common},
            # Shared by both: the lower namespace PID holds it.
            {"kind": "listen", "pid": 1, "comm": "agent", "protocol": "tcp", "family": "ipv6",
             "addr": "::", "port": 8443, **common},
            {"kind": "bind", "pid": 7, "comm": "worker", "protocol": "udp", "family": "ipv4",
             "addr": "0.0.0.0", "port": 5353, **common},
        ])

    def test_a_comm_that_is_not_utf8_keeps_its_sockets(self):
        # The agent names its own processes; listensnoop escapes each byte
        # as \u00XX, so a byte decodes to the same one character here.
        with tempfile.TemporaryDirectory() as tmp:
            self.fake_proc(Path(tmp))
            (Path(tmp) / "101" / "comm").write_bytes(b"w\xff\xc3\xa9\n")
            (Path(tmp) / "101" / "status").write_bytes(b"Name:\tw\xff\xc3\xa9\nNSpid:\t101\t7\n")
            records = follow_container.listening_sockets(100, proc=tmp)
        self.assertEqual([(r["port"], r["comm"]) for r in records],
                         [(9303, "w\xff\xc3\xa9"), (8443, "agent"), (5353, "w\xff\xc3\xa9")])
        self.assertEqual(json.loads('"w\\u00ff\\u00c3\\u00a9"'), records[0]["comm"])

    def test_the_scanner_keys_them_as_it_keys_listensnoops(self):
        snapshot = {"kind": "listen", "pid": 7, "uid": 0, "comm": "worker", "protocol": "tcp",
                    "family": "ipv4", "addr": "127.0.0.1", "port": 9303, "ephemeral": False,
                    "snapshot": True}
        probe = {**snapshot, "timestamp_ns": 1, "tid": 7, "host_pid": 4242}
        del probe["snapshot"]
        result = scanner.summarize_listeners([json.dumps(snapshot), json.dumps(probe)])
        self.assertEqual(result["listeners"],
                         [{"protocol": "tcp", "addr": "127.0.0.1", "port": 9303, "process": "worker"}])
        self.assertEqual(result["malformed"], 0)

    def test_the_snapshot_follows_the_start_record_once(self):
        start = b'{"kind":"start","time":"2026-10-07T00:00:00Z","every":5,"peers":true}\n'
        event = b'{"kind":"listen","port":1}\n'
        sink = io.BytesIO()
        found = [{"kind": "listen", "port": 9303}]
        with mock.patch.object(follow_container, "listening_sockets", return_value=found) as read, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            follow_container.copy_with_snapshot(io.BytesIO(start + event + start), sink, 4242, "listensnoop")
        read.assert_called_once_with(4242)
        self.assertEqual(sink.getvalue(), start + b'{"kind":"listen","port":9303}\n' + event + start)
        self.assertIn("1 socket(s) were already listening", err.getvalue())

    def test_an_agent_gone_before_the_snapshot_leaves_the_probes_lines(self):
        start = b'{"kind":"start"}\n'
        sink = io.BytesIO()
        with mock.patch.object(follow_container, "listening_sockets", side_effect=FileNotFoundError("gone")), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            follow_container.copy_with_snapshot(io.BytesIO(start), sink, 4242, "listensnoop")
        self.assertEqual(sink.getvalue(), start)
        self.assertIn("cannot read the sockets already listening", err.getvalue())


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
                    # No host id here, so a bundle would fail its contract
                    # and, since DR-157, the scan with it.
                    "--no-evidence-bundle",
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


class RegistrationPayloadAgentKeyTest(unittest.TestCase):
    """DR-109 M2: registration carries `agent_key` when one is configured
    (flag or `RAIL_AGENT_KEY`), and omits it entirely — not `null` — when
    none is, so every existing unkeyed caller's payload is byte-identical."""

    def setUp(self):
        os.environ.pop("RAIL_AGENT_KEY", None)

    def tearDown(self):
        os.environ.pop("RAIL_AGENT_KEY", None)

    def args(self, **overrides):
        base = dict(
            agent_type="personal",
            owner=None,
            sandbox_type=None,
            llm_provider=None,
            llm_model=None,
            capture_file=[],
            config_path=[],
            mcp_config=[],
            skills_file=[],
            agent_key=None,
            container=None,
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def identity(self):
        return {"host_id": "h-1", "sandbox_name": "sb-1"}

    def test_agent_key_absent_by_default(self):
        payload = scanner.build_registration_payload(self.args(), context(), self.identity())
        self.assertNotIn("agent_key", payload)

    def test_agent_key_flag_rides_the_payload(self):
        payload = scanner.build_registration_payload(self.args(agent_key="planner"), context(), self.identity())
        self.assertEqual(payload["agent_key"], "planner")

    def test_agent_key_env_fallback_rides_the_payload_too(self):
        os.environ["RAIL_AGENT_KEY"] = "executor"
        payload = scanner.build_registration_payload(self.args(), context(), self.identity())
        self.assertEqual(payload["agent_key"], "executor")


class ConfiguredTargetManifestTest(unittest.TestCase):
    """Same flag/env/absent convention as `--raildash-url`/`--agent-key`."""

    def setUp(self):
        os.environ.pop("RAIL_TARGET_MANIFEST", None)

    def tearDown(self):
        os.environ.pop("RAIL_TARGET_MANIFEST", None)

    def test_absent_by_default(self):
        self.assertIsNone(scanner.configured_target_manifest(argparse.Namespace(target_manifest=None)))

    def test_env_fallback(self):
        os.environ["RAIL_TARGET_MANIFEST"] = "/etc/rail/manifest.yaml"
        self.assertEqual(
            scanner.configured_target_manifest(argparse.Namespace(target_manifest=None)),
            "/etc/rail/manifest.yaml",
        )

    def test_flag_beats_env(self):
        os.environ["RAIL_TARGET_MANIFEST"] = "/env/manifest.yaml"
        self.assertEqual(
            scanner.configured_target_manifest(argparse.Namespace(target_manifest="/flag/manifest.yaml")),
            "/flag/manifest.yaml",
        )


class ConfiguredRailmonBinTest(unittest.TestCase):
    def setUp(self):
        os.environ.pop("RAILMON_BIN", None)

    def tearDown(self):
        os.environ.pop("RAILMON_BIN", None)

    def test_default_matches_entrypoint_sh(self):
        self.assertEqual(scanner.configured_railmon_bin(), "/usr/local/bin/railmon-collector")

    def test_env_override(self):
        os.environ["RAILMON_BIN"] = "/opt/railmon/railmon-collector"
        self.assertEqual(scanner.configured_railmon_bin(), "/opt/railmon/railmon-collector")


class KeyedPathTest(unittest.TestCase):
    def test_suffixes_the_file_name_with_the_key(self):
        self.assertEqual(
            scanner._keyed_path(Path("/x/y/features.json"), "planner"),
            "/x/y/features.json.planner",
        )


class ResolveTargetsTest(unittest.TestCase):
    """The collector, not this file, owns process resolution and collision
    detection — `resolve_targets` only shells out to it and parses the
    result, so these cases are the boundary of what can go wrong doing that."""

    def fake_bin(self, tmp, script: str) -> str:
        path = Path(tmp) / "fake-railmon"
        path.write_text(f"#!/bin/sh\n{script}\n")
        path.chmod(0o700)
        return str(path)

    def test_parses_the_collector_s_json_array(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            os.environ["RAILMON_BIN"] = self.fake_bin(
                tmp, 'echo \'[{"agent_key": "planner", "status": "available"}]\''
            )
            try:
                targets = scanner.resolve_targets(Path(tmp) / "manifest.yaml")
            finally:
                os.environ.pop("RAILMON_BIN", None)
        self.assertEqual(targets, [{"agent_key": "planner", "status": "available"}])

    def test_a_nonexistent_binary_raises_scanner_error(self):
        os.environ["RAILMON_BIN"] = "/does/not/exist/railmon-collector"
        try:
            with self.assertRaises(scanner.ScannerError):
                scanner.resolve_targets(Path("/tmp/manifest.yaml"))
        finally:
            os.environ.pop("RAILMON_BIN", None)

    def test_a_failing_binary_raises_scanner_error(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            os.environ["RAILMON_BIN"] = self.fake_bin(tmp, "echo bad manifest >&2; exit 1")
            try:
                with self.assertRaises(scanner.ScannerError):
                    scanner.resolve_targets(Path(tmp) / "manifest.yaml")
            finally:
                os.environ.pop("RAILMON_BIN", None)

    def test_non_json_output_raises_scanner_error(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            os.environ["RAILMON_BIN"] = self.fake_bin(tmp, "echo not-json")
            try:
                with self.assertRaises(scanner.ScannerError):
                    scanner.resolve_targets(Path(tmp) / "manifest.yaml")
            finally:
                os.environ.pop("RAILMON_BIN", None)

    def test_non_list_json_raises_scanner_error(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            os.environ["RAILMON_BIN"] = self.fake_bin(tmp, 'echo \'{"not": "a list"}\'')
            try:
                with self.assertRaises(scanner.ScannerError):
                    scanner.resolve_targets(Path(tmp) / "manifest.yaml")
            finally:
                os.environ.pop("RAILMON_BIN", None)


class RunOneCollectionTest(unittest.TestCase):
    """DR-109 M2: one sandbox-wide scan (the existing unkeyed call, args
    untouched) plus one agent-scoped scan per resolved `available` target,
    scoped to that target's config_roots and carrying its agent_key —
    `not_found`/`ambiguous` targets are skipped, not failed, and the
    collection's exit code is the worst of every scan it ran."""

    def base_args(self):
        return argparse.Namespace(
            target_manifest="/manifest.yaml",
            agent_key=None,
            config_path=[],
            feature_output=None,
            registration_output=None,
            evidence_bundle_output=None,
            no_evidence_bundle=True,
            raildash_url=None,
            host_id="host-01",
            sandbox_name="shared-agents",
            compact=True,
        )

    def v1_scope(self, attributes, host_id="host-01", sandbox_name="shared-agents"):
        return {
            "host_id": host_id,
            "sandbox_name": sandbox_name,
            "rule_pack_version": 1,
            "inputs_attempted": {"runtime": {"attempted": True, "reached": True}},
            "attributes": attributes,
            "attestations": [],
        }

    def test_sandbox_wide_scan_runs_unmodified_and_first(self):
        from unittest import mock

        calls = []
        with mock.patch.object(scanner, "run_one_scan", side_effect=lambda a: calls.append(a) or 0), \
                mock.patch.object(scanner, "resolve_targets", return_value=[]):
            code = scanner.run_one_collection(self.base_args())
        self.assertEqual(len(calls), 1)
        self.assertIsNone(calls[0].agent_key)
        self.assertEqual(code, 0)

    def test_available_targets_each_get_a_scoped_scan(self):
        from unittest import mock

        targets = [
            {"agent_key": "planner", "status": "available", "config_roots": ["/srv/planner"]},
            {"agent_key": "executor", "status": "not_found", "reason": "no locator"},
        ]
        calls = []
        with mock.patch.object(scanner, "run_one_scan", side_effect=lambda a: calls.append(a) or 0), \
                mock.patch.object(scanner, "resolve_targets", return_value=targets):
            code = scanner.run_one_collection(self.base_args())
        # One sandbox-wide call plus exactly one per *available* target.
        self.assertEqual(len(calls), 2)
        scoped = calls[1]
        self.assertEqual(scoped.agent_key, "planner")
        self.assertEqual(scoped.config_path, ["/srv/planner"])
        self.assertTrue(scoped.feature_output.endswith(".planner"))
        self.assertTrue(scoped.registration_output.endswith(".planner"))
        self.assertEqual(code, 0)

    def test_a_self_asserted_agent_key_mismatch_is_logged_not_acted_on(self):
        """DR-109 M2: the collector's `self_asserted_agent_key` (a process's
        own RAIL_AGENT_KEY, design §4.1) is diagnostic only -- a mismatch
        against the manifest's declared key gets a warning, never changes
        which key the scan below runs under."""
        import contextlib
        import io
        from unittest import mock

        targets = [
            {
                "agent_key": "planner",
                "status": "available",
                "config_roots": ["/srv/planner"],
                "self_asserted_agent_key": "executor",
            },
        ]
        calls = []
        captured = io.StringIO()
        with mock.patch.object(scanner, "run_one_scan", side_effect=lambda a: calls.append(a) or 0), \
                mock.patch.object(scanner, "resolve_targets", return_value=targets), \
                contextlib.redirect_stderr(captured):
            code = scanner.run_one_collection(self.base_args())
        self.assertEqual(code, 0)
        self.assertEqual(calls[1].agent_key, "planner")  # the manifest's key, unchanged
        self.assertIn("'planner' resolved to a process whose own RAIL_AGENT_KEY is 'executor'", captured.getvalue())

    def test_a_matching_or_absent_self_asserted_agent_key_is_silent(self):
        import contextlib
        import io
        from unittest import mock

        targets = [
            {"agent_key": "planner", "status": "available", "config_roots": ["/srv/planner"], "self_asserted_agent_key": "planner"},
            {"agent_key": "executor", "status": "not_found", "reason": "no locator"},
        ]
        captured = io.StringIO()
        with mock.patch.object(scanner, "run_one_scan", return_value=0), \
                mock.patch.object(scanner, "resolve_targets", return_value=targets), \
                contextlib.redirect_stderr(captured):
            scanner.run_one_collection(self.base_args())
        self.assertNotIn("RAIL_AGENT_KEY", captured.getvalue())

    def test_worst_exit_code_across_the_collection_wins(self):
        from unittest import mock

        targets = [{"agent_key": "planner", "status": "available", "config_roots": ["/srv/planner"]}]
        results = iter([0, 2])
        with mock.patch.object(scanner, "run_one_scan", side_effect=lambda a: next(results)), \
                mock.patch.object(scanner, "resolve_targets", return_value=targets):
            code = scanner.run_one_collection(self.base_args())
        self.assertEqual(code, 2)

    def test_an_available_target_with_no_config_roots_is_skipped_not_defaulted(self):
        """No declared scan.config_roots means nothing agent-specific to
        scope this scan to. Running it anyway would fall back to the same
        defaults the sandbox-wide scan above already covers, and register
        that duplicate un-scoped data as if it were this agent's own —
        exactly the fixture shape (`tests/fixtures/target-manifest-v1.valid.json`'s
        `executor` has no `scan` field at all)."""
        from unittest import mock

        targets = [{"agent_key": "executor", "status": "available", "config_roots": []}]
        calls = []
        with mock.patch.object(scanner, "run_one_scan", side_effect=lambda a: calls.append(a) or 0), \
                mock.patch.object(scanner, "resolve_targets", return_value=targets):
            code = scanner.run_one_collection(self.base_args())
        # Only the sandbox-wide call — the keyed scan never ran.
        self.assertEqual(len(calls), 1)
        self.assertIsNone(calls[0].agent_key)
        self.assertEqual(code, 0)

    def test_a_resolve_failure_is_reported_and_does_not_raise(self):
        from unittest import mock

        with mock.patch.object(scanner, "run_one_scan", return_value=0), mock.patch.object(
            scanner, "resolve_targets", side_effect=scanner.ScannerError("boom")
        ):
            code = scanner.run_one_collection(self.base_args())
        self.assertEqual(code, 2)

    def test_v2_collection_composes_one_bundle_with_every_target_scenario(self):
        """DR-109 M2: a manifest-scoped run producing evidence composes one
        v2 collection (not N v1 bundles) with a real per-target
        `discovery_status`, not a hardcoded `"available"` — an available
        scanned agent, a not_found agent, and an available agent with no
        `scan.config_roots` (BLIND/MULTI_AGENT_SCOPE_UNRESOLVED) each land
        their own correctly-shaped `agents[]` entry."""
        from unittest import mock

        args = self.base_args()
        args.no_evidence_bundle = False
        targets = [
            {"agent_key": "planner", "status": "available", "config_roots": ["/srv/planner"]},
            {"agent_key": "executor", "status": "not_found", "reason": "no locator"},
            {"agent_key": "reviewer", "status": "available", "config_roots": []},
        ]
        sandbox_v1 = self.v1_scope({
            "image_digest": {"value": "sha256:abc", "status": "ANSWERED", "tier": "observed"},
            "model_name": {"value": "should-not-leak-into-agents", "status": "ANSWERED", "tier": "observed"},
        })
        planner_v1 = self.v1_scope({"model_name": {"value": "claude", "status": "ANSWERED", "tier": "observed"}})
        scope_calls = iter([(sandbox_v1, {"env": {}}), (planner_v1, {"env": {}})])
        delivered = {}

        def fake_deliver(args, sandbox, agent_entries):
            delivered["sandbox"] = sandbox
            delivered["agent_entries"] = {e["agent_key"]: e for e in agent_entries}
            return 0

        with mock.patch.object(scanner, "run_one_scan", return_value=0), \
                mock.patch.object(scanner, "resolve_targets", return_value=targets), \
                mock.patch.object(scanner, "_v1_scope_from_scan_result", side_effect=lambda a: next(scope_calls)), \
                mock.patch.object(scanner, "_deliver_v2_collection", side_effect=fake_deliver):
            code = scanner.run_one_collection(args)

        self.assertEqual(code, 0)
        entries = delivered["agent_entries"]
        self.assertEqual(set(entries), {"planner", "executor", "reviewer"})
        self.assertEqual(entries["planner"]["discovery_status"], "available")
        self.assertEqual(entries["planner"]["attributes"]["model_name"]["value"], "claude")
        self.assertEqual(entries["executor"]["discovery_status"], "not_found")
        self.assertEqual(entries["executor"]["attributes"], {})
        self.assertEqual(entries["reviewer"]["discovery_status"], "available")
        self.assertEqual(
            entries["reviewer"]["attributes"]["model_name"]["reason"], "MULTI_AGENT_SCOPE_UNRESOLVED"
        )
        self.assertNotIn("image_digest", entries["reviewer"]["attributes"])

    def test_sandbox_collector_failure_marks_the_sandbox_scope_failed_not_omitted(self):
        """Design §5, 'Shared evidence collection fails': agent-scoped
        scanning still runs and the collection is still composed and
        delivered, with the sandbox scope's every source `FAILED` rather
        than no v2 collection at all — as long as `scan()` got far enough to
        name a `host_id`/`sandbox_name`."""
        from unittest import mock

        args = self.base_args()
        args.no_evidence_bundle = False
        targets = [{"agent_key": "planner", "status": "available", "config_roots": ["/srv/planner"]}]
        planner_v1 = self.v1_scope({"model_name": {"value": "claude", "status": "ANSWERED", "tier": "observed"}})
        scope_calls = iter([(None, {"env": {}}), (planner_v1, {"env": {}})])
        delivered = {}

        def fake_deliver(args, sandbox, agent_entries):
            delivered["sandbox"] = sandbox
            delivered["agent_entries"] = agent_entries
            return 0

        with mock.patch.object(scanner, "run_one_scan", return_value=0), \
                mock.patch.object(scanner, "resolve_targets", return_value=targets), \
                mock.patch.object(scanner, "_v1_scope_from_scan_result", side_effect=lambda a: next(scope_calls)), \
                mock.patch.object(scanner, "_deliver_v2_collection", side_effect=fake_deliver):
            code = scanner.run_one_collection(args)

        self.assertEqual(code, 2)  # the sandbox failure itself is still a real failure
        self.assertIn("sandbox", delivered)
        sandbox = delivered["sandbox"]
        self.assertEqual(sandbox["host_id"], "host-01")
        self.assertEqual(sandbox["sandbox_name"], "shared-agents")
        self.assertEqual(sandbox["attributes"], {})
        for source in sandbox["inputs_attempted"].values():
            self.assertTrue(source["attempted"])
            self.assertFalse(source["reached"])
        self.assertEqual(len(delivered["agent_entries"]), 1)

    def test_sandbox_collector_failure_with_no_context_produces_no_v2_collection(self):
        """When `scan()` fails before even a `host_id`/`sandbox_name` can be
        named, no schema-legal v2 collection can be built at all (both are
        required non-empty top-level fields) — delivery is skipped
        entirely, same as before this scope existed."""
        from unittest import mock

        args = self.base_args()
        args.host_id = None
        args.sandbox_name = None
        args.no_evidence_bundle = False
        targets = [{"agent_key": "planner", "status": "available", "config_roots": ["/srv/planner"]}]
        planner_v1 = self.v1_scope({"model_name": {"value": "claude", "status": "ANSWERED", "tier": "observed"}})
        scope_calls = iter([(None, None), (planner_v1, {"env": {}})])
        deliver = mock.Mock()

        with mock.patch.object(scanner, "run_one_scan", return_value=0), \
                mock.patch.object(scanner, "resolve_targets", return_value=targets), \
                mock.patch.object(scanner, "_v1_scope_from_scan_result", side_effect=lambda a: next(scope_calls)), \
                mock.patch.object(scanner, "_deliver_v2_collection", deliver):
            code = scanner.run_one_collection(args)

        self.assertEqual(code, 2)
        deliver.assert_not_called()

    def test_one_agent_collector_failure_is_present_and_failed_not_omitted(self):
        """Design §5, 'One agent collector fails': the other keyed agent
        still gets its own entry; the failed one is present with `FAILED`
        attributes covering the sandbox scope's own attribute template,
        not silently missing from `agents[]`."""
        from unittest import mock

        args = self.base_args()
        args.no_evidence_bundle = False
        targets = [
            {"agent_key": "planner", "status": "available", "config_roots": ["/srv/planner"]},
            {"agent_key": "executor", "status": "available", "config_roots": ["/srv/executor"]},
        ]
        sandbox_v1 = self.v1_scope({
            "image_digest": {"value": "sha256:abc", "status": "ANSWERED", "tier": "observed"},
            "model_name": {"value": "sandbox-template-only", "status": "ANSWERED", "tier": "declared"},
        })
        executor_v1 = self.v1_scope({"model_name": {"value": "gpt", "status": "ANSWERED", "tier": "observed"}})
        # planner's own scan fails after context was established.
        scope_calls = iter([(sandbox_v1, {"env": {}}), (None, {"env": {}}), (executor_v1, {"env": {}})])
        delivered = {}

        def fake_deliver(args, sandbox, agent_entries):
            delivered["agent_entries"] = {e["agent_key"]: e for e in agent_entries}
            return 0

        with mock.patch.object(scanner, "run_one_scan", return_value=0), \
                mock.patch.object(scanner, "resolve_targets", return_value=targets), \
                mock.patch.object(scanner, "_v1_scope_from_scan_result", side_effect=lambda a: next(scope_calls)), \
                mock.patch.object(scanner, "_deliver_v2_collection", side_effect=fake_deliver):
            code = scanner.run_one_collection(args)

        self.assertEqual(code, 2)
        entries = delivered["agent_entries"]
        self.assertEqual(set(entries), {"planner", "executor"})
        self.assertEqual(entries["executor"]["attributes"]["model_name"]["value"], "gpt")
        failed = entries["planner"]
        self.assertEqual(failed["discovery_status"], "available")
        self.assertEqual(failed["attributes"]["model_name"]["status"], "FAILED")
        self.assertEqual(failed["attributes"]["model_name"]["tier"], "declared")
        self.assertNotIn("image_digest", failed["attributes"])
        for source in failed["inputs_attempted"].values():
            self.assertTrue(source["attempted"])
            self.assertFalse(source["reached"])

    def test_scan_runs_exactly_once_per_scope_not_twice(self):
        """A rail-review finding on an earlier version of this branch: v2
        composition used to call `scan()` a second time per scope (once via
        `run_one_scan`, again to build the v1 scope for composing), breaking
        `build_verified_bundle`'s own "built once and shared" contract. Uses
        the real `run_one_scan`/`_v1_scope_from_scan_result` (only `scan`
        itself and network/registration are mocked) so this exercises the
        real stash-and-reuse wiring, not a mock that could hide a
        regression back to two scans."""
        import tempfile
        from unittest import mock

        calls = {"n": 0}

        def fake_scan(args):
            calls["n"] += 1
            return (
                scanner.collect_self_context(),
                {"host_id": "host-01", "sandbox_name": "shared"},
                {"mcp_servers": []},
            )

        with tempfile.TemporaryDirectory() as tmp:
            args = scanner.make_parser().parse_args(
                [
                    "--target-manifest", "/manifest.yaml",
                    "--host-id", "host-01",
                    "--sandbox-name", "shared",
                    "--no-feature-file",
                    "--evidence-bundle-output", os.path.join(tmp, "evidence.json"),
                    "--compact",
                ]
            )
            targets = [{"agent_key": "planner", "status": "available", "config_roots": [tmp]}]
            with mock.patch.object(scanner, "scan", side_effect=fake_scan), \
                    mock.patch.object(scanner, "resolve_targets", return_value=targets):
                code = scanner.run_one_collection(args)

        self.assertEqual(code, 0)
        # Exactly one scan for the sandbox scope, one for the single agent —
        # not four (two per scope), which is what the bug this test guards
        # against would have produced.
        self.assertEqual(calls["n"], 2)

    def test_a_resolve_failure_still_delivers_the_sandbox_v1_fallback(self):
        """A rail-review finding: suppressing the sandbox scan's own v1
        write on the bet that a v2 collection would follow means a broken
        manifest — caught only after that scan already ran — used to lose
        the sandbox's evidence outright. `_deliver_v1_fallback` must run
        with the exact args object `run_one_scan` was called with, so it
        can reuse that same scan's stashed result."""
        from unittest import mock

        args = self.base_args()
        args.no_evidence_bundle = False
        fallback = mock.Mock()

        with mock.patch.object(scanner, "run_one_scan", return_value=0) as run_scan, \
                mock.patch.object(scanner, "resolve_targets", side_effect=scanner.ScannerError("boom")), \
                mock.patch.object(scanner, "_deliver_v1_fallback", fallback):
            code = scanner.run_one_collection(args)

        self.assertEqual(code, 2)
        fallback.assert_called_once()
        (fallback_args,), _ = fallback.call_args
        (scan_args,), _ = run_scan.call_args
        self.assertIs(fallback_args, scan_args)

    def test_host_id_undetermined_still_calls_v1_fallback(self):
        """The other half of the same finding: when `scan()` fails before
        even a `host_id`/`sandbox_name` can be named, no v2 collection is
        schema-legal — but the scan that already ran should still fall back
        to a v1 delivery rather than vanishing."""
        from unittest import mock

        args = self.base_args()
        args.no_evidence_bundle = False
        targets = [{"agent_key": "planner", "status": "available", "config_roots": ["/srv/planner"]}]
        planner_v1 = self.v1_scope({"model_name": {"value": "claude", "status": "ANSWERED", "tier": "observed"}})
        scope_calls = iter([(None, None), (planner_v1, {"env": {}})])
        fallback = mock.Mock()

        with mock.patch.object(scanner, "run_one_scan", return_value=0), \
                mock.patch.object(scanner, "resolve_targets", return_value=targets), \
                mock.patch.object(scanner, "_v1_scope_from_scan_result", side_effect=lambda a: next(scope_calls)), \
                mock.patch.object(scanner, "_deliver_v1_fallback", fallback):
            code = scanner.run_one_collection(args)

        self.assertEqual(code, 2)
        fallback.assert_called_once()

    def test_agents_fall_back_to_normal_v1_path_when_no_v2_collection_possible(self):
        """The regression this finding named directly: when the sandbox
        scope can't be built at all (`sandbox_v1` stays `None`), an
        otherwise-successful agent must not have its own v1 evidence
        bundle suppressed for a v2 collection that will never exist —
        it gets the same keyed `evidence_bundle_output` a non-v2 run uses."""
        from unittest import mock

        args = self.base_args()
        args.no_evidence_bundle = False
        targets = [{"agent_key": "planner", "status": "available", "config_roots": ["/srv/planner"]}]
        calls = []

        with mock.patch.object(scanner, "run_one_scan", side_effect=lambda a: calls.append(a) or 0), \
                mock.patch.object(scanner, "resolve_targets", return_value=targets), \
                mock.patch.object(scanner, "_v1_scope_from_scan_result", return_value=(None, None)):
            code = scanner.run_one_collection(args)

        self.assertEqual(code, 2)
        # calls[0] is the sandbox scan; calls[1] is planner's own.
        self.assertEqual(len(calls), 2)
        planner_call = calls[1]
        self.assertFalse(getattr(planner_call, "_v2_collection", False))
        self.assertTrue(planner_call.evidence_bundle_output.endswith(".planner"))


class KeyedArtifactOwnershipTest(unittest.TestCase):
    """DR-109 M2's last open bullet: registration state and generated
    artifacts under owner-only keyed paths, with no registration ticket
    retained. `build_registration_state`/`store_json` are agent-key-agnostic
    (`TicketHandlingTest`/`ArtifactPermissionsTest` above already prove the
    ticket-stripping and 0o600/0o700 behavior in the single-agent path) —
    the actual gap was that nothing exercised them through a real, unmocked
    `run_one_collection` -> `run_one_scan` call for a *keyed* target, so a
    future change routing keyed writes around `store_json` would pass every
    existing test. These drive the real code, mocking only `scan()` (heavy,
    already covered elsewhere) and the network call `post_registration`."""

    def fake_scan(self, args):
        context = scanner.collect_self_context()
        return (
            context,
            {"host_id": "host-01", "sandbox_name": "shared"},
            scanner.collect_identity(args, context),
        )

    def test_a_keyed_scan_writes_its_feature_file_owner_only(self):
        import tempfile
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            feature_dir = os.path.join(tmp, "nested", "features.json")
            args = scanner.make_parser().parse_args(
                [
                    "--target-manifest", "/manifest.yaml",
                    "--host-id", "host-01",
                    "--sandbox-name", "shared",
                    "--feature-output", feature_dir,
                    "--no-evidence-bundle",
                    "--compact",
                ]
            )
            targets = [{"agent_key": "planner", "status": "available", "config_roots": [tmp]}]
            with mock.patch.object(scanner, "scan", side_effect=self.fake_scan), \
                    mock.patch.object(scanner, "resolve_targets", return_value=targets):
                code = scanner.run_one_collection(args)

            self.assertEqual(code, 0)
            keyed_feature = Path(feature_dir + ".planner")
            self.assertTrue(keyed_feature.exists())
            self.assertEqual(keyed_feature.stat().st_mode & 0o777, 0o600)
            self.assertEqual(keyed_feature.parent.stat().st_mode & 0o777, 0o700)
            # The sandbox-wide scan's own unkeyed feature file is just as
            # owner-only, and a distinct file from the keyed one above.
            self.assertEqual(Path(feature_dir).stat().st_mode & 0o777, 0o600)

    def test_a_keyed_v1_fallback_evidence_bundle_is_owner_only(self):
        """Mirrors `test_agents_fall_back_to_normal_v1_path_when_no_v2_collection_possible`:
        when no v2 collection can be composed, the agent's own evidence
        bundle falls back to its keyed v1 path — which must land owner-only
        exactly like every other artifact `store_json` writes."""
        import tempfile
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = os.path.join(tmp, "nested", "evidence.json")
            args = scanner.make_parser().parse_args(
                [
                    "--target-manifest", "/manifest.yaml",
                    "--host-id", "host-01",
                    "--sandbox-name", "shared",
                    "--no-feature-file",
                    "--evidence-bundle-output", bundle_dir,
                    "--compact",
                ]
            )
            targets = [{"agent_key": "planner", "status": "available", "config_roots": [tmp]}]
            with mock.patch.object(scanner, "scan", side_effect=self.fake_scan), \
                    mock.patch.object(scanner, "resolve_targets", return_value=targets), \
                    mock.patch.object(scanner, "_v1_scope_from_scan_result", return_value=(None, None)):
                code = scanner.run_one_collection(args)

            self.assertEqual(code, 2)  # the forced no-v2-possible case also fails the collection
            keyed_bundle = Path(bundle_dir + ".planner")
            self.assertTrue(keyed_bundle.exists())
            self.assertEqual(keyed_bundle.stat().st_mode & 0o777, 0o600)
            self.assertEqual(keyed_bundle.parent.stat().st_mode & 0o777, 0o700)

    def test_a_keyed_registration_is_owner_only_and_drops_the_ticket(self):
        import json
        import tempfile
        from unittest import mock

        response = {
            "status": 201,
            "body": {
                "agent": {"id": "a-planner", "sandbox_id": "s-1", "host_id": "host-01", "sandbox_name": "shared"},
                "token": "x-rail-placeholder-token",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            registration_path = os.path.join(tmp, "registration.json")
            args = scanner.make_parser().parse_args(
                [
                    "--target-manifest", "/manifest.yaml",
                    "--host-id", "host-01",
                    "--sandbox-name", "shared",
                    "--no-feature-file",
                    "--no-evidence-bundle",
                    "--register",
                    "--center-url", "https://rail-center.internal",
                    "--registration-output", registration_path,
                    "--compact",
                ]
            )
            targets = [{"agent_key": "planner", "status": "available", "config_roots": [tmp]}]
            with mock.patch.object(scanner, "scan", side_effect=self.fake_scan), \
                    mock.patch.object(scanner, "resolve_targets", return_value=targets), \
                    mock.patch.object(scanner, "post_registration", return_value=response):
                code = scanner.run_one_collection(args)

            self.assertEqual(code, 0)
            keyed_state_path = Path(registration_path + ".planner")
            self.assertTrue(keyed_state_path.exists())
            self.assertEqual(keyed_state_path.stat().st_mode & 0o777, 0o600)
            written = keyed_state_path.read_text(encoding="utf-8")
            self.assertNotIn("x-rail-placeholder-token", written)
            state = json.loads(written)
            self.assertEqual(state["agent_id"], "a-planner")
            self.assertNotIn("token", state["response"])


class MainTargetManifestDispatchTest(unittest.TestCase):
    """`--target-manifest` (or `RAIL_TARGET_MANIFEST`) switches `main` from
    the single unkeyed scan to a full collection; its absence preserves the
    exact call `MainIntervalLoopTest` already covers."""

    def setUp(self):
        os.environ.pop("RAIL_TARGET_MANIFEST", None)

    def tearDown(self):
        os.environ.pop("RAIL_TARGET_MANIFEST", None)

    def test_without_target_manifest_runs_the_plain_scan(self):
        from unittest import mock

        with mock.patch.object(scanner, "run_one_scan", return_value=0) as plain, mock.patch.object(
            scanner, "run_one_collection"
        ) as collection:
            scanner.main(["--no-feature-file", "--no-evidence-bundle"])
        plain.assert_called_once()
        collection.assert_not_called()

    def test_with_target_manifest_runs_the_collection(self):
        from unittest import mock

        with mock.patch.object(scanner, "run_one_scan") as plain, mock.patch.object(
            scanner, "run_one_collection", return_value=0
        ) as collection:
            scanner.main(["--target-manifest", "/manifest.yaml"])
        collection.assert_called_once()
        plain.assert_not_called()


if __name__ == "__main__":
    unittest.main()

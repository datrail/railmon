"""RC-520: any other harness gets the fields that need no profile.

The generic reader (tools/scan/gke/sidecar/harness/generic.py), which the shared
reader runs when no profile matches the agent, read against the config folder
of a made-up harness no profile knows (fixtures/generic/README.md): through
the reader with local files, through pod mode's harness attributes, and in a
whole pod-mode scan against a fake /proc.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "tools" / "scan"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "generic"


def load(name: str, path: Path):
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


def load_private(name: str, path: Path):
    """A module under a name of this test's own (see test_claude_code_profile)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reader = load("harness_reader", SCAN / "gke" / "sidecar" / "harness" / "reader.py")
pod_mode = load("gke_pod_mode", SCAN / "gke" / "sidecar" / "pod_mode.py")
scanner = load_private("generic_reader_test_scanner", SCAN / "scan_agent_environment.py")
evidence_bundle = load_private("generic_reader_test_bundle", SCAN / "evidence_bundle.py")

PROFILES = reader.load_profiles()
BUILDERS = {"answered": evidence_bundle._answered, "blind": evidence_bundle._blind,
            "absent": evidence_bundle._absent, "failed": evidence_bundle._failed,
            "partial": evidence_bundle._partial}
SHAPERS = {"mcp_inventory_entries": scanner.mcp_inventory_entries, "normalize_skill": scanner.normalize_skill,
           "merge_skill_lists": scanner.merge_skill_lists, "url_host": scanner.url_host,
           "redact_url": scanner.redact_url}
CMDLINE = "python3 -m plainagent serve --port 8080"
CONFIG = "/root/.plainagent"
# A fixed stand-in for a credential, which no result or bundle may carry.
PLACEHOLDER = "fixture-placeholder-not-a-key"
# The fields only a profile can fill, whatever the agent's files hold.
PROFILE_ONLY = ("harness_identity", "tool_names", "skills_inventory")


def unknown(result: dict[str, Any]) -> bool:
    return (result["status"], result.get("reason")) == ("BLIND", "UNKNOWN_HARNESS")


class Agent(unittest.TestCase):
    """An agent of no known harness: its root, with the fixture config
    folder at /root/.plainagent."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "agent-root"
        self.put(f"{CONFIG}/config.json", FIXTURES / "config.json")
        self.put(f"{CONFIG}/.mcp.json", FIXTURES / "mcp.json")
        self.put(f"{CONFIG}/AGENTS.md", FIXTURES / "AGENTS.md")

    def put(self, path: str, fixture: Path) -> None:
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(fixture, target)

    def write(self, path: str, content: Any) -> None:
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content if isinstance(content, str) else json.dumps(content))

    def remove(self, path: str) -> None:
        (self.root / path.lstrip("/")).unlink()

    def agent(self, cmdline: str = CMDLINE, cwd: str | None = "/app", **env: str):
        return reader.Agent(cmdline, {"HOME": "/root", **env}, cwd)

    def read(self, agent=None, config_paths=(CONFIG,), **kwargs):
        agent = agent or self.agent()
        profile = reader.harness_reader_for(PROFILES, agent)
        return reader.read_harness_fields(profile, agent, reader.LocalSources(self.root),
                                          config_paths=config_paths, **kwargs)


class GenericReaderTest(Agent):
    def test_no_shipped_profile_matches_so_the_generic_reader_runs(self):
        self.assertIsNone(reader.harness_reader_for(PROFILES, self.agent()))
        results = self.read()
        self.assertEqual(set(results), set(reader.HARNESS_FIELDS))
        self.assertTrue(all(r["harness"] == "generic" for r in results.values()))

    def test_mcp_servers_declared_is_answered_from_mcp_json(self):
        result = self.read()["mcp_servers_declared"]
        self.assertEqual(result["status"], "ANSWERED")
        self.assertEqual(result["source"], f"{CONFIG}/.mcp.json")
        self.assertEqual(set(result["value"]), {"finretail", "files"})
        self.assertEqual(result["value"]["finretail"]["url"], "http://finretail-mcp-server:23004/mcp")
        self.assertEqual(result["value"]["finretail"]["headers"], reader.REDACTED)
        self.assertEqual(result["value"]["files"]["env"], reader.REDACTED)

    def test_the_fields_only_a_profile_can_fill_are_blind_with_unknown_harness(self):
        results = self.read()
        for field in PROFILE_ONLY:
            self.assertTrue(unknown(results[field]), (field, results[field]))
            self.assertIn("no harness profile matched", results[field]["note"])

    def test_the_fields_it_cant_fill_are_blind_with_unknown_harness(self):
        # Only an MCP config: every field but mcp_servers_declared is unknown,
        # never ABSENT (which would say the harness doesn't set it).
        self.remove(f"{CONFIG}/config.json")
        self.remove(f"{CONFIG}/AGENTS.md")
        results = self.read()
        self.assertEqual(results["mcp_servers_declared"]["status"], "ANSWERED")
        for field in set(reader.HARNESS_FIELDS) - {"mcp_servers_declared"}:
            self.assertTrue(unknown(results[field]), (field, results[field]))

    def test_model_provider_and_endpoint_from_model_like_keys(self):
        results = self.read()
        self.assertEqual((results["model_name"]["value"], results["model_name"]["source"]),
                         ("gpt-4o-mini", f"{CONFIG}/config.json (llm.model)"))
        self.assertEqual((results["llm_provider"]["value"], results["llm_provider"]["source"]),
                         ("openai", f"{CONFIG}/config.json (llm.provider)"))
        # The base URL beside the model, never the telemetry endpoint.
        self.assertEqual((results["inference_endpoint"]["value"], results["inference_endpoint"]["source"]),
                         ("https://llm-gateway.example.internal/v1", f"{CONFIG}/config.json (llm.baseUrl)"))

    def test_model_and_base_url_variables_come_first(self):
        agent = self.agent(AGENT_LLM_MODEL="claude-sonnet-4-5", ANTHROPIC_BASE_URL="https://proxy.example/anthropic",
                           TEXT_EMBEDDING_MODEL="text-embedding-3-small", ANTHROPIC_MODEL="claude-opus-4-1")
        results = self.read(agent)
        # The scanner's own variables first (ANTHROPIC_MODEL), then any other
        # *_MODEL; an embedding model is never the agent's model.
        self.assertEqual((results["model_name"]["value"], results["model_name"]["source"]),
                         ("claude-opus-4-1", "$ANTHROPIC_MODEL"))
        self.assertIn("$AGENT_LLM_MODEL", results["model_name"]["note"])
        self.assertNotIn("EMBEDDING", results["model_name"]["note"])
        self.assertEqual((results["inference_endpoint"]["value"], results["inference_endpoint"]["source"]),
                         ("https://proxy.example/anthropic", "$ANTHROPIC_BASE_URL"))
        # A provider key in the config still names the provider.
        self.assertEqual(results["llm_provider"]["value"], "openai")

    def test_a_variable_that_names_no_model_service_is_never_taken(self):
        # A web app's own base URL and a framework's models are not the agent's.
        agent = self.agent(APP_BASE_URL="https://myapp.example.com", API_BASE_URL="https://api.example.com",
                           NEXT_PUBLIC_BASE_URL="https://web.example.com", AUTH_USER_MODEL="accounts.User",
                           DATA_MODEL="v2")
        results = self.read(agent)
        self.assertEqual((results["inference_endpoint"]["value"], results["inference_endpoint"]["source"]),
                         ("https://llm-gateway.example.internal/v1", f"{CONFIG}/config.json (llm.baseUrl)"))
        self.assertEqual(results["model_name"]["value"], "gpt-4o-mini")
        self.assertNotIn("note", results["inference_endpoint"])  # nor listed as also set
        self.remove(f"{CONFIG}/config.json")
        results = self.read(agent)
        for field in ("inference_endpoint", "model_name"):
            self.assertTrue(unknown(results[field]), (field, results[field]))
        # One whose name does say a model service is still taken.
        results = self.read(self.agent(OPENAI_COMPAT_BASE_URL="https://compat.example/v1", AGENT_MODEL="house-model"))
        self.assertEqual(results["inference_endpoint"]["source"], "$OPENAI_COMPAT_BASE_URL")
        self.assertEqual(results["model_name"]["source"], "$AGENT_MODEL")

    def test_the_provider_from_a_vendor_prefix_or_a_variables_name(self):
        self.remove(f"{CONFIG}/config.json")
        results = self.read(self.agent(LLM_MODEL="anthropic/claude-sonnet-4-5"))
        self.assertEqual(results["llm_provider"]["value"], "anthropic")
        self.assertEqual(results["llm_provider"]["source"], "$LLM_MODEL, the model's vendor prefix")
        results = self.read(self.agent(GEMINI_MODEL="gemini-flash-latest"))
        self.assertEqual((results["llm_provider"]["value"], results["llm_provider"]["source"]),
                         ("google", "$GEMINI_MODEL, the variable's name"))
        # A variable that names no vendor says nothing of the provider.
        self.assertTrue(unknown(self.read(self.agent(AGENT_MODEL="house-model"))["llm_provider"]))

    def test_an_endpoint_carrying_a_secret_is_redacted(self):
        results = self.read(self.agent(OPENAI_BASE_URL=f"https://user:{PLACEHOLDER}@llm.example/v1?key={PLACEHOLDER}"),
                            redact_url=scanner.redact_url)
        self.assertEqual(results["inference_endpoint"]["value"], "https://llm.example/v1")

    def test_permission_and_approval_named_keys(self):
        results = self.read()
        allow_deny = results["tool_allow_deny"]
        self.assertEqual(allow_deny["status"], "ANSWERED")
        self.assertEqual(allow_deny["value"], {f"{CONFIG}/config.json": {
            "tools.allow": ["read_file", "getStockPrice"], "tools.deny": ["shell"]}})
        self.assertEqual(results["approval_policy"]["value"], {f"{CONFIG}/config.json": {"approvalMode": "on-request"}})
        self.write(f"{CONFIG}/config.json", {"permissions": {"allow": ["Read"], "defaultMode": "ask"}})
        self.assertEqual(self.read()["tool_allow_deny"]["value"],
                         {f"{CONFIG}/config.json": {"permissions": {"allow": ["Read"], "defaultMode": "ask"}}})

    def test_nothing_under_a_credential_key_is_taken(self):
        # A key under env, headers or auth is flattened into a path that no
        # longer names the credential key, so it must never be taken at all.
        values = ("9f8e7d6c5b4a39281706f5e4d3c2b1a0", "hunter2-plain", "s3cr3tvalue", "482915", "tok-in-provider")
        self.write(f"{CONFIG}/config.json", {
            "env": {"APPROVAL_SIGNING_KEY": values[0], "PERMISSIONS": values[1], "LLM_MODEL": "env-model"},
            "headers": {"X-Approval": values[2]},
            "auth": {"approvalPin": values[3], "permissions": {"allow": ["x"]}},
            "clientSecret": {"approvalMode": values[4], "model": "secret-model"},
        })
        results = self.read()
        self.assertFalse(any(value in json.dumps(results) for value in values), json.dumps(results))
        for field in ("approval_policy", "tool_allow_deny", "model_name"):
            self.assertTrue(unknown(results[field]), (field, results[field]))
        # Beside them, the policy and model the file declares are still read.
        self.write(f"{CONFIG}/config.json", {"env": {"PERMISSIONS": values[1]}, "approvalMode": "on-request",
                                              "model": "gpt-4o-mini"})
        results = self.read()
        self.assertEqual(results["approval_policy"]["value"], {f"{CONFIG}/config.json": {"approvalMode": "on-request"}})
        self.assertEqual(results["model_name"]["value"], "gpt-4o-mini")
        self.assertNotIn(values[1], json.dumps(results))

    def test_an_undeclared_policy_is_unknown_not_restriction(self):
        self.write(f"{CONFIG}/config.json", {"llm": {"model": "gpt-4o-mini"}})
        results = self.read()
        for field in ("tool_allow_deny", "approval_policy"):
            self.assertTrue(unknown(results[field]), results[field])
            self.assertIn("NOT evidence of restriction", results[field]["note"])

    def test_agents_md_is_present_and_its_text_only_with_the_flag(self):
        results = self.read()
        self.assertEqual(results["system_prompt_present"]["value"], {"present": True, "files": [f"{CONFIG}/AGENTS.md"]})
        self.assertEqual((results["system_prompt_text"]["status"], results["system_prompt_text"]["reason"]),
                         ("BLIND", "NOT_COLLECTED_BY_PACK"))
        self.assertNotIn("stock prices", json.dumps(results))
        text = self.read(collect_prompt=True)["system_prompt_text"]
        self.assertIn("You answer questions about stock prices", text["value"][f"{CONFIG}/AGENTS.md"])

    def test_the_agents_own_folders_are_read_and_reported_as_written(self):
        self.remove(f"{CONFIG}/.mcp.json")
        self.remove(f"{CONFIG}/AGENTS.md")
        self.put("/app/.mcp.json", FIXTURES / "mcp.json")
        self.put("/root/AGENTS.md", FIXTURES / "AGENTS.md")
        results = self.read()
        self.assertEqual(results["mcp_servers_declared"]["source"], "$AGENT_CWD/.mcp.json")
        self.assertEqual(results["system_prompt_present"]["source"], ["~/AGENTS.md"])
        self.assertNotIn(str(self.root), json.dumps(results))

    def test_a_config_paths_mcp_json_wins_on_a_name(self):
        self.write("/app/.mcp.json", {"mcpServers": {"finretail": {"url": "http://elsewhere:1/mcp"},
                                                     "extra": {"url": "http://extra:2/mcp"}}})
        result = self.read()["mcp_servers_declared"]
        self.assertEqual(result["value"]["finretail"]["url"], "http://finretail-mcp-server:23004/mcp")
        self.assertIn("extra", result["value"])
        self.assertEqual(result["source"], [f"{CONFIG}/.mcp.json", "$AGENT_CWD/.mcp.json"])

    def test_mcp_servers_in_a_top_level_json_count(self):
        self.remove(f"{CONFIG}/.mcp.json")
        self.write(f"{CONFIG}/config.json", {"mcpServers": {"notes": {"url": "http://notes:9/mcp"}}})
        result = self.read()["mcp_servers_declared"]
        self.assertEqual((result["status"], result["source"]), ("ANSWERED", f"{CONFIG}/config.json (mcpServers)"))

    def test_an_mcp_config_with_no_servers_is_absent_not_blind(self):
        self.write(f"{CONFIG}/.mcp.json", {"mcpServers": {}})
        self.assertEqual(self.read()["mcp_servers_declared"]["status"], "ABSENT")

    def test_an_mcp_config_that_fails_outranks_one_with_no_servers(self):
        # The unreadable one may hold the servers: never "none declared".
        self.write(f"{CONFIG}/.mcp.json", "{not json")
        self.write("/app/.mcp.json", {"mcpServers": {}})
        result = self.read()["mcp_servers_declared"]
        self.assertEqual((result["status"], result["reason"]), ("FAILED", "PARSE_FAILED"))
        self.assertIn(f"{CONFIG}/.mcp.json", result["note"])
        self.assertIn("no MCP server in $AGENT_CWD/.mcp.json", result["note"])

    def test_a_top_level_json_that_fails_may_hold_mcp_servers_too(self):
        # Beside an MCP config with no servers: FAILED, never "none declared".
        self.remove(f"{CONFIG}/.mcp.json")
        self.write(f"{CONFIG}/agent.json", "{not json")
        self.write("/app/.mcp.json", {"mcpServers": {}})
        result = self.read()["mcp_servers_declared"]
        self.assertEqual((result["status"], result["reason"]), ("FAILED", "PARSE_FAILED"))
        self.assertIn(f"{CONFIG}/agent.json", result["note"])
        # With no MCP config anywhere: FAILED, never "no MCP config was found".
        self.remove("/app/.mcp.json")
        result = self.read()["mcp_servers_declared"]
        self.assertEqual((result["status"], result["reason"]), ("FAILED", "PARSE_FAILED"))

    def test_no_mcp_config_is_blind_with_unknown_harness(self):
        self.remove(f"{CONFIG}/.mcp.json")
        result = self.read()["mcp_servers_declared"]
        self.assertTrue(unknown(result), result)
        self.assertIn(f"{CONFIG}/.mcp.json", result["note"])

    def test_invalid_json_gives_failed_with_parse_failed(self):
        self.write(f"{CONFIG}/config.json", "{not json")
        results = self.read()
        for field in ("model_name", "tool_allow_deny"):
            self.assertEqual((results[field]["status"], results[field]["reason"]), ("FAILED", "PARSE_FAILED"))
        # The MCP config is its own file, and still read.
        self.assertEqual(results["mcp_servers_declared"]["status"], "ANSWERED")
        self.write(f"{CONFIG}/.mcp.json", "{not json")
        result = self.read()["mcp_servers_declared"]
        self.assertEqual((result["status"], result["reason"]), ("FAILED", "PARSE_FAILED"))

    def test_secrets_never_reach_the_results(self):
        results = self.read(self.agent(AGENT_LLM_API_KEY=PLACEHOLDER), collect_prompt=True)
        self.assertNotIn(PLACEHOLDER, json.dumps(results))

    def test_a_profiles_agent_never_runs_the_generic_reader(self):
        claude = self.agent("/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe -p hi")
        self.assertTrue(all(r["harness"] == "claude-code" for r in self.read(claude).values()))


class PodModeTest(Agent):
    """The generic reader through pod mode: the config folder on the volume,
    mounted at the agent's path, everything else through the agent's root."""

    def context(self, env: dict[str, str] | None = None) -> dict[str, Any]:
        volume = self.root / CONFIG.lstrip("/")
        subject = {"root": str(self.root), "cmdline": CMDLINE, "env": {"HOME": "/root", **(env or {})}, "cwd": "/app"}
        return {"mode": "pod", "subject": subject, "config_paths": [str(volume)]}

    def attributes(self, existing=None, **kwargs):
        return pod_mode.harness_attributes(self.context(**kwargs), BUILDERS, existing=existing or {}, shapers=SHAPERS)

    def test_pod_mode_fills_what_needs_no_profile_and_names_the_generic_reader(self):
        attributes = self.attributes()
        mcp = attributes["mcp_servers_declared"]
        self.assertEqual(mcp["status"], "ANSWERED")
        self.assertTrue(mcp["method"].startswith("generic reader: "))
        self.assertEqual(sorted(entry["name"] for entry in mcp["value"]), ["files", "finretail"])
        self.assertEqual(attributes["model_name"]["value"], "gpt-4o-mini")
        self.assertEqual(attributes["declared_destinations"]["value"],
                         ["finretail-mcp-server", "llm-gateway.example.internal"])
        for field in PROFILE_ONLY:
            self.assertTrue(unknown(attributes[field]), (field, attributes[field]))
        # An MCP config was read, so tool_schemas is the MCP probe's to report.
        self.assertNotIn("tool_schemas", attributes)
        self.assertNotIn(PLACEHOLDER, json.dumps(attributes))

    def test_tool_schemas_is_blind_not_absent_when_there_is_no_mcp_config(self):
        self.remove(f"{CONFIG}/.mcp.json")
        # What the bundle says on its own: no MCP config at the scanned roots,
        # so no servers and no tools.
        existing = {
            "mcp_servers_declared": evidence_bundle._absent("scanned /root/.plainagent", "declared"),
            "tool_schemas": evidence_bundle._absent("scanned /root/.plainagent", "declared"),
        }
        attributes = self.attributes(existing)
        for field in ("mcp_servers_declared", "tool_schemas"):
            self.assertEqual((attributes[field]["status"], attributes[field]["reason"]), ("BLIND", "UNKNOWN_HARNESS"))
        # With no account of tool_schemas at all, it is added the same way.
        self.assertEqual(self.attributes()["tool_schemas"]["status"], "BLIND")

    def test_tool_schemas_is_failed_not_absent_when_the_mcp_config_fails_to_parse(self):
        self.write(f"{CONFIG}/.mcp.json", "{not json")
        existing = {
            "mcp_servers_declared": evidence_bundle._absent("scanned /root/.plainagent", "declared"),
            "tool_schemas": evidence_bundle._absent("scanned /root/.plainagent", "declared"),
        }
        attributes = self.attributes(existing)
        for field in ("mcp_servers_declared", "tool_schemas"):
            self.assertEqual((attributes[field]["status"], attributes[field]["reason"]), ("FAILED", "PARSE_FAILED"))
        # Beside an MCP config with no servers, too.
        self.write("/app/.mcp.json", {"mcpServers": {}})
        self.assertEqual(self.attributes(existing)["tool_schemas"]["status"], "FAILED")
        # And when what failed is a top-level *.json, which may hold mcpServers.
        self.write(f"{CONFIG}/.mcp.json", {"mcpServers": {}})
        self.write(f"{CONFIG}/agent.json", "{not json")
        attributes = self.attributes(existing)
        for field in ("mcp_servers_declared", "tool_schemas"):
            self.assertEqual((attributes[field]["status"], attributes[field]["reason"]), ("FAILED", "PARSE_FAILED"))

    def test_an_mcp_config_the_bundle_read_itself_leaves_tool_schemas_alone(self):
        self.remove(f"{CONFIG}/.mcp.json")
        servers = scanner.mcp_inventory_entries({"x": {"url": "http://x:1/mcp"}}, "--mcp-config")
        existing = {"mcp_servers_declared": evidence_bundle._answered(servers, "declared", authored_by="subject")}
        attributes = self.attributes(existing)
        self.assertNotIn("tool_schemas", attributes)
        self.assertNotIn("mcp_servers_declared", attributes)  # the bundle's value stands
        # Nor when the bundle's MCP config names only a gateway.
        existing = {"mcp_servers_declared": evidence_bundle._blind("GATEWAY_MANAGED", "declared")}
        attributes = self.attributes(existing)
        self.assertNotIn("tool_schemas", attributes)
        self.assertNotIn("mcp_servers_declared", attributes)

    def test_unknown_replaces_only_a_bundle_account_that_says_not_found(self):
        self.remove(f"{CONFIG}/config.json")
        existing = {
            # Not found: replaced.
            "model_name": evidence_bundle._absent("model not detected in env, config or capture files", "observed"),
            "tool_allow_deny": evidence_bundle._blind("GATEWAY_MANAGED", "declared"),
            "system_prompt_present": evidence_bundle._blind("NOT_COLLECTED_BY_PACK", "observed"),
            # More specific: kept.
            "approval_policy": evidence_bundle._blind("PARSE_FAILED", "declared", note="x.json: bad"),
            # Observed by the scanner itself: kept.
            "tool_names": evidence_bundle._answered(["wireTool"], "observed", authored_by="none"),
        }
        attributes = self.attributes(existing)
        for field in ("model_name", "tool_allow_deny"):
            self.assertTrue(unknown(attributes[field]), (field, attributes[field]))
        self.assertEqual(attributes["system_prompt_present"]["status"], "ANSWERED")  # AGENTS.md
        self.assertNotIn("approval_policy", attributes)
        self.assertNotIn("tool_names", attributes)

    def test_no_agent_process_reads_nothing(self):
        context = dict(self.context(), subject=None)
        self.assertEqual(pod_mode.harness_attributes(context, BUILDERS, shapers=SHAPERS), {})


# ── a whole pod-mode scan ───────────────────────────────────────────────────
# As test_agent_process's PodModeBundleTest scans: the scanner and bundle
# modules registered under their own names for the scan, a fake /proc.

full_scanner = load_private("scan_agent_environment_for_generic_test", SCAN / "scan_agent_environment.py")
full_bundle = load_private("evidence_bundle_for_generic_test", SCAN / "evidence_bundle.py")
_PATCHED = {"scan_agent_environment": full_scanner, "evidence_bundle": full_bundle}


class PodModeScanTest(unittest.TestCase):
    def setUp(self):
        saved = {name: sys.modules.get(name) for name in _PATCHED}
        sys.modules.update(_PATCHED)

        def restore():
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module
        self.addCleanup(restore)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.agent_process = full_scanner._agent_process()
        # The config volume, mounted in the sidecar at the agent's own path
        # (a temporary folder stands for both here).
        self.config = self.tmp / "volume" / ".plainagent"
        self.config.mkdir(parents=True)
        shutil.copyfile(FIXTURES / "config.json", self.config / "config.json")
        shutil.copyfile(FIXTURES / "AGENTS.md", self.config / "AGENTS.md")
        # The fake /proc: the pause process, the agent, the sidecar.
        self.proc = self.tmp / "proc"
        roots = self.tmp / "roots"
        for name in ("pause", "agent", "sidecar"):
            (roots / name).mkdir(parents=True)
        (self.proc / "self").mkdir(parents=True)
        (self.proc / "self" / "root").symlink_to(roots / "sidecar")
        for pid, name, cmdline, env in (
                (1, "pause", ["/pause"], {}),
                (7, "agent", ["python3", "-m", "plainagent", "serve"],
                 {"HOME": "/root", "PATH": "/usr/bin", "AGENT_LLM_API_KEY": PLACEHOLDER}),
                (20, "sidecar", ["python3", "scan_agent_environment.py", "--mode", "pod"], {})):
            entry = self.proc / str(pid)
            entry.mkdir()
            (entry / "root").symlink_to(roots / name)
            (entry / "cmdline").write_text("\x00".join(cmdline) + "\x00")
            (entry / "environ").write_text("".join(f"{k}={v}\x00" for k, v in env.items()))
            (entry / "status").write_text(f"Name:\t{cmdline[0]}\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
        podinfo = self.tmp / "podinfo"
        podinfo.mkdir()
        (podinfo / "labels").write_text('app="agent-plain"\npod-template-hash="58cd78b55d"\n')
        self.sidecar_env = {
            "POD_NAME": "agent-plain-58cd78b55d-48jcw", "POD_NAMESPACE": "gke-test",
            "POD_UID": "f3fe5e58-b328-40cb-9b03-1acf558d773d", "NODE_NAME": "node-1",
            "RAIL_POD_INFO_DIR": str(podinfo), "HOME": str(self.tmp / "sidecar-home"),
        }

    def scan(self) -> dict[str, Any]:
        clean = {k: v for k, v in os.environ.items()
                 if not k.startswith(("RAIL_", "POD_", "GIT_")) and k not in ("NODE_NAME",)}
        args = full_scanner.make_parser().parse_args(
            ["--mode", "pod", "--config-path", str(self.config), "--no-feature-file", "--host-id", "gke-test"])
        with mock.patch.dict(os.environ, {**clean, **self.sidecar_env}, clear=True), \
                mock.patch.object(self.agent_process, "PROC_DIR", self.proc), \
                contextlib.redirect_stderr(io.StringIO()):
            context, payload, identity = full_scanner.scan(args)
            return full_bundle.build_verified_bundle(args, context, payload, identity)

    def test_a_scan_of_no_known_harness_with_no_mcp_config_passes_verify_bundle(self):
        bundle = self.scan()  # build_verified_bundle runs verify_bundle
        attributes = bundle["attributes"]
        self.assertEqual(attributes["model_name"]["value"], "gpt-4o-mini")
        self.assertTrue(attributes["model_name"]["method"].startswith("generic reader: "))
        self.assertEqual(attributes["system_prompt_present"]["status"], "ANSWERED")
        for field in ("harness_identity", "tool_names", "skills_inventory", "mcp_servers_declared", "tool_schemas"):
            self.assertEqual((attributes[field]["status"], attributes[field].get("reason")),
                             ("BLIND", "UNKNOWN_HARNESS"), field)
        self.assertNotIn(PLACEHOLDER, json.dumps(bundle))

    def test_a_scan_of_no_known_harness_answers_mcp_servers_declared(self):
        shutil.copyfile(FIXTURES / "mcp.json", self.config / ".mcp.json")
        attributes = self.scan()["attributes"]
        self.assertEqual(attributes["mcp_servers_declared"]["status"], "ANSWERED")
        self.assertIn("finretail", [entry["name"] for entry in attributes["mcp_servers_declared"]["value"]])
        self.assertNotEqual((attributes.get("tool_schemas") or {}).get("reason"), "UNKNOWN_HARNESS")


if __name__ == "__main__":
    unittest.main()

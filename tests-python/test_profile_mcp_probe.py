"""RC-531: tool_schemas probes the MCP servers each harness profile declares.

Task 7 (RC-511) probes the servers in .mcp.json and the environment. Tasks
4 and 5 (RC-516, RC-526) read OpenClaw's and Claude Code's own server lists
into mcp_servers_declared. Here those lists feed the probe in pod mode, as
build_registration_payload runs it: pod_mode.declared_mcp_servers, then
collect_skills without headers, then cap_tool_schemas and the attribute.

Each harness is laid out from its fixtures in an agent root, with its MCP
server pointed at a local fake MCP server (test_mcp_tool_discovery's).
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "tools" / "scan"
TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCAN))
import evidence_bundle  # noqa: E402
import scan_agent_environment as scanner  # noqa: E402

_spec = importlib.util.spec_from_file_location("rc531_mcp_discovery", TESTS / "test_mcp_tool_discovery.py")
discovery = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(discovery)
FakeMcpServer = discovery.FakeMcpServer

pod_mode = scanner._pod_mode()
KEY = "sk-live-" + "a1B2c3D4" * 4
TOOLS = [
    {"name": "getInterestRate", "inputSchema": {"type": "object", "properties": {"product": {"type": "string"}}}},
    {"name": "listBranches", "inputSchema": {"type": "object"}},
]
OTHER_TOOLS = [{"name": "searchDocs", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}}]


class AgentRoot(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "agent-root"
        self.volume = self.tmp / "volume"  # the config volume: --config-path, where .mcp.json is read
        self.volume.mkdir()

    def path(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def write(self, path: str, content) -> None:
        self.path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path(path).write_text(content if isinstance(content, str) else json.dumps(content))

    def mcp_json(self, servers: dict) -> None:
        (self.volume / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))

    def probe(self, subject: dict) -> tuple[dict | None, list[dict], list[dict], dict]:
        """As build_registration_payload does in pod mode: (the profile's
        declaration, skills, tool_schemas' servers, the attribute)."""
        context = {"mode": "pod", "subject": subject, "config_paths": [str(self.volume)]}
        declared = pod_mode.declared_mcp_servers(context)
        schemas: list[dict] = []
        skills = scanner.collect_skills(pod_mode.default_mcp_paths([self.volume]), {}, send_headers=False,
                                        schemas=schemas, declared=declared)
        servers = scanner.cap_tool_schemas(schemas)
        attribute = evidence_bundle.tool_schemas_attribute(servers, [], unread=scanner.unread_mcp_config(declared))
        return declared, skills, servers, attribute


class OpenClawTest(AgentRoot):
    CMDLINE = "node /usr/local/bin/openclaw gateway --allow-unconfigured"

    def openclaw(self, servers: dict) -> dict:
        config = json.loads((TESTS / "fixtures" / "openclaw" / "openclaw.json").read_text())
        config["mcp"]["servers"] = servers
        self.write("/root/.openclaw/openclaw.json", config)
        return {"root": str(self.root), "cmdline": self.CMDLINE, "env": {"HOME": "/root"}}

    def test_a_server_in_openclaw_json_is_probed_without_a_credential(self):
        with FakeMcpServer(TOOLS) as server:
            subject = self.openclaw({"finretail": {
                "url": server.url, "transport": "streamable-http", "headers": {"Authorization": f"Bearer {KEY}"}}})
            declared, skills, servers, attribute = self.probe(subject)
        self.assertEqual(declared["harness"], "openclaw")
        self.assertEqual(set(server.seen_authorization), {None})
        self.assertEqual(attribute["status"], "ANSWERED")
        (entry,) = attribute["value"]
        self.assertEqual((entry["server"], entry["source"], entry["reachability"]),
                         ("finretail", "openclaw profile", "reached"))
        self.assertEqual([t["inputSchema"] for t in entry["tools"]], [t["inputSchema"] for t in TOOLS])
        self.assertEqual(sorted(s["name"] for s in skills), ["getInterestRate", "listBranches"])
        self.assertNotIn(KEY, json.dumps([skills, servers, attribute]))

    def test_a_server_in_both_openclaw_json_and_mcp_json_is_probed_once_and_both_lists_count(self):
        with FakeMcpServer(TOOLS) as server, FakeMcpServer(OTHER_TOOLS) as other:
            subject = self.openclaw({"finretail": {"url": server.url}})
            self.mcp_json({"finretail": {"url": server.url}, "docs": {"url": other.url}})
            _, _, servers, attribute = self.probe(subject)
        self.assertEqual(len(server.seen_authorization), 2)  # initialize and tools/list, once
        self.assertEqual([(s["server"], s["source"]) for s in servers],
                         [("docs", ".mcp.json"), ("finretail", "openclaw profile")])
        self.assertEqual(attribute["status"], "ANSWERED")

    def test_a_server_whose_url_path_carries_a_key_is_never_asked(self):
        with FakeMcpServer(TOOLS) as server:
            subject = self.openclaw({"gateway": {"url": server.url.replace("/mcp", f"/mcp/{KEY}/sse")}})
            _, _, servers, attribute = self.probe(subject)
        self.assertEqual(server.seen_authorization, [])  # no request at all
        self.assertEqual(servers[0]["reachability"], "auth_refused")
        self.assertEqual((attribute["status"], attribute["reason"]), ("BLIND", "PRIVATE_STORE"))
        self.assertNotIn(KEY, json.dumps([servers, attribute]))

    def test_a_key_in_the_query_or_userinfo_is_never_asked(self):
        with FakeMcpServer(TOOLS) as server:
            subject = self.openclaw({
                "q": {"url": f"{server.url}?api_key={KEY}"},
                "u": {"url": server.url.replace("http://", f"http://agent:{KEY}@")},
            })
            _, _, servers, attribute = self.probe(subject)
        self.assertEqual(server.seen_authorization, [])  # no request at all
        self.assertEqual([(s["server"], s["reachability"]) for s in servers],
                         [("q", "auth_refused"), ("u", "auth_refused")])
        self.assertEqual((attribute["status"], attribute["reason"]), ("BLIND", "PRIVATE_STORE"))
        self.assertNotIn(KEY, json.dumps([servers, attribute]))

    def test_a_server_named_like_a_credential_is_still_probed_once(self):
        # Rail review (RC-511): the bundle's redaction hides the whole config
        # of a server named like a credential, which once left the probe a
        # "[redacted]" URL: auth_refused, PRIVATE_STORE, and its .mcp.json
        # entry skipped. The probe reads the profile's value unredacted.
        with FakeMcpServer(TOOLS) as secrets, FakeMcpServer(OTHER_TOOLS) as github:
            subject = self.openclaw({"secrets-manager": {"url": secrets.url},
                                     "github-token": {"url": github.url}})
            self.mcp_json({"secrets-manager": {"url": secrets.url}})
            _, _, servers, attribute = self.probe(subject)
        self.assertEqual([(s["server"], s["reachability"]) for s in servers],
                         [("github-token", "reached"), ("secrets-manager", "reached")])
        self.assertEqual(len(secrets.seen_authorization), 2)  # initialize and tools/list, once
        self.assertEqual(attribute["status"], "ANSWERED")
        # The bundle's own mcp_servers_declared still hides those configs.
        context = {"mode": "pod", "subject": subject, "config_paths": [str(self.volume)]}
        builders = {"answered": evidence_bundle._answered, "blind": evidence_bundle._blind,
                    "absent": evidence_bundle._absent, "failed": evidence_bundle._failed,
                    "partial": evidence_bundle._partial}
        declared_attribute = pod_mode.harness_attributes(context, builders)["mcp_servers_declared"]
        self.assertNotIn(secrets.url, json.dumps(declared_attribute))

    def test_headers_and_env_never_reach_the_probe(self):
        subject = self.openclaw({"fin": {
            "url": "http://mcp:8080/mcp", "transport": "streamable-http",
            "headers": {"Authorization": f"Bearer {KEY}"}, "env": {"API_KEY": KEY}, "oauth": {"clientSecret": KEY}}})
        declared = pod_mode.declared_mcp_servers(
            {"mode": "pod", "subject": subject, "config_paths": [str(self.volume)]})
        self.assertEqual(declared["value"], {"fin": {"url": "http://mcp:8080/mcp", "transport": "streamable-http"}})

    def test_openclaw_json_that_cannot_be_parsed_is_blind_not_absent(self):
        self.write("/root/.openclaw/openclaw.json", "{not json")
        subject = {"root": str(self.root), "cmdline": self.CMDLINE, "env": {"HOME": "/root"}}
        _, _, servers, attribute = self.probe(subject)
        self.assertEqual(servers, [])
        self.assertEqual((attribute["status"], attribute["reason"]), ("BLIND", "PARSE_FAILED"))


class ClaudeCodeTest(AgentRoot):
    PACKAGE = "/usr/local/lib/node_modules/@anthropic-ai/claude-code"

    def claude(self, state: dict) -> dict:
        self.write("/root/.claude.json", state)
        self.write(f"{self.PACKAGE}/package.json", (TESTS / "fixtures" / "claude-code" / "package.json").read_text())
        return {"root": str(self.root), "cmdline": f"{self.PACKAGE}/bin/claude.exe -p hi",
                "env": {"HOME": "/root"}, "cwd": "/work"}

    def test_a_local_scope_server_in_claude_json_is_probed(self):
        with FakeMcpServer(TOOLS) as user, FakeMcpServer(OTHER_TOOLS) as local:
            subject = self.claude({
                "mcpServers": {"finretail": {"type": "http", "url": user.url}},
                "projects": {"/work": {"mcpServers": {"docs": {"type": "http", "url": local.url}}}},
            })
            declared, _, servers, attribute = self.probe(subject)
        self.assertEqual(declared["harness"], "claude-code")
        self.assertEqual(attribute["status"], "ANSWERED")
        self.assertEqual([(s["server"], s["reachability"]) for s in servers],
                         [("docs", "reached"), ("finretail", "reached")])
        docs = next(s for s in servers if s["server"] == "docs")
        self.assertEqual(docs["tools"][0]["inputSchema"], OTHER_TOOLS[0]["inputSchema"])

    def test_with_managed_mcp_json_only_the_managed_servers_are_probed(self):
        with FakeMcpServer(TOOLS) as managed, FakeMcpServer(OTHER_TOOLS) as project, \
                FakeMcpServer(OTHER_TOOLS) as volume:
            subject = self.claude({"mcpServers": {}})
            self.write("/etc/claude-code/managed-mcp.json", {"mcpServers": {"finretail": {"url": managed.url}}})
            self.write("/work/.mcp.json", {"mcpServers": {"docs": {"url": project.url}}})
            self.mcp_json({"other": {"url": volume.url}})
            declared, skills, servers, attribute = self.probe(subject)
        self.assertTrue(declared["exclusive"])
        self.assertEqual([s["server"] for s in servers], ["finretail"])
        self.assertEqual((project.seen_authorization, volume.seen_authorization), ([], []))
        self.assertEqual({s["server"] for s in skills}, {"finretail"})
        self.assertEqual(attribute["status"], "ANSWERED")

    def test_the_bundles_mcp_servers_declared_does_not_carry_the_exclusive_mark(self):
        with FakeMcpServer(TOOLS) as managed:
            subject = self.claude({})
            self.write("/etc/claude-code/managed-mcp.json", {"mcpServers": {"finretail": {"url": managed.url}}})
            context = {"mode": "pod", "subject": subject, "config_paths": [str(self.volume)]}
            builders = {"answered": evidence_bundle._answered, "blind": evidence_bundle._blind,
                        "absent": evidence_bundle._absent, "failed": evidence_bundle._failed,
                        "partial": evidence_bundle._partial}
            attributes = pod_mode.harness_attributes(context, builders)
        self.assertNotIn("exclusive", attributes["mcp_servers_declared"])


class NoProfileTest(AgentRoot):
    def test_without_a_matching_profile_mcp_json_is_probed_as_before(self):
        with FakeMcpServer(TOOLS) as server:
            self.mcp_json({"finretail": {"url": server.url, "headers": {"Authorization": f"Bearer {KEY}"}}})
            subject = {"root": str(self.root), "cmdline": "python3 agent.py", "env": {"HOME": "/root"}}
            declared, _, servers, attribute = self.probe(subject)
        self.assertIsNone(declared)
        self.assertEqual(set(server.seen_authorization), {None})
        self.assertEqual([(s["server"], s["source"]) for s in servers], [("finretail", ".mcp.json")])
        self.assertEqual(attribute["status"], "ANSWERED")

    def test_without_an_agent_process_nothing_is_declared(self):
        self.assertIsNone(pod_mode.declared_mcp_servers({"mode": "pod", "subject": None, "config_paths": []}))


class UrlCredentialTest(unittest.TestCase):
    def test_what_counts_as_a_credential_in_a_url(self):
        carries = [
            "http://user:pass@mcp:8080/mcp",
            f"http://mcp:8080/mcp?api_key={KEY}",
            "http://mcp:8080/mcp?token=abc",
            f"http://mcp:8080/mcp?x={KEY}",
            f"https://gateway.example.com/mcp/{KEY}/sse",
            "https://gateway.example.com/mcp/[redacted]/sse",
        ]
        clean = [
            "http://finretail-mcp-server:23004/mcp",
            "http://mcp:8080/mcp/",
            "http://mcp:8080/mcp?transport=sse",
            "https://mcp.example.com/v1/tools",
        ]
        for url in carries:
            self.assertTrue(scanner.url_carries_credential(url), url)
        for url in clean:
            self.assertFalse(scanner.url_carries_credential(url), url)

    def test_the_env_declared_server_gets_the_same_check_in_pod_mode(self):
        # Rail review (RC-511): AGENT_MCP_URL, read from the agent's own
        # environment in pod mode, skipped the credential check.
        with FakeMcpServer(TOOLS) as server:
            for url in (f"{server.url}?api_key={KEY}", server.url.replace("/mcp", f"/mcp/{KEY}")):
                schemas: list[dict] = []
                env = {scanner.ENV_MCP_NAME_KEY: "envsrv", scanner.ENV_MCP_URL_KEY: url}
                skills = scanner.collect_skills([], env, send_headers=False, schemas=schemas)
                self.assertEqual((schemas[0]["server"], schemas[0]["reachability"]), ("envsrv", "auth_refused"), url)
                self.assertEqual(skills[0]["reachability"], "auth_refused")
            self.assertEqual(server.seen_authorization, [])  # neither URL was asked
            schemas = []
            scanner.collect_skills([], {scanner.ENV_MCP_NAME_KEY: "envsrv", scanner.ENV_MCP_URL_KEY: server.url},
                                   send_headers=False, schemas=schemas)
        self.assertEqual(schemas[0]["reachability"], "reached")  # a clean URL still is
        self.assertEqual(len(server.seen_authorization), 2)

    def test_self_and_docker_mode_still_ask_a_url_with_a_key(self):
        with FakeMcpServer(TOOLS) as server:
            skills = scanner.mcp_server_skills("gw", {"url": f"{server.url}?api_key={KEY}"}, "a.json")
        self.assertEqual(len(server.seen_authorization), 2)
        self.assertEqual(skills[0]["reachability"], "reached")


if __name__ == "__main__":
    unittest.main()

"""RC-510: the shared harness reader reads any harness's fields from its profile.

The reader (tools/scan/gke/harness/reader.py) is tested with a made-up harness,
"toyagent", and local files; no real harness's profile is involved (those are
tasks 4 and 5). The pod-mode side (tools/scan/gke/harness/harness_sources.py) is
tested against a folder standing in for the agent's root and one for the
config volume.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "tools" / "scan"


def load(name: str, path: Path):
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(SCAN))
reader = load("harness_reader", SCAN / "gke" / "harness" / "reader.py")
harness_sources = load("gke_harness_sources", SCAN / "gke" / "harness" / "harness_sources.py")
pod_mode = load("gke_pod_mode", SCAN / "gke" / "pod_mode.py")
import evidence_bundle  # noqa: E402
import scan_agent_environment as scanner  # noqa: E402

SHAPERS = {"mcp_inventory_entries": scanner.mcp_inventory_entries, "normalize_skill": scanner.normalize_skill,
           "merge_skill_lists": scanner.merge_skill_lists, "url_host": scanner.url_host}

BUILDERS = {"answered": evidence_bundle._answered, "blind": evidence_bundle._blind,
            "absent": evidence_bundle._absent, "failed": evidence_bundle._failed,
            "partial": evidence_bundle._partial}

# A made-up harness. Its sources are listed highest precedence first: a
# project file over the user's own, and a path an environment variable names
# over both.
TOY = {
    "harness": "toyagent",
    "markers": {"commands": ["toyagent"], "env": ["TOYAGENT_HOME"]},
    "sources": [
        {"path": "$TOY_CONFIG"},
        {"path": "/work/.toy/settings.json"},
        {"path": "~/.toy/settings.json"},
    ],
    "fields": {
        "harness_identity": "version",
        "model_name": ["model.primary", "model"],
        "inference_endpoint": "endpoint",
        "mcp_servers_declared": {"paths": ["mcp.servers"], "merge": "union"},
        "tool_allow_deny": {"keys": {"allow": "tools.allow", "deny": "tools.deny"}},
        "approval_policy": "approvals",
        "llm_provider": {"hook": "toy_provider"},
    },
    "workspace": {
        "prompt_files": ["/work/TOY.md", "~/.toy/TOY.md"],
        "skills": ["~/.toy/skills"],
        "transcripts": {"folders": ["~/.toy/sessions"], "files": "*.jsonl", "tool_name": "call.name"},
    },
}


@reader.hook("toy_provider")
def _toy_provider(ctx, field, spec):
    # A format no key path reaches: here, a one-line text file.
    path = ctx.agent.expand("~/.toy/provider.txt")
    text = ctx.sources.read_text(path, 100) if path else None
    if text is None:
        return ctx.result("ABSENT", field, method=f"{ctx.harness}: no provider.txt")
    return ctx.result("ANSWERED", field, value=text.strip(), source=path)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "agent-root"
        self.home = self.root / "home" / "toy"
        (self.home / ".toy").mkdir(parents=True)
        (self.root / "work" / ".toy").mkdir(parents=True)
        self.agent = reader.Agent("node /usr/bin/toyagent serve", {"HOME": "/home/toy"})

    def write(self, path: str, content) -> Path:
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content if isinstance(content, str) else json.dumps(content))
        return target

    def read(self, profile=TOY, agent=None, **kwargs):
        return reader.read_harness_fields(profile, agent or self.agent, reader.LocalSources(self.root), **kwargs)


class SharedReaderTest(Fixture):
    def test_each_field_is_answered_with_its_source_named(self):
        self.write("/home/toy/.toy/settings.json", {
            "version": "toyagent 1.2.0", "model": {"primary": "toy-large"},
            "endpoint": "https://llm.example/v1", "mcp": {"servers": {"files": {"url": "http://files:9000/mcp"}}},
            "tools": {"allow": ["read"], "deny": ["shell"]}, "approvals": {"mode": "ask"}})
        self.write("/home/toy/.toy/provider.txt", "example-ai\n")
        self.write("/work/TOY.md", "# You are a toy\n")
        self.write("/home/toy/.toy/skills/summarize/SKILL.md", "---\nname: summarize\ndescription: Summarize a file\n---\n")
        self.write("/home/toy/.toy/sessions/a.jsonl",
                   '{"call": {"name": "read"}}\n{"call": {"name": "read"}}\n{"call": {"name": "shell"}}\n')
        results = self.read()
        user = "~/.toy/settings.json"  # as the profile writes it, never expanded
        expected = {"harness_identity": "toyagent 1.2.0", "model_name": "toy-large",
                    "inference_endpoint": "https://llm.example/v1",
                    "mcp_servers_declared": {"files": {"url": "http://files:9000/mcp"}},
                    "tool_allow_deny": {"allow": ["read"], "deny": ["shell"]}, "approval_policy": {"mode": "ask"}}
        for field, value in expected.items():
            self.assertEqual((results[field]["status"], results[field]["value"], results[field]["source"]),
                             ("ANSWERED", value, user), field)
        self.assertEqual(results["llm_provider"]["value"], "example-ai")
        self.assertEqual(results["system_prompt_present"]["value"], {"present": True, "files": ["/work/TOY.md"]})
        self.assertEqual(results["skills_inventory"]["value"],
                         [{"name": "summarize", "description": "Summarize a file", "path": "~/.toy/skills/summarize"}])
        # The bundle's shape: sorted names, a floor, not a count (evidence_bundle.py).
        self.assertEqual(results["tool_names"]["value"], ["read", "shell"])
        self.assertTrue(all(r["harness"] == "toyagent" for r in results.values()))

    def test_a_higher_precedence_source_overrides_a_lower_one(self):
        self.write("/home/toy/.toy/settings.json", {"model": "user-model", "endpoint": "https://user.example"})
        self.write("/work/.toy/settings.json", {"model": "project-model"})
        results = self.read()
        self.assertEqual((results["model_name"]["value"], results["model_name"]["source"]),
                         ("project-model", "/work/.toy/settings.json"))
        # A key only the lower source sets still comes from it.
        self.assertEqual(results["inference_endpoint"]["source"], "~/.toy/settings.json")
        # A path an environment variable names comes first of all.
        self.write("/etc/toy-override.json", {"model": "override-model"})
        agent = reader.Agent("toyagent", {"HOME": "/home/toy", "TOY_CONFIG": "/etc/toy-override.json"})
        self.assertEqual(self.read(agent=agent)["model_name"]["value"], "override-model")

    def test_union_merges_across_sources_with_the_higher_one_winning(self):
        self.write("/home/toy/.toy/settings.json", {"mcp": {"servers": {"a": {"url": "http://user-a"}, "b": {"url": "http://b"}}}})
        self.write("/work/.toy/settings.json", {"mcp": {"servers": {"a": {"url": "http://project-a"}}}})
        result = self.read()["mcp_servers_declared"]
        self.assertEqual(result["value"], {"a": {"url": "http://project-a"}, "b": {"url": "http://b"}})
        self.assertEqual(result["source"], ["/work/.toy/settings.json", "~/.toy/settings.json"])

    def test_a_missing_source_is_skipped_and_an_unset_field_is_absent(self):
        # Only the user file exists; it doesn't set an endpoint.
        self.write("/home/toy/.toy/settings.json", {"model": "toy-large"})
        results = self.read()
        self.assertEqual(results["model_name"]["status"], "ANSWERED")
        self.assertEqual(results["inference_endpoint"]["status"], "ABSENT")
        self.assertIn("~/.toy/settings.json", results["inference_endpoint"]["method"])

    def test_an_undeclared_policy_is_blind_never_absent(self):
        # As evidence_bundle.py reports them: no declared policy is not
        # evidence of restriction, so never "collected, nothing there".
        self.write("/home/toy/.toy/settings.json", {"model": "toy-large"})
        results = self.read()
        for field in ("approval_policy", "tool_allow_deny"):
            self.assertEqual((results[field]["status"], results[field]["reason"]), ("BLIND", "GATEWAY_MANAGED"), field)
            self.assertIn("absence is NOT evidence of restriction", results[field]["note"])

    def test_no_readable_source_is_blind_with_no_source_access(self):
        results = self.read()
        self.assertEqual((results["model_name"]["status"], results["model_name"]["reason"]), ("BLIND", "NO_SOURCE_ACCESS"))
        self.assertEqual(results["tool_names"]["reason"], "NO_SOURCE_ACCESS")
        self.assertEqual(results["skills_inventory"]["reason"], "NO_SOURCE_ACCESS")

    def test_invalid_json_gives_failed_with_parse_failed(self):
        self.write("/home/toy/.toy/settings.json", "{not json")
        result = self.read()["model_name"]
        self.assertEqual((result["status"], result["reason"]), ("FAILED", "PARSE_FAILED"))
        # A lower source still answers, and says the higher one didn't parse.
        self.write("/work/.toy/settings.json", "[[[")
        self.write("/home/toy/.toy/settings.json", {"model": "toy-large"})
        result = self.read()["model_name"]
        self.assertEqual(result["status"], "ANSWERED")
        self.assertIn("could not be parsed", result["note"])

    def test_deep_nesting_is_a_parse_failure_not_a_crash(self):
        self.write("/home/toy/.toy/settings.json", '{"model": ' + "[" * 2000 + "]" * 2000 + "}")
        self.assertEqual(self.read()["model_name"]["reason"], "PARSE_FAILED")

    def test_a_hook_runs_for_its_format(self):
        self.write("/home/toy/.toy/provider.txt", "example-ai")
        self.assertEqual(self.read()["llm_provider"]["source"], "/home/toy/.toy/provider.txt")
        missing = dict(TOY, fields={"llm_provider": {"hook": "no_such_hook"}})
        self.assertEqual(self.read(missing)["llm_provider"]["status"], "FAILED")

    def test_an_agent_no_profile_matches_gets_unknown_harness(self):
        other = reader.Agent("python3 some_other_agent.py", {"HOME": "/home/toy"})
        self.assertIsNone(reader.harness_reader_for([TOY], other))
        results = self.read(profile=None, agent=other)
        self.assertEqual(set(results), set(reader.HARNESS_FIELDS))
        self.assertTrue(all((r["status"], r["reason"]) == ("BLIND", "UNKNOWN_HARNESS") for r in results.values()))

    def test_adding_a_profile_needs_no_change_to_the_reader(self):
        folder = self.tmp / "profiles"
        folder.mkdir()
        (folder / "toyagent.json").write_text(json.dumps(TOY))
        (folder / "otheragent.json").write_text(json.dumps({
            "harness": "otheragent", "markers": {"commands": ["otheragent"]},
            "sources": [{"path": "~/.other.json"}], "fields": {"model_name": "llm"}}))
        self.write("/home/toy/.other.json", {"llm": "other-model"})
        profiles = reader.load_profiles(folder)
        agent = reader.Agent("otheragent run", {"HOME": "/home/toy"})
        profile = reader.harness_reader_for(profiles, agent)
        self.assertEqual(profile["harness"], "otheragent")
        self.assertEqual(self.read(profile, agent)["model_name"]["value"], "other-model")
        # A marker in the environment matches too.
        by_env = reader.Agent("node server.js", {"TOYAGENT_HOME": "/x"})
        self.assertEqual(reader.harness_reader_for(profiles, by_env)["harness"], "toyagent")

    def test_a_field_the_profile_doesnt_name_is_not_collected(self):
        minimal = {"harness": "minimal", "markers": {"commands": ["minimal"]}, "fields": {}}
        self.assertEqual(self.read(minimal)["model_name"]["reason"], "NOT_COLLECTED_BY_PACK")


class SafetyTest(Fixture):
    def test_credentials_never_reach_a_value(self):
        self.write("/home/toy/.toy/settings.json", {
            "endpoint": "https://user:pass@llm.example/v1?api_key=sk-placeholder-not-real",
            "mcp": {"servers": {"files": {"url": "http://files/mcp", "headers": {"Authorization": "Bearer x"},
                                          "env": {"FILES_TOKEN": "t"}, "apiKey": "k"}}}})
        results = self.read()
        self.assertEqual(results["inference_endpoint"]["value"], "https://llm.example/v1")
        # The credential keys stay, so the server's shape is still reported; only their values go.
        self.assertEqual(results["mcp_servers_declared"]["value"], {"files": {
            "url": "http://files/mcp", "headers": "[redacted]", "env": "[redacted]", "apiKey": "[redacted]"}})
        text = json.dumps(results)
        for secret in ("pass", "sk-placeholder-not-real", "Bearer x", "FILES_TOKEN", '"k"'):
            self.assertNotIn(secret, text)

    def test_credentials_in_values_are_scrubbed_not_just_credential_keys(self):
        self.write("/home/toy/.toy/settings.json", {"mcp": {"servers": {
            "db": {"command": "mcp-postgres", "args": ["postgres://admin:pw-db-placeholder@db:5432/app"]},
            "cache": {"url": "redis://:pw-redis-placeholder@cache:6379/0"},
            "search": {"command": "mcp-search", "args": ["--api-key", "search-key-placeholder", "--region", "us"]},
            "git": {"command": "mcp-git", "args": ["--token=ghp_placeholderplaceholder1234", "--repo", "x"]},
            "notes": {"description": "calls https://u:p@api.example/v1?key=q-placeholder with Bearer bearer-placeholder"},
            "aws": {"command": "mcp-aws", "args": ["AWS_SECRET_ACCESS_KEY=aws-placeholder", "AKIAABCDEFGHIJKLMNOP"]},
            "llm": {"command": "mcp-llm", "args": ["sk-proj-placeholderplaceholder"]},
        }}})
        value = self.read()["mcp_servers_declared"]["value"]
        text = json.dumps(value)
        for secret in ("pw-db-placeholder", "pw-redis-placeholder", "search-key-placeholder",
                       "ghp_placeholderplaceholder1234", "q-placeholder", "bearer-placeholder", ":p@",
                       "aws-placeholder", "AKIAABCDEFGHIJKLMNOP", "sk-proj-placeholderplaceholder"):
            self.assertNotIn(secret, text)
        # What isn't a credential survives.
        self.assertEqual(value["db"]["args"], ["postgres://db:5432/app"])
        self.assertEqual(value["search"]["args"], ["--api-key", "[redacted]", "--region", "us"])
        self.assertIn("https://api.example/v1", value["notes"]["description"])

    def test_names_that_look_like_credentials_survive(self):
        # MCP server names are keys: none may be dropped (gugunund's review on #124).
        servers = {"github-auth": {"url": "http://gh/mcp"}, "keycloak": {"url": "http://kc/mcp"},
                   "monkeytype": {"command": "mt"}, "token-proxy": {"url": "http://tp/mcp"},
                   "auth-service": {"url": "http://as/mcp"}, "fs": {"command": "fs-mcp"}}
        self.write("/home/toy/.toy/settings.json", {"mcp": {"servers": servers}})
        self.assertEqual(self.read()["mcp_servers_declared"]["value"], servers)
        # A key that is a credential's name keeps its place, and so does the shape
        # of an object under it, with every plain value in it redacted.
        self.assertEqual(reader.redact({"github-token": {"url": "http://x"}, "maxTokens": 8192, "AUTH_TOKEN": "t",
                                        "client_secret": "s", "api_key": "k"}),
                         {"github-token": {"url": "[redacted]"}, "maxTokens": 8192, "AUTH_TOKEN": "[redacted]",
                          "client_secret": "[redacted]", "api_key": "[redacted]"})

    def test_a_prompt_file_path_used_as_a_key_survives(self):
        self.write("/workspace/auth-service/AGENTS.md", "# Auth service agent\n")
        profile = dict(TOY, workspace={"prompt_files": ["/workspace/auth-service/AGENTS.md"]})
        text = self.read(profile, collect_prompt=True)["system_prompt_text"]["value"]
        self.assertEqual(text, {"/workspace/auth-service/AGENTS.md": "# Auth service agent\n"})

    def test_no_environment_value_reaches_a_reported_path(self):
        # The agent's HOME and $TOY_CONFIG find the files; neither is reported.
        root_home = self.root / "home" / "home-value-placeholder"
        (root_home / ".toy" / "skills" / "s1").mkdir(parents=True)
        (root_home / ".toy" / "skills" / "s1" / "SKILL.md").write_text("x")
        (root_home / ".toy" / "sessions").mkdir()
        (root_home / ".toy" / "sessions" / "a.jsonl").write_text('{"call": {"name": "read"}}\n')
        self.write("/etc/config-value-placeholder.json", "{not json")
        self.write("/home/home-value-placeholder/.toy/settings.json", {"model": "toy-large"})
        agent = reader.Agent("toyagent", {"HOME": "/home/home-value-placeholder",
                                          "TOY_CONFIG": "/etc/config-value-placeholder.json"})
        results = self.read(agent=agent)
        self.assertEqual(results["model_name"]["value"], "toy-large")
        self.assertIn("$TOY_CONFIG", results["model_name"]["note"])  # the higher source that didn't parse
        for result in results.values():
            reported = json.dumps({k: v for k, v in result.items() if k in ("source", "method", "note", "value")})
            self.assertNotIn("value-placeholder", reported, result)

    def test_a_path_ending_at_a_credential_key_is_redacted_whole(self):
        # get_path pulls the value out from under its key, so the path itself is checked.
        self.write("/home/toy/.toy/settings.json", {
            "mcp": {"servers": {"g": {"env": {"MY_PASSWORD_X": "hunter2plain"}}}},
            "env": {"BASE_URL": "https://llm.example/v1", "OTHER": "o"}})
        profile = dict(TOY, fields={"approval_policy": "mcp.servers.*.env",
                                    "tool_allow_deny": {"keys": {"allow": "env.*", "deny": "mcp.servers.g.env"}},
                                    "inference_endpoint": "env.BASE_URL"})
        results = self.read(profile)
        self.assertNotIn("hunter2plain", json.dumps(results))
        self.assertEqual(results["approval_policy"]["value"], "[redacted]")
        self.assertEqual(results["tool_allow_deny"]["value"], {"allow": "[redacted]", "deny": "[redacted]"})
        # A path that names one entry under such a key reads it.
        self.assertEqual(results["inference_endpoint"]["value"], "https://llm.example/v1")
        for path, credential in (("mcpServers.*.env", True), ("env.*", True), ("models.providers.x.apiKey", True),
                                 ("env.ANTHROPIC_BASE_URL", False), ("mcpServers", False), ("mcp.servers", False),
                                 ("headers.0", True)):
            self.assertEqual(reader.credential_path(path), credential, path)

    def test_scrubbing_is_linear_on_hostile_input(self):
        # An agent writes these strings; none may stall the scan (64 KB, the source cap).
        import time
        size = reader.SOURCE_MAX_BYTES
        for hostile in ("a." * (size // 2), "a=" * (size // 2), "a:" * (size // 2), "-" * size,
                        "x" * size, "https://" * (size // 8), "eyJ" + "a." * (size // 2),
                        "--token-" * (size // 8), "a@" * (size // 2), "-----BEGIN " * (size // 11)):
            started = time.monotonic()
            reader.redact({"k": hostile, hostile[:200]: [hostile]})
            self.assertLess(time.monotonic() - started, 1.0, hostile[:20])

    def test_more_credential_shapes_are_scrubbed(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQ-pem-placeholder\n-----END PRIVATE KEY-----"
        value = reader.redact({
            "notes": "password: hunter2-placeholder and x-api-key: xyz-placeholder, AUTH_TOKEN=tok-placeholder",
            "cert": "-----BEGIN CERTIFICATE-----\nMIIC-public\n-----END CERTIFICATE-----",
            "key": "kept\n" + pem + "\nafter",
            "sk-proj-placeholderplaceholder": {"url": "http://x"},
            "github-auth": {"url": "http://gh/mcp"},
        })
        text = json.dumps(value)
        for secret in ("hunter2-placeholder", "xyz-placeholder", "tok-placeholder", "pem-placeholder",
                       "sk-proj-placeholderplaceholder"):
            self.assertNotIn(secret, text)
        # A public certificate isn't a private key; a key that is a name stays as it is.
        self.assertIn("MIIC-public", text)
        self.assertEqual(value["github-auth"], {"url": "http://gh/mcp"})
        self.assertEqual(value["key"], "[redacted]")  # "key" is a credential key: its value goes whole

    def test_a_source_over_the_cap_is_size_cap_exceeded_not_parse_failed(self):
        self.write("/home/toy/.toy/settings.json", '{"model": "toy-large", "pad": "' + "x" * reader.SOURCE_MAX_BYTES + '"}')
        result = self.read()["model_name"]
        self.assertEqual((result["status"], result["reason"]), ("FAILED", "SIZE_CAP_EXCEEDED"))
        self.assertIn("larger than", result["note"])

    def test_a_transcript_over_the_cap_is_partial_with_no_bad_line(self):
        line = '{"call": {"name": "read"}}\n'
        self.write("/home/toy/.toy/sessions/a.jsonl", line * (reader.TRANSCRIPT_MAX_BYTES // len(line) + 50))
        result = self.read()["tool_names"]
        self.assertEqual((result["status"], result["reason"], result["value"]), ("PARTIAL", "SIZE_CAP_EXCEEDED", ["read"]))
        self.assertNotIn("could not be parsed", result["note"])

    def test_the_token_after_an_auth_scheme_is_redacted(self):
        value = reader.redact({"h": "Authorization: Bearer bearer-placeholder-1",
                               "h2": "Authorization:Bearer bearer-placeholder-2",
                               "h3": "authorization: Basic basic-placeholder-3",
                               "args": ["--header", "Authorization: Bearer bearer-placeholder-4"]})
        text = json.dumps(value)
        for secret in ("bearer-placeholder-1", "bearer-placeholder-2", "basic-placeholder-3", "bearer-placeholder-4"):
            self.assertNotIn(secret, text)
        self.assertEqual(value["h"], "Authorization: Bearer [redacted]")

    def test_plural_and_compound_credential_keys_are_redacted(self):
        value = reader.redact({"secrets": {"a": "v1-placeholder"}, "apiKeys": ["v2-placeholder"],
                               "credentialsFile": "/v3-placeholder", "privateKeyPem": "v4-placeholder",
                               "dbPassword": "v5-placeholder", "clientSecretRef": "v6-placeholder",
                               "maxTokens": 8192})
        for key in ("secrets", "apiKeys", "credentialsFile", "privateKeyPem", "dbPassword", "clientSecretRef"):
            self.assertEqual(value[key], "[redacted]", key)
        self.assertEqual(value["maxTokens"], 8192)

    def test_a_server_named_with_a_credential_word_is_never_dropped(self):
        servers = {"1password": {"command": "op-mcp"}, "secrets-manager": {"url": "http://sm/mcp"},
                   "aws-credentials": {"command": "aws-mcp", "env": {"AWS_SECRET_ACCESS_KEY": "aws-placeholder"},
                                       "headers": {"Authorization": "Bearer hdr-placeholder"}}}
        self.write("/home/toy/.toy/settings.json", {"mcp": {"servers": servers}})
        value = self.read()["mcp_servers_declared"]["value"]
        self.assertEqual(sorted(value), ["1password", "aws-credentials", "secrets-manager"])
        # Reported, with its config hidden: its name says it's a credential's.
        self.assertEqual(value["1password"], {"command": "[redacted]"})
        # Its containers still lose their whole value.
        self.assertEqual((value["aws-credentials"]["env"], value["aws-credentials"]["headers"]), ("[redacted]", "[redacted]"))
        self.assertNotIn("placeholder", json.dumps(value))
        # And the bundle's inventory carries every one of them.
        self.assertEqual([e["name"] for e in scanner.mcp_inventory_entries(value, "toyagent profile")],
                         ["1password", "secrets-manager", "aws-credentials"])

    def test_an_object_under_a_credential_name_never_shows_its_values(self):
        value = reader.redact({"clientSecret": {"value": "hunter2-placeholder", "rotate": True, "ttl": 3600},
                               "dbPassword": {"primary": {"pw": "pw-placeholder"}}, "accessToken": ["tok-placeholder"]})
        self.assertEqual(value["clientSecret"], {"value": "[redacted]", "rotate": True, "ttl": "[redacted]"})
        self.assertEqual(value["dbPassword"], {"primary": {"pw": "[redacted]"}})
        self.assertEqual(value["accessToken"], "[redacted]")
        self.assertNotIn("placeholder", json.dumps(value))

    def test_a_malformed_url_does_not_crash_the_scan(self):
        def strict(url):  # the scanner's redact_url raises on a bad port
            raise ValueError("Port could not be cast to integer value")
        self.assertEqual(reader.redact({"u": "http://host:notaport/x"}, strict), {"u": "http://host:notaport/x"})

    def test_prompt_text_only_with_the_flag(self):
        self.write("/work/TOY.md", "# Secret instructions\n")
        self.assertEqual(self.read()["system_prompt_text"]["reason"], "NOT_COLLECTED_BY_PACK")
        self.assertNotIn("Secret instructions", json.dumps(self.read()))
        self.assertEqual(self.read(collect_prompt=True)["system_prompt_text"]["value"],
                         {"/work/TOY.md": "# Secret instructions\n"})

    def test_an_unset_variable_skips_its_source(self):
        self.assertIsNone(self.agent.expand("$TOY_CONFIG"))
        self.assertEqual(self.agent.expand("~/.toy/x.json"), "/home/toy/.toy/x.json")
        self.assertIsNone(reader.Agent("toyagent", {}).expand("~/.toy/x.json"))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
    def test_a_fifo_source_is_skipped_without_blocking(self):
        os.mkfifo(self.home / ".toy" / "settings.json")
        self.assertEqual(self.read()["model_name"]["reason"], "NO_SOURCE_ACCESS")

    def test_a_bad_transcript_line_gives_partial(self):
        self.write("/home/toy/.toy/sessions/a.jsonl", '{"call": {"name": "read"}}\nnot json\n')
        result = self.read()["tool_names"]
        self.assertEqual((result["status"], result["reason"]), ("PARTIAL", "PARSE_FAILED"))

    def test_invalid_profiles_are_refused(self):
        for bad in ({}, {"harness": "X Y", "markers": {"commands": ["x"]}},
                    {"harness": "x", "markers": {}},
                    {"harness": "x", "markers": {"commands": ["x"]}, "fields": {"not_a_field": "a"}},
                    {"harness": "x", "markers": {"commands": ["x"]}, "sources": [{"path": "a.yaml", "format": "yaml"}]}):
            with self.assertRaises(reader.ProfileError):
                reader.validate_profile(bad)


class PodSourcesTest(Fixture):
    """Pod mode reads the config volume under the volume, and anything else
    under the agent's root."""

    def setUp(self):
        super().setUp()
        self.volume = self.tmp / "volume" / "home" / "toy" / ".toy"  # mounted in the sidecar at the agent's path
        self.volume.mkdir(parents=True)

    def pod_sources(self):
        return harness_sources.PodSources(str(self.root), [self.volume])

    def test_the_config_volume_and_the_agent_root_are_each_read_in_their_own_root(self):
        (self.volume / "settings.json").write_text(json.dumps({"model": "from-volume"}))
        self.write("/work/.toy/settings.json", {"endpoint": "https://from-root.example"})
        sources = self.pod_sources()
        self.assertIn("from-volume", sources.read_text(str(self.volume / "settings.json"), 1000))
        self.assertIn("from-root", sources.read_text("/work/.toy/settings.json", 1000))
        self.assertEqual(sources.list_dir(str(self.volume)), ["settings.json"])

    def test_a_link_on_the_volume_cannot_leave_it(self):
        secret = self.tmp / "sidecar-secret.json"
        secret.write_text(json.dumps({"model": "sidecar-only"}))
        (self.volume / "settings.json").symlink_to(secret)
        self.assertIsNone(self.pod_sources().read_text(str(self.volume / "settings.json"), 1000))

    def test_listing_the_volume_root_itself_and_refusing_what_is_not_a_folder_inside(self):
        (self.volume / "skills").mkdir()
        (self.volume / "settings.json").write_text("{}")
        outside = self.tmp / "sidecar-only"
        outside.mkdir()
        (outside / "secret-dir").mkdir()
        (self.volume / "escape").symlink_to(outside)
        sources = self.pod_sources()
        # The volume's own top folder, listed directly rather than through its parent.
        self.assertEqual(sources.list_dir(str(self.volume)), ["escape", "settings.json", "skills"])
        # A link out of the volume resolves inside it, to nothing; a file is not a folder.
        self.assertIsNone(sources.list_dir(str(self.volume / "escape")))
        self.assertIsNone(sources.list_dir(str(self.volume / "settings.json")))
        self.assertIsNone(sources.list_dir(str(self.volume / "missing")))

    def test_pod_mode_fills_the_harness_fields_only_when_a_profile_matches(self):
        profile = dict(TOY, sources=[{"path": str(self.volume / "settings.json")}])
        (self.volume / "settings.json").write_text(json.dumps({"model": "toy-large", "approvals": {"mode": "ask"}}))
        subject = {"root": str(self.root), "cmdline": "toyagent serve", "env": {"HOME": "/home/toy"}}
        context = {"mode": "pod", "subject": subject, "config_paths": [str(self.volume)]}
        attributes = pod_mode.harness_attributes(context, BUILDERS, known_profiles=[profile])
        self.assertEqual(attributes["model_name"]["value"], "toy-large")
        self.assertEqual(attributes["model_name"]["authored_by"], "subject")
        self.assertEqual(attributes["model_name"]["method"], f"toyagent profile: {self.volume / 'settings.json'}")
        self.assertEqual(attributes["approval_policy"]["status"], "ANSWERED")
        # The bundle's own authorship for the policy fields.
        self.assertEqual(attributes["approval_policy"]["authored_by"], "platform")
        # A field the profile names but didn't find leaves the bundle's own value:
        # no tools in the file, so no tool_allow_deny here, nor an ABSENT inference_endpoint.
        self.assertNotIn("tool_allow_deny", attributes)
        self.assertNotIn("inference_endpoint", attributes)
        # No profile matches (none ships until tasks 4 and 5): the bundle's own values stand.
        other = dict(context, subject=dict(subject, cmdline="python3 agent.py"))
        self.assertEqual(pod_mode.harness_attributes(other, BUILDERS, known_profiles=[profile]), {})
        self.assertEqual(pod_mode.harness_attributes(context, BUILDERS, known_profiles=[]), {})
        self.assertEqual(pod_mode.harness_attributes(dict(context, subject=None), BUILDERS, known_profiles=[profile]), {})

    def merged(self, existing, settings):
        (self.volume / "settings.json").write_text(json.dumps(settings))
        (self.volume / "skills" / "lookup").mkdir(parents=True, exist_ok=True)
        (self.volume / "skills" / "lookup" / "SKILL.md").write_text("---\nname: lookup\ndescription: Look things up\n---\n")
        profile = dict(TOY, sources=[{"path": str(self.volume / "settings.json")}],
                       workspace={"skills": [str(self.volume / "skills")],
                                  "transcripts": {"folders": [str(self.volume / "sessions")], "tool_name": "call.name"}})
        (self.volume / "sessions").mkdir(exist_ok=True)
        (self.volume / "sessions" / "a.jsonl").write_text('{"call": {"name": "readFile"}}\n')
        subject = {"root": str(self.root), "cmdline": "toyagent serve", "env": {"HOME": "/home/toy"}}
        context = {"mode": "pod", "subject": subject, "config_paths": [str(self.volume)]}
        return pod_mode.harness_attributes(context, BUILDERS, known_profiles=[profile], existing=existing, shapers=SHAPERS)

    def test_a_value_the_scanner_observed_itself_is_never_replaced(self):
        existing = {"tool_names": evidence_bundle._answered(["wireTool"], "observed", authored_by="none", note="floor"),
                    "model_name": evidence_bundle._answered("captured-model", "observed", authored_by="none")}
        attributes = self.merged(existing, {"model": "toy-large"})
        self.assertNotIn("tool_names", attributes)  # AgentSight's wire-observed list stands
        self.assertNotIn("model_name", attributes)  # a captured model stands
        # Where the scanner observed nothing, the transcripts fill it, as the agent's own record.
        attributes = self.merged({"tool_names": evidence_bundle._blind("NOT_COLLECTED_BY_PACK", "observed")}, {})
        self.assertEqual((attributes["tool_names"]["value"], attributes["tool_names"]["authored_by"]), (["readFile"], "subject"))

    def test_profile_values_take_the_bundles_shapes_and_merge_with_its_own(self):
        mcp_json = scanner.mcp_inventory_entries({"files": {"command": "/usr/bin/files-mcp --token x"}}, ".mcp.json")
        existing = {
            "mcp_servers_declared": evidence_bundle._answered(mcp_json, "declared", authored_by="subject"),
            "skills_inventory": evidence_bundle._answered([scanner.normalize_skill(
                {"name": "files.read", "description": "Read a file", "source_type": "mcp_config"}, "x")],
                "declared", authored_by="subject"),
            "declared_destinations": evidence_bundle._answered(["egress.example"], "declared", authored_by="subject"),
        }
        attributes = self.merged(existing, {"endpoint": "https://llm.example/v1",
                                            "mcp": {"servers": {"github-auth": {"url": "https://gh.example/mcp"}}}})
        servers = attributes["mcp_servers_declared"]["value"]
        self.assertEqual([s["name"] for s in servers], ["files", "github-auth"])  # .mcp.json's kept, the profile's added
        self.assertEqual(set(servers[1]), set(mcp_json[0]))  # read_mcp_inventory's shape exactly
        self.assertEqual((servers[1]["url"], servers[1]["transport"], servers[1]["source"]),
                         ("https://gh.example/mcp", "http", "toyagent profile"))
        skills = attributes["skills_inventory"]["value"]
        self.assertEqual(sorted(s["name"] for s in skills), ["files.read", "lookup"])
        lookup = next(s for s in skills if s["name"] == "lookup")
        self.assertEqual(lookup, {"name": "lookup", "description": "Look things up", "destination_endpoints": [],
                                  "source_type": "skills_config"})
        self.assertEqual(attributes["declared_destinations"]["value"], ["egress.example", "gh.example", "llm.example"])

    def test_a_partial_inventory_stays_partial_after_the_profile_merges_into_it(self):
        # DR-293: an MCP server the scanner could not reach makes skills_inventory
        # PARTIAL; the profile's skills join the list but don't make it complete.
        server = scanner.normalize_skill({"name": "remote", "description": "x", "source_type": "mcp_config",
                                          "server": "remote", "entry": "server", "reachability": "unreachable"}, "x")
        existing = {"skills_inventory": evidence_bundle._partial(
            [server], "declared", "NO_SOURCE_ACCESS", authored_by="subject", note="MCP server(s) not reached: remote")}
        skills = self.merged(existing, {})["skills_inventory"]
        self.assertEqual((skills["status"], skills["reason"], skills["note"]),
                         ("PARTIAL", "NO_SOURCE_ACCESS", "MCP server(s) not reached: remote"))
        self.assertEqual(sorted((s["name"], s.get("reachability")) for s in skills["value"]),
                         [("lookup", None), ("remote", "unreachable")])
        # An ANSWERED inventory merges to ANSWERED, as before.
        existing = {"skills_inventory": evidence_bundle._answered([], "declared", authored_by="subject")}
        self.assertEqual(self.merged(existing, {})["skills_inventory"]["status"], "ANSWERED")

    def test_a_host_the_profile_declares_is_no_longer_undeclared(self):
        existing = {"declared_destinations": evidence_bundle._answered([], "declared", authored_by="subject"),
                    "undeclared_destinations": evidence_bundle._answered(
                        ["gh.example", "other.example"], "observed", authored_by="none")}
        attributes = self.merged(existing, {"mcp": {"servers": {"github-auth": {"url": "https://gh.example/mcp"}}}})
        self.assertIn("gh.example", attributes["declared_destinations"]["value"])
        self.assertEqual(attributes["undeclared_destinations"]["value"], ["other.example"])
        # Every observed host now declared: ABSENT, as the bundle says it.
        existing["undeclared_destinations"] = evidence_bundle._answered(["gh.example"], "observed", authored_by="none")
        attributes = self.merged(existing, {"mcp": {"servers": {"github-auth": {"url": "https://gh.example/mcp"}}}})
        self.assertEqual(attributes["undeclared_destinations"]["status"], "ABSENT")

    def test_a_secret_in_an_endpoints_path_is_masked_with_the_scanners_redact_url(self):
        shapers = dict(SHAPERS, redact_url=scanner.redact_url)
        (self.volume / "settings.json").write_text(json.dumps({"endpoint": "https://gw.example/mcp/sk-live-abcdefghijklmnop/sse"}))
        profile = dict(TOY, sources=[{"path": str(self.volume / "settings.json")}], workspace={})
        subject = {"root": str(self.root), "cmdline": "toyagent serve", "env": {"HOME": "/home/toy"}}
        context = {"mode": "pod", "subject": subject, "config_paths": [str(self.volume)]}
        attributes = pod_mode.harness_attributes(context, BUILDERS, known_profiles=[profile], shapers=shapers)
        self.assertEqual(attributes["inference_endpoint"]["value"], "https://gw.example/mcp/[redacted]/sse")
        self.assertNotIn("sk-live-abcdefghijklmnop", json.dumps(attributes))

    def test_no_profiles_ship_yet(self):
        self.assertEqual(harness_sources.profiles(), [])


if __name__ == "__main__":
    unittest.main()

"""RC-526: Claude Code's harness profile fills the harness fields.

The shipped profile (tools/scan/gke/sidecar/harness/profiles/claude-code.json and its
hooks, claude-code.py), loaded as production loads it, read against an agent
laid out from fixtures Claude Code 2.1.325 wrote itself
(fixtures/claude-code/README.md).
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
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "claude-code"


def load(name: str, path: Path):
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


def load_private(name: str, path: Path):
    """A module loaded under a name of this test's own, never registered as
    `scan_agent_environment` or `evidence_bundle`: test_evidence_bundle
    registers its own copies under those names and patches them, so a copy
    imported here first would be the one its code under test resolves to."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reader = load("harness_reader", SCAN / "gke" / "sidecar" / "harness" / "reader.py")
pod_mode = load("gke_pod_mode", SCAN / "gke" / "sidecar" / "pod_mode.py")
scanner = load_private("claude_code_profile_test_scanner", SCAN / "scan_agent_environment.py")
evidence_bundle = load_private("claude_code_profile_test_bundle", SCAN / "evidence_bundle.py")

PROFILES = reader.load_profiles()
CLAUDE = next(p for p in PROFILES if p["harness"] == "claude-code")
BUILDERS = {"answered": evidence_bundle._answered, "blind": evidence_bundle._blind,
            "absent": evidence_bundle._absent, "failed": evidence_bundle._failed,
            "partial": evidence_bundle._partial}
PACKAGE = "/usr/local/lib/node_modules/@anthropic-ai/claude-code"
CMDLINE = f"{PACKAGE}/bin/claude.exe -p Check the stock lookup setup."
TRANSCRIPT = "$CLAUDE_DIR/projects/<$CLAUDE_PROJECT>/0cf9746c-7773-486a-9058-fb795c31ab97.jsonl"
SECRETS = ("fixture-placeholder-not-a-key", "argument-placeholder", "You answer questions",
           "agent-bash-guard", "machineID", "userID")


def agent(cmdline: str = CMDLINE, cwd: str | None = "/work", **env: str):
    return reader.Agent(cmdline, {"HOME": "/root", **env}, cwd)


class Install(unittest.TestCase):
    """A Claude Code agent's root, laid out as claude-code-setup.sh left it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "agent-root"
        self.put("/root/.claude/settings.json", FIXTURES / "user-settings.json")
        self.put("/root/.claude.json", FIXTURES / "claude.json")
        self.put("/work/.claude/settings.json", FIXTURES / "project-settings.json")
        self.put(f"/root/.claude/projects/-work/{Path(TRANSCRIPT).name}", FIXTURES / "transcript.jsonl")
        self.put(f"{PACKAGE}/package.json", FIXTURES / "package.json")
        self.write("/work/CLAUDE.md", "# fixture-agent\nYou answer questions about stock prices.\n")
        self.write("/work/.claude/skills/stock-lookup/SKILL.md",
                   "---\nname: stock-lookup\ndescription: Look up a stock price\n---\nCall getStockPrice.\n")

    def path(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def put(self, path: str, source: Path) -> None:
        self.path(path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source, self.path(path))

    def write(self, path: str, content) -> None:
        self.path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path(path).write_text(content if isinstance(content, str) else json.dumps(content))

    def edit(self, path: str, change) -> None:
        document = json.loads(self.path(path).read_text())
        change(document)
        self.write(path, document)

    def read(self, who=None, **kwargs):
        return reader.read_harness_fields(CLAUDE, who or agent(), reader.LocalSources(self.root), **kwargs)


class ClaudeCodeProfileTest(Install):
    def test_the_profile_ships_and_recognizes_claude_code(self):
        for cmdline, env in ((CMDLINE, {}),                                   # the npm package's native binary
                             ("claude -p hi", {}),                            # through its bin link, or a native install
                             ("/root/.local/bin/claude --print hi", {}),
                             ("node /app/node_modules/@anthropic-ai/claude-code/cli.js", {}),
                             ("python3 runner.py", {"CLAUDE_CONFIG_DIR": "/cfg"})):
            with self.subTest(cmdline=cmdline):
                self.assertIs(reader.harness_reader_for(PROFILES, reader.Agent(cmdline, env)), CLAUDE)
        for cmdline in ("node /app/node_modules/@anthropic-ai/claude-code-lite/index.js", "claude-helper run",
                        "node /usr/local/bin/openclaw gateway", "python3 other_agent.py"):
            with self.subTest(cmdline=cmdline):
                self.assertIsNot(reader.harness_reader_for(PROFILES, reader.Agent(cmdline, {})), CLAUDE)

    def test_an_openclaw_agent_that_mentions_claude_stays_openclaw(self):
        # claude-code sorts before openclaw: a word or variable of Claude
        # Code's must never take an OpenClaw agent's harness.
        openclaw = next(p for p in PROFILES if p["harness"] == "openclaw")
        for cmdline, env in (("openclaw agent --message use claude for review", {}),
                             ("node /usr/bin/openclaw gateway --note claude", {}),
                             ("openclaw gateway", {"CLAUDE_CONFIG_DIR": "/cfg"}),
                             ("node /usr/local/lib/node_modules/openclaw/openclaw.mjs gateway",
                              {"CLAUDE_CONFIG_DIR": "/cfg"}),
                             ("node --title claude /usr/lib/node_modules/openclaw/openclaw.mjs", {}),
                             ("sh -c cd /app && openclaw gateway", {}),
                             ("/docker-entrypoint.sh openclaw gateway", {})):
            with self.subTest(cmdline=cmdline, env=env):
                self.assertIs(reader.harness_reader_for(PROFILES, reader.Agent(cmdline, env)), openclaw)
        # And the other way round.
        for cmdline in ("claude -p review the openclaw config", "claude -p look at /usr/local/bin/openclaw",
                        "node --max-old-space-size 4096 /app/node_modules/@anthropic-ai/claude-code/cli.js"):
            with self.subTest(cmdline=cmdline):
                self.assertIs(reader.harness_reader_for(PROFILES, reader.Agent(cmdline, {})), CLAUDE)

    def test_each_harness_field_is_answered_with_its_source_named(self):
        results = self.read()
        user, project = "$CLAUDE_DIR/settings.json", "$CLAUDE_PROJECT/.claude/settings.json"
        expected = {
            "harness_identity": ("claude-code/2.1.325",
                                 "node_modules/@anthropic-ai/claude-code/package.json (the package the command line runs)"),
            "model_name": ("claude-sonnet-4-5", user),
            "llm_provider": ("anthropic", user),
            "inference_endpoint": ("https://llm-gateway.example.internal:8443", user),
            "mcp_servers_declared": ({"finretail": {"type": "http", "url": "http://finretail-mcp-server:23004/mcp"}},
                                     "$CLAUDE_JSON"),
            "tool_allow_deny": ({"allow": ["mcp__finretail", "Read", "Bash(echo:*)"],
                                 "deny": ["WebFetch", "WebSearch", "Bash(curl:*)"], "ask": ["Bash(rm:*)"]}, project),
            "approval_policy": ({"defaultMode": "dontAsk", "hooks": {"PreToolUse": ["Bash"]}}, project),
            # The bundle's shape: sorted names, a floor, not a count.
            "tool_names": (["Bash", "Read"], TRANSCRIPT),
            "system_prompt_present": ({"present": True, "files": ["$CLAUDE_PROJECT/CLAUDE.md"]},
                                      ["$CLAUDE_PROJECT/CLAUDE.md"]),
            "skills_inventory": ([{"name": "stock-lookup", "description": "Look up a stock price",
                                   "path": "$CLAUDE_PROJECT/.claude/skills/stock-lookup"}],
                                 ["$CLAUDE_PROJECT/.claude/skills"]),
        }
        for field, (value, source) in expected.items():
            result = results[field]
            self.assertEqual((result["status"], result["value"], result["source"]), ("ANSWERED", value, source), field)
        self.assertEqual({result["harness"] for result in results.values()}, {"claude-code"})

    def test_secrets_tool_arguments_and_prompt_text_never_reach_the_results(self):
        text = json.dumps(self.read())
        for secret in SECRETS:
            self.assertNotIn(secret, text)
        # Paths are reported as the profile writes them, never as the agent's own.
        self.assertNotIn("/work", text.replace("$CLAUDE_PROJECT", ""))

    def test_no_prompt_text_without_the_flag(self):
        self.assertEqual(self.read()["system_prompt_text"]["reason"], "NOT_COLLECTED_BY_PACK")
        text = self.read(collect_prompt=True)["system_prompt_text"]
        self.assertEqual(text["status"], "ANSWERED")
        self.assertIn("You answer questions", json.dumps(text))

    def test_a_project_setting_overrides_the_users_and_a_managed_one_overrides_both(self):
        self.edit("/work/.claude/settings.json", lambda d: d.update(model="claude-opus-4-5"))
        result = self.read()["model_name"]
        self.assertEqual((result["value"], result["source"]), ("claude-opus-4-5", "$CLAUDE_PROJECT/.claude/settings.json"))
        self.write("/work/.claude/settings.local.json", {"model": "claude-haiku-4-5"})
        result = self.read()["model_name"]
        self.assertEqual((result["value"], result["source"]),
                         ("claude-haiku-4-5", "$CLAUDE_PROJECT/.claude/settings.local.json"))
        self.write("/etc/claude-code/managed-settings.json", {"model": "managed-model",
                                                              "permissions": {"defaultMode": "plan"}})
        results = self.read()
        self.assertEqual((results["model_name"]["value"], results["model_name"]["source"]),
                         ("managed-model", "/etc/claude-code/managed-settings.json"))
        self.assertEqual(results["approval_policy"]["value"]["defaultMode"], "plan")
        # A drop-in overrides managed-settings.json, a later one an earlier one.
        self.write("/etc/claude-code/managed-settings.d/10-a.json", {"model": "ten"})
        self.write("/etc/claude-code/managed-settings.d/20-b.json", {"model": "twenty"})
        result = self.read()["model_name"]
        self.assertEqual((result["value"], result["source"]), ("twenty", "/etc/claude-code/managed-settings.d/20-b.json"))

    def test_anthropic_model_and_the_model_flag_override_the_model_setting(self):
        # As Claude Code 2.1.325 picks it: --model, then ANTHROPIC_MODEL (a
        # settings env block's over the process's), then `model`, even managed.
        self.write("/etc/claude-code/managed-settings.json", {"model": "managed-model"})
        result = self.read(agent(ANTHROPIC_MODEL="process-model"))["model_name"]
        self.assertEqual((result["value"], result["source"]), ("process-model", "$ANTHROPIC_MODEL"))
        self.edit("/root/.claude/settings.json", lambda d: d["env"].update(ANTHROPIC_MODEL="settings-env-model"))
        result = self.read(agent(ANTHROPIC_MODEL="process-model"))["model_name"]
        self.assertEqual((result["value"], result["source"]), ("settings-env-model", "$CLAUDE_DIR/settings.json"))
        result = self.read(agent(f"{CMDLINE} --model flag-model"))["model_name"]
        self.assertEqual((result["value"], result["source"]), ("flag-model", "command line (--model)"))

    def test_the_provider_follows_the_cloud_flags_and_the_endpoint(self):
        self.assertEqual(self.read(agent(CLAUDE_CODE_USE_BEDROCK="1"))["llm_provider"]["value"], "aws")
        self.edit("/root/.claude/settings.json", lambda d: d["env"].update(CLAUDE_CODE_USE_VERTEX="true"))
        self.assertEqual(self.read()["llm_provider"]["value"], "google")
        self.edit("/root/.claude/settings.json", lambda d: (d["env"].pop("CLAUDE_CODE_USE_VERTEX"),
                                                            d["env"].update(ANTHROPIC_BASE_URL="https://api.anthropic.com")))
        self.assertEqual(self.read()["llm_provider"]["note"], "from the ANTHROPIC_BASE_URL host")
        self.edit("/root/.claude/settings.json", lambda d: d["env"].pop("ANTHROPIC_BASE_URL"))
        results = self.read()
        self.assertEqual((results["llm_provider"]["value"], results["inference_endpoint"]["status"]), ("anthropic", "ABSENT"))
        self.assertIn("default endpoint", results["llm_provider"]["note"])
        # The process's own variable, when no settings file sets one; named, never its value's source.
        result = self.read(agent(ANTHROPIC_BASE_URL="https://gw.example.internal/v1"))["inference_endpoint"]
        self.assertEqual((result["value"], result["source"]), ("https://gw.example.internal/v1", "$ANTHROPIC_BASE_URL"))

    def test_an_endpoint_url_carrying_a_secret_is_redacted(self):
        self.edit("/root/.claude/settings.json",
                  lambda d: d["env"].update(ANTHROPIC_BASE_URL="https://user:pw@gw.example.internal/v1?key=abc"))
        result = self.read()["inference_endpoint"]
        self.assertEqual(result["value"], "https://gw.example.internal/v1")

    def test_invalid_json_gives_failed_with_parse_failed(self):
        self.path("/work/.claude/settings.json").unlink()
        self.write("/root/.claude/settings.json", "{not json")
        self.write("/root/.claude.json", "{not json")
        results = self.read()
        for field in ("model_name", "inference_endpoint", "tool_allow_deny", "approval_policy", "mcp_servers_declared"):
            self.assertEqual((results[field]["status"], results[field]["reason"]), ("FAILED", "PARSE_FAILED"), field)
        # The installed package still names the harness, and the transcripts still answer.
        self.assertEqual(results["harness_identity"]["value"], "claude-code/2.1.325")
        self.assertEqual(results["tool_names"]["value"], ["Bash", "Read"])

    def test_a_project_file_that_doesnt_parse_is_skipped_and_named(self):
        # As Claude Code does: the user's setting applies, the broken file is noted.
        self.write("/work/.claude/settings.json", "{not json")
        result = self.read()["model_name"]
        self.assertEqual((result["status"], result["value"]), ("ANSWERED", "claude-sonnet-4-5"))
        self.assertIn("$CLAUDE_PROJECT/.claude/settings.json", result["note"])

    def test_an_untrusted_workspace_ignores_the_projects_allow_rules_only(self):
        self.edit("/root/.claude.json", lambda d: d["projects"]["/work"].update(hasTrustDialogAccepted=False))
        self.write("/work/.claude/settings.local.json", {"permissions": {"allow": ["Glob"]}})
        result = self.read()["tool_allow_deny"]
        # The shared file's allow rules are skipped; its deny and ask rules and the local file's allow rules apply.
        self.assertEqual(result["value"], {"allow": ["Glob"], "deny": ["WebFetch", "WebSearch", "Bash(curl:*)"],
                                           "ask": ["Bash(rm:*)"]})
        self.assertIn("3 allow rule(s) in $CLAUDE_PROJECT/.claude/settings.json ignored", result["note"])

    def test_rules_merge_across_files_and_managed_only_rules_drop_the_rest(self):
        self.edit("/root/.claude/settings.json", lambda d: d.update(permissions={"deny": ["Write"]}))
        self.assertEqual(self.read()["tool_allow_deny"]["value"]["deny"],
                         ["WebFetch", "WebSearch", "Bash(curl:*)", "Write"])
        self.write("/etc/claude-code/managed-settings.json",
                   {"allowManagedPermissionRulesOnly": True, "permissions": {"deny": ["Bash"]}})
        result = self.read()["tool_allow_deny"]
        self.assertEqual((result["value"], result["source"]), ({"deny": ["Bash"]}, "/etc/claude-code/managed-settings.json"))
        self.assertIn("allowManagedPermissionRulesOnly", result["note"])

    def test_the_command_lines_permission_mode_and_hooks_by_event_only(self):
        result = self.read(agent(f"{CMDLINE} --dangerously-skip-permissions"))["approval_policy"]
        self.assertEqual(result["value"]["commandLineMode"], "bypassPermissions")
        self.assertIn("command line", result["source"])
        self.assertEqual(self.read(agent(f"{CMDLINE} --permission-mode=plan"))["approval_policy"]["value"]["commandLineMode"],
                         "plan")
        self.write("/etc/claude-code/managed-settings.json", {"permissions": {"disableBypassPermissionsMode": "disable"}})
        result = self.read(agent(f"{CMDLINE} --dangerously-skip-permissions"))["approval_policy"]
        self.assertEqual(result["value"]["disableBypassPermissionsMode"], "disable")
        self.assertIn("which settings disable", result["note"])
        self.edit("/root/.claude/settings.json", lambda d: d.update(disableAllHooks=True))
        result = self.read()["approval_policy"]
        self.assertNotIn("hooks", result["value"])
        self.assertIn("disableAllHooks", result["note"])

    def test_no_declared_policy_is_never_evidence_of_restriction(self):
        self.path("/work/.claude/settings.json").unlink()
        results = self.read()
        for field in ("approval_policy", "tool_allow_deny"):
            self.assertEqual((results[field]["status"], results[field]["reason"]), ("BLIND", "GATEWAY_MANAGED"), field)

    def test_mcp_servers_merge_by_scope_and_managed_mcp_takes_exclusive_control(self):
        self.write("/work/.mcp.json", {"mcpServers": {"finretail": {"type": "http", "url": "http://project:1/mcp"},
                                                       "docs": {"command": "docs-mcp"}}})
        self.edit("/root/.claude.json", lambda d: d["projects"]["/work"].update(
            mcpServers={"docs": {"type": "http", "url": "http://local:1/mcp"}}))
        result = self.read()["mcp_servers_declared"]
        # local scope over project over user, on a name.
        self.assertEqual(result["value"], {"finretail": {"type": "http", "url": "http://project:1/mcp"},
                                           "docs": {"type": "http", "url": "http://local:1/mcp"}})
        self.assertEqual(result["source"], ["$CLAUDE_JSON", "$CLAUDE_PROJECT/.mcp.json",
                                            "$CLAUDE_JSON (projects[$CLAUDE_PROJECT].mcpServers)"])
        self.write("/etc/claude-code/managed-mcp.json", {"mcpServers": {"only": {"type": "http", "url": "http://m:1/mcp"}}})
        result = self.read()["mcp_servers_declared"]
        self.assertEqual((result["value"], result["source"]),
                         ({"only": {"type": "http", "url": "http://m:1/mcp"}}, "/etc/claude-code/managed-mcp.json"))

    def test_a_large_claude_json_is_still_read(self):
        # Real ~/.claude.json files hold caches well past the reader's 64 KB default.
        self.edit("/root/.claude.json", lambda d: d.update(cachedFeatureFlags={"x": "y" * 300_000}))
        self.assertEqual(self.read()["mcp_servers_declared"]["status"], "ANSWERED")

    def test_claude_config_dir_moves_settings_state_and_transcripts(self):
        shutil.move(self.path("/root/.claude"), self.path("/cfg"))
        shutil.move(self.path("/root/.claude.json"), self.path("/cfg/.claude.json"))
        results = self.read(agent(CLAUDE_CONFIG_DIR="/cfg"))
        self.assertEqual(results["model_name"]["source"], "$CLAUDE_DIR/settings.json")
        self.assertEqual(results["mcp_servers_declared"]["source"], "$CLAUDE_JSON")
        self.assertEqual(results["tool_names"]["value"], ["Bash", "Read"])
        self.assertNotIn("/cfg", json.dumps(results))

    def test_no_working_directory_reads_no_project_but_pwd_stands_in(self):
        results = self.read(agent(cwd=None))
        self.assertEqual(results["tool_allow_deny"]["status"], "BLIND")
        self.assertEqual(results["model_name"]["source"], "$CLAUDE_DIR/settings.json")
        self.assertEqual(self.read(agent(cwd=None, PWD="/work"))["tool_allow_deny"]["status"], "ANSWERED")

    def test_only_assistant_tool_use_entries_name_tools(self):
        # The request Claude Code sent (api-request-blob) carries earlier
        # messages, tool_use blocks included; it never names a tool called.
        transcript = self.path(f"/root/.claude/projects/-work/{Path(TRANSCRIPT).name}")
        with transcript.open("a") as out:
            out.write(json.dumps({"type": "api-request-blob", "message": {"role": "assistant", "content": [
                {"type": "tool_use", "name": "NotCalled", "input": {}}]}}) + "\n")
            out.write(json.dumps({"type": "user", "message": {"role": "user", "content": [
                {"type": "tool_use", "name": "AlsoNotCalled"}]}}) + "\n")
            out.write(json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "mcp_tool_use", "name": "mcp__finretail__getStockPrice", "input": {"symbol": "argument-placeholder"}},
                {"type": "text", "text": "done"}]}}) + "\n")
        result = self.read()["tool_names"]
        self.assertEqual(result["value"], ["Bash", "Read", "mcp__finretail__getStockPrice"])
        self.assertNotIn("argument-placeholder", json.dumps(result))

    def test_no_project_folder_name_reaches_the_results(self):
        # Claude Code names each project's transcript folder after its working
        # directory, which is used to find files and never reported.
        shutil.move(self.path("/root/.claude/projects/-work"), self.path("/root/.claude/projects/-home-agent-acme-payments"))
        self.write("/root/.claude/projects/-srv-other-billing/s.jsonl",
                   json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Grep"}]}}) + "\n")
        shutil.move(self.path("/work"), self.path("/home/agent/acme-payments"))
        self.edit("/root/.claude.json", lambda d: d.update(projects={"/home/agent/acme-payments": {"hasTrustDialogAccepted": True}}))
        results = self.read(agent(cwd="/home/agent/acme-payments"))
        result = results["tool_names"]
        self.assertEqual(result["value"], ["Bash", "Grep", "Read"])
        self.assertEqual(result["source"], [TRANSCRIPT, "$CLAUDE_DIR/projects/<project 1>/s.jsonl"])
        self.assertEqual(results["tool_allow_deny"]["status"], "ANSWERED")  # the project was found through it
        text = json.dumps(results)
        for name in ("acme", "payments", "billing", "-srv-", "-home-"):
            self.assertNotIn(name, text)

    def test_subagent_transcripts_count_and_a_bad_line_gives_partial(self):
        self.write("/root/.claude/projects/-work/0cf9746c/subagents/agent-1.jsonl",
                   json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Grep"}]}})
                   + "\nnot json\n")
        result = self.read()["tool_names"]
        self.assertEqual((result["status"], result["reason"]), ("PARTIAL", "PARSE_FAILED"))
        self.assertEqual(result["value"], ["Bash", "Grep", "Read"])
        self.assertIn("$CLAUDE_DIR/projects/<$CLAUDE_PROJECT>/0cf9746c/subagents/agent-1.jsonl", result["source"])

    def test_a_native_install_names_its_version(self):
        shutil.rmtree(self.path("/usr"))
        for version in ("2.1.322", "2.1.325", "2.1.9"):
            self.write(f"/root/.local/share/claude/versions/{version}", "")
        result = self.read(agent("/root/.local/share/claude/versions/2.1.322 -p hi"))["harness_identity"]
        self.assertEqual((result["value"], result["note"]), ("claude-code/2.1.322", "a native install; the command line runs it"))
        result = self.read(agent("claude -p hi"))["harness_identity"]
        self.assertEqual(result["value"], "claude-code/2.1.325")
        self.assertIn("newest of 3 installed", result["note"])

    def test_no_install_at_all_is_blind(self):
        shutil.rmtree(self.root)
        results = self.read()
        for field in ("model_name", "harness_identity", "tool_names", "skills_inventory", "mcp_servers_declared"):
            self.assertEqual((results[field]["status"], results[field]["reason"]), ("BLIND", "NO_SOURCE_ACCESS"), field)


class PodModeTest(Install):
    """The shipped profile through pod mode, read through the agent's root."""

    def subject(self):
        return {"root": str(self.root), "cmdline": CMDLINE, "env": {"HOME": "/root"}, "cwd": "/work"}

    def test_pod_mode_fills_claude_codes_fields_from_the_agents_root(self):
        context = {"mode": "pod", "subject": self.subject(), "config_paths": []}
        attributes = pod_mode.harness_attributes(context, BUILDERS)
        self.assertEqual(attributes["model_name"]["value"], "claude-sonnet-4-5")
        self.assertEqual(attributes["model_name"]["method"], "claude-code profile: $CLAUDE_DIR/settings.json")
        self.assertEqual(attributes["harness_identity"]["value"], "claude-code/2.1.325")
        self.assertEqual(attributes["tool_allow_deny"]["authored_by"], "platform")
        self.assertEqual(attributes["tool_names"]["value"], ["Bash", "Read"])
        text = json.dumps(attributes)
        for secret in SECRETS:
            self.assertNotIn(secret, text)
        self.assertNotIn(str(self.root), text)

    def test_pod_mode_merges_claude_codes_values_in_the_bundles_own_shapes(self):
        context = {"mode": "pod", "subject": self.subject(), "config_paths": []}
        shapers = {"mcp_inventory_entries": scanner.mcp_inventory_entries, "normalize_skill": scanner.normalize_skill,
                   "merge_skill_lists": scanner.merge_skill_lists, "url_host": scanner.url_host,
                   "redact_url": scanner.redact_url}
        existing = {"tool_names": evidence_bundle._answered(["wireTool"], "observed", authored_by="none")}
        attributes = pod_mode.harness_attributes(context, BUILDERS, existing=existing, shapers=shapers)
        self.assertEqual(attributes["mcp_servers_declared"]["value"], scanner.mcp_inventory_entries(
            {"finretail": {"type": "http", "url": "http://finretail-mcp-server:23004/mcp"}}, "claude-code profile"))
        self.assertEqual(attributes["declared_destinations"]["value"],
                         ["finretail-mcp-server", "llm-gateway.example.internal"])
        self.assertNotIn("tool_names", attributes)  # AgentSight's wire-observed list stands


if __name__ == "__main__":
    unittest.main()

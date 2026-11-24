"""Claude Code's hooks, for the fields claude-code.json's key paths can't
reach on their own (RC-526). Loaded with claude-code.json by
reader.load_profiles.

As Claude Code 2.1.325 lays its files out and reads them (checked against a
real install of the npm package in a container, set up with
tests-python/fixtures/claude-code/claude-code-setup.sh; see the README
there):

* Settings, highest precedence first: /etc/claude-code/managed-settings.d/
  (a later file over an earlier one), /etc/claude-code/managed-settings.json,
  the project's .claude/settings.local.json and .claude/settings.json, then
  the user's settings.json in $CLAUDE_CONFIG_DIR, else ~/.claude. The project
  is the agent's working directory.
* model: `--model` on the command line, then ANTHROPIC_MODEL (a settings
  `env` block's over the process environment's, which it overrides), then
  `model` in the highest settings file that sets it.
* The endpoint is ANTHROPIC_BASE_URL, found the same way; the provider is
  Bedrock, Vertex or Foundry when CLAUDE_CODE_USE_* says so, else the
  endpoint's host's vendor, else Anthropic (Claude Code's default endpoint).
* permissions.allow, .deny and .ask merge across every settings file. The
  allow rules of a project's shared .claude/settings.json are ignored until
  its workspace is trusted (projects[<project>].hasTrustDialogAccepted in
  ~/.claude.json): Claude Code says so and skips them. Its
  settings.local.json and the user's settings apply either way. allowManagedPermissionRulesOnly in managed
  settings leaves only the managed rules.
* permissions.defaultMode from the highest file that sets it, overridden by
  --permission-mode or --dangerously-skip-permissions; hooks merge across
  files (reported by event and matcher only, never their commands).
* MCP servers: ~/.claude.json's mcpServers (user scope), the project's
  .mcp.json (project scope), and ~/.claude.json's projects[<project>].mcpServers
  (local scope, `claude mcp add`'s default), a narrower scope winning on a
  name; /etc/claude-code/managed-mcp.json, when present, alone.
* Transcripts: $CLAUDE_DIR/projects/<project folder>/<session>.jsonl and
  <session>/subagents/*.jsonl, one JSON object a line. Only an `assistant`
  entry's tool_use blocks name a tool the agent called; other entries (the
  request Claude Code sent, attachments) carry earlier messages and its own
  system prompt, so they are never read for names.
* The version from the npm package's package.json, or a native install's
  versions folder (~/.local/share/claude/versions/<version>).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

PACKAGE = "@anthropic-ai/claude-code"
PACKAGE_DIRS = ("/usr/local/lib/node_modules/@anthropic-ai/claude-code",
                "/usr/lib/node_modules/@anthropic-ai/claude-code")
# npm's global folder on Windows, by default.
WINDOWS_PACKAGE_DIR = "$APPDATA/npm/node_modules/@anthropic-ai/claude-code"
NATIVE_VERSIONS = "~/.local/share/claude/versions"
WINDOWS_PATH = re.compile(r"[A-Za-z]:[\\/]")
# The Claude desktop app runs its own Claude Code from .../claude-code/<version>/<build>/claude(.exe).
DESKTOP_APP = re.compile(r"/claude-code/([^/]+)/[^/]+/claude(?:[.]exe)?$")
MANAGED_MCP = "/etc/claude-code/managed-mcp.json"
PROJECT_MCP = "$CLAUDE_PROJECT/.mcp.json"
STATE = "$CLAUDE_JSON"
SCOPES = {
    "/etc/claude-code/managed-settings.d/*.json": "managed",
    "/etc/claude-code/managed-settings.json": "managed",
    "$CLAUDE_PROJECT/.claude/settings.local.json": "local",
    "$CLAUDE_PROJECT/.claude/settings.json": "project",
    "$CLAUDE_DIR/settings.json": "user",
    STATE: "state",
}
RULE_KINDS = ("allow", "deny", "ask")
TOOL_USE_TYPES = ("tool_use", "server_tool_use", "mcp_tool_use")
CLOUD_FLAGS = (("CLAUDE_CODE_USE_BEDROCK", "aws"), ("CLAUDE_CODE_USE_VERTEX", "google"),
               ("CLAUDE_CODE_USE_FOUNDRY", "azure"))
VENDORS = (("anthropic.com", "anthropic"), ("amazonaws.com", "aws"), ("googleapis.com", "google"),
           ("azure.com", "azure"), ("openai.com", "openai"), ("openrouter.ai", "openrouter"))
CLAUDE_MODEL = re.compile(r"(claude|opus|sonnet|haiku)", re.IGNORECASE)
SHORT_WORD = re.compile(r"[A-Za-z0-9._:/@\[\]-]{1,128}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]{0,32}")
MANIFEST_MAX_BYTES = 64_000
FLOOR = "floor, not a count: tools not called in the transcripts read are absent here"


# --- the settings files ----------------------------------------------------

def _layers(ctx: Any, scopes: tuple[str, ...] = ("managed", "local", "project", "user")) -> list[tuple[str, str, dict]]:
    """(scope, the path reported, its document) for each settings file that
    parsed to an object, highest precedence first."""
    return [(SCOPES.get(s["spec"], "user"), s["path"], s["doc"]) for s in ctx.config_sources
            if isinstance(s.get("doc"), dict) and SCOPES.get(s["spec"]) in scopes]


def _state(ctx: Any) -> dict:
    """~/.claude.json (or $CLAUDE_CONFIG_DIR's), where Claude Code keeps MCP
    servers and per-project state; {} when it isn't readable."""
    for source in ctx.config_sources:
        if source["spec"] == STATE and isinstance(source.get("doc"), dict):
            return source["doc"]
    return {}


def _project_state(ctx: Any) -> dict:
    """The agent's project's entry in ~/.claude.json's projects, keyed by its
    absolute path (used to find it, never reported)."""
    project = ctx.agent.expand("$CLAUDE_PROJECT")
    projects = _state(ctx).get("projects")
    if not project or not isinstance(projects, dict):
        return {}
    key = project.rstrip("/") or "/"
    keys = [key]
    if re.match(r"[A-Za-z]:", key):
        # Windows: Claude Code has keyed one file's projects with / and with \.
        keys += [key.replace("\\", "/"), key.replace("/", "\\")]
    for candidate in keys:
        entry = projects.get(candidate)
        if isinstance(entry, dict):
            return entry
    return {}


def _no_value(ctx: Any, field: str, what: str) -> dict[str, Any]:
    """Why a field has no value: nothing readable, a file that didn't parse,
    or read and not set."""
    sources = ctx.config_sources
    failed = [s for s in sources if s["error"]]
    parsed = [s["path"] for s in sources if isinstance(s.get("doc"), dict)]
    if not parsed:
        if failed:
            return ctx.result("FAILED", field, reason=failed[0]["reason"], note="; ".join(s["error"] for s in failed))
        return ctx.result("BLIND", field, reason="NO_SOURCE_ACCESS", note="claude-code: no settings file could be read")
    if failed:
        return ctx.result("FAILED", field, reason=failed[0]["reason"],
                          note=f"{what} not in {', '.join(parsed)}; " + "; ".join(s["error"] for s in failed))
    if field in ("tool_allow_deny", "approval_policy"):
        return ctx.result("BLIND", field, reason="GATEWAY_MANAGED",
                          note=f"claude-code: {what} not set in {', '.join(parsed)}; absence is NOT evidence of restriction")
    return ctx.result("ABSENT", field, method=f"claude-code: {what} not set in {', '.join(parsed)}")


def _higher_failed_note(ctx: Any, source: str | None) -> dict[str, str]:
    """A note when a settings file above the one a value came from couldn't
    be parsed (Claude Code skips a project file that doesn't parse)."""
    failed = []
    for entry in ctx.config_sources:
        if entry["path"] == source:
            break
        if entry["error"]:
            failed.append(entry["error"])
    return {"note": "a higher-precedence settings file could not be parsed: " + "; ".join(failed)} if failed else {}


def _flag(ctx: Any, flag: str) -> str | None:
    """A command-line flag's value (`--flag value` or `--flag=value`), when
    it is one short word."""
    words = ctx.agent.cmdline.split()
    for index, word in enumerate(words):
        value = None
        if word == flag and index + 1 < len(words):
            value = words[index + 1]
        elif word.startswith(flag + "="):
            value = word[len(flag) + 1:]
        if value is not None:
            return value if SHORT_WORD.fullmatch(value) else None
    return None


def _setting_env(ctx: Any, name: str) -> tuple[str | None, str | None]:
    """An environment variable as Claude Code sees it: from the highest
    settings file whose `env` block sets it (which overrides the process's),
    else the agent's environment. (value, the source reported)."""
    for _, path, doc in _layers(ctx):
        env = doc.get("env")
        if isinstance(env, dict) and isinstance(env.get(name), str) and env[name].strip():
            return env[name].strip(), path
    value = ctx.agent.env.get(name)
    if isinstance(value, str) and value.strip():
        return value.strip(), f"${name}"
    return None, None


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def _vendor(endpoint: str | None) -> str | None:
    try:
        host = (urlsplit(endpoint).hostname or "") if endpoint else ""
    except ValueError:
        host = ""
    if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local"):
        return "local"
    for suffix, vendor in VENDORS:
        if host == suffix or host.endswith("." + suffix):
            return vendor
    return None


def _model(ctx: Any) -> tuple[str | None, str | None, str | None]:
    """(model, the source reported, a note) in Claude Code's own order."""
    flag = _flag(ctx, "--model")
    if flag:
        return flag, "command line (--model)", None
    value, source = _setting_env(ctx, "ANTHROPIC_MODEL")
    if value:
        return value, source, "ANTHROPIC_MODEL" + (" in the settings' env block" if not source.startswith("$") else "")
    for _, path, doc in _layers(ctx):
        if isinstance(doc.get("model"), str) and doc["model"].strip():
            return doc["model"].strip(), path, None
    return None, None, None


# --- the package -----------------------------------------------------------

def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"[0-9]+", version)[:3])


def _identity(ctx: Any) -> dict[str, Any] | None:
    """claude-code/<version> from the package the command line runs, an npm
    install's package.json, the Claude desktop app's own copy, or a native
    install's versions folder. A Windows path's backslashes count as slashes."""
    words = [word.replace("\\", "/") if WINDOWS_PATH.match(word) else word
             for word in ctx.agent.cmdline.split()]
    marker = f"/node_modules/{PACKAGE}/"
    roots = [(word[:word.index(marker) + len(marker) - 1],
              f"node_modules/{PACKAGE}/package.json (the package the command line runs)")
             for word in words if marker in word]
    roots += [(folder, f"{folder}/package.json") for folder in PACKAGE_DIRS]
    windows = ctx.agent.expand(WINDOWS_PACKAGE_DIR)
    if windows:
        roots.append((windows, f"{WINDOWS_PACKAGE_DIR}/package.json"))
    for root, shown in roots:
        text = ctx.sources.read_text(f"{root}/package.json", MANIFEST_MAX_BYTES)
        if text is None:
            continue
        try:
            manifest = ctx.loads(text)
        except ValueError:
            continue
        if isinstance(manifest, dict) and manifest.get("name") == PACKAGE and VERSION.fullmatch(str(manifest.get("version"))):
            return ctx.result("ANSWERED", "harness_identity", value=f"claude-code/{manifest['version']}",
                              source=shown, note="installed with npm")
    # A native install runs ~/.local/share/claude/versions/<version> itself.
    for word in words:
        head, _, version = word.rpartition("/")
        if head.endswith("/.local/share/claude/versions") and VERSION.fullmatch(version):
            return ctx.result("ANSWERED", "harness_identity", value=f"claude-code/{version}",
                              source=f"{NATIVE_VERSIONS}/{version}", note="a native install; the command line runs it")
        desktop = DESKTOP_APP.search(word)
        if desktop and VERSION.fullmatch(desktop.group(1)):
            return ctx.result("ANSWERED", "harness_identity", value=f"claude-code/{desktop.group(1)}",
                              source="the command line", note="the Claude desktop app's own Claude Code")
    folder = ctx.agent.expand(NATIVE_VERSIONS)
    versions = [v for v in (ctx.sources.list_dir(folder) or []) if VERSION.fullmatch(v)] if folder else []
    if versions:
        newest = max(versions, key=_version_key)
        note = "a native install" + (f"; the newest of {len(versions)} installed, as the command line doesn't say which runs"
                                     if len(versions) > 1 else "")
        return ctx.result("ANSWERED", "harness_identity", value=f"claude-code/{newest}",
                          source=f"{NATIVE_VERSIONS}/{newest}", note=note)
    return None


# --- policy ----------------------------------------------------------------

def _permissions(ctx: Any) -> tuple[dict[str, list[str]], list[str], list[str]]:
    """The allow, deny and ask rules merged across settings files, the files
    they came from, and notes on rules Claude Code ignores."""
    layers = _layers(ctx)
    notes: list[str] = []
    if any(scope == "managed" and doc.get("allowManagedPermissionRulesOnly") is True for scope, _, doc in layers):
        layers = [layer for layer in layers if layer[0] == "managed"]
        notes.append("managed settings allow only managed permission rules (allowManagedPermissionRulesOnly)")
    trusted = _project_state(ctx).get("hasTrustDialogAccepted") is True
    rules: dict[str, list[str]] = {kind: [] for kind in RULE_KINDS}
    sources: list[str] = []
    for scope, path, doc in layers:
        permissions = doc.get("permissions")
        if not isinstance(permissions, dict):
            continue
        used = False
        for kind in RULE_KINDS:
            listed = [r for r in permissions.get(kind) or [] if isinstance(r, str) and r.strip()] \
                if isinstance(permissions.get(kind), list) else []
            # Only the shared .claude/settings.json is gated: settings.local.json
            # is the user's own, uncommitted file, and Claude Code applies it.
            if kind == "allow" and listed and scope == "project" and not trusted:
                notes.append(f"{len(listed)} allow rule(s) in {path} ignored: Claude Code skips a project's allow "
                             "rules until its workspace is trusted")
                continue
            for rule in listed:
                if rule not in rules[kind]:
                    rules[kind].append(rule)
                    used = True
        if used:
            sources.append(path)
    return {kind: listed for kind, listed in rules.items() if listed}, sources, notes


def _hooks(ctx: Any) -> tuple[dict[str, list[str]], list[str], list[str]]:
    """Hooks merged across settings files, by event and matcher only (a
    hook's command can carry anything, so it is never reported)."""
    layers = _layers(ctx)
    notes: list[str] = []
    if any(doc.get("disableAllHooks") is True for _, _, doc in layers):
        return {}, [], ["hooks are disabled (disableAllHooks)"]
    if any(scope == "managed" and doc.get("allowManagedHooksOnly") is True for scope, _, doc in layers):
        layers = [layer for layer in layers if layer[0] == "managed"]
        notes.append("managed settings allow only managed hooks (allowManagedHooksOnly)")
    events: dict[str, list[str]] = {}
    sources: list[str] = []
    for _, path, doc in layers:
        hooks = doc.get("hooks")
        if not isinstance(hooks, dict):
            continue
        used = False
        for event, groups in hooks.items():
            if not isinstance(event, str) or not SHORT_WORD.fullmatch(event) or not isinstance(groups, list):
                continue
            for group in groups:
                if not isinstance(group, dict) or not isinstance(group.get("hooks"), list) or not group["hooks"]:
                    continue
                matcher = group.get("matcher")
                matcher = matcher if isinstance(matcher, str) and matcher.strip() and len(matcher) <= 128 else "*"
                listed = events.setdefault(event, [])
                if matcher not in listed:
                    listed.append(matcher)
                used = True
        if used:
            sources.append(path)
    return events, sources, notes


# --- transcripts -----------------------------------------------------------

def _project_folder(ctx: Any) -> str | None:
    """The folder Claude Code keeps the agent's project's transcripts in:
    its path with every character but a letter or digit made a dash."""
    project = ctx.agent.expand("$CLAUDE_PROJECT")
    return re.sub(r"[^A-Za-z0-9]", "-", project.rstrip("/") or "/") if project else None


def _transcript_files(ctx: Any, reader: Any) -> tuple[list[tuple[str, str]], str | None]:
    """(the path reported, the path read) of the transcripts to read, and a
    note when the file cap left some unread (RC-530). Every session and
    subagent transcript is listed, the agent's own project first, up to
    TRANSCRIPT_MAX_CANDIDATES; past TRANSCRIPT_MAX_FILES, the newest are
    read (reader.newest_first), since Claude Code names them by UUID and
    name order would pick arbitrary ones. A project folder's name is a
    working directory's path (the agent's own, or another project it ran
    in), so it is never reported, like the working directory itself: the
    agent's own is reported as <$CLAUDE_PROJECT>, any other as <project N>."""
    base = ctx.agent.expand("$CLAUDE_DIR/projects")
    folders = ctx.sources.list_dir(base) if base else None
    if not folders:
        return [], None
    own = _project_folder(ctx)
    files: list[tuple[str, str]] = []
    others = 0
    limit = reader.TRANSCRIPT_MAX_CANDIDATES
    more = False
    for folder in sorted(folders, key=lambda name: (name != own, name)):
        if more:
            break
        if folder == own:
            shown_folder = "<$CLAUDE_PROJECT>"
        else:
            others += 1
            shown_folder = f"<project {others}>"
        names = ctx.sources.list_dir(f"{base}/{folder}") or []
        for name in names:
            if len(files) >= limit:
                more = True
                break
            if name.endswith(".jsonl"):
                files.append((f"$CLAUDE_DIR/projects/{shown_folder}/{name}", f"{base}/{folder}/{name}"))
                continue
            # A session's subagents keep their own transcripts beside it.
            for sub in ctx.sources.list_dir(f"{base}/{folder}/{name}/subagents") or []:
                if not sub.endswith(".jsonl"):
                    continue
                if len(files) >= limit:
                    more = True
                    break
                files.append((f"$CLAUDE_DIR/projects/{shown_folder}/{name}/subagents/{sub}",
                              f"{base}/{folder}/{name}/subagents/{sub}"))
    return reader.newest_first(ctx.sources, files, lambda item: item[1], more)


def _tool_names(entry: Any) -> list[str]:
    """The tools an assistant entry called, by name only: never a call's
    input, and never a name from any other kind of entry."""
    if not isinstance(entry, dict) or entry.get("type") != "assistant":
        return []
    message = entry.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, list):
        return []
    return [part["name"] for part in content if isinstance(part, dict) and part.get("type") in TOOL_USE_TYPES
            and isinstance(part.get("name"), str) and part["name"]]


def register(reader: Any) -> None:
    @reader.hook("claude_identity")
    def identity(ctx: Any, field: str, spec: dict[str, Any]) -> dict[str, Any]:
        found = _identity(ctx)
        if found:
            return found
        return ctx.result("BLIND", field, reason="NO_SOURCE_ACCESS",
                          note="claude-code: no npm package or native install was found")

    @reader.hook("claude_model")
    def model(ctx: Any, field: str, spec: dict[str, Any]) -> dict[str, Any]:
        name, source, note = _model(ctx)
        if field == "model_name":
            if name:
                return ctx.result("ANSWERED", field, value=name, source=source,
                                  **({"note": note} if note else _higher_failed_note(ctx, source)))
            return _no_value(ctx, field, "--model, ANTHROPIC_MODEL and model")
        endpoint, endpoint_source = _setting_env(ctx, "ANTHROPIC_BASE_URL")
        if field == "inference_endpoint":
            if endpoint:
                return ctx.result("ANSWERED", field, value=endpoint, source=endpoint_source, note="ANTHROPIC_BASE_URL")
            return _no_value(ctx, field, "ANTHROPIC_BASE_URL (so Claude Code's default endpoint)")
        for flag, vendor in CLOUD_FLAGS:
            value, flag_source = _setting_env(ctx, flag)
            if _truthy(value):
                return ctx.result("ANSWERED", field, value=vendor, source=flag_source, note=flag)
        vendor = _vendor(endpoint)
        if vendor:
            return ctx.result("ANSWERED", field, value=vendor, source=endpoint_source,
                              note="from the ANTHROPIC_BASE_URL host")
        if endpoint and name and CLAUDE_MODEL.search(name):
            return ctx.result("ANSWERED", field, value="anthropic", source=source,
                              note="the model is Anthropic's; requests go through the custom endpoint in inference_endpoint")
        if endpoint:
            return ctx.result("ABSENT", field, method="claude-code: ANTHROPIC_BASE_URL is a custom endpoint and the model "
                                                       "doesn't name a provider")
        if any(s["error"] for s in ctx.config_sources) and not name:
            return _no_value(ctx, field, "the model's provider")
        return ctx.result("ANSWERED", field, value="anthropic", source=source or "claude-code default",
                          note="Claude Code's default endpoint, api.anthropic.com: no ANTHROPIC_BASE_URL or "
                               "CLAUDE_CODE_USE_* is set")

    @reader.hook("claude_mcp")
    def mcp(ctx: Any, field: str, spec: dict[str, Any]) -> dict[str, Any]:
        text = ctx.sources.read_text(MANAGED_MCP, reader.SOURCE_MAX_BYTES)
        managed = None
        if text is not None:
            try:
                managed = (ctx.loads(text) or {}).get("mcpServers")
            except (ValueError, AttributeError):
                return ctx.result("FAILED", field, reason="PARSE_FAILED", note=f"{MANAGED_MCP} could not be parsed")
        if isinstance(managed, dict):
            # Exclusive control: Claude Code loads these and no others.
            # `exclusive` tells the MCP probe (RC-531) to ask these servers
            # and no others; the bundle's attribute doesn't carry it.
            return ctx.result("ANSWERED", field, value=managed, source=MANAGED_MCP, exclusive=True,
                              note="managed-mcp.json takes exclusive control: no other server is loaded")
        servers: dict[str, Any] = {}
        sources: list[str] = []
        problems: list[str] = []
        user = _state(ctx).get("mcpServers")
        if isinstance(user, dict) and user:
            servers.update(user)
            sources.append(STATE)
        project_path = ctx.agent.expand(PROJECT_MCP)
        if project_path:
            text = ctx.sources.read_text(project_path, reader.SOURCE_MAX_BYTES)
            if text is not None:
                try:
                    project = (ctx.loads(text) or {}).get("mcpServers")
                except (ValueError, AttributeError):
                    problems.append(f"{PROJECT_MCP} could not be parsed")
                    project = None
                if isinstance(project, dict) and project:
                    servers.update(project)
                    sources.append(PROJECT_MCP)
        local = _project_state(ctx).get("mcpServers")
        if isinstance(local, dict) and local:
            servers.update(local)  # local scope wins on a name
            sources.append(f"{STATE} (projects[$CLAUDE_PROJECT].mcpServers)")
        if servers:
            if problems:
                return ctx.result("PARTIAL", field, value=servers, reason="PARSE_FAILED", source=sources,
                                  note="; ".join(problems))
            return ctx.result("ANSWERED", field, value=servers, source=sources if len(sources) > 1 else sources[0])
        if problems:
            return ctx.result("FAILED", field, reason="PARSE_FAILED", note="; ".join(problems))
        state = next((s for s in ctx.config_sources if s["spec"] == STATE), None)
        if state and state["error"]:
            return ctx.result("FAILED", field, reason=state["reason"], note=state["error"])
        if state is None or state["doc"] is reader._MISSING:
            return ctx.result("BLIND", field, reason="NO_SOURCE_ACCESS", note=f"claude-code: {STATE} could not be read")
        return ctx.result("ABSENT", field, method=f"claude-code: no mcpServers in {STATE} or {PROJECT_MCP}")

    @reader.hook("claude_permissions")
    def permissions(ctx: Any, field: str, spec: dict[str, Any]) -> dict[str, Any]:
        rules, sources, notes = _permissions(ctx)
        if not rules:
            result = _no_value(ctx, field, "permissions.allow, .deny and .ask")
            if notes:
                result["note"] = "; ".join([*notes, *([result["note"]] if result.get("note") else [])])
            return result
        return ctx.result("ANSWERED", field, value=rules, source=sources if len(sources) > 1 else sources[0],
                          **({"note": "; ".join(notes)} if notes else {}))

    @reader.hook("claude_approvals")
    def approvals(ctx: Any, field: str, spec: dict[str, Any]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        sources: list[str] = []
        notes: list[str] = []
        layers = _layers(ctx)
        for _, path, doc in layers:
            mode = (doc.get("permissions") or {}).get("defaultMode") if isinstance(doc.get("permissions"), dict) else None
            if isinstance(mode, str) and SHORT_WORD.fullmatch(mode):
                value["defaultMode"] = mode
                sources.append(path)
                break
        for _, path, doc in layers:
            disable = (doc.get("permissions") or {}).get("disableBypassPermissionsMode") \
                if isinstance(doc.get("permissions"), dict) else None
            if disable == "disable":
                value["disableBypassPermissionsMode"] = "disable"
                if path not in sources:
                    sources.append(path)
                break
        command_mode = "bypassPermissions" if "--dangerously-skip-permissions" in ctx.agent.cmdline.split() \
            else _flag(ctx, "--permission-mode")
        if command_mode:
            value["commandLineMode"] = command_mode
            sources.append("command line")
            if command_mode == "bypassPermissions" and value.get("disableBypassPermissionsMode") == "disable":
                notes.append("the command line asks to bypass permissions, which settings disable")
        hooks, hook_sources, hook_notes = _hooks(ctx)
        notes += hook_notes
        if hooks:
            value["hooks"] = hooks
            sources += [s for s in hook_sources if s not in sources]
        if not value:
            result = _no_value(ctx, field, "permissions.defaultMode and hooks")
            if notes:
                result["note"] = "; ".join([*notes, *([result["note"]] if result.get("note") else [])])
            return result
        return ctx.result("ANSWERED", field, value=value, source=sources if len(sources) > 1 else sources[0],
                          **({"note": "; ".join(notes)} if notes else {}))

    @reader.hook("claude_transcripts")
    def transcripts(ctx: Any, field: str, spec: dict[str, Any]) -> dict[str, Any]:
        counts: dict[str, int] = {}
        read: list[str] = []
        capped: list[str] = []
        bad_lines = 0
        chosen, file_note = _transcript_files(ctx, reader)
        for shown, path in chosen:
            text, cut = reader._read_capped(ctx, path, reader.TRANSCRIPT_MAX_BYTES)
            if text is None:
                continue
            if cut:  # the whole lines read count; the one the cap cut is not a bad line
                text = text.rpartition("\n")[0]
                capped.append(shown)
            read.append(shown)
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    entry = ctx.loads(line)
                except ValueError:
                    bad_lines += 1
                    continue
                for name in _tool_names(entry):
                    counts[name] = counts.get(name, 0) + 1
        if not read:
            return ctx.result("BLIND", field, reason="NO_SOURCE_ACCESS", note="claude-code: no transcript could be read")
        # The bundle's shape: the names, sorted; a floor, not a count.
        value = sorted(counts)
        notes = [n for n in (file_note,
                             f"read up to {reader.TRANSCRIPT_MAX_BYTES} bytes of {', '.join(capped)}" if capped else None,
                             f"{bad_lines} transcript line(s) could not be parsed" if bad_lines else None) if n]
        source = read if len(read) > 1 else read[0]
        if not value and not file_note:
            if bad_lines:
                return ctx.result("FAILED", field, reason="PARSE_FAILED",
                                  note=f"{bad_lines} transcript line(s) could not be parsed")
            return ctx.result("ABSENT", field, method=f"claude-code: no tool calls in {len(read)} transcript(s)")
        if file_note or capped:
            # Transcripts left unread (RC-530), or one cut short: a floor, and
            # none found isn't "none" (an empty floor, not ABSENT).
            return ctx.result("PARTIAL", field, value=value, reason="SIZE_CAP_EXCEEDED", source=source,
                              note=f"{FLOOR}; " + "; ".join(notes))
        if bad_lines:
            return ctx.result("PARTIAL", field, value=value, reason="PARSE_FAILED", source=source,
                              note=f"{FLOOR}; " + "; ".join(notes))
        return ctx.result("ANSWERED", field, value=value, source=source, note=FLOOR)

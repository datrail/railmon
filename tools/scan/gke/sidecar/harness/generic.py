"""The generic reader (RC-520): the harness fields that need no profile.

The shared reader (reader.py, beside this file) runs this when no profile's
markers match the agent (`harness_reader_for` gives None). An unknown harness
keeps its own files in its own formats, so nothing here guesses at them. It
reads only what any harness may use:

* `.mcp.json` (its `mcpServers`, or `servers` as some editors write it) in
  each --config-path folder, the agent's working directory, its home and
  /workdir, and an `mcpServers` key in the top-level *.json files under
  --config-path: mcp_servers_declared;
* `AGENTS.md` in the same folders: system_prompt_present, and its text only
  with --collect-system-prompt;
* the agent's `*_MODEL` and `*_BASE_URL` environment variables, the ones the
  scanner already knows first: model_name, inference_endpoint and, from a
  vendor's name in them, llm_provider;
* model-like keys (`model`, `modelName`, `defaultModel`, ...), base-URL keys
  beside them, provider keys, and permission- and approval-named keys in the
  top-level *.json files under --config-path: model_name, llm_provider,
  inference_endpoint, tool_allow_deny and approval_policy.

Every harness field it can't fill is BLIND with UNKNOWN_HARNESS: a harness
without a profile may keep that field anywhere, so not finding it is never
evidence that it is unset. harness_identity, tool_names and skills_inventory
are always so, since only a profile knows the harness's version, transcripts
and skills folders.

Like reader.py it imports nothing of railmon's: `read_generic_config` is
handed the reader module, whose `Sources`, `Agent`, result shape and caps it
uses.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable

GENERIC = "generic"
UNKNOWN = "UNKNOWN_HARNESS"

MCP_FILE = ".mcp.json"
PROMPT_FILE = "AGENTS.md"
# Folders an MCP config or AGENTS.md is looked for in besides --config-path,
# as the agent sees them: its working directory, its home, and the scanner's
# own default MCP folder.
AGENT_FOLDERS = ("$AGENT_CWD", "~", "/workdir")

# The variables the scanner itself reads (scan_agent_environment's
# detect_model and collect_model_egress), first and in its order; then any
# other *_MODEL or *_BASE_URL only when its name says a model service: an
# app's APP_BASE_URL or a framework's AUTH_USER_MODEL is not the agent's model.
KNOWN_MODEL_VARS = ("RAIL_LLM_MODEL", "LLM_MODEL", "OPENAI_MODEL", "ANTHROPIC_MODEL", "OPENCLAW_MODEL")
KNOWN_BASE_URL_VARS = ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE", "RAIL_LLM_BASE_URL",
                       "LLM_BASE_URL")
MODEL_VAR = re.compile(r"^[A-Z0-9_]+_MODEL$")
BASE_URL_VAR = re.compile(r"^[A-Z0-9_]+_BASE_URL$")
# A *_MODEL that names another kind of model than the one the agent talks to.
NOT_CHAT_MODEL_WORDS = ("EMBED", "RERANK", "WHISPER", "TTS", "STT", "TRANSCRIB")

# Vendors, by a word that names them in a variable, a model's "vendor/model"
# prefix or a provider key, and the name llm_provider reports.
PROVIDERS = {
    "openai": "openai", "anthropic": "anthropic", "claude": "anthropic", "gemini": "google",
    "google": "google", "vertex": "google-vertex", "azure": "azure", "bedrock": "aws-bedrock",
    "mistral": "mistral", "groq": "groq", "ollama": "ollama", "deepseek": "deepseek", "cohere": "cohere",
    "openrouter": "openrouter", "together": "together", "fireworks": "fireworks", "xai": "xai",
    "grok": "xai", "perplexity": "perplexity", "litellm": "litellm",
}
# The words, as whole parts of a variable's name split at "_", that say it
# names a model service. MODEL counts only for a *_BASE_URL, since every
# *_MODEL has it; AGENT only for a *_MODEL (AGENT_MODEL is the agent's
# model, AGENT_BASE_URL is likely its own address).
LLM_NAME_WORDS = frozenset({"LLM", "LLMS", "AI", "GENAI", "INFERENCE", "CHAT", "COMPLETION", "COMPLETIONS",
                            *(word.upper() for word in PROVIDERS)})
MODEL_VAR_WORDS = LLM_NAME_WORDS | {"AGENT"}
BASE_URL_VAR_WORDS = LLM_NAME_WORDS | {"MODEL", "MODELS"}

# Keys, compared with case and separators folded away.
MODEL_KEYS = frozenset({"model", "models", "modelname", "modelid", "defaultmodel", "llmmodel", "primarymodel",
                        "chatmodel"})
MODEL_OBJECT_KEYS = ("primary", "default", "name", "id", "model")
BASE_URL_KEYS = frozenset({"baseurl", "apibase", "apibaseurl", "llmbaseurl", "modelbaseurl", "endpoint",
                           "apiendpoint"})
PROVIDER_KEYS = frozenset({"provider", "llmprovider", "modelprovider"})
# Where a base URL is the model's: under a key naming one of these, or beside
# a model key.
MODEL_CONTEXT_WORDS = ("model", "provider", "llm", "inference")
MCP_KEYS = frozenset({"mcpservers"})
# Permission-named keys, as the bundle's own reader names them
# (evidence_bundle.PERMISSION_KEY_ALIASES) and the tool lists harnesses use.
PERMISSION_KEYS = frozenset({"permission", "permissions", "allowtools", "denytools", "allowedtools",
                             "disallowedtools", "deniedtools", "blockedtools", "toolallowlist", "tooldenylist",
                             "toolpermissions", "toolpolicy"})
# An allow or deny list under a key naming tools (`tools.allow`) is one too.
TOOL_RULE_KEYS = frozenset({"allow", "deny", "ask", "allowlist", "denylist", "blocklist"})
APPROVAL_WORD = "approval"


def _fold(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _provider_word(text: str) -> str | None:
    """The vendor a name or prefix names, by a whole word in it."""
    for word in re.split(r"[^a-z0-9]+", text.lower()):
        if word in PROVIDERS:
            return PROVIDERS[word]
    return None


class _Walk:
    """What the top-level *.json files under --config-path declare, found at
    any depth (documents are already depth-capped by the reader's parser):
    each (file, key path, value), in file order then document order.

    A credential-named key (env, headers, auth, secrets, apiKey, ...; the
    reader's is_credential_key) is neither taken nor walked into: a value
    found under it is kept under a flattened path (env.APPROVAL_KEY) that no
    longer names the credential key, so redaction, which judges each key by
    its own name, would let it through."""

    def __init__(self, is_credential_key: Callable[[Any], bool]) -> None:
        self.is_credential_key = is_credential_key
        self.models: list[tuple[str, str, str]] = []
        self.base_urls: list[tuple[str, str, str]] = []
        self.providers: list[tuple[str, str, str]] = []
        self.mcp: list[tuple[str, str, dict[str, Any]]] = []
        self.permissions: list[tuple[str, str, Any]] = []
        self.approvals: list[tuple[str, str, Any]] = []

    def document(self, shown: str, doc: Any) -> None:
        pending: list[tuple[Any, str]] = [(doc, "")]
        while pending:
            item, path = pending.pop(0)
            if isinstance(item, list):
                pending[0:0] = [(child, f"{path}.{i}" if path else str(i)) for i, child in enumerate(item)]
                continue
            if not isinstance(item, dict):
                continue
            keys = {_fold(k) for k in item}
            beside_model = bool(keys & MODEL_KEYS)
            children = []
            for key, value in item.items():
                folded, where = _fold(key), f"{path}.{key}" if path else str(key)
                if self.is_credential_key(key):
                    continue
                if folded in MCP_KEYS and isinstance(value, dict):
                    self.mcp.append((shown, where, value))
                    continue
                if folded in PERMISSION_KEYS or (folded in TOOL_RULE_KEYS and "tool" in path.lower()):
                    self.permissions.append((shown, where, value))
                    continue
                if APPROVAL_WORD in folded:
                    self.approvals.append((shown, where, value))
                    continue
                if folded in MODEL_KEYS:
                    model = _model_value(value)
                    if model:
                        self.models.append((shown, where, model))
                if folded in PROVIDER_KEYS and isinstance(value, str) and value.strip():
                    self.providers.append((shown, where, value.strip()))
                if (folded in BASE_URL_KEYS and isinstance(value, str) and "://" in value
                        and (beside_model or any(w in path.lower() for w in MODEL_CONTEXT_WORDS))):
                    self.base_urls.append((shown, where, value.strip()))
                children.append((value, where))
            pending[0:0] = children


def _model_value(value: Any) -> str | None:
    """A model's name: a string, or the primary/default/name of an object
    (`{"model": {"primary": "vendor/x"}}`); a list or anything else names
    several models or none."""
    if isinstance(value, str) and value.strip() and "://" not in value:
        return value.strip()
    if isinstance(value, dict):
        for key in MODEL_OBJECT_KEYS:
            inner = value.get(key)
            if isinstance(inner, str) and inner.strip() and "://" not in inner:
                return inner.strip()
    return None


def _ranked_vars(env: dict[str, str], known: tuple[str, ...], pattern: re.Pattern[str],
                 words: frozenset[str], skip: Callable[[str], bool] = lambda name: False) -> list[str]:
    """The variables set to something: the known ones first, in their order,
    then, by name, any other matching `pattern` whose name has one of
    `words` as a whole part (OPENAI_COMPAT_BASE_URL, AGENT_LLM_MODEL). A
    variable whose name says no model service (APP_BASE_URL, DATA_MODEL) is
    never taken, so a base URL the config puts beside its model wins over it."""
    names = [name for name in known if (env.get(name) or "").strip()]
    others = sorted(name for name, value in env.items()
                    if name not in known and pattern.match(name) and (value or "").strip() and not skip(name)
                    and words & set(name.split("_")))
    return names + others


class GenericReader:
    def __init__(self, reader: Any, agent: Any, sources: Any, config_paths: Iterable[str],
                 collect_prompt: bool, loads: Callable[[str], Any]):
        self.reader, self.agent, self.sources = reader, agent, sources
        self.collect_prompt, self.loads = collect_prompt, loads
        self.config_files: list[str] = []
        self.config_folders: list[str] = []
        for raw in config_paths:
            path = str(raw).rstrip("/") or "/"
            if path.endswith(".json"):
                self.config_files.append(path)
                self.config_folders.append(path.rpartition("/")[0] or "/")
            else:
                self.config_folders.append(path)
        self.config_folders = list(dict.fromkeys(self.config_folders))
        self.read: list[str] = []      # files parsed
        self.failed: list[tuple[str, str, str]] = []  # (file, reason, note), every file
        self.config_failed: list[tuple[str, str, str]] = []  # the top-level *.json only

    # --- the folders and files looked in --------------------------------

    def _folders(self) -> list[tuple[str, str]]:
        """(the folder reported, the folder read): the --config-path folders
        as given (the operator's, not the agent's environment), then the
        agent's own folders as written here."""
        folders = [(folder, folder) for folder in self.config_folders]
        for raw in AGENT_FOLDERS:
            expanded = self.agent.expand(raw)
            if expanded:
                folders.append((raw, expanded.rstrip("/") or "/"))
        seen, out = set(), []
        for shown, folder in folders:
            if folder not in seen:
                seen.add(folder)
                out.append((shown, folder))
        return out

    def _top_level_json(self) -> list[tuple[str, str]]:
        """The top-level *.json files under --config-path, .mcp.json aside,
        in name order, at most the reader's cap on drop-in files."""
        files = [(path, path) for path in self.config_files if not path.endswith("/" + MCP_FILE)]
        for folder in self.config_folders:
            names = self.sources.list_dir(folder) or []
            for name in sorted(names):
                if name.endswith(".json") and name != MCP_FILE:
                    path = f"{folder.rstrip('/')}/{name}"
                    files.append((path, path))
        return list(dict.fromkeys(files))[:self.reader.SOURCE_GLOB_MAX_FILES]

    def _parse(self, shown: str, path: str) -> Any:
        """A JSON file's document, or the reader's _MISSING when it isn't
        there, can't be read, is over the cap or doesn't parse (the last two
        recorded in `failed`)."""
        cap = self.reader.SOURCE_MAX_BYTES
        text = self.sources.read_text(path, cap + 1)
        if text is None:
            return self.reader._MISSING
        if len(text.encode("utf-8", errors="replace")) > cap:
            self.failed.append((shown, "SIZE_CAP_EXCEEDED", f"{shown}: larger than {cap} bytes, so not read"))
            return self.reader._MISSING
        try:
            doc = self.loads(text)
        except ValueError as exc:
            self.failed.append((shown, "PARSE_FAILED", f"{shown}: {exc}"))
            return self.reader._MISSING
        self.read.append(shown)
        return doc

    # --- results ----------------------------------------------------------

    def result(self, status: str, field: str, **extra: Any) -> dict[str, Any]:
        return self.reader._result(status, field, **extra)

    def unknown(self, field: str, looked: str) -> dict[str, Any]:
        """BLIND with UNKNOWN_HARNESS, or FAILED when a file that may have
        held the field couldn't be read (as a profile reports it)."""
        if self.config_failed:
            first = self.config_failed[0]
            return self.result("FAILED", field, reason=first[1],
                               note=f"{GENERIC}: {looked}; " + "; ".join(f[2] for f in self.config_failed))
        return self.result("BLIND", field, reason=UNKNOWN,
                           note=f"no harness profile matched the agent, and the generic reader found none: {looked}")

    def read_all(self) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        walk = _Walk(self.reader.is_credential_key)
        config_files = self._top_level_json()
        for shown, path in config_files:
            doc = self._parse(shown, path)
            if doc is not self.reader._MISSING:
                walk.document(shown, doc)
        self.config_failed = list(self.failed)
        config_where = ("the top-level *.json under " + ", ".join(self.config_folders)) if self.config_folders \
            else "no --config-path"

        results["mcp_servers_declared"] = self._mcp(walk)
        results.update(self._prompt())
        results.update(self._model_fields(walk, config_where))
        results.update(self._policy_fields(walk, config_where))
        for field, what in (("harness_identity", "only a harness profile knows the harness and its version"),
                            ("tool_names", "only a harness profile knows where its transcripts are"),
                            ("mcp_servers_observed", "only a harness profile knows where its transcripts are"),
                            ("skills_inventory", "only a harness profile knows where its skills are")):
            results[field] = self.result("BLIND", field, reason=UNKNOWN,
                                         note=f"no harness profile matched the agent: {what}")
        return results

    def _mcp(self, walk: _Walk) -> dict[str, Any]:
        """Every MCP config's servers, the earlier (a --config-path's own
        .mcp.json first) winning on a name."""
        found: list[tuple[str, dict[str, Any]]] = []
        mcp_read: list[str] = []
        mcp_failed_before = len(self.failed)
        for shown, folder in self._folders():
            label = f"{shown.rstrip('/')}/{MCP_FILE}"
            doc = self._parse(label, f"{folder.rstrip('/')}/{MCP_FILE}")
            if doc is self.reader._MISSING:
                continue
            mcp_read.append(label)
            servers = doc.get("mcpServers", doc.get("servers")) if isinstance(doc, dict) else None
            if isinstance(servers, dict) and servers:
                found.append((label, servers))
        for shown, where, servers in walk.mcp:
            mcp_read.append(f"{shown} ({where})")
            if servers:
                found.append((f"{shown} ({where})", servers))
        # A top-level *.json that couldn't be read may hold an mcpServers
        # key, so its failure counts here as an .mcp.json's does.
        mcp_failed = self.config_failed + self.failed[mcp_failed_before:]
        if found:
            merged: dict[str, Any] = {}
            for _, servers in reversed(found):
                merged.update(servers)
            sources = [label for label, _ in found]
            extra: dict[str, Any] = {"source": sources[0] if len(sources) == 1 else sources}
            if mcp_failed:
                extra["note"] = "an MCP config could not be read: " + "; ".join(f[2] for f in mcp_failed)
            return self.result("ANSWERED", "mcp_servers_declared", value=merged, **extra)
        # A config that couldn't be read may hold the servers the others
        # don't, so its failure outranks "none declared" (as reader.py's
        # profiles report it: none had it and one could not be parsed).
        if mcp_failed:
            note = "; ".join(f[2] for f in mcp_failed)
            if mcp_read:
                note += f"; no MCP server in {', '.join(mcp_read)}"
            return self.result("FAILED", "mcp_servers_declared", reason=mcp_failed[0][1], note=note)
        if mcp_read:
            return self.result("ABSENT", "mcp_servers_declared",
                               method=f"{GENERIC}: no MCP server in {', '.join(mcp_read)}")
        looked = ", ".join(f"{shown.rstrip('/')}/{MCP_FILE}" for shown, _ in self._folders()) or "no folder"
        return self.result("BLIND", "mcp_servers_declared", reason=UNKNOWN,
                           note=f"no harness profile matched the agent, and no MCP config was found in {looked} "
                                "or the top-level *.json under --config-path; the harness may keep its MCP "
                                "servers elsewhere")

    def _prompt(self) -> dict[str, dict[str, Any]]:
        present, texts = [], {}
        looked = []
        for shown, folder in self._folders():
            label = f"{shown.rstrip('/')}/{PROMPT_FILE}"
            looked.append(label)
            text = self.sources.read_text(f"{folder.rstrip('/')}/{PROMPT_FILE}",
                                          self.reader.PROMPT_TEXT_MAX_CHARS * 4)
            if text is not None:
                present.append(label)
                texts[label] = text[:self.reader.PROMPT_TEXT_MAX_CHARS]
        if not present:
            note = (f"no harness profile matched the agent, and there is no {PROMPT_FILE} in "
                    f"{', '.join(looked) or 'no folder'}; the harness may keep its prompt elsewhere")
            return {field: self.result("BLIND", field, reason=UNKNOWN, note=note)
                    for field in ("system_prompt_present", "system_prompt_text")}
        out = {"system_prompt_present": self.result("ANSWERED", "system_prompt_present",
                                                     value={"present": True, "files": present}, source=present)}
        if self.collect_prompt:
            out["system_prompt_text"] = self.result("ANSWERED", "system_prompt_text", value=texts, source=present)
        else:
            out["system_prompt_text"] = self.result("BLIND", "system_prompt_text", reason="NOT_COLLECTED_BY_PACK",
                                                    note="prompt text is read only with --collect-system-prompt")
        return out

    def _model_fields(self, walk: _Walk, config_where: str) -> dict[str, dict[str, Any]]:
        env = self.agent.env
        out: dict[str, dict[str, Any]] = {}

        model_vars = _ranked_vars(env, KNOWN_MODEL_VARS, MODEL_VAR, MODEL_VAR_WORDS,
                                  skip=lambda name: any(word in name for word in NOT_CHAT_MODEL_WORDS))
        model: tuple[str, str] | None = None  # (value, source)
        if model_vars:
            model = (env[model_vars[0]].strip(), f"${model_vars[0]}")
            others = [f"${name}" for name in model_vars[1:]]
        elif walk.models:
            model = (walk.models[0][2], f"{walk.models[0][0]} ({walk.models[0][1]})")
            others = [f"{s} ({w})" for s, w, _ in walk.models[1:]]
        if model:
            extra = {"note": "also set: " + ", ".join(others[:10])} if others else {}
            out["model_name"] = self.result("ANSWERED", "model_name", value=model[0], source=model[1], **extra)
        else:
            out["model_name"] = self.unknown("model_name", f"no *_MODEL variable and no model key in {config_where}")

        url_vars = _ranked_vars(env, KNOWN_BASE_URL_VARS, BASE_URL_VAR, BASE_URL_VAR_WORDS)
        endpoint: tuple[str, str] | None = None
        if url_vars:
            endpoint = (env[url_vars[0]].strip(), f"${url_vars[0]}")
            others = [f"${name}" for name in url_vars[1:]]
        elif walk.base_urls:
            endpoint = (walk.base_urls[0][2], f"{walk.base_urls[0][0]} ({walk.base_urls[0][1]})")
            others = [f"{s} ({w})" for s, w, _ in walk.base_urls[1:]]
        if endpoint:
            extra = {"note": "also set: " + ", ".join(others[:10])} if others else {}
            out["inference_endpoint"] = self.result("ANSWERED", "inference_endpoint", value=endpoint[0],
                                                    source=endpoint[1], **extra)
        else:
            out["inference_endpoint"] = self.unknown(
                "inference_endpoint", f"no *_BASE_URL variable and no model base URL in {config_where}")

        # The provider: a provider key; else the vendor a "vendor/model"
        # name starts with; else the vendor the model's or endpoint's
        # variable is named for.
        provider: tuple[str, str] | None = None
        if walk.providers:
            provider = (walk.providers[0][2], f"{walk.providers[0][0]} ({walk.providers[0][1]})")
        elif model and "/" in model[0] and _provider_word(model[0].split("/", 1)[0]):
            provider = (_provider_word(model[0].split("/", 1)[0]), f"{model[1]}, the model's vendor prefix")
        else:
            for found in (model, endpoint):
                if found and found[1].startswith("$") and _provider_word(found[1][1:]):
                    provider = (_provider_word(found[1][1:]), f"{found[1]}, the variable's name")
                    break
        if provider:
            out["llm_provider"] = self.result("ANSWERED", "llm_provider", value=provider[0], source=provider[1])
        else:
            out["llm_provider"] = self.unknown(
                "llm_provider", f"no provider key in {config_where}, and no vendor named by the model or "
                                "its variables")
        return out

    def _policy_fields(self, walk: _Walk, config_where: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for field, found, what in (("tool_allow_deny", walk.permissions, "permission-named"),
                                   ("approval_policy", walk.approvals, "approval-named")):
            if found:
                value: dict[str, dict[str, Any]] = {}
                for shown, where, item in found:
                    value.setdefault(shown, {})[where] = item
                sources = list(value)
                out[field] = self.result("ANSWERED", field, value=value,
                                         source=sources[0] if len(sources) == 1 else sources,
                                         note=f"the {what} keys as the files declare them; a harness without a "
                                              "profile may enforce more than this")
            else:
                out[field] = self.unknown(field, f"no {what} key in {config_where}; absence is NOT evidence "
                                                 "of restriction")
        return out


def read_generic_config(reader: Any, agent: Any, sources: Any, config_paths: Iterable[str] = (), *,
                        collect_prompt: bool = False,
                        loads: Callable[[str], Any] | None = None) -> dict[str, dict[str, Any]]:
    """Every harness field for an agent no profile matched (see above),
    unredacted: the shared reader redacts them as it does a profile's.
    `config_paths` are the --config-path values, as the sidecar mounts them
    at the agent's own paths."""
    generic = GenericReader(reader, agent, sources, config_paths, collect_prompt, loads or reader.loads_json)
    return generic.read_all()

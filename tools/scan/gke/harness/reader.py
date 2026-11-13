"""The shared harness reader (RC-510): one reader for every agent harness.

A harness (OpenClaw, Claude Code, ...) keeps its model, MCP servers, tool
policy, transcripts and prompt files in its own files and formats. Rather than
a reader written for each one, a harness is described by a *profile* (see
README.md in this folder) and this module reads any harness from its profile:

* `harness_reader_for` picks the profile whose markers match the agent;
* `read_harness_fields` reads the profile's sources in order, picks each
  harness field by its key path, merges, redacts, and reports each field with
  the source it came from, or why there is no value.

Where the files are read from is the caller's business, through a `Sources`
object: pod mode reads the agent's container (harness_sources.py, beside this file),
and `LocalSources` reads this machine's files. This module imports nothing of
railmon's and runs nothing.

Statuses, per field:

* ANSWERED: a source had it (`source` names which).
* ABSENT: sources were read and none had it (`method` names them).
* FAILED (PARSE_FAILED): no source had it and one could not be parsed.
* BLIND (NO_SOURCE_ACCESS): no source could be read at all.
* BLIND (UNKNOWN_HARNESS): no profile matched the agent.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

# The fields a harness profile fills, and the tier each has in the bundle (the
# same tiers evidence_bundle.py gives them).
HARNESS_FIELDS: dict[str, str] = {
    "harness_identity": "declared",
    "model_name": "observed",
    "llm_provider": "declared",
    "inference_endpoint": "observed",
    "mcp_servers_declared": "declared",
    "tool_allow_deny": "declared",
    "approval_policy": "declared",
    "tool_names": "observed",
    "system_prompt_present": "observed",
    "system_prompt_text": "observed",
    "skills_inventory": "declared",
}
# Who the bundle says wrote each field's value (evidence_bundle.py's own
# choices); "subject" for the rest.
FIELD_AUTHORED_BY = {"tool_allow_deny": "platform", "approval_policy": "platform"}
# Policy fields: a harness that declares none may still be governed elsewhere
# (a gateway), so their absence is never evidence of restriction. Not found,
# they are BLIND with GATEWAY_MANAGED, as evidence_bundle.py reports them.
POLICY_FIELDS = ("tool_allow_deny", "approval_policy")
CONFIG_FIELDS = ("harness_identity", "model_name", "llm_provider", "inference_endpoint",
                 "mcp_servers_declared", "tool_allow_deny", "approval_policy")
SOURCE_MAX_BYTES = 64_000
PROMPT_TEXT_MAX_CHARS = 16_000
TRANSCRIPT_MAX_BYTES = 1_000_000
TRANSCRIPT_MAX_FILES = 50
MAX_JSON_DEPTH = 100
PROFILES_DIR = Path(__file__).resolve().with_name("profiles")

# Keys whose values are credentials or carry them (an MCP server's headers and
# env, a provider's apiKey). Matched as whole names, case and separators
# ignored, never as a substring: a key that is a name (an MCP server called
# github-auth, keycloak or token-proxy, a prompt file's path) is not one. A
# matching key is kept and only its value replaced, so nothing a harness
# declares is ever silently left out.
CREDENTIAL_KEYS = frozenset({
    "env", "headers", "header", "auth", "authorization", "bearer", "cookie", "cookies",
    "credential", "credentials", "password", "passwords", "passwd", "pwd", "passphrase",
    "secret", "secrets", "token", "tokens", "key", "keys", "apikey", "apikeys",
})
CREDENTIAL_KEY_ENDINGS = ("apikey", "apikeys", "secretkey", "privatekey", "privatekeys", "accesskey", "token",
                          "secret", "secrets", "password", "passwords", "passwd", "passphrase", "credential",
                          "credentials", "cookie", "cookies", "authorization")
# Stems that name a credential wherever they appear in a key: credentialsFile,
# privateKeyPem, clientSecretRef, dbPassword. None of them is part of an
# ordinary name, so github-auth, keycloak and token-proxy stay names.
CREDENTIAL_KEY_STEMS = ("password", "passwd", "passphrase", "secret", "credential", "privatekey", "apikey",
                        "accesskey", "authtoken", "accesstoken", "refreshtoken", "sessiontoken", "bearertoken")


def _folded(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def is_credential_container(key: Any) -> bool:
    """Whether a key names something that holds credentials as a whole,
    whatever its value's shape: env, headers, secrets, credentials, auth."""
    return _folded(key) in CREDENTIAL_KEYS


def is_credential_key(key: Any) -> bool:
    """Whether a key names a credential: apiKey, api_key, headers, env,
    AUTH_TOKEN, client_secret, privateKeyPem, ... but not github-auth,
    keycloak, maxTokens."""
    name = _folded(key)
    return (name in CREDENTIAL_KEYS or name.endswith(CREDENTIAL_KEY_ENDINGS)
            or any(stem in name for stem in CREDENTIAL_KEY_STEMS))
_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


# --- where files come from -------------------------------------------------

class Sources(Protocol):
    """How the reader reaches the agent's files. Paths are as the agent sees
    them (after `~` and `$VAR` are expanded); None means not there, or not
    readable as a regular file."""

    def read_text(self, path: str, max_bytes: int) -> str | None: ...

    def list_dir(self, path: str) -> list[str] | None: ...


class LocalSources:
    """This machine's files, optionally under `root`: regular files only,
    opened without blocking, capped."""

    def __init__(self, root: Path | None = None):
        self.root = root

    def _path(self, path: str) -> Path:
        return self.root / path.lstrip("/") if self.root else Path(path)

    def read_text(self, path: str, max_bytes: int) -> str | None:
        try:
            fd = os.open(self._path(path), os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            return os.read(fd, max_bytes).decode("utf-8", errors="replace")
        except OSError:
            return None
        finally:
            os.close(fd)

    def list_dir(self, path: str) -> list[str] | None:
        try:
            return sorted(os.listdir(self._path(path)))
        except OSError:
            return None


class Agent:
    """What the reader knows about the agent: its command line and
    environment (from its process), for markers and path expansion."""

    def __init__(self, cmdline: str = "", env: dict[str, str] | None = None):
        self.cmdline = cmdline or ""
        self.env = dict(env or {})

    def expand(self, path: str) -> str | None:
        """`~` and `$VAR` as the agent's environment gives them; None when a
        variable it names isn't set, so that source is skipped."""
        missing = False

        def var(match: re.Match[str]) -> str:
            nonlocal missing
            value = self.env.get(match.group(1))
            if not value:
                missing = True
                return ""
            return value

        expanded = _VAR.sub(var, path)
        if missing:
            return None
        if expanded == "~" or expanded.startswith("~/"):
            home = self.env.get("HOME")
            if not home:
                return None
            expanded = home.rstrip("/") + expanded[1:]
        return expanded


# --- profiles --------------------------------------------------------------

class ProfileError(ValueError):
    pass


def validate_profile(profile: Any) -> dict[str, Any]:
    """A profile as README.md describes it, or ProfileError saying what is
    wrong with it."""
    if not isinstance(profile, dict):
        raise ProfileError("a profile is a JSON object")
    name = profile.get("harness")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", name):
        raise ProfileError("harness: a lower-case name")
    markers = profile.get("markers")
    if not isinstance(markers, dict) or not any(markers.get(k) for k in ("commands", "env")):
        raise ProfileError(f"{name}: markers needs commands or env")
    sources = profile.get("sources", [])
    if not isinstance(sources, list) or not all(isinstance(s, dict) and isinstance(s.get("path"), str) for s in sources):
        raise ProfileError(f"{name}: sources is a list of {{\"path\": ...}}")
    for source in sources:
        if source.get("format", "json") != "json":
            raise ProfileError(f"{name}: {source['path']}: only json sources are read; use a hook for others")
    fields = profile.get("fields", {})
    if not isinstance(fields, dict):
        raise ProfileError(f"{name}: fields is an object")
    for field, spec in fields.items():
        if field not in HARNESS_FIELDS:
            raise ProfileError(f"{name}: {field} is not a harness field")
        if not isinstance(spec, (str, list, dict)):
            raise ProfileError(f"{name}: {field}: a key path, a list of them, or an object")
    return profile


def load_profiles(folder: Path = PROFILES_DIR) -> list[dict[str, Any]]:
    """The profiles shipped in `folder` (one *.json each), validated."""
    profiles = []
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            profiles.append(validate_profile(json.loads(path.read_text(encoding="utf-8"))))
        except (ValueError, OSError) as exc:
            raise ProfileError(f"{path.name}: {exc}") from exc
    return profiles


def _command_words(cmdline: str) -> set[str]:
    # The basename of each word, so `node /usr/local/bin/openclaw gateway`
    # matches the command `openclaw`.
    return {word.rsplit("/", 1)[-1] for word in cmdline.split()}


def harness_reader_for(profiles: Iterable[dict[str, Any]], agent: Agent) -> dict[str, Any] | None:
    """The first profile whose markers match the agent, or None (then the
    generic reader runs, task 6; until it lands the harness fields are BLIND
    with UNKNOWN_HARNESS)."""
    words = _command_words(agent.cmdline)
    for profile in profiles:
        markers = profile.get("markers", {})
        if words & set(markers.get("commands", [])) or set(agent.env) & set(markers.get("env", [])):
            return profile
    return None


# --- reading ---------------------------------------------------------------

def _depth_exceeds(value: Any, limit: int) -> bool:
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        if isinstance(item, (dict, list)):
            if depth > limit:
                return True
            pending.extend((child, depth + 1) for child in (item.values() if isinstance(item, dict) else item))
    return False


def loads_json(text: str) -> Any:
    """json.loads, with documents nested deeper than MAX_JSON_DEPTH refused
    as a ValueError like any other parse failure."""
    try:
        value = json.loads(text)
    except RecursionError:
        raise ValueError("nested too deeply") from None
    if _depth_exceeds(value, MAX_JSON_DEPTH):
        raise ValueError(f"nested deeper than {MAX_JSON_DEPTH} levels")
    return value


_MISSING = object()


def get_path(document: Any, path: str) -> Any:
    """The value at a dotted key path; `*` takes every value of an object or
    item of a list (a list of matches, or _MISSING when nothing matches)."""
    current: list[Any] = [document]
    wild = False
    for part in path.split(".") if path else []:
        following: list[Any] = []
        for item in current:
            if part == "*":
                wild = True
                if isinstance(item, dict):
                    following.extend(item.values())
                elif isinstance(item, list):
                    following.extend(item)
            elif isinstance(item, dict) and part in item:
                following.append(item[part])
            elif isinstance(item, list) and part.isdigit() and int(part) < len(item):
                following.append(item[int(part)])
        current = following
        if not current:
            return _MISSING
    return current if wild else current[0]


REDACTED = "[redacted]"  # the scanner's marker
# Secrets inside a string, found by scanning it once, word by word (never a
# regex that can backtrack: a string is the agent's to write, so its length
# and shape are the agent's to choose): a URL's credentials, query and
# fragment, whatever scheme; the value after a credential name and `=` or
# `:` (TOKEN=x, password: x, x-api-key: x) or after a credential flag
# (--api-key x); the word after Bearer or Basic; well-known token shapes;
# and PEM private-key blocks.
_SECRET_WORDS = ("key", "token", "secret", "passw", "pwd", "auth", "credential", "cookie", "session")
_AUTH_SCHEMES = frozenset({"bearer", "basic"})
_TOKEN_PREFIXES = ("sk-", "sk_live_", "sk_test_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
                   "xoxa-", "xoxb-", "xoxp-", "xoxo-", "xoxs-", "xoxr-", "AKIA", "AIza", "glpat-")
_TOKEN_BODY = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_EDGE = "\"'`()[]{}<>,;"
_PEM_BEGIN, _PEM_END = "-----BEGIN ", "-----END "


def _names_secret(name: str) -> bool:
    folded = "".join(c for c in name.lower() if c.isalnum())
    return any(word in folded for word in _SECRET_WORDS)


def _is_token_shape(word: str) -> bool:
    # A known prefix and at least 8 token characters, or a JWT (three
    # dot-separated base64url parts, the first starting eyJ).
    for prefix in _TOKEN_PREFIXES:
        if word.startswith(prefix):
            body = word[len(prefix):]
            return len(body) >= 8 and all(c in _TOKEN_BODY for c in body)
    if word.startswith("eyJ"):
        parts = word.split(".")
        return len(parts) == 3 and all(len(p) >= 8 and all(c in _TOKEN_BODY for c in p) for p in parts)
    return False


def _clean_url(word: str) -> str:
    """A word holding a URL, without the URL's userinfo, query or fragment."""
    at = word.find("://")
    start = at
    while start > 0 and (word[start - 1].isalnum() or word[start - 1] in "+.-"):
        start -= 1
    if start == at:
        return word
    rest = word[at + 3:]
    for mark in ("?", "#"):
        cut = rest.find(mark)
        if cut != -1:
            rest = rest[:cut]
    slash = rest.find("/")
    authority, path = (rest, "") if slash == -1 else (rest[:slash], rest[slash:])
    authority = authority.rpartition("@")[2]
    return word[:at + 3] + authority + path


def _scrub_pem(text: str) -> str:
    out, i = [], 0
    while True:
        begin = text.find(_PEM_BEGIN, i)
        if begin == -1:
            break
        header_end = text.find("-----", begin + len(_PEM_BEGIN))
        if header_end == -1 or "PRIVATE KEY" not in text[begin:header_end]:
            out.append(text[i:begin + 1])
            i = begin + 1
            continue
        end = text.find(_PEM_END, header_end + 5)
        close = text.find("-----", end + len(_PEM_END)) if end != -1 else -1
        out.append(text[i:begin] + REDACTED)
        i = close + 5 if close != -1 else len(text)
    out.append(text[i:])
    return "".join(out)


def scrub_text(text: str, assignments: bool = True) -> str:
    """`text` with the secrets it may carry replaced (see above), in one pass.
    With `assignments` off (for a key, which is a name), only URLs, token
    shapes and private keys are scrubbed."""
    if not text:
        return text
    if _PEM_BEGIN in text:
        text = _scrub_pem(text)
    words = re.split(r"(\s+)", text)
    hide_next = False
    for index, word in enumerate(words):
        if not word or word.isspace():
            continue
        if hide_next:
            if word.strip(_EDGE).lower() in _AUTH_SCHEMES:
                continue  # Authorization: Bearer <token>: the scheme stays, the token after it goes
            words[index] = REDACTED
            hide_next = False
            continue
        core = word.strip(_EDGE)
        if "://" in word:
            words[index] = word = _clean_url(word)
            core = word.strip(_EDGE)
        if _is_token_shape(core):
            words[index] = word.replace(core, REDACTED)
            continue
        if not assignments:
            continue
        if core.lower() in _AUTH_SCHEMES:
            hide_next = True
            continue
        name, sep, value = "", "", ""
        for mark in ("=", ":"):
            cut = core.find(mark)
            if cut > 0 and (not sep or cut < len(name)):
                name, sep, value = core[:cut], mark, core[cut + 1:]
        if sep and "://" not in core[:len(name) + 3] and _names_secret(name):
            if value.lower() in _AUTH_SCHEMES:
                hide_next = True  # Authorization:Bearer <token>
            elif value:
                words[index] = word.replace(core, name + sep + REDACTED)
            else:
                hide_next = True  # password: x, TOKEN= x
        elif core.startswith("-") and _names_secret(core.lstrip("-")):
            hide_next = True  # --api-key x
    return "".join(words)


def credential_path(path: str) -> bool:
    """Whether a key path ends at, or reaches only through wildcards under, a
    credential key: `mcpServers.*.env`, `env.*`, `providers.x.apiKey`. Its
    value is then a credential however it is shaped, and is replaced whole.
    A path that names one entry under such a key (`env.ANTHROPIC_BASE_URL`)
    asks for that entry, which is not itself a credential, so it is read and
    scrubbed like any other value."""
    parts = [p for p in path.split(".") if p]
    for i, part in enumerate(parts):
        if part != "*" and not part.isdigit() and is_credential_key(part):
            if not any(p != "*" and not p.isdigit() for p in parts[i + 1:]):
                return True
    return False


def extract(document: Any, path: str) -> Any:
    """get_path, with a credential path's value replaced (credential_path)."""
    value = get_path(document, path)
    return REDACTED if value is not _MISSING and credential_path(path) else value


def redact(value: Any, redact_url: Callable[[str], str] | None = None) -> Any:
    """`value` with credentials removed at any depth (iteratively;
    documents are already depth-capped): a credential key's value replaced
    (the key itself kept), the item after a credential flag in a list
    (["--api-key", "sk-..."]) replaced,
    and every string scrubbed (scrub_text). `redact_url`, when given, is
    applied first to a string that is a whole URL."""
    def clean_string(text: str) -> str:
        if redact_url and "://" in text and not any(c.isspace() for c in text):
            try:
                text = redact_url(text)
            except ValueError:
                pass
        return scrub_text(text)

    def hide(item: Any) -> Any:
        # The shape kept, every plain value gone (None and booleans say nothing).
        if isinstance(item, dict):
            return {(scrub_text(k, assignments=False) if isinstance(k, str) else k):
                    (REDACTED if is_credential_container(k) else hide(v)) for k, v in item.items()}
        if isinstance(item, list):
            return [hide(v) for v in item]
        return item if item is None or isinstance(item, bool) else REDACTED

    def walk(item: Any) -> Any:
        if isinstance(item, dict):
            # Every key is kept (a key is a name: an MCP server's, a file's), and
            # only a secret written inside one is scrubbed. A credential
            # container (env, headers, secrets) loses its whole value. Under a key
            # that only names a credential, the value is redacted but its shape
            # kept: a plain value goes, and an object keeps its keys with every
            # plain value in it redacted. So {"clientSecret": {"value": x}} never
            # shows x, and an MCP server called 1password or secrets-manager is
            # still reported, its config hidden.
            out = {}
            for k, v in item.items():
                name = scrub_text(k, assignments=False) if isinstance(k, str) else k
                if is_credential_container(k) or (is_credential_key(k) and not isinstance(v, dict)):
                    out[name] = REDACTED
                elif is_credential_key(k):
                    out[name] = hide(v)
                else:
                    out[name] = walk(v)
            return out
        if isinstance(item, list):
            out, hide_next = [], False
            for child in item:
                if hide_next and isinstance(child, str):
                    out.append(REDACTED)
                else:
                    out.append(walk(child))
                hide_next = isinstance(child, str) and child.startswith("-") and _names_secret(child.lstrip("-"))
            return out
        if isinstance(item, str):
            return clean_string(item)
        return item

    return walk(value)


def _result(status: str, field: str, **extra: Any) -> dict[str, Any]:
    return {"status": status, "tier": HARNESS_FIELDS[field], **extra}


def unknown_harness_fields(note: str = "no harness profile matched the agent") -> dict[str, dict[str, Any]]:
    """Every harness field BLIND with UNKNOWN_HARNESS."""
    return {field: _result("BLIND", field, reason="UNKNOWN_HARNESS", note=note) for field in HARNESS_FIELDS}


class Context:
    """What a hook gets: the profile, the agent, its files, and the parser."""

    def __init__(self, profile: dict[str, Any], agent: Agent, sources: Sources,
                 loads: Callable[[str], Any], collect_prompt: bool):
        self.profile, self.agent, self.sources = profile, agent, sources
        self.loads, self.collect_prompt = loads, collect_prompt
        self.harness = profile["harness"]

    def result(self, status: str, field: str, **extra: Any) -> dict[str, Any]:
        return _result(status, field, **extra)


Hook = Callable[[Context, str, dict[str, Any]], dict[str, Any]]
HOOKS: dict[str, Hook] = {}


def hook(name: str) -> Callable[[Hook], Hook]:
    """Register a hook a profile names for a field whose format a key path
    can't reach (such as OpenClaw's SQLite, task 4)."""
    def register(function: Hook) -> Hook:
        HOOKS[name] = function
        return function
    return register


def _read_capped(ctx: Context, path: str, cap: int) -> tuple[str | None, bool]:
    """A file's text, at most `cap` bytes, and whether it was longer (one
    byte more is asked for, so a file cut at the cap is never mistaken for a
    whole one)."""
    text = ctx.sources.read_text(path, cap + 1)
    if text is None:
        return None, False
    if len(text.encode("utf-8", errors="replace")) > cap:
        return text.encode("utf-8", errors="replace")[:cap].decode("utf-8", errors="ignore"), True
    return text, False


def _read_sources(ctx: Context) -> list[dict[str, Any]]:
    """Each source in profile order: the path it is read at (expanded with the
    agent's environment, to find it) and the path it is reported as (as the
    profile writes it, so no environment value reaches the bundle), and its
    document, parse error, or nothing (missing or unreadable)."""
    read = []
    for spec in ctx.profile.get("sources", []):
        path = ctx.agent.expand(spec["path"])
        entry: dict[str, Any] = {"spec": spec["path"], "path": spec["path"], "read_at": path,
                                 "doc": _MISSING, "error": None, "reason": None}
        if path is not None:
            text, cut = _read_capped(ctx, path, SOURCE_MAX_BYTES)
            if text is not None and cut:
                entry["error"] = f"{spec['path']}: larger than {SOURCE_MAX_BYTES} bytes, so not read"
                entry["reason"] = "SIZE_CAP_EXCEEDED"
            elif text is not None:
                try:
                    entry["doc"] = ctx.loads(text)
                except ValueError as exc:
                    entry["error"] = f"{spec['path']}: {exc}"
                    entry["reason"] = "PARSE_FAILED"
        read.append(entry)
    return read


def _config_field(ctx: Context, field: str, spec: Any, sources: list[dict[str, Any]]) -> dict[str, Any]:
    if isinstance(spec, dict) and "hook" in spec:
        function = HOOKS.get(spec["hook"])
        if function is None:
            return _result("FAILED", field, reason="NOT_COLLECTED_BY_PACK", note=f"no hook named {spec['hook']}")
        return function(ctx, field, spec)
    merge = spec.get("merge", "first") if isinstance(spec, dict) else "first"
    if isinstance(spec, dict) and "paths" in spec:
        paths = spec["paths"]
    elif isinstance(spec, dict) and "keys" in spec:
        paths = None  # an object built from named key paths, e.g. {allow, deny}
    else:
        paths = [spec] if isinstance(spec, str) else list(spec)
    parsed = [s for s in sources if s["doc"] is not _MISSING]
    failed = [s for s in sources if s["error"]]
    if not parsed:
        if failed:
            return _result("FAILED", field, reason=failed[0]["reason"], note="; ".join(s["error"] for s in failed))
        tried = ", ".join(s["path"] for s in sources) or "no sources"
        return _result("BLIND", field, reason="NO_SOURCE_ACCESS", note=f"{ctx.harness}: none of {tried} could be read")
    found: list[tuple[Any, str]] = []
    for source in parsed:
        if paths is None:
            value = {name: extract(source["doc"], path) for name, path in spec["keys"].items()}
            value = {k: v for k, v in value.items() if v is not _MISSING}
            value = value or _MISSING
        else:
            value = next((v for v in (extract(source["doc"], p) for p in paths) if v is not _MISSING), _MISSING)
        if value is not _MISSING:
            found.append((value, source["path"]))
            if merge == "first":
                break
    if not found:
        where = ", ".join(s["path"] for s in parsed)
        if failed:
            return _result("FAILED", field, reason=failed[0]["reason"],
                           note=f"not in {where}; " + "; ".join(s["error"] for s in failed))
        if field in POLICY_FIELDS:
            return _result("BLIND", field, reason="GATEWAY_MANAGED",
                           note=f"{ctx.harness}: not set in {where}; absence is NOT evidence of restriction")
        return _result("ABSENT", field, method=f"{ctx.harness}: not set in {where}")
    if merge == "union" and len(found) > 1:
        # Earlier (higher-precedence) sources win on the same key.
        value: Any = {} if all(isinstance(v, dict) for v, _ in found) else []
        for item, _ in reversed(found):
            if isinstance(value, dict) and isinstance(item, dict):
                value.update(item)
            elif isinstance(value, list):
                value.extend(i for i in (item if isinstance(item, list) else [item]) if i not in value)
        source_names = [s for _, s in found]
    else:
        value, source_names = found[0][0], [found[0][1]]
    extra: dict[str, Any] = {"source": source_names[0] if len(source_names) == 1 else source_names}
    higher_failed = [s for s in failed if sources.index(s) < sources.index(next(x for x in sources if x["path"] == source_names[0]))]
    if higher_failed:
        extra["note"] = "a higher-precedence source could not be parsed: " + "; ".join(s["error"] for s in higher_failed)
    return _result("ANSWERED", field, value=value, **extra)


def _prompt_fields(ctx: Context, spec: list[str]) -> dict[str, dict[str, Any]]:
    present, texts, tried = [], {}, []
    for raw in spec:
        path = ctx.agent.expand(raw)
        if path is None:
            continue
        tried.append(raw)
        text = ctx.sources.read_text(path, PROMPT_TEXT_MAX_CHARS * 4)
        if text is not None:
            present.append(raw)
            texts[raw] = text[:PROMPT_TEXT_MAX_CHARS]
    where = ", ".join(tried) or "no prompt files"
    if present:
        out = {"system_prompt_present": _result("ANSWERED", "system_prompt_present",
                                                 value={"present": True, "files": present}, source=present)}
    else:
        out = {"system_prompt_present": _result("ABSENT", "system_prompt_present", method=f"{ctx.harness}: none of {where}")}
    if not ctx.collect_prompt:
        out["system_prompt_text"] = _result("BLIND", "system_prompt_text", reason="NOT_COLLECTED_BY_PACK",
                                            note="prompt text is read only with --collect-system-prompt")
    elif present:
        out["system_prompt_text"] = _result("ANSWERED", "system_prompt_text", value=texts, source=present)
    else:
        out["system_prompt_text"] = _result("ABSENT", "system_prompt_text", method=f"{ctx.harness}: none of {where}")
    return out


def skill_frontmatter(text: str) -> dict[str, str]:
    """`name` and `description` from a SKILL.md's frontmatter (the lines
    between its opening and closing ---), read as plain `key: value` lines."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    found: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        key, sep, value = line.partition(":")
        if sep and key.strip() in ("name", "description") and value.strip():
            found[key.strip()] = value.strip().strip("'\"")
    return found


def _skills_field(ctx: Context, spec: list[str]) -> dict[str, Any]:
    skills, read = [], []
    for raw in spec:
        folder = ctx.agent.expand(raw)
        names = ctx.sources.list_dir(folder) if folder else None
        if names is None:
            continue
        read.append(raw)
        for name in names:
            text = ctx.sources.read_text(f"{folder.rstrip('/')}/{name}/SKILL.md", SOURCE_MAX_BYTES)
            if text is not None:
                front = skill_frontmatter(text)
                skills.append({"name": front.get("name") or name, "description": front.get("description"),
                               "path": f"{raw.rstrip('/')}/{name}"})
    if skills:
        return _result("ANSWERED", "skills_inventory", value=skills, source=read)
    if read:
        return _result("ABSENT", "skills_inventory", method=f"{ctx.harness}: no SKILL.md under {', '.join(read)}")
    return _result("BLIND", "skills_inventory", reason="NO_SOURCE_ACCESS", note=f"{ctx.harness}: no skills folder could be read")


def _transcript_field(ctx: Context, spec: dict[str, Any]) -> dict[str, Any]:
    if "hook" in spec:
        function = HOOKS.get(spec["hook"])
        if function is None:
            return _result("FAILED", "tool_names", reason="NOT_COLLECTED_BY_PACK", note=f"no hook named {spec['hook']}")
        return function(ctx, "tool_names", spec)
    if spec.get("format", "jsonl") != "jsonl" or not isinstance(spec.get("tool_name"), str):
        return _result("FAILED", "tool_names", reason="NOT_COLLECTED_BY_PACK", note="transcripts need format jsonl and tool_name, or a hook")
    counts: dict[str, int] = {}
    files: list[str] = []
    capped: list[str] = []
    bad_lines = 0
    for raw in spec.get("folders", []):
        folder = ctx.agent.expand(raw)
        names = ctx.sources.list_dir(folder) if folder else None
        for name in names or []:
            if len(files) >= TRANSCRIPT_MAX_FILES or not fnmatch.fnmatch(name, spec.get("files", "*.jsonl")):
                continue
            path = f"{folder.rstrip('/')}/{name}"
            text, cut = _read_capped(ctx, path, TRANSCRIPT_MAX_BYTES)
            if text is None:
                continue
            if cut:
                # Count the whole lines read; the one the cap cut is not a bad line.
                text = text.rpartition("\n")[0]
                capped.append(f"{raw.rstrip('/')}/{name}")
            files.append(f"{raw.rstrip('/')}/{name}")
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    event = ctx.loads(line)
                except ValueError:
                    bad_lines += 1
                    continue
                names_found = get_path(event, spec["tool_name"])
                for tool in names_found if isinstance(names_found, list) else [names_found]:
                    if isinstance(tool, str) and tool:
                        counts[tool] = counts.get(tool, 0) + 1
    if not files:
        return _result("BLIND", "tool_names", reason="NO_SOURCE_ACCESS", note=f"{ctx.harness}: no transcript could be read")
    if not counts:
        return _result("ABSENT", "tool_names", method=f"{ctx.harness}: no tool calls in {len(files)} transcript(s)")
    # The bundle's shape (evidence_bundle.py, compose_evidence_bundle_v2.py):
    # the names, sorted; a floor, not a count.
    value = sorted(counts)
    floor = "floor, not a count: tools not called in the transcripts read are absent here"
    if capped:
        return _result("PARTIAL", "tool_names", value=value, reason="SIZE_CAP_EXCEEDED", source=files,
                       note=f"{floor}; read up to {TRANSCRIPT_MAX_BYTES} bytes of {', '.join(capped)}")
    if bad_lines:
        return _result("PARTIAL", "tool_names", value=value, reason="PARSE_FAILED", source=files,
                       note=f"{floor}; {bad_lines} transcript line(s) could not be parsed")
    return _result("ANSWERED", "tool_names", value=value, source=files, note=floor)


def read_harness_fields(profile: dict[str, Any] | None, agent: Agent, sources: Sources, *,
                        collect_prompt: bool = False, loads: Callable[[str], Any] = loads_json,
                        redact_url: Callable[[str], str] | None = None) -> dict[str, dict[str, Any]]:
    """Every harness field for `agent`, read with `profile` (None: no profile
    matched, so every field is BLIND with UNKNOWN_HARNESS). A field the
    profile doesn't name is BLIND with NOT_COLLECTED_BY_PACK."""
    if profile is None:
        return unknown_harness_fields()
    ctx = Context(profile, agent, sources, loads, collect_prompt)
    results: dict[str, dict[str, Any]] = {}
    config_sources = _read_sources(ctx)
    for field, spec in profile.get("fields", {}).items():
        if field in CONFIG_FIELDS:
            results[field] = _config_field(ctx, field, spec, config_sources)
    workspace = profile.get("workspace", {})
    if workspace.get("prompt_files"):
        results.update(_prompt_fields(ctx, workspace["prompt_files"]))
    if workspace.get("skills"):
        results["skills_inventory"] = _skills_field(ctx, workspace["skills"])
    if workspace.get("transcripts"):
        results["tool_names"] = _transcript_field(ctx, workspace["transcripts"])
    for field in HARNESS_FIELDS:
        results.setdefault(field, _result("BLIND", field, reason="NOT_COLLECTED_BY_PACK",
                                          note=f"the {profile['harness']} profile doesn't name this field"))
        if "value" in results[field]:
            results[field]["value"] = redact(results[field]["value"], redact_url)
        # Every string reported beside the value too: file names are the
        # agent's to choose.
        for key in ("source", "method", "note"):
            if key in results[field]:
                results[field][key] = redact(results[field][key])
        results[field]["harness"] = profile["harness"]
    return results


def to_attributes(results: dict[str, dict[str, Any]], builders: dict[str, Callable[..., dict[str, Any]]],
                  values_only: bool = False) -> dict[str, dict[str, Any]]:
    """The results as bundle attributes, built with the bundle's own builders
    (answered, absent, blind, failed, partial). With `values_only`, only
    fields the profile found a value for (ANSWERED, PARTIAL) are returned, so
    the caller's own attribute stands for every other field, with its own
    account of why there is no value."""
    attributes = {}
    for field, result in results.items():
        status, tier = result["status"], result["tier"]
        if values_only and status not in ("ANSWERED", "PARTIAL"):
            continue
        authored_by = FIELD_AUTHORED_BY.get(field, "subject")
        harness = result.get("harness")
        source = result.get("source")
        method = f"{harness} profile: {source if isinstance(source, str) else ', '.join(source or [])}" if harness else None
        note = result.get("note")
        if status == "ANSWERED":
            attributes[field] = builders["answered"](result["value"], tier, authored_by=authored_by, method=method,
                                                     **({"note": note} if note else {}))
        elif status == "PARTIAL":
            attributes[field] = builders["partial"](result["value"], tier, result["reason"], authored_by=authored_by,
                                                    method=method, **({"note": note} if note else {}))
        elif status == "ABSENT":
            attributes[field] = builders["absent"](result["method"], tier)
        elif status == "FAILED":
            attributes[field] = builders["failed"](result["reason"], tier, **({"note": note} if note else {}))
        else:
            attributes[field] = builders["blind"](result["reason"], tier, **({"note": note} if note else {}))
    return attributes

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
* BLIND (UNKNOWN_HARNESS): no profile matched the agent, and the generic
  reader (generic.py, RC-520) couldn't fill the field from what any harness
  may use.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
import sys
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
    "mcp_servers_observed": "observed",
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
# A source may raise its own cap (`max_bytes`) up to this, for a harness file
# that also holds caches (Claude Code's ~/.claude.json).
SOURCE_MAX_BYTES_LIMIT = 1_000_000
# A source whose last part is a pattern (drop-in files) reads at most this
# many files.
SOURCE_GLOB_MAX_FILES = 50
# The agent's working directory, as a derived name a profile's paths can use
# ($AGENT_CWD). Like every derived name, the agent's environment never sets it.
CWD_NAME = "AGENT_CWD"
PROMPT_TEXT_MAX_CHARS = 16_000
TRANSCRIPT_MAX_BYTES = 1_000_000
TRANSCRIPT_MAX_FILES = 50
# Transcripts listed when choosing which TRANSCRIPT_MAX_FILES to read: each
# past the file cap costs a stat, for its modification time (RC-530).
TRANSCRIPT_MAX_CANDIDATES = 5000
MAX_JSON_DEPTH = 100
PROFILES_DIR = Path(__file__).resolve().with_name("profiles")
GENERIC_READER = Path(__file__).resolve().with_name("generic.py")
# The name a result of the generic reader carries in place of a profile's.
GENERIC_HARNESS = "generic"

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

    def read_bytes(self, path: str, max_bytes: int) -> bytes | None: ...

    def list_dir(self, path: str) -> list[str] | None: ...

    # Optional: a regular file's modification time, or None. A Sources
    # without it gets transcripts read in name order (newest_first).
    # def mtime(self, path: str) -> float | None: ...


class LocalSources:
    """This machine's files, optionally under `root`: regular files only,
    opened without blocking, capped."""

    def __init__(self, root: Path | None = None):
        self.root = root

    def _path(self, path: str) -> Path:
        return self.root / path.lstrip("/") if self.root else Path(path)

    def read_bytes(self, path: str, max_bytes: int) -> bytes | None:
        try:
            fd = os.open(self._path(path), os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            chunks, size = [], 0
            while size < max_bytes:
                chunk = os.read(fd, max_bytes - size)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            return b"".join(chunks)
        except OSError:
            return None
        finally:
            os.close(fd)

    def read_text(self, path: str, max_bytes: int) -> str | None:
        data = self.read_bytes(path, max_bytes)
        return None if data is None else data.decode("utf-8", errors="replace")

    def list_dir(self, path: str) -> list[str] | None:
        try:
            return sorted(os.listdir(self._path(path)))
        except OSError:
            return None

    def mtime(self, path: str) -> float | None:
        try:
            fd = os.open(self._path(path), os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            return None
        try:
            info = os.fstat(fd)
            return info.st_mtime if stat.S_ISREG(info.st_mode) else None
        except OSError:
            return None
        finally:
            os.close(fd)


class Agent:
    """What the reader knows about the agent: its command line, environment
    and working directory (from its process), for markers and path
    expansion."""

    def __init__(self, cmdline: str = "", env: dict[str, str] | None = None, cwd: str | None = None):
        self.cmdline = cmdline or ""
        self.env = dict(env or {})
        # Only an absolute path is a working directory; anything else (a
        # deleted folder's "(deleted)", nothing at all) is none.
        self.cwd = cwd if isinstance(cwd, str) and cwd.startswith("/") and " (deleted)" not in cwd else None

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
    if not isinstance(markers, dict) or not any(markers.get(k) for k in ("commands", "packages", "env")):
        raise ProfileError(f"{name}: markers needs commands, packages or env")
    if not all(isinstance(package, str) and re.fullmatch(r"(@[\w.-]+/)?[\w.-]+", package)
               for package in markers.get("packages", [])):
        raise ProfileError(f"{name}: markers.packages are npm package names")
    sources = profile.get("sources", [])
    if not isinstance(sources, list) or not all(isinstance(s, dict) and isinstance(s.get("path"), str) for s in sources):
        raise ProfileError(f"{name}: sources is a list of {{\"path\": ...}}")
    for source in sources:
        if source.get("format", "json") != "json":
            raise ProfileError(f"{name}: {source['path']}: only json sources are read; use a hook for others")
        cap = source.get("max_bytes", SOURCE_MAX_BYTES)
        if isinstance(cap, bool) or not isinstance(cap, int) or not 0 < cap <= SOURCE_MAX_BYTES_LIMIT:
            raise ProfileError(f"{name}: {source['path']}: max_bytes is a number of bytes up to {SOURCE_MAX_BYTES_LIMIT}")
        folder, _, last = source["path"].rpartition("/")
        if any(c in folder for c in "*?[") or (any(c in last for c in "*?[") and not folder):
            raise ProfileError(f"{name}: {source['path']}: only a source's last part can be a pattern")
    flags = profile.get("flags", {})
    if not isinstance(flags, dict) or not all(
            isinstance(specs, list) and all(isinstance(f, dict) and isinstance(f.get("flag"), str)
                                            and f["flag"].startswith("-") for f in specs)
            for specs in flags.values()):
        raise ProfileError(f"{name}: flags maps a name to a list of {{\"flag\": \"--x\"[, \"value\": ...]}}")
    variables = profile.get("variables", {})
    if not isinstance(variables, dict) or not all(
            isinstance(templates, list) and all(isinstance(t, str) for t in templates) for templates in variables.values()):
        raise ProfileError(f"{name}: variables maps a name to a list of path templates")
    fields = profile.get("fields", {})
    if not isinstance(fields, dict):
        raise ProfileError(f"{name}: fields is an object")
    transcripts = (profile.get("workspace") or {}).get("transcripts") or {}
    if "mcp_tools" in transcripts:
        try:
            mcp_tool_pattern(transcripts["mcp_tools"])
        except ValueError as exc:
            raise ProfileError(f"{name}: workspace.transcripts.mcp_tools: {exc}") from None
    for field, spec in fields.items():
        if field not in HARNESS_FIELDS:
            raise ProfileError(f"{name}: {field} is not a harness field")
        if not isinstance(spec, (str, list, dict)):
            raise ProfileError(f"{name}: {field}: a key path, a list of them, or an object")
    return profile


def load_profiles(folder: Path = PROFILES_DIR) -> list[dict[str, Any]]:
    """The profiles shipped in `folder` (one *.json each), validated. A
    profile's hooks ship beside it as <harness>.py, whose register(reader)
    registers them; it is loaded with the profile."""
    import importlib.util
    import sys

    profiles = []
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            profile = validate_profile(json.loads(path.read_text(encoding="utf-8")))
        except (ValueError, OSError) as exc:
            raise ProfileError(f"{path.name}: {exc}") from exc
        hooks = path.with_suffix(".py")
        if hooks.is_file():
            name = f"harness_profile_{profile['harness'].replace('-', '_').replace('.', '_')}"
            module = sys.modules.get(name)
            if module is None:
                spec = importlib.util.spec_from_file_location(name, hooks)
                if spec is None or spec.loader is None:
                    raise ProfileError(f"{hooks.name}: cannot be loaded")
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
            module.register(sys.modules[__name__])
        profiles.append(profile)
    return profiles


PACKAGE_EVIDENCE, COMMAND_EVIDENCE = 0, 1  # lower is stronger


def _command_line_evidence(cmdline: str, markers: dict[str, Any]) -> tuple[int, int] | None:
    """The strongest sign on the command line that it runs this harness, as
    (strength, word position), or None. A word inside one of its packages
    (`node /usr/lib/node_modules/openclaw/openclaw.mjs`) is the strongest:
    that is where the code being run lives. Otherwise a word that is one of
    its commands, by basename (`/usr/local/bin/openclaw`, `openclaw`), the
    earliest one: a program comes before its arguments. Every word is looked
    at, since the program can come after any wrapper (`npm run`, `uv run`,
    `sh -c cd /app && ...`, an entrypoint script, a launcher's flags and
    their values), and /proc gives the command line with its quoting lost."""
    packages, commands = markers.get("packages", []), set(markers.get("commands", []))
    best: tuple[int, int] | None = None
    for position, word in enumerate(cmdline.split()):
        if any(f"/node_modules/{package}/" in word for package in packages):
            found = (PACKAGE_EVIDENCE, position)
        elif word.rsplit("/", 1)[-1] in commands:
            found = (COMMAND_EVIDENCE, position)
        else:
            continue
        if best is None or found < best:
            best = found
    return best


def _flag_value(words: list[str], spec: dict[str, Any]) -> str | None:
    """A command-line flag's value: `--flag value` or `--flag=value`, or for a
    flag that takes none, the spec's fixed `value` when the flag is there."""
    flag = spec["flag"]
    for index, word in enumerate(words):
        if "value" in spec:
            if word == flag:
                return str(spec["value"])
        elif word == flag and index + 1 < len(words) and not words[index + 1].startswith("-"):
            return words[index + 1]
        elif word.startswith(flag + "="):
            return word[len(flag) + 1:] or None
    return None


def with_derived(profile: dict[str, Any], agent: Agent) -> Agent:
    """The agent with the names a profile derives, for finding its files only
    (never reported, like the environment): each `flags` name from the
    agent's command line, then each `variables` name as the first of its
    templates whose names are all known, in order, so a later variable can
    use an earlier one. A harness that picks one folder by a rule (OpenClaw:
    $OPENCLAW_STATE_DIR, else ~/.openclaw-<profile>, else ~/.openclaw) says it
    once here and uses the name everywhere. The agent's own environment never
    sets a derived name. $AGENT_CWD, the agent's working directory, is
    derived for every profile."""
    derived_names = [CWD_NAME, *profile.get("flags", {}), *profile.get("variables", {})]
    env = {key: value for key, value in agent.env.items() if key not in derived_names}
    if agent.cwd:
        env[CWD_NAME] = agent.cwd
    words = agent.cmdline.split()
    for name, specs in profile.get("flags", {}).items():
        for spec in specs:
            value = _flag_value(words, spec)
            if value and "/" not in value and value not in (".", ".."):  # a name, never a path
                env[name] = value
                break
    derived = Agent(agent.cmdline, env, agent.cwd)
    for name, templates in profile.get("variables", {}).items():
        for template in templates:
            value = derived.expand(template)
            if value:
                env[name] = value
                derived = Agent(agent.cmdline, env, agent.cwd)
                break
    return derived


def harness_reader_for(profiles: Iterable[dict[str, Any]], agent: Agent) -> dict[str, Any] | None:
    """The profile whose markers match the agent, or None (then
    read_harness_fields runs the generic reader, generic.py). The command line decides first: of the profiles it
    shows any sign of, the one with the strongest (_command_line_evidence),
    so an OpenClaw agent whose prompt or note says "claude" stays OpenClaw
    and a Claude Code agent asked about OpenClaw stays Claude Code; on a tie,
    the first in order. An environment marker counts only when the command
    line shows no harness, since an agent's environment can carry another
    harness's variables (an OpenClaw agent with CLAUDE_CONFIG_DIR set)."""
    profiles = list(profiles)
    ranked = [(evidence, order, profile) for order, profile in enumerate(profiles)
              if (evidence := _command_line_evidence(agent.cmdline, profile.get("markers", {}))) is not None]
    if ranked:
        return min(ranked, key=lambda item: item[:2])[2]
    for profile in profiles:
        if set(agent.env) & set(profile.get("markers", {}).get("env", [])):
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
        self.config_sources: list[dict[str, Any]] = []

    def parsed_sources(self) -> list[tuple[str, Any]]:
        """The profile's config sources that parsed, as (path, document),
        highest precedence first: for a hook whose field depends on another
        (a model's provider, that provider's endpoint)."""
        return [(s["path"], s["doc"]) for s in self.config_sources if s["doc"] is not _MISSING]

    def config_value(self, path: str) -> tuple[Any, str | None]:
        """The value at a key path in the highest source that has it, and
        that source; (None, None) when none does."""
        for source, doc in self.parsed_sources():
            value = extract(doc, path)  # a credential path's value is replaced (credential_path)
            if value is not _MISSING:
                return value, source
        return None, None

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


def _source_paths(ctx: Context, spec: dict[str, Any]) -> list[tuple[str, str | None]]:
    """(the path reported, the path read) for a source. A source whose last
    part is a pattern (`/etc/x/managed-settings.d/*.json`) is the matching
    files in its folder, as drop-in files are read: in name order, a later
    one overriding an earlier one, so the last is listed first (highest
    precedence first, like the sources themselves). It is reported by the
    folder as the profile writes it and each file's own name."""
    folder, _, pattern = spec["path"].rpartition("/")
    if not any(c in pattern for c in "*?["):
        return [(spec["path"], ctx.agent.expand(spec["path"]))]
    expanded = ctx.agent.expand(folder)
    names = ctx.sources.list_dir(expanded) if expanded else None
    matching = sorted(n for n in names or [] if fnmatch.fnmatchcase(n, pattern) and n not in (".", ".."))
    return [(f"{folder}/{n}", f"{expanded.rstrip('/')}/{n}") for n in reversed(matching[-SOURCE_GLOB_MAX_FILES:])]


def _read_sources(ctx: Context) -> list[dict[str, Any]]:
    """Each source in profile order: the path it is read at (expanded with the
    agent's environment, to find it) and the path it is reported as (as the
    profile writes it, so no environment value reaches the bundle), and its
    document, parse error, or nothing (missing or unreadable)."""
    read = []
    for spec in ctx.profile.get("sources", []):
        cap = spec.get("max_bytes", SOURCE_MAX_BYTES)
        for shown, path in _source_paths(ctx, spec):
            entry: dict[str, Any] = {"spec": spec["path"], "path": shown, "read_at": path,
                                     "doc": _MISSING, "error": None, "reason": None}
            if path is not None:
                text, cut = _read_capped(ctx, path, cap)
                if text is not None and cut:
                    entry["error"] = f"{shown}: larger than {cap} bytes, so not read"
                    entry["reason"] = "SIZE_CAP_EXCEEDED"
                elif text is not None:
                    try:
                        entry["doc"] = ctx.loads(text)
                    except ValueError as exc:
                        entry["error"] = f"{shown}: {exc}"
                        entry["reason"] = "PARSE_FAILED"
            read.append(entry)
    return read


def _run_hook(ctx: Context, field: str, spec: dict[str, Any]) -> dict[str, Any]:
    """A hook's result, or FAILED for that one field when it raises: a hook
    reads files the agent writes, and one bad file or a full /tmp must never
    stop the scan. As the scanner records a collector that raised, the reason
    is PARSE_FAILED; the note names the exception's type only, since its
    message can hold a path the agent's environment expanded."""
    function = HOOKS.get(spec["hook"])
    if function is None:
        return _result("FAILED", field, reason="NOT_COLLECTED_BY_PACK", note=f"no hook named {spec['hook']}")
    try:
        return function(ctx, field, spec)
    except Exception as error:  # noqa: BLE001 - any failure is this field's, never the scan's
        return _result("FAILED", field, reason="PARSE_FAILED",
                       note=f"{ctx.harness}: hook {spec['hook']} failed ({type(error).__name__})")


def _config_field(ctx: Context, field: str, spec: Any, sources: list[dict[str, Any]]) -> dict[str, Any]:
    if isinstance(spec, dict) and "hook" in spec:
        return _run_hook(ctx, field, spec)
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


def newest_first(sources: Any, candidates: list[Any], path_of: Callable[[Any], str],
                 more: bool = False) -> tuple[list[Any], str | None]:
    """At most TRANSCRIPT_MAX_FILES of `candidates` (transcripts, in the
    order they were listed), and a note when that left some unread (RC-530).

    Past the cap, the newest by modification time are kept, when `sources`
    can give one (Sources.mtime), so the cap keeps recent activity: Claude
    Code names its transcripts by UUID, so name order is arbitrary. A file
    whose time can't be read sorts as the oldest. Without modification times
    the first in listed order are kept, and the note says so. `more` means
    listing stopped at TRANSCRIPT_MAX_CANDIDATES with more left."""
    total = f"{'more than ' if more else ''}{len(candidates)}"
    if len(candidates) <= TRANSCRIPT_MAX_FILES and not more:
        return list(candidates), None
    mtime = getattr(sources, "mtime", None)
    if not callable(mtime):
        return (list(candidates[:TRANSCRIPT_MAX_FILES]),
                f"read the first {TRANSCRIPT_MAX_FILES} of {total} transcripts, in name order "
                f"(no modification times; TRANSCRIPT_MAX_FILES)")
    stamped = []
    for index, candidate in enumerate(candidates):
        when = mtime(path_of(candidate))
        stamped.append((when if isinstance(when, (int, float)) else float("-inf"), index, candidate))
    stamped.sort(key=lambda item: (-item[0], item[1]))
    chosen = [candidate for _, _, candidate in stamped[:TRANSCRIPT_MAX_FILES]]
    return chosen, f"read the {len(chosen)} newest of {total} transcripts (TRANSCRIPT_MAX_FILES)"


def _transcript_field(ctx: Context, spec: dict[str, Any]) -> dict[str, Any]:
    if "hook" in spec:
        return _run_hook(ctx, "tool_names", spec)
    if spec.get("format", "jsonl") != "jsonl" or not isinstance(spec.get("tool_name"), str):
        return _result("FAILED", "tool_names", reason="NOT_COLLECTED_BY_PACK", note="transcripts need format jsonl and tool_name, or a hook")
    counts: dict[str, int] = {}
    files: list[str] = []
    capped: list[str] = []
    bad_lines = 0
    # Every transcript first (names only), then at most TRANSCRIPT_MAX_FILES
    # of them, the newest first (newest_first): a cap that leaves some unread
    # says so, as the byte cap does (RC-530).
    candidates: list[tuple[str, str]] = []
    more = False
    for raw in spec.get("folders", []):
        folder = ctx.agent.expand(raw)
        names = ctx.sources.list_dir(folder) if folder else None
        for name in names or []:
            if not fnmatch.fnmatch(name, spec.get("files", "*.jsonl")):
                continue
            if len(candidates) >= TRANSCRIPT_MAX_CANDIDATES:
                more = True
                break
            candidates.append((f"{raw.rstrip('/')}/{name}", f"{folder.rstrip('/')}/{name}"))
    chosen, file_note = newest_first(ctx.sources, candidates, lambda item: item[1], more)
    for shown, path in chosen:
        text, cut = _read_capped(ctx, path, TRANSCRIPT_MAX_BYTES)
        if text is None:
            continue
        if cut:
            # Count the whole lines read; the one the cap cut is not a bad line.
            text = text.rpartition("\n")[0]
            capped.append(shown)
        files.append(shown)
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
    # The bundle's shape (evidence_bundle.py, compose_evidence_bundle_v2.py):
    # the names, sorted; a floor, not a count.
    value = sorted(counts)
    floor = "floor, not a count: tools not called in the transcripts read are absent here"
    notes = [n for n in (file_note,
                         f"read up to {TRANSCRIPT_MAX_BYTES} bytes of {', '.join(capped)}" if capped else None,
                         f"{bad_lines} transcript line(s) could not be parsed" if bad_lines else None) if n]
    if not value and not file_note:
        return _result("ABSENT", "tool_names", method=f"{ctx.harness}: no tool calls in {len(files)} transcript(s)")
    if file_note or capped:
        # Some transcripts, or some of one, weren't read: what was found is a
        # floor, and none found isn't "none" (an empty floor, not ABSENT).
        return _result("PARTIAL", "tool_names", value=value, reason="SIZE_CAP_EXCEEDED", source=files,
                       note=f"{floor}; " + "; ".join(notes))
    if bad_lines:
        return _result("PARTIAL", "tool_names", value=value, reason="PARSE_FAILED", source=files,
                       note=f"{floor}; " + "; ".join(notes))
    return _result("ANSWERED", "tool_names", value=value, source=files, note=floor)


# mcp_servers_observed (RC-545): which MCP servers the agent called, and which
# of their tools, from the tool names tool_names found in the transcripts. A harness names an
# MCP server's tool by a pattern its profile gives (workspace.transcripts.
# mcp_tools): OpenClaw "{server}__{tool}", Claude Code "mcp__{server}__{tool}".
# A call is the server's when its name matches the pattern with a server
# mcp_servers_declared names; with "undeclared": true (a prefix only MCP tools
# use) a server no config declares is kept too, split at the first separator.
# Names only, never a call's arguments, and no counts: a count grows with
# every call, so a locked baseline would see drift on every scan.
_SERVER_NAME_UNSAFE = re.compile(r"[^A-Za-z0-9_-]")


def mcp_tool_pattern(spec: Any) -> tuple[str, str, bool]:
    """(prefix, separator, undeclared) from a profile's mcp_tools: a pattern
    "<prefix>{server}<separator>{tool}" and whether undeclared servers count."""
    if not isinstance(spec, dict) or not isinstance(spec.get("pattern"), str):
        raise ValueError('an object with "pattern": "<prefix>{server}<separator>{tool}"')
    pattern = spec["pattern"]
    prefix, found, rest = pattern.partition("{server}")
    separator, found_tool, suffix = rest.partition("{tool}")
    if not found or not found_tool or not separator or suffix or "{" in prefix + separator:
        raise ValueError(f'{pattern!r} is not "<prefix>{{server}}<separator>{{tool}}" with a separator')
    undeclared = spec.get("undeclared", False)
    if not isinstance(undeclared, bool):
        raise ValueError("undeclared is true or false")
    return prefix, separator, undeclared


def _server_key(name: str) -> str:
    """A server name as a harness spells it in a tool name: characters other
    than letters, digits, _ and - become _ (as Claude Code writes them), so a
    declared "my.server" matches mcp__my_server__tool. A name already in that
    form is unchanged."""
    return _SERVER_NAME_UNSAFE.sub("_", name)


def _declared_servers(declared: dict[str, Any] | None) -> set[str]:
    """The names of mcp_servers_declared's servers, from a value the reader
    found (a {name: spec} object, or a list of {"name": ...})."""
    value = (declared or {}).get("value") if (declared or {}).get("status") in ("ANSWERED", "PARTIAL") else None
    if isinstance(value, dict):
        return {str(name) for name in value}
    if isinstance(value, list):
        return {str(entry["name"]) for entry in value if isinstance(entry, dict) and entry.get("name")}
    return set()


def observed_mcp_servers(tool_names: Iterable[str], declared: Iterable[str], spec: Any) -> list[dict[str, Any]]:
    """[{"name", "tools_called": [tool, ...]}] for the MCP servers whose tools
    are among `tool_names`, sorted by name, each server's tools sorted.
    `declared` is the declared servers' names; a call matched to one carries
    that name, and an undeclared server (with "undeclared": true) the name as
    the harness spells it in the tool name. A tool of no MCP server (a
    built-in) is left out. No endpoint: a transcript records the tool's name,
    not the address that was called, and this is an observed field."""
    prefix, separator, undeclared = mcp_tool_pattern(spec)
    # Longest first, so "a__b" is matched before "a" for a__b__tool; then by
    # key and name, so two declared names one key spells (my.server,
    # my_server) are tried in the same order on every scan.
    keys = sorted(((_server_key(name), name) for name in declared), key=lambda item: (-len(item[0]), item))
    by_server: dict[str, set[str]] = {}
    for tool_name in tool_names:
        if not isinstance(tool_name, str) or not tool_name.startswith(prefix):
            continue
        rest = tool_name[len(prefix):]
        server = tool = None
        for key, name in keys:
            if rest.startswith(key + separator) and len(rest) > len(key + separator):
                server, tool = name, rest[len(key + separator):]
                break
        if server is None and undeclared:
            head, sep, tail = rest.partition(separator)
            if sep and head and tail:
                server, tool = head, tail
        if server is not None:
            by_server.setdefault(server, set()).add(tool)
    return [{"name": server, "tools_called": sorted(by_server[server])} for server in sorted(by_server)]


OBSERVED_FLOOR = ("the agent's own transcripts, not the wire; a floor, not a count: a server or tool not "
                  "called in the transcripts read is absent here")


def _observed_mcp_field(tool_names: dict[str, Any], declared: dict[str, Any] | None,
                        spec: dict[str, Any]) -> dict[str, Any]:
    """mcp_servers_observed from the tool names the tool_names result found:
    the same transcripts, so the same account of them. Where no transcript
    was read (BLIND, or FAILED for another reason), tool_names' account.
    Where some weren't (PARTIAL, or FAILED with nothing found), an empty
    floor at most. Where transcripts were read and no MCP server was called,
    ABSENT, as tool_names is with no tool calls."""
    field = "mcp_servers_observed"
    no_mcp_call = "no call in the transcripts read named an MCP server"
    if "mcp_tools" not in spec:
        return _result("BLIND", field, reason="NOT_COLLECTED_BY_PACK",
                       note="the profile doesn't say how its harness names an MCP server's tools")
    names = tool_names.get("value") if tool_names["status"] in ("ANSWERED", "PARTIAL") else []
    # Each name scrubbed whole before it is split into server and tool, as
    # tool_names' is: "mcp__token=__x" split first would put "token=" and x in
    # separate strings, where redaction no longer sees them together.
    names = [scrub_text(name) for name in names if isinstance(name, str)] if isinstance(names, list) else []
    servers = _declared_servers(declared)
    value = observed_mcp_servers(names, servers, spec["mcp_tools"])
    undeclared = [entry["name"] for entry in value if entry["name"] not in servers]
    source = tool_names.get("source")
    status = tool_names["status"]
    if status == "PARTIAL" or (status == "FAILED" and tool_names.get("reason") in ("PARSE_FAILED", "SIZE_CAP_EXCEEDED")):
        # Some transcripts, or some of one, weren't read: a floor, and none
        # found isn't "none" (an empty floor).
        return _result("PARTIAL", field, value=value, reason=tool_names.get("reason") or "PARSE_FAILED",
                       source=source or [],
                       note="; ".join(n for n in (OBSERVED_FLOOR, tool_names.get("note")) if n))
    if status not in ("ANSWERED", "ABSENT"):
        return _result(status, field, **{key: tool_names[key] for key in ("reason", "note") if key in tool_names})
    if not value:
        # As tool_names with no tool calls: looked, and found none.
        why = no_mcp_call
        if not servers and not mcp_tool_pattern(spec["mcp_tools"])[2]:
            why += " (none was declared, so no call could be matched to one)"
        where = ", ".join(source) if isinstance(source, list) else source or tool_names.get("method")
        return _result("ABSENT", field, method=f"{why}" + (f": {where}" if where else ""))
    note = OBSERVED_FLOOR
    if undeclared:
        # Named as the harness spells them in a tool name, so they don't
        # match a name in mcp_servers_declared (a plugin's server, say).
        note += ("; not declared in any MCP config the scan read, named as the harness spells them in its "
                 "tool names: " + ", ".join(undeclared))
    return _result("ANSWERED", field, value=value, source=source or [], note=note)


def _generic_reader() -> Any:
    """generic.py beside this file, loaded by path once, as a profile's hooks are."""
    import importlib.util
    import sys

    name = "harness_generic_reader"
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, GENERIC_READER)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {GENERIC_READER}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


def _finish(results: dict[str, dict[str, Any]], harness: str,
            redact_url: Callable[[str], str] | None) -> dict[str, dict[str, Any]]:
    """Every value, and every string reported beside it, redacted, and each
    result tagged with the harness (or reader) it came from."""
    for field in HARNESS_FIELDS:
        if "value" in results[field]:
            results[field]["value"] = redact(results[field]["value"], redact_url)
        # Every string reported beside the value too: file names are the
        # agent's to choose.
        for key in ("source", "method", "note"):
            if key in results[field]:
                results[field][key] = redact(results[field][key])
        results[field]["harness"] = harness
    return results


def read_harness_fields(profile: dict[str, Any] | None, agent: Agent, sources: Sources, *,
                        collect_prompt: bool = False, loads: Callable[[str], Any] = loads_json,
                        redact_url: Callable[[str], str] | None = None,
                        config_paths: Iterable[str] = ()) -> dict[str, dict[str, Any]]:
    """Every harness field for `agent`, read with `profile`. A field the
    profile doesn't name is BLIND with NOT_COLLECTED_BY_PACK.

    With no profile (none matched), the generic reader (generic.py) reads
    what any harness may use: .mcp.json, AGENTS.md, *_MODEL and *_BASE_URL
    variables, and model-like and permission-named keys in the top-level
    *.json files under `config_paths` (the --config-path values); every
    field it can't fill is BLIND with UNKNOWN_HARNESS."""
    if profile is None:
        agent = with_derived({"harness": GENERIC_HARNESS}, agent)
        results = _generic_reader().read_generic_config(
            sys.modules[__name__], agent, sources, [str(p) for p in config_paths],
            collect_prompt=collect_prompt, loads=loads)
        return _finish(results, GENERIC_HARNESS, redact_url)
    agent = with_derived(profile, agent)
    ctx = Context(profile, agent, sources, loads, collect_prompt)
    results: dict[str, dict[str, Any]] = {}
    config_sources = _read_sources(ctx)
    ctx.config_sources = config_sources
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
        results["mcp_servers_observed"] = _observed_mcp_field(
            results["tool_names"], results.get("mcp_servers_declared"), workspace["transcripts"])
    for field in HARNESS_FIELDS:
        results.setdefault(field, _result("BLIND", field, reason="NOT_COLLECTED_BY_PACK",
                                          note=f"the {profile['harness']} profile doesn't name this field"))
    return _finish(results, profile["harness"], redact_url)


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
        label = "generic reader" if harness == GENERIC_HARNESS else f"{harness} profile"
        method = f"{label}: {source if isinstance(source, str) else ', '.join(source or [])}" if harness else None
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

# Harness profiles

An agent's harness (OpenClaw, Claude Code, ...) keeps its model, MCP servers,
tool policy, transcripts and prompt files in its own files. `reader.py` reads
any harness from a **profile**: a JSON file in `profiles/` that says where
that harness keeps each field. Supporting a harness means writing its profile
(and fixtures), not code.

| Profile | Harness | Hooks |
|---|---|---|
| `profiles/openclaw.json` (RC-516) | OpenClaw, as 2026.9.2 lays out its files | `profiles/openclaw.py`: the installed version, the model's provider and endpoint, exec approvals and transcripts from its SQLite databases, including the events 2026.10.8 compresses into `event_zstd` (RC-530) |
| `profiles/claude-code.json` (RC-526) | Claude Code, as 2.1.325 lays out and reads its files | `profiles/claude-code.py`: the version (npm package or native install), the model, provider and endpoint in Claude Code's own order (`--model`, `ANTHROPIC_MODEL`, `model`), MCP servers by scope (user, project `.mcp.json`, local, or `managed-mcp.json` alone), permission rules merged across settings files with an untrusted project's allow rules left out, the permission mode and hooks (by event and matcher only), and `tool_use` names from its JSONL transcripts |

For an agent no profile matches, the generic reader (`generic.py`, RC-520)
reads the fields that need no profile; see [The generic reader](#the-generic-reader).

## The reader

- `harness_reader_for(profiles, agent)` picks the profile with the strongest
  sign on the agent's command line, else the first whose environment markers
  it sets, or None.
- `read_harness_fields(profile, agent, sources, config_paths=...)` reads each
  field. With no profile, the generic reader reads them from what any
  harness may use, under the `--config-path` values in `config_paths`.
- `to_attributes(results, builders)` turns the results into bundle attributes.

Where files come from is the caller's: a `Sources` object reads a path as the
agent sees it. `LocalSources` reads this machine's files; pod mode reads the
agent's container (`harness_sources.py`). The reader imports nothing of
railmon's and runs nothing.

Each field comes back as one of:

| Status | When |
|---|---|
| `ANSWERED` | A source had it. `source` names which, or which ones for a union |
| `ABSENT` | Sources were read and none set it. `method` names them |
| `BLIND`, `GATEWAY_MANAGED` | `tool_allow_deny` or `approval_policy` not set: an undeclared policy is never evidence of restriction (as the bundle already reports it) |
| `FAILED`, `PARSE_FAILED` | None had it and one could not be parsed |
| `FAILED`, `SIZE_CAP_EXCEEDED` | None had it and one was larger than the cap, so it was not read |
| `PARTIAL`, `PARSE_FAILED` or `SIZE_CAP_EXCEEDED` | Tool names read, with some transcript lines unparsed, or a transcript read only up to its cap (whole lines only), or more transcripts than `TRANSCRIPT_MAX_FILES` (the note says how many were read). With transcripts left unread, none found is an empty floor, not `ABSENT` |
| `BLIND`, `NO_SOURCE_ACCESS` | No source could be read |
| `FAILED`, `PARSE_FAILED`, "hook … failed" | A hook raised (a malformed database, a full or read-only `/tmp`): that field only, never the scan |
| `BLIND`, `NOT_COLLECTED_BY_PACK` | The profile doesn't name the field, or prompt text without the flag |
| `BLIND`, `UNKNOWN_HARNESS` | No profile matched, and the generic reader couldn't fill the field |

In pod mode the scanner's own `redact_url` is applied to any whole URL, which
also masks a secret in a URL's path (a gateway's `/mcp/<key>/sse`).

Every source is read safely: 64 KB at most, regular files only, without
blocking, JSON nested at most 100 levels. Every value is scrubbed at any
depth:

- a credential key's value replaced (`apiKey`, `headers`, `env`, `token`,
  `client_secret`, `privateKeyPem`, ...): the key itself is always kept. A
  container (`env`, `headers`, `secrets`, `credentials`) loses its whole
  value; under a key that only names a credential, a plain value goes and an
  object keeps its shape with every plain value in it redacted, so an MCP
  server called `1password` or `secrets-manager` is still reported, its
  config hidden, and `github-auth` is untouched;
- in a list, the item after a credential flag (`["--api-key", "..."]`)
  replaced;
- in every string, scanned once word by word (no regex an agent's string
  could make backtrack): any scheme's URL user, password, query and fragment
  (`postgres://u:pw@db/x`, a URL inside a sentence); the value after a
  credential name and `=` or `:` (`TOKEN=...`, `password: ...`,
  `x-api-key: ...`) or after a credential flag (`--api-key ...`); the word
  after `Bearer` or `Basic`; token shapes such as `sk-...`, `ghp_...`,
  `AKIA...` and JWTs; and PEM private-key blocks. All are replaced with
  `[redacted]` (the scanner's marker);
- in a key, only URLs, token shapes and private keys: the key itself, a name,
  stays.

A value reached by a key path that ends at, or wildcards under, a credential
key (`mcpServers.*.env`, `env.*`) is replaced whole, since its parent key is
no longer there to say what it is; a path naming one entry under such a key
(`env.ANTHROPIC_BASE_URL`) reads that entry.

Paths are reported as the profile writes them (`~/.toy/settings.json`,
`$TOY_CONFIG`): the agent's environment is used to find files, and no value of
it reaches the bundle. `source`, `method` and `note` are scrubbed like values.

Pod mode replaces a bundle field only with a value a profile found
(`ANSWERED` or `PARTIAL`); for anything else the bundle's own account stands.
A value the scanner observed itself (`authored_by: none`, such as
AgentSight's wire-observed `tool_names`) is never replaced by what the agent's
own files say. The declared lists are merged in the bundle's own shapes, with
the scanner's own functions: `mcp_servers_declared` as `read_mcp_inventory`'s
entries beside the `.mcp.json` ones, `skills_inventory` as normalized skills
(name and description from each `SKILL.md`'s frontmatter), and
`declared_destinations` recomputed from the result.

## The generic reader

`generic.py`'s `read_generic_config` runs when no profile matches the agent.
It reads only what any harness may use, and reports its results as
`generic` (`generic reader: <source>` in the bundle's `method`):

| Field | From |
|---|---|
| `mcp_servers_declared` | `.mcp.json` (`mcpServers`, or `servers`) in each `--config-path` folder, `$AGENT_CWD`, `~` and `/workdir`, the earlier winning on a name, and an `mcpServers` key in the top-level `*.json` under `--config-path`. `ABSENT` when an MCP config was read and names no server, `FAILED` when one of these files (an `.mcp.json` or a top-level `*.json`) couldn't be read or parsed, since it may hold the servers |
| `system_prompt_present`, `system_prompt_text` | `AGENTS.md` in the same folders; its text only with `--collect-system-prompt` |
| `model_name` | The agent's `*_MODEL` variables: the scanner's own first (`RAIL_LLM_MODEL`, `LLM_MODEL`, `OPENAI_MODEL`, `ANTHROPIC_MODEL`, `OPENCLAW_MODEL`), then any whose name has a model-service word (`LLM`, `AI`, `CHAT`, `AGENT`, a vendor), never an embedding or reranking model nor one like `AUTH_USER_MODEL`; else a model-like key (`model`, `modelName`, `defaultModel`, `model.primary`, ...) |
| `inference_endpoint` | `*_BASE_URL` variables, the scanner's own first, then any whose name has a model-service word (`LLM`, `MODEL`, a vendor), never one like `APP_BASE_URL`; else a base-URL key beside a model key or under a model or provider key, redacted |
| `llm_provider` | A provider key, else a `vendor/model` prefix, else the vendor a model or base-URL variable is named for (`GEMINI_MODEL`) |
| `tool_allow_deny` | Permission-named keys (`permissions`, `allowedTools`, `tools.allow`, ...), by file and key path |
| `approval_policy` | Approval-named keys (`approvalMode`, `autoApprove`, ...), by file and key path |

Nothing under a credential-named key (`env`, `headers`, `auth`, `apiKey`, ...) is taken from them, since a value found there would be reported under a path that no longer names it. The top-level `*.json` are read like a profile's sources (64 KB, regular
files only, at most 50); one that doesn't parse makes the fields it might
have held `FAILED` with `PARSE_FAILED`. Every other field it can't fill is
`BLIND` with `UNKNOWN_HARNESS`, never `ABSENT`: a harness without a profile
may keep it anywhere. `harness_identity`, `tool_names` and `skills_inventory`
always are, since only a profile knows the version, transcripts and skills.

In pod mode its values are merged as a profile's are. Where it found no
value, its account replaces a bundle account that only says "not found"
(`ABSENT`, `BLIND` with `NOT_COLLECTED_BY_PACK`, or `GATEWAY_MANAGED` for an
undeclared policy); a value the scanner observed itself, or a more specific
failure, stands. `tool_schemas` is never `ABSENT` while the servers are
unknown: `BLIND` with `UNKNOWN_HARNESS` when no MCP config was found, and
`FAILED` with the config's own reason when one couldn't be read or parsed.

## A profile

```json
{
  "harness": "toyagent",
  "markers": {"commands": ["toyagent"], "env": ["TOYAGENT_HOME"]},
  "sources": [
    {"path": "$TOY_CONFIG"},
    {"path": "/work/.toy/settings.json"},
    {"path": "~/.toy/settings.json"}
  ],
  "fields": {
    "harness_identity": "version",
    "model_name": ["model.primary", "model"],
    "mcp_servers_declared": {"paths": ["mcp.servers"], "merge": "union"},
    "tool_allow_deny": {"keys": {"allow": "tools.allow", "deny": "tools.deny"}},
    "approval_policy": "approvals",
    "llm_provider": {"hook": "toy_provider"}
  },
  "workspace": {
    "prompt_files": ["/work/TOY.md", "~/.toy/TOY.md"],
    "skills": ["~/.toy/skills"],
    "transcripts": {"folders": ["~/.toy/sessions"], "files": "*.jsonl", "tool_name": "call.name"}
  }
}
```

- **`markers`**: the program the agent runs (`commands`, by its basename),
  or the npm package it runs from (`packages`: inside
  `node_modules/<package>/`, so `node
  /usr/local/lib/node_modules/openclaw/openclaw.mjs` matches `openclaw`), or
  an environment variable it sets (`env`). Every word of the command line
  is looked at, since the program can come after any wrapper (`npm run`,
  `uv run`, `sh -c cd /app && ...`, an entrypoint script, a launcher's flags)
  and `/proc` gives the command line with its quoting lost. Of the profiles
  it shows a sign of, a word inside a profile's package wins, as that is
  where the code being run lives; otherwise the earliest command word wins,
  as a program comes before its arguments, so a prompt or note that names
  another harness doesn't change the answer. A prompt that holds a path
  into another harness's package still would. An `env` marker counts only
  when the command line shows no harness, since an agent's environment can
  carry another harness's variables.
- **`flags`** and **`variables`** (optional): names a profile derives, for a
  harness that picks its folder by a rule. A `flags` name is the value of a
  command-line flag (`--profile x` or `--profile=x`; a flag with a `value`
  takes none and sets that value); a `variables` name is the first of its
  templates whose names are all known. `profiles/openclaw.json` derives
  `$OPENCLAW_DIR` this way, from `$OPENCLAW_STATE_DIR`, `$OPENCLAW_HOME`,
  `--profile` and `--dev`. Like the environment, a derived name finds files
  and is never reported, and the agent's environment never sets one; a flag
  value with a `/` in it is ignored. `$AGENT_CWD`, the agent's working
  directory (pod mode reads `/proc/<pid>/cwd`), is derived for every profile
  the same way: `profiles/claude-code.json` finds the project's settings
  through it.
- **`sources`**: JSON files, **highest precedence first**. `~` is the agent's
  `HOME` and `$VAR` its environment; a source whose variable isn't set is
  skipped, and so is a file that isn't there. A source whose last part is a
  pattern (`/etc/claude-code/managed-settings.d/*.json`) is the drop-in files
  matching it, a later name over an earlier one (at most 50), each reported by
  its own name. A source is read up to 64 KB, or up to its own `max_bytes`
  (1 MB at most) for a file that also holds caches, such as `~/.claude.json`.
- **`fields`**, one per harness field:
  - a key path (`model.primary`; `*` takes every item), or a list tried in
    order;
  - `{"paths": [...], "merge": "union"}` to merge objects or lists across
    sources, the higher source winning on the same key (the default, `first`,
    takes the highest source that has it);
  - `{"keys": {"allow": "...", "deny": "..."}}` to build an object from
    several key paths;
  - `{"hook": "name"}` for a format a key path can't reach. Hooks ship beside
    the profile as `profiles/<harness>.py`, whose `register(reader)` registers
    them with `@reader.hook("name")`; a hook gets the profile, the agent, its
    files (`read_text`, `read_bytes`, `list_dir`) and the parsed config sources
    (`ctx.config_value`, `ctx.parsed_sources`).
- **`workspace`**: prompt files (`system_prompt_present`; their text only with
  prompt collection on), skills folders (a subfolder holding `SKILL.md` is a
  skill), and transcripts (JSON lines, `tool_name` a key path in each line;
  or `{"hook": "name"}`). `tool_names` is the bundle's shape: the names,
  sorted, a floor rather than a count. At most `TRANSCRIPT_MAX_FILES` (50)
  transcripts are read, 1 MB each; past that, the newest by modification
  time (`newest_first`, RC-530), since a harness may name them by UUID.
  Every transcript is listed first, up to 5,000. A `Sources` without
  `mtime` gets name order, and the note says so. Claude Code's profile uses
  the same selection, its subagent transcripts counted with its sessions.
  The cap stays at 50: with the newest read first and the note saying how
  many weren't, it keeps a scan's reads bounded at 50 MB, to revisit with
  the overhead benchmark (RC-525).
- **`watch`** (optional, pod mode's watcher, RC-523): `content`, more paths
  hashed by content beside the `sources`, prompt files and skills, which
  always are (a last part may be a pattern); `list`, folders hashed by file
  list only, for transcripts that grow on every turn; and `wait_for`, what
  must exist before the first scan, for up to `wait_seconds`. A `wait_for`
  item may be a list of alternatives, the first whose variables are set
  being used. OpenClaw waits for `openclaw.json` and `agents/main/`; a
  profile with no `wait_for` is scanned as soon as its process is found. See
  [the watcher](../README.md#rescans-shutdown-and-health-rc-523).

A field the profile doesn't name is `BLIND` with `NOT_COLLECTED_BY_PACK`, and
pod mode leaves the bundle's own value for it.

## The MCP probe

The MCP probe reads `mcp_servers_declared` on its own, before the bundle is
built (`read_declared_mcp_servers`, RC-531), and asks each server the profile
declares, so `tool_schemas` and `skills_inventory` list those servers' tools.
Only that field is read, and its value isn't redacted: redaction hides a
server's whole config when its name looks like a credential's
(`secrets-manager`), which would leave the probe no URL. Each server keeps
only what the probe uses (`url`, `command`, `args`, `type`, `transport`), so
`headers` and `env` never reach it, and the probe judges each URL for a
credential itself. That value is the probe's alone and never reaches the
bundle. A hook that
settles a list the harness loads to the exclusion of every other server says
`exclusive` in its result, as Claude Code's does for `managed-mcp.json`, and
only those servers are probed.

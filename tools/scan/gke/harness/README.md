# Harness profiles

An agent's harness (OpenClaw, Claude Code, ...) keeps its model, MCP servers,
tool policy, transcripts and prompt files in its own files. `reader.py` reads
any harness from a **profile**: a JSON file in `profiles/` that says where
that harness keeps each field. Supporting a harness means writing its profile
(and fixtures), not code.

No profile ships yet: OpenClaw's is RC-516 and Claude Code's RC-526. Until
one matches an agent, its harness fields come from the scanner's generic code;
the generic reader for any other harness is RC-520.

## The reader

- `harness_reader_for(profiles, agent)` picks the first profile whose markers
  match the agent's command line or environment, or None.
- `read_harness_fields(profile, agent, sources)` reads each field. With no
  profile, every field is `BLIND` with `UNKNOWN_HARNESS`.
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
| `PARTIAL`, `PARSE_FAILED` or `SIZE_CAP_EXCEEDED` | Tool names read, with some transcript lines unparsed, or a transcript read only up to its cap (whole lines only) |
| `BLIND`, `NO_SOURCE_ACCESS` | No source could be read |
| `BLIND`, `NOT_COLLECTED_BY_PACK` | The profile doesn't name the field, or prompt text without the flag |
| `BLIND`, `UNKNOWN_HARNESS` | No profile matched |

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

- **`markers`**: a word of the agent's command line (its basename, so
  `node /usr/bin/toyagent` matches `toyagent`), or an environment variable it
  sets.
- **`sources`**: JSON files, **highest precedence first**. `~` is the agent's
  `HOME` and `$VAR` its environment; a source whose variable isn't set is
  skipped, and so is a file that isn't there.
- **`fields`**, one per harness field:
  - a key path (`model.primary`; `*` takes every item), or a list tried in
    order;
  - `{"paths": [...], "merge": "union"}` to merge objects or lists across
    sources, the higher source winning on the same key (the default, `first`,
    takes the highest source that has it);
  - `{"keys": {"allow": "...", "deny": "..."}}` to build an object from
    several key paths;
  - `{"hook": "name"}` for a format a key path can't reach. A hook is a
    function registered with `@reader.hook("name")` that gets the profile, the
    agent and its files.
- **`workspace`**: prompt files (`system_prompt_present`; their text only with
  prompt collection on), skills folders (a subfolder holding `SKILL.md` is a
  skill), and transcripts (JSON lines, `tool_name` a key path in each line;
  or `{"hook": "name"}`). `tool_names` is the bundle's shape: the names,
  sorted, a floor rather than a count.

A field the profile doesn't name is `BLIND` with `NOT_COLLECTED_BY_PACK`, and
pod mode leaves the bundle's own value for it.

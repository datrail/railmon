# Skills Scanner

Scans loaded agent skills from real OpenClaw and NemoClaw environments and emits
rail-center `SkillInput` objects:

```json
[
  {
    "name": "skill-name",
    "description": "What the skill does",
    "destination_endpoints": ["https://service.example/api"],
    "source_type": "skills_config"
  }
]
```

The scanner is external. It does not modify OpenClaw, NemoClaw, their images, or
their source code. It reads `SKILL.md` files from the agent data directory or
from a running Docker container.

## How It Works

OpenClaw and NemoClaw load skills from files on disk. The important metadata is
already present in each skill's `SKILL.md`, so Rail Guardian does not need to
instrument or patch the agent runtime to discover the skill inventory.

The scanner uses this read-only flow:

1. Locate skill roots.
   - Host mode scans paths passed with `--root`, `$RAIL_SCAN_SKILL_ROOTS`, or the
     default OpenClaw config directories.
   - Container mode uses `docker inspect` to find host bind mounts for
     `/home/node/.openclaw`.
   - Container mode also uses `docker exec` to read OpenClaw's bundled install
     paths inside the running container.
2. Find skill manifests.
   - The scanner recursively searches those roots for files named `SKILL.md`.
   - It scans the real files used by OpenClaw/NemoClaw; no mock skill fixtures
     are created.
3. Parse each manifest.
   - `name` comes from metadata, the first Markdown heading, or the parent
     directory name.
   - `description` comes from metadata, the first prose paragraph, or a source
     path fallback.
   - `destination_endpoints` comes from endpoint metadata fields and URLs found
     in the Markdown text.
4. Normalize output.
   - Duplicate skills are merged by `(source_type, name)`.
   - URL query strings and fragments are dropped to avoid leaking credentials.
   - Each result is emitted as a rail-center-compatible `SkillInput`.

Trigger-based scanning is implemented by polling and hashing the generated
output. When the hash changes, the scanner emits or registers the new payload.
Time-based scanning uses the same scan path on a fixed interval, for example
`--daily` for every 24 hours.

The scanner does not prove that a skill is safe and does not perform static
analysis of the skill implementation. It only reports the skill inventory and
documented service destinations available to the agent.

## What Gets Scanned

By default, OpenClaw and NemoClaw keep agent state under:

```text
/home/node/.openclaw
```

Their container images can also include bundled skills under:

```text
/usr/local/lib/node_modules/openclaw/skills
/usr/local/lib/node_modules/openclaw/dist/extensions
```

The example Compose files mount that path from the host:

```text
examples/openclaw-monitoring/openclaw-data  -> /home/node/.openclaw
examples/nemoclaw-monitoring/nemoclaw-data  -> /home/node/.openclaw
```

`skill_scanner.py` recursively finds `SKILL.md` files and extracts:

| Field | Source |
| --- | --- |
| `name` | frontmatter `name`, first Markdown heading, then parent directory name |
| `description` | frontmatter `description`, first body paragraph, then source path fallback |
| `destination_endpoints` | frontmatter endpoint fields and `http://` / `https://` URLs found in `SKILL.md` |
| `source_type` | always `skills_config` |

URL query strings and fragments are removed before output to avoid leaking
credentials embedded in documentation.

## Real OpenClaw Run

From the repository root:

```bash
cd datrail-agent-monitor
tools/skills-scanner/run-openclaw.sh
cat examples/openclaw-monitoring/output/openclaw-skills.json
```

The script runs the real OpenClaw service from
`examples/openclaw-monitoring/docker-compose.yml`, discovers the running
container, scans both the host data volume and `/home/node/.openclaw` inside the
container, then writes:

```text
examples/openclaw-monitoring/output/openclaw-skills.json
```

If OpenClaw has no `SKILL.md` files loaded yet, the output is `[]`. That is a
successful scan of the real container, not a mock.

The script waits briefly after the container is ready so OpenClaw can finish
installing plugin runtime dependencies. Override the delay when needed:

```bash
SKILL_SCANNER_STARTUP_DELAY=15 tools/skills-scanner/run-openclaw.sh
```

Manual equivalent:

```bash
cd datrail-agent-monitor/examples/openclaw-monitoring
mkdir -p openclaw-data output
docker compose up -d openclaw
OPENCLAW_CONTAINER="$(docker compose ps -q openclaw)"

cd ../..
python3 tools/skills-scanner/skill_scanner.py \
  --agent openclaw \
  --container "$OPENCLAW_CONTAINER" \
  --root examples/openclaw-monitoring/openclaw-data \
  --output examples/openclaw-monitoring/output/openclaw-skills.json
```

## Real NemoClaw Run

From the repository root:

```bash
cd datrail-agent-monitor
tools/skills-scanner/run-nemoclaw.sh
cat examples/nemoclaw-monitoring/output/nemoclaw-skills.json
```

The script runs the real NemoClaw service from
`examples/nemoclaw-monitoring/docker-compose.yml`, discovers the running
container, scans both the host data volume and `/home/node/.openclaw` inside the
container, then writes:

```text
examples/nemoclaw-monitoring/output/nemoclaw-skills.json
```

Manual equivalent:

```bash
cd datrail-agent-monitor/examples/nemoclaw-monitoring
mkdir -p nemoclaw-data output
docker compose up -d nemoclaw
NEMOCLAW_CONTAINER="$(docker compose ps -q nemoclaw)"

cd ../..
python3 tools/skills-scanner/skill_scanner.py \
  --agent nemoclaw \
  --container "$NEMOCLAW_CONTAINER" \
  --root examples/nemoclaw-monitoring/nemoclaw-data \
  --output examples/nemoclaw-monitoring/output/nemoclaw-skills.json
```

## Existing Containers

Scan an already-running OpenClaw container:

```bash
python3 tools/skills-scanner/skill_scanner.py \
  --agent openclaw \
  --container openclaw-test
```

Scan an already-running NemoClaw container:

```bash
python3 tools/skills-scanner/skill_scanner.py \
  --agent nemoclaw \
  --container nemoclaw-test
```

When `--container` is used, the scanner:

1. Uses `docker inspect` to find host mounts for `/home/node/.openclaw`.
2. Scans those host paths when readable.
3. Uses `docker exec` to read `SKILL.md` files from the data directory and
   OpenClaw's bundled install paths inside the container.

This keeps the integration read-only.

## Host-Only Scan

Scan explicit directories:

```bash
python3 tools/skills-scanner/skill_scanner.py \
  --root examples/openclaw-monitoring/openclaw-data \
  --root examples/nemoclaw-monitoring/nemoclaw-data
```

Without `--root` or `--container`, the scanner checks:

```text
$RAIL_SCAN_SKILL_ROOTS
~/.openclaw
~/.config/openclaw
.openclaw
```

`RAIL_SCAN_SKILL_ROOTS` accepts comma-separated or colon-separated paths.

## Registration Payload

By default, the scanner prints only the `skills` list. To emit a complete
`RegisterAgentRequest` payload:

```bash
python3 tools/skills-scanner/skill_scanner.py \
  --agent openclaw \
  --container "$OPENCLAW_CONTAINER" \
  --payload \
  --owner "$USER" \
  --llm-provider local \
  --llm-model tinyllama
```

To register directly with rail-center:

```bash
python3 tools/skills-scanner/skill_scanner.py \
  --agent openclaw \
  --container "$OPENCLAW_CONTAINER" \
  --register \
  --center-url http://localhost:23001 \
  --owner "$USER" \
  --llm-provider local \
  --llm-model tinyllama
```

For richer environment detection, use
`tools/agent-environment-scanner/scan_agent_environment.py` and replace its
`skills` field with this tool's output.

## Trigger-Based Scanning

Run continuously and emit whenever `SKILL.md` content changes:

```bash
python3 tools/skills-scanner/skill_scanner.py \
  --container "$OPENCLAW_CONTAINER" \
  --watch \
  --poll-interval 5
```

This uses polling instead of inotify so it works with Docker bind mounts and
container fallback reads.

## Time-Based Scanning

Run a daily scan:

```bash
python3 tools/skills-scanner/skill_scanner.py \
  --container "$OPENCLAW_CONTAINER" \
  --daily \
  --output /var/log/datrail/openclaw-skills.json
```

Or choose an explicit interval:

```bash
python3 tools/skills-scanner/skill_scanner.py \
  --container "$OPENCLAW_CONTAINER" \
  --interval-seconds 3600
```

## Validation

Syntax check:

```bash
python3 -m py_compile tools/skills-scanner/skill_scanner.py
```

Run against real apps:

```bash
tools/skills-scanner/run-openclaw.sh
tools/skills-scanner/run-nemoclaw.sh
```

These commands use the real OpenClaw/NemoClaw containers from `examples/`; they
do not create artificial skill fixtures.

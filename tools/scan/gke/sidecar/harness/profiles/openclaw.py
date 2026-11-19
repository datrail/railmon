"""OpenClaw's hooks, for the fields openclaw.json's key paths can't reach on
their own (RC-516). Loaded with openclaw.json by reader.load_profiles.

As OpenClaw 2026.9.2 lays its files out (checked against a real install in
NemoClaw's sandbox-base image, set up with rail-center's agent-setup.sh):

* openclaw.json: meta.lastTouchedVersion; agents.defaults.model.primary
  ("external/gemini-flash-latest"), an agent in agents.list overriding it;
  models.providers.<id>.baseUrl for the provider the model names.
* <state>/state/openclaw.sqlite, table exec_approvals_config: the host side of
  the exec policy. Its summary columns only; raw_json is never selected, since
  its socket entry can carry the approvals socket's token.
* <state>/agents/<id>/agent/openclaw-agent.sqlite, table transcript_events:
  each assistant message's toolCall parts name the tools it called.

Both databases are in WAL mode, so each is copied with its -wal into a
temporary folder and read there: the live files are never opened, and the
latest writes are included. The agent writes them, so a copy is opened
read-only with schema functions untrusted, values capped at 1 MB, a 5-second
deadline on each query, at most 200,000 rows and 64 MB of values read from
one query, and only an ordinary table with no generated column queried
(never a view, which could compute rows without end). SQLite applies the
1 MB cap when it reads a stored value too, so transcript events are fetched
one row at a time: an event over the cap (a screenshot, a large tool result)
is left unread and counted as an unparsed event, and the rest still count. A checkpointed
database, with no -wal beside it, is copied with an empty one, as read-only
SQLite needs one for a WAL-mode file. <state> is the folder OpenClaw picks, which the
profile derives as $OPENCLAW_DIR: $OPENCLAW_STATE_DIR if set, else
<home>/.openclaw-<profile> for an agent started with --profile <profile>
(--dev is the profile "dev"), else <home>/.openclaw, where <home> is
$OPENCLAW_HOME, else ~. Checked against 2026.9.2: OPENCLAW_PROFILE in the
environment alone doesn't move it.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

PACKAGE_DIRS = ("/usr/local/lib/node_modules/openclaw", "/usr/lib/node_modules/openclaw",
                "/opt/openclaw", "/app")
DB_MAX_BYTES = 64_000_000
DB_SECONDS = 5.0           # a query that runs longer is interrupted
DB_MAX_VALUE = 1_000_000   # bytes in any one value SQLite will build
DB_MAX_ROWS = 200_000      # rows read from one query
DB_MAX_READ = 64_000_000   # bytes of values read from one query, in all
APPROVAL_TEXT_MAX = 64     # an approvals summary column is a short word or a count
APPROVAL_COLUMNS = ("default_security", "default_ask", "default_ask_fallback", "auto_allow_skills",
                    "allowlist_count", "agent_count")
VENDORS = (("googleapis.com", "google"), ("openai.com", "openai"), ("anthropic.com", "anthropic"),
           ("openrouter.ai", "openrouter"), ("azure.com", "azure"), ("amazonaws.com", "aws"))


def _state_dirs(ctx: Any) -> list[tuple[str, str]]:
    """OpenClaw's state folder as (the path reported, as the profile writes
    it, so no environment value reaches the bundle; the path read).
    $OPENCLAW_DIR is the profile's derived name for it."""
    path = ctx.agent.expand("$OPENCLAW_DIR")
    return [("$OPENCLAW_DIR", path.rstrip("/"))] if path else []


def _no_value(ctx: Any, field: str, what: str) -> dict[str, Any]:
    """Why a config-derived field has no value: nothing readable, a source
    that didn't parse, or read and not set."""
    sources = ctx.config_sources
    failed = [s["error"] for s in sources if s["error"]]
    reason = next((s.get("reason") for s in sources if s["error"]), None) or "PARSE_FAILED"
    parsed = [path for path, _ in ctx.parsed_sources()]
    if not parsed:
        if failed:
            return ctx.result("FAILED", field, reason=reason, note="; ".join(failed))
        return ctx.result("BLIND", field, reason="NO_SOURCE_ACCESS", note="no openclaw.json could be read")
    if failed:
        return ctx.result("FAILED", field, reason=reason, note=f"{what} not in {', '.join(parsed)}; " + "; ".join(failed))
    return ctx.result("ABSENT", field, method=f"openclaw: {what} not set in {', '.join(parsed)}")


def _copy_sqlite(ctx: Any, base: str, folder: str) -> tuple[Path | None, str | None]:
    """The database at `base` and its -wal copied into `folder`: (the copy,
    None), (None, None) when it isn't there, or (None, why) when it is there
    but can't be copied whole."""
    data = ctx.sources.read_bytes(base, DB_MAX_BYTES) if hasattr(ctx.sources, "read_bytes") else None
    if data is None:
        return None, None
    if len(data) >= DB_MAX_BYTES:
        return None, f"{base} is larger than {DB_MAX_BYTES} bytes"
    copy = Path(folder, "db.sqlite")
    copy.write_bytes(data)
    wal = ctx.sources.read_bytes(base + "-wal", DB_MAX_BYTES)
    if wal is not None and len(wal) >= DB_MAX_BYTES:
        return None, f"{base}-wal is larger than {DB_MAX_BYTES} bytes"
    # Always a -wal, empty when the agent's has been checkpointed away: a
    # WAL-mode database opened read-only can't be read without one.
    Path(folder, "db.sqlite-wal").write_bytes(wal or b"")
    return copy, None


def _open(copy: Path, table: str) -> sqlite3.Connection:
    """A copied database the agent wrote, opened so a crafted file can't hang
    or exhaust the scanner: read-only, with schema functions untrusted,
    values capped at DB_MAX_VALUE, and every query on it interrupted once
    DB_SECONDS have passed since it was opened. `table` must be an ordinary
    table with no generated column, never a view or virtual table, all of
    which can compute values the file doesn't hold. Raises sqlite3.Error."""
    db = sqlite3.connect(f"{copy.as_uri()}?mode=ro", uri=True)
    try:
        if hasattr(db, "setlimit"):  # Python 3.11+
            # SQLite applies this when it reads a stored value too, not only
            # when it builds one: a larger value raises DataError when fetched.
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, DB_MAX_VALUE)
        db.execute("pragma trusted_schema = off")
        deadline = time.monotonic() + DB_SECONDS
        db.set_progress_handler(lambda: time.monotonic() > deadline, 10_000)
        kind = db.execute("select type, sql from sqlite_schema where name = ?", (table,)).fetchone()
        if not kind or kind[0] != "table" or not str(kind[1] or "").lstrip().upper().startswith("CREATE TABLE"):
            raise sqlite3.DatabaseError(f"{table} is not an ordinary table")
        # table_xinfo's hidden is 2 or 3 for a generated column.
        if any(column[6] in (2, 3) for column in db.execute(f'pragma table_xinfo("{table}")')):
            raise sqlite3.DatabaseError(f"{table} has a generated column")
    except BaseException:
        db.close()
        raise
    return db


def _query_each(copy: Path, table: str, column: str) -> tuple[list[Any], bool, int]:
    """`column` of every row of `table`, each fetched on its own, so one value
    over DB_MAX_VALUE (an event holding a screenshot) fails only that row:
    (the values, whether the budget cut them short, how many rows were too
    large to read). Rows are read up to DB_MAX_ROWS and DB_MAX_READ bytes,
    within one DB_SECONDS deadline. Raises sqlite3.Error for anything else."""
    db = _open(copy, table)
    try:
        values: list[Any] = []
        too_big, read, cut = 0, 0, False
        rowids = db.execute(f'select rowid from "{table}" order by rowid limit ?', (DB_MAX_ROWS + 1,)).fetchall()
        if len(rowids) > DB_MAX_ROWS:
            rowids, cut = rowids[:DB_MAX_ROWS], True
        for (rowid,) in rowids:
            try:
                row = db.execute(f'select "{column}" from "{table}" where rowid = ?', (rowid,)).fetchone()
            except sqlite3.DataError:  # larger than DB_MAX_VALUE: not read, and counted
                too_big += 1
                continue
            if row is None:
                continue
            read += len(row[0]) if isinstance(row[0], (str, bytes)) else 8
            if read > DB_MAX_READ:
                return values, True, too_big
            values.append(row[0])
        return values, cut, too_big
    finally:
        db.close()


def _query(copy: Path, table: str, sql: str) -> tuple[list[tuple[Any, ...]], bool]:
    """`sql`'s rows from `table` of a copied database the agent wrote, opened
    with _open's guards. Rows are read one at a time up to DB_MAX_ROWS and
    DB_MAX_READ bytes: (the rows, whether the budget cut them short). A value
    over DB_MAX_VALUE raises sqlite3.DataError, and anything else wrong
    sqlite3.Error."""
    db = _open(copy, table)
    try:
        rows: list[tuple[Any, ...]] = []
        read = 0
        for row in db.execute(sql):
            read += sum(len(v) if isinstance(v, (str, bytes)) else 8 for v in row)
            if len(rows) >= DB_MAX_ROWS or read > DB_MAX_READ:
                return rows, True
            rows.append(row)
        return rows, False
    finally:
        db.close()


def _summary_value(value: Any) -> Any:
    """An approvals summary column as a short str, an int or a bool; None
    for anything else (a BLOB, a long text), so no value of the agent's
    choosing reaches the bundle whole."""
    if isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, str) and len(value) <= APPROVAL_TEXT_MAX:
        return value
    return None


def _vendor(endpoint: str | None, provider_id: str | None) -> str | None:
    try:
        host = (urlsplit(endpoint).hostname or "") if endpoint else ""
    except ValueError:
        host = ""
    if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local"):
        return "local"
    for suffix, vendor in VENDORS:
        if host == suffix or host.endswith("." + suffix):
            return vendor
    return provider_id


def _model_route(ctx: Any) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """(model, its source, provider id, endpoint, the endpoint's source). The
    model is an agent's own in agents.list (the default one, else main) over
    agents.defaults; the endpoint is the baseUrl of the provider it names."""
    for path, doc in ctx.parsed_sources():
        agents = doc.get("agents") if isinstance(doc, dict) else None
        if not isinstance(agents, dict):
            continue
        model = None
        listed = agents.get("list") if isinstance(agents.get("list"), list) else []
        own = [a for a in listed if isinstance(a, dict) and (a.get("default") is True or a.get("id") == "main")]
        for candidate in [a.get("model") for a in own] + [(agents.get("defaults") or {}).get("model")]:
            if isinstance(candidate, dict):
                candidate = candidate.get("primary")
            if isinstance(candidate, str) and candidate.strip():
                model = candidate.strip()
                break
        if model is None:
            continue
        provider_id = model.split("/", 1)[0] if "/" in model else None
        endpoint, endpoint_source = None, None
        if provider_id:
            for provider_path, provider_doc in ctx.parsed_sources():
                provider = ((provider_doc.get("models") or {}).get("providers") or {}).get(provider_id) \
                    if isinstance(provider_doc, dict) else None
                if isinstance(provider, dict) and isinstance(provider.get("baseUrl"), str):
                    endpoint, endpoint_source = provider["baseUrl"], provider_path
                    break
        return model, path, provider_id, endpoint, endpoint_source
    return None, None, None, None, None


def register(reader: Any) -> None:
    @reader.hook("openclaw_identity")
    def identity(ctx: Any, field: str, spec: dict[str, Any]) -> dict[str, Any]:
        # The installed package says what runs; openclaw.json only which
        # version last wrote it.
        for folder in PACKAGE_DIRS:
            for name in ("dist/build-info.json", "package.json"):
                path = f"{folder}/{name}"
                text = ctx.sources.read_text(path, 64_000)
                if text is None:
                    continue
                try:
                    info = ctx.loads(text)
                except ValueError:
                    continue
                if not isinstance(info, dict) or (name == "package.json" and info.get("name") not in (None, "openclaw")):
                    continue
                version = info.get("version")
                if isinstance(version, str) and version:
                    commit = str(info.get("commit") or "")[:7]
                    return ctx.result("ANSWERED", field, value=f"openclaw/{version}", source=path,
                                      **({"note": f"build {commit}"} if commit else {}))
        version, source = ctx.config_value("meta.lastTouchedVersion")
        if isinstance(version, str) and version:
            return ctx.result("ANSWERED", field, value=f"openclaw/{version}", source=source,
                              note="the OpenClaw version that last wrote openclaw.json; no package was found")
        return _no_value(ctx, field, "meta.lastTouchedVersion")

    @reader.hook("openclaw_model")
    def model(ctx: Any, field: str, spec: dict[str, Any]) -> dict[str, Any]:
        name, source, provider_id, endpoint, endpoint_source = _model_route(ctx)
        if field == "model_name":
            if name:
                return ctx.result("ANSWERED", field, value=name, source=source)
            return _no_value(ctx, field, "agents.defaults.model")
        if field == "inference_endpoint":
            if endpoint:
                return ctx.result("ANSWERED", field, value=endpoint, source=endpoint_source,
                                  note=f"the baseUrl of provider {provider_id!r}, which the model names")
            return _no_value(ctx, field, f"models.providers.{provider_id or '<provider>'}.baseUrl")
        vendor = _vendor(endpoint, provider_id)
        if vendor:
            return ctx.result("ANSWERED", field, value=vendor, source=endpoint_source or source,
                              note="from the provider's endpoint host" if endpoint and vendor != provider_id
                              else "the provider id the model names")
        return _no_value(ctx, field, "the model's provider")

    @reader.hook("openclaw_approvals")
    def approvals(ctx: Any, field: str, spec: dict[str, Any]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        sources: list[str] = []
        exec_policy, exec_source = ctx.config_value("tools.exec")
        if isinstance(exec_policy, dict) and exec_policy:
            value["exec"] = exec_policy
            sources.append(exec_source)
        problem = None
        for shown, state in _state_dirs(ctx):
            base, shown_base = f"{state}/state/openclaw.sqlite", f"{shown}/state/openclaw.sqlite"
            with tempfile.TemporaryDirectory() as folder:
                copy, why = _copy_sqlite(ctx, base, folder)
                if copy is None:
                    problem = why.replace(base, shown_base) if why else problem
                    continue
                try:
                    # The summary columns, named: never raw_json.
                    rows, _ = _query(copy, "exec_approvals_config", f"select {', '.join(APPROVAL_COLUMNS)} "
                                  "from exec_approvals_config where config_key = 'current' limit 1")
                    row = rows[0] if rows else None
                except sqlite3.Error as exc:
                    problem = f"{shown_base}: {exc}"
                    continue
            problem = None
            if row:
                host = {name: _summary_value(column) for name, column in zip(
                    ("security", "ask", "ask_fallback", "auto_allow_skills", "allowlist_entries", "agent_overrides"), row)}
                host = {name: column for name, column in host.items() if column is not None}
                if "auto_allow_skills" in host:
                    host["auto_allow_skills"] = bool(host["auto_allow_skills"])
                value["host_approvals"] = host
                sources.append(f"{shown_base}#exec_approvals_config")
            break
        problem_reason = "SIZE_CAP_EXCEEDED" if problem and "larger than" in problem else "NO_SOURCE_ACCESS"
        if value and problem:
            return ctx.result("PARTIAL", field, value=value, reason=problem_reason, source=sources,
                              note=f"the host approvals could not be read: {problem}")
        if value:
            return ctx.result("ANSWERED", field, value=value, source=sources if len(sources) > 1 else sources[0])
        if problem:
            return ctx.result("BLIND", field, reason=problem_reason, note=f"the host approvals could not be read: {problem}")
        return ctx.result("BLIND", field, reason="GATEWAY_MANAGED",
                          note="no tools.exec and no host approvals; absence is NOT evidence of restriction")

    @reader.hook("openclaw_transcripts")
    def transcripts(ctx: Any, field: str, spec: dict[str, Any]) -> dict[str, Any]:
        counts: dict[str, int] = {}
        read: list[str] = []
        problems: list[str] = []
        bad_events = 0
        capped = False
        for shown, state in _state_dirs(ctx):
            for agent in ctx.sources.list_dir(f"{state}/agents") or []:
                base = f"{state}/agents/{agent}/agent/openclaw-agent.sqlite"
                shown_base = f"{shown}/agents/{agent}/agent/openclaw-agent.sqlite"
                with tempfile.TemporaryDirectory() as folder:
                    copy, why = _copy_sqlite(ctx, base, folder)
                    if copy is None:
                        if why:
                            problems.append(why.replace(base, shown_base))
                            capped = capped or "larger than" in why
                        continue
                    try:
                        events, cut, too_big = _query_each(copy, "transcript_events", "event_json")
                    except sqlite3.Error as exc:
                        problems.append(f"{shown_base}: {exc}")
                        continue
                read.append(shown_base)
                if cut:  # read up to the budget: the names so far count, PARTIAL
                    problems.append(f"{shown_base}: read up to {DB_MAX_ROWS} events or {DB_MAX_READ} bytes")
                    capped = True
                # An event over DB_MAX_VALUE (a screenshot, a large tool result)
                # isn't read; it counts as unparsed, and the rest still count.
                if too_big:
                    problems.append(f"{shown_base}: {too_big} event(s) larger than {DB_MAX_VALUE} bytes not read")
                bad_events += too_big
                for event_json in events:
                    try:
                        message = (ctx.loads(event_json) or {}).get("message") or {}
                    except (ValueError, TypeError, AttributeError):
                        bad_events += 1
                        continue
                    if not isinstance(message, dict) or message.get("role") != "assistant":
                        continue
                    content = message.get("content")
                    if not isinstance(content, list):
                        continue  # text only, or not OpenClaw's shape: no tool call to name
                    for part in content:
                        # Names only: never a call's arguments or result.
                        if isinstance(part, dict) and part.get("type") == "toolCall" and isinstance(part.get("name"), str):
                            counts[part["name"]] = counts.get(part["name"], 0) + 1
            if read or problems:
                break
        if not read:
            if problems:
                if capped:  # as the shared reader says a source too large to read
                    return ctx.result("FAILED", field, reason="SIZE_CAP_EXCEEDED", note="; ".join(problems))
                return ctx.result("BLIND", field, reason="NO_SOURCE_ACCESS", note="; ".join(problems))
            return ctx.result("BLIND", field, reason="NO_SOURCE_ACCESS", note="no OpenClaw transcript database was found")
        # The bundle's shape: the names, sorted; a floor, not a count.
        value = sorted(counts)
        floor = "floor, not a count: tools not called in the transcripts read are absent here"
        if problems or bad_events:
            notes = problems + ([f"{bad_events} transcript event(s) could not be parsed"] if bad_events else [])
            reason = "SIZE_CAP_EXCEEDED" if capped and not bad_events else "PARSE_FAILED"
            if not value:
                return ctx.result("FAILED", field, reason=reason, note="; ".join(notes))
            return ctx.result("PARTIAL", field, value=value, reason=reason, source=read,
                              note=f"{floor}; " + "; ".join(notes))
        if not value:
            return ctx.result("ABSENT", field, method=f"openclaw: no tool calls in {', '.join(read)}")
        return ctx.result("ANSWERED", field, value=value, source=read if len(read) > 1 else read[0], note=floor)

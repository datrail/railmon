"""API spec prober (RC-512): the sidecar's `http_operations`.

Pod mode asks each HTTP destination the agent calls for its public API spec,
for Data GuardRail's before-run rules. The destinations are the origins of
the MCP servers the scan probes (the scanner's `mcp_probe_plan`), never the
model endpoint; each is asked, without credentials, for the usual spec paths
and then the same under its MCP servers' mount path, and the first OpenAPI 3
or Swagger 2 JSON document found is kept, cut to each operation's method,
path, operationId and content types.

Only pod mode runs this (gke/probe_pool.py's probe stage), so it lives here
with the rest of the sidecar. Like the other modules in tools/scan/gke/, it
imports nothing of railmon's: the scanner hands itself over with `register`
(as harness/reader.py does its profile hooks), and the helpers it shares with
every scan mode (redaction, strict JSON, the JSON parse lock) stay there.
`http_operations_attribute` builds the bundle attribute from the builders
pod_mode.py is given, as its other attributes are.
"""

from __future__ import annotations

import http.client
import json
import re
import time
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

_s: Any = None  # the scanner module (scan_agent_environment), set by register


def register(scanner: Any) -> None:
    """Hand over the scanner, whose shared helpers this module uses."""
    global _s
    _s = scanner

# http_operations: the operations in the public API spec of each HTTP
# destination the agent calls, for Data GuardRail's before-run rules. The
# destinations are the origins of the MCP servers the scan probes
# (mcp_probe_plan: the MCP config, AGENT_MCP_URL and the harness profile's
# servers), never the model endpoint. Each is asked, without credentials, for
# the usual spec paths in order, and the first OpenAPI 3 or Swagger 2 JSON
# document found is kept.
OPENAPI_PATHS = ("/openapi.json", "/v3/api-docs", "/swagger.json", "/api-docs")
OPENAPI_MAX_BYTES = 4 * 1024 * 1024
# And the JSON elements a spec may parse to (json_element_count): a real
# 4 MB spec has far fewer; a body of tiny elements is cut here instead of
# becoming hundreds of MB of objects.
OPENAPI_MAX_ELEMENTS = 500_000
OPENAPI_PATH_TIMEOUT_SECONDS = 5.0
OPENAPI_READ_CHUNK = 64 * 1024
OPENAPI_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
# What one operation keeps: its path and operationId cut to this many
# characters, and at most this many content types each way.
HTTP_OPERATION_TEXT_MAX = 512
HTTP_OPERATION_MEDIA_TYPES_MAX = 16
# Operations kept a destination, and all of them as the bundle renders them
# (pretty-printed, a destination entry at HTTP_OPERATIONS_DESTINATION_INDENT
# and an operation at HTTP_OPERATIONS_OPERATION_INDENT, as tool_schemas'
# servers and tools), so with skills_inventory's and tool_schemas' 256 KiB
# each the bundle stays inside RailDash's and Rail Center's 1 MiB bound.
HTTP_OPERATIONS_MAX = 1000
HTTP_OPERATIONS_BYTES = 128 * 1024
HTTP_OPERATIONS_DESTINATION_INDENT = 12
HTTP_OPERATIONS_OPERATION_INDENT = 16

_JSON_STRUCTURE_RE = re.compile(rb"[{\[,]")
_SPEC_DECODER: json.JSONDecoder | None = None


def _decoder() -> json.JSONDecoder:
    """The scanner's strict JSON (no NaN or Infinity), as a raw decoder for
    `_salvage_object`; built once the scanner is registered."""
    global _SPEC_DECODER
    if _SPEC_DECODER is None:
        _SPEC_DECODER = json.JSONDecoder(parse_constant=_s._refuse_non_json_constant,
                                         parse_float=_s._finite_json_float)
    return _SPEC_DECODER
_JSON_SPACE = re.compile(r"[ \t\r\n]*")


def http_origin(url: Any) -> str | None:
    """`scheme://host[:port]` of an http or https URL, without its userinfo,
    path, query or fragment, or None for anything else (file://, a URL that
    doesn't parse): the only URLs the spec prober ever asks."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return None
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return f"{scheme}://{host}" + (f":{port}" if port is not None else "")


def spec_destinations(plan: list[tuple[str, dict[str, Any], str]]) -> list[str]:
    """The HTTP destinations whose API specs are probed: each planned MCP
    server's origin (`http_origin`), once each, in plan order. A command
    server, or a URL that isn't http or https, is no destination; nor is a
    URL that carries a credential (`url_carries_credential`), which the MCP
    probe doesn't ask either: such a server is usually a tenant of a shared
    service, whose origin's spec wouldn't describe what the agent calls."""
    return _s.dedupe([
        origin for origin, url in ((http_origin(spec.get("url")), spec.get("url")) for _, spec, *_ in plan)
        if origin and not _s.url_carries_credential(url)
    ])


# Mount paths tried a destination after its origin, and how long one may be.
SPEC_MOUNT_PATHS_MAX = 2
SPEC_MOUNT_PATH_MAX = 256


def mcp_mount_path(url: Any) -> str | None:
    """The path an MCP server's URL is mounted under (`/finretail` for
    `http://host/finretail/mcp`), where a service behind a context path
    serves its spec too (`/finretail/v3/api-docs`), or None when the server
    sits at the root. None as well for a URL that carries a credential
    (`url_carries_credential`, which a key-shaped path segment makes it) or a
    dot segment: the prober asks nothing the agent's credential is in."""
    if http_origin(url) is None or _s.url_carries_credential(url):
        return None
    path = urlsplit(url.strip()).path.rstrip("/")
    parent = path.rsplit("/", 1)[0] if "/" in path else ""
    segments = parent.split("/")[1:]
    if not parent or len(parent) > SPEC_MOUNT_PATH_MAX or any(seg in ("", ".", "..") for seg in segments):
        return None
    return parent


def spec_mount_paths(plan: list[tuple[str, dict[str, Any], str]]) -> dict[str, list[str]]:
    """Each destination's mount paths (`mcp_mount_path`) from the servers
    planned on it, in plan order, at most SPEC_MOUNT_PATHS_MAX each."""
    mounts: dict[str, list[str]] = {}
    for _, spec, *_ in plan:
        origin, mount = http_origin(spec.get("url")), mcp_mount_path(spec.get("url"))
        if origin and mount and mount not in mounts.setdefault(origin, []) \
                and len(mounts[origin]) < SPEC_MOUNT_PATHS_MAX:
            mounts[origin].append(mount)
    return mounts


class _NoFollow(HTTPRedirectHandler):
    """Follows nothing: urllib then raises a 3xx as an HTTPError without
    reading its body. Left to urllib, a followed redirect's body is read in
    full first, past OPENAPI_MAX_BYTES and the element cut (rail review of
    RC-512), so `fetch_openapi_document` follows redirects itself."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_SPEC_OPENER = build_opener(_NoFollow)
# A spec path's redirects followed (Spring's /api-docs to /api-docs/, say),
# each only to the same origin: never another host, nor a scheme other than
# the one asked, ftp:// and file:// included.
SPEC_REDIRECTS_MAX = 3
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def fetch_openapi_document(
    url: str, timeout: float = OPENAPI_PATH_TIMEOUT_SECONDS
) -> tuple[int | None, bytes | None, bool]:
    """GET one spec path, without credentials: `(status, body, over_cap)`.

    `status` is None when nothing answered within `timeout` (for the whole
    request, redirects and body included, not only each read) or the
    connection failed; `body` is None for a non-2xx status. At most
    OPENAPI_MAX_BYTES of the body are kept, and `over_cap` says there was
    more. Only http and https URLs are opened (urllib would read a file://
    one). A redirect is followed here, to the same origin only and at most
    SPEC_REDIRECTS_MAX times, from its Location header alone: a 3xx's body
    is never read. Never raises.
    """
    if http_origin(url) is None:
        return None, None, False
    started = time.monotonic()
    for hop in range(SPEC_REDIRECTS_MAX + 1):
        if time.monotonic() - started > timeout:
            return None, None, False
        status, location, answer = _fetch_once(url, started, timeout)
        if location is None:
            return answer
        target = urljoin(url, location)
        if hop == SPEC_REDIRECTS_MAX or http_origin(target) is None or http_origin(target) != http_origin(url):
            return status, None, False  # not followed: no spec at this path
        url = target
    return None, None, False


def _fetch_once(url: str, started: float, timeout: float
                ) -> tuple[int | None, str | None, tuple[int | None, bytes | None, bool]]:
    """One GET of a spec path: its status, the Location of a redirect (or
    None), and `fetch_openapi_document`'s answer when it isn't one."""
    remaining = max(0.1, timeout - (time.monotonic() - started))
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with _SPEC_OPENER.open(request, timeout=remaining) as response:
            chunks: list[bytes] = []
            size = 0
            while size <= OPENAPI_MAX_BYTES:
                if time.monotonic() - started > timeout:
                    return None, None, (None, None, False)
                chunk = response.read1(min(OPENAPI_READ_CHUNK, OPENAPI_MAX_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            body, over_cap = b"".join(chunks)[:OPENAPI_MAX_BYTES], size > OPENAPI_MAX_BYTES
            # Bytes don't bound what a body parses to (rail review): one
            # past OPENAPI_MAX_ELEMENTS is cut there, and read as a spec
            # past the cap, keeping the operations that fit.
            cut = json_element_cut(body, OPENAPI_MAX_ELEMENTS)
            if cut is not None:
                body, over_cap = body[:cut], True
            return response.status, None, (response.status, body, over_cap)
    except HTTPError as exc:
        location = exc.headers.get("Location") if exc.code in REDIRECT_STATUSES and exc.headers else None
        exc.close()  # its body is never read
        return exc.code, location, (exc.code, None, False)
    except (URLError, TimeoutError, OSError, ValueError, http.client.HTTPException):
        return None, None, (None, None, False)


def _salvage_object(text: str, index: int, depth: int = 0) -> tuple[dict[str, Any], bool]:
    """The members of the JSON object starting at text[index] that decode
    whole, and whether the object closed, for a document cut at
    OPENAPI_MAX_BYTES. At the top level a `paths` member that was cut is
    salvaged the same way, one path item at a time, so a spec past the cap
    keeps the operations that fit."""
    members: dict[str, Any] = {}
    index = _JSON_SPACE.match(text, index + 1).end()
    while index < len(text):
        if text[index] == "}":
            return members, True
        try:
            key, index = _decoder().raw_decode(text, index)
        except (json.JSONDecodeError, RecursionError):
            break
        index = _JSON_SPACE.match(text, index).end()
        if not isinstance(key, str) or not text.startswith(":", index):
            break
        index = _JSON_SPACE.match(text, index + 1).end()
        try:
            value, index = _decoder().raw_decode(text, index)
        except (json.JSONDecodeError, RecursionError):
            if depth == 0 and key == "paths" and text.startswith("{", index):
                members[key] = _salvage_object(text, index, depth + 1)[0]
            break
        members[key] = value
        index = _JSON_SPACE.match(text, index).end()
        if text.startswith(",", index):
            index = _JSON_SPACE.match(text, index + 1).end()
            continue
        return members, text.startswith("}", index)
    return members, False


def parse_openapi_document(body: bytes, over_cap: bool) -> dict[str, Any] | None:
    """The spec in a spec path's body, or None when it holds none. A whole
    body must parse as an OpenAPI 3 (`openapi`) or Swagger 2 (`swagger`)
    document with `paths`. A body cut at the cap can't parse whole, so its
    top-level members that decode are kept (`_salvage_object`): any JSON
    object served at a spec path past the cap counts as a spec, since its
    version key may be past the cut too."""
    text = body.decode("utf-8", errors="replace")
    if over_cap:
        start = _JSON_SPACE.match(text).end()
        if not text.startswith("{", start):
            return None
        document, _ = _salvage_object(text, start)
        return None if _s.json_depth_exceeds(document) else document
    try:
        document = _s.strict_json_loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        return None
    if not isinstance(document.get("openapi"), str) and not isinstance(document.get("swagger"), str):
        return None
    return document


def _spec_text(value: Any) -> str | None:
    text = _s.first_nonempty(_s.redact_text(value)) if isinstance(value, str) else None
    return text[:HTTP_OPERATION_TEXT_MAX] if text else None


def _media_types(value: Any) -> list[str]:
    """Content types from an OpenAPI 3 `content` map's keys or a Swagger 2
    `consumes` or `produces` list."""
    names = value.keys() if isinstance(value, dict) else value if isinstance(value, list) else []
    return _s.dedupe([text for text in map(_spec_text, names) if text])[:HTTP_OPERATION_MEDIA_TYPES_MAX]


def openapi_operations(document: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """Each operation in a spec, as http_operations keeps it, and whether the
    list was cut at HTTP_OPERATIONS_MAX: `method`, `path`, `operationId`
    when it has one, and the request and response content types it
    declares (OpenAPI 3: requestBody's and the responses' `content`;
    Swagger 2: the operation's `consumes` and `produces`, else the
    document's). Every string goes through redact_text; nothing else of the
    spec (parameters, schemas, examples, descriptions) is kept."""
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return [], False
    swagger = isinstance(document.get("swagger"), str)
    operations: list[dict[str, Any]] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in OPENAPI_METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            if len(operations) >= HTTP_OPERATIONS_MAX:
                return operations, True
            record: dict[str, Any] = {"method": method.upper(), "path": _spec_text(path) or "/"}
            operation_id = _spec_text(operation.get("operationId"))
            if operation_id:
                record["operationId"] = operation_id
            if swagger:
                requests = _media_types(operation.get("consumes", document.get("consumes")))
                responses = _media_types(operation.get("produces", document.get("produces")))
            else:
                body = operation.get("requestBody")
                requests = _media_types(body.get("content")) if isinstance(body, dict) else []
                answers = operation.get("responses")
                responses = _s.dedupe([
                    media for answer in (answers.values() if isinstance(answers, dict) else [])
                    if isinstance(answer, dict) for media in _media_types(answer.get("content"))
                ])[:HTTP_OPERATION_MEDIA_TYPES_MAX]
            if requests:
                record["request_content_types"] = requests
            if responses:
                record["response_content_types"] = responses
            operations.append(record)
    return operations, False


def probe_openapi(destination: str, timeout: float = OPENAPI_PATH_TIMEOUT_SECONDS,
                  mount_paths: Iterable[str] = ()) -> dict[str, Any]:
    """One HTTP destination's entry in http_operations: OPENAPI_PATHS asked
    in order, without credentials, `timeout` seconds each, at the origin and
    then under each of `mount_paths` (`spec_mount_paths`: where the
    destination's MCP servers are mounted), and the first spec found kept;
    its `spec_path` is the path it was found at.

    The entry's `status` is the attribute statuses' own: ANSWERED with the
    spec's operations; PARTIAL, SIZE_CAP_EXCEEDED for a spec past
    OPENAPI_MAX_BYTES (the operations in what fits) or past
    HTTP_OPERATIONS_MAX operations; BLIND, PRIVATE_STORE when a path
    answered 401 or 403 and none served a spec (it is not public: no
    credential is ever sent); BLIND, NO_SOURCE_ACCESS when the destination
    didn't answer or answered 5xx; ABSENT when it answered and serves no
    spec at any path. A destination that is not http or https is never
    asked. Never raises."""
    origin = http_origin(destination)
    if origin is None:
        return {"destination": _s.redact_url(destination) or _s.UNPARSEABLE, "status": "BLIND",
                "reason": "NOT_COLLECTED_BY_PACK", "note": "only http and https destinations are asked"}
    # The origin as the bundle names it: through redact_text, as a server's name is.
    entry: dict[str, Any] = {"destination": _s.redact_text(origin)}
    refused: list[str] = []
    failed: list[str] = []
    mounts = [mount for mount in dict.fromkeys(mount_paths) if isinstance(mount, str) and mount.startswith("/")]
    candidates = [mount + path for mount in ["", *mounts[:SPEC_MOUNT_PATHS_MAX]] for path in OPENAPI_PATHS]
    for path in candidates:
        status, body, over_cap = fetch_openapi_document(origin + path, timeout)
        if status is None:
            failed.append(path)
            break  # nothing answered: the same host's other paths won't either
        if status in (401, 403):
            refused.append(path)
            continue
        if status >= 500:
            failed.append(path)
            continue
        if not 200 <= status < 300 or body is None:
            continue
        # One parse at a time (_JSON_PARSE_LOCK), and the document freed
        # before the next: only its operations outlive the lock.
        with _s._JSON_PARSE_LOCK:
            document = parse_openapi_document(body, over_cap)
            found = document is not None
            if found:
                operations, cut = openapi_operations(document)
                version = _spec_text(document.get("openapi")) or _spec_text(document.get("swagger"))
            del document
        if not found:
            continue
        entry.update(status="ANSWERED", spec_path=path, **({"spec_version": version} if version else {}),
                     operations=operations)
        if over_cap:
            entry.update(status="PARTIAL", reason="SIZE_CAP_EXCEEDED", operations_truncated=True,
                         note=f"the spec is larger than {OPENAPI_MAX_BYTES} bytes or "
                              f"{OPENAPI_MAX_ELEMENTS} JSON elements; only the operations in the part read are listed")
        elif cut:
            entry.update(status="PARTIAL", reason="SIZE_CAP_EXCEEDED", operations_truncated=True,
                         note=f"the spec has more than {HTTP_OPERATIONS_MAX} operations; the first are listed")
        return entry
    if refused:
        return {**entry, "status": "BLIND", "reason": "PRIVATE_STORE",
                "note": f"answered 401 or 403 without credentials at {', '.join(refused)}: not public"}
    if failed:
        return {**entry, "status": "BLIND", "reason": "NO_SOURCE_ACCESS",
                "note": f"no answer, or an error status, at {', '.join(failed)}"}
    return {**entry, "status": "ABSENT", "note": "no OpenAPI or Swagger JSON document at " + ", ".join(candidates)}


def cap_http_operations(destinations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """http_operations' destinations within HTTP_OPERATIONS_BYTES as the
    bundle renders them (`_rendered_size`): every destination entry counts,
    then each operation in order; past the budget a destination keeps the
    operations that fit, says operations_truncated, and an ANSWERED one is
    PARTIAL with SIZE_CAP_EXCEEDED."""
    used = sum(_s._rendered_size({**entry, "operations": []}, HTTP_OPERATIONS_DESTINATION_INDENT)
               for entry in destinations)
    for entry in destinations:
        operations = entry.get("operations") or []
        kept = 0
        for operation in operations:
            size = _s._rendered_size(operation, HTTP_OPERATIONS_OPERATION_INDENT)
            if used + size > HTTP_OPERATIONS_BYTES:
                break
            used += size
            kept += 1
        if kept < len(operations):
            entry["operations"] = operations[:kept]
            entry["operations_truncated"] = True
            if entry.get("status") == "ANSWERED":
                entry.update(status="PARTIAL", reason="SIZE_CAP_EXCEEDED",
                             note="operations past the bundle's budget for http_operations are left out")
    return destinations




def json_element_cut(body: bytes, limit: int) -> int | None:
    """Where `body` passes `limit` elements (json_element_count), or None
    when it doesn't: the byte offset to cut it at so what is kept parses to
    at most `limit` elements."""
    if _s.json_element_count(body) <= limit:
        return None
    seen, chunk = 0, 64 * 1024
    for start in range(0, len(body), chunk):
        part = body[start:start + chunk]
        count = _s.json_element_count(part)
        if seen + count > limit:
            for match in _JSON_STRUCTURE_RE.finditer(part):
                seen += 1
                if seen > limit:
                    return start + match.start()
        seen += count
    return len(body)


# ── the bundle attribute ────────────────────────────────────────────────────

HTTP_OPERATIONS_NO_DESTINATION = "no HTTP destination in the MCP config"
HTTP_OPERATIONS_METHOD = ("GET /openapi.json, /v3/api-docs, /swagger.json and /api-docs on each MCP server's "
                          "origin, without credentials, in pod mode")

Builder = Callable[..., dict[str, Any]]


HTTP_OPERATIONS_NO_HTTP_SERVER = ("no HTTP destination: every MCP server found is a command (stdio) server "
                                  "or carries a credential in its URL, so none has an origin to ask")


def http_operations_attribute(destinations: list[dict[str, Any]], tool_schemas: dict[str, Any],
                              builders: dict[str, Builder], servers: int = 0) -> dict[str, Any]:
    """http_operations from `probe_openapi`'s entries, one per destination
    with its own status, built with pod_mode's `builders` (answered, absent,
    blind, partial).

    The attribute's status names the worst gap, as tool_schemas' does: a
    destination that needs a credential (PRIVATE_STORE), one that did not
    answer, before the scan's deadline included (NO_SOURCE_ACCESS), a spec
    cut for size (SIZE_CAP_EXCEEDED). BLIND when no destination served a
    spec and some gap stands; PARTIAL when some served one; ABSENT when
    every destination answered without a spec.

    With no destination, `servers` (how many MCP servers the probe stage
    planned) decides. Some were found but none has an origin to ask (all
    command servers, or URLs carrying a credential): ABSENT, as "no
    destination" is established. None were found: it follows `tool_schemas`
    (the bundle's final one, after the harness reader), since the
    destinations are its servers' origins; where that is BLIND or FAILED
    with no server ("no server" wasn't established: a harness reader that
    couldn't read the MCP config, or RC-520's generic reader with none), so
    is "no destination", BLIND with its reason. Otherwise ABSENT."""
    answered, absent, blind, partial = (builders[name] for name in ("answered", "absent", "blind", "partial"))
    if not destinations:
        if servers:
            return absent(HTTP_OPERATIONS_METHOD, "declared", note=HTTP_OPERATIONS_NO_HTTP_SERVER)
        if tool_schemas.get("status") in ("BLIND", "FAILED") and not tool_schemas.get("value"):
            return blind(tool_schemas.get("reason") or "NO_SOURCE_ACCESS", "declared",
                         note="no HTTP destination, and the MCP servers they come from weren't established: "
                              + (tool_schemas.get("note") or "tool_schemas is " + tool_schemas["status"]))
        return absent(HTTP_OPERATIONS_METHOD, "declared", note=HTTP_OPERATIONS_NO_DESTINATION)

    def named(status: str, reason: str | None = None) -> list[str]:
        return [entry["destination"] for entry in destinations
                if entry.get("status") == status and (reason is None or entry.get("reason") == reason)]

    refused = named("BLIND", "PRIVATE_STORE")
    unreached = [entry["destination"] for entry in destinations
                 if entry.get("status") == "BLIND" and entry.get("reason") != "PRIVATE_STORE"]
    capped = named("PARTIAL")
    served = named("ANSWERED") + capped
    notes = []
    if refused:
        notes.append("needs a credential, not public: " + ", ".join(refused))
    if unreached:
        notes.append("no answer: " + ", ".join(unreached))
    if capped:
        notes.append("spec cut for size: " + ", ".join(capped))
    reason = ("PRIVATE_STORE" if refused else "NO_SOURCE_ACCESS" if unreached
              else "SIZE_CAP_EXCEEDED" if capped else None)
    if not served:
        if reason:
            return blind(reason, "declared", method=HTTP_OPERATIONS_METHOD, note="; ".join(notes))
        return absent(HTTP_OPERATIONS_METHOD, "declared",
                      note="no destination serves an OpenAPI or Swagger document: "
                           + ", ".join(entry["destination"] for entry in destinations))
    if reason:
        return partial(destinations, "declared", reason, authored_by="external", method=HTTP_OPERATIONS_METHOD,
                       note="; ".join(notes))
    return answered(destinations, "declared", authored_by="external", method=HTTP_OPERATIONS_METHOD,
                    note="each operation's method, path, operationId and content types as its spec declares "
                         "them; strings that look like keys are redacted")


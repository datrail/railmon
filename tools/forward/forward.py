#!/usr/bin/env python3
"""Forward RailMon RuntimeInteraction JSONL events to Rail Center."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

DEFAULT_SPOOL_DIR = Path(".rail") / "railmon" / "forward"
# Where the spool lived while this forwarder was RailScan's `rail-collector`.
# Still used when it exists and the new one does not, so events pending from
# before an upgrade are delivered instead of stranded.
LEGACY_SPOOL_DIR = Path(".datrail") / "rail-guardian" / "rail-collector"


class RailCollectorError(Exception):
    """User-correctable collector error."""


AUTH_MODES = ("none", "bearer", "gcp")
DEFAULT_METADATA_HOST = "metadata.google.internal"
# Mint again once less than this much of an identity token's life is left.
GCP_REFRESH_MARGIN_SECONDS = 300
# RFC 7230 header-value characters; anything else in a token is refused by
# offset, so the token itself never reaches a message.
_HEADER_SAFE = set(chr(c) for c in range(0x21, 0x7F))


class _NoRedirect(HTTPRedirectHandler):
    """Refuse to follow: urllib would carry `Authorization` to wherever a 3xx
    points, any host or scheme. A redirect surfaces as an HTTPError instead,
    so the event stays spooled."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = build_opener(_NoRedirect)
# The metadata server is link-local: never through an HTTP proxy, which would
# see the minted identity token in clear.
_METADATA_OPENER = build_opener(ProxyHandler({}), _NoRedirect)


def header_safe(raw: str, name: str) -> str:
    value = raw.strip()
    if not value:
        raise RailCollectorError(f"{name} is empty")
    for offset, ch in enumerate(value):
        if ch not in _HEADER_SAFE:
            raise RailCollectorError(
                f"{name} holds U+{ord(ch):04X} at offset {offset}, which cannot go in a header value"
            )
    return value


def jwt_expiry(token: str) -> int | None:
    """The `exp` claim of our own freshly minted JWT, unverified; None if unreadable."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        exp = claims.get("exp")
        return exp if isinstance(exp, int) else None
    except (IndexError, ValueError, AttributeError):
        return None


class Credential:
    """The credential RAIL_AUTH_MODE names, the same contract as the collector's (RM-F2…F5).

    - `none` (default) sends nothing; a token set beside it is refused.
    - `bearer` sends RAIL_AUTH_TOKEN, or RAIL_AUTH_TOKEN_FILE re-read on every
      forward so a rotated secret needs no restart; both set is refused.
    - `gcp` mints an identity token for RAIL_AUTH_AUDIENCE from the metadata
      server (GCE_METADATA_HOST overrides its address), held only in memory.

    A credential that cannot be produced raises; nothing is sent anonymously.
    """

    def __init__(self, env: dict | None = None):
        env = os.environ if env is None else env
        get = lambda name: (env.get(name) or "").strip()  # noqa: E731
        mode = get("RAIL_AUTH_MODE").lower()
        token, token_file = get("RAIL_AUTH_TOKEN"), get("RAIL_AUTH_TOKEN_FILE")
        token_set = "RAIL_AUTH_TOKEN" if token else "RAIL_AUTH_TOKEN_FILE" if token_file else None
        self._token = self._token_file = self._audience = None
        self._cached: tuple[str, int | None] | None = None

        if mode in ("", "none"):
            if token_set:
                configured = "none" if mode else "unset, which is none"
                raise RailCollectorError(
                    f"RAIL_AUTH_MODE is {configured} and sends no credential, but {token_set} is set; "
                    f"set RAIL_AUTH_MODE=bearer to use it, or unset {token_set} to mean none"
                )
            self.mode = "none"
        elif mode == "bearer":
            if token and token_file:
                raise RailCollectorError(
                    "RAIL_AUTH_MODE=bearer takes RAIL_AUTH_TOKEN or RAIL_AUTH_TOKEN_FILE, and both are set; unset one"
                )
            if token_file:
                self._token_file = Path(token_file)
            elif token:
                self._token = header_safe(token, "RAIL_AUTH_TOKEN")
            else:
                raise RailCollectorError("RAIL_AUTH_MODE=bearer requires RAIL_AUTH_TOKEN or RAIL_AUTH_TOKEN_FILE")
            self.mode = "bearer"
        elif mode == "gcp":
            if token_set:
                raise RailCollectorError(
                    f"RAIL_AUTH_MODE=gcp mints its own credential, but {token_set} is set; "
                    "unset it, or set RAIL_AUTH_MODE=bearer to use it"
                )
            self._audience = get("RAIL_AUTH_AUDIENCE")
            if not self._audience:
                raise RailCollectorError("RAIL_AUTH_MODE=gcp requires RAIL_AUTH_AUDIENCE")
            self._metadata_host = get("GCE_METADATA_HOST") or DEFAULT_METADATA_HOST
            self.mode = "gcp"
        else:
            raise RailCollectorError(f"RAIL_AUTH_MODE must be one of {', '.join(AUTH_MODES)}, got: {mode}")

    def headers(self, timeout: float = 10.0) -> dict[str, str]:
        if self.mode == "none":
            return {}
        if self._token_file is not None:
            try:
                raw = self._token_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise RailCollectorError(
                    f"reading RAIL_AUTH_TOKEN_FILE {self._token_file}: {exc.__class__.__name__}"
                ) from None
            return {"Authorization": f"Bearer {header_safe(raw, 'RAIL_AUTH_TOKEN_FILE')}"}
        if self._token is not None:
            return {"Authorization": f"Bearer {self._token}"}
        return {"Authorization": f"Bearer {self._gcp_token(timeout)}"}

    def _gcp_token(self, timeout: float) -> str:
        if self._cached is not None:
            token, exp = self._cached
            if exp is not None and time.time() + GCP_REFRESH_MARGIN_SECONDS < exp:
                return token
        url = (
            f"http://{self._metadata_host}/computeMetadata/v1/instance/service-accounts/default/identity?"
            + urlencode({"audience": self._audience})
        )
        request = Request(url, headers={"Metadata-Flavor": "Google"})
        try:
            with _METADATA_OPENER.open(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            raise RailCollectorError(
                f"RAIL_AUTH_MODE=gcp: the metadata server at {self._metadata_host} returned {exc.code} "
                "for an identity token"
            ) from None
        except (URLError, OSError) as exc:
            raise RailCollectorError(
                f"RAIL_AUTH_MODE=gcp: minting an identity token from the metadata server at "
                f"{self._metadata_host}: {exc}"
            ) from None
        token = header_safe(body, "the metadata server's identity token")
        exp = jwt_expiry(token)
        self._cached = (token, exp) if exp is not None else None
        return token


def canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def event_key(event: dict) -> str:
    interaction_id = event.get("interaction_id")
    if isinstance(interaction_id, str) and interaction_id.strip():
        return interaction_id.strip()
    return hashlib.sha256(canonical_json(event).encode("utf-8")).hexdigest()


def safe_filename(key: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in key)
    return f"{safe[:120]}.json"


def validate_event(event: object) -> dict:
    if not isinstance(event, dict):
        raise RailCollectorError("event must be a JSON object")

    missing = [field for field in ("interaction_id", "timestamp", "request", "response") if field not in event]
    if missing:
        raise RailCollectorError(f"event missing required fields: {', '.join(missing)}")

    request = event.get("request")
    if not isinstance(request, dict):
        raise RailCollectorError("event.request must be an object")
    for field in ("method", "path", "destination"):
        if not request.get(field):
            raise RailCollectorError(f"event.request.{field} is required")

    response = event.get("response")
    if not isinstance(response, dict):
        raise RailCollectorError("event.response must be an object")

    return event


def spool_event(event: dict, pending_dir: Path) -> Path:
    pending_dir.mkdir(parents=True, exist_ok=True)
    path = pending_dir / safe_filename(event_key(event))
    if path.exists():
        return path

    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(canonical_json(event) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def load_spooled_event(path: Path) -> dict:
    try:
        return validate_event(json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        raise RailCollectorError(f"{path}: invalid JSON: {exc}") from exc


def post_event(
    center_url: str, event: dict, timeout: float, auth_headers: dict[str, str] | None = None
) -> tuple[bool, int | None, str]:
    url = f"{center_url.rstrip('/')}/v1/interactions"
    data = canonical_json(event).encode("utf-8")
    request = Request(url, data=data, headers={"Content-Type": "application/json", **(auth_headers or {})})
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            return 200 <= response.status < 300, response.status, body
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return False, exc.code, body
    except (URLError, OSError) as exc:
        return False, None, str(exc)


def drain_pending(
    pending_dir: Path,
    sent_dir: Path,
    center_url: str,
    timeout: float,
    keep_sent: bool,
    credential: Credential | None = None,
) -> tuple[int, int]:
    sent = 0
    failed = 0
    if not pending_dir.exists():
        return sent, failed

    paths = sorted(pending_dir.glob("*.json"))
    if not paths:
        return sent, failed
    try:
        auth_headers = credential.headers(timeout) if credential else {}
    except RailCollectorError as exc:
        # Left in the spool for the next drain, never sent anonymously.
        print(
            f"[rail-collector] RAIL_AUTH_MODE={credential.mode} could not produce a credential; "
            f"{len(paths)} event(s) stay spooled: {exc}",
            file=sys.stderr,
        )
        return sent, len(paths)

    for path in paths:
        try:
            event = load_spooled_event(path)
        except RailCollectorError as exc:
            failed += 1
            print(f"[rail-collector] skip invalid spool file: {exc}", file=sys.stderr)
            continue

        ok, status, body = post_event(center_url, event, timeout, auth_headers)
        if ok:
            sent += 1
            if keep_sent:
                sent_dir.mkdir(parents=True, exist_ok=True)
                shutil.move(str(path), sent_dir / path.name)
            else:
                path.unlink(missing_ok=True)
            print(
                f"[rail-collector] forwarded {event.get('interaction_id')} status={status}",
                file=sys.stderr,
            )
        else:
            failed += 1
            print(
                f"[rail-collector] forward failed {path.name} status={status} error={body[:240]}",
                file=sys.stderr,
            )
    return sent, failed


def read_jsonl(path: str, follow: bool, poll_interval: float):
    if path == "-":
        for line in sys.stdin:
            yield line
        return

    input_path = Path(path)
    while True:
        if input_path.exists():
            break
        if not follow:
            raise RailCollectorError(f"input file does not exist: {input_path}")
        time.sleep(poll_interval)

    with input_path.open("r", encoding="utf-8") as handle:
        while True:
            line = handle.readline()
            if line:
                yield line
                continue
            if not follow:
                break
            time.sleep(poll_interval)


def default_spool_dir() -> Path:
    if not DEFAULT_SPOOL_DIR.exists() and LEGACY_SPOOL_DIR.exists():
        print(
            f"[rail-collector] using legacy spool {LEGACY_SPOOL_DIR}; it is deprecated, "
            f"move it to {DEFAULT_SPOOL_DIR} or pass --spool-dir",
            file=sys.stderr,
        )
        return LEGACY_SPOOL_DIR
    return DEFAULT_SPOOL_DIR


def process_input(args: argparse.Namespace) -> int:
    center_url = args.center_url or os.getenv("RAIL_CENTER_URL")
    if not center_url:
        raise RailCollectorError("--center-url or RAIL_CENTER_URL is required")

    # Checked, and a first credential produced, before anything is read: a
    # forwarder that cannot authenticate stops here (RM-F2).
    credential = Credential()
    credential.headers(args.post_timeout)

    spool_dir = Path(args.spool_dir) if args.spool_dir else default_spool_dir()
    pending_dir = spool_dir / "pending"
    sent_dir = spool_dir / "sent"

    sent, failed = drain_pending(pending_dir, sent_dir, center_url, args.post_timeout, args.keep_sent, credential)
    if sent or failed:
        print(f"[rail-collector] startup drain sent={sent} failed={failed}", file=sys.stderr)

    if args.drain_only:
        return 0 if failed == 0 else 1

    queued = 0
    last_flush = time.time()
    for line_number, line in enumerate(read_jsonl(args.input, args.follow, args.poll_interval), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = validate_event(json.loads(stripped))
        except (json.JSONDecodeError, RailCollectorError) as exc:
            print(f"[rail-collector] skip line {line_number}: {exc}", file=sys.stderr)
            continue

        path = spool_event(event, pending_dir)
        queued += 1
        print(f"[rail-collector] queued {event.get('interaction_id')} spool={path}", file=sys.stderr)

        now = time.time()
        if queued >= args.flush_count or (now - last_flush) >= args.flush_interval:
            drain_pending(pending_dir, sent_dir, center_url, args.post_timeout, args.keep_sent, credential)
            queued = 0
            last_flush = now

    _, final_failed = drain_pending(
        pending_dir, sent_dir, center_url, args.post_timeout, args.keep_sent, credential
    )
    return 0 if final_failed == 0 else 1


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="railmon forward: send RailMon RuntimeInteraction JSONL to Rail Center."
    )
    parser.add_argument(
        "--input",
        default="-",
        help="Input JSONL file from RailMon, or '-' for stdin. Defaults to stdin.",
    )
    parser.add_argument(
        "--center-url",
        default=None,
        help="Rail Center base URL. Defaults to RAIL_CENTER_URL.",
    )
    parser.add_argument(
        "--spool-dir",
        default=None,
        help=f"Durable spool directory. Defaults to {DEFAULT_SPOOL_DIR} "
        f"({LEGACY_SPOOL_DIR} if only that one exists).",
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help="Keep reading the input file as RailMon appends new JSONL events.",
    )
    parser.add_argument(
        "--drain-only",
        action="store_true",
        help="Only resend pending spooled events, then exit.",
    )
    parser.add_argument(
        "--keep-sent",
        action="store_true",
        help="Move delivered events to spool/sent instead of deleting them.",
    )
    parser.add_argument("--flush-count", type=int, default=1, help="Forward after this many queued events.")
    parser.add_argument("--flush-interval", type=float, default=1.0, help="Max seconds between forward attempts.")
    parser.add_argument("--poll-interval", type=float, default=0.5, help="Seconds between follow-mode polls.")
    parser.add_argument("--post-timeout", type=float, default=10.0, help="Rail Center POST timeout in seconds.")
    return parser


def main() -> int:
    args = make_parser().parse_args()
    started_at = datetime.now(timezone.utc).isoformat()
    print(f"[rail-collector] started_at={started_at}", file=sys.stderr)
    try:
        return process_input(args)
    except RailCollectorError as exc:
        print(f"rail-collector: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

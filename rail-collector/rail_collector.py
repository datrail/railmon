#!/usr/bin/env python3
"""Forward RailMon RuntimeInteraction JSONL events to Rail Center."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_SPOOL_DIR = Path(".datrail") / "rail-guardian" / "rail-collector"


class RailCollectorError(Exception):
    """User-correctable collector error."""


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


def post_event(center_url: str, event: dict, timeout: float) -> tuple[bool, int | None, str]:
    url = f"{center_url.rstrip('/')}/v1/interactions"
    data = canonical_json(event).encode("utf-8")
    request = Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
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
) -> tuple[int, int]:
    sent = 0
    failed = 0
    if not pending_dir.exists():
        return sent, failed

    for path in sorted(pending_dir.glob("*.json")):
        try:
            event = load_spooled_event(path)
        except RailCollectorError as exc:
            failed += 1
            print(f"[rail-collector] skip invalid spool file: {exc}", file=sys.stderr)
            continue

        ok, status, body = post_event(center_url, event, timeout)
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


def process_input(args: argparse.Namespace) -> int:
    center_url = args.center_url or os.getenv("RAIL_CENTER_URL")
    if not center_url:
        raise RailCollectorError("--center-url or RAIL_CENTER_URL is required")

    spool_dir = Path(args.spool_dir)
    pending_dir = spool_dir / "pending"
    sent_dir = spool_dir / "sent"

    sent, failed = drain_pending(pending_dir, sent_dir, center_url, args.post_timeout, args.keep_sent)
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
            drain_pending(pending_dir, sent_dir, center_url, args.post_timeout, args.keep_sent)
            queued = 0
            last_flush = now

    _, final_failed = drain_pending(pending_dir, sent_dir, center_url, args.post_timeout, args.keep_sent)
    return 0 if final_failed == 0 else 1


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RailCollector: forward RailMon RuntimeInteraction JSONL to Rail Center."
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
        default=str(DEFAULT_SPOOL_DIR),
        help=f"Durable spool directory. Defaults to {DEFAULT_SPOOL_DIR}.",
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

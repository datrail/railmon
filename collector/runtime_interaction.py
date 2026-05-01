#!/usr/bin/env python3
"""Rail Center RuntimeInteraction formatter for RailMon HTTP captures."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import urlsplit


def to_runtime_interaction(
    interaction: dict,
    *,
    session_id: str | None = None,
    capture_start: str | None = None,
    capture_source: str = "railmon",
) -> dict:
    """Convert RailMon's legacy HTTP interaction dict to Rail Center schema."""
    request = interaction.get("request") if isinstance(interaction.get("request"), dict) else {}
    response = interaction.get("response") if isinstance(interaction.get("response"), dict) else {}

    method = str(request.get("method") or "").upper() or "UNKNOWN"
    path, destination = _path_and_destination(request)
    x_rail_header = _header(request, "x-rail")
    agent_id = _agent_id_from_x_rail(x_rail_header)
    status = response.get("status_code")

    raw = deepcopy(interaction)
    raw["railmon_session_id"] = session_id
    raw["railmon_capture_start"] = capture_start

    return {
        "interaction_id": _interaction_id(
            interaction,
            session_id=session_id,
            method=method,
            path=path,
            destination=destination,
            status=status,
        ),
        "agent_id": agent_id,
        "x_rail_header": x_rail_header,
        "timestamp": _timestamp(interaction),
        "request": {
            "method": method,
            "path": path,
            "destination": destination,
        },
        "response": {
            "status": _status_code(status),
        },
        "latency_ms": _latency_ms(interaction.get("latency_ms")),
        "capture_source": capture_source,
        "raw": raw,
    }


def _path_and_destination(request: dict) -> tuple[str, str]:
    raw_path = str(request.get("path") or "/")
    parsed = urlsplit(raw_path)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path, parsed.netloc

    destination = _header(request, "host") or _header(request, ":authority") or "unknown"
    return raw_path, destination


def _header(request: dict, name: str) -> str | None:
    headers = request.get("headers")
    if not isinstance(headers, dict):
        return None
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted and value not in (None, ""):
            return str(value)
    return None


def _agent_id_from_x_rail(x_rail_header: str | None) -> str | None:
    if not x_rail_header:
        return None

    token = x_rail_header.strip()
    if not token:
        return None

    try:
        padded = token + "=" * (-len(token) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        candidate = payload.get("agent_id")
        if candidate:
            return str(uuid.UUID(str(candidate)))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return None
    return None


def _interaction_id(
    interaction: dict,
    *,
    session_id: str | None,
    method: str,
    path: str,
    destination: str,
    status: object,
) -> str:
    seed = {
        "session_id": session_id,
        "timestamp_ns": interaction.get("timestamp_ns"),
        "timestamp": interaction.get("timestamp"),
        "pid": interaction.get("pid"),
        "tid": interaction.get("tid"),
        "method": method,
        "path": path,
        "destination": destination,
        "status": status,
        "request_size": interaction.get("request_size"),
        "response_size": interaction.get("response_size"),
    }
    encoded = json.dumps(seed, sort_keys=True, separators=(",", ":"), default=str).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    return f"railmon-{digest[:40]}"


def _timestamp(interaction: dict) -> str:
    timestamp = interaction.get("timestamp")
    if isinstance(timestamp, str) and timestamp:
        return timestamp
    return datetime.now(timezone.utc).isoformat()


def _status_code(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _latency_ms(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

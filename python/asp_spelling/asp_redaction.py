"""The rule RailMon redacts a URL by, for every consumer that matches on one.

RailMon never records a URL as it was written: a gateway's key often rides in
the path, the query, the userinfo or the fragment. What a bundle carries is
`redact_url`'s result, so any consumer that matches a URL it sees elsewhere (a
call the proxy forwards, Rail Center's capture plan) against one from a bundle
has to redact its own side by the same rule first. This module is that rule;
import it rather than re-implementing it, so the two sides can't drift.

- `redact_url(url)`: scheme, host, port and a path shape, with userinfo and
  fragment dropped, a query replaced by `REDACTED_QUERY`, every path segment
  that could be a key replaced by `REDACTED_SEGMENT`, and `UNPARSEABLE` for a
  URL with no scheme or host or one `urllib` refuses to parse.
- `redact_path_segment(segment)`: one path segment by the same rule.
- `is_secret_token(value)` / `looks_like_secret_segment(segment)`: the key
  tests behind it, over `SECRET_TOKEN_RES`.

The markers can't arise any other way: a kept segment's `[` and `]` are
percent-encoded, so a consumer can match on the redacted form, path markers
included, and know a marker means something was taken out there.

It uses only the standard library. RailMon's scanner imports it from here.

**Versioning.** `REDACTION_VERSION` moves only with RailMon's
`rule_pack_version`: any change to this rule changes what a bundle carries, so
it is a rule-pack bump on RailMon's side, never a silent one.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

__all__ = [
    "REDACTED_QUERY",
    "REDACTED_SEGMENT",
    "REDACTION_VERSION",
    "SECRET_TOKEN_RES",
    "UNPARSEABLE",
    "is_secret_token",
    "looks_like_secret_segment",
    "redact_path_segment",
    "redact_url",
]

#: Moves with every change to the rule, and only with a RailMon
#: `rule_pack_version` bump. Version 1 is the rule as RailMon applied it at rule
#: pack 15, when it moved here.
REDACTION_VERSION = 1

# Credentials in the shapes their vendors actually issue. Length alone cannot
# catch these — `sk-live-abc12` is thirteen characters and still opens the
# account — but a bare prefix cannot be used either: `asia`, `akia` and `aiza`
# are the leading letters of AWS and Google keys *and* of ordinary words, so
# prefix matching would silently delete a skill named `asian-markets` and a host
# called `aizawa-metrics.internal`. Each entry therefore carries the length and
# character shape that distinguishes the key from the word.
SECRET_TOKEN_RES = (
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),  # OpenAI, Anthropic, and lookalikes
    re.compile(r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"),  # Stripe
    re.compile(r"gh[pousr]_[A-Za-z0-9]{12,}"),  # GitHub
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{6,}"),  # GitLab
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack
    re.compile(r"xapp-[0-9]-[A-Za-z0-9-]{10,}"),
    re.compile(r"npm_[A-Za-z0-9]{30,}"),
    re.compile(r"shpat_[a-f0-9]{20,}"),  # Shopify
    re.compile(r"hf_[A-Za-z0-9]{30,}"),  # Hugging Face
    re.compile(r"dop_v1_[a-f0-9]{32,}"),  # DigitalOcean
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),  # Google API key
    re.compile(r"ya29\.[A-Za-z0-9_-]{20,}"),  # Google OAuth
    re.compile(r"A(?:KIA|SIA)[0-9A-Z]{16}"),  # AWS access key id
)

# What a redacted path segment reads as. A consumer matching paths (Rail
# Center's capture plan, the proxy) matches on the redacted path, marker
# included, so the marker must not arise any other way: `[` and `]` are not
# legal in a path (RFC 3986 gen-delims), and a kept segment that has them
# anyway is percent-encoded below.
REDACTED_SEGMENT = "[redacted]"

# What a URL's query reads as, appended to the path: the query is dropped whole
# rather than trusted to look harmless.
REDACTED_QUERY = "?[redacted]"

# A URL with no scheme or host, or one urlsplit refuses to parse.
UNPARSEABLE = "[unparseable]"


def redact_url(url: str | None) -> str | None:
    """A URL with everything that could be a credential removed.

    Gateways routinely carry the key in the URL — `https://host/mcp/sk-live-…/sse`
    or `?api_key=…` or `https://user:pass@host` or `#access_token=…` — so
    recording a base_url or an MCP endpoint verbatim would put a live secret in a
    file whose whole premise is that it holds none. Scheme, host and a path shape
    are what the scorer needs; userinfo, query and fragment are dropped whole
    rather than trusted to look harmless.

    Idempotent: re-redacting an already-redacted URL returns it unchanged, so a
    value can pass through more than one collector safely.
    """
    if not url:
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        # A netloc urlsplit refuses to parse — an unbracketed IPv6 literal is the
        # usual one. Nothing here can be reported as a host without guessing.
        return UNPARSEABLE
    if not parts.scheme or not host:
        return UNPARSEABLE
    # Re-bracketed, so the result parses back the same way. Emitting a bare
    # `::1:8080` would make this function crash on its own output.
    netloc = (f"[{host}]" if ":" in host else host) + (f":{port}" if port else "")
    segments = [segment for segment in parts.path.split("/") if segment]
    path = "/".join(redact_path_segment(segment) for segment in segments)
    suffix = REDACTED_QUERY if parts.query else ""
    return f"{parts.scheme}://{netloc}" + (f"/{path}" if path else "") + suffix


def redact_path_segment(segment: str) -> str:
    """One path segment: the marker if it could be a key, else as written.

    A segment that already is the marker stays the marker, and any other
    `[`/`]` is percent-encoded, so the marker in a redacted URL always means
    "something was taken out here". The key test reads the segment with
    those encodings undone: encoding grows a bracket to three characters,
    and testing the encoded form would let a second pass (pod mode redacts a
    harness URL, then the inventory redacts it again) push a 16-19
    character segment past the length bound and redact what the first pass
    kept.
    """
    raw = re.sub("%5[bB]", "[", re.sub("%5[dD]", "]", segment))
    if raw == REDACTED_SEGMENT or looks_like_secret_segment(raw):
        return REDACTED_SEGMENT
    return raw.replace("[", "%5B").replace("]", "%5D")


def is_secret_token(value: str) -> bool:
    """Whether the whole value is a credential in a shape some vendor issues."""
    return any(pattern.fullmatch(value) for pattern in SECRET_TOKEN_RES)


def looks_like_secret_segment(segment: str) -> bool:
    """A path segment that could be a key rather than a route.

    Deliberately over-inclusive. The earlier shape test — long, no character
    outside `[A-Za-z0-9._~-]`, at least one digit — let two whole families
    through: base64 keys, whose `+` and `/` and `=` fail the character class, and
    all-alphabetic keys, which carry no digit. Redacting a long route segment
    costs a scorer a path component; keeping one live key costs the file its
    entire premise, so length alone is now enough, and a recognised vendor shape
    redacts a short one.
    """
    return is_secret_token(segment) or len(segment) >= 20

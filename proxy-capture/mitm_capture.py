"""
mitmproxy addon for capturing Apple App Store auth/buy/download flows.

Run with:
  mitmweb --listen-host 0.0.0.0 --listen-port 8080 \
          --set web_open_browser=true \
          -s mitm_capture.py \
          --save-stream-file flows.mitm

What it does:
  - Only logs flows whose hostname matches an Apple endpoint we care about.
  - Dumps each request/response as one JSON line to capture.jsonl in CWD.
  - Pretty-prints a short summary to the terminal for live monitoring.

Filters out:
  - Metric/telemetry endpoints (xp.apple.com, metrics.apple.com, etc).
  - CDN binary fetches by default (logged as URL+size only, not full body).
  - Bag / image / artwork URLs.
"""
from __future__ import annotations
import base64
import json
import os
import re
import time
import urllib.parse
from typing import Any

from mitmproxy import ctx, http

OUTPUT = "capture.jsonl"

# Hostnames we want flows from. Anything else is dropped silently.
ALLOW_HOSTS = (
    "gsa.apple.com",
    "buy.itunes.apple.com",
    "auth.itunes.apple.com",
    "init.itunes.apple.com",
    "p2-buy.itunes.apple.com", "p29-buy.itunes.apple.com",
    # Catch any pNN-buy.itunes.apple.com variant
)
ALLOW_HOST_REGEX = re.compile(r"^p\d+-buy\.itunes\.apple\.com$")

# Hosts we'll log as URL-only (don't capture full body — they're either huge
# binaries or pure telemetry that would just bloat the dump).
SKIP_BODY_HOSTS = (
    "phobos.apple.com",
    "phobos.itunes.apple.com",
    "iosapps.itunes.apple.com",
    "mzstatic.com",
)
SKIP_BODY_HOST_REGEX = re.compile(r"(?:^|\.)(phobos|mzstatic|cdn-apple|aaplimg)\.")

START = time.time()
_seen = 0


def _host_allowed(host: str) -> bool:
    if host in ALLOW_HOSTS:
        return True
    if ALLOW_HOST_REGEX.match(host):
        return True
    if any(h in host for h in SKIP_BODY_HOSTS):
        return True
    if SKIP_BODY_HOST_REGEX.search(host):
        return True
    return False


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _maybe_text(b: bytes, max_len: int = 32_000) -> dict:
    """Return a JSON-friendly representation of a bytes payload."""
    if not b:
        return {"len": 0, "text": ""}
    try:
        s = b.decode("utf-8")
        if len(s) > max_len:
            return {"len": len(b), "text": s[:max_len], "truncated": True}
        return {"len": len(b), "text": s}
    except UnicodeDecodeError:
        if len(b) > max_len:
            return {"len": len(b), "b64": _b64(b[:max_len]), "truncated": True}
        return {"len": len(b), "b64": _b64(b)}


def _normalize_headers(headers) -> list[tuple[str, str]]:
    # Preserve order and duplicates.
    return [(k, v) for k, v in headers.items(multi=True)]


def _is_body_skip(host: str) -> bool:
    if any(h in host for h in SKIP_BODY_HOSTS):
        return True
    if SKIP_BODY_HOST_REGEX.search(host):
        return True
    return False


def response(flow: http.HTTPFlow) -> None:
    global _seen
    host = flow.request.pretty_host
    if not _host_allowed(host):
        return

    _seen += 1
    elapsed = time.time() - START
    skip_body = _is_body_skip(host)

    req = flow.request
    res = flow.response

    record: dict[str, Any] = {
        "n":         _seen,
        "t":         round(elapsed, 3),
        "method":    req.method,
        "scheme":    req.scheme,
        "host":      host,
        "port":      req.port,
        "path":      req.path,
        "url":       req.pretty_url,
        "req_headers": _normalize_headers(req.headers),
        "req_body":  None if skip_body else _maybe_text(req.raw_content or b""),
        "status":    res.status_code if res else None,
        "res_headers": _normalize_headers(res.headers) if res else [],
        "res_body":  None if skip_body else (_maybe_text(res.raw_content or b"") if res else None),
        "res_set_cookies": [
            v for k, v in res.headers.items(multi=True) if k.lower() == "set-cookie"
        ] if res else [],
    }
    if skip_body:
        record["note"] = "body skipped (CDN/binary host)"
        record["res_content_length"] = res.headers.get("Content-Length", "?") if res else "?"

    # Append a JSONL record next to flows.mitm.
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT)
    with open(out_path, "a") as f:
        f.write(json.dumps(record, default=str) + "\n")

    # Live log
    short_path = req.path
    if len(short_path) > 80:
        short_path = short_path[:77] + "..."
    ctx.log.info(
        f"[{_seen:>3}] {req.method:6} {res.status_code if res else '---':>3}  "
        f"{host}{short_path}"
    )


def load(loader):
    # Truncate the output file at start of a new mitmproxy run so each session
    # writes a fresh log. Saves you from confusion later.
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT)
    if os.path.exists(out_path):
        backup = out_path + ".prev"
        try:
            os.rename(out_path, backup)
            ctx.log.info(f"previous capture moved to {backup}")
        except OSError:
            pass
    ctx.log.info(f"appstore capture addon active — writing to {out_path}")

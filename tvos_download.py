#!/usr/bin/env python3
"""
tvOS App Store download — Python prototype.

Goal: prove an end-to-end "encrypted tvOS .ipa on disk" flow using
GSA SRP-6a + 2FA + MZBuy.woa wosid session. Once this works, port to Go.

Pipeline:
  1. Look up app (iTunes Search, entity=tvSoftware) → adamId, bundleId, name, version.
  2. Fetch anisette headers from local server (default http://localhost:6969).
  3. GSA SRP-6a init/complete against gsa.apple.com (User-Agent: Xcode).
  4. Decrypt SPD → DsPrsId, GsIdmsToken, adsid, Status.au.
  5. If 2FA needed → trigger trusted-device push, prompt for code, submit via
     /grandslam/GsService2/validate. Tries BOTH DsPrsId: and adsid: identity
     tokens (current POC only tries adsid which yields ec=-22410).
  6. POST GsIdToken to MZBuy.woa/wa/signIn → wosid cookie.
  7. POST volumeStoreDownloadProduct with deviceClass=AppleTV + storefront -6
     → grab the songList[0].URL.
  8. Stream CDN URL to <bundleId>_<version>_tvOS.ipa.

Usage:
  python3 tvos_download.py <bundle-id|adam-id> [--ext-ver-id N]

Reads creds from ./config.py (gitignored) if present, else prompts.
"""

from __future__ import annotations
import argparse
import base64
import getpass
import hashlib
import http.cookiejar
import json
import locale
import os
import plistlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

# Use pysrp (Tom Cocagne) — same library proven to work in auth/gsa_xcode.py.
# Apple's GSA mode: rfc5054_enable() + no_username_in_x() + SHA256 + NG_2048.
# IMPORTANT: do NOT shadow the `srp` package with a local srp.py.
import srp._pysrp as pysrp  # noqa: E402
pysrp.rfc5054_enable()
pysrp.no_username_in_x()

from cryptography.hazmat.primitives import padding as crypto_padding  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

# ─── Constants ────────────────────────────────────────────────────────────────

ANISETTE_URL_DEFAULT = "http://localhost:6969"

GSA_URL         = "https://gsa.apple.com/grandslam/GsService2"
GSA_VALIDATE    = "https://gsa.apple.com/grandslam/GsService2/validate"
GSA_TRUSTED_DEV = "https://gsa.apple.com/auth/verify/trusteddevice"

# gsa.apple.com only accepts the Xcode UA; akd/1.0 gets 503.
GSA_USER_AGENT  = "Xcode"
GSA_CLIENT_INFO = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"

# Consumer store domain. volumeStoreDownloadProduct lives on MZFinance.woa
# (matches ipatool and the existing Go consumerDownload path). MZBuy was a
# wrong guess — it returns 404. There is no separate /signIn step for the
# GSA path; the validated X-Apple-Identity-Token IS the credential.
STORE_DOMAIN     = "buy.itunes.apple.com"
MZFINANCE_DL     = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct"
MZFINANCE_BUY    = "/WebObjects/MZFinance.woa/wa/buyProduct"

SESSION_FILE     = "/tmp/tvos_session.json"
SPD_FILE         = "/tmp/tvos_spd.json"
MZFIN_DEFAULT    = "/tmp/mzfinance_result.json"   # output of auth/mzfinance_auth.py
APPLETV_SESSION  = "/tmp/appletv_session.json"    # tvOS-stamped Configurator session

APPLETV_UA       = "iTunes-AppleTV/12.7.0 (4; 32GB; dt:174) AppleWebKit/9537.53.11.21"

# Country → leading storefront-id digits. App Store storefront strings look like
# "143441-6,32" where 143441 is the region (US here), 6 is platform (6=tvOS,
# 2=iOS), 32 is a version-ish suffix. We need the region prefix to match the
# Apple ID's account region; the platform digit is what selects iOS vs tvOS.
STOREFRONT_ID = {
    "us": "143441",
    "gb": "143444",
    "gr": "143448",
    "fr": "143442",
    "de": "143443",
    "ca": "143455",
    "au": "143460",
    "jp": "143462",
    "it": "143450",
    "es": "143454",
}

# ─── Logging ──────────────────────────────────────────────────────────────────

def info(msg: str)  -> None: print(f"[*] {msg}")
def ok(msg: str)    -> None: print(f"[+] {msg}")
def warn(msg: str)  -> None: print(f"[!] {msg}")
def fail(msg: str)  -> None: print(f"[x] {msg}");

def hexdump(label, b, n=16):
    if isinstance(b, str):
        s = b
    elif isinstance(b, bytes):
        s = b[:n].hex() + ("…" if len(b) > n else "")
    else:
        s = repr(b)
    print(f"    {label}: {s}")

# ─── Config ───────────────────────────────────────────────────────────────────

def load_config():
    """email/password from ./config.py if present, else prompt."""
    cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.py")
    if os.path.exists(cfg_path):
        ns = {}
        with open(cfg_path) as f:
            exec(f.read(), ns)
        return ns.get("EMAIL", "").strip(), ns.get("PASSWORD", "").strip()
    email = input("Apple ID email: ").strip()
    password = getpass.getpass("Apple ID password: ")
    return email, password

# ─── Anisette ─────────────────────────────────────────────────────────────────

class AnisetteSession:
    """
    Holds the anisette identity headers fetched once at session start. Apple's
    GSA validate endpoint binds the SRP session to the X-Mme-Device-Id /
    X-Apple-I-MD-LU headers seen during /init, so we must keep them stable
    across init → complete → validate. The X-Apple-I-MD/MD-M/Client-Time OTPs
    are refreshed per-call (they're time-bound).
    """
    def __init__(self, base_url=ANISETTE_URL_DEFAULT):
        self.base_url = base_url.rstrip("/")
        self._first = None  # bound identity (Device-Id, MD-LU, SRL-NO, Client-Info)

    def _fetch_raw(self):
        with urllib.request.urlopen(self.base_url, timeout=10) as r:
            return json.loads(r.read())

    def headers(self, otp_only: bool = False) -> dict:
        raw = self._fetch_raw()
        if self._first is None:
            self._first = {
                k: raw.get(k, "") for k in (
                    "X-Mme-Device-Id",
                    "X-Apple-I-MD-LU",
                    "X-Apple-I-SRL-NO",
                    "X-MMe-Client-Info",
                )
            }
        # OTP fields refresh every call.
        out = {
            "X-Apple-I-MD":         raw.get("X-Apple-I-MD", ""),
            "X-Apple-I-MD-M":       raw.get("X-Apple-I-MD-M", ""),
            "X-Apple-I-MD-RINFO":   raw.get("X-Apple-I-MD-RINFO", "17106176"),
            "X-Apple-I-Client-Time":raw.get("X-Apple-I-Client-Time", ""),
            "X-Apple-I-TimeZone":   raw.get("X-Apple-I-TimeZone", "UTC"),
            "X-Apple-Locale":       raw.get("X-Apple-Locale", "en_US"),
        }
        if not otp_only:
            out.update(self._first)
        return out

# ─── App lookup ───────────────────────────────────────────────────────────────

def lookup_app(query: str, country: str = "us") -> dict:
    """
    iTunes Search for entity=tvSoftware. `query` is a bundleId (preferred) or
    numeric adam id (will try Lookup API directly).
    """
    if query.isdigit():
        url = (
            f"https://itunes.apple.com/lookup?id={query}"
            f"&country={country}&entity=tvSoftware&limit=1"
        )
    else:
        url = (
            f"https://itunes.apple.com/lookup?bundleId={urllib.parse.quote(query)}"
            f"&country={country}&entity=tvSoftware&limit=1"
        )
    req = urllib.request.Request(url, headers={"User-Agent": "iTunes/12.12.4 (Macintosh; OS X 10.15.7)"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.loads(r.read())
    results = data.get("results", [])
    if not results:
        raise SystemExit(f"lookup_app: no tvSoftware result for {query!r} in country={country}")
    a = results[0]
    return {
        "adamId":   str(a["trackId"]),
        "bundleId": a.get("bundleId", ""),
        "name":     a.get("trackName", ""),
        "version":  a.get("version", ""),
        "kind":     a.get("kind", ""),
        "country":  country,
    }

# ─── SRP helpers ──────────────────────────────────────────────────────────────

def derive_password(password: str, protocol: str, salt: bytes, iterations: int) -> bytes:
    """Apple s2k / s2k_fo PBKDF2 password derivation."""
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, 32)

def hmac_key(usr_K: bytes, name: str) -> bytes:
    import hmac
    return hmac.new(usr_K, name.encode(), hashlib.sha256).digest()

def decrypt_spd(K: bytes, ciphertext: bytes) -> dict:
    key = hmac_key(K, "extra data key:")
    iv  = hmac_key(K, "extra data iv:")[:16]

    print(f"    [dbg] K        = {K.hex()[:32]}…  len={len(K)}")
    print(f"    [dbg] aes-key  = {key.hex()[:32]}…  len={len(key)}")
    print(f"    [dbg] aes-iv   = {iv.hex()}")
    print(f"    [dbg] ct       = len={len(ciphertext)} first16={ciphertext[:16].hex()}")

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    pt        = decryptor.update(ciphertext) + decryptor.finalize()

    print(f"    [dbg] pt raw   = len={len(pt)} last16={pt[-16:].hex()}")
    print(f"    [dbg] pt head  = {pt[:64]!r}")

    # Try gsa_xcode.py's loose strip (chop pad_byte bytes blindly) instead of strict PKCS7.
    candidates = [pt]  # try the raw plaintext first
    pb = pt[-1]
    if 1 <= pb <= 16:
        candidates.append(pt[:-pb])
    # Also try strict PKCS7 verification.
    if 1 <= pb <= 16 and pt[-pb:] == bytes([pb]) * pb:
        candidates.append(pt[:-pb])

    last_err = None
    for i, c in enumerate(candidates):
        for fmt_name, fmt in [
            ("auto",   None),
            ("xml",    plistlib.FMT_XML),
            ("binary", plistlib.FMT_BINARY),
        ]:
            try:
                if fmt is None:
                    out = plistlib.loads(c)
                else:
                    out = plistlib.loads(c, fmt=fmt)
                print(f"    [dbg] parsed via candidate#{i} fmt={fmt_name} ({len(c)} bytes)")
                return out
            except Exception as e:
                last_err = e

    # Dump the plaintext so the user can paste it back to me for inspection.
    dump_path = "/tmp/tvos_spd_pt.bin"
    with open(dump_path, "wb") as f:
        f.write(pt)
    print(f"    [dbg] saved decrypted SPD → {dump_path}")
    raise SystemExit(f"SPD decrypt: plaintext not a plist (last error: {last_err})")

# ─── GSA protocol ─────────────────────────────────────────────────────────────

def gsa_post(body_dict: dict) -> dict:
    data = plistlib.dumps(body_dict)
    req = urllib.request.Request(GSA_URL, data=data, method="POST")
    req.add_header("Content-Type",       "text/x-xml-plist")
    req.add_header("Accept",             "*/*")
    req.add_header("User-Agent",         GSA_USER_AGENT)
    req.add_header("X-MMe-Client-Info",  GSA_CLIENT_INFO)
    req.add_header("X-Apple-App-Info",   "com.apple.gs.xcode.auth")
    req.add_header("X-Xcode-Version",    "11.2 (11B41)")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return plistlib.loads(r.read())["Response"]
    except urllib.error.HTTPError as e:
        body = e.read()
        raise SystemExit(f"gsa_post HTTP {e.code}: {body[:400]!r}")

def build_cpd(ani: AnisetteSession) -> dict:
    """cpd dict for GSA init/complete, per JJTech reference + AltStore wiki."""
    h = ani.headers()
    return {
        "bootstrap": True,
        "icscrec":   True,
        "pbe":       False,
        "prkgen":    True,
        "svct":      "iCloud",  # NOT iTunes for this flow — JJTech reference
        # meta
        "X-Apple-I-Client-Time":              h["X-Apple-I-Client-Time"] or _iso_now(),
        "X-Apple-I-TimeZone":                 h.get("X-Apple-I-TimeZone", "UTC"),
        "loc":                                "en_US",
        "X-Apple-Locale":                     h.get("X-Apple-Locale", "en_US"),
        "X-Apple-I-MD-RINFO":                 h["X-Apple-I-MD-RINFO"],
        "X-Apple-I-MD-LU":                    h["X-Apple-I-MD-LU"],
        "X-Mme-Device-Id":                    h["X-Mme-Device-Id"],
        "X-Apple-I-SRL-NO":                   h.get("X-Apple-I-SRL-NO", "0"),
        # OTPs
        "X-Apple-I-MD":                       h["X-Apple-I-MD"],
        "X-Apple-I-MD-M":                     h["X-Apple-I-MD-M"],
    }

def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def gsa_authenticate(email: str, password: str, ani: AnisetteSession) -> dict:
    """
    Full GSA SRP-6a. Returns the decrypted SPD dict + extracted fields:
    {dsid, idms_token, adsid, identity_token_dsid, identity_token_adsid,
     status_au, spd}
    """
    info("GSA SRP init…")
    usr = pysrp.User(email.encode(), b"", hash_alg=pysrp.SHA256, ng_type=pysrp.NG_2048)
    _, A = usr.start_authentication()

    cpd = build_cpd(ani)
    r1 = gsa_post({
        "Header":  {"Version": "1.0.1"},
        "Request": {
            "A2k": A,
            "ps":  ["s2k", "s2k_fo"],
            "u":   email,
            "o":   "init",
            "cpd": cpd,
        },
    })
    if "sp" not in r1:
        raise SystemExit(f"GSA init failed: {r1}")
    protocol = r1["sp"]
    salt     = r1["s"]
    B        = r1["B"]
    c        = r1["c"]
    iters    = int(r1.get("i", 20000))
    ok(f"GSA init: protocol={protocol} iters={iters}")

    usr.p = derive_password(password, protocol, salt, iters)
    M1 = usr.process_challenge(salt, B)
    if M1 is None:
        raise SystemExit("GSA SRP challenge failed")

    info("GSA SRP complete…")
    cpd2 = build_cpd(ani)  # fresh OTPs, same bound identity
    r2 = gsa_post({
        "Header":  {"Version": "1.0.1"},
        "Request": {
            "c":   c,
            "M1":  M1,
            "u":   email,
            "o":   "complete",
            "cpd": cpd2,
        },
    })
    if "M2" not in r2:
        raise SystemExit(f"GSA complete failed: {r2}")

    # Verify the server's M2 — if our K is wrong this will fail and we'd
    # otherwise just get garbage when decrypting SPD.
    usr.verify_session(r2["M2"])
    if not usr.authenticated():
        raise SystemExit("GSA: server M2 verification failed (K mismatch — auth invalid)")
    ok("GSA M2 verified")

    K = usr.get_session_key()
    if not r2.get("spd"):
        raise SystemExit("GSA complete: no spd in response")
    spd = decrypt_spd(K, r2["spd"])

    dsid       = str(spd.get("DsPrsId", spd.get("dsid", "")))
    idms_token = spd.get("GsIdmsToken", spd.get("GsIdToken", ""))
    adsid      = str(spd.get("adsid", ""))

    status_au = ""
    if isinstance(r2.get("Status"), dict):
        status_au = r2["Status"].get("au", "") or ""

    if not dsid or not idms_token:
        raise SystemExit(f"GSA complete: missing DsPrsId/GsIdmsToken in SPD (keys={list(spd.keys())})")

    # Persist SPD so we can inspect it after a run.
    try:
        # SPD contains bytes (M2-style), so dump as a JSON-safe dict.
        def _coerce(v):
            if isinstance(v, bytes):
                return {"_bytes_b64": base64.b64encode(v).decode()}
            if isinstance(v, dict):
                return {k: _coerce(x) for k, x in v.items()}
            if isinstance(v, list):
                return [_coerce(x) for x in v]
            return v
        with open(SPD_FILE, "w") as f:
            json.dump(_coerce(spd), f, indent=2, default=str)
        info(f"SPD saved → {SPD_FILE}")
    except Exception as e:
        warn(f"could not save SPD: {e}")

    # Surface the service-token table if it exists — `t` keys are which Apple
    # services your session is authorized for. For App Store/iTunes we expect
    # something like com.apple.gs.idms.pet or com.apple.gs.appleid.auth.
    t_dict = spd.get("t")
    if isinstance(t_dict, dict):
        info(f"SPD t-keys: {list(t_dict.keys())}")

    return {
        "dsid":                  dsid,
        "idms_token":            str(idms_token),
        "adsid":                 adsid,
        "identity_token_dsid":   base64.b64encode(f"{dsid}:{idms_token}".encode()).decode(),
        "identity_token_adsid":  base64.b64encode(f"{adsid}:{idms_token}".encode()).decode() if adsid else "",
        "status_au":             status_au,
        "spd":                   spd,
    }

# ─── 2FA ──────────────────────────────────────────────────────────────────────

def gsa_trigger_push(identity_token: str, ani: AnisetteSession,
                     with_anisette: bool = True) -> tuple[int, bytes]:
    """
    GET /auth/verify/trusteddevice with the identity-token. Returns (status, body).
    NOTE: Apple frequently returns 401 here even when the push DOES go through to
    the trusted device — the actual push is bound to the active SRP session and
    Status.au flag in the SRP complete response, not to this GET succeeding.
    """
    headers = {
        "User-Agent":             GSA_USER_AGENT,
        "Accept":                 "text/x-xml-plist",
        "Accept-Language":        "en-us",
        "X-Apple-App-Info":       "com.apple.gs.xcode.auth",
        "X-Xcode-Version":        "11.2 (11B41)",
        "X-MMe-Client-Info":      GSA_CLIENT_INFO,
        "X-Apple-Identity-Token": identity_token,
    }
    if with_anisette:
        h = ani.headers()
        headers.update({
            "X-Apple-I-MD":          h["X-Apple-I-MD"],
            "X-Apple-I-MD-M":        h["X-Apple-I-MD-M"],
            "X-Apple-I-MD-RINFO":    h["X-Apple-I-MD-RINFO"],
            "X-Apple-I-MD-LU":       h["X-Apple-I-MD-LU"],
            "X-Mme-Device-Id":       h["X-Mme-Device-Id"],
            "X-Apple-I-SRL-NO":      h["X-Apple-I-SRL-NO"],
            "X-Apple-I-Client-Time": h["X-Apple-I-Client-Time"],
            "X-Apple-I-TimeZone":    h["X-Apple-I-TimeZone"],
            "X-Apple-Locale":        h["X-Apple-Locale"],
        })
    req = urllib.request.Request(GSA_TRUSTED_DEV, method="GET")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()

def gsa_submit_code(code: str, identity_token: str, ani: AnisetteSession) -> tuple[int, bytes, list[str]]:
    """
    GET /grandslam/GsService2/validate?security-code=NNNN — Apple inspects the
    plist body / status code for success. Status code 200 + ec=0 ⇒ accepted.
    Returns (http_status, body_bytes, x_apple_gs_tokens).
    """
    h = ani.headers()
    headers = {
        "User-Agent":             GSA_USER_AGENT,
        "Accept":                 "*/*",
        "Accept-Language":        "en-us",
        "Content-Type":           "text/x-xml-plist",
        "X-Apple-App-Info":       "com.apple.gs.xcode.auth",
        "X-Xcode-Version":        "11.2 (11B41)",
        "X-MMe-Client-Info":      GSA_CLIENT_INFO,
        "X-Apple-Identity-Token": identity_token,
        "security-code":          code,
        "Loc":                    "en_US",
        "X-Apple-I-MD":           h["X-Apple-I-MD"],
        "X-Apple-I-MD-M":         h["X-Apple-I-MD-M"],
        "X-Apple-I-MD-RINFO":     h["X-Apple-I-MD-RINFO"],
        "X-Apple-I-MD-LU":        h["X-Apple-I-MD-LU"],
        "X-Mme-Device-Id":        h["X-Mme-Device-Id"],
        "X-Apple-I-SRL-NO":       h["X-Apple-I-SRL-NO"],
        "X-Apple-I-Client-Time":  h["X-Apple-I-Client-Time"],
        "X-Apple-I-TimeZone":     h["X-Apple-I-TimeZone"],
        "X-Apple-Locale":         h["X-Apple-Locale"],
    }
    req = urllib.request.Request(GSA_VALIDATE, method="GET")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            gs = [v for k, v in r.headers.items() if k.lower() == "x-apple-gs-token"]
            return r.status, r.read(), gs
    except urllib.error.HTTPError as e:
        gs = [v for k, v in e.headers.items() if k.lower() == "x-apple-gs-token"]
        return e.code, e.read(), gs

def validate_response_ok(status: int, body: bytes) -> tuple[bool, str]:
    """Returns (ok, message). Apple sometimes returns 200 with ec!=0."""
    if status not in (200, 204):
        return False, f"HTTP {status}: {body[:200]!r}"
    if not body:
        return True, "ok (empty body)"
    try:
        pl = plistlib.loads(body)
        if isinstance(pl, dict):
            # Response.Status.ec OR top-level ec
            ec = None
            em = ""
            if isinstance(pl.get("Response"), dict):
                st = pl["Response"].get("Status") or {}
                ec = st.get("ec")
                em = st.get("em", "")
            if ec is None:
                ec = pl.get("ec")
                em = pl.get("em", em)
            if ec is None or ec == 0:
                return True, "ec=0"
            return False, f"ec={ec} em={em!r}"
    except Exception as e:
        return True, f"body not plist ({e}); status={status}"
    return True, f"status={status}"

def handle_2fa(auth: dict, ani: AnisetteSession) -> dict:
    """
    Trigger push + prompt code + submit. Tries both identity-token variants
    (DsPrsId-based and adsid-based) because current POC stops at ec=-22410
    with adsid only. Returns auth dict updated with the identity_token that
    actually worked.
    """
    candidates = []
    if auth["identity_token_dsid"]:
        candidates.append(("DsPrsId", auth["identity_token_dsid"]))
    if auth["identity_token_adsid"]:
        candidates.append(("adsid",   auth["identity_token_adsid"]))

    # Trigger with both identity-token variants, with and without anisette.
    # All commonly return 401, but the actual push may still go through because
    # it's bound to the active SRP session and Status.au, not this GET.
    info("trigger trusted-device push (best-effort — 401 is expected)")
    any_2xx = False
    for label, token in candidates:
        for ani_label, with_ani in [("with-anisette", True), ("no-anisette", False)]:
            status, body = gsa_trigger_push(token, ani, with_anisette=with_ani)
            body_snip = body[:160].decode(errors="replace").strip()
            print(f"    trigger identity={label} {ani_label} → HTTP {status} body={body_snip!r}")
            if 200 <= status < 300:
                any_2xx = True
    if any_2xx:
        ok("at least one trigger variant returned 2xx")
    else:
        warn("all trigger variants returned 4xx — push usually still arrives, watch your device")

    print()
    print(">>> A 6-digit code should now be on your trusted device.")
    code = input(">>> Enter the code: ").strip()
    if not (code.isdigit() and len(code) == 6):
        raise SystemExit(f"Invalid code format: {code!r}")

    last_msg = ""
    for label, token in candidates:
        info(f"submit code via /validate (identity={label})…")
        status, body, gs_tokens = gsa_submit_code(code, token, ani)
        good, msg = validate_response_ok(status, body)
        if good:
            ok(f"2FA accepted (identity={label}): {msg}")
            if gs_tokens:
                info(f"  /validate returned {len(gs_tokens)} X-Apple-GS-Token headers")
                for t in gs_tokens[:3]:
                    print(f"    gs-token: {t[:60]}…")
            auth["identity_token"]      = token
            auth["identity_token_kind"] = label
            auth["gs_tokens"]           = gs_tokens
            return auth
        warn(f"2FA rejected (identity={label}): {msg}")
        last_msg = msg

    raise SystemExit(f"2FA submission failed (tried {[c[0] for c in candidates]}): {last_msg}")

# ─── MZFinance: direct tvOS download ──────────────────────────────────────────

def _guid_from_mac() -> str:
    import subprocess, re
    try:
        out = subprocess.check_output(["ifconfig", "en0"], text=True)
        m = re.search(r"ether\s+([0-9a-f:]+)", out)
        if m:
            return m.group(1).replace(":", "").upper()
    except Exception:
        pass
    return ("%012X" % uuid.getnode())

def load_configurator_session(path: str) -> dict | None:
    """
    Load /tmp/mzfinance_result.json (from auth/mzfinance_auth.py). Returns a
    dict with keys: cookies (dict), passwordToken, dsPersonId, storeFront, pod.
    Returns None if not present.
    """
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            d = json.load(f)
        if not d.get("cookies") or not d.get("dsPersonId"):
            warn(f"configurator session at {path} missing cookies/dsid; ignoring")
            return None
        return d
    except Exception as e:
        warn(f"could not load configurator session at {path}: {e}")
        return None

def appletv_authenticate(email: str, password: str, code: str = "") -> dict:
    """
    Configurator-style authenticate against MZFinance.woa/wa/authenticate BUT
    with an Apple TV User-Agent so the resulting session cookies are stamped
    tvOS — the per-request deviceClass/storefront flags don't override the
    session's device-class once cookies are minted.

    Returns {passwordToken, dsPersonId, storeFront, pod, cookies} on success.

    First call: pass code="" → expects BadLogin (2FA needed). Second call:
    pass the 6-digit code. We also try the trusted-device shortcut where Apple
    sometimes accepts the call w/o code if the device is already trusted from a
    very recent GSA validation.
    """
    g = _guid_from_mac()
    pwd = password + (code or "").replace(" ", "")
    body = plistlib.dumps({
        "appleId":  email,
        "attempt":  "2" if code else "1",
        "guid":     g,
        "password": pwd,
        "rmp":      "0",
        "why":      "signIn",
    }, fmt=plistlib.FMT_XML)

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    auth_url = "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"
    req = urllib.request.Request(auth_url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent",   APPLETV_UA)
    req.add_header("Accept",       "application/xml")

    try:
        with opener.open(req, timeout=30) as r:
            status, raw, hdrs = r.status, r.read(), {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        status, raw, hdrs = e.code, e.read(), {k.lower(): v for k, v in e.headers.items()}

    # Apple often returns the dict bare without a <plist> wrapper here. Extract.
    import re
    m = re.search(rb"<dict\b[^>]*>.*</dict>", raw, re.DOTALL)
    if m:
        raw_dict = b'<?xml version="1.0"?><plist version="1.0">' + m.group(0) + b"</plist>"
    else:
        raw_dict = raw

    try:
        data = plistlib.loads(raw_dict)
    except Exception:
        data = {}

    ft   = data.get("failureType", "")
    cmsg = data.get("customerMessage", "")
    tok  = data.get("passwordToken", "")
    dsid = data.get("dsPersonId", "")
    sf   = hdrs.get("x-set-apple-store-front", "")
    pod  = hdrs.get("pod", "")

    return {
        "_status":         status,
        "_failureType":    ft,
        "_customerMessage":cmsg,
        "_raw_keys":       list(data.keys()) if isinstance(data, dict) else [],
        "passwordToken":   tok,
        "dsPersonId":      dsid,
        "storeFront":      sf,
        "pod":             pod,
        "cookies":         {c.name: c.value for c in cj},
    }

def run_appletv_authenticate(email: str, password: str) -> dict:
    """
    Orchestrate the Apple TV authenticate with optional 2FA prompt. Saves the
    successful result to APPLETV_SESSION.
    """
    info("Apple TV authenticate (fresh, tvOS-stamped session)…")
    resp = appletv_authenticate(email, password, code="")
    info(f"  HTTP {resp['_status']} failureType={resp['_failureType']!r} customerMessage={resp['_customerMessage']!r}")
    info(f"  response keys: {resp['_raw_keys']}")
    info(f"  storeFront={resp['storeFront']!r} pod={resp['pod']!r}")

    if resp["passwordToken"] and resp["dsPersonId"]:
        ok("Apple TV authenticated without 2FA (trusted device shortcut)")
    elif resp["_customerMessage"] == "MZFinance.BadLogin.Configurator_message":
        info("Apple TV authenticate wants a 2FA code")
        print()
        print(">>> A 6-digit code should be on your trusted device for the Apple TV authenticate.")
        code = input(">>> Enter the code: ").strip()
        if not (code.isdigit() and len(code) == 6):
            raise SystemExit(f"Invalid code: {code!r}")
        resp = appletv_authenticate(email, password, code=code)
        info(f"  retry HTTP {resp['_status']} failureType={resp['_failureType']!r} customerMessage={resp['_customerMessage']!r}")
    else:
        raise SystemExit(
            f"Apple TV authenticate: unexpected response. "
            f"failureType={resp['_failureType']!r} msg={resp['_customerMessage']!r} keys={resp['_raw_keys']}"
        )

    if not (resp["passwordToken"] and resp["dsPersonId"]):
        raise SystemExit(
            f"Apple TV authenticate failed: failureType={resp['_failureType']!r} "
            f"msg={resp['_customerMessage']!r}"
        )

    ok(f"Apple TV session: dsid={resp['dsPersonId']} pod={resp['pod']} storefront={resp['storeFront']}")
    ok(f"  cookies: {sorted(resp['cookies'].keys())}")
    out = {
        "passwordToken": resp["passwordToken"],
        "dsPersonId":    resp["dsPersonId"],
        "storeFront":    resp["storeFront"],
        "pod":           resp["pod"],
        "cookies":       resp["cookies"],
    }
    with open(APPLETV_SESSION, "w") as f:
        json.dump(out, f, indent=2)
    ok(f"  saved → {APPLETV_SESSION}")
    return out

def storefront_to_tvos(sf: str) -> str:
    """'143448-2,34' → '143448-6,34' (replace platform 2=iOS with 6=tvOS)."""
    if not sf:
        return sf
    head, _, tail = sf.partition(",")
    region, _, _platform = head.partition("-")
    if not region:
        return sf
    new_head = f"{region}-6"
    return f"{new_head},{tail}" if tail else new_head

def _build_cookie_jar(cookies_dict: dict, domain: str = ".apple.com") -> http.cookiejar.CookieJar:
    cj = http.cookiejar.CookieJar()
    for name, value in (cookies_dict or {}).items():
        c = http.cookiejar.Cookie(
            version=0, name=name, value=str(value),
            port=None, port_specified=False,
            domain=domain, domain_specified=True, domain_initial_dot=domain.startswith("."),
            path="/", path_specified=True,
            secure=True, expires=int(time.time()) + 3600 * 24 * 30,
            discard=False, comment=None, comment_url=None, rest={},
        )
        cj.set_cookie(c)
    return cj

def mzfinance_buy(adam_id: str, dsid: str, storefront: str,
                  identity_token: str, gs_tokens: list[str],
                  pod: str = "", cookies: dict | None = None,
                  password_token: str = "",
                  device_class: str = "AppleTV",
                  user_agent: str = "") -> dict:
    """
    POST buyProduct with deviceClass=AppleTV. For free apps this should be a
    no-op acquisition that registers a tvOS-class license against the account.
    The Go code's failureType=5002 we kept seeing was Apple saying "you have
    an iOS license but not a tvOS license" — this call mints the tvOS license.
    """
    g = _guid_from_mac()
    pod_prefix = f"p{pod}-" if pod else ""
    url = f"https://{pod_prefix}{STORE_DOMAIN}{MZFINANCE_BUY}?guid={g}"

    payload = {
        "appExtVrsId":           0,
        "guid":                  g,
        "needDiv":               "0",
        "origPage":              f"Software-{adam_id}",
        "origPageLocation":      "Search",
        "price":                 0,
        "pricingParameters":     "STDQ",
        "productType":           "C",  # consumable=A, software=C
        "salableAdamId":         int(adam_id),
        "deviceClass":           device_class,
    }
    body = plistlib.dumps(payload, fmt=plistlib.FMT_XML)

    cj = _build_cookie_jar(cookies or {})
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    ua = user_agent or "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type",        "application/x-apple-plist")
    req.add_header("User-Agent",          ua)
    req.add_header("iCloud-DSID",         dsid)
    req.add_header("X-Dsid",              dsid)
    req.add_header("X-Apple-Store-Front", storefront)
    if identity_token:
        req.add_header("X-Apple-Identity-Token", identity_token)
    if password_token:
        # buyProduct often requires X-Token to actually create the license,
        # unlike download which we keep tokenless.
        req.add_header("X-Token", password_token)
    for t in (gs_tokens or [])[:1]:
        req.add_header("X-Apple-GS-Token", t)

    info(f"MZFinance buyProduct → {url}")
    info(f"  deviceClass={device_class} storefront={storefront} adamId={adam_id}")
    try:
        with opener.open(req, timeout=30) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()

    dump = "/tmp/tvos_buy_raw.bin"
    with open(dump, "wb") as f:
        f.write(raw)

    try:
        data = plistlib.loads(raw)
    except Exception:
        info(f"  HTTP {status}, body len={len(raw)} — not plist; saved {dump}")
        return {"_status": status, "_raw": raw[:300]}

    if isinstance(data, dict):
        ft   = data.get("failureType", "")
        cmsg = data.get("customerMessage", "")
        items = data.get("songList", [])
        info(f"  HTTP {status} items={len(items)} failureType={ft!r} customerMessage={cmsg[:160]!r}")
        info(f"  response keys: {sorted(data.keys())}")
        return data
    return {"_status": status, "_data": data}

def mzfinance_download(adam_id: str, dsid: str, storefront: str,
                       identity_token: str, gs_tokens: list[str],
                       pod: str = "", cookies: dict | None = None,
                       password_token: str = "",
                       ext_ver_id: str = "",
                       user_agent: str = "",
                       verbose: bool = True) -> dict:
    """
    POST volumeStoreDownloadProduct with deviceClass=AppleTV.

    Per the Go consumerDownload comment in internal/appstore/download.go:
      "For tvOS, omit X-Token so Apple uses the mz_at_ssl cookie session
       instead of VPP. VPP (X-Token) triggers a license-creation check
       that returns 5002 when the account already owns the app via
       consumer purchase."

    So we attach the Configurator cookies (especially mz_at_ssl-<dsid>) but
    we do NOT send X-Token. The GSA-issued X-Apple-Identity-Token IS sent
    as the consumer-path credential.
    """
    g = _guid_from_mac()
    pod_prefix = f"p{pod}-" if pod else ""
    url = f"https://{pod_prefix}{STORE_DOMAIN}{MZFINANCE_DL}?guid={g}"

    payload = {
        "creditDisplay":     "",
        "guid":              g,
        "salableAdamId":     int(adam_id),
        "pricingParameters": "STDQ",
        "deviceClass":       "AppleTV",
    }
    if ext_ver_id:
        payload["externalVersionId"] = int(ext_ver_id)

    body = plistlib.dumps(payload, fmt=plistlib.FMT_XML)

    cj = _build_cookie_jar(cookies or {})
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    ua = user_agent or "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type",          "application/x-apple-plist")
    req.add_header("User-Agent",            ua)
    req.add_header("iCloud-DSID",           dsid)
    req.add_header("X-Dsid",                dsid)
    req.add_header("X-Apple-Store-Front",   storefront)
    if identity_token:
        req.add_header("X-Apple-Identity-Token", identity_token)
    # Note: we deliberately do NOT send X-Token (passwordToken) — see docstring.
    for t in (gs_tokens or [])[:1]:
        req.add_header("X-Apple-GS-Token", t)

    if verbose:
        info(f"MZFinance download → {url}")
        info(f"  storefront={storefront} adamId={adam_id} ext_ver_id={ext_ver_id or '-'}")
        info(f"  User-Agent: {ua}")
        info(f"  cookies attached: {sorted(cookies.keys()) if cookies else []}")
        info(f"  identity-token kind: {'present' if identity_token else 'absent'}, gs_tokens={len(gs_tokens or [])}")

    try:
        with opener.open(req, timeout=60) as r:
            status, raw = r.status, r.read()
            resp_hdrs = {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
        resp_hdrs = {k.lower(): v for k, v in e.headers.items()}

    if verbose:
        info(f"  response HTTP {status}, body len={len(raw)}")

    # Always dump the raw response so we can compare across runs.
    dump = "/tmp/tvos_download_raw.bin"
    with open(dump, "wb") as f:
        f.write(raw)

    try:
        data = plistlib.loads(raw)
    except Exception:
        raise SystemExit(f"MZFinance download: not a plist (HTTP {status}, len={len(raw)}). raw saved → {dump}")

    if isinstance(data, dict):
        ft    = data.get("failureType", "")
        cmsg  = data.get("customerMessage", "")
        items = data.get("songList", [])
        if verbose:
            ok(f"items={len(items)} failureType={ft!r} customerMessage={cmsg[:160]!r}")
            # Dump the whole response if it looks unhelpful — usually 5002 / 2042 / etc.
            if not items or ft:
                short_keys = sorted(data.keys())
                info(f"  response keys: {short_keys}")
                for k in ("metrics", "is-auto-download", "jingleAction", "jingleDocType"):
                    if k in data:
                        v = data[k]
                        info(f"    {k} = {str(v)[:200]!r}")
        if items and items[0].get("URL"):
            return data
        if ft or cmsg:
            raise SystemExit(f"MZFinance download: failureType={ft!r} msg={cmsg!r}")
        raise SystemExit(f"MZFinance download: empty songList, raw saved → {dump}")
    raise SystemExit(f"MZFinance download: unexpected payload shape: {type(data)}")

# ─── Disk writer ──────────────────────────────────────────────────────────────

def stream_to_disk(url: str, dest: str, expected_size: int = 0) -> None:
    info(f"downloading → {dest}")
    if expected_size:
        info(f"  expected size: {expected_size:,} bytes")
    req = urllib.request.Request(url, headers={"User-Agent": "Configurator/2.17"})
    t0 = time.time()
    total = 0
    last_print = 0.0
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1 << 18)  # 256 KiB
            if not chunk:
                break
            f.write(chunk)
            total += len(chunk)
            now = time.time()
            if now - last_print > 0.5:
                last_print = now
                pct = (100 * total / expected_size) if expected_size else 0
                sys.stdout.write(f"\r    {total/1e6:8.1f} MB" + (f"  ({pct:5.1f}%)" if expected_size else ""))
                sys.stdout.flush()
    sys.stdout.write("\n")
    ok(f"saved {total:,} bytes in {time.time()-t0:.1f}s → {dest}")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="tvOS IPA download prototype")
    ap.add_argument("target", help="bundle ID or numeric adam ID")
    ap.add_argument("--ext-ver-id", default="", help="pin a specific externalVersionId")
    ap.add_argument("--country", default="us", help="storefront country (lower-case; default us)")
    ap.add_argument("--storefront", default="", help="raw storefront region id (e.g. 143441 US, 143448 GR). Overrides --country.")
    ap.add_argument("--anisette-url", default=ANISETTE_URL_DEFAULT)
    ap.add_argument("--output", default=".", help="output directory")
    ap.add_argument("--configurator-session", default=MZFIN_DEFAULT,
                    help=f"path to a Configurator session JSON (output of auth/mzfinance_auth.py); default {MZFIN_DEFAULT}")
    ap.add_argument("--no-configurator", action="store_true",
                    help="skip loading the Configurator session (test pure GSA path; usually returns 5002)")
    ap.add_argument("--download-ua", default="",
                    help="override the User-Agent for the MZFinance download call. Useful for probing whether Apple re-evaluates device-class from UA. Try 'iTunes-AppleTV/12.7.0 (4; 32GB; dt:174) AppleWebKit/9537.53.11.21'.")
    ap.add_argument("--appletv-auth", action="store_true",
                    help="run a fresh MZFinance authenticate with Apple TV UA to obtain tvOS-stamped cookies. Recommended for downloading tvOS binaries.")
    ap.add_argument("--appletv-session", default=APPLETV_SESSION,
                    help=f"path to cached Apple TV session JSON; reused if present (default {APPLETV_SESSION})")
    ap.add_argument("--reauth-appletv", action="store_true",
                    help="ignore cached Apple TV session and force a fresh authenticate (may prompt 2FA)")
    ap.add_argument("--buy", action="store_true",
                    help="call MZFinance.woa/wa/buyProduct with deviceClass=AppleTV before download — mints a tvOS license if the account only has iOS, which is the suspected reason Apple keeps returning iOS binaries.")
    args = ap.parse_args()

    email, password = load_config()
    if not email or not password:
        raise SystemExit("missing Apple ID email/password (set in config.py or enter when prompted)")

    info(f"target={args.target!r}, country={args.country}, output={args.output}")

    # 1) Look up app via tvSoftware entity.
    app = lookup_app(args.target, country=args.country)
    ok(f"app: {app['name']!r} ({app['bundleId']}) adamId={app['adamId']} version={app['version']} kind={app['kind']!r}")
    if app["kind"] and "tv" not in app["kind"].lower():
        warn(f"kind={app['kind']!r} — not tvSoftware. The iTunes search may have fallen back to iOS.")

    # 2) Anisette session.
    ani = AnisetteSession(args.anisette_url)
    h0 = ani.headers()
    info(f"anisette device-id={h0['X-Mme-Device-Id'][:8]}… MD-LU={h0['X-Apple-I-MD-LU'][:12]}…")

    # 3) GSA SRP init + complete + decrypt SPD.
    auth = gsa_authenticate(email, password, ani)
    ok(f"GSA OK — dsid={auth['dsid']} adsid={auth['adsid']!r} status.au={auth['status_au']!r}")

    # 4) 2FA if needed.
    if "secondaryAuth" in auth["status_au"] or auth["status_au"] == "trustedDeviceSecondaryAuth":
        auth = handle_2fa(auth, ani)
    else:
        # Default to DsPrsId-based token for downstream calls.
        auth["identity_token"] = auth["identity_token_dsid"]
        auth["identity_token_kind"] = "DsPrsId"

    # 5) Acquire a Configurator-style session whose cookies are stamped for
    #    the right device class (tvOS). Three sources, in priority order:
    #      a) cached Apple TV session at --appletv-session (best for tvOS)
    #      b) fresh Apple TV authenticate via --appletv-auth (creates the cache)
    #      c) cached Configurator (iOS) session at --configurator-session
    #         (works for iOS downloads but Apple returns iOS binary for tvOS too)
    cfg = None
    if args.appletv_auth or os.path.exists(args.appletv_session):
        if not args.reauth_appletv and os.path.exists(args.appletv_session):
            try:
                with open(args.appletv_session) as f:
                    cfg = json.load(f)
                ok(f"apple-tv session (cached): dsid={cfg.get('dsPersonId')} "
                   f"pod={cfg.get('pod')} storefront={cfg.get('storeFront')}")
            except Exception as e:
                warn(f"could not read apple-tv session: {e}")
                cfg = None
        if cfg is None and args.appletv_auth:
            cfg = run_appletv_authenticate(email, password)
        cfg_kind = "apple-tv"
    else:
        cfg_kind = "configurator"
        cfg = None if args.no_configurator else load_configurator_session(args.configurator_session)
        if cfg and cfg.get("dsPersonId") and cfg["dsPersonId"] != auth["dsid"]:
            warn(f"configurator dsid={cfg['dsPersonId']} ≠ GSA dsid={auth['dsid']} — skipping (mismatched account)")
            cfg = None
        elif cfg:
            ok(f"configurator session: dsid={cfg.get('dsPersonId')} pod={cfg.get('pod')} storefront={cfg.get('storeFront')}")

    if cfg and cfg.get("dsPersonId") and cfg["dsPersonId"] != auth["dsid"]:
        warn(f"{cfg_kind} dsid mismatch — ignoring")
        cfg = None

    # Resolve the tvOS storefront. If we have a Configurator session, derive
    # from its iOS storefront (most reliable — matches the account region).
    # Otherwise fall back to --storefront / --country.
    if cfg and cfg.get("storeFront"):
        sf_tvos = storefront_to_tvos(cfg["storeFront"])
    else:
        region = args.storefront or STOREFRONT_ID.get(args.country.lower(), "")
        if not region:
            raise SystemExit(
                f"unknown country {args.country!r} — pass --storefront <id> "
                f"(e.g. 143441 for US, 143448 for GR)"
            )
        sf_tvos = f"{region}-6,32"
    info(f"tvOS storefront: {sf_tvos}")

    # 6) MZFinance volumeStoreDownloadProduct deviceClass=AppleTV.
    pod     = (cfg or {}).get("pod", "")
    cookies = (cfg or {}).get("cookies", {})
    # 5b) Optionally call buyProduct first to mint a tvOS-class license.
    if args.buy:
        buy = mzfinance_buy(
            app["adamId"], auth["dsid"], sf_tvos,
            auth["identity_token"], auth.get("gs_tokens") or [],
            pod=pod, cookies=cookies,
            password_token=(cfg or {}).get("passwordToken", ""),
        )
        ft = buy.get("failureType", "")
        cmsg = buy.get("customerMessage", "")
        if ft and ft != "5002":
            warn(f"buyProduct returned failureType={ft!r} msg={cmsg!r} — continuing anyway")

    # When we have an Apple TV session, default the download UA to Apple TV
    # so it matches the session's device-class.
    dl_ua = args.download_ua or (APPLETV_UA if cfg_kind == "apple-tv" and cfg else "")
    dl = mzfinance_download(
        app["adamId"], auth["dsid"], sf_tvos,
        auth["identity_token"], auth.get("gs_tokens") or [],
        pod=pod, cookies=cookies,
        password_token=(cfg or {}).get("passwordToken", ""),
        ext_ver_id=args.ext_ver_id,
        user_agent=dl_ua,
    )
    item   = dl["songList"][0]
    url    = item["URL"]
    meta   = item.get("metadata", {})
    asset  = item.get("asset-info", {})
    size   = int(asset.get("file-size", 0))

    plat   = meta.get("DTPlatformName") or meta.get("softwarePlatform") or "?"
    bid    = meta.get("softwareVersionBundleId") or app["bundleId"]
    ver    = meta.get("bundleShortVersionString") or app["version"]
    ok(f"download URL acquired: platform={plat!r} bundleId={bid} version={ver} size={size:,}")

    # Dump every metadata field — we want to see exactly what platform Apple
    # tagged the binary with. The 'DTPlatformName', 'softwarePlatform',
    # 'UIDeviceFamily', 'MinimumOSVersion' fields are the truth.
    if isinstance(meta, dict):
        for k in ("DTPlatformName", "DTPlatformVersion", "softwarePlatform",
                  "softwareVersionBundleId", "bundleShortVersionString",
                  "kind", "UIDeviceFamily", "MinimumOSVersion", "playlistName"):
            if k in meta:
                info(f"    meta.{k} = {meta[k]!r}")

    # Sanity-abort if the returned binary is clearly iOS. The user's tvOS YouTube
    # is v4.x; iOS YouTube is v21.x. If we got the iOS one, don't waste 250 MB.
    looks_ios = (
        plat and "tv" not in plat.lower() and plat not in ("", "?")
    ) or (
        bid == "com.google.ios.youtube" and ver.startswith("21.")
    )
    if looks_ios and not args.ext_ver_id:
        raise SystemExit(
            "ABORT: response is iOS, not tvOS. "
            f"platform={plat!r} bundleId={bid} version={ver}. "
            "Re-run with --download-ua 'iTunes-AppleTV/12.7.0 (4; 32GB; dt:174) AppleWebKit/9537.53.11.21' "
            "to probe whether UA flips the response. If that doesn't work either, "
            "we need fresh tvOS-context cookies (Apple TV authenticate flow)."
        )

    # 7) Save to disk.
    out_dir = os.path.abspath(args.output)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{bid}_{ver}_tvOS.ipa")
    stream_to_disk(url, out_path, expected_size=size)

    # Save session snapshot for debugging.
    with open(SESSION_FILE, "w") as f:
        json.dump({
            "app":         app,
            "dsid":        auth["dsid"],
            "storefront":  sf_tvos,
            "identity":    auth["identity_token_kind"],
            "out_path":    out_path,
        }, f, indent=2)
    ok(f"session snapshot saved → {SESSION_FILE}")

if __name__ == "__main__":
    main()

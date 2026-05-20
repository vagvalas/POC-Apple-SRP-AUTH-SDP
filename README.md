# POC: Apple SRP Auth + SPD + 2FA — and where the tvOS App Store wall lives

> A reverse-engineering proof-of-concept that authenticates against Apple's
> Grand Slam Authentication service (GSA) from scratch, decrypts the
> session-payload blob, completes 2-factor authentication, and probes how
> far you can go toward downloading a tvOS encrypted IPA — **from a Mac,
> without an actual Apple TV's hardware credentials**.
>
> Spoiler: you can authenticate all the way. You can't get the tvOS binary.
> The "why" is the interesting part, and it's documented in detail.

[![Python](https://img.shields.io/badge/Python-3.13-blue?style=flat-square&logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status: research POC](https://img.shields.io/badge/status-research%20POC-orange?style=flat-square)]()

---

## What this is

A single-file Python prototype that walks the full Apple consumer-store
authentication pipeline:

1. **Anisette** — fetches Apple's per-device OTP headers from a local
   anisette server.
2. **GSA SRP-6a** — Secure Remote Password handshake against
   `gsa.apple.com/grandslam/GsService2`. Builds A, M1 the way Apple's
   AOSKit does; verifies the server's M2 before trusting the session.
3. **SPD decryption** — Apple's "Session Payload Data" is returned
   AES-CBC-encrypted with keys derived from the SRP session key via two
   `HMAC-SHA256("extra data key:" / "extra data iv:", K)` calls. Decrypt,
   unpad, parse the (bare) XML plist.
4. **2FA push trigger + code submission** — the original POCs got stuck
   here with `ec=-22410`; this one solves it. Key finding documented in
   detail.
5. **Probe of the App Store consumer download path** — `buyProduct` and
   `volumeStoreDownloadProduct` with `deviceClass=AppleTV` + tvOS
   storefront + validated identity token.

Then a structured exploration of **why the tvOS binary specifically can't
be obtained this way**, with an edge-block UA probe matrix and a documented
pivot to proxy-capture from a real jailbroken Apple TV.

This is research code. It's not trying to be ipatool. It's trying to
*understand exactly where Apple's wall is* and document it crisply.

---

## Why this exists

`ipatool` and a few open-source siblings already download iOS IPAs by
emulating the macOS Apple Configurator client. They've worked for years.
**They don't work for tvOS.** Every public tool that has tried to extend
the Configurator approach to tvOS ends up with the iOS binary served back
instead — because Apple stamps the resulting session as iOS device-class
and refuses to serve a different platform from that session.

I wanted to know exactly *where* the wall sits — at the Authentication
layer? Authorization? Per-request header check? License-database lookup?
— and what (if anything) would let you cross it from a Mac.

Result: the wall is structural and lives in two places at once. The full
write-up is in [`progress.md`](progress.md). The summary table is below.

---

## What works

| Stage | Result |
|---|---|
| Anisette V3 server (`dadoum/anisette-v3-server`) on localhost | ✓ identity headers + OTPs |
| GSA SRP-6a init + complete | ✓ session keys agree (M2 verifies) |
| SPD AES-CBC decrypt (`HMAC(K, "extra data key:")` + IV) | ✓ XML plist recovered |
| 2FA push trigger (`/auth/verify/trusteddevice`) | ✓ prompt arrives (despite HTTP 401 response) |
| 2FA code submission (`/grandslam/GsService2/validate`) | ✓ `ec=0` — **only with `adsid:GsIdmsToken` identity token** |
| `MZFinance.woa/wa/volumeStoreDownloadProduct` returns a CDN URL | ✓ but the binary at that URL is iOS, regardless of `deviceClass=AppleTV` |

## What hits the wall

| Attempt | Apple's response | Interpretation |
|---|---|---|
| `Apple TV` UA on `MZFinance.woa/wa/authenticate` | HTTP 403 at the edge, empty body | Edge ACL — only `Configurator/2.17` UA admitted |
| Same on `auth.itunes.apple.com/auth/v1/native/fast` | HTTP 403 at the edge | Same ACL |
| `deviceClass=AppleTV` + tvOS storefront with iOS-stamped cookies | HTTP 200, **iOS** binary | Session cookie's class dominates |
| Apple TV UA on the *download* call only | HTTP 200, `m-allowed=false`, `customerMessage="AMD-Action:volumeStoreDownloadProduct:SP"` | "Sign-in required" — UA/cookie mismatch |
| `buyProduct(deviceClass=AppleTV)` to mint a tvOS license | `failureType=2034` ("Sign In to the iTunes Store") | iOS-class `passwordToken` can't create a tvOS license |
| Pure GSA path without cookies | `failureType=5002` ("LicenseAlreadyExists") | Account owns the app (iOS); refuses cross-platform |

## The structural reason in one sentence

Apple's public auth endpoints accept exactly one User-Agent
(`Configurator/2.17`), which mints iOS-class session cookies; tvOS App
Store authentication on a real Apple TV uses **FairPlay device certificates**
baked into the device's secure enclave — not a public HTTP credential a
Mac can replicate.

---

## Repo layout

```
.
├── README.md                 ← you are here
├── LICENSE                   ← MIT
├── progress.md               ← full detailed timeline + everything tried
├── requirements.txt          ← cryptography, srp (pysrp 1.0.22)
├── config.py                 ← Apple ID + password — placeholders only; gitignored once you fill it in
├── tvos_download.py          ← end-to-end pipeline (~1200 lines, single file)
└── proxy-capture/
    ├── README.md             ← step-by-step setup for Apple TV side of the pivot
    └── mitm_capture.py       ← mitmproxy addon that filters Apple flows into capture.jsonl
```

---

## Quick start

You need:

- macOS or Linux, Python 3.11+
- Docker (for the local anisette server)
- An Apple ID. **Use a throwaway / sacrificial one** — this is research code
  and you'll be triggering 2FA on it repeatedly.

```sh
# 1. Anisette server (one-time)
docker run -d --name anisette-v3 -p 6969:6969 dadoum/anisette-v3-server

# 2. This repo
git clone https://github.com/vagvalas/POC-Apple-SRP-AUTH-SDP.git
cd POC-Apple-SRP-AUTH-SDP

# 3. Python env
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 4. Credentials — copy the example and fill in your own
cp config.example.py config.py
$EDITOR config.py     # set EMAIL + PASSWORD

# 5. Run — give a numeric adam-id (App Store id) or a bundle id
python3 tvos_download.py 544007664        # YouTube, for example
```

On the first run you'll get a 2FA push on your trusted device — enter the
6-digit code at the prompt. Subsequent runs within the trust window skip
the push (`Status.au` comes back empty).

What you'll see:

```
[+] GSA M2 verified
[*] SPD saved → /tmp/tvos_spd.json
[+] GSA OK — dsid=<your_dsid> adsid='<your_adsid>' status.au='trustedDeviceSecondaryAuth'
[*] submit code via /validate (identity=DsPrsId)…
[!] 2FA rejected (identity=DsPrsId): HTTP 401
[*] submit code via /validate (identity=adsid)…
[+] 2FA accepted (identity=adsid): ec=0
...
[!] ABORT: response is iOS, not tvOS. ...
```

The "ABORT" is intentional — the script detects when Apple has returned
the iOS binary instead of tvOS and stops before downloading 250 MB you
don't want.

---

## The three findings worth remembering

### 1. SRP session-key padding

`pysrp` computes `K = SHA256(pad(S, modulus_length))`. The local
`libsrp.py` variants floating around — including the one in some Apple
SRP reference repos — compute `K = SHA256(min_bytes(S))`. When the
high byte of `S` happens to be zero, the two disagree silently. M2
verification will accept the wrong K because pysrp uses its own K for
M2 too. Then SPD decryption produces garbage and you spend an hour
chasing a "plistlib InvalidFileException" that's really an SRP math
bug.

**Always verify M2 explicitly** before consuming the session key for
anything else — pysrp does this automatically with `verify_session()`
+ `authenticated()`. The local libsrp.py does not.

### 2. The `adsid` vs `DsPrsId` identity-token format

`X-Apple-Identity-Token` on `/grandslam/GsService2/validate` must be
`base64("<adsid>:<GsIdmsToken>")`, **not** the more obvious
`base64("<DsPrsId>:<GsIdmsToken>")`.

Direct evidence from a working run:

```
submit code via /validate (identity=DsPrsId) → HTTP 401, empty body
submit code via /validate (identity=adsid)   → HTTP 200, ec=0
```

Every existing reference implementation I checked either guesses (and
fails) or uses adsid without explaining why. Both fields are in SPD;
you just have to pick the right one.

### 3. The 401 on `/auth/verify/trusteddevice` is not a failure

The trigger endpoint returns `HTTP 401` on every variant I tried —
DsPrsId-identity, adsid-identity, with and without anisette OTP
headers. Yet the push prompt always arrives on the trusted device.

The actual push is sent server-side as a consequence of the SRP
complete response containing `Status.au == "trustedDeviceSecondaryAuth"`.
The trigger GET is essentially a "click to resend" hint, not the
cause. **Treat 401 from the trigger as expected; proceed to prompt
the user for the code.**

---

## Pivot — capture from a real Apple TV

Since the Mac-only path is closed, the next move is to proxy-capture
exactly what `itunesstored` on a real (jailbroken) Apple TV sends to
`buy.itunes.apple.com`. Full plan + step-by-step setup in
[`proxy-capture/README.md`](proxy-capture/README.md).

Current status: blocked on **SSL pinning bypass**. The standard SSL Kill
Switch 2 (iOS 11 `.deb`) installs on tvOS 11 via force-arch but breaks
`itunesstored` when enabled. Trying SSL Kill Switch 3 / NoMoreTrust /
TrustMe next.

---

## References & prior art

This work would have taken weeks longer without the following — full
credit to those authors. Where their approach worked I borrowed it.
Where it didn't, the diffs are documented above and in `progress.md`.

- **[Dadoum / anisette-v3-server](https://github.com/Dadoum/anisette-v3-server)**
  — the headless anisette server that produces Apple's per-device OTP
  headers. Docker image used as-is; absolute prerequisite for any GSA
  flow.
- **[musaspacecadet / icloud-auth](https://github.com/musaspacecadet/icloud-auth)**
  — the iCloud SRP reference. Shape of the request/response cycle was
  cleaner here than in most other places. Their `libsrp.py` is what
  alerted me to the K-padding bug (see Finding #1 — their version
  *does* pad, but a derivative I started from didn't).
- **[MathewYaldo / Apple-GSA-Protocol](https://github.com/MathewYaldo/Apple-GSA-Protocol)**
  — clearest single description of the Grand Slam endpoint I've found.
  Used as the canonical reference for `cpd`-block shape and
  authentication flow ordering.
- **JJTech's Apple Private API notes** — referenced throughout the
  community for the SPD-decryption key labels (`"extra data key:"`,
  `"extra data iv:"`).

The two scripts that I wrote alongside this POC (`auth/gsa_xcode.py`
and `auth/mzfinance_auth.py` in the parent `ipadecrypt` workspace)
are not included here because they predate the cleaned-up
single-file approach.

---

## Ethics / scope

This is **research code against my own account**. It does not crack
anything cryptographic, defeat any DRM, bypass any payment, or
impersonate any other user. Everything it does is the same protocol a
licensed Apple Configurator client does, plus carefully-documented
unsuccessful variations.

The point is to understand a protocol surface and document where it
intentionally walls off non-Apple clients. If you use this against
accounts you don't own or to ship anything that touches Apple's
infrastructure beyond research limits, that's on you, not me.

---

## Status & roadmap

- [x] Working GSA SRP + SPD + 2FA chain
- [x] Documented the iOS-binary wall on the Mac path
- [x] Polished single-file Python prototype
- [ ] Apple TV proxy capture (blocked on tvOS-compatible pinning bypass)
- [ ] Analysis of captured `itunesstored` traffic → decide replay feasibility
- [ ] (Stretch) Replay-from-Mac if the captured handshake doesn't carry device-cert signatures
- [ ] (Stretch) Port the working auth flow into a Go library

This repo is also my **record of work** for this exploration — each
significant commit corresponds to a concrete finding or attempted
direction. If you're reading this from a future session, start at
`progress.md` and the latest commit messages.

---

## About me

I built this to teach myself Apple's auth fabric end-to-end and to
have a concrete artifact that proves what I learned. If you're hiring
for protocol reverse-engineering / security research / native iOS &
macOS internals work and this kind of write-up matches what you need:

- GitHub: [@vagvalas](https://github.com/vagvalas)

Happy to walk through any section in depth.

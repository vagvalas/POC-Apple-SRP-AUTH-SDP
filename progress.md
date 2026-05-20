# tvOS download — progress, 2026-05-20

Living hand-off document for the `tvos-prototype/` work. Read this before doing
anything else when resuming.

---

## 0. Goal

`ipadecrypt` is a Go end-to-end FairPlay decrypter for App Store IPAs. It works
for iOS today. We want to extend it so it can also produce **encrypted tvOS
IPAs on disk** (the decrypt-on-device step comes later, separately).

Concretely: given a tvOS app's bundle-id / adam-id, save a `.ipa` whose
`Info.plist` says `DTPlatformName=AppleTVOS`, `UIDeviceFamily` contains `3`,
and whose binary is `arm64-apple-tvos`.

We are NOT trying to do tvOS decrypt yet — that's a separate next step.

---

## 1. The big picture in one paragraph

We got **authentication working all the way through**: GSA SRP-6a → encrypted
session data (SPD) decrypted → 2FA push triggers on the trusted device → user
enters the 6-digit code → `/grandslam/GsService2/validate` accepts it. The
account ends up holding a valid GSA session and a validated `X-Apple-Identity-Token`.

We can then call `MZFinance.woa/wa/volumeStoreDownloadProduct` and receive a
valid CDN URL plus sinfs. **But the binary at that URL is always the iOS one**
(YouTube example: we want v4.54.01, Apple keeps serving v21.20.4). Changing
`deviceClass=AppleTV`, the storefront's platform digit, the User-Agent, sending
an Apple TV UA on the *download* call, calling `buyProduct` first — none of it
flips the served binary. The wall isn't "I can't authenticate"; it's "Apple
will not serve the tvOS binary to a session whose cookies were minted by the
Configurator-UA authenticate flow, which is the only UA the edge lets through
on the public auth endpoints".

The pivot, as of 2026-05-20: proxy-capture an actual jailbroken Apple TV
talking to Apple, so we can see exactly what `itunesstored` sends that we
aren't sending. That's blocked right now because SSL Kill Switch 2 0.14
(needed to bypass cert pinning on the TV) is incompatible with tvOS 11.4.1
itunesstored — App Store stops working when SKS2 is enabled.

---

## 2. The path that **works** end-to-end (authentication)

This entire chain is implemented in `tvos-prototype/tvos_download.py`. It's
reproducible from a cold start (no cached state needed) up through "got a
download URL". The bug is *what's at the download URL*.

### 2.1 Local anisette server

- Docker `dadoum/anisette-v3-server` runs on `localhost:6969`. Container name
  `anisette-v3`. Already running on the dev machine.
- `GET http://localhost:6969/` returns a JSON with the device-identity headers
  plus the time-bound OTPs: `X-Apple-I-MD`, `X-Apple-I-MD-M`,
  `X-Apple-I-MD-RINFO`, `X-Apple-I-MD-LU`, `X-Mme-Device-Id`, `X-Apple-I-SRL-NO`,
  `X-Apple-I-Client-Time`, `X-Apple-I-TimeZone`, `X-Apple-Locale`,
  `X-MMe-Client-Info`.
- Our `AnisetteSession` class fetches once at session start to bind the
  identity headers (`X-Mme-Device-Id`, `X-Apple-I-MD-LU`, etc) and re-fetches
  per-call for the OTPs only. The identity must stay stable across init → complete
  → validate or Apple rejects with `ec=-22410`.

### 2.2 GSA SRP-6a — init + complete

- Library: `pysrp` (`srp._pysrp`) with `rfc5054_enable()` + `no_username_in_x()`.
  **Don't** use the local `libsrp.py` from `auth/` — its `K = SHA256(min_bytes(S))`
  doesn't pad S to the modulus length and silently produces a wrong key in many
  runs. pysrp pads correctly.
- Endpoint: `POST https://gsa.apple.com/grandslam/GsService2`
- User-Agent: **`Xcode`** (akd/1.0 returns 503 here; only Xcode UA is whitelisted
  for the GSA endpoint).
- `X-MMe-Client-Info: <MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>`
- Init body (`o:init`): SRP `A` bytes, `ps: [s2k, s2k_fo]`, the email as `u`,
  and a full `cpd` dict containing anisette identity + OTPs + flags
  (`bootstrap`, `icscrec`, `pbe:false`, `prkgen`, `svct:iCloud`).
- Response: `sp` (protocol), `s` (salt), `B`, `c` (challenge id), `i` (iter count).
- Derive password: PBKDF2-HMAC-SHA256 of `SHA256(password)` (hex-encode first if
  `sp == s2k_fo`), with `salt`, `iterations`, length 32.
- Set `usr.p = derived_password`, call `usr.process_challenge(salt, B)` → M1.
- Complete body (`o:complete`): `c`, `M1`, `u`, fresh `cpd` (OTPs refreshed, identity
  stable).
- Response: `M2` (server proof), `spd` (AES-CBC encrypted session data),
  optional `Status.au`.

### 2.3 Verify M2 (don't skip this)

```python
usr.verify_session(r2["M2"])
if not usr.authenticated():
    raise SystemExit("K mismatch")
```

Without this step you get an InvalidFileException from plistlib when you try
to parse the SPD plaintext — because your K is wrong, the AES decrypt
produces gibberish, plistlib fails, and you spend an hour thinking the bug is
in plist parsing instead of SRP math.

### 2.4 SPD decrypt

- Session key K = `usr.get_session_key()` (pysrp gives you the post-PAD SHA256).
- AES key = `HMAC-SHA256(K, b"extra data key:")`
- AES iv = `HMAC-SHA256(K, b"extra data iv:")[:16]`
- AES-CBC decrypt, PKCS#7 unpad.
- The plaintext is a **bare `<dict>…</dict>` XML fragment** (no `<?xml…<plist…>`
  envelope). plistlib auto-detect rejects this; we strip the loose pad bytes and
  try `plistlib.loads` with `fmt=FMT_XML` explicitly. Implemented as a candidate
  loop in `decrypt_spd()` — see code for the exact fallback.

What SPD contains:
- `DsPrsId`: the numeric dsid, e.g. `XXXXXXXXXXX` (an 11-digit Apple account id).
- `adsid`: a UUID-style id, e.g. `XXXXXX-XX-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
- `GsIdmsToken` / `GsIdToken`: the long-lived auth token.
- `t`: a dict of per-service GSA tokens (~19 entries on a 2FA-required session
  the values are short; on an already-trusted session the SPD is ~13 KB instead
  of ~3 KB and `t` has full tokens for each service).
- `url`, `status-code`, `sk`, `acname`, `countryCode`, `fn`/`ln` (name), etc.
- For 2FA-needed sessions, `Status.au == "trustedDeviceSecondaryAuth"` is set
  on the GSA response itself (NOT inside SPD).

### 2.5 2FA push trigger

- Endpoint: `GET https://gsa.apple.com/auth/verify/trusteddevice`
- Headers: `User-Agent: Xcode`, `X-Apple-Identity-Token: base64(<adsid>:<GsIdmsToken>)`,
  plus anisette OTP headers.
- **Returns 401 even on success.** The push is sent server-side as a consequence
  of the SRP complete returning `au=trustedDeviceSecondaryAuth`; the trigger GET
  is more like a "click to resend hint" than the actual cause. All five variants
  we tried (DsPrsId-identity, adsid-identity, with and without anisette) returned
  4xx, yet the push *always* arrived on the trusted device. So: log the status
  for diagnostics and proceed regardless.

### 2.6 2FA code submission — the original blocker, now solved

- Endpoint: `GET https://gsa.apple.com/grandslam/GsService2/validate`
- Headers: `security-code: <6 digits>`, `X-Apple-Identity-Token: <token>`,
  `User-Agent: Xcode`, anisette OTPs, `X-MMe-Client-Info`, `X-Apple-App-Info: com.apple.gs.xcode.auth`.
- **The key finding**: `X-Apple-Identity-Token` must be built from **`adsid`**,
  not `DsPrsId`. Direct evidence:
  - `base64(DsPrsId:GsIdmsToken)` → HTTP 401, empty body.
  - `base64(adsid:GsIdmsToken)` → HTTP 200, ec=0.
  - The original `auth/gsa_xcode.py` POC tried 5 variants on push trigger but
    submitted with only one (adsid in newer revisions; mixed in earlier ones).
    The `ec=-22410` everybody was seeing was either anisette mismatch OR
    DsPrsId-identity submission.
- After a 200/ec=0, the GSA session is authenticated. Apple may also return
  one or more `X-Apple-GS-Token` response headers — we capture them but they
  haven't been needed downstream so far.

### 2.7 Already-trusted shortcut

On the second run after a fresh 2FA, the SRP complete returns `Status.au == ""`
(empty) instead of `trustedDeviceSecondaryAuth`. Skip the push and prompt
entirely; the identity token from SPD is immediately valid. Useful when
iterating.

---

## 3. Where it stops working — the download

### 3.1 What we send

```
POST https://p29-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=<MAC>
Content-Type: application/x-apple-plist
User-Agent: Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6
iCloud-DSID: <DSID>
X-Dsid:      <DSID>
X-Apple-Store-Front: 143448-6,34
X-Apple-Identity-Token: <validated adsid token>
Cookie: <all cookies from /tmp/mzfinance_result.json>
   incl. mz_at_ssl-<DSID>, mz_at0_fr*, pldfltcid, tv-pldfltcid, wosid-lite, hsaccnt, X-Dsid, itspod

plist body:
  creditDisplay     = ""
  guid              = <MAC>
  salableAdamId     = 544007664        (YouTube)
  pricingParameters = "STDQ"
  deviceClass       = "AppleTV"
```

### 3.2 What Apple returns

`HTTP 200` with `songList[0]` populated. URL is valid. **But the metadata
inside the response says iOS**:

```
softwareVersionBundleId = 'com.google.ios.youtube'
bundleShortVersionString = '21.20.4'         # iOS YouTube
kind = 'software'
playlistName = 'Google'
```

The actual tvOS YouTube is on the 4.x line (v4.54.01 per iTunes Search with
`entity=tvSoftware`). 21.x is iOS. **We've been downloading the iOS YouTube
every time we tested**, including all three existing `_tvOS.ipa` files on disk
at the repo root (which the user had wrongly labeled `_tvOS`).

---

## 4. Why this is a wall, not a bug we can fix from the Mac

The cookie set we're sending to MZFinance came from
`MZFinance.woa/wa/authenticate` (this is what `auth/mzfinance_auth.py` did, and
its result is at `/tmp/mzfinance_result.json`). That `authenticate` call was
sent with the `Configurator/2.17 …` User-Agent. Apple stamps the resulting
session as iOS device-class. The per-request `deviceClass=AppleTV` and
storefront `-6` are merely hints — Apple gives priority to the session's
device-class.

### 4.1 Edge-block probe

We probed every plausible User-Agent against both candidate authenticate URLs:

| UA | `MZFinance.woa/wa/authenticate` | `auth.itunes.apple.com/auth/v1/native/fast` |
|---|---|---|
| `Configurator/2.17 (Mac …)` | **200** (with `x-apple-plist` or `xml`; form returns 403) | 200 |
| `iTunes/12.10.7 (Apple TV; tvOS 13.4)` | 403 (edge-blocked, empty body) | 403 |
| `iTunes-AppleTV/12.6.0 (4; 32GB; dt:174)` | 403 | 403 |
| `AppleTV6,2/15.6 (19M65) CFNetwork/1240.0.4 Darwin/20.6.0` | 403 | 403 |
| `appstored/1 CFNetwork/…` | 403 | 403 |
| `itunesstored/1.0 tvOS/17.0 model/AppleTV6,2 …` | 403 | 403 |
| `iTunes/12.13.6.2 (Macintosh; OS X 14.3)` | 403 | 403 |
| `akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0` | 403 | 403 |
| `Xcode` | (not tested, but presumed: no, this is for GSA not the store) | n/a |

**Only `Configurator/2.17` gets past Apple's edge on the App Store auth
endpoints.** This is hard-coded server-side. We can't fake an Apple TV UA.

### 4.2 What we tried after that proves it's locked

- **Apple TV UA on the *download* call only** (keep Configurator cookies):
  Apple returned `HTTP 200, m-allowed: false, customerMessage: "AMD-Action:volumeStoreDownloadProduct:SP"` —
  "Sign-in required (Prompt)". The cookies' device-class trumps the per-request UA.
- **Apple TV UA on a fresh `MZFinance.woa/wa/authenticate`**: HTTP 403 at the
  edge. Never reaches the application layer.
- **`buyProduct(deviceClass=AppleTV)` to try to mint a tvOS license**:
  `failureType=2034` ("Sign In to the iTunes Store") — the iOS-class
  passwordToken can't create a tvOS-class license.
- **Pure GSA without Configurator cookies** (just identity-token):
  `failureType=5002` ("LicenseAlreadyExists") on download — Apple sees the
  account already owns the app (iOS license) and refuses to serve a
  different-platform binary.
- **Apple TV bag** (`init.itunes.apple.com/bag.xml` with Apple TV UA): the
  Apple TV bag has 222 keys but **no `authenticateAccount`** entry. tvOS
  devices appear to authenticate via private framework calls, not a public
  HTTP endpoint.
- **All combinations of the above**: same outcomes.

### 4.3 The structural reason

Apple TV's `itunesstored` authenticates the device using **FairPlay
certificates** baked into the device's secure enclave. There is no public HTTP
endpoint we can call from a Mac that produces "tvOS-class" session cookies,
because no public endpoint accepts non-Configurator UAs and Configurator =
iOS by Apple's design. The tvOS device's identity is bound to its hardware.

---

## 5. Code that exists right now

```
tvos-prototype/
├── README.md                      ← prototype overview, install steps, sanity output
├── progress.md                    ← THIS FILE
├── requirements.txt               ← cryptography, srp (pysrp 1.0.22)
├── config.py                      ← gitignored creds (your Apple ID + password)
├── .gitignore
├── .venv/                         ← python3 -m venv .venv
├── tvos_download.py               ← end-to-end pipeline; everything is here
└── proxy-capture/
    ├── README.md                  ← Apple-TV-side setup (mitmproxy + SKS2 + proxy config)
    └── mitm_capture.py            ← mitmproxy addon that dumps Apple flows to capture.jsonl
```

`tvos_download.py` flow (chronological):

1. `load_config()` → credentials from `config.py` (or prompt).
2. `lookup_app(target, country)` → iTunes Search for `entity=tvSoftware`.
   Note: this returns iOS metadata for shared adam-ids; we warn but proceed.
3. `AnisetteSession(localhost:6969)` → identity headers + OTP fetcher.
4. `gsa_authenticate(email, password, ani)` → SRP init → derive → process_challenge
   → complete → `verify_session(M2)` → decrypt SPD → return dict with
   `dsid`, `idms_token`, `adsid`, `identity_token_dsid`, `identity_token_adsid`,
   `status_au`, full `spd`.
5. `handle_2fa(auth, ani)` if `Status.au` contains `secondaryAuth` →
   `gsa_trigger_push()` (best effort) → input code → `gsa_submit_code()` trying
   `DsPrsId:` then `adsid:` identity tokens. Records which one worked.
6. `load_configurator_session('/tmp/mzfinance_result.json')` or
   `run_appletv_authenticate()` (the latter blocked by 403 at edge — kept for
   completeness; defaults to Configurator session).
7. `mzfinance_buy(deviceClass=AppleTV)` if `--buy` flag set. Currently returns 2034.
8. `mzfinance_download(deviceClass=AppleTV, sf=…-6, identity-token, cookies)` →
   gets a 200 with iOS binary. Aborts early if it detects iOS via
   bundleId + version pattern (no more 250 MB false positives).
9. Saves session snapshot to `/tmp/tvos_session.json`.

Files dumped during a run:
- `/tmp/tvos_spd.json` — decrypted SPD (with bytes b64-encoded).
- `/tmp/tvos_download_raw.bin` — raw plist response from the download call.
- `/tmp/tvos_buy_raw.bin` — raw plist response from buyProduct (when --buy).

---

## 6. The pivot — proxy-capture a real Apple TV

User has an unc0ver-jailbroken Apple TV 4K (A10X) on tvOS 11.4.1, with SSH
access. Same LAN as the Mac. Plan in `tvos-prototype/proxy-capture/README.md`.

### 6.1 What we want to learn from the capture

Concretely:
- What URL does `itunesstored` POST to for authenticate? (`MZFinance.woa/wa/authenticate`
  with a different UA? `auth.itunes.apple.com/auth/v1/native/fast`? Something
  we haven't found?)
- What headers? Especially anything starting with `X-Apple-FairPlay-`,
  `X-Apple-Tisk`, `X-Apple-Device-`, `X-Apple-AKE`, or signed body fields.
- Body format: plist (likely), JSON, form-urlencoded, or signed binary?
- Cookies the response sets — names and structure. Anything with `tv-` prefix?
  Anything we don't already have from Configurator?
- Request flow ordering — does it call `buyProduct` before `volumeStoreDownloadProduct`?
  Does it hit a "device commit" endpoint?

If the auth body contains a signed device certificate or a FairPlay-derived
challenge response, we're done — the Mac can't replay that. If the auth body is
plain (just email/password/2FA) with only the UA differing, we can replay
from Mac.

### 6.2 The blocker right now

mitmproxy can't decrypt itunesstored's traffic without a TLS-pinning bypass
on the device. **A user-installed CA is not enough** (Apple's itunesstored
pins by public-key fingerprint, independent of the trust store). We need a
substrate tweak.

**Attempted:** SSL Kill Switch 2 0.14 (the iOS 11 .deb).

- Installed with `dpkg -i --force-architecture --force-depends` (forced past
  arch tag `iphoneos-arm` vs system `appletvos-arm64`, and past missing
  `mobilesubstrate`/`preferenceloader` declarations since they exist under
  different names on unc0ver tvOS).
- Toggle appeared in Settings (via PreferenceLoader).
- **Enabling it → itunesstored fails on next launch.** App Store shows
  "Cannot connect to the App Store. Check your internet connection."
- **Disabling it + respring → App Store works again.** Reproducible.

So SKS2 0.14 is genuinely incompatible with `itunesstored` on tvOS 11.4.1.
Either the dylib's hook is wrong for tvOS's TLS stack, or there's a
secondary check in itunesstored that goes off when `SecTrustEvaluate` always
returns success.

### 6.3 Next tweaks to try (in order)

1. **SSL Kill Switch 3** — `https://julioverne.github.io/`. Newer fork,
   typically built clean for arm64. Install via same
   `dpkg -i --force-architecture --force-depends` if it's tagged iphoneos.
2. **NoMoreTrust** — `https://alexandrosk.github.io/`.
3. **TrustMe** by leptos-null — `https://leptos-null.github.io/`.

Test sequence for each candidate:
1. Install + enable + respring SpringBoard.
2. **Without** proxy configured on the TV, open App Store. Should still work.
   If it doesn't → tweak is incompatible, disable and try next.
3. If it works: start mitmproxy on Mac, configure TV proxy, retry App Store.
4. If App Store works through the proxy, we're in business.

### 6.4 Once we have a working bypass

```sh
# On Mac:
cd /Users/vaggosval/ipadecrypt/tvos-prototype/proxy-capture
mitmweb --listen-host 0.0.0.0 --listen-port 8080 \
        --set web_open_browser=true \
        -s mitm_capture.py \
        --save-stream-file flows.mitm
```

Then on the TV: Settings → Network → Wi-Fi → Configure Proxy → Manual →
`<Mac LAN IP>:8080`. Trigger a free tvOS app download (e.g. VLC for Apple TV)
that the account doesn't currently own. Capture finishes. Restore TV proxy to
Off. Send `capture.jsonl` back here.

### 6.5 Proxyman vs mitmproxy

User asked whether Proxyman's `.cer` install path achieves the same thing.
Answer: yes for the CA-trust foundation (same as mitmproxy), but **NO** for
the pinning bypass. Pinning is a separate concern that's solved on the device
side with a substrate tweak — independent of whether the Mac proxy is
Proxyman or mitmproxy. Either is fine; the current setup uses mitmproxy and
the addon `mitm_capture.py` is mitmproxy-specific.

---

## 7. If the proxy path also fails

Two structural fallbacks if no tvOS-11 pinning bypass works:

A. **Build SSL Kill Switch from source for `appletvos-arm64`.** Requires
   Theos + an arm64 toolchain + the tvOS 11 SDK headers. Workable but a 2-3
   hour rabbit hole.
B. **Skip the proxy and run a small native tool on the TV via SSH** that
   uses the TV's *existing* keychain / FairPlay credentials to do the
   download itself, then SCP the IPA back. The user explicitly does NOT want
   the production tool to download via the TV, but for *one-time research*
   into "what does Apple actually require for tvOS download" it's the
   shortest path to certainty.

If both A and B prove impractical, the conclusion is firm: tvOS App Store
downloads cannot be done from a Mac with public endpoints, full stop. At that
point the scope decision is: either descope tvOS from ipadecrypt entirely,
or build a "download via tvOS device" mode in addition to the existing
iOS-download mode.

---

## 8. Open questions

- Does `auth.itunes.apple.com/auth/v1/native/fast` accept a `deviceClass` or
  `softwarePlatform` body field that would stamp the resulting session
  differently? We have it 200-ing with Configurator UA + plist body; never
  exercised it with real creds to see.
- Does the user's existing `mz_at_ssl-<dsid>` cookie ever expire? It's now
  >24h old from the last successful Configurator authenticate. If it expired,
  re-running `auth/mzfinance_auth.py` will re-mint it (needs fresh 2FA code).
- Is the "iOS-stamped" theory correct? The proxy capture will confirm: if a
  real Apple TV's session cookies have different names or a `tv-` prefix
  beyond what Configurator gives us, theory holds. If they look identical
  cookie-wise to Configurator's set, the device-class info is somewhere else
  — maybe a header on the request, maybe a body field.

---

## 9. Useful exact paths and commands

**Run the prototype:**

```sh
cd /Users/vaggosval/ipadecrypt/tvos-prototype
source .venv/bin/activate
python3 tvos_download.py 544007664        # YouTube, GR account; auto-detects via configurator session
# Aborts before download if it detects iOS metadata.
```

**Re-authenticate (Configurator iOS) if cookies expire:**

```sh
cd /Users/vaggosval/ipadecrypt
python3 auth/mzfinance_auth.py           # prompts for 2FA
# Writes /tmp/mzfinance_result.json
```

**Inspect last SPD:**

```sh
python3 -c "import json; print(json.dumps(json.load(open('/tmp/tvos_spd.json')), indent=2))" | head -80
```

**Inspect last download response (when it failed):**

```sh
python3 -c "import plistlib, json; d = plistlib.loads(open('/tmp/tvos_download_raw.bin','rb').read()); print(json.dumps(d, indent=2, default=str))"
```

**Anisette server status:**

```sh
docker ps | grep anisette
curl -s http://localhost:6969 | python3 -m json.tool
```

**Apple TV SSH:** default user is `root`. Password depends on your jailbreak —
unc0ver/checkra1n typically leave the default `alpine`; change it to something
saner if you haven't already.

**Test accounts:** put your own creds in `config.py`. Personal identifiers in
this document are scrubbed; concrete values you'll see in your own run will be
specific to your account (the protocol behavior is the same regardless).

---

## 10. Decisions baked in

- **pysrp**, not the local `libsrp.py`. The local copy doesn't pad S for K.
- **`adsid:GsIdmsToken`**, not `DsPrsId:GsIdmsToken`, for `X-Apple-Identity-Token`
  on `/grandslam/GsService2/validate`.
- **User-Agent `Xcode`** for `gsa.apple.com`. **`Configurator/2.17 …`** for
  `buy.itunes.apple.com`. Don't mix.
- **`X-MMe-Client-Info: <MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>`**
  on GSA calls.
- **Don't send `X-Token`** on the consumer-style download — it triggers VPP
  checks that 5002 us out.
- **Don't trust `/auth/verify/trusteddevice` returning 401** — push fires regardless.
- **Always `verify_session(M2)`** before decrypting SPD.
- **The Configurator session at `/tmp/mzfinance_result.json` is iOS-stamped.**
  Don't expect it to ever serve tvOS, no matter what hints you add.

---

## 11. Where someone resuming this should start

1. Read this file end-to-end.
2. Check whether `auth/gsa_xcode.py`, `auth/mzfinance_auth.py`, and the
   `tvos_download.py` script still run cleanly — Apple changes endpoint
   contracts every few months and the SRP body shape sometimes drifts.
3. If they do: the next concrete action is to get a working pinning-bypass
   tweak on the Apple TV (SKS3 / NoMoreTrust / TrustMe). Section 6.3.
4. After capture: analyze `capture.jsonl`, particularly any flow whose
   host is `auth.itunes.apple.com` or `buy.itunes.apple.com`, especially
   `*/authenticate` and `*/volumeStoreDownloadProduct`. Look for headers
   we don't currently send.
5. Based on what's in the capture, decide: replay possible from Mac, or
   not.

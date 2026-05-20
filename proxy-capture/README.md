# Apple TV traffic capture for tvOS App Store replay

Goal: capture exactly what `appstored` on a real jailbroken Apple TV sends to
`buy.itunes.apple.com` when downloading a tvOS IPA, so we can analyze and
hopefully replay those requests from the Mac.

## Your setup (recorded)

- Apple TV 4K, A10X SoC, tvOS 11.4.1, **unc0ver** jailbreak (Cydia installed)
- Mac running mitmproxy
- Same Wi-Fi / subnet
- SSL pinning bypass: **not yet installed** (will use SSL Kill Switch 2)

## Safety notes

- **Do NOT respring or reboot during capture** if you don't have to. Re-jailbreaking unc0ver after a reboot can be flaky.
- **Take a snapshot of `/var/jb` or your tweak list** (`dpkg -l > /var/mobile/tweaks.txt`) so you can restore if something goes wrong.
- SSL Kill Switch 2 is a passive hook — it only patches `SecTrustEvaluate` family. Removing it is clean. Won't damage your jailbreak.
- mitmproxy doesn't modify traffic by default (we'll run it in `--mode regular`). Just observes.

---

## Step 1 — Install mitmproxy on the Mac

```sh
brew install mitmproxy
mitmproxy --version  # expect 10.x+
```

Or via pip if you prefer:

```sh
pip install --user mitmproxy
```

Find the Mac's LAN IP (the Apple TV will need this):

```sh
ipconfig getifaddr en0   # Wi-Fi
# or: ipconfig getifaddr en1 (wired)
```

Pick a port — `8080` is conventional.

## Step 2 — Start mitmweb with the capture filter

From this directory:

```sh
cd /Users/vaggosval/ipadecrypt/tvos-prototype/proxy-capture
mitmweb \
  --listen-host 0.0.0.0 \
  --listen-port 8080 \
  --set web_open_browser=true \
  -s mitm_capture.py \
  --save-stream-file flows.mitm
```

What this does:
- `--listen-host 0.0.0.0` — accept connections from the Apple TV on your LAN.
- `mitm_capture.py` — the addon (in this folder) that filters/logs only the
  relevant Apple endpoints to `capture.jsonl` for easy analysis.
- `--save-stream-file flows.mitm` — saves the raw flows so we can re-load
  them later with `mitmproxy --rfile flows.mitm`.

Open `http://localhost:8081` in your browser — that's the live UI.

Leave this running. You'll see a `Listening on http://0.0.0.0:8080` line.

## Step 3 — Install SSL Kill Switch 2 on the Apple TV

Add the repo in Cydia (if it isn't already added):

```
https://julioverne.github.io/  
```

Or use the canonical one:

```
https://repo.skitty.xyz/
```

Or sideload manually — the .deb is here:
- https://github.com/nabla-c0d3/ssl-kill-switch2/releases  
  pick the latest `.deb`; works on iOS/tvOS 9 through 14.

To install via SSH if you prefer:

```sh
# from the Mac:
scp com.nablac0d3.SSLKillSwitch2_0.14.deb root@<APPLE_TV_IP>:/tmp/
ssh root@<APPLE_TV_IP> 'dpkg -i /tmp/com.nablac0d3.SSLKillSwitch2_0.14.deb'
```

After install: respring (in Cydia, or `killall SpringBoard` from SSH).

**Verify it's active:** Settings → SSL Kill Switch 2 → toggle should say "Enabled".  
On tvOS the Settings entry should appear in `Settings → Apps` (varies by tweak version). If you can't find a UI, the tweak is active if it's installed — it hooks at boot.

## Step 4 — Install the mitmproxy CA on the Apple TV

With SSL Kill Switch 2 active, **you technically don't need the CA installed at all** — SSL Kill Switch disables all certificate validation, including pinning. But install the CA anyway as a belt-and-suspenders measure (some Apple frameworks check the CA before the pinning kicks in).

Generate the CA file from the running mitmproxy (it's at `~/.mitmproxy/mitmproxy-ca-cert.pem` on the Mac after first launch):

```sh
ls ~/.mitmproxy/
# expect: mitmproxy-ca-cert.pem, mitmproxy-ca.pem, mitmproxy-dhparam.pem
```

Push it to the Apple TV's trust store:

```sh
scp ~/.mitmproxy/mitmproxy-ca-cert.pem root@<APPLE_TV_IP>:/private/etc/ssl/certs/
ssh root@<APPLE_TV_IP> 'ls -la /private/etc/ssl/certs/ | head'
```

(If `/private/etc/ssl/certs/` doesn't exist, the system trust store on
tvOS 11 lives at `/private/etc/ssl/cert.pem` as a bundle — append:

```sh
ssh root@<APPLE_TV_IP> 'cat - >> /private/etc/ssl/cert.pem' < ~/.mitmproxy/mitmproxy-ca-cert.pem
```

Be careful — keep a backup of the original `cert.pem` first.)

## Step 5 — Point the Apple TV at the proxy

On the Apple TV:

1. Settings → Network → Wi-Fi → (highlight your network) → **Configure Proxy**
2. Choose **Manual**
3. Server: `<MAC_LAN_IP>` (the address from Step 1)
4. Port: `8080`
5. Save.

Trip-wire check: open a web app on the TV that hits HTTPS (e.g. browse the App Store). You should see flows appearing in the mitmweb UI. If you see TLS errors instead of decrypted traffic, SSL Kill Switch 2 isn't taking effect for that process — recheck the install.

## Step 6 — Trigger an App Store download

The capture moment. Best target is a **free tvOS app you don't own yet** —
that exercises the *entire* flow: authenticate, license-mint, download.

Suggestions:
- "VLC for Apple TV" (com.videolan.vlc-ios on tvOS)
- "Plex" (com.plexapp.plex on tvOS)
- Any free game in the App Store

Steps:
1. Open the App Store on the Apple TV.
2. Search for the target app.
3. Tap **Get** / **Install**.
4. Watch mitmweb flow list grow. You'll see hits to:
   - `gsa.apple.com` (likely — if appstored does GSA auth on first session)
   - `buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate`
   - `buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct`
   - `buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct`
   - `https://...phobos.apple.com/.../*.ipa` (the CDN URL)
5. Wait for the download to finish (or at least the auth + buyProduct calls).
6. Stop mitmweb with `Ctrl-C`.

`flows.mitm` and `capture.jsonl` are now in this folder.

## Step 7 — Restore Apple TV networking (important)

After capture is done, **turn off the proxy on the Apple TV** so it doesn't keep trying to reach your Mac when mitmproxy isn't running:

Settings → Network → Wi-Fi → (network) → Configure Proxy → **Off**.

Leave SSL Kill Switch 2 installed — it doesn't hurt anything and makes future
captures easy.

## Step 8 — Send me the capture

Once you have `capture.jsonl`, paste it (or just the relevant parts) here. I'll
look at:

- What URL `appstored` uses for authenticate (matches `auth/v1/native/fast`, or different?)
- What `User-Agent`, `X-Apple-*` headers it sends — especially anything starting with `X-Apple-FairPlay-` or `X-Apple-Tisk`
- The exact body shape (plist? JSON? form-urlencoded?)
- What cookies Apple sets in the response
- Whether there are device-specific tokens we'd need (and can read off the device once)

Then we either:
- Replay the same requests from the Mac with whatever device tokens are needed → **win**.
- Find out the requests are signed with a device cert that can't leave the TV → **wall**, and we close this chapter.

---

## File layout

```
proxy-capture/
├── README.md            ← this file
├── mitm_capture.py      ← mitmproxy addon: filters/dumps Apple flows to capture.jsonl
└── flows.mitm           ← raw flow archive (created during capture)
└── capture.jsonl        ← one-line-per-request structured dump (created during capture)
```

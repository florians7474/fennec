# Fennec — Project State

Fennec is a web-based launcher (Flask, fullscreen) that runs several
Wi-Fi / network pentest tools from a single Raspberry Pi 5 with a
touchscreen. Each tool is independent but chainable, driven from tiles.

Repo (public): github.com/florians7474/fennec
Local folder on the Pi: ~/console  (SSH: ssh florian@fennec.local)

## Legal scope
Offensive actions (cracking, Bjorn scan, connecting) are only allowed on
a user-declared whitelist of networks, identified by BSSID
(liste_blanche.json, not tracked in git). Pwnagotchi wide capture stays free.
Ethernet access = implicit authorization (physical act), so the BSSID lock
only applies to Wi-Fi.

## Hardware

### Owned / final build
- Raspberry Pi 5, Raspberry Pi OS 64-bit desktop (hostname fennec, user florian)
- Screen: Waveshare 3.5" RPi LCD (C), resistive touch, 480x320, high-speed SPI
  (the reference portable display profile; install.sh downloads its overlay,
  configures the framebuffer, kiosk, and calibrated touch input — see Install below)
- Wi-Fi USB adapter (monitor mode, required — Pi 5 built-in chip can't do it):
  Alfa AWUS036AXM (MediaTek MT7921AU), plugs straight into USB. Auto-detected
  by Fennec (first wlan* whose phy advertises monitor mode), no config needed.
- GPS: VK-162 USB GPS module (waterproof, for the Map / wardriving module —
  tags each captured network with its position)

### Test gear
- Alfa AWUS036ACH (Realtek RTL8812AU) — validated in monitor mode as wlan1,
  used as the test adapter

## Ports
Fennec :5000 · Pwnagotchi :8080 · Bjorn :8000

## Modules
| Module | Role | Status |
|--------|------|--------|
| Pwnagotchi | Handshake capture (jayofelony fork) | Done (install + control + head display) |
| Bjorn | LAN scan/attack (infinition/Bjorn) | Done (install + control + live console) |
| Sly | Offline WPA cracking (custom) | Done (9-stage engine + intelligence base, tested live); GPU export to polish |
| Connexion | Join a whitelisted network | Done (real nmcli connect/disconnect on the built-in interface; key from the whitelist or a saved profile; multi-band matched by SSID) |
| Sentry | Network radar + per-device traffic watch | Done (ARP scan, per-device port scan/type, device naming, live traffic monitoring via bettercap MITM with saved history, DNS capture via on-demand dnsmasq, Force DNS against DoT/DoH, and VPN detection) |
| Map | Map of geolocated captures, then wardriving (WiGLE-style) | Phase 1 done (GPS geolocation of handshakes, tested outdoors); phase 2 wardriving to do |
| Hugin | Bjorn companion: surfaces Bjorn's results, Metasploit correlation (by CVE and by service), deported execution via RPC with live sessions | Phases 1-2-3 done and validated end to end |

Pwnagotchi and Bjorn run "behind" Fennec: installed on the Pi, started/stopped
by their tile via systemd services kept disabled at boot (sudoers rules allow
florian to systemctl start/stop them without a password). Sly and Hugin are
coded in-house.

## Connection, scan and lists
- Header badge: shows the Pi's real connection, read live from nmcli — Ethernet,
  Wi-Fi + SSID, or Offline. On the kiosk home it refreshes itself every few
  seconds via /connection/state (the kiosk never reloads the page), so it follows
  a cable being unplugged or a Wi-Fi being joined without a reload. Ethernet takes
  priority when both are up, so it never claims a Wi-Fi when the Pi is on Ethernet.
- Connection page (opened by the header badge): lists the whitelisted networks and
  connects/disconnects the Pi over Wi-Fi for real, via nmcli on the built-in
  interface (wlan0), keeping the USB adapter free for monitor mode. A network is
  connectable when a key is stored in the whitelist or the Pi already knows it (a
  saved profile, e.g. from imaging); otherwise its row shows "no key". Before
  connecting, the helper clears any stale profile for that SSID, frees the
  interface and rescans all bands (so a target on another channel/band is found).
  The connected network is matched by SSID, so a multi-band box shows
  Connected/Disconnect on the right row. Backed by sudo helpers
  fennec-wifi-connect / fennec-wifi-disconnect.
- On-screen keyboard (static/keyboard.js): a self-contained touchscreen keyboard
  that pops up on any text field (Wi-Fi key, device rename…), since the kiosk has
  no physical keyboard. Included on the pages that take input.
- Allowed networks (liste_blanche.json, gitignored): the BSSID whitelist, with
  per-entry key, inline edit, and a Clear all that empties it.
- Scan page, two tabs:
  - Direct scan: a live nmcli scan stored as a snapshot (scan_direct.json,
    gitignored). "Scan" from Allowed networks runs it; "Rescan" refreshes it;
    Clear all empties the snapshot (it stays empty until the next scan).
  - Spotted by Pwnagotchi: lists the .pcap captures; Clear all deletes them via
    a small sudo helper (/usr/local/bin/fennec-clear-handshakes).
- All Clear all buttons use an in-page 480x320 confirm dialog, not the browser's
  native popup (which is unusable on the kiosk touchscreen).
- Bjorn's stopped screen names the network and /24 subnet it will scan (or asks
  to connect when offline), so the target is obvious before pressing Start.
- Bjorn Wi-Fi start gate: Bjorn only starts on Ethernet (a cable is a deliberate
  authorization) or when the connected Wi-Fi SSID is in the whitelist (any band of
  that network); otherwise Start is refused with a message. Enforced in the toggle
  route before the service is started.
- Power button (top-right of the header): an in-page dialog offers Lock screen,
  Reboot and Shut down. Reboot/Shut down post to /power/<action>, which runs
  sudo systemctl reboot|poweroff (exact-path rules in fennec.sudoers). Lets the
  kiosk be powered off from the touchscreen, no keyboard or SSH needed.
- Lock screen (nomadic use): a full-screen overlay (Fennec logo + a looping
  Wi-Fi fill animation) that swallows every touch, so accidental presses while
  the Pi is in a bag do nothing and no running module is stopped. Purely
  client-side (home.html), no backlight change — the running capture/GPS keep
  going underneath. Unlock is a deliberate slide-to-unlock (pointer drag past a
  threshold), so random bag contact can't release it.

## Sentry (device radar)
- Real ARP scan of the current /24 via nmap -sn, run as root by a dedicated
  sudo helper (/usr/local/bin/fennec-netscan, allowed in fennec.sudoers). Needs
  root so nmap returns MAC addresses + vendor (OUI).
- Each device: IP, MAC, vendor. The Pi (own IP) is tagged "This Pi", the default
  gateway "Router"; both are excluded from the unknown count.
- Mine vs unknown is keyed by MAC (stable across IP changes), stored in
  mes_appareils.json (gitignored). One tap on an "Unknown" chip marks it mine.
- Unknown devices sort to the top; header shows "N devices · M unknown".
- Scans on open; "Rescan" reloads.
- Tap a device -> detail (vigie_detail.html): a top-100 TCP port scan
  (nmap -sT -F, rootless connect scan, no sudo), open ports + services, a
  device-type guess from the ports then the vendor, hostname (reverse DNS),
  MAC and vendor. Last scan cached in _dernier_scan so the detail doesn't
  re-sweep the whole subnet; if the cache is empty, the MAC is read from the
  ARP table (ip neigh) so naming and history still work.
- Rename a device (pencil on the detail): the custom name is saved per network
  (noms_appareils.json, gitignored), keyed by network id (gateway MAC) + device
  MAC, so it survives rescans and is scoped to that network. It shows in the list
  and the detail.
- Traffic watch ("Watch" button): starts a MITM of the whole subnet via bettercap
  (/usr/local/bin/fennec-monitor, sudo) to reveal the domains each device
  contacts. It runs as an exclusive mode (stops Pwnagotchi/Bjorn/Sly, and they
  stop it). The capture script runs two sources on the forwarded traffic: tshark
  (TLS SNI, QUIC destination) and an on-demand dnsmasq the Pi redirects port 53 to
  (dedicated nat chain VIGIE_DNS), which answers and logs every cleartext DNS query
  per device. The engine vigie_monitor.py reads both, keyed by device IP, and
  tolerates non-UTF8 bytes. bettercap, dnsmasq and the DNS redirect are all torn
  down on Stop and on Fennec exit (atexit), so the network is never left under ARP
  spoofing or without DNS.
- Traffic history is persistent: domains per device are kept in
  historique_trafic.json (gitignored), scoped per network, each with a last-seen
  timestamp shown as "X ago". The detail shows the saved history even when the
  monitor is off, and merges live domains while it runs. Flushed to disk at most
  every ~20s and on Stop, to spare the SD card.
- Force DNS (amber toggle, only while watching): /usr/local/bin/fennec-dns-force
  (sudo) adds a FORWARD chain VIGIE_FORCE that REJECTs DoT (port 853) and the main
  public DoH resolvers (port 443, curated IP list), pushing a hardened device back
  onto cleartext DNS so dnsmasq can log it. Reverted on toggle-off and on Stop.
- VPN detection: tshark also passes VPN control packets only (rare, not the data
  flood) — WireGuard handshake, ISAKMP (IPsec/IKEv2/L2TP on UDP 500/4500) and
  OpenVPN hard-reset/control — and the protocol column labels the tunnel. A device
  seen tunnelling is flagged on its detail page (type + reverse-resolved endpoint)
  instead of logging the endpoint as a contacted domain. A proprietary tunnel
  disguised as HTTPS/DTLS on 443 cannot be told apart from normal web traffic and
  is not labelled.
- Remaining limits: a full-tunnel VPN stays opaque by design (only the tunnel and
  its endpoint are shown); ECH and some QUIC leave the SNI unreadable; IPv6 is not
  MITM'd (ARP spoof is IPv4 only); a device in strict private-DNS mode may fail
  closed under Force DNS until it is turned off.

## Sly — cracking engine
Local cracking = aircrack-ng (stable on ARM, CPU). hashcat is NOT used locally
(segfaults on the Pi's PoCL/OpenCL ARM backend); it is reserved for the GPU
export only. Sly is the smart orchestrator.

### Pi constraints (hard rules)
- Everything in flux (pipes) or in RAM (/dev/shm), no large wordlist written
  to the SD card.
- Only tiny files on disk: the box-profile knowledge base and the run log.
- Everything else stays in RAM.

### Honesty guardrail
Sly reveals WEAK keys. On a modern box with a random factory key it passes
quickly, concludes "probably sound", and points to the GPU export. It never
promises to crack long random WPA2.

### Intelligence = knowledge base (not self-learning)
The intelligence comes from external knowledge about how boxes and humans make
weak keys, not from Sly's own (rare) successes. At launch Sly reads the
BSSID (OUI -> vendor) and the ESSID, queries the local box-profile base, and
derives a targeted plan. Key point: you cannot deduce password length/shape
from the hash (PBKDF2 destroys it) — the only possible narrowing comes from
knowing the target.

Sources now integrated:
- Box-profile base: profils_box.json (prefix ESSID -> vendor/model/algo),
  routed to routerkeygen-cli (compiled in /usr/local/bin/routerkeygen-cli).
  An ESSID flagged "ignore" (e.g. community hotspot) skips the factory stage.
- ESSID profiling: raton_essid_gen.py mutates words extracted from a custom
  network name (case, leet, suffixes, name+digits), capped at 100k, written to
  /dev/shm so aircrack keeps a real counter and progress bar.
- Real cracked keys: SecLists probable-v2-wpa-top4800 (tiny, WPA-specific).
- Rules: John default --rules on the 10k list (OneRule too heavy for the Pi CPU).

### Stage plan (escalation, stops as soon as a key falls)
9 stages, in order:
1. Factory default keys (profils_box.json + routerkeygen)
2. ESSID profiling (custom-name words + mutations; skipped if the name is generic)
3. Real cracked keys (probable-wpa-top4800)
4. Birth dates (DDMMYYYY / YYYYMMDD)
5. 10k common passwords
6. Keyboard patterns
7. 10k common + John mutation rules
8. John incremental, 1h cap
9. rockyou random (shuf), 1h cap

Stages 8 and 9 are long "deep" passes with a TIME gauge (0% -> 100% over 1h,
hard stop via a watchdog thread). Short stages show the key counter + bar;
the time stages show mm:ss / 60:00 and the live candidate, not a key count.

Length filter: every stage feeds aircrack only candidates of 8..63 chars
(WPA minimum), via awk on the pipe or a filtered /dev/shm copy, so no invalid
short candidate is ever shown or tested.

### Already done on Sly
- 9-stage escalation built, reordered, and tested live on a real Bbox.
- Robustness score recalibrated for the 9 stages: stage where the box falls =
  its grade (Critical / Very weak / Weak / Moderate / Robust).
  _robustness_score() in raton_engine.py, shown on result.
- Auto key write: a cracked key is written back into the whitelist by BSSID
  (route /cracking/state in app.py).
- GPU export: /cracking/export/<bssid> converts the .pcap to .hc22000
  (hcxpcapngtool) and returns the hashcat command; "GPU" button -> crack_gpu.html.
- Robust stdout reading (errors="replace") so a non-UTF8 byte from aircrack no
  longer freezes a stage.
- install.sh now folds all Sly deps (routerkeygen build, hcxtools, John,
  wordlists: 10k-common, probable-wpa-top4800, rockyou).
- No-handshake guard: before cracking, Sly checks the capture really holds a
  4-way handshake (aircrack-ng). If not, the Test button is greyed out in the
  capture list ("· no handshake") and the result reads "No usable handshake"
  instead of a misleading "Robust". Presence is cached per file (mtime + size).

### Work left on Sly
- Clearer GPU export — one-click handoff, so the user has nothing to copy:
  - a download button for the already-generated .hc22000 file
  - a ready command pointing at that file + a known wordlist, e.g.
    hashcat -m 22000 fennec_<box>.hc22000 rockyou.txt -r best64.rule
  - optionally a one-click script (crack.sh / crack.bat) that fetches the
    wordlist if needed and launches hashcat, so there is zero manual step

## Hugin — Bjorn companion
Hugin is to Bjorn what Sly is to Pwnagotchi: it turns Bjorn's raw output into
something readable, then adds Metasploit correlation and (deported) execution.
Raven mascot (Odin's Huginn, "thought").

### Phase 1 — surface Bjorn's results (done)
- Reads Bjorn's own files under ~/Bjorn/data: netkb.csv (devices, ports, per-device
  action status), livestatus.csv (global counts), and output/ (scans,
  vulnerabilities, cracked credentials, stolen data).
- Device list with alive state and open-port / action counts.
- Per-device detail: open ports with service names, vulnerabilities (from
  vulnerability_summary.csv), Bjorn actions with status and date, and the files
  linked to that device (matched by IP/MAC), with preview and download.
- Global file explorer by category, with text preview and secure download (paths
  confined to Bjorn's output dir).

### Phase 2 — Metasploit correlation (done; local, no Metasploit needed)
Two complementary layers, both local (no Metasploit install, nothing running on
the Pi):
- By CVE: ships a compact CVE->modules index (hugin_msf_index.json, ~0.5 MB) built
  from Metasploit's module metadata. For each CVE Bjorn found on a device, lists the
  candidate modules (type, rank).
- By open service: Bjorn's vuln scan rarely yields clean CVEs, but the ports it maps
  are already a real attack surface. A built-in table maps detected services to
  well-known modules (e.g. vsftpd 2.3.4 backdoor on FTP, Samba usermap_script on
  SMB, login scanners on SSH/Telnet/MySQL/PostgreSQL/VNC). This lights up from the
  open ports alone, no CVE required.
Both layers are candidates only, never a confirmed vulnerability.

### Phase 3 — deported execution (done; validated end to end)
Metasploit never runs on the Pi. It runs on a separate lab machine
(msfrpcd -P <pass> -S); the Pi talks to it over the network with a small
msgpack-RPC client (python3-msgpack).
- Brick 1: guided connection screen — auto-detect the host (nmap on port 55553),
  enter the RPC password, connect, live state. Config stored locally in
  msf_config.json (gitignored).
- Brick 2: per-module attack plan — a pre-filled .rc (use + RHOSTS, and RPORT for
  service-based modules) viewable and downloadable from each candidate module.
- Brick 3: run a module via RPC with explicit confirmation, watch for an opened
  session, and record the result; Activity screen with history. The Run button is
  disabled until Metasploit is connected. Service-based runs pass the detected RPORT.
- Live sessions: the machine page lists the sessions held by the remote msfrpcd and
  runs a command inside one over RPC (shell or meterpreter), output shown inline —
  e.g. `id` returning `uid=0(root)`. The session lives in the daemon; the Pi only
  drives it.
Validated end to end against a lab target: Bjorn discovery -> service correlation ->
Run (Samba usermap_script) over RPC -> root session, driven from Fennec.
Lab use only, on explicitly authorized targets.

## Install (showcase)
One command on a fresh Pi: git clone the repo, then ./install.sh (idempotent,
adapts to any user/path; generates a random bettercap password; nothing
sensitive in the repo). Installs Fennec, Pwnagotchi, Bjorn (clone + dedicated
venv + systemd services), and all Sly deps (routerkeygen, hcxtools, John,
nmap, and the wordlists 10k-common / probable-wpa / rockyou fetched from
SecLists). Fennec itself is installed as a systemd service (enabled at boot),
and the Waveshare 3.5" touchscreen is set up end to end so it lights up on its
own on a fresh Pi.
Notes:
- Display profiles: the installer asks which display to configure, or reads
  FENNEC_DISPLAY (waveshare35c, cuqi35, hdmi, or headless). The Waveshare 3.5-inch RPi
  LCD (C) profile downloads the vendor overlay, enables SPI, configures its /dev/fb0
  framebuffer for X11, calibrates the ADS7846 touch input, and starts the Chromium
  kiosk through tty1 auto-login. The cuqi35 profile is for the CUQI 3.5-inch RPM-01
  (sold with a Pi 5 case): a generic 480x320 SPI panel (ILI9486 + XPT2046) that is
  driver-compatible with the Waveshare (C), so it reuses that exact config (verified
  on hardware, display and touch). The HDMI profile starts the same kiosk without SPI
  configuration. Headless mode keeps only the network interface. Reboot once after
  installation when using a local display.
- Fennec service: system/fennec.service runs app.py as the install user with
  FENNEC_DEBUG=0, enabled at boot (WorkingDirectory = the repo folder).
- On Raspberry Pi OS Trixie, routerkeygen's qmake may default to Qt6; if the
  CLI build fails on a fresh Pi, force Qt5 (qmake -qt5).
- Bjorn's upstream requirements.txt pins old versions (e.g. Pillow 9.4.0) that
  do not build on Python 3.13; install.sh installs from a pinned
  system/bjorn-requirements.txt instead (Pillow 11.1.0).
- Bjorn needs more than its 15 upstream deps on Python 3.13 / Trixie: the
  display/GPIO stack (gpiozero, lgpio, rpi-lgpio, colorzero) for the e-paper
  init, and legacy-cgi because Python 3.13 removed the stdlib cgi module.
  python3-dev is installed so netifaces (sdist only) compiles.
- SPI is enabled by the installer (raspi-config nonint do_spi 0); without it
  /dev/spidev0.0 is missing and Bjorn crashes on e-paper init. Reboot once
  after install so it takes effect.
- Bjorn's web server is patched at install time (allow_reuse_address + a fixed
  port 8000): upstream jumps to 8001 on a quick Stop/Start because the port is
  still in TIME_WAIT, which breaks the embedded view. The patch keeps it on 8000.
- Sentry uses small sudo helpers installed to /usr/local/bin: fennec-netscan
  (nmap ARP sweep), fennec-monitor (bettercap MITM + tshark + on-demand dnsmasq),
  fennec-dns-force (Force DNS: block DoT/DoH) and fennec-clear-handshakes (delete
  Pwnagotchi captures). Each is granted by an exact-path rule in fennec.sudoers,
  so no broad sudo is given.
- Connection uses two more sudo helpers, fennec-wifi-connect (clears a stale
  profile, frees wlan0, rescans, then nmcli connect) and fennec-wifi-disconnect,
  granted the same exact-path way in fennec.sudoers.
- Bjorn runs web-only here, so its e-paper helper is replaced at install time by
  system/bjorn-epd_helper.py (copied over ~/Bjorn/epd_helper.py): a no-op stand-in
  that never claims GPIO. Without it Bjorn aborts with "GPIO busy" because the
  e-paper driver wants pins the Fennec touchscreen already uses.

## Dev loop
Edited directly on the Pi and pushed from there.
Editing any project file: nano ~/console/<file>.

## Other work left (outside Sly)
- Wi-Fi lock: done. Step 2 (real Connexion via nmcli) and step 3 (Bjorn start
  gate) are both in — see "Connection, scan and lists" above. The connection page
  joins/leaves a whitelisted Wi-Fi for real, and Bjorn refuses to start on a
  non-whitelisted Wi-Fi (Ethernet stays free).
- Sentry DNS capture (v3): done. During a Watch the Pi is the network's DNS
  resolver (dnsmasq + port-53 redirect), with a Force DNS toggle against DoT/DoH
  and VPN detection (WireGuard, OpenVPN, IPsec/IKEv2). v1 (device radar) and v2
  (per-device port scan/type,
  naming, traffic watch via MITM with saved history) were already done.
- Map phase 1: done. The Pwnagotchi GPS plugin writes a .gps.json next to each
  handshake when a fix is available, and the Map tile plots them (colour-coded
  by whitelist status, tap to add to the whitelist). The plugin is enabled in
  config.toml ([main.plugins.gps], device /dev/ttyACM0) and install.sh patches a
  bug in it (it replaced ".pcapng" while bettercap writes ".pcap", which made it
  overwrite the handshake instead of writing the .gps.json). Markers sit at the
  capture position (where the Pi was), not at the access point.
- Map phase 2: build the full wardriving map (map every network even without a
  handshake, via airodump-ng + GPS) and add offline map tiles for nomadic use.
- Nomadic Wi-Fi reconnection: NetworkManager now retries autoconnect forever
  (/etc/NetworkManager/conf.d/wifi-retry.conf, installed by install.sh), so the
  Pi rejoins its network on its own when it comes back in range without a reboot.
- Hugin: optionally refresh the Metasploit CVE index from the upstream repo via
  install.sh, and extend the service->modules table as new targets come up.
- Hugin phase 4 (later): combined Bjorn + Hugin reports, export, cross-session
  history, and the future "Audit" orchestrator.

## Known issues
- While Sentry's Watch (MITM) is active, all LAN traffic routes through the Pi,
  so SSH and the UI can lag; it recovers once you Stop. Starting another mode or
  quitting Fennec stops it automatically.

# Fennec — Project State

Fennec is a web-based launcher (Flask, fullscreen) that runs several
Wi-Fi / network pentest tools from a single Raspberry Pi 5 with a
touchscreen. Each tool is independent but chainable, driven from tiles.

Repo (public): github.com/florians7474/fennec
Local folder on the Pi: ~/console  (SSH: ssh florian@fennec.local)

## Legal scope
Offensive actions (cracking, Bjorn scan, connecting) are only allowed on
a user-declared whitelist of networks, identified by BSSID
(whitelist.json, not tracked in git). Scoutchi wide capture stays free.
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
- GPS: VK-162 USB GPS module (waterproof, for the Echo / wardriving module —
  tags each captured network with its position)

### Test gear
- Alfa AWUS036ACH (Realtek RTL8812AU) — validated in monitor mode as wlan1,
  used as the test adapter

## Ports
Fennec :5000 · Bjorn :8000 · bettercap API (Scoutchi) :8081

## Modules
| Module | Role | Status |
|--------|------|--------|
| Bjorn | LAN scan/attack (infinition/Bjorn) | Done (install + control + live console) |
| Sly | Offline WPA cracking (custom) | Done (9-stage engine + intelligence base, tested live; guided GPU export) |
| Mirage | Evil-twin AP + captive portal, takes over when Sly's offline crack fails | Done (SSID clone of a whitelisted target, DHCP + DNS catch-all, captive-portal web layer with a built-in theme library + custom-ZIP upload, live client view, `iw`-based WPA2/WPA3/PMF detection, deauth via bettercap gated on PMF + a second monitor adapter, handshake capture handed to Sly) |
| Connexion | Join a whitelisted network | Done (real nmcli connect/disconnect on the built-in interface; key from the whitelist or a saved profile; multi-band matched by SSID) |
| Sentry | Network radar + per-device traffic watch | Done (ARP scan, per-device port scan/type, device naming, live traffic monitoring via bettercap MITM with saved history, DNS capture via on-demand dnsmasq, Force DNS against DoT/DoH, and VPN detection) |
| Echo | Map of geolocated captures + wardriving (WiGLE-style) | Done (GPS geolocation of handshakes and wardriving, both validated outdoors; offline tiles, on-screen GPS badge, Sly verdict overlay) |
| Hugin | Bjorn companion: surfaces Bjorn's results, Metasploit correlation (by CVE and by service), deported execution via RPC with live sessions | Phases 1-2-3 done and validated end to end |
| Mole | Wired drop box: capture + crack LAN credentials over Ethernet, plus active relay | Phase 1 done and tested on the Pi (Responder capture + nmap map + John jumbo crack + report). Phase 2 (mitm6 + ntlmrelayx relay) built, untested — home net is a workgroup, needs a lab domain |
| Scoutchi | Wide handshake harvester (bettercap): PMKID + 4-way capture with continuous deauth, one or two adapters, plus GPS tagging and wardriving | Done, the sole capture module. Replaced Pwnagotchi, which is archived in archive/pwnagotchi/ |
Bjorn runs "behind" Fennec: installed on the Pi, started/stopped by its tile via a
systemd service kept disabled at boot (sudoers rules allow florian to systemctl
start/stop it without a password). Scoutchi, Sly and Hugin are coded in-house.

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
- Allowed networks (whitelist.json, gitignored): the BSSID whitelist, with
  per-entry key, inline edit, and a Clear all that empties it.
- Scan page, two tabs:
  - Direct scan: a live nmcli scan stored as a snapshot (scan_cache.json,
    gitignored). "Scan" from Allowed networks runs it; "Rescan" refreshes it;
    Clear all empties the snapshot (it stays empty until the next scan).
  - Captured handshakes: lists the .pcap captures; Clear all deletes them via
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
  Rotate screen, PIN code, Logs, Reboot and Shut down. Reboot/Shut down post to
  /power/<action>, which runs sudo systemctl reboot|poweroff (exact-path rules in
  fennec.sudoers). Lets the kiosk be handled from the touchscreen, no keyboard or
  SSH needed.
- Remote-access PIN: the web UI is open on the local touchscreen (requests from
  localhost are exempt) but asks for a 6-digit PIN from any other device on the
  network. Set/changed/removed from the power menu (localhost only); stored
  hashed (pbkdf2) in settings.json; 5 wrong tries trigger a short lockout. While
  no PIN is set, nothing changes. FENNEC_DEBUG defaults to off so the Werkzeug
  debugger is never exposed.
- Journal (power menu -> Logs): one page listing recent events newest-first
  (time, module, level). Tiles show a red dot when a systemd-backed module
  (Bjorn, Mirage) crashes. Besides lifecycle events, "attention"
  (amber) signals flag anomalies that are not errors (empty wardrive, captures
  without a GPS fix, no usable handshake, Metasploit unreachable). An Alerts
  filter shows warnings and errors only. Capped at the last 200 (events.json).
- Lock screen (nomadic use): a full-screen overlay (Fennec mascot) that swallows
  every touch, so accidental presses while the Pi is in a bag do nothing and no
  running module is stopped. Purely client-side (home.html), no backlight change —
  the running capture/GPS keep going underneath. Unlock is a deliberate
  press-and-hold (fills a bar over ~1.2 s), so random bag contact can't release it.
- Home tile grid: paginated like a phone home screen; the current page is
  remembered (sessionStorage), so returning from a module lands back on the page
  whose tile opened it instead of jumping to the first page.
- Network list ordering: the whitelist shows saved-key networks first (then
  alphabetical); the connection page shows the connected network first, then the
  ones you can connect to, then the rest.

## Mirage — evil twin
Takes over when Sly's offline crack fails: clone a whitelisted SSID, lure the
clients onto the twin, and collect the key (captive portal) or the handshake (for
Sly). Whitelisted targets only.
- AP + portal: hostapd rogue AP on the USB adapter cloning the target SSID,
  dnsmasq for DHCP and a DNS catch-all, and a small web layer serving the captive
  portal. DFS 5 GHz channels are remapped to channel 36 so hostapd can start.
  Live client view from the dnsmasq leases; captured passwords listed as they
  arrive. Backed by sudo helpers fennec-mirage-ap / fennec-mirage-portal.
- Portal library: built-in captive pages under system/mirage-portals/<slug>
  (Default, Hotel, Station — each in English and French), installed to
  /opt/fennec-mirage/portals and applied in one tap (fennec-mirage-portal-manage
  apply <slug>). Each page keeps the same form (POST / with a `password` field)
  and success page, so only text and design change; the capture backend is
  untouched. On-screen preview per theme, a custom portal can still be uploaded as
  a ZIP, and a starter template (the working default) is downloadable so a custom
  page can't accidentally drop the password form.
- Security detection: resolved from a real `iw` scan (sudo helper
  fennec-wifi-scan, JSON out), which sees every nearby AP — unlike nmcli, which
  only reports a handful when the station interface is busy — and reads the RSN
  info: WPA2 (PSK) vs WPA3 (SAE) vs WPA2/WPA3 transition, and whether PMF is
  required or merely capable. The scan runs in a background thread so the page
  never blocks. Networks in the Mirage list show their real security tag.
- Deauth: optional bettercap deauth on a second monitor adapter, gated on PMF —
  allowed unless PMF is required (so WPA2 and transition qualify, pure WPA3 does
  not), rather than on the SSID label. The deauth forces reconnections, and the
  same bettercap run records the resulting 4-way handshake to Sly's folder
  (/etc/pwnagotchi/handshakes/<ssid>_<bssid>.pcap), so a captured handshake shows
  up in Sly ready to crack. A live "Handshake for Sly" line reports whether a
  crackable handshake exists for the current target.

## Sentry (device radar)
- Real ARP scan of the current /24 via nmap -sn, run as root by a dedicated
  sudo helper (/usr/local/bin/fennec-netscan, allowed in fennec.sudoers). Needs
  root so nmap returns MAC addresses + vendor (OUI).
- Each device: IP, MAC, vendor. The Pi (own IP) is tagged "This Pi", the default
  gateway "Router"; both are excluded from the unknown count.
- Mine vs unknown is keyed by MAC (stable across IP changes), stored in
  my_devices.json (gitignored). One tap on an "Unknown" chip marks it mine.
- Unknown devices sort to the top; header shows "N devices · M unknown".
- Scans on open; "Rescan" reloads.
- Tap a device -> detail (vigie_detail.html): a top-100 TCP port scan
  (nmap -sT -F, rootless connect scan, no sudo), open ports + services, a
  device-type guess from the ports then the vendor, hostname (reverse DNS),
  MAC and vendor. Last scan cached in _dernier_scan so the detail doesn't
  re-sweep the whole subnet; if the cache is empty, the MAC is read from the
  ARP table (ip neigh) so naming and history still work.
- Rename a device (pencil on the detail): the custom name is saved per network
  (device_names.json, gitignored), keyed by network id (gateway MAC) + device
  MAC, so it survives rescans and is scoped to that network. It shows in the list
  and the detail.
- Traffic watch ("Watch" button): starts a MITM of the whole subnet via bettercap
  (/usr/local/bin/fennec-monitor, sudo) to reveal the domains each device
  contacts. It runs as an exclusive mode (stops Scoutchi/Bjorn/Sly, and they
  stop it). The capture script runs two sources on the forwarded traffic: tshark
  (TLS SNI, QUIC destination) and an on-demand dnsmasq the Pi redirects port 53 to
  (dedicated nat chain VIGIE_DNS), which answers and logs every cleartext DNS query
  per device. The engine vigie_monitor.py reads both, keyed by device IP, and
  tolerates non-UTF8 bytes. bettercap, dnsmasq and the DNS redirect are all torn
  down on Stop and on Fennec exit (atexit), so the network is never left under ARP
  spoofing or without DNS.
- Traffic history is persistent: domains per device are kept in
  traffic_history.json (gitignored), scoped per network, each with a last-seen
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
- Box-profile base: box_profiles.json (prefix ESSID -> vendor/model/algo),
  routed to routerkeygen-cli (compiled in /usr/local/bin/routerkeygen-cli).
  An ESSID flagged "ignore" (e.g. community hotspot) skips the factory stage.
- ESSID profiling: raton_essid_gen.py mutates words extracted from a custom
  network name (case, leet, suffixes, name+digits), capped at 100k, written to
  /dev/shm so aircrack keeps a real counter and progress bar.
- Real cracked keys: SecLists probable-v2-wpa-top4800 (tiny, WPA-specific).
- Rules: John default --rules on the 10k list (OneRule too heavy for the Pi CPU).

### Stage plan (escalation, stops as soon as a key falls)
9 stages, in order:
1. Factory default keys (box_profiles.json + routerkeygen)
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
  (hcxpcapngtool); the "GPU" button opens crack_gpu.html, a guided handoff with
  a Download .hc22000 button and a ready-to-run hashcat command (file + wordlist
  + rules) with a Copy button. Nothing to retype.
- Robust stdout reading (errors="replace") so a non-UTF8 byte from aircrack no
  longer freezes a stage.
- install.sh now folds all Sly deps (routerkeygen build, hcxtools, John,
  wordlists: 10k-common, probable-wpa-top4800, rockyou).
- No-handshake guard: before cracking, Sly checks the capture really holds a
  4-way handshake (aircrack-ng). If not, the Test button is greyed out in the
  capture list ("· no handshake") and the result reads "No usable handshake"
  instead of a misleading "Robust". Presence is cached per file (mtime + size).

## Hugin — Bjorn companion
Hugin is to Bjorn what Sly is to Scoutchi: it turns Bjorn's raw output into
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

## Mole — drop box
Mole turns the "expert with three terminals" LAN credential attack into one tile.
Plug the Pi into a LAN over Ethernet, press Start, and the module coerces Windows
hosts into authenticating to it, captures their hashes, maps the subnet, and cracks
the captured hashes offline — then shows a short audit-style report: recovered
passwords, the accounts and domain seen, the hosts found, and a one-line verdict.
Mole mascot = a mole (burrowing animal and planted insider), fitting a wired implant.

### Authorization
Ethernet only: the tile refuses to start on Wi-Fi. Plugging in a cable is the
deliberate authorization, the same gate Bjorn uses on Ethernet. Lab use only, on
networks you own or are explicitly authorized to test.

### Architecture
- Orchestrator /usr/local/bin/fennec-mole (root, via fennec-mole.service, kept
  disabled at boot, started/stopped by the tile through sudoers). It detects the
  default-route interface, maps the /24 with `nmap -sn`, runs Responder
  (LLMNR/NBT-NS/mDNS poisoning + rogue WPAD + DHCP) to capture NetNTLMv2 hashes,
  and consolidates the captures into a world-readable /tmp/fennec-mole/hashes.txt.
- mole_engine.py reads the loot (hashes, nmap hosts, meta), de-duplicates accounts
  by (domain, user), computes the verdict, and runs the offline crack: one capped
  John pass (`--format=netntlmv2`, rockyou, --max-run-time) in a thread, parsed
  back with `john --show`.
- app.py routes: /mole (report page), /mole/toggle (Ethernet-gated start/stop,
  stops Sentry first so Responder can bind port 53), /mole/state (live JSON),
  /mole/crack (kick the offline crack). templates/mole.html renders the live report.

### Verdict (mirrors Sly's robustness score, for the LAN)
- Critical "Network: wide open" — a captured account was cracked (weak password).
- Warning "Credentials captured" — hashes caught, not cracked yet.
- Idle "Listening" / "Idle" — running with nothing captured yet / stopped.

### Active relay (phase 2)
An aggressive mode beside the capture Start, its own red "Relay" button, also
Ethernet-gated. Orchestrator /usr/local/bin/fennec-mole-relay (root, via
fennec-mole-relay.service, tile-driven): scans the /24 for SMB (445) hosts and any
domain controller (LDAP 389/636), runs mitm6 (rogue DHCPv6/DNS) to coerce WPAD, and
ntlmrelayx (impacket, in a dedicated /opt/mole-venv) to relay the coerced auth to
those targets, saving relayed hashes and SAM/domain dumps under /tmp/fennec-mole/relay.
Relay and capture bind the same ports, so starting one stops the other (and Sentry).
mole_engine.relay_snapshot() reports targets and loot; the screen lists them.

### Done
- Phase 1: orchestrator, engine, routes, tile, report page, sudoers, install repli,
  tested end to end on the Pi (capture a real NetNTLMv2 hash, crack a weak one with
  John jumbo, verdict). Responder (pinned, /opt/Responder) with python3-netifaces +
  python3-aioquic; John jumbo built to /opt/john (Debian john lacks netntlmv2).
- Phase 2 built: relay orchestrator, service, engine parsing, UI, install repli.

### To do
- Test phase 2 against a lab Active Directory (the home net is a workgroup, local
  accounts only, so the AD dump can't be exercised there yet).
- Tune the relay loot parsing to the real ntlmrelayx output once tested.
- Add a mole.png mascot to match the other tiles; wire the report to a file export
  and the planned VPS handoff.

## Scoutchi — handshake harvester
Scoutchi is Fennec's own capture module, built to replace Pwnagotchi with a lighter,
more aggressive harvester tuned for the Pi 5 and for roaming. It drives one or two
monitor-mode adapters with bettercap and writes its loot where Sly already reads
it, so cracking is unchanged. Fox mascot = Scoutchi, a hound that sniffs out and
retrieves handshakes.

### Why not Pwnagotchi
Fennec only used Pwnagotchi's capture engine; its e-paper face, reinforcement-learning brain and web UI
were disabled at install. Scoutchi keeps the capture, drops the rest, and adds PMKID
harvesting, dual-adapter coverage, and the GPS tagging and wardriving Pwnagotchi
used to provide. Pwnagotchi has been removed from the active install (no second
venv, no pwngrid build, no clone) and archived in archive/pwnagotchi/ for reference.

### Scope
Wide only: sweep every supported frequency (2.4 + 5 GHz) with continuous deauth
(bettercap ticker), harvesting PMKIDs and forcing 4-way handshakes automatically,
no interaction — the same wide, always-on behaviour as Pwnagotchi.
PMKID is clientless, so a drive-by also picks up networks with no connected client.
With two adapters both sweep in parallel. A targeted
evil-twin attack on one network is left to Mirage.

### Adapters
Capability-based detection, not brand-locked: Scoutchi lists the monitor-capable USB
interfaces (built-in wlan0 station excluded) and adapts. One adapter sweeps all
bands; a second, if plugged in, splits the bands (one on 2.4 GHz, one on 5 GHz) for
parallel coverage. The Scoutchi page shows a slot per adapter and a "plug a 2nd adapter"
hint when only one is present. Compatibility depends on the kernel driver supporting
monitor + injection (MediaTek MT76xx, Realtek RTL88xxAU via the DKMS driver, Ralink
RT2800/RT3070, Atheros AR9271).

MT7921U quirk: these combo Wi-Fi/Bluetooth adapters (0e8d:7961, e.g. Alfa AWUS036AXM)
reset-loop on the Pi because their Bluetooth function fails HCI_Reset (opcode 0x0c03
times out), resetting the whole USB device every few seconds, so the Wi-Fi never stays
up and the adapter slot flickers. install.sh ships a udev rule
(system/99-fennec-mt7921-no-bt.rules) that disables only that device's Bluetooth
interface (bInterfaceClass e0), targeted by VID:PID: the Wi-Fi works, and no other
adapter's Bluetooth nor the Pi's onboard Bluetooth is affected.

Pi 5 USB current cap: the Pi 5 limits total USB current to 600 mA unless it detects a
5A PSU, which brown-out-resets power-hungry Wi-Fi adapters (they enumerate, load
firmware, then disconnect in a loop; get_throttled can still read 0x0 because the Pi
rail itself is fine). install.sh adds usb_max_current_enable=1 to config.txt to lift
the cap. This assumes a capable supply - the official 27W (5V/5A) PSU is recommended;
on a weak supply the Pi may then under-volt instead. With the cap lifted, one adapter
(even a large amplified one) is stable; two power-hungry adapters at once can still
exceed the lifted budget, so dual-adapter operation needs a powered USB hub.

### Architecture
Built on bettercap, the same engine Pwnagotchi used, so capture and deauth run
together on a single adapter (two if present).
- Orchestrator /usr/local/bin/fennec-scoutchi (root, via fennec-scoutchi.service, disabled
  at boot, tile-driven through sudoers). Reads /tmp/fennec-scoutchi/config.json
  (adapters), sets the interfaces to monitor, and runs bettercap per adapter with:
  wifi.recon on (channel hopping), handshakes written per-AP (aggregate false) to a
  working dir (/tmp/fennec-scoutchi/live) that only bettercap touches, and a ticker
  firing wifi.deauth ff:ff:ff:ff:ff:ff every 10 s (continuous deauth of every AP).
  Card 1 carries bettercap's REST API, and (when a GPS receiver is wired) bettercap's
  GPS module, enabled on that card from the gps section of config.toml so position is
  available on the same API.
- fennec-scoutchi-poll (root) reads that REST API (APs seen plus the GPS fix) plus
  bettercap's working dir (what was captured this session, classified HS vs PMKID
  with hcxpcapngtool) and writes /tmp/fennec-scoutchi/stats.json, including a climbing
  deauth count. It is also the safe handoff to Sly: bettercap keeps re-appending to a
  per-AP file as it re-captures, so the poller publishes a stable copy into the
  handshakes dir Sly reads only once a file has settled (unchanged for one interval)
  and holds a real handshake or PMKID, copied atomically (temp + rename) so Sly never
  reads a half-written file. It also carries the GPS work Pwnagotchi used to do, so
  Echo works with Scoutchi alone: it writes a <capture>.gps.json next to each
  published handshake (its capture position) and maintains /etc/pwnagotchi/wardrive.json,
  the signal-weighted centroid of every AP seen with a fix — the same file and format
  Echo already reads, so the map needs no change.
- scoutchi_engine.py detects the adapters, starts/stops the service and reads the stats.
- app.py routes: /scoutchi (page), /scoutchi/toggle (start/stop the sweep, takes over the
  radio from the other modes), /scoutchi/state (live JSON).
  templates/scoutchi.html renders the mascot, the mode switch, the adapter slots, the
  counters (handshakes / PMKID / APs) and the live capture list.

### Validated on the Pi
- Capture is real: hcxpcapngtool reports EAPOL pairs/PMKID and writes a non-empty
  .22000; aircrack-ng accepts the handshake and cracks it. Sly runs end to end on a
  Scoutchi capture.
- read_handshakes now keeps the largest file per BSSID, so a stale small capture no
  longer hides the real one from Sly.
- Sly reads the real ESSID from the capture (not the filename), so the factory-key
  and ESSID stages match even when bettercap drops the hyphen from the filename.
- GPS and wardriving validated outdoors with the VK-162: a roaming run logged
  thousands of networks at real positions that tracked the route, wrote a .gps.json
  next to each captured handshake, and populated the wardrive map Echo reads — so Echo
  works from Scoutchi alone, with no Pwnagotchi.

### To do
- Stable per-session captures: done. bettercap now writes to a working dir only it
  touches; the poller publishes a settled, atomic copy into Sly's dir, so Sly never
  reads a file mid-write (removed the old race on the shared handshake file).
- GPS tagging and Echo wardriving are native to Scoutchi (bettercap GPS on card 1,
  .gps.json sidecars and wardrive.json written by the poller), validated outdoors on
  the Pi with the VK-162 fix. Pwnagotchi has been removed and archived.
- Sly's verdict is surfaced where it matters (Echo and the Sly list), not in
  Scoutchi: Scoutchi only harvests, so a crackable/robust tag there would be noise.
- Replace the estimated deauth count with bettercap's real deauth event count.

## Install (showcase)
One command on a fresh Pi: git clone the repo, then ./install.sh (idempotent,
adapts to any user/path; generates a random bettercap password; nothing
sensitive in the repo). Installs Fennec, bettercap and Bjorn (clone + dedicated
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
- routerkeygen-cli requires Qt5. The installer detects a Qt6 default qmake on
  Raspberry Pi OS Trixie and automatically falls back to Qt5.
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
  captured handshakes). Each is granted by an exact-path rule in fennec.sudoers,
  so no broad sudo is given.
- Connection uses two more sudo helpers, fennec-wifi-connect (clears a stale
  profile, frees wlan0, rescans, then nmcli connect) and fennec-wifi-disconnect,
  granted the same exact-path way in fennec.sudoers.
- Bjorn runs web-only here, so its e-paper helper is replaced at install time by
  system/bjorn-epd_helper.py (copied over ~/Bjorn/epd_helper.py): a no-op stand-in
  that never claims GPIO. Without it Bjorn aborts with "GPIO busy" because the
  e-paper driver wants pins the Fennec touchscreen already uses.

## Screen & UI
- Screen rotation: the power menu has a Rotate button that cycles the UI through
  0/90/180/270. It is a software rotation — a CSS transform injected into every
  HTML page by an after_request hook, plus a /rotate/toggle route — so it applies
  instantly, with no reboot and no touch recalibration (the browser remaps the
  touch coordinates with the transform). The choice is stored in settings.json
  (git-ignored, per-device) and survives restarts. In portrait (90/270) the body
  is pinned to 320x480 so the <html> flex box cannot warp the geometry, the home
  grid reflows to two columns, and the header drops the network name to keep only
  the Wi-Fi/Ethernet icon (green connected, grey not) so the power button stays
  reachable in the narrow header.
- Lock screen: a full-screen overlay for nomadic use that swallows accidental
  touches. Unlock is press-and-hold (a bar fills over ~1.2 s) instead of a slide,
  which is unreliable on the resistive panel.

## Dev loop
Changes are committed to this repository; the Pi pulls them with
`cd ~/console && git pull && sudo systemctl restart fennec`. Changes under system/
(helpers installed to /usr/local/bin, udev rules, service units) are not picked up by a
restart alone and need `sudo ./install.sh`.
Continuous integration (.github/workflows/ci.yml) runs on every push: it
compiles all Python, runs tests/smoke.py (imports the app and checks the main
routes return 200 plus the risk-level logic), and runs the pytest unit suite
(tests/test_*.py) covering the engine logic — Sly scoring/ESSID, Hugin
correlation and path confinement, Sentry parsing, the PIN and journal, the
Bjorn/Mirage security gates — plus regression guards (wardrive path, vigie
routes). The app degrades gracefully without hardware, nmcli or
handshake files, so the suite runs anywhere. It covers the web app only — not
live NetworkManager or Wi-Fi adapter behaviour, which has to be verified on the
Pi.
The local checkout on the Pi is still named ~/console (the repo was renamed
console -> fennec, the folder was not).

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
- Echo phase 1: done. Scoutchi's poller writes a .gps.json next to each handshake
  when a fix is available (bettercap's GPS module, enabled on card 1 from
  config.toml's [main.plugins.gps], device /dev/ttyACM0), and the Echo tile plots
  them (colour-coded by whitelist status, tap to add to the whitelist). Markers sit
  at the capture position (where the Pi was), not at the access point. (Originally
  the Pwnagotchi GPS plugin did this; Scoutchi now carries it, see the Scoutchi
  section.)
- Echo phase 2: done. Wardriving reuses bettercap instead of a separate
  airodump-ng (which would conflict over the single monitor interface): Scoutchi's
  poller polls bettercap's REST API every few seconds, reads every AP in range plus
  the current GPS fix, and appends them to
  handshakes/wardrive.json (keyed by BSSID; only logged when there is a real
  fix). It also records WPS and keeps an incremental signal-weighted centroid
  per BSSID, so a seen AP is plotted at its estimated real location, refined on
  each pass, not where the Pi stood. Echo merges these as grey "seen" points,
  deduped by BSSID against the handshake points. Two view modes toggle on screen:
  Status (whitelist/handshake/seen) and Risk — open/WEP = critical, WPS = weak,
  WPA2/3 = solid, unknown = grey, coloured only on observed facts. Real
  crackability overrides the heuristic: Raton persists its outcome per BSSID
  (raton_verdicts.json, robust/cracked), and the risk view shows that verdict
  first (robust = solid, cracked = critical), falling back to the heuristic only
  for untested networks; a captured handshake is treated as WPA2. A point's popup
  also spells the verdict out in words (key cracked / robust), and the Sly list
  tags each capture the same way, so a tested network is never re-run blindly.
  Offline tiles:
  Fennec serves map tiles from a local cache (tiles/ dir) through a /tiles proxy
  that reads from disk, else fetches from OSM and caches when online, else
  returns a light placeholder; Leaflet is vendored in static/ so the map needs no
  CDN; an "offline" button pre-downloads the visible area (bounded, run in a
  background thread with a /tiles/status poll). A /gps route plus a badge on
  Echo shows the live satellite fix on the device (for checking in the car without
  SSH). Centering fits the bulk of the points, dropping far outliers.
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
- Pure WPA3 targets (PMF required): Mirage leaves deauth disabled, and such a
  network yields no offline-crackable material (non-recoverable PMKID, protected
  4-way), so neither Sly nor any offline tool can test it. Use a WPA2 or
  WPA2/WPA3 transition target to exercise deauth and handshake capture.
- The UI is designed for a 480x320 landscape screen. In portrait it overflows
  horizontally; the whitelist edit modal is anchored and sized to stay usable
  with the on-screen keyboard, but full portrait layout support is not done.

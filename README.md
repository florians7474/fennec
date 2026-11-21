# Fennec 🦊

![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%205-c51a4a)
![Python](https://img.shields.io/badge/python-3.11%2B-3776ab)
![License](https://img.shields.io/badge/license-MIT-blue)
![Status](https://img.shields.io/badge/status-active-success)

A full-chain network audit and monitoring console on a Raspberry Pi 5.

Fennec turns a Raspberry Pi 5 and a touchscreen into a self-contained network auditing console that covers the whole chain. It starts in the air (Wi-Fi reconnaissance, handshake capture and GPS mapping), moves to offline WPA cracking, and once on the network it discovers the devices, identifies and tests their weaknesses, and watches the traffic in real time. Everything runs from a full-screen web interface of six tiles, one tool at a time, each module independent and started or stopped on demand straight from the screen.

It also works as a hands-on sandbox for learning offensive security end to end, from the air to post-access reconnaissance, exploitation and surveillance. The cracking stage aims at weak and default keys rather than brute-forcing strong WPA2. Use it only on networks you own or are explicitly authorized to test.

## Preview

https://github.com/user-attachments/assets/14991e5f-1f13-4fef-ae11-81ae7df54729

▶ **38-second demo** — the whole kill chain: capture → map → crack → breach → root → watch.

## Screens

<table>
  <tr>
    <td><img width="420" alt="Home — six modules" src="https://github.com/user-attachments/assets/a94f09ae-ccc2-4faf-8705-3449bebca135" /></td>
    <td><img width="420" alt="Sly — offline WPA cracking" src="https://github.com/user-attachments/assets/d2da69bf-743e-4b33-86ff-70e084117006" /></td>
  </tr>
  <tr>
    <td><img width="420" alt="Sentry — device radar & traffic watch" src="https://github.com/user-attachments/assets/04647c0f-e198-4b67-a706-9b4724b0c61f" /></td>
    <td><img width="420" alt="Hugin — exploit correlation" src="https://github.com/user-attachments/assets/81fb1444-7bd2-424d-9f2f-4a40d6107644" /></td>
  </tr>
</table>

## Modules

| Tile | Role | Status |
|------|------|--------|
| **Pwnagotchi** | Passive Wi-Fi handshake capture | ✅ Working |
| **Echo** | Captures, wardriving and attack-surface map by GPS location | ✅ Working |
| **Sly** | Offline WPA cracking on your own captures | ✅ Working |
| **Mirage** | Evil-twin AP to recover a Wi-Fi key when Sly's offline cracking fails | ✅ Working |
| **Bjorn** | Network reconnaissance and targeted attacks | ✅ Working |
| **Hugin** | Bjorn companion: results, Metasploit correlation (CVE + service), deported execution & live sessions | ✅ Working |
| **Sentry** | Network radar + per-device traffic watch | ✅ Working |
| **Mole** | Wired drop box: capture and crack LAN credentials over Ethernet | 🚧 In progress |

The header shows the Pi's live connection, Ethernet, Wi-Fi with its SSID, or Offline, and tapping it opens the connection manager: you scan for networks, pick the ones you are allowed to test, and connect the Pi to a whitelisted Wi-Fi or disconnect it (real nmcli on the built-in interface; the key comes from the whitelist or an existing profile, and a network answering on several bands is handled by SSID). An on-screen keyboard pops up on any text field, so keys and device names can be typed on the touchscreen without a physical keyboard. A power button in the top-right opens an on-screen menu to lock the screen, rotate the screen, set the remote-access PIN code, open the Logs, reboot, or shut down, so the Pi can be handled entirely from the touchscreen without a keyboard. Lock screen is for nomadic use: it covers the UI with the Fennec mascot and ignores every touch (so the Pi can ride in a bag while a capture runs), and only a deliberate press-and-hold brings the interface back.

All six modules are operational: automatic installation, control from the tile, and a live view inside the interface.

- **Pwnagotchi — passive capture.** Captures handshakes in the background and mirrors its head live in the tile.
- **Echo — map & wardriving.** Plots captured handshakes by GPS and logs every network merely seen during a run (passive, WiGLE-style, via bettercap), placing seen networks at a signal-weighted **estimated position** refined on each pass. Two on-screen views: **Status** (whitelist / handshake / seen) and **Risk** (open or WEP, WPS, WPA2/3), with a real Sly crack verdict overriding the guess. Map tiles are cached locally and work offline, with a live GPS badge and outlier-trimmed centring.
- **Sly — offline WPA cracking.** Runs a 9-stage escalation on your own captures (factory keys, ESSID profiling, known keys, dates, common passwords, keyboard patterns, mutation rules, then two one-hour deep passes) and grades the key's robustness, with a one-tap handoff to GPU cracking. Captures with no usable handshake are flagged, so a network is never wrongly reported as robust.
- **Mirage — evil-twin AP** (the follow-up when Sly can't crack the key). Clones the SSID of a whitelisted target on the USB adapter (hostapd), hands out DHCP and redirects every request to an onboard captive portal (dnsmasq catch-all), and lists the clients that join live. A built-in **portal library** ships ready-to-use captive pages (Default, Hotel and Station themes, each in English and French) that apply in one tap and can be previewed on screen; a custom portal can still be uploaded as a ZIP, and a starter template is downloadable so a custom page keeps the working password form. Security is read from a real `iw` scan, so a target is labelled accurately as WPA2, WPA3 or WPA2/WPA3 transition. An optional deauth (bettercap) pushes a target's clients toward the twin, allowed whenever management-frame protection is not required (so WPA2 and transition networks qualify, a pure WPA3/PMF network does not); the same deauth also records the resulting 4-way handshake into Sly's folder for offline cracking. Whitelisted targets only.
- **Bjorn — recon & targeted attacks.** Scans and probes the network the Pi is on, naming it and its subnet before you start, with a live console in the tile. On Wi-Fi it starts only for a whitelisted network; on Ethernet it starts freely, since plugging in a cable is itself a deliberate authorization.
- **Hugin — Bjorn companion** (what Sly is to Pwnagotchi). Reads Bjorn's results per device (ports, services, vulnerabilities, actions, files) and suggests Metasploit modules two ways — by CVE (local index) and by open service (service→module map) — flagged as candidates, with a ready-to-run `.rc` plan per module. Execution is **deported**: Metasploit runs on a separate lab machine driven over RPC (run a module, watch a session open, list sessions, run in-session commands). Lab use only, on authorized targets.
- **Sentry — device radar & traffic watch.** Scans the subnet (nmap ARP) and lists every device (IP, MAC, vendor) with unknowns surfaced and a one-tap "mine" chip; tap for detail (ports, guessed type, hostname). **Watch** mode turns it into a passive monitor (bettercap MITM) revealing the domains each device contacts (TLS SNI/QUIC via tshark, plus cleartext DNS via an on-demand dnsmasq), with timestamped per-network history, a **Force DNS** toggle against DoT/DoH, and VPN detection.
- **Mole — wired drop box.** Plug the Pi into a LAN over Ethernet, press Start, and it coerces Windows hosts into authenticating to it (Responder: LLMNR/NBT-NS/mDNS poisoning with a rogue WPAD proxy and DHCP), captures their NetNTLMv2 hashes, maps the subnet (nmap), and cracks the captured hashes offline with John. The screen reports recovered passwords, the accounts and domain seen, the hosts found, and a one-line verdict on the network. Ethernet is the authorization: plugging in a cable is a deliberate act. An aggressive **Relay** mode (mitm6 + ntlmrelayx) goes further: it coerces authentication and relays it to the network's SMB services, and to a domain controller when present, to dump accounts and Active Directory data. Lab use only, on authorized networks.
## Legal scope

Fennec is built to audit networks you own or are authorized to test. Offensive actions (cracking, targeted reconnaissance, exploitation) are restricted to networks you declare on a whitelist, identified by their BSSID: on Wi-Fi, Fennec only connects to and attacks whitelisted networks, and Metasploit execution runs on a separate lab machine, never on the Pi. The observation features only watch, they do not attack: passive air capture listens to the surrounding airspace like any Wi-Fi analyzer, and the traffic monitor inspects a network you are already connected to.

Only use this tool on networks you own or have written permission to test. Any other use is illegal.

## Hardware

- Raspberry Pi 5
- Display profile selected during installation: Waveshare 3.5-inch RPi LCD (C), HDMI kiosk, or headless
- USB Wi-Fi adapter with monitor mode (tested with an Alfa AWUS036AXM, MediaTek MT7921AU chipset)
- Optional: VK-162 USB GPS module (for the Echo / wardriving module)
- microSD card, 32 GB or more, Raspberry Pi OS 64-bit (desktop)

The Pi 5 built-in Wi-Fi does not support monitor mode, so a compatible USB adapter is required. The interface is detected automatically, no adapter name is hardcoded.

## Installation

Install on a freshly flashed Pi:

    git clone --branch v1.2 --depth 1 https://github.com/florians7474/fennec.git
    cd fennec
    ./install.sh

The installer asks for a display profile before it starts. The default is the
Waveshare 3.5-inch RPi LCD (C), which is the reference portable build. Set
`FENNEC_DISPLAY` to automate the choice:

    FENNEC_DISPLAY=waveshare35c ./install.sh
    FENNEC_DISPLAY=cuqi35 ./install.sh
    FENNEC_DISPLAY=hdmi ./install.sh
    FENNEC_DISPLAY=headless ./install.sh

The `cuqi35` profile is for the CUQI 3.5-inch RPM-01 touchscreen (sold with a
Raspberry Pi 5 case). It is a generic 480x320 SPI panel (ILI9486 + XPT2046)
that is driver-compatible with the Waveshare (C), so it reuses the same config
(verified on hardware, display and touch).

| Profile | Result |
|---|---|
| `waveshare35c` | Downloads the Waveshare overlay, enables SPI, configures the framebuffer, X11 kiosk, and calibrated ADS7846 touch input. |
| `cuqi35` | Uses the Waveshare (C)-compatible SPI touchscreen configuration for the CUQI 3.5-inch RPM-01. |
| `hdmi` | Starts Fennec in a Chromium kiosk on an HDMI display. |
| `headless` | Does not configure a local display; use Fennec from a browser on the local network. |

The script is idempotent and adapts to any user. It installs the system packages
(including nmap), enables SPI (needed by Bjorn's e-paper display), sets up
Pwnagotchi in an isolated venv, compiles pwngrid, builds routerkeygen-cli,
installs Bjorn in its own venv from a pinned requirements file that works on
Python 3.13, downloads the Sly wordlists (10k-common, probable-wpa and
rockyou from SecLists), generates a random bettercap password, and configures
all systemd services. No sensitive data is stored in the repository.

Reboot once after the install when using a local display. Fennec then starts as
a service and opens automatically in the selected kiosk profile.

## Reproducible releases

Each stable release locks Fennec's external source revisions in `system/sources.lock`: Pwnagotchi, pwngrid, Bjorn, routerkeygen and SecLists are checked out at their recorded commits, while the Waveshare overlay archive is verified with SHA-256. A fresh installation of the same Fennec release therefore uses the same tracked sources.

The weekly upstream monitor only opens a GitHub issue when newer upstream revisions exist. It never changes an installed Pi or updates the lock file automatically. New versions are reviewed, tested and released explicitly.

## Usage

After the reboot the interface runs full-screen on the touchscreen and is ready to use. You can also reach it from a browser on the local network:

    http://fennec.local:5000/

Click or tap a tile to activate the matching module. The power menu offers lock
screen (hold to unlock), screen rotation (tap to turn the UI by 90°), the PIN
code, the Logs, reboot and shut down.

## Architecture

- **Fennec**: Flask app that drives the modules without modifying them (port 5000)
- **Pwnagotchi**: jayofelony fork in an isolated venv, driven through systemd
- **Echo**: in-house wardriving and GPS map (reads Pwnagotchi's `.gps.json` handshakes, a bettercap-fed wardrive logger with signal-weighted position estimates, offline OSM tile cache, Leaflet served locally, risk/attack-surface view with Sly verdict override)
- **Sly**: in-house WPA cracking engine (aircrack-ng, CPU), staged escalation, GPU export
- **Mirage**: in-house evil-twin launcher that picks up where Sly leaves off (hostapd rogue AP cloning a whitelisted SSID on the USB adapter, dnsmasq DHCP + DNS catch-all, a captive-portal web layer with a built-in theme library plus custom-ZIP upload, live client view from the dnsmasq leases, `iw`-based WPA2/WPA3/PMF detection, bettercap deauth gated on PMF and a second monitor adapter, and handshake capture handed to Sly)
- **Bjorn**: infinition/Bjorn, driven through systemd, live console in the tile
- **Hugin**: in-house Bjorn companion (reads Bjorn's CSV/output, Metasploit correlation by CVE and by open service, `.rc` attack plans, msgpack-RPC link to a remote Metasploit — never on the Pi — with run, live sessions and in-session commands)
- **Sentry**: in-house device radar and traffic monitor (nmap for discovery and port scans, bettercap MITM, tshark for SNI/QUIC and an on-demand dnsmasq for DNS, optional Force DNS against DoT/DoH, VPN detection, persistent per-network history)
- **Mole**: in-house drop-box orchestrator (Responder for LAN credential capture, nmap subnet map, offline John jumbo cracking of captured NetNTLMv2 hashes), plus an aggressive relay mode (mitm6 + impacket ntlmrelayx), driven through systemd, Ethernet-gated
- **Connection**: joins or leaves a whitelisted Wi-Fi via nmcli on the built-in interface; keeps the USB adapter free for monitor mode- On-screen keyboard for the touchscreen, so any field can be filled without a physical keyboard
- Automatic detection of the monitor-mode Wi-Fi adapter at launch
- On-screen screen rotation: cycle the UI through 0/90/180/270 from the power menu (portrait and landscape), applied instantly with no reboot and no touch recalibration

## Features

- [x] Fennec launcher and tile interface
- [x] Pwnagotchi module (install, control, display)
- [x] One-command installer (SPI enabled, works on a fresh card in one pass)
- [x] Touchscreen display and Chromium kiosk auto-starting at boot
- [x] On-screen power menu: lock screen (hold to unlock), screen rotation, PIN code, Logs, reboot, shut down
- [x] On-screen screen rotation (portrait/landscape, instant, no reboot)
- [x] Remote-access PIN for the web UI (6-digit; the local touchscreen is exempt)
- [x] Module journal (Logs): recent events, crash dots on tiles, attention signals, alerts filter
- [x] Bjorn module (install, control, live console)
- [x] Sly module (WPA cracking, 9-stage escalation, GPU export)
- [x] Live connection indicator (Ethernet / Wi-Fi / Offline)
- [x] Sentry module (device radar, per-device recon, naming, and traffic watch via MITM)
- [x] Sentry DNS capture (Pi as resolver), Force DNS against DoT/DoH, and VPN detection
- [x] Echo module – phase 1 (geolocate captured handshakes on a live map)
- [x] On-screen keyboard for the touchscreen
- [x] Real Wi-Fi join/disconnect from the connection manager (nmcli)
- [x] Bjorn Wi-Fi start gate (whitelisted network required on Wi-Fi, free on Ethernet)
- [x] Hugin module – phase 1 (surface Bjorn's results: devices, ports, vulns, files, downloads)
- [x] Hugin module – phase 2 (Metasploit correlation: local CVE index + service→module map)
- [x] Hugin module – phase 3 (deported Metasploit execution over RPC: run, live sessions, in-session commands) — validated end to end
- [x] Echo module – phase 2 (wardriving: every network seen logged with GPS, offline tiles, on-screen GPS fix indicator)
- [x] Mirage portal library (Default/Hotel/Station themes in English and French, one-tap apply, on-screen preview, custom ZIP upload, downloadable starter template)
- [x] Mirage accurate security detection via `iw` (WPA2 / WPA3 / WPA2-WPA3 transition, PMF), with deauth gated on PMF instead of the SSID label
- [x] Mirage handshake capture during deauth, handed to Sly for offline cracking
- [x] Network lists sorted by relevance (saved-key networks first in the whitelist; connected then connectable first in the connection manager)

## Planned

- [x] Mole module – phase 1 (Ethernet drop box: Responder credential capture, subnet map, offline cracking)
- [ ] Mole module – phase 2 (active relay: mitm6 + ntlmrelayx) — built, needs testing against a lab domain
- [ ] Custom carrier board (Raspberry Pi CM5) to turn the prototype into a self-contained device
- [ ] WPA3 (SAE) auditing support

## Credits & third-party

Fennec drives several open-source projects, installed and run as separate programs — it does not fork or bundle their source. All names, mascots and trademarks belong to their respective owners; Fennec is an independent project and is not affiliated with or endorsed by them.

- **Pwnagotchi** — created by [@evilsocket](https://github.com/evilsocket), maintained by [jayofelony/pwnagotchi](https://github.com/jayofelony/pwnagotchi). Licensed under **GPL-3.0**. The Pwnagotchi module icon (`static/pwnagotchi.png`) is taken from the Pwnagotchi project and remains under GPL-3.0.
- **Bjorn** — created by [infinition](https://github.com/infinition/Bjorn). Copyright © 2024 infinition, licensed under the **MIT License**. The Bjorn module icon (`static/bjorn.png`) is taken from the Bjorn project and is used under the MIT License.
- **Responder** — created by [lgandx/Responder](https://github.com/lgandx/Responder) (originally by Laurent Gaffié). Licensed under **GPL-3.0**. Installed from source and run as a separate program by the Mole module.
- **Leaflet** (BSD-2-Clause) is vendored in `static/leaflet/`; map tiles © **OpenStreetMap** contributors (ODbL).
- Runtime tools: **bettercap**, **aircrack-ng**, **nmap**, **tshark**, **dnsmasq**, **Metasploit**, **routerkeygen**, **John the Ripper** — each under its own license.

## License

Released under the [MIT License](LICENSE). This tool is for auditing networks you own or are explicitly authorized to test; any other use is your responsibility.


# Fennec 🦊

Web-based launcher for Wi-Fi pentest modes on a Raspberry Pi 5.

Fennec turns a Raspberry Pi 5 and a touchscreen into a small Wi-Fi auditing console. A full-screen web interface, five tiles, one tool running at a time. Each module stays independent and starts or stops on demand straight from the screen.

The project also serves as a hands-on sandbox for learning offensive security. The goal is not to crack strong WPA2 but to reveal weak keys on your own networks.

## Preview

> _(interface screenshot to add here: `docs/preview.png`)_

## Modules

| Tile | Role | Status |
|------|------|--------|
| **Pwnagotchi** | Passive Wi-Fi handshake capture | ✅ Working |
| **Bjorn** | Network reconnaissance and targeted attacks | ✅ Working |
| **Sly** | Offline WPA cracking on your own captures | ✅ Working |
| **Sentry** | Network radar + per-device traffic watch | ✅ Working |
| **Map** | Map of captures by GPS location | 🚧 Phase 1 |
| **Hugin** | Bjorn companion: results, Metasploit correlation (CVE + service), deported execution & live sessions | ✅ Working |

The header shows the Pi's live connection, Ethernet, Wi-Fi with its SSID, or Offline, and tapping it opens the connection manager: you scan for networks, pick the ones you are allowed to test, and connect the Pi to a whitelisted Wi-Fi or disconnect it (real nmcli on the built-in interface; the key comes from the whitelist or an existing profile, and a network answering on several bands is handled by SSID). An on-screen keyboard pops up on any text field, so keys and device names can be typed on the touchscreen without a physical keyboard. A power button in the top-right opens an on-screen menu to lock the screen, reboot, or shut down, so the Pi can be handled entirely from the touchscreen without a keyboard. Lock screen is for nomadic use: it covers the UI with a looping Wi-Fi animation and ignores every touch (so the Pi can ride in a bag while a capture runs), and only a deliberate slide-to-unlock brings the interface back.

**Pwnagotchi**, **Bjorn**, **Sly** and **Sentry** are operational: automatic installation, control from the tile, and a live view inside the interface.

- **Pwnagotchi** captures handshakes in the background and mirrors its head live in the tile.
- **Bjorn** scans and probes the network the Pi is currently on. The screen names that network and its subnet before you start, so there is no doubt about what is being audited, and its live console streams inside the tile. On Wi-Fi it only starts when the connected network is in your whitelist; on Ethernet it starts freely, since plugging in a cable is itself a deliberate authorization.
- **Sly** runs a 9-stage escalation on your own captures (factory keys, ESSID profiling, known cracked keys, dates, common passwords, keyboard patterns, mutation rules, then two one-hour deep passes) and grades the key's robustness, with a one-step handoff to GPU cracking. Captures with no usable handshake are flagged and cannot be tested, so a network is never wrongly reported as robust.
- **Sentry** scans the current subnet (ARP via nmap) and lists every device with its IP, MAC and vendor. Unknown devices are sorted to the top with an amber accent, a one-tap chip marks a device as yours, and a header count ("6 devices · 2 unknown") tells you at a glance whether something is on the network that shouldn't be. Tap a device to open its detail: open ports and services, a guessed device type (PC, phone, printer, camera, NAS…), hostname, MAC and vendor. You can rename any device (saved per network), and the **Watch** mode turns Sentry into a passive monitor: a bettercap MITM of the whole subnet reveals the domains each device contacts (TLS SNI and QUIC via tshark, plus every cleartext DNS query through an on-demand dnsmasq the Pi redirects port 53 to), with a persistent, timestamped history kept per network. A **Force DNS** toggle blocks DoT and the main DoH resolvers to push hardened devices back onto readable DNS, and a device running a VPN is detected and flagged (WireGuard, OpenVPN or IPsec/IKEv2 tunnel plus endpoint) instead of showing blank.
- **Map** plots captured handshakes on a live map using the position read at capture time (Pwnagotchi's GPS plugin writes a `.gps.json` next to each handshake when a fix is available). Markers are colour-coded by whitelist status, and tapping one adds that network to the allowed list. Phase 1 (geolocating captures) is in; full wardriving comes next.
- **Hugin** is to Bjorn what Sly is to Pwnagotchi. It reads Bjorn's own results and shows them per device: open ports and services, vulnerabilities, the actions Bjorn ran (with status and date), and the files it produced (preview and download). It suggests candidate Metasploit modules two ways — by CVE (from a local index, no Metasploit on the Pi) and by open service (a built-in service→module map, so it lights up from the open ports even when no CVE was found) — clearly flagged as candidates, not confirmed vulnerabilities, and exports a ready-to-run `.rc` attack plan per module. Execution is deported: Metasploit runs on a separate lab machine and the Pi drives it over RPC — run a module with confirmation, watch a session open, then list the live sessions and run commands inside one (e.g. `id` returning `uid=0(root)`), all from Fennec. Validated end to end against a lab target. Lab use only, on authorized targets.

## Legal scope

Fennec is built to audit your own networks. Offensive actions (cracking, targeted reconnaissance) are restricted to a whitelist of networks you declare yourself, identified by their BSSID. Passive capture stays open because it only listens to the surrounding airspace, like any Wi-Fi analyzer.

Only use this tool on networks you own or have written permission to test. Any other use is illegal.

## Hardware

- Raspberry Pi 5
- Display profile selected during installation: Waveshare 3.5-inch RPi LCD (C), HDMI kiosk, or headless
- USB Wi-Fi adapter with monitor mode (tested with an Alfa AWUS036AXM, MediaTek MT7921AU chipset)
- Optional: VK-162 USB GPS module (for the Map / wardriving module)
- microSD card, 32 GB or more, Raspberry Pi OS 64-bit (desktop)

The Pi 5 built-in Wi-Fi does not support monitor mode, so a compatible USB adapter is required. The interface is detected automatically, no adapter name is hardcoded.

## Installation

Install on a freshly flashed Pi:

    git clone https://github.com/florians7474/fennec.git
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

## Usage

After the reboot the interface runs full-screen on the touchscreen and is ready to use. You can also reach it from a browser on the local network:

    http://fennec.local:5000/

Click or tap a tile to activate the matching module. The power menu offers lock
screen (hold to unlock), screen rotation (tap to turn the UI by 90°), reboot and
shut down.

## Architecture

- **Fennec**: Flask app that drives the modules without modifying them (port 5000)
- **Pwnagotchi**: jayofelony fork in an isolated venv, driven through systemd
- **Bjorn**: infinition/Bjorn, driven through systemd, live console in the tile
- **Sly**: in-house WPA cracking engine (aircrack-ng, CPU), staged escalation, GPU export
- **Sentry**: in-house device radar and traffic monitor (nmap for discovery and port scans, bettercap MITM, tshark for SNI/QUIC and an on-demand dnsmasq for DNS, optional Force DNS against DoT/DoH, VPN detection, persistent per-network history)
- **Connection**: joins or leaves a whitelisted Wi-Fi via nmcli on the built-in interface; keeps the USB adapter free for monitor mode
- **Hugin**: in-house Bjorn companion (reads Bjorn's CSV/output, Metasploit correlation by CVE and by open service, `.rc` attack plans, msgpack-RPC link to a remote Metasploit — never on the Pi — with run, live sessions and in-session commands)
- On-screen keyboard for the touchscreen, so any field can be filled without a physical keyboard
- Automatic detection of the monitor-mode Wi-Fi adapter at launch
- On-screen screen rotation: cycle the UI through 0/90/180/270 from the power menu (portrait and landscape), applied instantly with no reboot and no touch recalibration

## Roadmap

- [x] Fennec launcher and tile interface
- [x] Pwnagotchi module (install, control, display)
- [x] One-command installer (SPI enabled, works on a fresh card in one pass)
- [x] Touchscreen display and Chromium kiosk auto-starting at boot
- [x] On-screen power menu: lock screen (hold to unlock), screen rotation, reboot, shut down
- [x] On-screen screen rotation (portrait/landscape, instant, no reboot)
- [x] Bjorn module (install, control, live console)
- [x] Sly module (WPA cracking, 9-stage escalation, GPU export)
- [x] Live connection indicator (Ethernet / Wi-Fi / Offline)
- [x] Sentry module (device radar, per-device recon, naming, and traffic watch via MITM)
- [x] Sentry DNS capture (Pi as resolver), Force DNS against DoT/DoH, and VPN detection
- [x] Map module – phase 1 (geolocate captured handshakes on a live map)
- [x] On-screen keyboard for the touchscreen
- [x] Real Wi-Fi join/disconnect from the connection manager (nmcli)
- [x] Bjorn Wi-Fi start gate (whitelisted network required on Wi-Fi, free on Ethernet)
- [x] Hugin module – phase 1 (surface Bjorn's results: devices, ports, vulns, files, downloads)
- [x] Hugin module – phase 2 (Metasploit correlation: local CVE index + service→module map)
- [x] Hugin module – phase 3 (deported Metasploit execution over RPC: run, live sessions, in-session commands) — validated end to end
- [ ] Map module – phase 2 (full wardriving: map every network, offline tiles)

# Fennec 🦊

![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%205-c51a4a)
![Python](https://img.shields.io/badge/python-3.11%2B-3776ab)
![License](https://img.shields.io/badge/license-MIT-blue)
![Status](https://img.shields.io/badge/status-active-success)

Web-based launcher for Wi-Fi pentest modes on a Raspberry Pi 5.

Fennec turns a Raspberry Pi 5 and a touchscreen into a small Wi-Fi auditing console. A full-screen web interface, six tiles, one tool running at a time. Each module stays independent and starts or stops on demand straight from the screen.

The project also serves as a hands-on sandbox for learning offensive security. The goal is not to crack strong WPA2 but to reveal weak keys on your own networks.

## Preview

> _(interface screenshot to add here: `docs/preview.png`)_

## Modules

| Tile | Role | Status |
|------|------|--------|
| **Pwnagotchi** | Passive Wi-Fi handshake capture | ✅ Working |
| **Echo** | Captures, wardriving and attack-surface map by GPS location | ✅ Working |
| **Sly** | Offline WPA cracking on your own captures | ✅ Working |
| **Bjorn** | Network reconnaissance and targeted attacks | ✅ Working |
| **Hugin** | Bjorn companion: results, Metasploit correlation (CVE + service), deported execution & live sessions | ✅ Working |
| **Sentry** | Network radar + per-device traffic watch | ✅ Working |

The header shows the Pi's live connection, Ethernet, Wi-Fi with its SSID, or Offline, and tapping it opens the connection manager: you scan for networks, pick the ones you are allowed to test, and connect the Pi to a whitelisted Wi-Fi or disconnect it (real nmcli on the built-in interface; the key comes from the whitelist or an existing profile, and a network answering on several bands is handled by SSID). An on-screen keyboard pops up on any text field, so keys and device names can be typed on the touchscreen without a physical keyboard. A power button in the top-right opens an on-screen menu to lock the screen, rotate the screen, reboot, or shut down, so the Pi can be handled entirely from the touchscreen without a keyboard. Lock screen is for nomadic use: it covers the UI with a looping Wi-Fi animation and ignores every touch (so the Pi can ride in a bag while a capture runs), and only a deliberate press-and-hold brings the interface back.

All six modules are operational: automatic installation, control from the tile, and a live view inside the interface.

- **Pwnagotchi — passive capture.** Captures handshakes in the background and mirrors its head live in the tile.
- **Echo — map & wardriving.** Plots captured handshakes by GPS and logs every network merely seen during a run (passive, WiGLE-style, via bettercap), placing seen networks at a signal-weighted **estimated position** refined on each pass. Two on-screen views: **Status** (whitelist / handshake / seen) and **Risk** (open or WEP, WPS, WPA2/3), with a real Sly crack verdict overriding the guess. Map tiles are cached locally and work offline, with a live GPS badge and outlier-trimmed centring.
- **Sly — offline WPA cracking.** Runs a 9-stage escalation on your own captures (factory keys, ESSID profiling, known keys, dates, common passwords, keyboard patterns, mutation rules, then two one-hour deep passes) and grades the key's robustness, with a one-tap handoff to GPU cracking. Captures with no usable handshake are flagged, so a network is never wrongly reported as robust.
- **Bjorn — recon & targeted attacks.** Scans and probes the network the Pi is on, naming it and its subnet before you start, with a live console in the tile. On Wi-Fi it starts only for a whitelisted network; on Ethernet it starts freely, since plugging in a cable is itself a deliberate authorization.
- **Hugin — Bjorn companion** (what Sly is to Pwnagotchi). Reads Bjorn's results per device (ports, services, vulnerabilities, actions, files) and suggests Metasploit modules two ways — by CVE (local index) and by open service (service→module map) — flagged as candidates, with a ready-to-run `.rc` plan per module. Execution is **deported**: Metasploit runs on a separate lab machine driven over RPC (run a module, watch a session open, list sessions, run in-session commands). Lab use only, on authorized targets.
- **Sentry — device radar & traffic watch.** Scans the subnet (nmap ARP) and lists every device (IP, MAC, vendor) with unknowns surfaced and a one-tap "mine" chip; tap for detail (ports, guessed type, hostname). **Watch** mode turns it into a passive monitor (bettercap MITM) revealing the domains each device contacts (TLS SNI/QUIC via tshark, plus cleartext DNS via an on-demand dnsmasq), with timestamped per-network history, a **Force DNS** toggle against DoT/DoH, and VPN detection.

## Legal scope

Fennec is built to audit your own networks. Offensive actions (cracking, targeted reconnaissance) are restricted to a whitelist of networks you declare yourself, identified by their BSSID. Passive capture stays open because it only listens to the surrounding airspace, like any Wi-Fi analyzer.

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
- **Echo**: in-house wardriving and GPS map (reads Pwnagotchi's `.gps.json` handshakes, a bettercap-fed wardrive logger with signal-weighted position estimates, offline OSM tile cache, Leaflet served locally, risk/attack-surface view with Sly verdict override)
- **Sly**: in-house WPA cracking engine (aircrack-ng, CPU), staged escalation, GPU export
- **Bjorn**: infinition/Bjorn, driven through systemd, live console in the tile
- **Hugin**: in-house Bjorn companion (reads Bjorn's CSV/output, Metasploit correlation by CVE and by open service, `.rc` attack plans, msgpack-RPC link to a remote Metasploit — never on the Pi — with run, live sessions and in-session commands)
- **Sentry**: in-house device radar and traffic monitor (nmap for discovery and port scans, bettercap MITM, tshark for SNI/QUIC and an on-demand dnsmasq for DNS, optional Force DNS against DoT/DoH, VPN detection, persistent per-network history)
- **Connection**: joins or leaves a whitelisted Wi-Fi via nmcli on the built-in interface; keeps the USB adapter free for monitor mode
- On-screen keyboard for the touchscreen, so any field can be filled without a physical keyboard
- Automatic detection of the monitor-mode Wi-Fi adapter at launch
- On-screen screen rotation: cycle the UI through 0/90/180/270 from the power menu (portrait and landscape), applied instantly with no reboot and no touch recalibration

## Features

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
- [x] Echo module – phase 1 (geolocate captured handshakes on a live map)
- [x] On-screen keyboard for the touchscreen
- [x] Real Wi-Fi join/disconnect from the connection manager (nmcli)
- [x] Bjorn Wi-Fi start gate (whitelisted network required on Wi-Fi, free on Ethernet)
- [x] Hugin module – phase 1 (surface Bjorn's results: devices, ports, vulns, files, downloads)
- [x] Hugin module – phase 2 (Metasploit correlation: local CVE index + service→module map)
- [x] Hugin module – phase 3 (deported Metasploit execution over RPC: run, live sessions, in-session commands) — validated end to end
- [x] Echo module – phase 2 (wardriving: every network seen logged with GPS, offline tiles, on-screen GPS fix indicator)

## Planned

- [ ] Custom carrier board (Raspberry Pi CM5) to turn the prototype into a self-contained device
- [ ] WPA3 (SAE) auditing support

## License

Released under the [MIT License](LICENSE). This tool is for auditing networks you own or are explicitly authorized to test; any other use is your responsibility.

"""Scoutchi engine. Scoutchi is Fennec's handshake harvester: it drives one or two
monitor-mode adapters with hcxdumptool to collect WPA PMKIDs and 4-way
handshakes, geared for roaming (wardriving) where PMKID capture brings in far
more networks than a passive listen. It has two postures:

- Wide: PMKID plus opportunistic handshakes across 2.4 and 5 GHz, no deauth.
  This stays inside the free wide-capture scope and is the roaming mode.
- Targeted: locks onto one whitelisted BSSID and deauthenticates its clients to
  force the 4-way handshake. Offensive, so it is gated on the whitelist by the
  caller, like Mirage and Bjorn.

Captures are written where Sly already reads them (the handshakes dir), one pcap
per network named <essid>_<bssid>.pcap, so cracking needs no change.

The capture runs as root in the fennec-scoutchi systemd service (the orchestrator
/usr/local/bin/fennec-scoutchi). This module detects the adapters, starts and stops
that service, and reads the stats the orchestrator writes under /tmp/fennec-scoutchi.
"""
import os
import glob
import json
import subprocess

RUN_DIR = "/tmp/fennec-scoutchi"
CONFIG_FILE = os.path.join(RUN_DIR, "config.json")
STATS_FILE = os.path.join(RUN_DIR, "stats.json")
SERVICE = "fennec-scoutchi"

# The built-in chip drives the Pi's own Wi-Fi connection (station), so Scoutchi
# leaves it alone and only uses USB monitor adapters.
STATION_IFACE = "wlan0"


def _systemctl(action, service):
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/systemctl", action, service],
            check=True, capture_output=True, timeout=20,
        )
        return True
    except Exception:
        return False


def _phy_of(iface):
    try:
        with open("/sys/class/net/%s/phy80211/name" % iface) as f:
            return f.read().strip()
    except OSError:
        return None


def _driver_of(iface):
    try:
        with open("/sys/class/net/%s/device/uevent" % iface) as f:
            for line in f:
                if line.startswith("DRIVER="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


def _phy_info(phy):
    try:
        return subprocess.run(
            ["iw", "phy", phy, "info"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return ""


def _supports_monitor(info):
    """True only if 'monitor' appears in the phy's supported-interface-modes block."""
    in_modes = False
    for line in info.splitlines():
        s = line.strip()
        if s.startswith("Supported interface modes"):
            in_modes = True
            continue
        if in_modes:
            if s.startswith("*"):
                if s[1:].strip() == "monitor":
                    return True
            else:
                break
    return False


def _bands(info):
    """'2.4+5' when the phy advertises any 5 GHz channel, else '2.4'."""
    return "2.4+5" if (" 5180" in info or " 5180.0" in info or "5180 MHz" in info) else "2.4"


def detect_adapters():
    """Monitor-capable USB wireless interfaces, built-in station excluded.
    Returns a list of {iface, driver, label, bands}, at most the first two found."""
    adapters = []
    for path in sorted(glob.glob("/sys/class/net/*")):
        iface = os.path.basename(path)
        if iface == STATION_IFACE:
            continue
        if not os.path.isdir(os.path.join(path, "phy80211")):
            continue
        phy = _phy_of(iface)
        if not phy:
            continue
        info = _phy_info(phy)
        if not _supports_monitor(info):
            continue
        driver = _driver_of(iface) or "unknown"
        adapters.append({
            "iface": iface,
            "driver": driver,
            "label": driver,
            "bands": _bands(info),
        })
        if len(adapters) >= 2:
            break
    return adapters


def is_active():
    try:
        r = subprocess.run(
            ["systemctl", "is-active", SERVICE],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False


def start(mode="wide", target=None):
    """Write the run config and start the capture service.
    mode is 'wide' or 'targeted'; target (targeted only) is {bssid, name, channel}.
    Returns False when no monitor adapter is present."""
    adapters = detect_adapters()
    if not adapters:
        return False
    if mode == "targeted" and not (target and target.get("bssid")):
        return False
    os.makedirs(RUN_DIR, exist_ok=True)
    config = {
        "mode": "targeted" if mode == "targeted" else "wide",
        "adapters": [a["iface"] for a in adapters],
        "target": target if mode == "targeted" else None,
    }
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f)
    except OSError:
        return False
    return _systemctl("start", SERVICE)


def stop():
    return _systemctl("stop", SERVICE)


def _read_stats():
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def snapshot():
    """JSON-able state for the Scoutchi screen."""
    active = is_active()
    stats = _read_stats()
    # Show the adapters that are plugged in right now so the second-adapter slot
    # reflects reality whether Scoutchi is running or not.
    adapters = detect_adapters()
    recent = stats.get("recent") if isinstance(stats.get("recent"), list) else []
    return {
        "active": active,
        "mode": stats.get("mode", "wide"),
        "target": stats.get("target"),
        "adapters": adapters,
        "adapter_count": len(adapters),
        "handshakes": int(stats.get("handshakes", 0) or 0),
        "pmkid": int(stats.get("pmkid", 0) or 0),
        "aps": int(stats.get("aps", 0) or 0),
        "deauth": int(stats.get("deauth", 0) or 0),
        "recent": recent[:20],
    }

import os
import re
import json
import time
import atexit
import threading
import socket
import raton_engine
import vigie_monitor
import mole_engine
import scout_engine
import hugin
import hugin_msf
from flask import Flask, render_template, redirect, url_for, abort, request, jsonify, send_file, send_from_directory, Response, session

app = Flask(__name__)
# The kiosk browser caches static assets; restarting Fennec doesn't clear that
# cache, so updated JS/CSS never reached a running kiosk. Tell the browser not
# to cache static files, and version their URLs (see asset_v below) so a pulled
# change is picked up on the next load without a manual cache clear.
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.context_processor
def _asset_version():
    try:
        v = int(os.path.getmtime(os.path.join(app.static_folder, "keyboard.js")))
    except Exception:
        v = 0
    return {"asset_v": v}


BASE = os.path.dirname(os.path.abspath(__file__))
MIRAGE_PORTAL_DIR = "/opt/fennec-mirage/portal"
MIRAGE_PORTAL_META = "/opt/fennec-mirage/portal.json"
MIRAGE_PORTAL_UPLOAD = "/tmp/fennec-mirage-portal-upload.zip"
MIRAGE_PORTAL_MAX_UPLOAD = 20 * 1024 * 1024
MIRAGE_PORTAL_LIBRARY = "/opt/fennec-mirage/portals"

# Built-in portal themes shipped with Mirage. Each one changes only the copy and
# the look of the captive page; the form (POST / with a `password` field) and the
# capture backend are identical across all of them.
MIRAGE_PORTAL_CATALOG = [
    {"slug": "default-en", "name": "Default", "lang": "EN"},
    {"slug": "default-fr", "name": "Default", "lang": "FR"},
    {"slug": "hotel-en", "name": "Hotel", "lang": "EN"},
    {"slug": "hotel-fr", "name": "Hotel", "lang": "FR"},
    {"slug": "station-en", "name": "Station", "lang": "EN"},
    {"slug": "station-fr", "name": "Station", "lang": "FR"},
]
MIRAGE_PORTAL_LABELS = {
    p["slug"]: "%s (%s)" % (p["name"], p["lang"]) for p in MIRAGE_PORTAL_CATALOG
}
WHITELIST_FILE = os.path.join(BASE, "whitelist.json")
MINE_FILE = os.path.join(BASE, "my_devices.json")
SCAN_FILE  = os.path.join(BASE, "scan_cache.json")
NAMES_FILE  = os.path.join(BASE, "device_names.json")   # {network: {mac: name}}
HISTORY_FILE  = os.path.join(BASE, "traffic_history.json")  # {network: {mac: {domain: ts}}}

app_state = {"active_mode": None, "network": None}

MODES = {
    "pwnagotchi": {"name": "Pwnagotchi", "classe": "pwn",   "url": None},
    "cracking":    {"name": "Sly",      "classe": "cass",  "url": None},
    "bjorn":      {"name": "Bjorn",      "classe": "bjorn", "url": None},
    "mirage":     {"name": "Mirage",     "classe": "mirage", "url": None},
}

# ---------- JSON files ----------

def _load(file):
    try:
        with open(file, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def _save(file, data):
    with open(file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_whitelist():
    return _load(WHITELIST_FILE)

def save_whitelist(networks):
    _save(WHITELIST_FILE, networks)

def load_mine():
    return _load(MINE_FILE)   # list of device ids declared "mine"

def save_mine(ids):
    _save(MINE_FILE, ids)

def load_scan():
    return _load(SCAN_FILE)   # last saved direct scan

def save_scan(networks):
    _save(SCAN_FILE, networks)

# ---------- Device settings (per-Pi state, not in the repo) ----------

SETTINGS_FILE = os.path.join(BASE, "settings.json")

def load_settings():
    data = _load(SETTINGS_FILE)
    return data if isinstance(data, dict) else {}

def save_settings(data):
    _save(SETTINGS_FILE, data)

# ---------- Remote-access PIN (the touchscreen on localhost is always exempt) ----------
import hashlib, hmac, secrets

# A fresh session key is generated on every start, so each Fennec reboot (or
# service restart) invalidates all existing web sessions: a remote browser is
# always asked for the PIN again after a power cycle. The local touchscreen is
# exempt from the PIN, so this never affects the kiosk.
app.secret_key = secrets.token_hex(32)

def pin_is_set():
    return bool(load_settings().get("pin_hash"))

def set_pin(pin):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 200_000).hex()
    s = load_settings()
    s["pin_salt"] = salt
    s["pin_hash"] = h
    save_settings(s)

def check_pin(pin):
    s = load_settings()
    salt, h = s.get("pin_salt"), s.get("pin_hash")
    if not salt or not h:
        return False
    test = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 200_000).hex()
    return hmac.compare_digest(test, h)

def clear_pin():
    s = load_settings()
    s.pop("pin_salt", None)
    s.pop("pin_hash", None)
    save_settings(s)

_pin_fails = {"n": 0, "until": 0.0}

def _is_local():
    return request.remote_addr in ("127.0.0.1", "::1")

@app.before_request
def _require_pin():
    # The kiosk talks to itself on localhost: never ask the touchscreen for a PIN.
    if request.remote_addr in ("127.0.0.1", "::1"):
        return
    # Always let the static assets load (the locked pages use them).
    if request.endpoint == "static":
        return
    # No PIN configured yet: remote access stays closed until a PIN is set on the
    # touchscreen. Show the visitor where to set it instead of exposing the UI.
    if not pin_is_set():
        if request.method == "GET":
            return render_template("needs_pin.html"), 403
        abort(403)
    # Always let the unlock page and its check load.
    if request.endpoint == "unlock":
        return
    # Already unlocked for this browser session.
    if session.get("ok"):
        return
    # Remote and locked: a page -> PIN screen, anything else -> refused.
    if request.method == "GET":
        return redirect(url_for("unlock"))
    abort(403)

# ---------- Modes ----------

import subprocess
import urllib.request
import base64

# systemd services managed by each mode, in start order
SERVICES = {
    "pwnagotchi": ["bettercap", "pwngrid-peer", "pwnagotchi", "fennec-wardrive"],
    "bjorn": ["bjorn", "bjorn-console"],
    "mirage": ["fennec-mirage"],
    "scout": ["fennec-scout"],
}

import glob

def detect_monitor_iface():
    """Return the name of the first wlan interface capable of monitor mode, else None."""
    for path in sorted(glob.glob("/sys/class/net/wlan*")):
        iface = os.path.basename(path)
        try:
            with open(os.path.join(path, "phy80211/name")) as f:
                phy = f.read().strip()
            info = subprocess.run(
                ["iw", "phy", phy, "info"],
                capture_output=True, text=True, timeout=10,
            ).stdout
            # We target the supported-modes section
            if "* monitor" in info:
                return iface
        except Exception:
            continue
    return None

def _phy_supports_monitor(phy):
    """True only if 'monitor' is in the phy's *Supported interface modes* block
    (not the 'software interface modes' section, which many chips list but can't
    really use as a second card)."""
    try:
        info = subprocess.run(
            ["iw", "phy", phy, "info"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except Exception:
        return False
    in_block = False
    for line in info.splitlines():
        s = line.strip()
        if s.startswith("Supported interface modes:"):
            in_block = True
            continue
        if in_block:
            if s.startswith("* "):
                if s[2:].strip() == "monitor":
                    return True
            else:
                break
    return False

def _wireless_ifaces():
    """All wireless interfaces (any name), i.e. netdevs that expose a phy80211."""
    names = []
    for path in sorted(glob.glob("/sys/class/net/*")):
        if os.path.isdir(os.path.join(path, "phy80211")):
            names.append(os.path.basename(path))
    return names

def _wifi_iface_connected(iface):
    """Return True when a wireless interface is currently associated as a station."""
    try:
        r = subprocess.run(
            ["iw", "dev", iface, "link"],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0 and "Connected to " in r.stdout
    except Exception:
        return False

def current_mirage_ap_iface():
    """Return the Wi-Fi interface selected by the running Mirage AP, if known."""
    try:
        with open("/tmp/fennec-mirage/ap_iface", encoding="utf-8") as f:
            iface = f.readline().strip()
        if iface and os.path.exists(f"/sys/class/net/{iface}"):
            return iface
    except OSError:
        pass
    return None

def monitor_iface_except(exclude):
    """Return the first free monitor-capable wireless interface other than `exclude`."""
    for iface in _wireless_ifaces():
        if iface == exclude or _wifi_iface_connected(iface):
            continue
        try:
            with open(f"/sys/class/net/{iface}/phy80211/name") as f:
                phy = f.read().strip()
        except OSError:
            continue
        if _phy_supports_monitor(phy):
            return iface
    return None

def scan_security_channel(bssid, ssid):
    """Security and channel of a target, from an nmcli scan. Match by BSSID first
    (reliable), then by SSID. (sec, chan) or (None, None)."""
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "BSSID,SSID,CHAN,SECURITY", "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, timeout=20,
        )
    except Exception:
        return None, None
    by_ssid = None
    want_b = (bssid or "").upper()
    for line in r.stdout.splitlines():
        fields = re.split(r"(?<!\\):", line)
        if len(fields) < 4:
            continue
        b = fields[0].replace("\\:", ":").upper().strip()
        nm = fields[1].replace("\\:", ":").strip()
        if want_b and b == want_b:
            return (fields[3].strip() or None), (fields[2].strip() or None)
        if ssid and nm == ssid and by_ssid is None:
            by_ssid = (fields[3].strip() or None), (fields[2].strip() or None)
    return by_ssid if by_ssid else (None, None)

def _scan_securities():
    """One nmcli scan -> (by BSSID, by SSID) security maps."""
    by_bssid, by_ssid = {}, {}
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "BSSID,SSID,SECURITY", "dev", "wifi", "list", "--rescan", "auto"],
            capture_output=True, text=True, timeout=20,
        )
    except Exception:
        return by_bssid, by_ssid
    for line in r.stdout.splitlines():
        fields = re.split(r"(?<!\\):", line)
        if len(fields) < 3:
            continue
        b = fields[0].replace("\\:", ":").upper().strip()
        nm = fields[1].replace("\\:", ":").strip()
        sec = fields[2].strip()
        if b and sec:
            by_bssid[b] = sec
        if nm and sec and nm not in by_ssid:
            by_ssid[nm] = sec
    return by_bssid, by_ssid

def _iw_scan():
    """Full scan via the root helper: list of {bssid, ssid, security, pmf, chan}.
    Returns None when the helper is unavailable (then nmcli is used as fallback)."""
    try:
        r = subprocess.run(["sudo", "-n", "/usr/local/bin/fennec-wifi-scan"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return None
        data = json.loads(r.stdout or "[]")
        return data if isinstance(data, list) else None
    except Exception:
        return None


def _scan_networks():
    """(by BSSID, by SSID) maps of {security, pmf, chan}. Prefers iw (sees every AP
    and reads PMF); falls back to nmcli (security only, limited visibility)."""
    by_bssid, by_ssid = {}, {}
    data = _iw_scan()
    if data is not None:
        for n in data:
            b = (n.get("bssid") or "").upper()
            nm = n.get("ssid") or ""
            entry = {"security": n.get("security"), "pmf": n.get("pmf"),
                     "chan": n.get("chan")}
            if b:
                by_bssid[b] = entry
            if nm and nm not in by_ssid:
                by_ssid[nm] = entry
        return by_bssid, by_ssid
    nb, ns = _scan_securities()
    for b, sec in nb.items():
        by_bssid[b] = {"security": sec, "pmf": None, "chan": None}
    for nm, sec in ns.items():
        by_ssid[nm] = {"security": sec, "pmf": None, "chan": None}
    return by_bssid, by_ssid


# A scan is a momentary snapshot: a given AP is not in every scan, so badges
# would flicker. We keep a cache that accumulates what we've seen. The refresh
# runs in a background thread so a page never blocks on the (slow) iw scan; the
# page returns the current cache immediately and new badges show on a later load.
_sec_cache = {"bssid": {}, "ssid": {}, "ts": 0.0}
_sec_refreshing = {"on": False}

def _refresh_sec_cache():
    try:
        by_bssid, by_ssid = _scan_networks()
        _sec_cache["bssid"].update(by_bssid)
        _sec_cache["ssid"].update(by_ssid)
        _sec_cache["ts"] = time.time()
    finally:
        _sec_refreshing["on"] = False

def all_securities():
    """Accumulated (by BSSID, by SSID) maps of {security, pmf, chan}. Non-blocking:
    kicks off a background refresh when the cache is stale and returns at once."""
    now = time.time()
    if now - _sec_cache["ts"] > 20 and not _sec_refreshing["on"]:
        _sec_refreshing["on"] = True
        threading.Thread(target=_refresh_sec_cache, daemon=True).start()
    return _sec_cache["bssid"], _sec_cache["ssid"]


def resolve_target(bssid, ssid):
    """(security, chan, pmf) for a target. Starting the AP is a deliberate action,
    so when the cache has nothing usable we do a direct iw scan (accurate channel),
    then fall back to nmcli as a last resort."""
    b = (bssid or "").upper()
    by_bssid, by_ssid = all_securities()
    e = by_bssid.get(b) or by_ssid.get(ssid)
    if not (e and (e.get("security") or e.get("chan"))):
        for n in (_iw_scan() or []):
            if (n.get("bssid") or "").upper() == b or (ssid and n.get("ssid") == ssid):
                e = {"security": n.get("security"), "pmf": n.get("pmf"),
                     "chan": n.get("chan")}
                break
    if e and (e.get("security") or e.get("chan")):
        return e.get("security"), e.get("chan"), e.get("pmf")
    sec, chan = scan_security_channel(bssid or "", ssid or "")
    return sec, chan, None

def deauth_possible(security, pmf=None):
    """Deauth works on WPA2/WEP/open. It is blocked only when management-frame
    protection (PMF) is *required*, which pure WPA3 (SAE) enforces. A WPA2/WPA3
    transition network advertises PMF as merely *capable*, so its WPA2 clients can
    still be deauthenticated. When PMF is unknown, fall back to the security string
    (unknown security -> allowed, we can't prove it's WPA3-only)."""
    if pmf == "required":
        return False
    if pmf in ("capable", "none"):
        return True
    if not security:
        return True
    s = security.upper()
    return not ("WPA3" in s and "WPA2" not in s)

def _systemctl(action, service):
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/systemctl", action, service],
            check=True, capture_output=True, timeout=20,
        )
        return True
    except Exception:
        return False

def start(mode):
    for service in SERVICES.get(mode, []):
        _systemctl("start", service)

def stop(mode):
    for service in reversed(SERVICES.get(mode, [])):
        _systemctl("stop", service)

def is_active(service):
    try:
        r = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False

# ---------- Module journal (events) + crash detection ----------
import threading as _threading

EVENTS_FILE = os.path.join(BASE, "events.json")
EVENTS_MAX = 200

# Module -> primary systemd unit (crash detection) and display label (journal).
MODULE_SERVICE = {"pwnagotchi": "pwnagotchi", "bjorn": "bjorn", "mirage": "fennec-mirage"}
MODULE_LABEL = {"pwnagotchi": "Pwnagotchi", "bjorn": "Bjorn", "mirage": "Mirage",
                "cracking": "Sly", "vigie": "Sentry", "hugin": "Hugin",
                "mole": "Mole", "echo": "Echo", "scout": "Scout", "fennec": "Fennec"}

_events_lock = _threading.Lock()

def log_event(module, level, message):
    """Append one event to the journal. level is info, warn or error."""
    entry = {"t": time.time(), "mod": module, "level": level, "msg": str(message)[:200]}
    with _events_lock:
        data = _load(EVENTS_FILE)
        events = data if isinstance(data, list) else []
        events.append(entry)
        if len(events) > EVENTS_MAX:
            events = events[-EVENTS_MAX:]
        _save(EVENTS_FILE, events)

def read_events():
    data = _load(EVENTS_FILE)
    events = data if isinstance(data, list) else []
    return sorted(events, key=lambda e: e.get("t", 0), reverse=True)

def clear_events():
    with _events_lock:
        _save(EVENTS_FILE, [])

def _is_failed(service):
    try:
        r = subprocess.run(["systemctl", "is-failed", service],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() == "failed"
    except Exception:
        return False

_failed_seen = set()

def refresh_crashed():
    """Return the set of modules whose service crashed, logging each new crash once."""
    crashed = set()
    for mod, svc in MODULE_SERVICE.items():
        if _is_failed(svc):
            crashed.add(mod)
            if mod not in _failed_seen:
                _failed_seen.add(mod)
                log_event(mod, "error", MODULE_LABEL.get(mod, mod) + " service crashed")
        else:
            _failed_seen.discard(mod)
    return crashed

# Deduplication state so polled routes log a change once, not on every poll.
_sly_logged = {"bssid": None}
_echo_last = {"count": None, "nogps": None}

def log_echo_health(count, nogps):
    """Log Echo data health once per change: empty wardrive or captures without GPS."""
    if count != _echo_last["count"]:
        _echo_last["count"] = count
        if count == 0:
            log_event("echo", "warn", "Echo: wardrive empty (0 networks loaded)")
        else:
            log_event("echo", "info", "Echo: " + str(count) + " networks loaded")
    if nogps != _echo_last["nogps"]:
        _echo_last["nogps"] = nogps
        if nogps:
            log_event("echo", "warn", "Echo: " + str(nogps) + " capture(s) without GPS position")

@app.route("/pwna-ui")
def pwna_ui():
    from flask import Response
    url = "http://127.0.0.1:8080/ui"
    ident = base64.b64encode(b"pwnagotchi:pwnagotchi").decode()
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {ident}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return Response(r.read(), mimetype="image/png")
    except Exception:
        abort(503)

def connection_state():
    """The Pi's real network connection: ethernet, or the station Wi-Fi (wlan0)
    with its SSID, or none. Only wlan0 counts as the station — the USB adapter
    (wlan1) is for monitor and must never drive the header or the manager."""
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return {"type": None, "name": "Offline"}
    for line in r.stdout.splitlines():
        fields = line.split(":")
        if len(fields) >= 3 and fields[1] == "ethernet" and fields[2] == "connected":
            return {"type": "ethernet", "name": "Ethernet"}
    ssid, _ = wifi_active()
    if ssid:
        return {"type": "wifi", "name": ssid}
    return {"type": None, "name": "Offline"}

def primary_ip():
    """The Pi's main LAN IP (first address of `hostname -I`), or None if offline.
    Used on the setup "done" screen so the user gets the real web and SSH
    addresses, not an example."""
    try:
        r = subprocess.run(["hostname", "-I"],
                           capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    for tok in r.stdout.split():
        tok = tok.strip()
        # Skip IPv6 and loopback; the first IPv4 is the LAN address.
        if tok and ":" not in tok and not tok.startswith("127."):
            return tok
    return None

WIFI_IFACE = "wlan0"  # built-in station interface; USB adapter stays for monitor

def _nmcli_split(line):
    """Split an nmcli -t line on unescaped ':' (it escapes field ':' as '\\:')."""
    out, cur, i = [], "", 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur += line[i + 1]
            i += 2
        elif c == ":":
            out.append(cur)
            cur = ""
            i += 1
        else:
            cur += c
            i += 1
    out.append(cur)
    return out

def wifi_active():
    """(ssid, bssid) currently associated on the station interface (wlan0) only,
    else (None, None). The USB adapter (wlan1) is ignored so a profile that grabs
    it never shows up as the Pi's connection."""
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,DEVICE", "device", "wifi"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return (None, None)
    for line in r.stdout.splitlines():
        p = _nmcli_split(line)
        if len(p) >= 4 and p[0] == "yes" and p[3] == WIFI_IFACE:
            return (p[1] or None, (p[2] or "").upper() or None)
    return (None, None)

def known_wifi_profiles():
    """SSIDs NetworkManager already has a saved Wi-Fi profile for."""
    ssids = set()
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return ssids
    for line in r.stdout.splitlines():
        p = _nmcli_split(line)
        if len(p) >= 2 and p[1] in ("802-11-wireless", "wifi"):
            ssids.add(p[0])
    return ssids

def scan_wifi_simple():
    """Nearby Wi-Fi networks for first-run onboarding: list of
    {ssid, bssid, signal, secure}, strongest first, one entry per SSID."""
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY",
             "device", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, timeout=25,
        )
    except Exception:
        return []
    best = {}
    for line in r.stdout.splitlines():
        p = _nmcli_split(line)
        if len(p) < 4:
            continue
        ssid, bssid, signal, security = p[0], p[1], p[2], p[3]
        if not ssid:                      # hidden network, skip
            continue
        try:
            sig = int(signal)
        except ValueError:
            sig = 0
        if ssid not in best or sig > best[ssid]["signal"]:
            best[ssid] = {"ssid": ssid, "bssid": bssid, "signal": sig,
                          "secure": bool(security and security != "--")}
    return sorted(best.values(), key=lambda n: -n["signal"])

def bjorn_wifi_gate():
    """Whether Bjorn may start. Ethernet = implicit authorization (physical act).
    On Wi-Fi, allowed only if the connected SSID is in the whitelist (any band of
    that network). Returns (ok, message)."""
    conn = connection_state()
    if conn["type"] == "ethernet":
        return True, None
    if conn["type"] == "wifi":
        ssid_act, _ = wifi_active()
        if ssid_act and any(r.get("name") == ssid_act for r in load_whitelist()):
            return True, None
        return (False, "This Wi-Fi is not in your allowed networks. "
                       "Connect to an allowed network first.")
    return (False, "Not connected. Plug in Ethernet or join an allowed Wi-Fi first.")

def local_ip():
    """The Pi's first non-loopback IPv4, or None."""
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    for tok in r.stdout.split():
        if tok.count(".") == 3 and not tok.startswith("127."):
            return tok
    return None

def local_subnet():
    """The Pi's /24 subnet (e.g. 192.168.1.0/24), or None."""
    ip = local_ip()
    return ".".join(ip.split(".")[:3]) + ".0/24" if ip else None

def passerelle_ip():
    """Default gateway IP (the router), or None."""
    try:
        r = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    m = re.search(r"default via ([\d.]+)", r.stdout)
    return m.group(1) if m else None

def scan_network():
    """LAN devices via nmap -sn (dedicated sudo script). IP, MAC, vendor."""
    try:
        r = subprocess.run(
            ["sudo", "-n", "/usr/local/bin/fennec-netscan"],
            capture_output=True, text=True, timeout=90,
        )
    except Exception:
        return []
    appareils, current = [], None
    for line in r.stdout.splitlines():
        m = re.search(r"Nmap scan report for (.+)", line)
        if m:
            target = m.group(1).strip()
            mip = re.search(r"\(([\d.]+)\)", target)
            ip = mip.group(1) if mip else target
            current = {"ip": ip, "mac": None, "vendor": None}
            appareils.append(current)
            continue
        mmac = re.search(r"MAC Address:\s*([0-9A-Fa-f:]{17})\s*(?:\((.*)\))?", line)
        if mmac and current is not None:
            current["mac"] = mmac.group(1).upper()
            v = (mmac.group(2) or "").strip()
            current["vendor"] = v or None
    return appareils

def vigie_devices():
    """Enriched list for Sentry: type, 'mine', unknown; unknowns first."""
    mienne = local_ip()
    passerelle = passerelle_ip()
    miens = set(load_mine())
    out = []
    for a in scan_network():
        pi = (a["ip"] == mienne)
        routeur = (a["ip"] == passerelle)
        mac = a["mac"]
        mien = (mac in miens)
        inconnu = not pi and not routeur and not mien
        out.append({
            "ip": a["ip"],
            "mac": mac,
            "name": custom_name(mac) or a["vendor"] or ("This Pi" if pi else ("Router" if routeur else "Unknown device")),
            "type": "pi" if pi else ("router" if routeur else "device"),
            "pi": pi,
            "routeur": routeur,
            "mien": mien,
            "inconnu": inconnu,
        })
    # Unknowns first, then by IP (numeric order on the octets)
    def ip_key(d):
        try:
            return tuple(int(x) for x in d["ip"].split("."))
        except Exception:
            return (999,)
    def rank(d):
        if d["routeur"]:
            return 0
        if d["pi"]:
            return 1
        if d["mien"]:
            return 2
        return 3  # unknown, last
    out.sort(key=lambda d: (rank(d), ip_key(d)))
    last_scan.clear()
    last_scan.update({d["ip"]: d for d in out})
    return out

last_scan = {}

def arp_mac(ip):
    """MAC of an IP from the ARP cache (without re-scanning), or None."""
    try:
        r = subprocess.run(["ip", "neigh", "show", ip],
                           capture_output=True, text=True, timeout=5)
        m = re.search(r"lladdr ([0-9a-f:]{17})", r.stdout, re.I)
        return m.group(1).upper() if m else None
    except Exception:
        return None

NMAP_OUI = "/usr/share/nmap/nmap-mac-prefixes"
_oui_map = None

def vendor_from_mac(mac):
    """Vendor name for a MAC from nmap's OUI table, or None.

    Lets the device detail name a device even when the scan cache is cold
    (e.g. right after a Fennec restart), instead of falling back to Unknown."""
    global _oui_map
    if not mac:
        return None
    if _oui_map is None:
        _oui_map = {}
        try:
            with open(NMAP_OUI, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if len(line) > 7 and not line.startswith("#"):
                        _oui_map[line[:6].upper()] = line[7:].strip()
        except OSError:
            pass
    return _oui_map.get(mac.upper().replace(":", "")[:6]) or None

def device_pour(ip):
    """Build a device detail for an IP, even outside the last scan."""
    mac = arp_mac(ip)
    pi = (ip == local_ip())
    routeur = (ip == passerelle_ip())
    mien = bool(mac) and mac in set(load_mine())
    vendor = vendor_from_mac(mac)
    name = custom_name(mac) or ("This Pi" if pi else
                                ("Router" if routeur else (vendor or "Unknown device")))
    return {"ip": ip, "mac": mac, "vendor": vendor, "name": name,
            "type": "pi" if pi else ("router" if routeur else "device"),
            "pi": pi, "routeur": routeur, "mien": mien,
            "inconnu": not (pi or routeur or mien)}

def host_name(ip):
    """Reverse DNS de l'IP, ou None."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

PORTS_VIGIE = ("21,22,23,25,53,80,110,135,139,143,443,445,515,554,587,631,993,"
               "995,1723,3306,3389,5000,5357,5900,8000,8080,8443,9100,32400,"
               "37777,49152")

def scan_ports(ip):
    """Open TCP ports (targeted list, rootless connect scan, fast)."""
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip or ""):
        return []
    try:
        r = subprocess.run(
            ["nmap", "-sT", "-Pn", "-n", "-T4", "--max-retries", "1",
             "--host-timeout", "25s", "-p", PORTS_VIGIE, "--open", ip],
            capture_output=True, text=True, timeout=40,
        )
    except Exception:
        return []
    ports = []
    for line in r.stdout.splitlines():
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line.strip())
        if m:
            ports.append({"port": int(m.group(1)), "service": m.group(2)})
    return ports

def guess_type(ports, vendor):
    """Guess the device type from the open ports, then the vendor."""
    svc = {p["port"] for p in ports}
    if 9100 in svc or 631 in svc:
        return "Printer"
    if 554 in svc or 8554 in svc or 37777 in svc:
        return "IP camera"
    if 445 in svc or 139 in svc:
        if 3389 in svc or 5357 in svc:
            return "Windows PC"
        return "File share / NAS"
    if 22 in svc:
        return "Linux / server"
    if 80 in svc or 443 in svc or 8080 in svc:
        return "Web device / IoT"
    v = (vendor or "").lower()
    if any(k in v for k in ["apple", "samsung", "xiaomi", "huawei", "google", "oneplus", "oppo"]):
        return "Phone / mobile"
    if "raspberry" in v:
        return "Raspberry Pi"
    return "Unknown"

# ---------- Sentry: network identity, custom names, traffic history ----------

def network_id():
    """Stable id of the current network: the router's MAC, else the subnet."""
    pg = passerelle_ip()
    if pg:
        try:
            r = subprocess.run(["ip", "neigh", "show", pg],
                               capture_output=True, text=True, timeout=5)
            m = re.search(r"lladdr ([0-9a-f:]{17})", r.stdout, re.I)
            if m:
                return m.group(1).upper()
        except Exception:
            pass
    return local_subnet() or "default"

def custom_name(mac):
    """User-given name for a device (this network), or None."""
    if not mac:
        return None
    noms = _load(NAMES_FILE)
    if not isinstance(noms, dict):
        return None
    return noms.get(network_id(), {}).get(mac.upper())

def set_name(mac, name):
    noms = _load(NAMES_FILE)
    if not isinstance(noms, dict):
        noms = {}
    rid = network_id()
    noms.setdefault(rid, {})
    name = (name or "").strip()[:40]
    if name:
        noms[rid][mac.upper()] = name
    else:
        noms[rid].pop(mac.upper(), None)
    _save(NAMES_FILE, noms)

# Traffic history kept in memory, flushed to disk from time to time.
_hist = None
_hist_dirty = False
_hist_last = 0.0

def _history_load():
    global _hist
    if _hist is None:
        h = _load(HISTORY_FILE)
        _hist = h if isinstance(h, dict) else {}
    return _hist

def _history_flush(force=False):
    global _hist_dirty, _hist_last
    if _hist is None or (not _hist_dirty and not force):
        return
    if not force and (time.time() - _hist_last) < 20:
        return
    _save(HISTORY_FILE, _hist)
    _hist_dirty = False
    _hist_last = time.time()

def merge_traffic(mac, live):
    """Merge the live domains (dict domain->ts) into the device history."""
    global _hist_dirty
    if not mac:
        return dict(live)
    h = _history_load()
    rid = network_id()
    dev = h.setdefault(rid, {}).setdefault(mac.upper(), {})
    for dom, ts in live.items():
        if dom not in dev or ts > dev[dom]:
            dev[dom] = ts
            _hist_dirty = True
    _history_flush()
    return dev

@app.route("/")
def home():
    # First-run onboarding on the touchscreen: if the Pi is offline, send the
    # kiosk straight to the Wi-Fi setup screen (unless skipped this boot). Only
    # on localhost, so remote web users are never forced into it.
    if (request.remote_addr in ("127.0.0.1", "::1")
            and connection_state()["type"] is None
            and not session.get("wifi_setup_skipped")):
        return redirect(url_for("setup_wifi"))
    active_mode = app_state["active_mode"]
    # Sly runs in a thread, not a service: the dot follows the engine's real state.
    if active_mode == "cracking" and not raton_engine.crack_state.get("active"):
        active_mode = None
        app_state["active_mode"] = None
    if active_mode == "vigie" and not vigie_monitor.monitor_state.get("active"):
        active_mode = None
        app_state["active_mode"] = None
    # Scout is service-backed: if it stopped on its own, release the active mode.
    if active_mode == "scout" and not scout_engine.is_active():
        active_mode = None
        app_state["active_mode"] = None
    # Echo is a viewer, not a service — show how many networks are mapped.
    bssids = set()
    for c in read_handshakes():
        gp = os.path.join(HANDSHAKES_DIR, c["file"].replace(".pcap", ".gps.json"))
        if os.path.exists(gp):
            bssids.add(c["bssid"].upper())
    for b in load_wardrive():
        bssids.add(b.upper())
    n = len(bssids)
    echo_count = f"{n / 1000:.1f}k" if n >= 1000 else str(n)
    return render_template("home.html", active=active_mode,
                           connection=connection_state(), echo_count=echo_count,
                           crashed=refresh_crashed(), local=_is_local())

HANDSHAKES_DIR = "/etc/pwnagotchi/handshakes"

_hs_cache = {}

def capture_has_handshake(file):
    """Whether a capture holds a handshake, cached per file (mtime+size)."""
    path = os.path.join(HANDSHAKES_DIR, file)
    try:
        st = os.stat(path)
        key = (st.st_mtime, st.st_size)
    except OSError:
        return False
    hit = _hs_cache.get(path)
    if hit and hit[0] == key:
        return hit[1]
    val = raton_engine.a_un_handshake(path)
    _hs_cache[path] = (key, val)
    return val

def read_handshakes():
    captures = {}
    try:
        files = os.listdir(HANDSHAKES_DIR)
    except OSError:
        return []
    # Several files can share one BSSID (e.g. a stale small capture and the real
    # full one). Process largest first so the file with the actual handshake wins.
    def _size(f):
        try:
            return os.path.getsize(os.path.join(HANDSHAKES_DIR, f))
        except OSError:
            return 0
    for f in sorted(files, key=_size, reverse=True):
        if not f.endswith(".pcap"):
            continue
        base = f[:-5]
        if "_" not in base:
            continue
        name, _, raw = base.rpartition("_")
        raw = raw.lower()
        if len(raw) != 12 or not all(c in "0123456789abcdef" for c in raw):
            continue
        bssid = ":".join(raw[i:i+2] for i in range(0, 12, 2)).upper()
        if bssid not in captures:
            captures[bssid] = {"name": name.strip("-_"), "bssid": bssid, "file": f}
    return sorted(captures.values(), key=lambda c: c["name"].lower())

def direct_scan():
    try:
        res = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,BSSID", "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, timeout=25
        )
    except Exception:
        return []
    networks = {}
    for line in res.stdout.splitlines():
        fields = re.split(r"(?<!\\):", line)
        if len(fields) < 3:
            continue
        ssid = fields[0].replace("\\:", ":").strip()
        signal = fields[1].strip()
        bssid = fields[2].replace("\\:", ":").upper().strip()
        if not bssid or bssid in networks:
            continue
        try:
            dbm = int(signal) // 2 - 100
        except ValueError:
            dbm = None
        networks[bssid] = {"name": ssid or "(hidden)", "bssid": bssid, "signal": dbm}
    return sorted(networks.values(), key=lambda r: -(r["signal"] if r["signal"] is not None else -999))

@app.route("/mode/<name>")
def mode(name):
    if name not in MODES:
        abort(404)

    if name == "cracking":
        e = raton_engine.crack_state
        if e.get("active"):
            capture = next((c for c in read_handshakes()
                            if c["bssid"] == e.get("bssid")), None)
            if capture:
                return render_template("crack_result.html", c=capture)
        seen = {r["bssid"] for r in load_whitelist()}
        captures = read_handshakes()
        wd_up = {k.upper(): v for k, v in load_wardrive().items()}
        for cap in captures:
            # Only check for a handshake on allowed networks (the only ones that
            # show a Test button), to avoid useless scans.
            cap["handshake"] = cap["bssid"] in seen and capture_has_handshake(cap["file"])
            # WPS seen for this BSSID (recorded by the wardrive logger).
            w = wd_up.get(cap["bssid"].upper())
            cap["wps"] = bool(w and w.get("wps"))
        # Testable captures first (allowed + handshake), then allowed without a
        # handshake, then locked ones; alphabetical within each group.
        captures.sort(key=lambda c: (
            0 if c["handshake"] else (1 if c["bssid"] in seen else 2),
            c["name"].lower(),
        ))
        # The WPS attack needs a monitor-capable adapter.
        wps_ok = detect_monitor_iface() is not None
        return render_template("cracking.html", captures=captures, seen=seen, wps_ok=wps_ok)

    if name == "pwnagotchi":
        active = is_active("pwnagotchi")
        app_state["active_mode"] = "pwnagotchi" if active else app_state["active_mode"]
        url_ui = "/pwna-ui"
        return render_template("mode.html", key=name, info=MODES[name], active=active,
                               url_ui=url_ui, url_iframe=None)
    if name == "bjorn":
        active = is_active("bjorn")
        app_state["active_mode"] = "bjorn" if active else app_state["active_mode"]
        # Just after Start the service is "activating" and its web UI isn't up
        # yet, so show a "starting" view that waits for readiness instead of the
        # pre-start screen (which forced a manual home-and-back).
        starting = (app_state["active_mode"] == "bjorn" and not active
                    and not _is_failed("bjorn"))
        hote = request.host.split(":")[0]
        url_iframe = f"http://{hote}:8000/"
        conn = connection_state()
        reseau_scan = {"type": conn["type"], "name": conn["name"],
                       "sous_reseau": local_subnet()}
        return render_template("mode.html", key=name, info=MODES[name], active=active,
                               starting=starting, url_ui=None, url_iframe=url_iframe,
                               reseau_scan=reseau_scan, err=request.args.get("err"))
    if name == "mirage":
        active = is_active("fennec-mirage")
        if active:
            app_state["active_mode"] = "mirage"
        cible = None
        try:
            with open("/tmp/fennec-mirage-target", encoding="utf-8") as f:
                cible = f.readline().strip() or None
        except OSError:
            pass
        meta = {}
        try:
            with open("/tmp/fennec-mirage-meta.json", encoding="utf-8") as f:
                meta = json.load(f)
        except (OSError, ValueError):
            pass
        deauth_active = is_active("fennec-mirage-deauth")
        ap_iface = current_mirage_ap_iface()
        second = monitor_iface_except(ap_iface)
        # WPA3 with PMF blocks deauthentication, so the action is not offered.
        deauth_wpa3 = not deauth_possible(meta.get("security"), meta.get("pmf"))
        deauth_avail = active and bool(second) and not deauth_wpa3
        nets = load_whitelist()
        by_bssid, by_ssid = all_securities()
        for r in nets:
            e = by_bssid.get((r.get("bssid") or "").upper()) or by_ssid.get(r.get("name"))
            if e:
                r["security"] = e.get("security") or None
                r["deauthable"] = deauth_possible(e.get("security"), e.get("pmf"))
            else:
                r["security"] = None
                r["deauthable"] = None
        return render_template("mirage.html", key=name, info=MODES[name],
                               active=active, networks=nets, cible=cible,
                               security=meta.get("security"),
                               deauth_active=deauth_active, deauth_avail=deauth_avail,
                               deauth_wpa3=deauth_wpa3,
                               portal=mirage_portal_info())
    active = (app_state["active_mode"] == name)
    return render_template("mode.html", key=name, info=MODES[name], active=active,
                           url_ui=None, url_iframe=None)

@app.route("/toggle/<name>")
def toggle(name):
    if name not in MODES:
        return redirect(url_for("home"))
    if vigie_monitor.monitor_state["active"]:   # another mode starts: stop Sentry monitoring
        vigie_monitor.stop()
    current = app_state["active_mode"]
    if current == "vigie":
        current = None
    if current == name:
        stop(name)
        app_state["active_mode"] = None
        log_event(name, "info", MODULE_LABEL.get(name, name) + " stopped")
    else:
        if name == "bjorn":
            ok, msg = bjorn_wifi_gate()
            if not ok:
                return redirect(url_for("mode", name="bjorn", err=msg))
        if current:
            stop(current)
            log_event(current, "info", MODULE_LABEL.get(current, current) + " stopped")
        start(name)
        app_state["active_mode"] = name
        _failed_seen.discard(name)
        log_event(name, "info", MODULE_LABEL.get(name, name) + " started")
    return redirect(url_for("mode", name=name))


@app.route("/bjorn/ready")
def bjorn_ready():
    # Bjorn is ready once its service is active AND its web UI answers on :8000.
    ready = is_active("bjorn")
    if ready:
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", 8000))
        except OSError:
            ready = False
        finally:
            s.close()
    return jsonify(ready=ready)


def _human_bytes(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def mirage_portal_info():
    """Small read-only summary of the portal currently served by Mirage."""
    meta = {}
    try:
        with open(MIRAGE_PORTAL_META, encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError):
        pass

    count = 0
    total = 0
    try:
        for root, _dirs, files in os.walk(MIRAGE_PORTAL_DIR):
            for name in files:
                path = os.path.join(root, name)
                try:
                    if os.path.isfile(path):
                        count += 1
                        total += os.path.getsize(path)
                except OSError:
                    pass
    except OSError:
        pass

    installed = os.path.isfile(os.path.join(MIRAGE_PORTAL_DIR, "index.html"))
    kind = meta.get("kind") if isinstance(meta, dict) else None
    label = meta.get("label") if isinstance(meta, dict) else None
    slug = meta.get("slug") if isinstance(meta, dict) else None
    if kind == "builtin" and slug in MIRAGE_PORTAL_LABELS:
        label = MIRAGE_PORTAL_LABELS[slug]
    if not label:
        label = "Default portal" if installed else "Portal not installed"
    if not kind:
        kind = "default" if installed else "missing"
    return {
        "label": label,
        "kind": kind,
        "slug": slug,
        "files": count,
        "bytes": total,
        "size": _human_bytes(total),
        "installed": installed,
    }


def mirage_portal_catalog(active_slug=None):
    """Built-in themes with on-disk availability and which one is active."""
    items = []
    for p in MIRAGE_PORTAL_CATALOG:
        index = os.path.join(MIRAGE_PORTAL_LIBRARY, p["slug"], "index.html")
        items.append({
            "slug": p["slug"],
            "name": p["name"],
            "lang": p["lang"],
            "available": os.path.isfile(index),
            "active": p["slug"] == active_slug,
        })
    return items


@app.route("/mirage/portal")
def mirage_portal_page():
    portal = mirage_portal_info()
    return render_template(
        "mirage_portal.html",
        portal=portal,
        library=mirage_portal_catalog(portal.get("slug")),
        active=is_active("fennec-mirage"),
        ok=request.args.get("ok"),
        err=request.args.get("err"),
    )


@app.route("/mirage/portal/apply/<slug>", methods=["POST"])
def mirage_portal_apply(slug):
    if is_active("fennec-mirage"):
        return redirect(url_for("mirage_portal_page",
                                err="Stop Mirage before changing the portal."))
    if slug not in MIRAGE_PORTAL_LABELS:
        return redirect(url_for("mirage_portal_page", err="Unknown portal."))
    try:
        res = subprocess.run(
            ["sudo", "-n", "/usr/local/bin/fennec-mirage-portal-manage", "apply", slug],
            capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            msg = (res.stderr or res.stdout or "Could not apply portal.").strip()
            return redirect(url_for("mirage_portal_page", err=msg[:180]))
    except Exception as exc:
        return redirect(url_for("mirage_portal_page", err=str(exc)[:180]))
    return redirect(url_for("mirage_portal_page",
                            ok="Portal set to " + MIRAGE_PORTAL_LABELS[slug] + "."))


@app.route("/mirage/portal/upload", methods=["POST"])
def mirage_portal_upload():
    if is_active("fennec-mirage"):
        return redirect(url_for("mirage_portal_page",
                                err="Stop Mirage before replacing the portal."))

    upload = request.files.get("portal")
    if not upload or not upload.filename:
        return redirect(url_for("mirage_portal_page", err="Choose a ZIP file first."))
    if not upload.filename.lower().endswith(".zip"):
        return redirect(url_for("mirage_portal_page", err="Portal must be a ZIP archive."))
    if request.content_length and request.content_length > MIRAGE_PORTAL_MAX_UPLOAD + 1024 * 1024:
        return redirect(url_for("mirage_portal_page", err="Portal archive is too large."))

    try:
        upload.save(MIRAGE_PORTAL_UPLOAD)
        if os.path.getsize(MIRAGE_PORTAL_UPLOAD) > MIRAGE_PORTAL_MAX_UPLOAD:
            raise ValueError("Portal archive is too large.")
        r = subprocess.run(
            ["sudo", "-n", "/usr/local/bin/fennec-mirage-portal-manage", "install"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            msg = (r.stderr or r.stdout or "Portal installation failed.").strip()
            return redirect(url_for("mirage_portal_page", err=msg[:180]))
    except Exception as exc:
        return redirect(url_for("mirage_portal_page", err=str(exc)[:180]))
    finally:
        try:
            os.remove(MIRAGE_PORTAL_UPLOAD)
        except OSError:
            pass

    return redirect(url_for("mirage_portal_page", ok="Portal replaced."))


@app.route("/mirage/portal/reset", methods=["POST"])
def mirage_portal_reset():
    if is_active("fennec-mirage"):
        return redirect(url_for("mirage_portal_page",
                                err="Stop Mirage before restoring the portal."))
    try:
        r = subprocess.run(
            ["sudo", "-n", "/usr/local/bin/fennec-mirage-portal-manage", "reset"],
            capture_output=True, text=True, timeout=20,
        )
        if r.returncode != 0:
            msg = (r.stderr or r.stdout or "Portal restore failed.").strip()
            return redirect(url_for("mirage_portal_page", err=msg[:180]))
    except Exception as exc:
        return redirect(url_for("mirage_portal_page", err=str(exc)[:180]))
    return redirect(url_for("mirage_portal_page", ok="Default portal restored."))


@app.route("/mirage/portal/preview")
def mirage_portal_preview():
    return render_template("mirage_portal_preview.html",
                           portal=mirage_portal_info())


@app.route("/mirage/portal/content/")
@app.route("/mirage/portal/content/<path:relpath>")
def mirage_portal_content(relpath="index.html"):
    """Read-only preview. Scripts, forms and network calls are disabled by CSP."""
    if not mirage_portal_info()["installed"]:
        abort(404)
    response = send_from_directory(MIRAGE_PORTAL_DIR, relpath)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' data:; "
        "script-src 'none'; connect-src 'none'; form-action 'none'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'self';"
    )
    return response


@app.route("/mirage/portal/preview/<slug>")
def mirage_portal_preview_builtin(slug):
    if slug not in MIRAGE_PORTAL_LABELS:
        abort(404)
    return render_template(
        "mirage_portal_preview.html",
        portal={"label": MIRAGE_PORTAL_LABELS[slug]},
        preview_src="/mirage/portal/library/" + slug + "/index.html",
    )


@app.route("/mirage/portal/library/<slug>/")
@app.route("/mirage/portal/library/<slug>/<path:relpath>")
def mirage_portal_library_content(slug, relpath="index.html"):
    """Read-only preview of a built-in theme. Scripts and forms disabled by CSP."""
    if slug not in MIRAGE_PORTAL_LABELS:
        abort(404)
    directory = os.path.join(MIRAGE_PORTAL_LIBRARY, slug)
    if not os.path.isfile(os.path.join(directory, "index.html")):
        abort(404)
    response = send_from_directory(directory, relpath)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' data:; "
        "script-src 'none'; connect-src 'none'; form-action 'none'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'self';"
    )
    return response


@app.route("/mirage/portal/template.zip")
def mirage_portal_template():
    """Download a ready-to-edit portal (the working default) as a starter ZIP."""
    import io
    import zipfile
    src = "/opt/fennec-mirage/default-portal"
    if not os.path.isfile(os.path.join(src, "index.html")):
        src = os.path.join(MIRAGE_PORTAL_LIBRARY, "default-en")
    if not os.path.isfile(os.path.join(src, "index.html")):
        abort(404)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(src):
            for name in files:
                full = os.path.join(root, name)
                zf.write(full, os.path.relpath(full, src))
    buf.seek(0)
    return send_file(buf, mimetype="application/zip",
                     as_attachment=True, download_name="fennec-portal-template.zip")


@app.route("/mirage/start/<bssid>")
def mirage_start(bssid):
    # Gate : Mirage ne peut cloner qu'un reseau de la whitelist.
    net = next((r for r in load_whitelist()
                if r["bssid"].upper() == bssid.upper()), None)
    if not net:
        return redirect(url_for("mode", name="mirage"))
    # Resolve the target's security, channel and PMF before starting the AP.
    sec, chan, pmf = resolve_target(net.get("bssid") or "", net.get("name") or "")
    chan_str = str(chan) if chan else ""
    # The AP launcher reads the SSID then its channel from this file.
    with open("/tmp/fennec-mirage-target", "w", encoding="utf-8") as f:
        f.write((net.get("name") or "") + "\n")
        f.write(chan_str + "\n")
    # Keep the same target metadata for deauthentication gating.
    with open("/tmp/fennec-mirage-meta.json", "w", encoding="utf-8") as f:
        json.dump({"bssid": net["bssid"], "security": sec, "chan": chan_str,
                   "pmf": pmf}, f)
    if vigie_monitor.monitor_state["active"]:
        vigie_monitor.stop()
    current = app_state["active_mode"]
    if current and current not in ("mirage", "vigie"):
        stop(current)
    _systemctl("stop", "fennec-mirage")
    _systemctl("start", "fennec-mirage")
    app_state["active_mode"] = "mirage"
    return redirect(url_for("mode", name="mirage"))

@app.route("/mirage/stop")
def mirage_stop():
    _systemctl("stop", "fennec-mirage-deauth")
    _systemctl("stop", "fennec-mirage")
    if app_state["active_mode"] == "mirage":
        app_state["active_mode"] = None
    return redirect(url_for("mode", name="mirage"))

def mirage_hs_filename(ssid, bssid):
    """Sly-compatible capture name: <ssid>_<bssid12hex>.pcap (None if no BSSID)."""
    raw = re.sub(r"[^0-9a-fA-F]", "", bssid or "").lower()
    if len(raw) != 12:
        return None
    name = re.sub(r"[^A-Za-z0-9-]", "", ssid or "") or "mirage"
    return "%s_%s.pcap" % (name, raw)


@app.route("/mirage/deauth/start")
def mirage_deauth_start():
    # Require a second free monitor interface and a target that allows deauthentication.
    iface = monitor_iface_except(current_mirage_ap_iface())
    if not iface:
        return redirect(url_for("mode", name="mirage"))
    try:
        with open("/tmp/fennec-mirage-meta.json", encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError):
        meta = {}
    if not deauth_possible(meta.get("security"), meta.get("pmf")):
        return redirect(url_for("mode", name="mirage"))
    # The deauth also forces the target's clients to reconnect, which yields a
    # 4-way handshake. bettercap writes it to Sly's handshake folder for offline
    # cracking. The filename matches what Sly expects (<ssid>_<bssid>.pcap).
    ssid = ""
    try:
        with open("/tmp/fennec-mirage-target", encoding="utf-8") as f:
            ssid = f.readline().strip()
    except OSError:
        pass
    hs_name = mirage_hs_filename(ssid, meta.get("bssid"))
    hs_path = os.path.join(HANDSHAKES_DIR, hs_name) if hs_name else ""
    with open("/tmp/fennec-mirage-deauth", "w", encoding="utf-8") as f:
        f.write((iface or "") + "\n")
        f.write((meta.get("bssid") or "") + "\n")
        f.write((meta.get("chan") or "") + "\n")
        f.write(hs_path + "\n")
    _systemctl("start", "fennec-mirage-deauth")
    return redirect(url_for("mode", name="mirage"))

@app.route("/mirage/deauth/stop")
def mirage_deauth_stop():
    _systemctl("stop", "fennec-mirage-deauth")
    return redirect(url_for("mode", name="mirage"))

@app.route("/mirage/handshake")
def mirage_handshake():
    """Whether a crackable handshake has been captured for the current target."""
    ssid = ""
    try:
        with open("/tmp/fennec-mirage-target", encoding="utf-8") as f:
            ssid = f.readline().strip()
    except OSError:
        pass
    try:
        with open("/tmp/fennec-mirage-meta.json", encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError):
        meta = {}
    fname = mirage_hs_filename(ssid, meta.get("bssid"))
    if not fname:
        return jsonify({"captured": False})
    path = os.path.join(HANDSHAKES_DIR, fname)
    captured = os.path.isfile(path) and capture_has_handshake(fname)
    return jsonify({"captured": bool(captured)})

@app.route("/mirage/clients")
def mirage_clients():
    # Clients connectes au faux AP, lus depuis les baux dnsmasq.
    clients = []
    try:
        with open("/tmp/fennec-mirage/leases", encoding="utf-8") as f:
            for line in f:
                p = line.split()
                if len(p) >= 4:
                    clients.append({"mac": p[1], "ip": p[2],
                                    "name": "" if p[3] == "*" else p[3]})
    except OSError:
        pass
    return jsonify(clients)

@app.route("/mirage/credentials")
def mirage_credentials():
    """Captures for the network currently being cloned, not every network ever seen."""
    import sqlite3
    # The ESSID being cloned right now; each capture is tagged with it.
    essid = None
    try:
        with open("/tmp/fennec-mirage-target", encoding="utf-8") as f:
            essid = f.readline().strip() or None
    except OSError:
        pass
    credentials = []
    try:
        conn = sqlite3.connect("/opt/fennec-mirage/credentials.db")
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT id, timestamp, username, password FROM credentials "
                "WHERE essid = ? ORDER BY id DESC LIMIT 10", (essid,)
            )
            rows = cursor.fetchall()
        except sqlite3.OperationalError:
            # Database predates the essid column (portal not redeployed yet).
            cursor.execute(
                "SELECT id, timestamp, username, password "
                "FROM credentials ORDER BY id DESC LIMIT 10"
            )
            rows = cursor.fetchall()
        for row in rows:
            credentials.append({
                "id": row[0],
                "timestamp": row[1],
                "username": row[2] or "",
                "password": row[3] or ""
            })
        conn.close()
    except Exception:
        pass
    return jsonify(credentials)

@app.route("/cracking/test/<bssid>")
def crack_test(bssid):
    autorises = {r["bssid"] for r in load_whitelist()}
    if bssid not in autorises:
        return redirect(url_for("mode", name="cracking"))
    capture = next((c for c in read_handshakes() if c["bssid"] == bssid), None)
    if not capture:
        return redirect(url_for("mode", name="cracking"))
    # Sly takes over: stop the running modes (Pwnagotchi / Bjorn / Sentry)
    if is_active("pwnagotchi"):
        stop("pwnagotchi")
    if is_active("bjorn"):
        stop("bjorn")
    if vigie_monitor.monitor_state["active"]:
        vigie_monitor.stop()
    app_state["active_mode"] = "cracking"
    app_state["network"] = capture["name"]
    pcap = os.path.join(HANDSHAKES_DIR, capture["file"])
    raton_engine.launch(pcap, bssid, capture["name"])
    return render_template("crack_result.html", c=capture)

@app.route("/cracking/export/<bssid>")
def crack_export(bssid):
    autorises = {r["bssid"] for r in load_whitelist()}
    if bssid not in autorises:
        return jsonify({"ok": False, "error": "Network not in allowed list"})
    capture = next((c for c in read_handshakes() if c["bssid"] == bssid), None)
    if not capture:
        return jsonify({"ok": False, "error": "No handshake for this network"})
    pcap = os.path.join(HANDSHAKES_DIR, capture["file"])
    output = "/tmp/raton_export_" + bssid.replace(":", "") + ".hc22000"
    try:
        subprocess.run(
            ["hcxpcapngtool", "-o", output, pcap],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as ex:
        return jsonify({"ok": False, "error": "Conversion failed: " + str(ex)})
    try:
        with open(output) as f:
            hash_hc = f.read().strip()
    except OSError:
        hash_hc = ""
    if not hash_hc:
        return jsonify({"ok": False, "error": "No crackable handshake in this capture"})
    file = os.path.basename(output)
    profile = raton_engine.profile_for_essid(capture["name"])
    fmt = (profile or {}).get("format") or {}
    mask = fmt.get("mask", "")
    if profile and profile.get("algo") == "mask" and "?" in mask:
        command = "cd ~/Downloads && hashcat -m 22000 " + file + " -a 3 " + mask
        type_attaque = "mask"
    else:
        command = ("cd ~/Downloads && hashcat -m 22000 " + file
                    + " /usr/share/wordlists/rockyou.txt"
                    + " -r /usr/share/hashcat/rules/best64.rule")
        type_attaque = "wordlist"
    return jsonify({
        "ok": True,
        "file": file,
        "hash": hash_hc,
        "command": command,
        "download": "/cracking/download/" + bssid,
        "type": type_attaque,
    })

@app.route("/cracking/download/<bssid>")
def crack_download(bssid):
    autorises = {r["bssid"] for r in load_whitelist()}
    if bssid not in autorises:
        abort(404)
    output = "/tmp/raton_export_" + bssid.replace(":", "") + ".hc22000"
    if not (os.path.exists(output) and os.path.getsize(output) > 0):
        capture = next((c for c in read_handshakes() if c["bssid"] == bssid), None)
        if not capture:
            abort(404)
        pcap = os.path.join(HANDSHAKES_DIR, capture["file"])
        try:
            subprocess.run(["hcxpcapngtool", "-o", output, pcap],
                           capture_output=True, text=True, timeout=30)
        except Exception:
            abort(404)
    if not (os.path.exists(output) and os.path.getsize(output) > 0):
        abort(404)
    from flask import send_file
    return send_file(output, as_attachment=True,
                     download_name=os.path.basename(output),
                     mimetype="text/plain")

@app.route("/cracking/gpu/<bssid>")
def crack_gpu(bssid):
    capture = next((c for c in read_handshakes() if c["bssid"] == bssid), None)
    name = capture["name"] if capture else bssid
    return render_template("crack_gpu.html", bssid=bssid, name=name)

@app.route("/cracking/state")
def crack_status():
    e = raton_engine.crack_state
    if e.get("found") and e.get("key") and not e.get("saved"):
        networks = load_whitelist()
        for r in networks:
            if r["bssid"] == e.get("bssid"):
                r["key"] = e["key"]
                break
        save_whitelist(networks)
        e["saved"] = True
    # Journal: a run in progress re-arms the logger; the final verdict is logged once.
    if e.get("active"):
        _sly_logged["bssid"] = None
    elif e.get("finished") and _sly_logged["bssid"] != e.get("bssid"):
        _sly_logged["bssid"] = e.get("bssid")
        net = e.get("network") or e.get("bssid") or "?"
        if e.get("no_handshake"):
            log_event("cracking", "warn", "Sly: no usable handshake (" + str(net) + ")")
        elif e.get("found"):
            log_event("cracking", "info", "Sly: key found (" + str(net) + ")")
        else:
            log_event("cracking", "info", "Sly: no weak key, likely robust (" + str(net) + ")")
    return jsonify(e)

@app.route("/cracking/wps/<bssid>")
def wps_start(bssid):
    # WPS pixie-dust (reaver) sur une cible autorisee. Gate : whitelist + carte monitor.
    net = next((r for r in load_whitelist()
                if r["bssid"].upper() == bssid.upper()), None)
    iface = detect_monitor_iface()
    if not net or not iface:
        return redirect(url_for("mode", name="cracking"))
    w = {k.upper(): v for k, v in load_wardrive().items()}.get(bssid.upper()) or {}
    chan = w.get("channel") or ""
    with open("/tmp/fennec-wps-target", "w", encoding="utf-8") as f:
        f.write("%s\n%s\n%s\n" % (iface, bssid, chan))
    try:
        os.remove("/tmp/fennec-wps-result.json")
    except OSError:
        pass
    _systemctl("stop", "fennec-wps")
    _systemctl("start", "fennec-wps")
    return render_template("wps.html", bssid=bssid, name=net.get("name") or bssid)

@app.route("/cracking/wps/state")
def wps_state():
    active = is_active("fennec-wps")
    res = {}
    try:
        with open("/tmp/fennec-wps-result.json", encoding="utf-8") as f:
            res = json.load(f)
    except (OSError, ValueError):
        pass
    log = ""
    try:
        with open("/tmp/fennec-wps.log", encoding="utf-8") as f:
            raw = f.read()
        skip = ("Reaver v", "Copyright", "Tactical Network", "cheffner",
                "WiFi Protected Setup Attack Tool")
        kept = [ln for ln in raw.splitlines() if not any(s in ln for s in skip)]
        log = "\n".join(kept).strip()[-1600:]
    except OSError:
        pass
    # On success, write the recovered key into the whitelist once.
    if res.get("status") == "found" and res.get("psk"):
        nets = load_whitelist()
        for r in nets:
            if r["bssid"].upper() == str(res.get("bssid", "")).upper() and r.get("key") != res["psk"]:
                r["key"] = res["psk"]
                save_whitelist(nets)
                break
    return jsonify(active=active, status=res.get("status"),
                   psk=res.get("psk"), log=log)

@app.route("/cracking/wps/stop")
def wps_stop():
    _systemctl("stop", "fennec-wps")
    return redirect(url_for("mode", name="cracking"))

@app.route("/cracking/stop")
def crack_stop():
    raton_engine.stop()
    return jsonify({"ok": True})

WARDRIVE_FILE = "/etc/pwnagotchi/wardrive.json"

def load_wardrive():
    try:
        with open(WARDRIVE_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _bettercap_creds():
    user = pw = ""
    try:
        with open("/etc/pwnagotchi/pwnagotchi-auto.cap", encoding="utf-8") as f:
            for line in f:
                m = re.match(r"\s*set\s+api\.rest\.username\s+(\S+)", line)
                if m:
                    user = m.group(1)
                m = re.match(r"\s*set\s+api\.rest\.password\s+(\S+)", line)
                if m:
                    pw = m.group(1)
    except OSError:
        pass
    return user, pw


@app.route("/gps")
def gps_state():
    # Live GPS status read from bettercap (only up while Pwnagotchi runs), so the
    # Echo can show a fix indicator on the device — no SSH needed in the car.
    import base64
    user, pw = _bettercap_creds()
    try:
        auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
        req = urllib.request.Request(
            "http://127.0.0.1:8081/api/session",
            headers={"Authorization": "Basic " + auth})
        with urllib.request.urlopen(req, timeout=3) as r:
            g = json.load(r).get("gps") or {}
        return jsonify(ok=True,
                       sats=int(g.get("NumSatellites") or 0),
                       fix=str(g.get("FixQuality") or "0"))
    except Exception:
        return jsonify(ok=False)  # bettercap/Pwnagotchi not running


def _risk_level(enc, wps):
    # Colour only on concrete, observed facts (no guessing a weak factory key
    # from the name — unreliable). Real crackability is decided by Raton, whose
    # verdict overrides this in map_view. "unknown" with no observed encryption,
    # "crit" open/WEP, "high" WPS enabled, "low" otherwise.
    if not enc:
        return "unknown"
    e = enc.upper()
    if e in ("OPEN", "NONE") or "WEP" in e:
        return "crit"
    if wps:
        return "high"
    return "low"


@app.route("/map")
def map_view():
    seen = {r["bssid"].upper() for r in load_whitelist()}
    wd = load_wardrive()
    wd_up = {k.upper(): v for k, v in wd.items()}  # for enc/wps lookup by BSSID
    try:
        verdicts = raton_engine.load_verdicts()
    except Exception:
        verdicts = {}

    def risk_for(key, enc, wps, essid, handshake):
        # A real Raton verdict wins over the heuristic (truth for audited boxes).
        v = verdicts.get(key)
        if v:
            return "crit" if v.get("result") == "cracked" else "low"
        # A captured handshake means the network is WPA/WPA2-PSK.
        if handshake and not enc:
            enc = "WPA2"
        return _risk_level(enc, wps)
    pts = {}  # keyed by uppercase BSSID so handshake and wardrive points dedup
    sans_position = 0
    # Handshake points (orange, or green if whitelisted) — take precedence.
    for c in read_handshakes():
        gps_path = os.path.join(HANDSHAKES_DIR, c["file"].replace(".pcap", ".gps.json"))
        try:
            with open(gps_path, "r", encoding="utf-8") as f:
                g = json.load(f)
            lat, lon = g.get("Latitude"), g.get("Longitude")
        except (FileNotFoundError, json.JSONDecodeError):
            lat = lon = None
        if lat and lon:
            key = c["bssid"].upper()
            w = wd_up.get(key, {})
            pts[key] = {
                "name": c["name"],
                "bssid": c["bssid"],
                "lat": lat,
                "lon": lon,
                "autorise": key in seen,
                "handshake": True,
                "risk": risk_for(key, w.get("enc"), w.get("wps"), c["name"], True),
            }
        else:
            sans_position += 1
    # Wardrive points (grey): every AP seen with a GPS fix, no handshake needed.
    # Their lat/lon is the signal-weighted centroid = estimated AP position.
    for bssid, w in wd.items():
        key = bssid.upper()
        if key in pts:
            continue  # already plotted via its handshake
        lat, lon = w.get("lat"), w.get("lon")
        if lat and lon:
            pts[key] = {
                "name": w.get("name") or bssid,
                "bssid": bssid,
                "lat": lat,
                "lon": lon,
                "autorise": key in seen,
                "handshake": False,
                "risk": risk_for(key, w.get("enc"), w.get("wps"), w.get("name"), False),
            }
    log_echo_health(len(wd), sans_position)
    return render_template("map.html", points=list(pts.values()),
                           sans_position=sans_position)


# ---------- Offline map tiles ----------
# Fennec serves OSM tiles from a local cache so the map works with no internet
# (nomadic use). A requested tile is served from disk if cached; otherwise, when
# online, it is fetched from OSM, saved, and served; offline and uncached, a
# neutral placeholder is returned. A "Save this area" action pre-fills the cache.

TILES_DIR = os.path.join(BASE, "tiles")
import base64 as _b64
_TILE_PLACEHOLDER = _b64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGO4//gFAAVPAqtspm6mAAAAAElFTkSuQmCC"
)
_tiles_dl = {"active": False, "done": 0, "total": 0, "failures": 0}


def fetch_osm_tile(z, x, y):
    url = f"https://tile.openstreetmap.org/{z}/{x}/{y}.png"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Fennec/1.0 (personal pentest console)"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read()
    except Exception:
        return None


@app.route("/tiles/<int:z>/<int:x>/<int:y>.png")
def tile(z, x, y):
    path = os.path.join(TILES_DIR, str(z), str(x), f"{y}.png")
    if os.path.exists(path):
        return send_file(path, mimetype="image/png")
    data = fetch_osm_tile(z, x, y)
    if data:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(data)
        except OSError:
            pass
        return Response(data, mimetype="image/png")
    return Response(_TILE_PLACEHOLDER, mimetype="image/png")


def _deg2tile(lat, lon, z):
    import math
    n = 2 ** z
    xt = int((lon + 180.0) / 360.0 * n)
    yt = int((1.0 - math.asinh(math.tan(math.radians(lat))) / math.pi) / 2.0 * n)
    return xt, yt


def _download_area(tiles):
    _tiles_dl.update({"active": True, "done": 0, "total": len(tiles), "failures": 0})
    for (z, x, y) in tiles:
        path = os.path.join(TILES_DIR, str(z), str(x), f"{y}.png")
        if not os.path.exists(path):
            data = fetch_osm_tile(z, x, y)
            if data:
                try:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as f:
                        f.write(data)
                except OSError:
                    _tiles_dl["failures"] += 1
                time.sleep(0.05)  # be gentle on the OSM tile servers
            else:
                _tiles_dl["failures"] += 1
        _tiles_dl["done"] += 1
    _tiles_dl["active"] = False


@app.route("/tiles/save", methods=["POST"])
def tiles_save():
    if _tiles_dl["active"]:
        return jsonify(error="A download is already running"), 409
    try:
        south = float(request.form["south"]); west = float(request.form["west"])
        north = float(request.form["north"]); east = float(request.form["east"])
        zmin = int(request.form.get("zmin", 13)); zmax = int(request.form.get("zmax", 16))
    except (KeyError, ValueError):
        return jsonify(error="Bad bounds"), 400
    tiles = []
    for z in range(zmin, zmax + 1):
        x1, y1 = _deg2tile(north, west, z)
        x2, y2 = _deg2tile(south, east, z)
        for x in range(min(x1, x2), max(x1, x2) + 1):
            for y in range(min(y1, y2), max(y1, y2) + 1):
                tiles.append((z, x, y))
    CAP = 1500
    if len(tiles) > CAP:
        return jsonify(error=f"Too many tiles ({len(tiles)}). Zoom in first.",
                       count=len(tiles)), 400
    threading.Thread(target=_download_area, args=(tiles,), daemon=True).start()
    return jsonify(total=len(tiles))


@app.route("/tiles/status")
def tiles_status():
    return jsonify(_tiles_dl)

# ---------- Connection ----------

@app.route("/connection")
def connection():
    networks = load_whitelist()
    ssid_act, bssid_act = wifi_active()
    known = known_wifi_profiles()
    current = None
    for r in networks:
        # Connectable if we hold a key, or the Pi already knows this network.
        r["connectable"] = bool(r.get("key")) or (r.get("name") in known)
        # Match the live Wi-Fi by SSID: a multi-band network answers on several
        # BSSIDs, so the associated BSSID may differ from the whitelisted one.
        r["connected"] = bool(ssid_act) and r.get("name") == ssid_act
        if r["connected"]:
            current = r
    if ssid_act and not current:
        current = {"name": ssid_act, "bssid": bssid_act, "connected": True}
    # Order: the connected network first, then the ones you can connect to, then
    # the rest; alphabetical within each group.
    networks.sort(key=lambda r: (
        0 if r.get("connected") else (1 if r.get("connectable") else 2),
        (r.get("name") or "").lower()))
    return render_template("connection.html", networks=networks, current=current,
                           conn=connection_state(), err=request.args.get("err"))

@app.route("/connection/to/<bssid>")
def connection_to(bssid):
    target = next((r for r in load_whitelist() if r["bssid"].upper() == bssid.upper()), None)
    if not target:
        return redirect(url_for("connection", err="Unknown network"))
    key = target.get("key", "")
    if not key and target.get("name") not in known_wifi_profiles():
        return redirect(url_for("connection",
            err="No key for this network. Add it in Allowed networks, or crack it with Sly."))
    try:
        r = subprocess.run(
            ["sudo", "-n", "/usr/local/bin/fennec-wifi-connect",
             target.get("name", ""), target["bssid"], key],
            capture_output=True, text=True, timeout=45,
        )
    except Exception:
        return redirect(url_for("connection", err="Connection command failed"))
    if r.returncode != 0:
        lines = (r.stderr or r.stdout or "").strip().splitlines()
        msg = lines[-1].strip() if lines else "Connection failed"
        return redirect(url_for("connection", err=msg[:120]))
    return redirect(url_for("connection"))

@app.route("/connection/stop")
def connection_stop():
    try:
        subprocess.run(["sudo", "-n", "/usr/local/bin/fennec-wifi-disconnect"],
                       capture_output=True, text=True, timeout=20)
    except Exception:
        pass
    return redirect(url_for("connection"))

@app.route("/connection/state")
def connection_state_json():
    """Live connection for the header badge (polled by the kiosk home page)."""
    return jsonify(connection_state())

# ---------- First-run Wi-Fi onboarding ----------

@app.route("/setup/wifi")
def setup_wifi():
    """Join any nearby Wi-Fi from the touchscreen (first-run onboarding)."""
    return render_template("setup_wifi.html",
                           networks=scan_wifi_simple(),
                           conn=connection_state(),
                           err=request.args.get("err"))

@app.route("/setup/wifi/connect", methods=["POST"])
def setup_wifi_connect():
    ssid = request.form.get("ssid", "").strip()
    bssid = request.form.get("bssid", "").strip()
    key = request.form.get("key", "")
    if not ssid or not bssid:
        return redirect(url_for("setup_wifi", err="Pick a network first"))
    try:
        r = subprocess.run(
            ["sudo", "-n", "/usr/local/bin/fennec-wifi-connect", ssid, bssid, key],
            capture_output=True, text=True, timeout=45,
        )
    except Exception:
        return redirect(url_for("setup_wifi", err="Connection command failed"))
    if r.returncode != 0:
        lines = (r.stderr or r.stdout or "").strip().splitlines()
        msg = lines[-1].strip() if lines else "Connection failed"
        return redirect(url_for("setup_wifi", err=msg[:120]))
    session.pop("wifi_setup_skipped", None)
    return redirect(url_for("setup_done"))

@app.route("/setup/done")
def setup_done():
    """Shown right after the first-run Wi-Fi connect: the real web and SSH
    addresses so the user can reach the device from another machine."""
    ip = primary_ip()
    return render_template("setup_done.html",
                           conn=connection_state(),
                           ip=ip)

@app.route("/setup/wifi/skip")
def setup_wifi_skip():
    session["wifi_setup_skipped"] = True
    return redirect(url_for("home"))

# ---------- Sentry ----------

@app.route("/hugin")
def hugin_page():
    return render_template("hugin.html",
                           machines=hugin.read_machines(),
                           stats=hugin.read_stats())

@app.route("/hugin/machine/<mac>")
def hugin_machine(mac):
    m = hugin.get_machine(mac)
    if not m:
        return redirect(url_for("hugin_page"))
    return render_template("hugin_machine.html", m=m)

@app.route("/hugin/msf")
def hugin_msf_page():
    cfg = hugin_msf.load_config()
    return render_template("hugin_msf.html", cfg=cfg, subnet=local_subnet(),
                           default_port=hugin_msf.DEFAULT_PORT,
                           err=request.args.get("err"))

@app.route("/hugin/msf/scan")
def hugin_msf_scan():
    return jsonify({"hosts": hugin_msf.detect(local_subnet())})

@app.route("/hugin/msf/state")
def hugin_msf_state():
    return jsonify(hugin_msf.state())

@app.route("/hugin/msf/connect", methods=["POST"])
def hugin_msf_connect():
    host = request.form.get("host", "").strip()
    port = request.form.get("port", "").strip() or hugin_msf.DEFAULT_PORT
    password = request.form.get("password", "").strip()
    if not host or not password:
        return redirect(url_for("hugin_msf_page", err="Host and password are required."))
    res = hugin_msf.connect(host, port, password)
    if not res.get("connected"):
        log_event("hugin", "warn", "Metasploit RPC unreachable (" + host + ")")
        return redirect(url_for("hugin_msf_page",
                                err=res.get("error") or "Connection failed.", host=host))
    log_event("hugin", "info", "Metasploit RPC connected (" + host + ")")
    return redirect(url_for("hugin_msf_page"))

@app.route("/hugin/msf/disconnect")
def hugin_msf_disconnect():
    hugin_msf.clear_config()
    return redirect(url_for("hugin_msf_page"))

@app.route("/hugin/plan")
def hugin_plan():
    module = request.args.get("module", "")
    ip = request.args.get("ip", "")
    cve = request.args.get("cve", "")
    port = request.args.get("port", "")
    if not hugin.module_known(module):
        abort(404)
    machine = next((m for m in hugin.read_machines() if m["ip"] == ip), None)
    if not machine:
        abort(404)
    rc = hugin.build_rc(module, ip, machine.get("hostname", ""), cve, port)
    if request.args.get("dl") == "1":
        from flask import Response
        fname = module.replace("/", "_") + ".rc"
        return Response(rc, mimetype="text/plain",
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})
    return render_template("hugin_plan.html", module=module, ip=ip, cve=cve, rc=rc)

@app.route("/hugin/run", methods=["POST"])
def hugin_run():
    module = request.form.get("module", "")
    ip = request.form.get("ip", "")
    cve = request.form.get("cve", "")
    port = request.form.get("port", "")
    if not hugin.module_known(module):
        return jsonify({"status": "error", "error": "Unknown module."})
    machine = next((m for m in hugin.read_machines() if m["ip"] == ip), None)
    if not machine:
        return jsonify({"status": "error", "error": "Unknown target."})
    opts = {"RHOSTS": ip}
    if port:
        opts["RPORT"] = port
    res = hugin_msf.run_module(module, opts)
    hugin_msf.log_run({
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "ip": ip, "hostname": machine.get("hostname", ""),
        "module": module, "cve": cve,
        "status": res.get("status"), "session": res.get("session"),
        "error": res.get("error", ""),
    })
    return jsonify(res)

@app.route("/hugin/sessions")
def hugin_sessions():
    return jsonify(hugin_msf.list_sessions())

@app.route("/hugin/session/run", methods=["POST"])
def hugin_session_run():
    sid = request.form.get("sid", "")
    cmd = request.form.get("cmd", "").strip()
    if not sid or not cmd:
        return jsonify({"ok": False, "error": "Missing session or command."})
    return jsonify(hugin_msf.session_run(sid, cmd))

@app.route("/hugin/activity")
def hugin_activity():
    return render_template("hugin_activity.html", runs=hugin_msf.read_runs())

@app.route("/hugin/files")
def hugin_files():
    return render_template("hugin_files.html", groups=hugin.list_files())

@app.route("/hugin/file")
def hugin_file():
    path = hugin.safe_output_path(request.args.get("path", ""))
    if not path:
        abort(404)
    if request.args.get("dl") == "1":
        from flask import send_file
        return send_file(path, as_attachment=True,
                         download_name=os.path.basename(path))
    name = os.path.basename(path)
    content, truncated = (hugin.read_text(path) if hugin.is_text(name)
                          else (None, False))
    return render_template("hugin_file.html", name=name,
                           rel=request.args.get("path", ""),
                           content=content, truncated=truncated)

@app.route("/vigie")
def vigie():
    return render_template("vigie.html")

@app.route("/vigie/data")
def vigie_data():
    appareils = vigie_devices()
    inconnus = sum(1 for a in appareils if a["inconnu"])
    return jsonify({"appareils": appareils, "total": len(appareils), "inconnus": inconnus})

@app.route("/vigie/mine/<mac>")
def vigie_mine(mac):
    mac = mac.upper()
    ids = load_mine()
    if mac not in ids:
        ids.append(mac)
        save_mine(ids)
    return jsonify({"ok": True})

@app.route("/vigie/notmine/<mac>")
def vigie_notmine(mac):
    mac = mac.upper()
    ids = [i for i in load_mine() if i.upper() != mac]
    save_mine(ids)
    return jsonify({"ok": True})

@app.route("/vigie/device/<ip>")
def vigie_device(ip):
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return redirect(url_for("vigie"))
    d = last_scan.get(ip) or device_pour(ip)
    return render_template("vigie_detail.html", d=d)

@app.route("/vigie/ports/<ip>")
def vigie_ports(ip):
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return jsonify({"ports": [], "type": "Unknown", "hote": None})
    d = last_scan.get(ip) or {}
    ports = scan_ports(ip)
    return jsonify({"ports": ports,
                    "type": guess_type(ports, d.get("vendor")),
                    "hote": host_name(ip)})

@app.route("/vigie/monitor/start")
def vigie_monitor_start():
    # Monitoring takes over: stop the other active modes.
    if app_state["active_mode"] in SERVICES:
        stop(app_state["active_mode"])
    if raton_engine.crack_state.get("active"):
        raton_engine.stop()
    ip = local_ip()
    prefix = ".".join(ip.split(".")[:3]) + "." if ip else None
    ok = vigie_monitor.start(prefix)
    if ok:
        app_state["active_mode"] = "vigie"
        log_event("vigie", "info", "Watch started (MITM)")
    return jsonify({"active": vigie_monitor.monitor_state["active"]})

@app.route("/vigie/monitor/stop")
def vigie_monitor_stop():
    vigie_monitor.stop()
    _history_flush(force=True)
    if app_state["active_mode"] == "vigie":
        app_state["active_mode"] = None
        log_event("vigie", "info", "Watch stopped")
    return jsonify({"active": False})

@app.route("/vigie/monitor/data")
def vigie_monitor_data():
    return jsonify(vigie_monitor.snapshot())

@app.route("/vigie/monitor/force")
def vigie_monitor_force():
    # Only while watching: the DoT/DoH block sits on the MITM-forwarded traffic.
    if not vigie_monitor.monitor_state["active"]:
        return jsonify({"active": False, "force": False})
    force = vigie_monitor.force_dns(request.args.get("on") == "1")
    return jsonify({"active": True, "force": force})

@app.route("/vigie/traffic/<ip>")
def vigie_traffic(ip):
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return jsonify({"active": False, "domains": []})
    d = last_scan.get(ip) or {}
    mac = d.get("mac") or arp_mac(ip)
    hote = (host_name(ip) or "").lower().rstrip(".")
    live = vigie_monitor.timestamps([c for c in (ip, hote) if c])
    dom_ts = merge_traffic(mac, live)   # fusionne live + historique persistant
    items = sorted(dom_ts.items(), key=lambda kv: kv[1], reverse=True)
    return jsonify({
        "active": vigie_monitor.monitor_state["active"],
        "vpn": vigie_monitor.vpn_info([c for c in (ip, hote) if c]),
        "domains": [{"d": dom, "t": ts} for dom, ts in items],
    })

@app.route("/vigie/rename/<mac>", methods=["POST"])
def vigie_rename(mac):
    set_name(mac, request.form.get("name", ""))
    return jsonify({"ok": True, "name": custom_name(mac)})

# ---------- Mole (drop-box LAN credential capture) ----------

@app.route("/mole")
def mole():
    return render_template("mole.html", snap=mole_engine.snapshot(),
                           conn=connection_state(), err=request.args.get("err"))

@app.route("/mole/toggle")
def mole_toggle():
    if mole_engine.is_active():
        mole_engine.stop()
        log_event("mole", "info", "Mole stopped")
        return redirect(url_for("mole"))
    # A drop box is a wired implant: Ethernet is the physical authorization.
    conn = connection_state()
    if conn["type"] != "ethernet":
        return redirect(url_for("mole", err="eth"))
    # Capture and relay bind the same ports; Sentry holds port 53. Stop them first.
    if mole_engine.is_relay_active():
        mole_engine.stop_relay()
    if vigie_monitor.monitor_state["active"]:
        vigie_monitor.stop()
    if mole_engine.start():
        log_event("mole", "info", "Mole started on " + conn["name"])
    else:
        return redirect(url_for("mole", err="start"))
    return redirect(url_for("mole"))

@app.route("/mole/state")
def mole_state():
    return jsonify(mole_engine.snapshot())

@app.route("/mole/crack")
def mole_crack():
    return jsonify({"started": mole_engine.crack()})

@app.route("/mole/relay")
def mole_relay():
    if mole_engine.is_relay_active():
        mole_engine.stop_relay()
        log_event("mole", "info", "Mole relay stopped")
        return redirect(url_for("mole"))
    # Active relay is aggressive and wired: Ethernet is the authorization.
    conn = connection_state()
    if conn["type"] != "ethernet":
        return redirect(url_for("mole", err="eth"))
    # Relay and capture bind the same ports; stop capture and Sentry's DNS first.
    if mole_engine.is_active():
        mole_engine.stop()
    if vigie_monitor.monitor_state["active"]:
        vigie_monitor.stop()
    if mole_engine.start_relay():
        log_event("mole", "info", "Mole relay started on " + conn["name"])
    else:
        return redirect(url_for("mole", err="start"))
    return redirect(url_for("mole"))

# ---------- Scout (handshake harvester) ----------

@app.route("/scout")
def scout():
    nets = load_whitelist()
    nets.sort(key=lambda r: (r.get("name") or "").lower())
    return render_template("scout.html", whitelist=nets,
                           err=request.args.get("err"))

@app.route("/scout/state")
def scout_state():
    return jsonify(scout_engine.snapshot())

@app.route("/scout/toggle")
def scout_toggle():
    """Start or stop the Wide sweep (Scout's single harvesting mode)."""
    if scout_engine.is_active():
        scout_engine.stop()
        if app_state["active_mode"] == "scout":
            app_state["active_mode"] = None
        log_event("scout", "info", "Scout stopped")
        return redirect(url_for("scout"))
    # Scout drives the monitor adapter, so it takes over from the other radio
    # modes (Pwnagotchi, Mirage, Bjorn) and from Sentry's MITM.
    if app_state["active_mode"] in SERVICES:
        stop(app_state["active_mode"])
    if vigie_monitor.monitor_state["active"]:
        vigie_monitor.stop()
    if scout_engine.start("wide"):
        app_state["active_mode"] = "scout"
        log_event("scout", "info", "Scout sweeping")
    else:
        return redirect(url_for("scout", err="start"))
    return redirect(url_for("scout"))

# ---------- Whitelist (routes) ----------

@app.route("/whitelist")
def whitelist_page():
    # Networks that already have a saved key come first, then alphabetical.
    nets = load_whitelist()
    nets.sort(key=lambda r: (0 if r.get("key") else 1, (r.get("name") or "").lower()))
    return render_template("whitelist_page.html", networks=nets)

@app.route("/whitelist/add", methods=["POST"])
def whitelist_add():
    name = request.form.get("name", "").strip()
    bssid = request.form.get("bssid", "").strip().upper()
    key = request.form.get("key", "").strip()
    back = request.form.get("back", "")
    source = request.form.get("source", "direct")
    if bssid:
        networks = load_whitelist()
        if not any(r["bssid"] == bssid for r in networks):
            entry = {"name": name or "Unnamed", "bssid": bssid}
            if key:
                entry["key"] = key
            networks.append(entry)
            save_whitelist(networks)
    if back == "scan":
        return redirect(url_for("scan", source=source))
    return redirect(url_for("whitelist_page"))

@app.route("/whitelist/edit", methods=["POST"])
def whitelist_edit():
    bssid = request.form.get("bssid", "").strip().upper()
    name = request.form.get("name", "").strip()
    key = request.form.get("key", "").strip()
    networks = load_whitelist()
    for r in networks:
        if r["bssid"] == bssid:
            r["name"] = name or r.get("name", "Unnamed")
            if key:
                r["key"] = key
            else:
                r.pop("key", None)
            break
    save_whitelist(networks)
    return redirect(url_for("whitelist_page"))

@app.route("/whitelist/remove/<bssid>")
def whitelist_remove(bssid):
    networks = [r for r in load_whitelist() if r["bssid"] != bssid]
    save_whitelist(networks)
    if app_state["network"] and app_state["network"]["bssid"] == bssid:
        app_state["network"] = None
    return redirect(url_for("whitelist_page"))

@app.route("/whitelist/reset")
def whitelist_reset():
    save_whitelist([])
    app_state["network"] = None
    source = request.args.get("source")
    if source:
        return redirect(url_for("scan", source=source))
    return redirect(url_for("whitelist_page"))

@app.route("/scan")
def scan():
    source = request.args.get("source", "direct")
    if source == "pwna":
        networks = read_handshakes()
    else:
        source = "direct"
        if request.args.get("rescan"):
            save_scan(direct_scan())
            return redirect(url_for("scan", source="direct"))
        networks = load_scan()
    seen = {r["bssid"] for r in load_whitelist()}
    return render_template("scan.html", networks=networks, seen=seen, source=source)

@app.route("/scan/vider/<source>")
def scan_clear(source):
    if source == "pwna":
        try:
            subprocess.run(
                ["sudo", "-n", "/usr/local/bin/fennec-clear-handshakes"],
                check=True, capture_output=True, timeout=20,
            )
        except Exception:
            pass
        return redirect(url_for("scan", source="pwna"))
    save_scan([])
    return redirect(url_for("scan", source="direct"))

@app.route("/rotate/toggle", methods=["POST"])
def rotate_toggle():
    # Rotate the Fennec UI by +90° each press (0 -> 90 -> 180 -> 270 -> 0).
    # Software rotation: instant, no reboot, no touch recalibration.
    s = load_settings()
    s["rotation"] = (int(s.get("rotation", 0)) + 90) % 360
    save_settings(s)
    return jsonify(rotation=s["rotation"])


# CSS applied to <body> for each orientation. 90° and 270° are portrait:
# the body logical size is swapped to 320x480 and rotated to fill the
# physical 480x320 panel, so the landscape layout reflows into portrait.
# Shared portrait tweaks: body is pinned absolutely (so the <html> flex box
# can't shrink it and warp the rotation geometry), and the home grid spreads
# its rows over the full height instead of staying landscape-centered.
_PORTRAIT_BASE = (
    "html{overflow:hidden!important;}"
    "body{position:absolute!important;top:0;left:0;"
    "width:320px!important;height:480px!important;transform-origin:top left;"
    # Put the rotated body on its own compositing layer, so a child repaint
    # (e.g. a blinking indicator) doesn't re-rasterize the rotation and make
    # the whole page jitter sideways each frame.
    "backface-visibility:hidden!important;}"
    ".grille{align-content:space-evenly!important;gap:10px 24px!important;"
    "padding:8px!important;}"
    # Narrow header: drop the network name, keep only the icon (green when
    # connected, grey when not) so the power button stays reachable.
    ".conn #conn-name{display:none!important;}"
    ".conn{max-width:none!important;padding:0!important;"
    "border:none!important;background:none!important;}"
    ".conn svg{width:22px!important;height:22px!important;}"
    ".conn.ok{color:#01F994!important;}"
    # Every app page: in portrait, drop the module name from the top bar and
    # keep only its icon. The title stays as a flex spacer that pushes the
    # action buttons to the right, but can shrink to nothing (min-width:0) so
    # it never forces the buttons onto a second line.
    ".topbar .title{visibility:hidden;flex:1 1 0;min-width:0;}"
)

_ROTATION_CSS = {
    90:  _PORTRAIT_BASE + "body{transform:rotate(90deg) translate(0,-100%);}",
    180: "body{transform:rotate(180deg);transform-origin:50% 50%;}",
    270: _PORTRAIT_BASE + "body{transform:rotate(270deg) translate(-100%,0);}",
}


@app.after_request
def apply_screen_rotation(response):
    # Inject the orientation CSS into every full HTML page. Done centrally
    # here so no individual template needs touching.
    try:
        rotation = int(load_settings().get("rotation", 0))
        css_rule = _ROTATION_CSS.get(rotation)
        if not css_rule:
            return response
        if response.direct_passthrough:
            return response
        if "text/html" not in response.headers.get("Content-Type", ""):
            return response
        html = response.get_data(as_text=True)
        if "</head>" not in html:
            return response
        css = '<style id="fennec-rotate">' + css_rule + '</style>'
        html = html.replace("</head>", css + "</head>", 1)
        # Mark the document as portrait so each page can add its own
        # portrait-only layout rules (html[data-portrait] ...), applied only
        # when rotated 90/270. Media queries can't do this: the framebuffer
        # stays 480x320 landscape and portrait is only a CSS transform.
        if rotation in (90, 270):
            html = html.replace(
                "<html", '<html data-portrait="1" data-rot="%d"' % rotation, 1)
        response.set_data(html)
    except Exception:
        pass
    return response


@app.route("/unlock", methods=["GET", "POST"])
def unlock():
    if request.method == "GET":
        return render_template("unlock.html")
    now = time.time()
    if now < _pin_fails["until"]:
        return jsonify(ok=False, wait=int(_pin_fails["until"] - now)), 429
    data = request.get_json(silent=True) or request.form
    if check_pin((data.get("pin") or "").strip()):
        _pin_fails["n"] = 0
        session["ok"] = True
        session.permanent = True
        return jsonify(ok=True)
    _pin_fails["n"] += 1
    if _pin_fails["n"] >= 5:
        _pin_fails["until"] = now + 30
        _pin_fails["n"] = 0
    return jsonify(ok=False), 401


@app.route("/pin/state")
def pin_state():
    return jsonify(set=pin_is_set())


@app.route("/pin/set", methods=["POST"])
def pin_set():
    # The PIN can only be set/changed from the touchscreen, never remotely.
    if not _is_local():
        abort(403)
    data = request.get_json(silent=True) or request.form
    pin = (data.get("pin") or "").strip()
    if not (pin.isdigit() and len(pin) == 6):
        return jsonify(ok=False, error="Il faut 6 chiffres."), 400
    set_pin(pin)
    return jsonify(ok=True)


@app.route("/pin/clear", methods=["POST"])
def pin_clear():
    if not _is_local():
        abort(403)
    clear_pin()
    return jsonify(ok=True)


@app.route("/pin")
def pin_page():
    return render_template("pin.html", pin_set=pin_is_set(), local=_is_local())


# ---------- System (SSH) password ----------

_PASSWD_ERRORS = {
    "BAD_CURRENT": "Current password is wrong.",
    "TOO_SHORT": "The new password must be at least 6 characters.",
    "SAME": "The new password must be different from the current one.",
    "NO_USER": "Could not read the account.",
    "ERROR": "Could not change the password.",
}


@app.route("/settings/password")
def settings_password():
    return render_template("settings_password.html")


@app.route("/settings/password/change", methods=["POST"])
def settings_password_change():
    data = request.get_json(silent=True) or request.form
    current = data.get("current") or ""
    new = data.get("new") or ""
    confirm = data.get("confirm") or ""
    if new != confirm:
        return jsonify(ok=False, error="The new passwords do not match."), 400
    if len(new) < 6:
        return jsonify(ok=False, error=_PASSWD_ERRORS["TOO_SHORT"]), 400
    try:
        r = subprocess.run(
            ["sudo", "-n", "/usr/local/bin/fennec-passwd"],
            input="%s\n%s\n" % (current, new),
            text=True, capture_output=True, timeout=15,
        )
    except Exception:
        return jsonify(ok=False, error=_PASSWD_ERRORS["ERROR"]), 500
    token = (r.stdout or "").strip().splitlines()
    token = token[-1].strip() if token else ""
    if r.returncode == 0 and token == "OK":
        return jsonify(ok=True)
    return jsonify(ok=False, error=_PASSWD_ERRORS.get(token, _PASSWD_ERRORS["ERROR"])), 400


MODULE_COLOR = {"pwnagotchi": "#19e38c", "bjorn": "#6f9bc8", "mirage": "#f0689b",
                "cracking": "#ffb020", "vigie": "#28c0d4", "hugin": "#a78bfa",
                "echo": "#2a3566", "fennec": "#01F994"}

@app.route("/journal")
def journal():
    refresh_crashed()
    rows = []
    for e in read_events():
        mod = e.get("mod", "fennec")
        rows.append({
            "time": time.strftime("%H:%M", time.localtime(e.get("t", 0))),
            "label": MODULE_LABEL.get(mod, mod),
            "color": MODULE_COLOR.get(mod, "#8b949e"),
            "level": e.get("level", "info"),
            "msg": e.get("msg", ""),
        })
    return render_template("journal.html", rows=rows)


@app.route("/journal/clear", methods=["POST"])
def journal_clear():
    clear_events()
    return jsonify(ok=True)


@app.errorhandler(500)
def _log_app_error(e):
    try:
        log_event("fennec", "error",
                  "App error: " + str(getattr(e, "original_exception", e)))
    except Exception:
        pass
    return "Internal error", 500


@app.route("/power/<action>", methods=["POST"])
def power(action):
    # Power off / reboot the Pi from the screen (keyboard-less kiosk).
    if action not in ("poweroff", "reboot"):
        abort(404)
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/systemctl", action],
            check=True, capture_output=True, timeout=20,
        )
    except Exception:
        pass
    return ("", 204)

# On Fennec shutdown, stop bettercap so the network is not left under ARP
# spoofing (otherwise the connection stays disrupted after exit).
atexit.register(vigie_monitor.stop)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True,
            debug=os.environ.get("FENNEC_DEBUG", "0") == "1")

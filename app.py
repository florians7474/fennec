import os
import re
import json
import time
import atexit
import threading
import socket
import raton_engine
import vigie_monitor
import hugin
import hugin_msf
from flask import Flask, render_template, redirect, url_for, abort, request, jsonify, send_file, Response

app = Flask(__name__)

BASE = os.path.dirname(os.path.abspath(__file__))
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

# ---------- Modes ----------

import subprocess
import urllib.request
import base64

# systemd services managed by each mode, in start order
SERVICES = {
    "pwnagotchi": ["bettercap", "pwngrid-peer", "pwnagotchi", "fennec-wardrive"],
    "bjorn": ["bjorn", "bjorn-console"],
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
    out.sort(key=lambda d: (not d["inconnu"], ip_key(d)))
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

def device_pour(ip):
    """Build a device detail for an IP, even outside the last scan."""
    mac = arp_mac(ip)
    pi = (ip == local_ip())
    routeur = (ip == passerelle_ip())
    mien = bool(mac) and mac in set(load_mine())
    name = custom_name(mac) or ("This Pi" if pi else ("Router" if routeur else "Unknown device"))
    return {"ip": ip, "mac": mac, "vendor": None, "name": name,
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
    active_mode = app_state["active_mode"]
    # Sly runs in a thread, not a service: the dot follows the engine's real state.
    if active_mode == "cracking" and not raton_engine.crack_state.get("active"):
        active_mode = None
        app_state["active_mode"] = None
    if active_mode == "vigie" and not vigie_monitor.monitor_state.get("active"):
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
                           connection=connection_state(), echo_count=echo_count)

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
    for f in files:
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
            captures[bssid] = {"name": name, "bssid": bssid, "file": f}
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
        for cap in captures:
            # Only check for a handshake on allowed networks (the only ones that
            # show a Test button), to avoid useless scans.
            cap["handshake"] = cap["bssid"] in seen and capture_has_handshake(cap["file"])
        # Testable captures first (allowed + handshake), then allowed without a
        # handshake, then locked ones; alphabetical within each group.
        captures.sort(key=lambda c: (
            0 if c["handshake"] else (1 if c["bssid"] in seen else 2),
            c["name"].lower(),
        ))
        return render_template("cracking.html", captures=captures, seen=seen)

    if name == "pwnagotchi":
        active = is_active("pwnagotchi")
        app_state["active_mode"] = "pwnagotchi" if active else app_state["active_mode"]
        url_ui = "/pwna-ui"
        return render_template("mode.html", key=name, info=MODES[name], active=active,
                               url_ui=url_ui, url_iframe=None)
    if name == "bjorn":
        active = is_active("bjorn")
        app_state["active_mode"] = "bjorn" if active else app_state["active_mode"]
        hote = request.host.split(":")[0]
        url_iframe = f"http://{hote}:8000/"
        conn = connection_state()
        reseau_scan = {"type": conn["type"], "name": conn["name"],
                       "sous_reseau": local_subnet()}
        return render_template("mode.html", key=name, info=MODES[name], active=active,
                               url_ui=None, url_iframe=url_iframe, reseau_scan=reseau_scan,
                               err=request.args.get("err"))
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
    else:
        if name == "bjorn":
            ok, msg = bjorn_wifi_gate()
            if not ok:
                return redirect(url_for("mode", name="bjorn", err=msg))
        if current:
            stop(current)
        start(name)
        app_state["active_mode"] = name
    return redirect(url_for("mode", name=name))

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
    return jsonify(e)

@app.route("/cracking/stop")
def crack_stop():
    raton_engine.stop()
    return jsonify({"ok": True})

WARDRIVE_FILE = os.path.join(HANDSHAKES_DIR, "wardrive.json")

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
        return redirect(url_for("hugin_msf_page",
                                err=res.get("error") or "Connection failed.", host=host))
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
    return jsonify({"active": vigie_monitor.monitor_state["active"]})

@app.route("/vigie/monitor/stop")
def vigie_monitor_stop():
    vigie_monitor.stop()
    _history_flush(force=True)
    if app_state["active_mode"] == "vigie":
        app_state["active_mode"] = None
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

# ---------- Whitelist (routes) ----------

@app.route("/whitelist")
def whitelist_page():
    return render_template("whitelist_page.html", networks=load_whitelist())

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
            html = html.replace("<html", '<html data-portrait="1"', 1)
        response.set_data(html)
    except Exception:
        pass
    return response


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
            debug=os.environ.get("FENNEC_DEBUG", "1") == "1")

#!/usr/bin/env python3
"""Scoutchi stats poller.

Reads bettercap's REST API (the access points it sees and the current GPS fix)
and the handshakes directory (what has actually been captured this session), and
writes a compact state file for the Scoutchi screen. Modelled on fennec-wardrive,
which reads the same API.

It also carries the GPS work Pwnagotchi used to do, so Echo works with Scoutchi
on its own:
  - writes a <capture>.gps.json next to each new handshake (the position where it
    was captured), which Echo plots as a located handshake point;
  - maintains /etc/pwnagotchi/wardrive.json, the signal-weighted centroid of every
    AP seen with a fix, which Echo plots as grey "seen" points.

Output:
  - /tmp/fennec-scoutchi/stats.json, consumed by scoutchi_engine.snapshot()
  - /etc/pwnagotchi/handshakes/<name>_<bssid>.gps.json, one per located capture
  - /etc/pwnagotchi/wardrive.json, shared with Echo (same format as fennec-wardrive)
"""
import base64
import glob
import json
import os
import re
import subprocess
import time
import urllib.request

RUN_DIR = "/tmp/fennec-scoutchi"
STATS = os.path.join(RUN_DIR, "stats.json")
CAPLET = "/etc/pwnagotchi/pwnagotchi-auto.cap"
API = "http://127.0.0.1:8081/api/session"
HANDSHAKES = "/etc/pwnagotchi/handshakes"
WARDRIVE = "/etc/pwnagotchi/wardrive.json"
INTERVAL = 5
START = time.time()


def creds():
    user = pw = ""
    try:
        with open(CAPLET, encoding="utf-8") as f:
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


def clean_name(name):
    if not name:
        return ""
    n = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("_")[:32]
    if n.lower() in ("", "hidden", "unknown", "missing"):
        return ""
    if re.match(r"^[0-9a-fA-F]{12,}$", n):   # undecoded hex blob, not a real SSID
        return ""
    return n


def classify(path):
    """'HS' if the capture holds a 4-way handshake, else 'PMKID'."""
    try:
        r = subprocess.run(["hcxpcapngtool", path], capture_output=True,
                           text=True, timeout=20)
        txt = (r.stdout or "") + (r.stderr or "")
    except Exception:
        return "HS"
    def num(pats):
        for p in pats:
            m = re.search(p, txt, re.I)
            if m:
                return int(m.group(1))
        return 0
    if num([r"EAPOL pairs[^\n]*?:\s*(\d+)"]) > 0:
        return "HS"
    if num([r"PMKID\(s\)[^\n]*?:\s*(\d+)", r"PMKID[^\n]*?:\s*(\d+)"]) > 0:
        return "PMKID"
    return "HS"


# ---- GPS / wardrive ---------------------------------------------------------

def fix_from_session(data):
    """Return (lat, lon, sats, fix) from bettercap's GPS field, or None when the
    fix is not reliable enough to record a position (mirrors fennec-wardrive)."""
    gps = (data or {}).get("gps") or {}
    try:
        lat = float(gps.get("Latitude") or 0)
        lon = float(gps.get("Longitude") or 0)
        sats = int(gps.get("NumSatellites") or 0)
        fix = str(gps.get("FixQuality") or "0")
    except (TypeError, ValueError):
        return None
    if fix == "0" or sats < 3 or (lat == 0 and lon == 0):
        return None
    return lat, lon, sats, fix


def gps_json_path(pcap):
    """The .gps.json sidecar path for a capture, matching what Echo reads."""
    if pcap.endswith(".pcap"):
        return pcap[:-5] + ".gps.json"
    return pcap + ".gps.json"


def write_gps_json(pcap, lat, lon, sats, fix):
    """Write a <capture>.gps.json next to the pcap, once (same shape the Pwnagotchi
    GPS plugin produced). Echo reads Latitude/Longitude from it."""
    path = gps_json_path(pcap)
    if os.path.exists(path):
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"Latitude": lat, "Longitude": lon,
                       "NumSatellites": sats, "FixQuality": fix}, f)
        os.chmod(path, 0o644)
    except OSError:
        pass


def load_wardrive():
    try:
        with open(WARDRIVE, encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_wardrive(store):
    tmp = WARDRIVE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(store, f)
        os.replace(tmp, WARDRIVE)
        os.chmod(WARDRIVE, 0o644)
    except OSError:
        pass


def wardrive_update(store, aps, lat, lon, now):
    """Fold the APs seen at this fix into the wardrive store, keeping a
    signal-weighted centroid per BSSID (the estimated AP position, refined on each
    pass). Returns True when the store changed. Identical to fennec-wardrive so
    Echo reads a single format whichever harvester produced it."""
    changed = False
    for ap in aps:
        bssid = (ap.get("mac") or "").upper()
        if not bssid:
            continue
        try:
            rssi = int(ap.get("rssi") or -999)
        except (TypeError, ValueError):
            rssi = -999
        essid = ap.get("hostname") or ""
        chan = ap.get("channel") or 0
        enc = ap.get("encryption") or ""
        wps = bool(ap.get("wps"))  # bettercap fills this only when WPS is seen
        w = max(rssi + 100, 1)     # signal weight: stronger = closer = heavier
        cur = store.get(bssid)
        if cur is None:
            store[bssid] = {
                "name": essid, "bssid": bssid, "channel": chan,
                "enc": enc, "wps": wps, "rssi": rssi,
                # incremental weighted centroid -> estimated AP position
                "slat": lat * w, "slon": lon * w, "sw": w, "n": 1,
                "lat": lat, "lon": lon,
                "first": now, "last": now,
            }
            changed = True
        else:
            cur["last"] = now
            if essid and not cur.get("name"):
                cur["name"] = essid
            if enc:
                cur["enc"] = enc
            if wps:
                cur["wps"] = True
            if rssi > cur.get("rssi", -999):
                cur["rssi"] = rssi
            # Seed accumulators for records written before this feature.
            if "sw" not in cur:
                w0 = max(cur.get("rssi", -70) + 100, 1)
                cur["slat"] = cur.get("lat", lat) * w0
                cur["slon"] = cur.get("lon", lon) * w0
                cur["sw"] = w0
                cur["n"] = cur.get("n", 1)
            cur["slat"] += lat * w
            cur["slon"] += lon * w
            cur["sw"] += w
            cur["n"] = cur.get("n", 1) + 1
            cur["lat"] = cur["slat"] / cur["sw"]
            cur["lon"] = cur["slon"] / cur["sw"]
            changed = True
    return changed


# ---- capture scan -----------------------------------------------------------

def captured(status, hs_cache, fix):
    """Networks with a capture file written this session -> HS / PMKID. When a
    reliable fix is available, tag each new capture with a .gps.json so Echo can
    plot it as a located handshake."""
    for f in glob.glob(os.path.join(HANDSHAKES, "*.pcap")):
        try:
            st = os.stat(f)
        except OSError:
            continue
        if st.st_mtime < START - 2:        # only this session's captures
            continue
        if fix:
            write_gps_json(f, *fix)
        base = os.path.basename(f)[:-5]
        if "_" not in base:
            continue
        name, _, raw = base.rpartition("_")
        raw = raw.lower()
        key = (st.st_mtime, st.st_size)
        hit = hs_cache.get(f)
        typ = hit[1] if hit and hit[0] == key else classify(f)
        hs_cache[f] = (key, typ)
        nm = clean_name(name)
        if not nm:
            continue
        if len(raw) == 12 and all(c in "0123456789abcdef" for c in raw):
            bssid = ":".join(raw[i:i + 2] for i in range(0, 12, 2)).upper()
        else:
            bssid = raw.upper()
        rank = 3 if typ == "HS" else 2
        if status.get(nm, (0,))[0] < rank:
            status[nm] = (rank, typ, bssid)


def main():
    user, pw = creds()
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    hs_cache = {}
    deauth_total = 0
    wardrive = load_wardrive()

    while True:
        time.sleep(INTERVAL)
        status = {}   # name -> (rank, type, bssid)

        data = {}
        try:
            req = urllib.request.Request(API, headers={"Authorization": "Basic " + auth})
            with urllib.request.urlopen(req, timeout=4) as r:
                data = json.load(r)
        except Exception:
            data = {}
        aps = (data.get("wifi") or {}).get("aps") or []
        fix = fix_from_session(data)

        captured(status, hs_cache, fix)

        for ap in aps:
            nm = clean_name(ap.get("hostname") or "")
            if not nm:
                continue
            bssid = (ap.get("mac") or "").upper()
            if status.get(nm, (0,))[0] < 1:
                status[nm] = (1, "seen", bssid)

        # Wardrive: record every AP seen at a reliable fix (grey Echo points),
        # into the same file the Pwnagotchi-era logger used.
        if fix:
            if wardrive_update(wardrive, aps, fix[0], fix[1], int(time.time())):
                save_wardrive(wardrive)

        # Continuous deauth hits every AP each ticker period; accumulate an
        # activity count so the UI shows it climbing.
        deauth_total += len(aps)

        items = []
        for want in ("HS", "PMKID", "seen"):
            for nm, (rank, typ, bssid) in status.items():
                if typ == want:
                    items.append({"name": nm, "bssid": bssid, "type": typ})
        hs = sum(1 for v in status.values() if v[1] == "HS")
        pmkid = sum(1 for v in status.values() if v[1] == "PMKID")

        out = {
            "mode": "wide", "status": "running",
            "handshakes": hs, "pmkid": pmkid, "aps": len(status),
            "deauth": deauth_total, "recent": items[:40],
        }
        try:
            with open(STATS, "w", encoding="utf-8") as f:
                json.dump(out, f)
            os.chmod(STATS, 0o644)
        except OSError:
            pass


if __name__ == "__main__":
    main()

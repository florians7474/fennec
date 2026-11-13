#!/usr/bin/env python3
"""Hugin - Metasploit RPC link (phase 3, brick 1).

Metasploit never runs on the Pi. It runs on a separate lab machine as
`msfrpcd -P <password> -S` (SSL off). The Pi only talks to it over the network
with a tiny msgpack-RPC client: detect the host, log in, show the state.
"""
import os
import re
import json
import time
import socket
import subprocess
import urllib.request

try:
    import msgpack
except ImportError:  # installed via apt (python3-msgpack) by install.sh
    msgpack = None

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(BASE, "msf_config.json")
DEFAULT_PORT = 55553
RPC_USER = "msf"


def load_config():
    try:
        with open(CONFIG, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, OSError, ValueError):
        return {}


def save_config(host, port, password):
    data = {"host": host, "port": int(port), "password": password}
    with open(CONFIG, "w", encoding="utf-8") as f:
        json.dump(data, f)
    try:
        os.chmod(CONFIG, 0o600)
    except OSError:
        pass
    return data


def clear_config():
    try:
        os.remove(CONFIG)
    except OSError:
        pass


def _rpc(host, port, method, *args, token=None):
    """One msgpack-RPC call to msfrpcd (SSL off). Returns the decoded reply."""
    if msgpack is None:
        raise RuntimeError("msgpack not installed")
    payload = [method]
    if token is not None:
        payload.append(token)
    payload.extend(args)
    body = msgpack.packb(payload, use_bin_type=False)
    req = urllib.request.Request(
        f"http://{host}:{port}/api/", data=body,
        headers={"Content-Type": "binary/message-pack"},
    )
    with urllib.request.urlopen(req, timeout=8) as r:
        return msgpack.unpackb(r.read(), raw=False, strict_map_key=False)


def login(host, port, password):
    """(token, version) on success; raises on failure."""
    res = _rpc(host, port, "auth.login", RPC_USER, password)
    if not isinstance(res, dict) or res.get("result") != "success":
        raise RuntimeError("authentication refused")
    token = res["token"]
    ver = _rpc(host, port, "core.version", token=token)
    version = ver.get("version", "") if isinstance(ver, dict) else ""
    return token, version


def connect(host, port, password):
    """Test the link and, on success, save the config. Returns a state dict."""
    port = int(port or DEFAULT_PORT)
    try:
        _token, version = login(host, port, password)
    except Exception as e:
        return {"connected": False, "error": _friendly(e)}
    save_config(host, port, password)
    return {"connected": True, "host": host, "port": port, "version": version}


def state():
    """Current link state, re-checked live from the saved config."""
    cfg = load_config()
    if not cfg.get("host"):
        return {"configured": False, "connected": False}
    try:
        _token, version = login(cfg["host"], cfg["port"], cfg["password"])
        return {"configured": True, "connected": True,
                "host": cfg["host"], "port": cfg["port"], "version": version}
    except Exception as e:
        return {"configured": True, "connected": False,
                "host": cfg["host"], "port": cfg["port"], "error": _friendly(e)}


def _friendly(exc):
    msg = str(exc).lower()
    if "refused" in msg and "auth" not in msg:
        return "Host reachable but no Metasploit RPC there (is msfrpcd running?)."
    if "authentication" in msg:
        return "Wrong RPC password."
    if "timed out" in msg or "timeout" in msg:
        return "No answer (host off, or a firewall blocks the port)."
    if "msgpack" in msg:
        return "msgpack missing on the Pi (reinstall)."
    return "Could not connect: " + str(exc)[:180]


def detect(subnet):
    """Scan the subnet for a host answering on the Metasploit RPC port.
    Rootless connect scan on a single port; returns a list of IPs."""
    if not subnet:
        return []
    try:
        r = subprocess.run(
            ["nmap", "-sT", "-p", str(DEFAULT_PORT), "--open", "-oG", "-", subnet],
            capture_output=True, text=True, timeout=90,
        )
    except Exception:
        return []
    hosts = []
    for line in r.stdout.splitlines():
        if f"{DEFAULT_PORT}/open" in line:
            m = re.search(r"Host:\s+([\d.]+)", line)
            if m:
                hosts.append(m.group(1))
    return hosts


# --- Phase 3 brick 3: run a module via RPC, record the result ----------------

RUNS = os.path.join(BASE, "hugin_runs.json")


def run_module(fullname, options, wait=15):
    """Run a Metasploit module on the remote msfrpcd and watch for a session.

    Correlation/execution happens on the remote lab machine, never on the Pi.
    Returns a status dict: 'session' (a session opened), 'no_session' (ran, no
    session within the wait window), or 'error'.
    """
    cfg = load_config()
    if not cfg.get("host"):
        return {"status": "error", "error": "Not connected to Metasploit."}
    host, port = cfg["host"], int(cfg["port"])
    try:
        token, _v = login(host, port, cfg["password"])
    except Exception as e:
        return {"status": "error", "error": _friendly(e)}
    mtype, _, refname = fullname.partition("/")
    if not mtype or not refname:
        return {"status": "error", "error": "Bad module name."}
    try:
        before = set((_rpc(host, port, "session.list", token=token) or {}).keys())
        res = _rpc(host, port, "module.execute", mtype, refname, options, token=token)
    except Exception as e:
        return {"status": "error", "error": _friendly(e)}
    if not isinstance(res, dict) or res.get("error"):
        detail = ""
        if isinstance(res, dict):
            detail = res.get("error_message") or res.get("error_string") or ""
        return {"status": "error", "error": detail or "Module did not start."}
    job_id = res.get("job_id")
    session = None
    end = time.time() + wait
    while time.time() < end:
        time.sleep(2)
        try:
            cur = _rpc(host, port, "session.list", token=token) or {}
        except Exception:
            break
        new = set(cur.keys()) - before
        if new:
            sid = sorted(new, key=lambda x: str(x))[0]
            s = cur.get(sid, {}) if isinstance(cur, dict) else {}
            session = {
                "id": str(sid),
                "type": s.get("type", ""),
                "peer": s.get("tunnel_peer", "") or s.get("session_host", ""),
                "info": s.get("info", ""),
            }
            break
    return {"status": "session" if session else "no_session",
            "job_id": job_id, "session": session}


def read_runs():
    try:
        with open(RUNS, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, OSError, ValueError):
        return []


def log_run(entry):
    runs = read_runs()
    runs.insert(0, entry)
    try:
        with open(RUNS, "w", encoding="utf-8") as f:
            json.dump(runs[:100], f)
    except OSError:
        pass

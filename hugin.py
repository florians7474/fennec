#!/usr/bin/env python3
"""Hugin - reads and surfaces Bjorn's results (Bjorn's companion module).

Phase 1: read-only. Parses Bjorn's own files under ~/Bjorn/data and presents
them per device. No action is taken on the network here.
"""
import os
import re
import csv

BJORN_DATA = os.path.expanduser("~/Bjorn/data")
NETKB = os.path.join(BJORN_DATA, "netkb.csv")
LIVESTATUS = os.path.join(BJORN_DATA, "livestatus.csv")
OUTPUT_DIR = os.path.join(BJORN_DATA, "output")

# netkb.csv fixed columns; every column after these is a Bjorn action.
FIXED_COLS = ["MAC Address", "IPs", "Hostnames", "Alive", "Ports"]


def _read_csv(path):
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            return list(csv.DictReader(f))
    except (FileNotFoundError, OSError):
        return []


def _ipkey(ip):
    parts = (ip or "").split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return tuple(int(p) for p in parts)
    return (999, 999, 999, 999)


def read_machines():
    """Devices from netkb.csv, excluding the STANDALONE pseudo-row.

    Each: mac, ip, hostname, alive, ports[], actions{name: status}, counts.
    An action cell is empty (not run) or "success_<ts>" / "failed_<ts>".
    """
    machines = []
    for row in _read_csv(NETKB):
        mac = (row.get("MAC Address") or "").strip()
        if not mac or mac == "STANDALONE":
            continue
        ports = [p for p in (row.get("Ports") or "").split(";") if p and p != "0"]
        actions = {}
        for col, val in row.items():
            if col in FIXED_COLS or col is None:
                continue
            val = (val or "").strip()
            if val:
                actions[col] = val
        nb_success = sum(1 for v in actions.values()
                         if v.lower().startswith("success"))
        machines.append({
            "mac": mac,
            "ip": (row.get("IPs") or "").strip(),
            "hostname": (row.get("Hostnames") or "").strip(),
            "alive": (row.get("Alive") or "").strip() == "1",
            "ports": ports,
            "nb_ports": len(ports),
            "actions": actions,
            "nb_actions": len(actions),
            "nb_success": nb_success,
        })
    machines.sort(key=lambda m: (not m["alive"], _ipkey(m["ip"])))
    return machines


# Common port -> service names, enough to label what Bjorn targets.
PORT_SERVICES = {
    "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS",
    "80": "HTTP", "110": "POP3", "111": "RPC", "135": "MSRPC", "139": "NetBIOS",
    "143": "IMAP", "161": "SNMP", "389": "LDAP", "443": "HTTPS", "445": "SMB",
    "465": "SMTPS", "500": "IKE", "515": "Printer", "548": "AFP", "631": "IPP",
    "993": "IMAPS", "995": "POP3S", "1433": "MSSQL", "1883": "MQTT",
    "3000": "HTTP", "3306": "MySQL", "3389": "RDP", "5000": "HTTP",
    "5432": "PostgreSQL", "5900": "VNC", "6379": "Redis", "8000": "HTTP",
    "8080": "HTTP", "8443": "HTTPS", "9100": "Printer", "32400": "Plex",
}


def _humanize(name):
    """RDPBruteforce -> RDP Bruteforce, StealFilesSSH -> Steal Files SSH."""
    name = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", name)
    name = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", name)
    return name


def _action_status(value):
    """('success'|'failed'|'done', 'YYYY-MM-DD HH:MM') from a netkb action cell."""
    low = value.lower()
    if low.startswith("success"):
        state = "success"
    elif low.startswith("fail"):
        state = "failed"
    else:
        state = "done"
    when = ""
    m = re.search(r"(\d{8})_(\d{6})", value)
    if m:
        d, t = m.group(1), m.group(2)
        when = f"{d[0:4]}-{d[4:6]}-{d[6:8]} {t[0:2]}:{t[2:4]}"
    return state, when


def get_machine(mac):
    """One device, enriched for its detail page: ports with service names and
    Bjorn actions with status and date. Returns None if not found."""
    machine = next((m for m in read_machines() if m["mac"] == mac), None)
    if not machine:
        return None
    machine["ports_detail"] = [
        {"port": p, "service": PORT_SERVICES.get(p, "unknown")}
        for p in machine["ports"]
    ]
    actions = []
    for name, value in sorted(machine["actions"].items()):
        state, when = _action_status(value)
        actions.append({"name": _humanize(name), "state": state, "when": when})
    machine["actions_detail"] = actions
    return machine


def read_stats():
    """Global counters from livestatus.csv."""
    rows = _read_csv(LIVESTATUS)
    if not rows:
        return {}
    r = rows[0]

    def _int(key):
        try:
            return int(r.get(key, 0))
        except (ValueError, TypeError):
            return 0

    return {
        "open_ports": _int("Total Open Ports"),
        "alive": _int("Alive Hosts Count"),
        "known": _int("All Known Hosts Count"),
        "vulns": _int("Vulnerabilities Count"),
    }

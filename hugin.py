#!/usr/bin/env python3
"""Hugin - reads and surfaces Bjorn's results (Bjorn's companion module).

Phase 1: read-only. Parses Bjorn's own files under ~/Bjorn/data and presents
them per device. No action is taken on the network here.
"""
import os
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

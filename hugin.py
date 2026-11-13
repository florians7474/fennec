#!/usr/bin/env python3
"""Hugin - reads and surfaces Bjorn's results (Bjorn's companion module).

Phase 1: read-only. Parses Bjorn's own files under ~/Bjorn/data and presents
them per device. No action is taken on the network here.
"""
import os
import re
import csv
import json
import time

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
        # Candidate Metasploit modules from the open services: Hugin's
        # exploitable-surface signal (Bjorn's own CVE list is usually empty).
        nb_mods = sum(len(SERVICE_MODULES.get(p, ())) for p in ports)
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
            "nb_mods": nb_mods,
        })
    # Most exposed first: candidate modules, then open ports, then alive, then IP.
    machines.sort(key=lambda m: (-m["nb_mods"], -m["nb_ports"],
                                 not m["alive"], _ipkey(m["ip"])))
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
    "512": "rexec", "513": "rlogin", "514": "rsh", "2049": "NFS",
    "3632": "distcc", "6667": "IRC", "8180": "HTTP",
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
    machine["vulns"] = machine_vulns(machine["ip"], machine["mac"])
    machine["files"] = machine_files(machine["ip"], machine["mac"])
    machine["msf"] = correlate_machine(machine)
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


# --- File explorer (phase 1, section B) -------------------------------------

# Human labels for Bjorn's output subfolders.
FILE_CATEGORIES = {
    "scan_results": "Scans",
    "vulnerabilities": "Vulnerabilities",
    "crackedpwd": "Cracked credentials",
    "data_stolen": "Stolen data",
    "zombies": "Zombies",
}

TEXT_EXT = {".txt", ".csv", ".log", ".json", ".md", ".nmap", ".xml", ".conf"}
PREVIEW_MAX = 100_000  # bytes shown in a preview


def _human_size(n):
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def list_files():
    """Bjorn's output files grouped by category, newest first.

    Returns [(label, [file, ...]), ...] ordered by FILE_CATEGORIES.
    """
    base = OUTPUT_DIR
    groups = {}
    for root, _dirs, files in os.walk(base):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, base)
            cat_dir = rel.split(os.sep)[0]
            label = FILE_CATEGORIES.get(cat_dir, cat_dir)
            try:
                st = os.stat(full)
            except OSError:
                continue
            groups.setdefault(label, []).append({
                "rel": rel,
                "name": name,
                "size_h": _human_size(st.st_size),
                "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
                "mtime_raw": st.st_mtime,
                "text": is_text(name),
            })
    for files in groups.values():
        files.sort(key=lambda f: -f["mtime_raw"])
    ordered, seen = [], set()
    for _dir, label in FILE_CATEGORIES.items():
        if label in groups and label not in seen:
            ordered.append((label, groups[label]))
            seen.add(label)
    for label, files in groups.items():
        if label not in seen:
            ordered.append((label, files))
    return ordered


def safe_output_path(rel):
    """Absolute path of a file under OUTPUT_DIR, or None if it escapes it."""
    base = os.path.realpath(OUTPUT_DIR)
    target = os.path.realpath(os.path.join(base, rel or ""))
    if target != base and not target.startswith(base + os.sep):
        return None
    if not os.path.isfile(target):
        return None
    return target


def is_text(name):
    return os.path.splitext(name)[1].lower() in TEXT_EXT


def read_text(abs_path):
    """(content, truncated) for a text preview, or (None, False) on error."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read(PREVIEW_MAX + 1)
    except OSError:
        return None, False
    return data[:PREVIEW_MAX], len(data) > PREVIEW_MAX


VULN_SUMMARY = os.path.join(OUTPUT_DIR, "vulnerabilities", "vulnerability_summary.csv")


def machine_vulns(ip, mac):
    """Vulnerabilities for a device, from vulnerability_summary.csv.
    Each: {port, vulns:[...]}. Empty when Bjorn found none."""
    out = []
    for r in _read_csv(VULN_SUMMARY):
        r_ip = (r.get("IP") or "").strip()
        r_mac = (r.get("MAC Address") or "").strip()
        if r_ip != ip and (not mac or r_mac != mac):
            continue
        raw = (r.get("Vulnerabilities") or "").strip()
        vulns = [v.strip() for v in raw.split(";") if v.strip()]
        if not vulns and not (r.get("Port") or "").strip():
            continue
        out.append({"port": (r.get("Port") or "").strip(), "vulns": vulns})
    return out


def machine_files(ip, mac):
    """Output files that belong to a device, matched by IP or MAC in the path
    (vuln scans, stolen data). Global files (cracked creds, network scans) stay
    in the main explorer."""
    base = OUTPUT_DIR
    mac_nc = (mac or "").replace(":", "").lower()
    ip_re = re.compile(r"(?<![0-9.])" + re.escape(ip) + r"(?![0-9])") if ip else None
    out = []
    for root, _dirs, files in os.walk(base):
        for name in files:
            rel = os.path.relpath(os.path.join(root, name), base)
            if ip_re and ip_re.search(rel):
                pass
            elif mac_nc and mac_nc in rel.lower():
                pass
            else:
                continue
            try:
                st = os.stat(os.path.join(root, name))
            except OSError:
                continue
            cat_dir = rel.split(os.sep)[0]
            out.append({
                "rel": rel,
                "name": name,
                "category": FILE_CATEGORIES.get(cat_dir, cat_dir),
                "size_h": _human_size(st.st_size),
                "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
                "text": is_text(name),
                "mtime_raw": st.st_mtime,
            })
    out.sort(key=lambda f: -f["mtime_raw"])
    return out


# --- Phase 2: Metasploit module correlation (local, no Metasploit running) ---

MSF_INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "hugin_msf_index.json")
RANK_LABELS = {0: "Manual", 100: "Low", 200: "Average", 300: "Normal",
               400: "Good", 500: "Great", 600: "Excellent"}
_msf_cache = None


def load_msf_index():
    """Load the compact CVE->modules index once, cached."""
    global _msf_cache
    if _msf_cache is None:
        try:
            with open(MSF_INDEX, encoding="utf-8") as f:
                _msf_cache = json.load(f)
        except (FileNotFoundError, OSError, ValueError):
            _msf_cache = {"by_cve": {}, "modules_with_cve": 0, "cve_count": 0}
    return _msf_cache


_msf_modules_set = None


def module_in_index(fullname):
    """Whether a module fullname is one Hugin knows (from the CVE index).
    Guards the plan generator against arbitrary input."""
    global _msf_modules_set
    if _msf_modules_set is None:
        s = set()
        for mods in load_msf_index().get("by_cve", {}).values():
            for m in mods:
                s.add(m["f"])
        _msf_modules_set = s
    return fullname in _msf_modules_set


def build_rc(module, ip, hostname="", cve="", rport=""):
    """A Metasploit resource script (.rc) pre-filled for a target.

    This only writes a text plan; it runs nothing. The operator reviews and
    runs it themselves, in an authorized lab.
    """
    lines = [
        "# Fennec / Hugin - Metasploit resource script",
        "# Lab use only, on explicitly authorized targets.",
        "# Review 'show options' before running.",
        f"# Target: {ip}" + (f" ({hostname})" if hostname else ""),
    ]
    if cve:
        lines.append(f"# Reference: {cve}")
    lines += [
        "",
        f"use {module}",
        f"set RHOSTS {ip}",
    ]
    if rport:
        lines.append(f"set RPORT {rport}")
    else:
        lines.append("# set RPORT <port>   # set the service port if the default is wrong")
    lines += [
        "# show options       # check required options first",
        "run",
        "",
    ]
    return "\n".join(lines)


# --- Phase 2b: Metasploit modules suggested by open service ------------------
# When Bjorn's vuln scan yields no CVE, the ports it mapped are still a real
# attack surface. These are well-known modules per service: candidates to try,
# never confirmed vulnerabilities. Keyed by port -> [{f: fullname, n: label,
# t: type}]. Covers this target's services and a few common extras.
SERVICE_MODULES = {
    "21": [{"f": "exploit/unix/ftp/vsftpd_234_backdoor", "n": "vsftpd 2.3.4 backdoor", "t": "exploit"},
           {"f": "auxiliary/scanner/ftp/ftp_login", "n": "FTP login bruteforce", "t": "auxiliary"},
           {"f": "auxiliary/scanner/ftp/anonymous", "n": "Anonymous FTP check", "t": "auxiliary"}],
    "22": [{"f": "auxiliary/scanner/ssh/ssh_login", "n": "SSH login bruteforce", "t": "auxiliary"},
           {"f": "auxiliary/scanner/ssh/ssh_version", "n": "SSH version", "t": "auxiliary"}],
    "23": [{"f": "auxiliary/scanner/telnet/telnet_login", "n": "Telnet login bruteforce", "t": "auxiliary"}],
    "25": [{"f": "auxiliary/scanner/smtp/smtp_enum", "n": "SMTP user enumeration", "t": "auxiliary"},
           {"f": "auxiliary/scanner/smtp/smtp_version", "n": "SMTP version", "t": "auxiliary"}],
    "80": [{"f": "auxiliary/scanner/http/http_version", "n": "HTTP version", "t": "auxiliary"},
           {"f": "auxiliary/scanner/http/dir_scanner", "n": "HTTP directory scan", "t": "auxiliary"}],
    "139": [{"f": "exploit/multi/samba/usermap_script", "n": "Samba usermap_script (root shell)", "t": "exploit"},
            {"f": "auxiliary/scanner/smb/smb_version", "n": "SMB version", "t": "auxiliary"}],
    "445": [{"f": "exploit/multi/samba/usermap_script", "n": "Samba usermap_script (root shell)", "t": "exploit"},
            {"f": "exploit/linux/samba/is_known_pipename", "n": "Samba is_known_pipename", "t": "exploit"},
            {"f": "auxiliary/scanner/smb/smb_login", "n": "SMB login bruteforce", "t": "auxiliary"},
            {"f": "auxiliary/scanner/smb/smb_version", "n": "SMB version", "t": "auxiliary"}],
    "512": [{"f": "auxiliary/scanner/rservices/rexec_login", "n": "rexec login", "t": "auxiliary"}],
    "513": [{"f": "auxiliary/scanner/rservices/rlogin_login", "n": "rlogin login", "t": "auxiliary"}],
    "514": [{"f": "auxiliary/scanner/rservices/rsh_login", "n": "rsh login", "t": "auxiliary"}],
    "2049": [{"f": "auxiliary/scanner/nfs/nfsmount", "n": "NFS export scan", "t": "auxiliary"}],
    "3306": [{"f": "auxiliary/scanner/mysql/mysql_login", "n": "MySQL login bruteforce", "t": "auxiliary"},
             {"f": "auxiliary/scanner/mysql/mysql_version", "n": "MySQL version", "t": "auxiliary"}],
    "5432": [{"f": "auxiliary/scanner/postgres/postgres_login", "n": "PostgreSQL login bruteforce", "t": "auxiliary"},
             {"f": "exploit/linux/postgres/postgres_payload", "n": "PostgreSQL payload (auth)", "t": "exploit"}],
    "5900": [{"f": "auxiliary/scanner/vnc/vnc_none_auth", "n": "VNC no-auth check", "t": "auxiliary"},
             {"f": "auxiliary/scanner/vnc/vnc_login", "n": "VNC login bruteforce", "t": "auxiliary"}],
    "1433": [{"f": "auxiliary/scanner/mssql/mssql_login", "n": "MSSQL login bruteforce", "t": "auxiliary"}],
    "3389": [{"f": "auxiliary/scanner/rdp/rdp_scanner", "n": "RDP scanner", "t": "auxiliary"}],
    "6379": [{"f": "auxiliary/scanner/redis/redis_login", "n": "Redis login", "t": "auxiliary"}],
    "6667": [{"f": "exploit/unix/irc/unreal_ircd_3281_backdoor", "n": "UnrealIRCd 3.2.8.1 backdoor", "t": "exploit"}],
    "3632": [{"f": "exploit/unix/misc/distcc_exec", "n": "distcc command execution", "t": "exploit"}],
    "8180": [{"f": "auxiliary/scanner/http/tomcat_mgr_login", "n": "Tomcat manager login", "t": "auxiliary"},
             {"f": "exploit/multi/http/tomcat_mgr_upload", "n": "Tomcat manager upload", "t": "exploit"}],
    "8080": [{"f": "auxiliary/scanner/http/tomcat_mgr_login", "n": "Tomcat manager login", "t": "auxiliary"}],
}

_service_set = None


def module_known(fullname):
    """Whether Hugin can plan/run this module: known from the CVE index or from
    the service map. Guards the plan and run endpoints against arbitrary input."""
    global _service_set
    if _service_set is None:
        s = set()
        for mods in SERVICE_MODULES.values():
            for m in mods:
                s.add(m["f"])
        _service_set = s
    return module_in_index(fullname) or fullname in _service_set


def suggest_by_service(machine):
    """Candidate modules for each open port Bjorn found, grouped by port.
    Suggestions from the attack surface, not confirmed vulnerabilities."""
    out = []
    for p in machine.get("ports", []):
        mods = SERVICE_MODULES.get(p)
        if not mods:
            continue
        out.append({
            "port": p,
            "service": PORT_SERVICES.get(p, "service"),
            "modules": [{"fullname": m["f"], "name": m["n"], "type": m["t"]}
                        for m in mods],
        })
    return out


def correlate_machine(machine):
    """Metasploit modules matching the CVEs Bjorn found on this device.

    Correlation only: a CVE match is a candidate, NOT a confirmed vulnerability
    and NOT a proven exploit. Running anything is a separate, deferred step.
    """
    idx = load_msf_index()
    by_cve = idx.get("by_cve", {})
    cves = set()
    for v in machine.get("vulns", []):
        for s in v.get("vulns", []):
            for c in re.findall(r"CVE-\d{4}-\d{4,7}", s, re.IGNORECASE):
                cves.add(c.upper())
    results = []
    for c in sorted(cves):
        mods = []
        for m in by_cve.get(c, []):
            mods.append({
                "fullname": m["f"], "name": m["n"], "type": m["t"],
                "rank": RANK_LABELS.get(m["r"], str(m["r"])),
            })
        results.append({"cve": c, "modules": mods})
    services = suggest_by_service(machine)
    return {
        "cves": results,
        "services": services,
        "nb_cve": len(cves),
        "nb_matched": sum(1 for r in results if r["modules"]),
        "nb_services": sum(len(s["modules"]) for s in services),
        "index": {"modules": idx.get("modules_with_cve", 0),
                  "cve": idx.get("cve_count", 0)},
    }

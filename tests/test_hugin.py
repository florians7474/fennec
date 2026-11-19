"""Tests for the Hugin logic: Metasploit correlation, path confinement, helpers."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hugin as h


def test_human_size():
    assert h._human_size(512) == "512 B"
    assert h._human_size(2048) == "2.0 KB"
    assert h._human_size(5 * 1024 * 1024) == "5.0 MB"


def test_is_text():
    assert h.is_text("scan.txt") is True
    assert h.is_text("report.CSV") is True
    assert h.is_text("photo.png") is False


def test_build_rc_with_rport():
    rc = h.build_rc("exploit/multi/samba/usermap_script", "1.2.3.4",
                    hostname="pc", cve="CVE-2007-2447", rport="445")
    assert "use exploit/multi/samba/usermap_script" in rc
    assert "set RHOSTS 1.2.3.4" in rc
    assert "set RPORT 445" in rc
    assert "CVE-2007-2447" in rc
    assert "pc" in rc


def test_build_rc_without_rport():
    rc = h.build_rc("auxiliary/scanner/ssh/ssh_login", "10.0.0.5")
    assert "set RHOSTS 10.0.0.5" in rc
    # No active RPORT line, only the commented placeholder.
    assert not any(line.strip().startswith("set RPORT") for line in rc.splitlines())


def test_module_known():
    assert h.module_known("exploit/multi/samba/usermap_script") is True
    assert h.module_known("exploit/not/a/real/module") is False


def test_suggest_by_service():
    sug = h.suggest_by_service({"ports": ["445", "22", "99999"]})
    ports = {g["port"] for g in sug}
    assert "445" in ports
    assert "22" in ports
    assert "99999" not in ports  # unmapped port yields nothing
    for g in sug:
        assert g["modules"]  # every returned port has at least one module


def test_safe_output_path_blocks_traversal():
    # A path escaping Bjorn's output dir must be rejected.
    assert h.safe_output_path("../../../etc/passwd") is None
    assert h.safe_output_path("../../secret") is None

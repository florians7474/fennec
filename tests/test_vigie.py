"""Tests for the Sentry traffic parser (dnsmasq + tshark line handling)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vigie_monitor as v


def _reset():
    with v._lock:
        v.monitor_state["hosts"].clear()
        v._vpn.clear()


def test_is_private():
    assert v._is_private("192.168.1.10") is True
    assert v._is_private("10.0.0.5") is True
    assert v._is_private("172.16.0.1") is True
    assert v._is_private("8.8.8.8") is False
    assert v._is_private("1.2.3.4") is False


def test_dnsmasq_line_records_domain():
    _reset()
    v._process("query[A] example.com from 192.168.1.10")
    assert "example.com" in v.monitor_state["hosts"].get("192.168.1.10", {})


def test_tshark_sni_records_domain():
    _reset()
    v._process("192.168.1.10\t1.2.3.4\twww.test.com\t\thttps")
    assert "www.test.com" in v.monitor_state["hosts"].get("192.168.1.10", {})


def test_ignores_server_to_client():
    # Source is public (a reply packet), not a local device: must be ignored.
    _reset()
    v._process("8.8.8.8\t192.168.1.10\treply.example\t\thttps")
    assert "8.8.8.8" not in v.monitor_state["hosts"]


def test_vpn_control_packet_flags_tunnel():
    _reset()
    v._process("192.168.1.10\t203.0.113.9\t\t\twireguard")
    assert "192.168.1.10" in v._vpn
    assert v._vpn["192.168.1.10"]["type"] == "WireGuard"
    # The endpoint is not logged as a contacted domain.
    assert "192.168.1.10" not in v.monitor_state["hosts"]

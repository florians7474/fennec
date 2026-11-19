"""Security gates: Bjorn Wi-Fi start gate and Mirage deauth gating."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app


def test_deauth_possible():
    assert app.deauth_possible("WPA2") is True
    assert app.deauth_possible("WPA2/WPA3") is True   # mixed mode still allows it
    assert app.deauth_possible("WEP") is True
    assert app.deauth_possible("OPEN") is True
    assert app.deauth_possible("") is True            # unknown -> allowed
    assert app.deauth_possible(None) is True


def test_deauth_blocked_on_wpa3():
    assert app.deauth_possible("WPA3") is False
    assert app.deauth_possible("WPA3-SAE") is False


def test_bjorn_gate_ethernet_is_free(monkeypatch):
    monkeypatch.setattr(app, "connection_state", lambda: {"type": "ethernet"})
    ok, _ = app.bjorn_wifi_gate()
    assert ok is True


def test_bjorn_gate_allows_whitelisted_wifi(monkeypatch):
    monkeypatch.setattr(app, "connection_state", lambda: {"type": "wifi"})
    monkeypatch.setattr(app, "wifi_active", lambda: ("HomeNet", None))
    monkeypatch.setattr(app, "load_whitelist", lambda: [{"name": "HomeNet"}])
    ok, _ = app.bjorn_wifi_gate()
    assert ok is True


def test_bjorn_gate_refuses_unlisted_wifi(monkeypatch):
    monkeypatch.setattr(app, "connection_state", lambda: {"type": "wifi"})
    monkeypatch.setattr(app, "wifi_active", lambda: ("NeighborNet", None))
    monkeypatch.setattr(app, "load_whitelist", lambda: [{"name": "HomeNet"}])
    ok, msg = app.bjorn_wifi_gate()
    assert ok is False
    assert msg


def test_bjorn_gate_refuses_offline(monkeypatch):
    monkeypatch.setattr(app, "connection_state", lambda: {"type": None})
    ok, msg = app.bjorn_wifi_gate()
    assert ok is False
    assert msg

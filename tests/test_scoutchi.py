"""Tests for the Scoutchi engine: adapter parsing and snapshot, all hardware-free."""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scoutchi_engine


def test_supports_monitor_true():
    info = (
        "Wiphy phy1\n"
        "\tSupported interface modes:\n"
        "\t\t * managed\n"
        "\t\t * monitor\n"
        "\tBand 1:\n"
    )
    assert scoutchi_engine._supports_monitor(info) is True


def test_supports_monitor_false():
    info = (
        "Wiphy phy0\n"
        "\tSupported interface modes:\n"
        "\t\t * managed\n"
        "\t\t * AP\n"
        "\tBand 1:\n"
    )
    assert scoutchi_engine._supports_monitor(info) is False


def test_bands_detection():
    assert scoutchi_engine._bands("Frequencies:\n\t* 2412 MHz\n") == "2.4"
    assert scoutchi_engine._bands("Frequencies:\n\t* 2412 MHz\n\t* 5180 MHz\n") == "2.4+5"


def test_start_targeted_without_target_fails(monkeypatch):
    # Even with an adapter present, targeted mode needs a BSSID.
    monkeypatch.setattr(scoutchi_engine, "detect_adapters",
                        lambda: [{"iface": "wlan1", "driver": "mt76",
                                  "label": "mt76", "bands": "2.4+5"}])
    assert scoutchi_engine.start("targeted", None) is False


def test_start_without_adapter_fails(monkeypatch):
    monkeypatch.setattr(scoutchi_engine, "detect_adapters", lambda: [])
    assert scoutchi_engine.start("wide") is False


def test_snapshot_shape(monkeypatch, tmp_path):
    monkeypatch.setattr(scoutchi_engine, "is_active", lambda: False)
    monkeypatch.setattr(scoutchi_engine, "detect_adapters", lambda: [])
    monkeypatch.setattr(scoutchi_engine, "STATS_FILE", str(tmp_path / "stats.json"))
    s = scoutchi_engine.snapshot()
    for key in ("active", "mode", "adapters", "handshakes", "pmkid", "aps", "recent"):
        assert key in s
    assert s["active"] is False
    assert s["handshakes"] == 0
    assert s["recent"] == []


def test_snapshot_reads_stats(monkeypatch, tmp_path):
    stats = tmp_path / "stats.json"
    stats.write_text(json.dumps({"mode": "wide", "handshakes": 3, "pmkid": 5,
                                 "aps": 20, "recent": [{"name": "Box", "bssid": "x", "type": "HS"}]}))
    monkeypatch.setattr(scoutchi_engine, "is_active", lambda: True)
    monkeypatch.setattr(scoutchi_engine, "detect_adapters", lambda: [])
    monkeypatch.setattr(scoutchi_engine, "STATS_FILE", str(stats))
    s = scoutchi_engine.snapshot()
    assert s["handshakes"] == 3
    assert s["pmkid"] == 5
    assert s["aps"] == 20
    assert len(s["recent"]) == 1

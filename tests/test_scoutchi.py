"""Tests for the Scoutchi engine: adapter parsing and snapshot, all hardware-free."""

import os
import sys
import re
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scoutchi_engine
import app


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


# --- GPS / wardrive integration (Scoutchi feeds Echo, as Pwnagotchi used to) ---

import importlib.util

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_poller():
    """Load the standalone poller script as a module (its name has hyphens)."""
    path = os.path.join(ROOT, "system", "fennec-scoutchi-poll.py")
    spec = importlib.util.spec_from_file_location("scoutchi_poll", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_fix_from_session_rejects_weak_fix():
    poll = _load_poller()
    assert poll.fix_from_session({}) is None
    # No fix quality / too few satellites / null island -> no position.
    assert poll.fix_from_session({"gps": {"Latitude": 48.8, "Longitude": 2.3,
                                          "NumSatellites": 2, "FixQuality": "1"}}) is None
    assert poll.fix_from_session({"gps": {"Latitude": 48.8, "Longitude": 2.3,
                                          "NumSatellites": 7, "FixQuality": "0"}}) is None
    assert poll.fix_from_session({"gps": {"Latitude": 0, "Longitude": 0,
                                          "NumSatellites": 7, "FixQuality": "1"}}) is None


def test_fix_from_session_accepts_good_fix():
    poll = _load_poller()
    fix = poll.fix_from_session({"gps": {"Latitude": 48.85, "Longitude": 2.35,
                                         "NumSatellites": 7, "FixQuality": "1"}})
    assert fix == (48.85, 2.35, 7, "1")


def test_write_gps_json_shape_and_once(tmp_path):
    poll = _load_poller()
    pcap = tmp_path / "Box_001122334455.pcap"
    pcap.write_bytes(b"")
    poll.write_gps_json(str(pcap), 48.85, 2.35, 7, "1")
    sidecar = tmp_path / "Box_001122334455.gps.json"
    assert sidecar.exists()
    data = json.loads(sidecar.read_text())
    # Echo reads Latitude/Longitude from the sidecar: the keys must match exactly.
    assert data["Latitude"] == 48.85 and data["Longitude"] == 2.35
    # Existing sidecar is never overwritten (keeps the capture-time position).
    sidecar.write_text(json.dumps({"Latitude": 1.0, "Longitude": 1.0}))
    poll.write_gps_json(str(pcap), 48.85, 2.35, 7, "1")
    assert json.loads(sidecar.read_text())["Latitude"] == 1.0


def test_wardrive_update_centroid():
    poll = _load_poller()
    store = {}
    aps = [{"mac": "aa:bb:cc:dd:ee:ff", "rssi": -40, "hostname": "Box",
            "channel": 6, "encryption": "WPA2", "wps": False}]
    assert poll.wardrive_update(store, aps, 48.0, 2.0, 1000) is True
    key = "AA:BB:CC:DD:EE:FF"
    assert key in store and store[key]["lat"] == 48.0
    # A second pass refines the weighted centroid and bumps the sample count.
    poll.wardrive_update(store, aps, 50.0, 4.0, 1005)
    assert store[key]["n"] == 2
    assert 48.0 < store[key]["lat"] < 50.0


def test_poller_contract_matches_echo():
    # Regression: Echo (app.py) reads wardrive.json and the .gps.json sidecars;
    # the poller must write the same path and the same sidecar naming, or the
    # captures stay invisible on the map.
    with open(os.path.join(ROOT, "system", "fennec-scoutchi-poll.py")) as f:
        script = f.read()
    m = re.search(r'WARDRIVE\s*=\s*"([^"]+)"', script)
    assert m and app.WARDRIVE_FILE == m.group(1)
    poll = _load_poller()
    assert poll.gps_json_path("/x/Box_00.pcap") == "/x/Box_00.gps.json"


# --- stable per-session publishing (Sly never reads a file being written) ---

def test_publish_only_when_settled_and_real(tmp_path, monkeypatch):
    poll = _load_poller()
    live = tmp_path / "live"; live.mkdir()
    dest = tmp_path / "hs"; dest.mkdir()
    monkeypatch.setattr(poll, "LIVE", str(live))
    monkeypatch.setattr(poll, "HANDSHAKES", str(dest))
    # Pretend the capture holds a 4-way handshake.
    monkeypatch.setattr(poll, "hcx_counts", lambda p: (1, 0))

    cap = live / "Box_001122334455.pcap"
    cap.write_bytes(b"xxxx")
    settle, published, cache = {}, {}, {}

    # First pass: file just seen, not settled yet -> nothing published.
    poll.scan_and_publish({}, cache, settle, published, None)
    assert not (dest / "Box_001122334455.pcap").exists()

    # Second pass with the same (mtime, size): settled -> published atomically.
    poll.scan_and_publish({}, cache, settle, published, None)
    assert (dest / "Box_001122334455.pcap").exists()
    # No stray temp file left behind.
    assert not list(dest.glob("*.fennectmp"))


def test_publish_skips_empty_capture(tmp_path, monkeypatch):
    poll = _load_poller()
    live = tmp_path / "live"; live.mkdir()
    dest = tmp_path / "hs"; dest.mkdir()
    monkeypatch.setattr(poll, "LIVE", str(live))
    monkeypatch.setattr(poll, "HANDSHAKES", str(dest))
    monkeypatch.setattr(poll, "hcx_counts", lambda p: (0, 0))  # no handshake, no PMKID

    cap = live / "Box_001122334455.pcap"
    cap.write_bytes(b"xxxx")
    settle, published, cache = {}, {}, {}
    poll.scan_and_publish({}, cache, settle, published, None)
    poll.scan_and_publish({}, cache, settle, published, None)
    assert not (dest / "Box_001122334455.pcap").exists()


def test_publish_waits_while_file_grows(tmp_path, monkeypatch):
    poll = _load_poller()
    live = tmp_path / "live"; live.mkdir()
    dest = tmp_path / "hs"; dest.mkdir()
    monkeypatch.setattr(poll, "LIVE", str(live))
    monkeypatch.setattr(poll, "HANDSHAKES", str(dest))
    monkeypatch.setattr(poll, "hcx_counts", lambda p: (1, 0))

    cap = live / "Box_001122334455.pcap"
    cap.write_bytes(b"xxxx")
    settle, published, cache = {}, {}, {}
    poll.scan_and_publish({}, cache, settle, published, None)
    cap.write_bytes(b"xxxxyyyy")   # bettercap appended -> size changed
    poll.scan_and_publish({}, cache, settle, published, None)
    assert not (dest / "Box_001122334455.pcap").exists()  # still not settled


def test_publish_writes_gps_sidecar_when_located(tmp_path, monkeypatch):
    poll = _load_poller()
    live = tmp_path / "live"; live.mkdir()
    dest = tmp_path / "hs"; dest.mkdir()
    monkeypatch.setattr(poll, "LIVE", str(live))
    monkeypatch.setattr(poll, "HANDSHAKES", str(dest))
    monkeypatch.setattr(poll, "hcx_counts", lambda p: (1, 0))

    cap = live / "Box_001122334455.pcap"
    cap.write_bytes(b"xxxx")
    settle, published, cache = {}, {}, {}
    fix = (48.85, 2.35, 7, "1")
    poll.scan_and_publish({}, cache, settle, published, fix)
    poll.scan_and_publish({}, cache, settle, published, fix)
    sidecar = dest / "Box_001122334455.gps.json"
    assert sidecar.exists()
    assert json.loads(sidecar.read_text())["Latitude"] == 48.85

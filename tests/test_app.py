"""Tests for app-level logic: risk, PIN, the journal, and file-path regressions."""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_risk_levels():
    assert app._risk_level(None, False) == "unknown"
    assert app._risk_level("WEP", False) == "crit"
    assert app._risk_level("WPA2", True) == "high"
    assert app._risk_level("WPA2", False) == "low"


def test_pin_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "SETTINGS_FILE", str(tmp_path / "settings.json"))
    assert app.pin_is_set() is False
    app.set_pin("123456")
    assert app.pin_is_set() is True
    assert app.check_pin("123456") is True
    assert app.check_pin("000000") is False
    app.clear_pin()
    assert app.pin_is_set() is False


def test_pin_is_hashed(tmp_path, monkeypatch):
    f = tmp_path / "settings.json"
    monkeypatch.setattr(app, "SETTINGS_FILE", str(f))
    app.set_pin("424242")
    assert "424242" not in f.read_text()  # stored as a hash, never in clear


def test_events_log_order_and_clear(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "EVENTS_FILE", str(tmp_path / "events.json"))
    app.clear_events()
    app.log_event("bjorn", "error", "boom")
    app.log_event("echo", "info", "ok")
    evs = app.read_events()
    assert len(evs) == 2
    assert evs[0]["mod"] == "echo"  # newest first
    app.clear_events()
    assert app.read_events() == []


def test_events_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "EVENTS_FILE", str(tmp_path / "events.json"))
    app.clear_events()
    for i in range(app.EVENTS_MAX + 20):
        app.log_event("fennec", "info", str(i))
    assert len(app.read_events()) == app.EVENTS_MAX


def test_echo_health_dedup(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "EVENTS_FILE", str(tmp_path / "events.json"))
    monkeypatch.setattr(app, "_echo_last", {"count": None, "nogps": None})
    app.clear_events()
    app.log_echo_health(0, 0)   # warns: wardrive empty
    app.log_echo_health(0, 0)   # no change -> nothing logged
    app.log_echo_health(5, 0)   # info: 5 networks loaded
    msgs = [e["msg"] for e in app.read_events()]
    assert any("wardrive empty" in m for m in msgs)
    assert any("5 networks loaded" in m for m in msgs)
    assert len(app.read_events()) == 2  # three calls, one duplicate dropped


def test_mine_persistence_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "MINE_FILE", str(tmp_path / "my_devices.json"))
    c = app.app.test_client()
    local = {"REMOTE_ADDR": "127.0.0.1"}
    c.get("/vigie/mine/aa:bb:cc:dd:ee:ff", environ_base=local)  # approve a device
    assert "AA:BB:CC:DD:EE:FF" in app.load_mine()               # persisted, upper
    c.get("/vigie/notmine/AA:BB:CC:DD:EE:FF", environ_base=local)
    assert "AA:BB:CC:DD:EE:FF" not in app.load_mine()


def test_vigie_template_calls_real_routes():
    # Regression: the FR->EN rename left the client calling /vigie/mien, which
    # 404'd, so approvals never persisted. The template must hit the real routes.
    with open(os.path.join(ROOT, "templates", "vigie.html")) as f:
        html = f.read()
    assert "'mine'" in html and "'notmine'" in html
    assert "'mien'" not in html and "'pasmien'" not in html


def test_vendor_from_mac(tmp_path, monkeypatch):
    oui = tmp_path / "oui"
    oui.write_text("582059 Xiaomi Communications Co Ltd\nA86DAA Alienware\n")
    monkeypatch.setattr(app, "NMAP_OUI", str(oui))
    monkeypatch.setattr(app, "_oui_map", None)  # force reload from the fixture
    assert app.vendor_from_mac("58:20:59:90:0B:10") == "Xiaomi Communications Co Ltd"
    assert app.vendor_from_mac("a8:6d:aa:52:c3:c6") == "Alienware"  # case-insensitive
    assert app.vendor_from_mac("00:00:00:00:00:00") is None
    assert app.vendor_from_mac(None) is None


def test_device_sort_order(monkeypatch):
    # Expected order: router, then Pi, then mine, then unknown.
    monkeypatch.setattr(app, "scan_network", lambda: [
        {"ip": "192.168.1.50", "mac": "CC:CC:CC:CC:CC:CC", "vendor": "Acme"},   # unknown
        {"ip": "192.168.1.254", "mac": "DD:DD:DD:DD:DD:DD", "vendor": "Box"},   # router
        {"ip": "192.168.1.122", "mac": "EE:EE:EE:EE:EE:EE", "vendor": "Pi"},    # this Pi
        {"ip": "192.168.1.40", "mac": "BB:BB:BB:BB:BB:BB", "vendor": "Dell"},   # mine
    ])
    monkeypatch.setattr(app, "local_ip", lambda: "192.168.1.122")
    monkeypatch.setattr(app, "passerelle_ip", lambda: "192.168.1.254")
    monkeypatch.setattr(app, "load_mine", lambda: ["BB:BB:BB:BB:BB:BB"])
    monkeypatch.setattr(app, "custom_name", lambda mac: None)
    order = [d["ip"] for d in app.vigie_devices()]
    assert order == ["192.168.1.254", "192.168.1.122", "192.168.1.40", "192.168.1.50"]


def test_wardrive_path_matches_logger():
    # Regression: Fennec once read wardrive.json from the wrong path, so the
    # weekend's data stayed invisible. The read path must equal the write path.
    # The Scoutchi poller is the live writer now (see test_poller_contract_matches_echo);
    # the archived Pwnagotchi-era logger kept the same path and is checked here too.
    with open(os.path.join(ROOT, "archive", "pwnagotchi", "fennec-wardrive")) as f:
        script = f.read()
    m = re.search(r'STORE\s*=\s*"([^"]+)"', script)
    assert m, "STORE path not found in fennec-wardrive"
    assert app.WARDRIVE_FILE == m.group(1)


def test_mirage_ap_interface_is_detected_dynamically():
    with open(os.path.join(ROOT, "system", "fennec-mirage-ap")) as f:
        script = f.read()
    assert "detect_ap_iface" in script
    assert "iface_supports_ap" in script
    assert "iface_is_connected" in script
    assert "IFACE=wlan1" not in script


def test_mirage_service_uses_dynamic_cleanup():
    with open(os.path.join(ROOT, "system", "fennec-mirage.service")) as f:
        service = f.read()
    assert "/usr/local/bin/fennec-mirage-ap cleanup" in service
    assert "ip addr flush dev wlan1" not in service


def test_installer_deploys_mirage_ap_runtime():
    with open(os.path.join(ROOT, "install.sh")) as f:
        installer = f.read()
    assert 'sudo cp "$SYS/fennec-mirage-ap" /usr/local/bin/fennec-mirage-ap' in installer
    assert 'sudo cp "$SYS/fennec-mirage.service" /etc/systemd/system/fennec-mirage.service' in installer


def test_cracking_page_shows_sly_verdict(monkeypatch):
    # Sly's stored outcome must surface on the cracking list so a tested capture
    # is not re-run blindly.
    cap = {"name": "Box", "bssid": "AA:BB:CC:DD:EE:FF", "file": "Box_aabbccddeeff.pcap"}
    monkeypatch.setattr(app, "read_handshakes", lambda: [dict(cap)])
    monkeypatch.setattr(app, "load_whitelist", lambda: [{"bssid": "AA:BB:CC:DD:EE:FF"}])
    monkeypatch.setattr(app, "load_wardrive", lambda: {})
    monkeypatch.setattr(app, "capture_has_handshake", lambda f: True)
    monkeypatch.setattr(app, "detect_monitor_iface", lambda: None)
    monkeypatch.setattr(app.raton_engine, "load_verdicts",
                        lambda: {"AA:BB:CC:DD:EE:FF": {"result": "cracked"}})
    html = app.app.test_client().get("/mode/cracking").get_data(as_text=True)
    assert "cracked" in html


def test_map_exposes_verdict_on_points(monkeypatch):
    # Echo must carry Sly's verdict to the point so the popup can label it.
    cap = {"name": "Box", "bssid": "AA:BB:CC:DD:EE:FF", "file": "Box_aabbccddeeff.pcap"}
    monkeypatch.setattr(app, "read_handshakes", lambda: [dict(cap)])
    monkeypatch.setattr(app, "load_whitelist", lambda: [])
    monkeypatch.setattr(app, "load_wardrive", lambda: {})

    def fake_gps(path, *a, **k):
        import io
        return io.StringIO('{"Latitude": 48.8, "Longitude": 2.3}')
    # Provide a .gps.json for the capture via a patched open path.
    monkeypatch.setattr(app.raton_engine, "load_verdicts",
                        lambda: {"AA:BB:CC:DD:EE:FF": {"result": "robust"}})
    real_open = open

    def open_patch(path, *a, **k):
        if str(path).endswith("Box_aabbccddeeff.gps.json"):
            import io
            return io.StringIO('{"Latitude": 48.8, "Longitude": 2.3}')
        return real_open(path, *a, **k)
    monkeypatch.setattr("builtins.open", open_patch)
    html = app.app.test_client().get("/map").get_data(as_text=True)
    assert "robust" in html

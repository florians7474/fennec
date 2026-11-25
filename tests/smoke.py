#!/usr/bin/env python3
"""Smoke tests for the Fennec launcher.

Imports the app and exercises the main read-only routes with Flask's test
client, plus a few pure helper functions. No hardware, nmcli, or handshake
files are required: the app degrades gracefully when they are absent, so this
runs anywhere (including CI).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app

client = app.app.test_client()

failures = []


def check_route(path):
    try:
        r = client.get(path)
    except Exception as e:
        failures.append(f"{path} raised {e!r}")
        return
    if r.status_code >= 400:
        failures.append(f"{path} returned {r.status_code}")
    else:
        # A redirect (e.g. "/" -> Wi-Fi onboarding when offline) is a healthy
        # response for a smoke test; only 4xx/5xx are failures.
        print(f"ok   {path} -> {r.status_code}")


for path in ["/", "/map", "/connection", "/tiles/status", "/gps",
             "/mirage/portal", "/mirage/portal/preview", "/scout", "/scout/state",
             "/setup/wifi", "/setup/done"]:
    check_route(path)


def check(label, cond):
    if cond:
        print(f"ok   {label}")
    else:
        failures.append(label)


check("risk unknown", app._risk_level(None, False) == "unknown")
check("risk critical (WEP)", app._risk_level("WEP", False) == "crit")
check("risk weak (WPS)", app._risk_level("WPA2", True) == "high")
check("risk solid (WPA2)", app._risk_level("WPA2", False) == "low")

if failures:
    print("\nFAILED:")
    for f in failures:
        print(" -", f)
    sys.exit(1)

print("\nAll smoke tests passed.")

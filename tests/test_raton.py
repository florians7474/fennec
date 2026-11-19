"""Tests for the Sly cracking engine logic (no hardware, no aircrack needed)."""

import os
import sys
from itertools import islice

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import raton_engine as r
import raton_essid_gen as gen


def test_robustness_robust():
    s = r._robustness_score(None, 9)
    assert s["label"] == "Robust"
    assert s["level"] == "ok"


def test_robustness_grades():
    assert r._robustness_score(1, 9)["label"] == "Critical"
    assert r._robustness_score(3, 9)["label"] == "Very weak"
    assert r._robustness_score(5, 9)["label"] == "Weak"
    assert r._robustness_score(9, 9)["label"] == "Moderate"


def test_profile_for_essid():
    assert r.profile_for_essid("Livebox-1234")["prefix"] == "Livebox-"
    assert r.profile_for_essid("TotallyCustomName") is None
    assert r.profile_for_essid("") is None


def test_factory_keys_skips_ignored():
    # FreeWifi is flagged "ignore": the stage is skipped, no routerkeygen call.
    assert r.factory_keys("FreeWifi_abc", "00:11:22:33:44:55") == []


def test_essid_words():
    assert r.essid_words("") == []
    assert r.essid_words("Livebox-1234") == []  # known box prefix -> skip
    words = r.essid_words("MyCoolWifi")
    assert "MyCoolWifi" in words
    assert words == sorted(words)


def test_essid_gen_respects_wpa_length():
    out = list(islice(gen.generate(["home"]), 50))
    assert out, "generator should yield candidates for a real word"
    assert all(gen.MIN_LEN <= len(c) <= gen.MAX_LEN for c in out)
    assert len(out) == len(set(out))  # no duplicates

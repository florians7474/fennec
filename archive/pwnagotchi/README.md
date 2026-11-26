# Pwnagotchi (archived)

Fennec used Pwnagotchi (jayofelony fork) as its first handshake harvester. Scoutchi
now covers everything Fennec relied on it for — wide 4-way and PMKID capture, GPS
tagging of captures, and Echo wardriving — on the same bettercap engine, so
Pwnagotchi was dropped from the active install to lighten it (no second venv, no
pwngrid build, no Pwnagotchi clone).

These files are kept here for reference, not installed or run:

- `pwnagotchi.service` — the Pwnagotchi daemon unit.
- `pwngrid-peer.service`, `fennec-pwngrid` — the pwngrid mesh (peer sharing), never
  read by the Fennec UI.
- `bettercap.service`, `fennec-bettercap` — the always-on bettercap the Pwnagotchi
  daemon drove over the REST API. Scoutchi launches its own bettercap instead.
- `fennec-wardrive`, `fennec-wardrive.service` — the wardrive logger bound to the
  Pwnagotchi service. The Scoutchi poller now writes the same `wardrive.json`.
- `fennec-pwna-iface` — monitor-interface helper for the Pwnagotchi bettercap.

Scoutchi still uses the shared bettercap plumbing that lived under the Pwnagotchi
install: the caplet `system/pwnagotchi-auto.cap` (REST API credentials), the
`/etc/pwnagotchi/handshakes` directory, the GPS section of `system/config.toml`, and
`/etc/pwnagotchi/wardrive.json`. Those stay in the active install.

To restore Pwnagotchi: move these files back under `system/`, re-add the install
steps (clone + venv + pwngrid build + service enable) and the UI tile/mode in
`app.py`, referring to the git history of this change.

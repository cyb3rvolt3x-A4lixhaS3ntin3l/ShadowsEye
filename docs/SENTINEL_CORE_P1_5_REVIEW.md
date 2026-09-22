# Sentinel Core P1.5 — drop broken `nmap==1.7.0` pin (review before push)

Date: 2026-09-22

**Change:** Remove `nmap==1.7.0` from `sentinel_core/requirements.txt` (no matching distribution on PyPI). Keep `python-nmap==0.7.1` for the Python API; system `nmap` binary remains an optional OS dependency for live scans.

**Why:** Strangers cannot `pip install -r sentinel_core/requirements.txt` while that pin remains.

**Verify:** `pip install -r sentinel_core/requirements.txt` should no longer fail on `nmap==1.7.0`. Primary suite still 15/15 (smoke does not need nmap).

**No Guard SDK touch. No push until GO.**

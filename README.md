# ShadowsEye (mirror)

> **Active development for the Sentinel Suite packages lives in**
> [`sentinel-suite`](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/sentinel-suite)
> (`packages/shadowseye`, shared `sentinel_core`, `sentinel` CLI).
>
> This repository remains for historical CLI / prior releases. New suite work lands in the monorepo.
> Do not expect this README to track every suite feature.

Authorized use only. No malware / exploit PoCs. Guard SDK is a separate product (untouched).

## Quick start (suite)

```bash
git clone https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/sentinel-suite.git
cd sentinel-suite
python3 -m venv .venv && source .venv/bin/activate
pip install -U pip pytest
pip install -e packages/sentinel_core \
            -e packages/shadowseye \
            -e packages/gungnir \
            -e packages/sentinel_cli
# see suite README for `sentinel doctor` + `sentinel eye run`
```

## Legacy tree

Code in this repo is retained for now (no deletes this ship). Prefer the monorepo for new contributions.

Historical CLI install (this tree) — inventory helper for assets you own or have written permission to test:

```bash
git clone https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/ShadowsEye.git
cd ShadowsEye
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
shadowseye --help
# Prefer lab path in docs/DEMO.md before any remote host.
```

This historical tree does **not** ship exploit modules, exploit PoCs, or attack runbooks.

License: MIT (unchanged). See suite [`docs/HUMAN-QUEUE.md`](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/sentinel-suite/blob/main/docs/HUMAN-QUEUE.md) for Sprint 0 follow-ups.

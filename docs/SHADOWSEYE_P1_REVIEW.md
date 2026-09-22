# ShadowsEye P1 review — safe-by-default extras

Date: 2026-09-22 (Asia/Colombo)

Working tree: `/workspace/shadowseye-harden`. **No git push** (parent pushes).

## Goal

Make inventory **safe by default**: DNS + wordlist subdomain discovery + bounded ports only.
WHOIS / social profile / breach helpers require explicit `--extras`. Remove dummy HIBP
range HTTP egress from `password_leak_check`. Keep `--dns-only` as a documented alias.
**Guard SDK / sentinelagent-guard NEVER touched.** No X.

## Files changed / added

| Path | Change |
| --- | --- |
| `shadowseye.py` | Default `include_extras=False`; `--extras` opt-in; `--dns-only` alias; conflict → exit 2; `password_leak_check` zero egress |
| `tests/test_shadowseye.py` | Default skips extras; `--extras` calls helpers; breach never `requests.get`; flag conflict |
| `README.md` | Default + `--extras` / `--dns-only` documented |
| `docs/DEMO.md` | Note that default is already safe; `--extras` callout |
| `docs/SHADOWSEYE_P1_REVIEW.md` | **This file** |

**Not touched:** Guard SDK, `sentinelagent-guard`, X, malware/exploits, sentinel_core packaging/GUI, real HIBP brand API, rate/CIDR guards, greenfield rewrite.

## Behavior

| Invocation | Extras (WHOIS / social / breach helper) |
| --- | --- |
| `shadowseye TARGET` (default) | **Skipped** (safe path) |
| `shadowseye TARGET --dns-only` | **Skipped** (explicit alias) |
| `shadowseye TARGET --extras` | **Run** (WHOIS + social HTTP; breach prints honest skip, no network) |
| `--extras` + `--dns-only` | **Error**, exit code **2**, clear stderr message |

`password_leak_check` never calls `requests.get` (no `api.pwnedpasswords.com` probe).
It prints an honest skip: no domain-keyed brand API in this tool, zero network egress.

## Verify

```bash
cd /workspace/shadowseye-harden
source .venv/bin/activate
pip install -e ".[dev]" -q
pytest -q
shadowseye --help
```

## Residuals

1. WHOIS / social still hit third-party HTTP **when** `--extras` is set (operator choice).
2. No real domain-keyed HIBP brand monitor (by design; honest skip).
3. `sentinel_core/` still optional / out of product wheel.
4. No rate limiting / CIDR guards beyond operator discipline.
5. Threading + global `found_subdomains` unchanged.

## Success checklist

- [x] Safe by default (extras off)
- [x] `--extras` opt-in
- [x] `--dns-only` retained; conflict with `--extras` → exit 2
- [x] `password_leak_check` zero network egress
- [x] README + DEMO updated
- [x] Mocked tests for default / extras / breach / conflict
- [x] Local commit only (no push)
- [x] Guard SDK untouched

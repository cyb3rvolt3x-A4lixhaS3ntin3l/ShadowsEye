# ShadowsEye harden review (for Arisha)

Date: 2026-09-22 (Asia/Colombo)

Working tree: `/workspace/shadowseye-harden` (copied from `/workspace/audit-shadowseye`). **No git push** performed.

## Goals addressed

| # | Goal | Outcome |
| --- | --- | --- |
| 1 | Real pytest suite (mock DNS/socket/network) | `tests/test_shadowseye.py` — mocked only |
| 2 | Fix `bruteforce_subdomains` `inet_aton` bug | Uses `resolve_host()` → `socket.getaddrinfo` |
| 3 | Dual CLI cleanup | Root `shadowseye.py` = primary; `sentinel_core/` demoted/documented |
| 4 | Tone scrub | Authorized banner; no malevolent/chaos intro |
| 5 | Root `requirements.txt` + MIT `LICENSE` | Added |
| 6 | README install + lab demo; no attack runbooks | Updated + `docs/DEMO.md` |
| 7 | This review doc | `docs/HARDEN_REVIEW.md` |

## Files changed / added

- `shadowseye.py` — rewrite: import-safe `main()`, DNS fix, banner, `--dns-only`, `--quiet-banner`, default wordlist `subdomain.txt`
- `requirements.txt` — new (requests + pytest)
- `LICENSE` — MIT
- `README.md` — primary CLI path, dual-entry table, install/`--help`/pytest
- `docs/DEMO.md` — lab path + offline `--help` check
- `docs/HARDEN_REVIEW.md` — this file
- `pytest.ini`, `tests/__init__.py`, `tests/test_shadowseye.py`, `tests/fixtures/tiny_wordlist.txt`
- `.gitignore` — fixed (was fenced/broken); ignore venv/pycache/pytest
- `sentinel_core/README.md` — demotion notice prepended (tree kept intact)

**Not touched:** `sentinelagent-guard` / Guard SDK (absent from this tree; never referenced). No malware/exploit PoCs added.

## Bug fixed

Old loop:

```python
socket.inet_aton(subdomain)  # only accepts dotted-quad IPs → always fails on hostnames
```

New path: `resolve_host()` via `socket.getaddrinfo(..., AF_INET)` (equivalent intent to `gethostbyname`, IPv4-first). Unit tests assert `inet_aton` is **not** called and that resolving labels are collected.

## Dual CLI decision

- **Primary (strangers):** `python shadowseye.py …`
- **Advanced (defer):** entire `sentinel_core/` Flask UI + modules — keep, document as optional; do not delete wholesale.

## Test posture

- No live internet scans in tests.
- DNS, port connect, and CLI path mocked.
- `password_leak_check` no longer pretends HIBP range API is domain-keyed; residual honesty gap documented below.

## Residual gaps (honest)

1. **`sentinel_core/` still heavy** — many live API modules remain; demoted only in the prior harden pass.
   **P0 password/tone scrub** (see `docs/SENTINEL_CORE_P0_REVIEW.md`): no live `admin123` default;
   authorized-use notes on sentinel_core README/templates.
   **P1 bind/smoke/secrets** applied (see `docs/SENTINEL_CORE_P1_REVIEW.md`): default bind `127.0.0.1`, smoke tests, placeholders.
2. **WHOIS / social HTTP helpers** still hit third-party URLs when not using `--dns-only`; lab docs steer to `--dns-only`.
3. **Breach check** is effectively a no-op for domains (HIBP range is hash-prefix); needs a real authorized brand-monitor integration later or removal.
4. **Threading + global `found_subdomains`** retained for CLI shape; fine for lab, not ideal for library reuse.
5. **Wordlist `subdomain.txt`** is large; fixtures use a tiny list for tests/demo.
6. **No packaging** (`pyproject.toml` / console_scripts) yet — run via `python shadowseye.py`.
7. **Port scan** remains a simple connect sweep — authorized lab only; no rate limiting / CIDR guards beyond operator discipline.

## Success criteria checklist

- [x] pytest passes — **10 passed** (mocked DNS/socket/CLI; no live scans)
- [x] subdomain discovery works under mocks
- [x] README install path supports import / `CLI --help` offline-enough
- [x] No push
- [x] No Guard SDK / sentinelagent-guard contact

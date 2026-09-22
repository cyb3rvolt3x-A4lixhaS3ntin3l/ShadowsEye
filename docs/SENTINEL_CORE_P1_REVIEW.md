# Sentinel Core P1 review (for Arisha)

Date: 2026-09-22 (Asia/Colombo)

Working tree: `/workspace/shadowseye-harden` (tracks origin ShadowsEye; base `main` @ `67e186f` P0). **No git push.** Guard SDK / `sentinelagent-guard` **not touched** (absent / out of scope).

## GO — P1 only (this pass)

| # | Item | Outcome |
| --- | --- | --- |
| 1 | Bind Flask to `127.0.0.1` by default | Done — `get_bind_host()` / `get_bind_port()`; `app.run` uses them; override via `SHADOWSEYE_BIND_HOST` / `SHADOWSEYE_BIND_PORT` |
| 2 | Smoke tests (app factory/import + empty-password login) | Done — `tests/test_sentinel_core_smoke.py` (mocked DB; no live network) |
| 3 | Secrets placeholders pass | Done — `.env.example` placeholders + bind vars; `config/settings.json` + `.example` empty API keys only |
| 4 | This review doc | Done |

## Files changed / added

| Path | Change |
| --- | --- |
| `sentinel_core/app.py` | Default bind `127.0.0.1:5001`; env override; `create_app()` helper; login rejects empty/whitespace password before DB |
| `sentinel_core/.env.example` | Document bind host/port; placeholders-only banner; SMTP host → `example.com` |
| `sentinel_core/config/settings.json` | Valid placeholder JSON (empty API key strings) |
| `sentinel_core/config/settings.json.example` | Same sample for copy/docs |
| `tests/test_sentinel_core_smoke.py` | Import/`create_app`, bind defaults/override, empty + whitespace password rejection |
| `docs/SENTINEL_CORE_P1_REVIEW.md` | This file |
| `sentinel_core/INSTALL.md` | Document default localhost bind + env overrides |
| `docs/HARDEN_REVIEW.md` | Residual note: P1 bind/smoke/secrets closed |

**Not touched:** Guard SDK / `sentinelagent-guard`; primary CLI `shadowseye.py` behavior unchanged.

## Verification

- `rg "app.run\\(host='0.0.0.0'"` → no matches (default is localhost; `0.0.0.0` only mentioned in docstring as opt-in override).
- Full suite: `python -m pytest` → **15 passed** (10 primary CLI + 5 sentinel_core smoke; mocked; no live network).
- No live network in tests; User.query mocked for empty-password path.

## Residual (known, not P1)

- Dual User/`init_db` paths (`app.py` vs `models/intelligence.py` via launcher) remain; password policy already aligned in P0.
- Module-level Flask app (not a full app-factory refactor); `create_app()` is a thin wrapper for tests/WSGI.
- Live third-party API modules in `sentinel_core/` still present (demoted product path).
- Marketing “Elite” / persona flavor in AI prompts and COMPLETE deep sections may remain.
- Importing `app` still creates a `FileHandler('logs/app.log')` relative to CWD — smoke tests chdir into `sentinel_core/`.
- Empty `SECRET_KEY` env still falls back to `dev-key-change-in-production` in code (documented; operators must set real `SECRET_KEY`).

## Success criteria

- [x] Flask binds `127.0.0.1` by default (env override available)
- [x] Smoke pytest for import/factory + empty password rejection
- [x] Primary CLI tests still **10/10**; full suite **15 passed**
- [x] Config samples: placeholders only
- [x] Review doc lists files
- [x] **NO git push**

## Re-verify on this box

After `pip install -r sentinel_core/requirements.txt` (needs `bcrypt` etc.): `pytest -q` → **15 passed**.

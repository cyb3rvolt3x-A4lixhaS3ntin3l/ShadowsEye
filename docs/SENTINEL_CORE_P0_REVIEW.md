# Sentinel Core P0 review (for Arisha)

Date: 2026-09-22 (Asia/Colombo)

Working tree: `/workspace/shadowseye-harden` (tracks origin ShadowsEye; `main` at harden SHA). **No git push.** Guard SDK / `sentinelagent-guard` **not touched** (absent / out of scope).

## GO — P0 only (this pass)

| # | Item | Outcome |
| --- | --- | --- |
| 1 | Kill `admin123` seed | Done — env `SHADOWSEYE_ADMIN_PASSWORD` or one-time `secrets.token_urlsafe(16)` + console print on first boot |
| 2 | Fix `models/intelligence.py` | Done — no hardcoded password |
| 3 | Align `app.py` first-boot path | Done — same env-or-generate policy (was generate-only; now prefers env) |
| 4 | README / README_COMPLETE | Done — removed live `admin123` examples; documented env var |
| 5 | Tone / authorized-use | Done — README demotion banner + authorized-use; login + launcher notices; light “Elite/chaos” marketing soften |
| 6 | Reconcile `FINAL_SUMMARY.md` | Done — archived as historical; password claim honesty gap called out |
| 7 | This review doc | Done |

**Not done (P1 — deferred):** bind `127.0.0.1`, smoke tests, broader secrets hardening (unless trivial; none required for P0).

## Files changed / added

| Path | Change |
| --- | --- |
| `sentinel_core/models/intelligence.py` | Admin seed: `SHADOWSEYE_ADMIN_PASSWORD` or generate + print |
| `sentinel_core/app.py` | Same policy on Flask `init_db()` path |
| `sentinel_core/.env.example` | Document `SHADOWSEYE_ADMIN_PASSWORD` |
| `sentinel_core/README.md` | Credentials section; authorized-use; tone soften |
| `sentinel_core/README_COMPLETE.md` | Credentials section; authorized-use banner; tone soften |
| `sentinel_core/INSTALL.md` | Env / first-boot password; authorized-use |
| `sentinel_core/FINAL_SUMMARY.md` | Historical archive banner + honesty fix on password claim |
| `sentinel_core/templates/login.html` | Authorized-use copy (no chaos/malevolent echo found) |
| `sentinel_core/shadowseye.py` | Launcher authorized-use line |
| `docs/HARDEN_REVIEW.md` | Residual #1 updated (password/tone P0 closed) |
| `docs/SENTINEL_CORE_P0_REVIEW.md` | This file |

## Verification

- `rg admin123` after scrub: remains only as **historical / residual narrative** in `FINAL_SUMMARY.md` (archived honesty callout) and this review / harden notes — **not** as a live default in Python or as documented credentials.
- Primary CLI: `python -m pytest` → **10/10** (mocked; no live scans).
- Templates: no `chaos` / `malevolent` strings found; login copy updated for authorized use.

## Residual (known, not P0)

- `sentinel_core/app.py` still `app.run(host='0.0.0.0', port=5001, …)` — **P1** bind localhost.
- Dual User/`init_db` paths (`app.py` vs `models/intelligence.py` via launcher) remain; both now share the same password policy.
- Marketing “Elite” / persona flavor in AI prompts and some COMPLETE deep sections may remain; P0 targeted README/templates + credential honesty.
- Live third-party API modules in `sentinel_core/` still present (demoted product path; not scrubbed this pass).
- No pytest coverage for sentinel_core Flask seed itself (P1 smoke).

## Success criteria

- [x] No `admin123` left in `.py` / markdown docs as a **live default**
- [x] Review doc lists files
- [x] Primary CLI pytest still **10/10**
- [x] **NO git push**

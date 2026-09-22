# ShadowsEye P0 review — packaging

Date: 2026-09-22 (Asia/Colombo)

Working tree: `/workspace/shadowseye-harden`. **No git push** (parent pushes).

## Goal

Ship stranger-usable packaging: `pip install -e .` → `shadowseye --help`, keep `python shadowseye.py`, keep pytest green, document research + residuals. **Guard SDK / sentinelagent-guard NEVER touched.**

## Files changed / added

| Path | Change |
| --- | --- |
| `pyproject.toml` | **New** — setuptools project, `shadowseye` console_scripts, `py-modules = ["shadowseye"]`, `[dev]` pytest |
| `shadowseye.py` | Add `cli()` wrapper (`SystemExit(main())`); `__main__` calls `cli()` |
| `README.md` | Install via `pip install -e ".[dev]"` + `shadowseye --help`; dual-entry table; one-line breach honesty |
| `tests/test_packaging.py` | **New** — import + entry-point metadata (no network) |
| `docs/SHADOWSEYE_P0_RESEARCH.md` | **New** — short research note |
| `docs/SHADOWSEYE_P0_REVIEW.md` | **This file** |

**Not touched:** Guard SDK, `sentinelagent-guard`, X, malware/exploits, sentinel_core GUI, live HIBP brand monitor, CI OAuth.

## Entry command

**`shadowseye`** → `shadowseye:cli` → existing `main()`.

Compat: `python shadowseye.py` still works.

## Verify

```bash
cd /workspace/shadowseye-harden
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
shadowseye --help
python shadowseye.py --help
```

Expect: packaging tests included; full suite green; both help paths print usage (no live scans).

## Residuals

1. WHOIS / profile HTTP still fire without `--dns-only`.
2. Breach check still not a real domain-keyed brand monitor (README honesty line only).
3. `sentinel_core/` still heavy / optional — not in the product wheel.
4. Large default `subdomain.txt`; tests use tiny fixture.
5. Threading + global `found_subdomains` unchanged (CLI shape).
6. No rate limiting / CIDR guards beyond operator discipline.

## Success checklist

- [x] `pyproject.toml` + console entry `shadowseye`
- [x] `pip install -e .` stranger path documented
- [x] Historical `python shadowseye.py` retained
- [x] Packaging import/entry tests (no live network)
- [x] Existing suite stays green
- [x] Research + review docs
- [x] Local commit only (no push)
- [x] Guard SDK untouched

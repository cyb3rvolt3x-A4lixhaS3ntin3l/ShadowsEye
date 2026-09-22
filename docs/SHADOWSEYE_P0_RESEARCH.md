# ShadowsEye P0 research — packaging

Date: 2026-09-22 (Asia/Colombo)

## What ShadowsEye is

ShadowsEye is an **authorized** OSINT / recon **inventory CLI** (root `shadowseye.py`) for assets you own or have written permission to map: DNS, subdomain wordlist pass, bounded port connect sweep, optional WHOIS / profile HTTP helpers. An optional advanced Flask UI and extra modules live under `sentinel_core/` and are **not** the stranger-facing product.

It is inventory-oriented: shrink unknown surface on *scoped* hosts. It does not ship exploit modules, PoCs, or attack runbooks.

## Peers (high level)

In the same broad class as tools such as **theHarvester** and **recon-ng**: CLI (or modular) recon helpers used by defenders and scoped bounty work. No star counts or ranking claims here — the point is category, not popularity. ShadowsEye is intentionally thinner: one primary CLI plus a demoted optional UI tree, with an authorized-use banner and lab-first docs.

## Why packaging is the stranger P0

Prior harden passes fixed real defects (DNS `inet_aton` bug, tests, tone, sentinel_core password/bind/deps). The remaining stranger friction from `docs/HARDEN_REVIEW.md` was simple: **no packaging**. A new user had to remember `python shadowseye.py` and manually install from `requirements.txt`. Modern Python projects expect:

```bash
pip install -e .
shadowseye --help
```

That is a small change with outsized onboarding value. It does not expand attack surface, does not touch Guard SDK, and keeps the historical `python shadowseye.py` path working.

## What NOT to do (this stream)

| Avoid | Why |
| --- | --- |
| Big GUI / greenfield rewrite | `sentinel_core/` already exists; strangers need a CLI entry, not another UI. |
| Guard SDK / `sentinelagent-guard` | Explicitly out of tree and out of scope for harden streams. |
| Live breach / HIBP brand API without auth story | Current breach helper is a placeholder; do not fake domain-keyed HIBP. |
| Removing WHOIS wholesale / X / malware-adjacent features | Not this P0; honesty docs + `--dns-only` steer lab use. |
| Inventing a second CLI | Wire `console_scripts` to the existing `main`/`cli` — one product. |

## Packaging shape chosen

- Modern `pyproject.toml` (setuptools) with `py-modules = ["shadowseye"]` — single-file module, no forced package rename.
- Console entry: `shadowseye = shadowseye:cli` (`cli()` → `SystemExit(main())`).
- Runtime dep: `requests`; optional `[dev]` → `pytest`.
- `sentinel_core/` stays un-packaged as the product wheel (advanced/optional).

## Residual honesty (not fixed as code in this P0)

- WHOIS / social HTTP still run when not `--dns-only`.
- Breach check remains a no-op for domain-keyed brand monitoring.
- Port sweep is still operator-disciplined (authorized lab only).

See `docs/SHADOWSEYE_P0_REVIEW.md` for verify commands and file list.

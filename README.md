# ShadowsEye

Authorized reconnaissance inventory for assets you own or have written permission to test.

ShadowsEye helps defenders and bug bounty hunters map **DNS**, **subdomains**, **open ports**, and **registration metadata** so they can shrink unknown attack surface — not so they can hit random internet hosts.

> **Authorized use only.** Point this tool only at targets in your written scope (your lab, your org, or a program that explicitly allows recon). Unauthorized scanning is out of scope for this project.

Related platform: [gungnir](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/gungnir) (parallel authorized assessment). MCP runtime gate demo: [mcp-grade-neq-gate](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/mcp-grade-neq-gate).

## What it does

| Capability | Purpose (defensive) |
| --- | --- |
| DNS lookup | Resolve hosts you already own or are scoped to inventory |
| Subdomain wordlist pass | Find forgotten names in *your* DNS tree |
| Port sweep (bounded range) | See which services are exposed on scoped hosts |
| WHOIS lookup | Registration metadata for scoped domains |
| Optional profile / breach checks | Situational awareness for *your* brand names — not credential abuse |

This repo is an inventory helper. It does **not** ship exploit modules, exploit PoCs, or attack runbooks.

## Install (product CLI)

The stranger-facing product is the **root** `shadowseye.py`. Tests and `--help` work offline after install.

```bash
git clone https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/ShadowsEye.git
cd ShadowsEye
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python shadowseye.py --help
python -m pytest
```

`pip install -r requirements.txt` plus `python shadowseye.py --help` does not need live internet scans (requests is imported lazily for optional HTTP extras).

## Lab demo path

Prefer the lab path in [`docs/DEMO.md`](docs/DEMO.md) before any remote host.

```bash
python shadowseye.py lab.shadowseye.local --wordlist tests/fixtures/tiny_wordlist.txt --ports 80-80 --dns-only
```

Replace the hostname with a host you control (local lab DNS / `/etc/hosts`, or a domain in a signed scope brief). Use `--dns-only` for a quiet lab run that skips WHOIS / profile HTTP extras.

## Authorized-use banner

By running ShadowsEye you confirm:

1. You have permission to inventory the named target.
2. You will not use output to attack systems outside that permission.
3. You accept that noisy scans can trigger alerts — coordinate with the asset owner.

## Layout

```
shadowseye.py              # PRIMARY CLI (product entry for strangers)
requirements.txt           # product CLI + pytest
LICENSE                    # MIT
subdomain.txt              # sample wordlist (lab-sized)
tests/                     # mocked DNS/socket tests (no live scans)
docs/DEMO.md               # lab-only walkthrough
docs/HARDEN_REVIEW.md      # harden notes for maintainers
sentinel_core/             # ADVANCED / optional UI + extra modules — not the product CLI
```

### Dual entry note

| Path | Status |
| --- | --- |
| `python shadowseye.py` | **Use this.** Product CLI. |
| `sentinel_core/` | Optional advanced platform / glass UI. Deferred for strangers. See [`sentinel_core/README.md`](sentinel_core/README.md). Do not start here. |

## What this is not

- Not a pentest exploit framework.
- Not permission to scan the public internet.
- Not affiliated with camera-grab, browser-exploit, or “ransomware remover” toys — those are out of this project’s narrative.

## License

MIT — see [LICENSE](LICENSE).

## Maintainer

Public surface under [`cyb3rvolt3x-A4lixhaS3ntin3l`](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l).

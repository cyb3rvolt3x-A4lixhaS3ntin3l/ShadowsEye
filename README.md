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

## Quick start (lab)

Prefer the lab path in [`docs/DEMO.md`](docs/DEMO.md) before any remote host.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # if present under sentinel_core/
python shadowseye.py example.lab --wordlist subdomain.txt --ports 1-1024
```

Replace `example.lab` with a host you control (local lab DNS or a domain in a signed scope brief).

## Authorized-use banner

By running ShadowsEye you confirm:

1. You have permission to inventory the named target.
2. You will not use output to attack systems outside that permission.
3. You accept that noisy scans can trigger alerts — coordinate with the asset owner.

## Layout

```
shadowseye.py          # CLI entry
subdomain.txt          # sample wordlist (lab-sized)
sentinel_core/         # extended modules / UI (see that tree’s docs)
docs/DEMO.md           # lab-only walkthrough
```

## What this is not

- Not a pentest exploit framework.
- Not permission to scan the public internet.
- Not affiliated with camera-grab, browser-exploit, or “ransomware remover” toys — those are out of this project’s narrative.

## License

MIT (see repository license file if present; otherwise treat contributions as MIT-intended until LICENSE is confirmed on push).

## Maintainer

Public surface under [`cyb3rvolt3x-A4lixhaS3ntin3l`](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l).

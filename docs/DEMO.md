# ShadowsEye — lab-only demo

## Goal

Show an authorized recon inventory against a **host you control**, then stop. No internet drive-by targets. This is a workflow demo, not an attack runbook.

## Lab options (pick one)

1. **Local hostname** — add `lab.shadowseye.local` to `/etc/hosts` pointing at `127.0.0.1` and run a tiny local listener (e.g. `python3 -m http.server 8080`).
2. **Docker lab** — run any single-host training container you already use on a private compose network; use its service DNS name only.
3. **Owned domain** — a domain in a written bug-bounty or internal ASM scope.

## Install check (offline-enough)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python shadowseye.py --help
```

`--help` must print usage without contacting the network.

## Inventory against a lab host

```bash
python shadowseye.py lab.shadowseye.local \
  --wordlist tests/fixtures/tiny_wordlist.txt \
  --ports 80-80 \
  --dns-only
# (default is already safe; --dns-only is an explicit alias.
# Use --extras only when you intentionally want WHOIS/profile helpers.)
```

Expected: DNS/port lines for the lab host; empty or sparse subdomain hits on a single-label lab name (that is fine — the demo is the authorized workflow, not a vanity subdomain count).

Unit tests cover the subdomain-discovery bugfix with mocked DNS (`python -m pytest`). Do not use pytest as a live scanner.

## Stop conditions

- Do not paste real production customer domains into public screenshots.
- Do not publish raw WHOIS/PII dumps from third parties.
- Escalate real findings through your program’s disclosure channel — not as exploit writeups in this repo.

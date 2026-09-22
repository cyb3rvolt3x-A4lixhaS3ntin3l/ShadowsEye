# ShadowsEye — lab-only demo

## Goal

Show an authorized recon inventory against a **host you control**, then stop. No internet drive-by targets.

## Lab options (pick one)

1. **Local hostname** — add `lab.shadowseye.local` to `/etc/hosts` pointing at `127.0.0.1` and run a tiny local listener (e.g. `python3 -m http.server 8080`).
2. **Docker lab** — run any single-host training container you already use on a private compose network; use its service DNS name only.
3. **Owned domain** — a domain in a written bug-bounty or internal ASM scope.

## Steps

```bash
cd ShadowsEye
python3 shadowseye.py lab.shadowseye.local --wordlist subdomain.txt --ports 80-90
```

Expected: DNS/port lines for the lab host; empty or sparse subdomain hits on a single-label lab name (that is fine — the demo is the authorized workflow, not a vanity subdomain count).

## Stop conditions

- Do not paste real production customer domains into public screenshots.
- Do not publish raw WHOIS/PII dumps from third parties.
- Escalate real findings through your program’s disclosure channel — not as exploit writeups in this repo.

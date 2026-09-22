#!/usr/bin/env python3
"""
ShadowsEye — authorized reconnaissance inventory CLI.

Primary product entry for strangers. Point only at assets you own or have
written permission to inventory. Does not ship exploit modules or PoCs.

Advanced UI / multi-module platform lives under sentinel_core/ (optional).
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
from typing import Iterable, List, Optional, Sequence, Tuple

try:
    import requests
except ImportError:  # pragma: no cover - exercised when deps missing
    requests = None  # type: ignore

BANNER = """
  _________.__                .___                  ___________
 /   _____/|  |__ _____     __| _/______  _  _______\\_   _____/__.__. ____
 \\_____  \\ |  |  \\\\__  \\   / __ |/  _ \\ \\/ \\/ /  ___/|    __)<   |  |/ __ \\
 /        \\|   Y  \\/ __ \\_/ /_/ (  <_> )     /\\___ \\ |        \\___  \\  ___/
/_______  /|___|  (____  /\\____ |\\____/ \\/\\_/ /____  >_______  / ____|\\___  >
        \\/      \\/     \\/      \\/                 \\/        \\/\\/         \\/

  ShadowsEye — authorized reconnaissance inventory
  Use only on targets in your written scope (lab, org, or program).
  Unauthorized scanning is out of scope for this project.
"""

found_subdomains: List[str] = []
_found_lock = threading.Lock()


def authorized_banner(stream=None) -> None:
    """Print the authorized-use banner (no sensational / attack framing)."""
    out = stream if stream is not None else sys.stdout
    print(BANNER, file=out)


def resolve_host(hostname: str) -> Optional[str]:
    """
    Resolve a hostname to an IPv4 address via DNS (getaddrinfo).

    Returns the first IPv4 address string, or None if resolution fails.
    Never uses socket.inet_aton on hostnames — that only validates dotted quads.
    """
    try:
        infos = socket.getaddrinfo(
            hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
    except (socket.gaierror, OSError):
        return None
    if not infos:
        return None
    # getaddrinfo result: (family, type, proto, canonname, sockaddr)
    sockaddr = infos[0][4]
    return sockaddr[0]


def dns_lookup(target: str, stream=None) -> Optional[str]:
    """Resolve and print DNS result for a scoped target. Returns IP or None."""
    out = stream if stream is not None else sys.stdout
    ip_address = resolve_host(target)
    if ip_address:
        print(f"[+] DNS Lookup: {target} resolves to {ip_address}", file=out)
        return ip_address
    print(f"[-] DNS Lookup failed for {target}", file=out)
    return None


def bruteforce_subdomains(
    target: str,
    wordlist: str,
    *,
    collect: Optional[List[str]] = None,
    stream=None,
) -> List[str]:
    """
    Wordlist subdomain discovery using proper DNS resolution.

    Only appends names that resolve. Safe for unit tests with mocked resolve_host.
    """
    out = stream if stream is not None else sys.stdout
    discovered: List[str] = collect if collect is not None else []
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as wordlist_file:
        for word in wordlist_file:
            label = word.strip()
            if not label or label.startswith("#"):
                continue
            subdomain = f"{label}.{target}"
            ip = resolve_host(subdomain)
            if ip is None:
                continue
            print(
                f"[+] DNS Lookup: {subdomain} resolves to {ip}",
                file=out,
            )
            with _found_lock:
                if subdomain not in discovered:
                    discovered.append(subdomain)
    return discovered


def parse_port_range(spec: str) -> Tuple[int, int]:
    """Parse 'start-end' into inclusive integers. Raises ValueError on bad input."""
    parts = spec.split("-")
    if len(parts) != 2:
        raise ValueError(f"port range must be start-end, got {spec!r}")
    start, end = int(parts[0]), int(parts[1])
    if start < 0 or end < 0 or start > end:
        raise ValueError(f"invalid port range: {spec!r}")
    return start, end


def port_scan(target: str, port_range: Sequence[int], stream=None) -> List[int]:
    """Bounded TCP connect sweep against a scoped host. Returns open ports."""
    out = stream if stream is not None else sys.stdout
    start, end = port_range[0], port_range[1]
    open_ports: List[int] = []
    for port in range(start, end + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[+] Open port: {target}:{port}", file=out)
                open_ports.append(port)
        finally:
            sock.close()
    return open_ports


def whois_lookup(target: str, stream=None) -> None:
    """WHOIS via public HTTP API (requires network + requests)."""
    out = stream if stream is not None else sys.stdout
    if requests is None:
        print("[-] WHOIS Lookup skipped (requests not installed)", file=out)
        return
    whois_url = "https://api.whois.com/whois/" + target
    try:
        response = requests.get(whois_url, timeout=15)
    except requests.RequestException as exc:
        print(f"[-] WHOIS Lookup failed for {target}: {exc}", file=out)
        return
    if response.status_code == 200:
        try:
            whois_data = response.json()
            print(
                f"[+] WHOIS Lookup for {target}:\n{json.dumps(whois_data, indent=2)}",
                file=out,
            )
        except ValueError:
            print(f"[+] WHOIS Lookup for {target}:\n{response.text[:2000]}", file=out)
    else:
        print(f"[-] WHOIS Lookup failed for {target}", file=out)


def social_media_scan(target: str, stream=None) -> None:
    """Optional brand-name presence check (authorized situational awareness)."""
    out = stream if stream is not None else sys.stdout
    if requests is None:
        print("[-] Social media scan skipped (requests not installed)", file=out)
        return
    social_media_urls = {
        "facebook": "https://www.facebook.com/" + target,
        "twitter": "https://twitter.com/" + target,
        "instagram": "https://www.instagram.com/" + target,
        "linkedin": "https://www.linkedin.com/company/" + target,
    }
    for platform, url in social_media_urls.items():
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
        except requests.RequestException:
            print(f"[-] {platform} check failed (network error)", file=out)
            continue
        if response.status_code == 200:
            print(f"[+] {platform} profile found: {url}", file=out)
        else:
            print(f"[-] {platform} profile not found", file=out)


def password_leak_check(target: str, stream=None) -> None:
    """
    Placeholder situational check. HIBP range API is hash-prefix based, not domain;
    this path is kept for CLI compatibility and reports skip/fail cleanly.
    """
    out = stream if stream is not None else sys.stdout
    if requests is None:
        print("[-] Breach check skipped (requests not installed)", file=out)
        return
    try:
        response = requests.get(
            "https://api.pwnedpasswords.com/range/00000",
            timeout=10,
            headers={"User-Agent": "ShadowsEye-authorized-lab"},
        )
    except requests.RequestException as exc:
        print(f"[!] Failed to reach breach API: {exc}", file=out)
        return
    if response.status_code == 200:
        # Domain-keyed leak enumeration is not supported by this endpoint.
        print(
            f"[-] No domain-keyed breach enumeration available for {target} "
            "(API is hash-prefix only; use an authorized org process for brand monitoring)",
            file=out,
        )
    else:
        print("[!] Failed to retrieve password leak data", file=out)


def run_information_gathering(
    target: str,
    wordlist: str,
    port_range: Sequence[int],
    *,
    skip_network_extras: bool = False,
    stream=None,
) -> List[str]:
    """Run inventory modules against a scoped target. Returns discovered subdomains."""
    global found_subdomains
    out = stream if stream is not None else sys.stdout
    found_subdomains = []

    print(f"\n[+] Initiating information gathering for {target}", file=out)

    t1 = threading.Thread(
        target=bruteforce_subdomains,
        args=(target, wordlist),
        kwargs={"collect": found_subdomains, "stream": out},
    )
    t1.start()

    dns_lookup(target, stream=out)
    port_scan(target, port_range, stream=out)

    if not skip_network_extras:
        whois_lookup(target, stream=out)
        social_media_scan(target, stream=out)
        password_leak_check(target, stream=out)

    t1.join()

    if found_subdomains:
        print(f"[+] Discovered subdomains for {target}:", file=out)
        for subdomain in found_subdomains:
            print(f"  - {subdomain}", file=out)
    else:
        print(f"[-] No subdomains discovered for {target}", file=out)

    print("\n[+] Information gathering completed", file=out)
    return list(found_subdomains)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shadowseye",
        description=(
            "ShadowsEye — authorized reconnaissance inventory. "
            "Use only on targets in written scope."
        ),
    )
    parser.add_argument("target", help="Target domain or IP (scoped / lab only)")
    parser.add_argument(
        "--wordlist",
        default="subdomain.txt",
        help="Wordlist for subdomain discovery (default: subdomain.txt)",
    )
    parser.add_argument(
        "--ports",
        default="1-1000",
        help="Port range for scanning (format: start-end)",
    )
    parser.add_argument(
        "--dns-only",
        action="store_true",
        help="Skip WHOIS / profile / breach HTTP extras (DNS + ports + wordlist only)",
    )
    parser.add_argument(
        "--quiet-banner",
        action="store_true",
        help="Suppress the startup banner",
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not args.quiet_banner:
        authorized_banner()

    try:
        port_range = parse_port_range(args.ports)
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    run_information_gathering(
        args.target,
        args.wordlist,
        port_range,
        skip_network_extras=args.dns_only,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

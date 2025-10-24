#!/usr/bin/env python3
"""
subenum.py - Simple multithreaded subdomain enumerator

Features:
- Reads candidate subdomains from a wordlist file (one per line).
- Tests each candidate by resolving and making an HTTP(S) request.
- Uses a ThreadPoolExecutor to run checks concurrently.
- Thread-safe collection of discovered subdomains and saving to output file.
- Command-line options for domain, wordlist, workers, timeout, scheme, and output.

Requirements:
- Python 3.7+
- requests (install via: pip install requests)
"""

import argparse
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import sys

# Thread-safe results container
results_lock = threading.Lock()
discovered = []

def parse_args():
    p = argparse.ArgumentParser(description="Multithreaded Subdomain Enumerator")
    p.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    p.add_argument("-w", "--wordlist", default="subdomains.txt", help="Wordlist file (one subdomain per line). Default: subdomains.txt")
    p.add_argument("-o", "--output", default="discovered_subdomains.txt", help="Output file for discovered subdomains")
    p.add_argument("-t", "--timeout", type=float, default=5.0, help="Request timeout in seconds (default: 5)")
    p.add_argument("-c", "--workers", type=int, default=40, help="Number of concurrent workers (default: 40)")
    p.add_argument("-s", "--scheme", choices=["http", "https", "both"], default="http", help="Scheme to try: http, https, or both (default: http)")
    p.add_argument("--no-resolve", action="store_true", help="Skip DNS pre-resolve and rely only on HTTP requests")
    return p.parse_args()

def load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            # Filter out empty lines and comments
            items = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            return items
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {path}", file=sys.stderr)
        sys.exit(1)

def safe_resolve(host):
    """Resolve hostname to IP. Return True if resolves, False otherwise."""
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False

def try_request(url, timeout):
    """Make a GET request and return (ok: bool, status: int or None, reason: str)."""
    try:
        # Using a new session per call is fine for simplicity; for heavier loads, consider session pooling.
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        return True, resp.status_code, resp.reason
    except requests.RequestException as e:
        # Could be ConnectionError, Timeout, SSLError, etc.
        return False, None, str(e)

def check_subdomain(sub, domain, scheme, timeout, no_resolve):
    host = f"{sub}.{domain}"
    schemes_to_try = [scheme] if scheme in ("http", "https") else ["http", "https"]

    if not no_resolve:
        if not safe_resolve(host):
            # DNS does not resolve; treat as not found
            return None

    for s in schemes_to_try:
        url = f"{s}://{host}"
        ok, status, reason = try_request(url, timeout)
        if ok:
            return (host, s, status, reason)
    return None

def save_results(path, results):
    try:
        with open(path, "w", encoding="utf-8") as f:
            for item in results:
                # item is tuple: (host, scheme, status, reason)
                host, scheme, status, reason = item
                f.write(f"{scheme}://{host}  {status}  {reason}\n")
        print(f"[+] Saved {len(results)} discovered subdomain(s) to {path}")
    except Exception as e:
        print(f"[!] Failed to write results: {e}", file=sys.stderr)

def main():
    args = parse_args()
    domain = args.domain.strip()
    wordlist = load_wordlist(args.wordlist)
    total = len(wordlist)
    if total == 0:
        print("[!] Wordlist is empty.", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Target domain: {domain}")
    print(f"[+] Candidates loaded: {total}")
    print(f"[+] Workers: {args.workers}, Timeout: {args.timeout}s, Scheme: {args.scheme}")
    if args.no_resolve:
        print("[!] DNS pre-resolve disabled (using HTTP checks only)")

    # Use ThreadPoolExecutor for concurrency
    futures = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for sub in wordlist:
            # Submit the task
            futures.append(ex.submit(check_subdomain, sub, domain, args.scheme, args.timeout, args.no_resolve))

        checked = 0
        for future in as_completed(futures):
            checked += 1
            try:
                result = future.result()
            except Exception as exc:
                # Unexpected exception from check_subdomain
                print(f"[!] Worker raised an exception: {exc}", file=sys.stderr)
                continue

            if result:
                # thread-safe append
                with results_lock:
                    discovered.append(result)
                    host, scheme, status, reason = result
                    print(f"[+] Found: {scheme}://{host}  [{status}]")

            # Optional progress print every N checks
            if checked % 50 == 0 or checked == total:
                print(f"[i] Progress: {checked}/{total} checked")

    # Save results
    if discovered:
        save_results(args.output, discovered)
    else:
        print("[i] No subdomains discovered.")

if __name__ == "__main__":
    main()

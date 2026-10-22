#!/usr/bin/env python3
"""Usage: report.py [events.jsonl] [--ip 1.2.3.4] [--since 2026-10-22]

Author: Markus Fritz (wirehack7)
"""

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field


@dataclass
class Collected:
    """Events from the log, grouped by action."""

    reqs: list = field(default_factory=list)
    cmds: Counter = field(default_factory=Counter)
    urls: Counter = field(default_factory=Counter)
    shells: list = field(default_factory=list)
    samples: list = field(default_factory=list)
    logins: Counter = field(default_factory=Counter)

    def add(self, e: dict) -> None:
        """Record one event according to its action."""
        act = e["event"]["action"]
        if act == "http_request":
            self.reqs.append(e)
        elif act == "command_emulated":
            self.cmds[e["process"]["command_line"]] += 1
        elif act == "download_url_seen":
            self.urls[e["url"]["original"]] += 1
        elif act == "webshell_registered":
            self.shells.append(e)
        elif act == "sample_fetched":
            self.samples.append(e)
        elif act == "login_attempt":
            self.logins[f'{e["user"]["name"]} / {e.get("password", "")}'] += 1


def _as_name(e: dict) -> str:
    """Return "AS<number> <organization>" for an event's source."""
    a = e["source"]["as"]
    return f'AS{a["number"]} {(a.get("organization") or {}).get("name", "")}'


def is_attempt(e: dict) -> bool:
    """Return whether a request event is a PHP2Shell attempt."""
    p = e.get("php2shell") or {}
    if "attempt" in p:
        return p["attempt"]
    return any(
        t.startswith("php2shell.") for t in e.get("tags", [])
    )  # old events


def parse_args() -> argparse.Namespace:
    """Parse the command line."""
    ap = argparse.ArgumentParser()
    ap.add_argument("events", nargs="?", default="data/events.jsonl")
    ap.add_argument("--ip", help="timeline for this source IP only")
    ap.add_argument("--since", help="ISO timestamp prefix, e.g. 2026-10-22")
    ap.add_argument("--top", type=int, default=20)
    return ap.parse_args()


def load(path: str, since: str | None, ip: str | None) -> Collected:
    """Read the JSONL log, applying the --since and --ip filters."""
    out = Collected()
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if since and e["@timestamp"] < since:
                continue
            if ip and (e.get("source") or {}).get("ip") != ip:
                continue
            out.add(e)
    return out


def print_timeline(ip: str, reqs: list) -> None:
    """Print one line per request (plus its commands) for one IP."""
    print(f"== Timeline {ip}")
    for e in reqs:
        h = e["http"]
        p2s = "P2S" if is_attempt(e) else "   "
        print(
            f'{e["@timestamp"]}  {h["request"]["method"]:6} '
            f'{e["url"]["path"][:60]:60} '
            f'{h["response"]["status_code"]}  '
            f'{h["request"]["body"]["bytes"]:>10}B  '
            f'{p2s} {e["php2shell"]["stage"]:18} {",".join(e["tags"])}'
        )
        for c in (e.get("attacker") or {}).get("commands", []):
            print(f"      $ {c[:200]}")


def print_top(title: str, counter: Counter, n: int) -> None:
    """Print the n most common entries of counter under a heading."""
    print(f"\n== {title}")
    for k, count in counter.most_common(n):
        print(f"{count:6}  {str(k)[:200]}")


def attempt_tops(attempts: list) -> list:
    """Return (title, counter) pairs about PHP2Shell attempts."""
    return [
        (
            "Stages (PHP2Shell attempts)",
            Counter(e["php2shell"]["stage"] for e in attempts),
        ),
        (
            "Source IPs (PHP2Shell attempts)",
            Counter(e["source"]["ip"] for e in attempts),
        ),
        (
            "User agents (PHP2Shell attempts)",
            Counter(e["user_agent"]["original"] for e in attempts),
        ),
        (
            "AS (PHP2Shell attempts)",
            Counter(
                _as_name(e)
                for e in attempts
                if (e["source"].get("as") or {}).get("number")
            ),
        ),
        (
            "Countries (PHP2Shell attempts)",
            Counter(
                (e["source"].get("geo") or {}).get("country_name")
                for e in attempts
                if e["source"].get("geo")
            ),
        ),
    ]


def request_tops(reqs: list, others: list) -> list:
    """Return (title, counter) pairs about other exploits and requests."""
    return [
        (
            "Other exploits: paths (no PHP2Shell indicator)",
            Counter(e["url"]["path"] for e in others),
        ),
        (
            "Other exploits: user agents",
            Counter(e["user_agent"]["original"] for e in others),
        ),
        (
            "Multipart boundaries",
            Counter(
                (e.get("multipart") or {}).get("boundary", "")[:80]
                for e in reqs
                if e.get("multipart")
            ),
        ),
        (
            "Paths (POST)",
            Counter(
                e["url"]["path"]
                for e in reqs
                if e["http"]["request"]["method"] == "POST"
            ),
        ),
        (
            "Body hashes (same template)",
            Counter(
                e["http"]["request"]["body"]["stored"]["sha256"][:16]
                for e in reqs
                if e["http"]["request"]["body"].get("stored")
            ),
        ),
        (
            "Upload progress values",
            Counter(
                v[:120]
                for e in reqs
                for v in e["php2shell"]["upload_progress_values"]
            ),
        ),
    ]


def print_webshells(shells: list) -> None:
    """Print the registered webshells."""
    print("\n== Webshells")
    for s in shells:
        f = s.get("file", {})
        print(
            f'{s["@timestamp"]}  {s["source"]["ip"]:15}  {f.get("name")}  '
            f'{f.get("sha256", "")[:16]}  via={s.get("via")}'
        )


def print_samples(samples: list) -> None:
    """Print the downloaded malware samples."""
    print("\n== Downloaded samples")
    for s in samples:
        f = s["file"]
        print(
            f'{f["sha256"]}  {f["type"]:6} {f["size"]:>9}B  '
            f'{s["url"]["original"]}'
        )


def print_full_chains(stage_by_ip: dict) -> None:
    """Print IPs that went from arm/probe to exploitation."""
    print(
        "\n== IPs with full chain (arm/probe -> exploit -> post_exploitation)"
    )
    for ip, st in stage_by_ip.items():
        if {"exploit", "post_exploitation"} & st and st & {"arm", "probe"}:
            print(f"{ip:15}  {sorted(st)}")


def print_summary(data: Collected, n: int) -> None:
    """Print the aggregate report over all collected events."""
    reqs = data.reqs
    stage_by_ip = defaultdict(set)
    for e in reqs:
        if is_attempt(e):
            stage_by_ip[e["source"]["ip"]].add(e["php2shell"]["stage"])
    attempts = [e for e in reqs if is_attempt(e)]
    others = [
        e
        for e in reqs
        if not is_attempt(e) and e["php2shell"]["stage"] != "none"
    ]
    print(
        f"Requests: {len(reqs)}  PHP2Shell attempts: {len(attempts)}  "
        f"Other exploits: {len(others)}  Source IPs: {len(stage_by_ip)}"
    )
    tops = attempt_tops(attempts)
    tops.insert(1, ("Tags", Counter(t for e in reqs for t in e["tags"])))
    tops += request_tops(reqs, others)
    tops += [
        ("Emulated commands (post-exploitation)", data.cmds),
        ("Download URLs", data.urls),
        ("login attempts (user / password)", data.logins),
    ]
    for title, counter in tops:
        print_top(title, counter, n)
    print_webshells(data.shells)
    print_samples(data.samples)
    print_full_chains(stage_by_ip)


def main() -> None:
    """Print a timeline for --ip, otherwise the aggregate report."""
    args = parse_args()
    data = load(args.events, args.since, args.ip)
    if args.ip:
        print_timeline(args.ip, data.reqs)
    else:
        print_summary(data, args.top)


if __name__ == "__main__":
    main()

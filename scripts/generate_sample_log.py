#!/usr/bin/env python3
"""Generate a synthetic SSH auth.log for testing the Auth Log Analyzer.

All data is fake: users and IPs come from reserved documentation ranges
(RFC 5737), and the output is reproducible through --seed.
"""
import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "web01"
VALID_USERS = {"root", "kenvin", "deploy"}
LEGIT_IPS = {"kenvin": "198.51.100.7", "deploy": "198.51.100.22"}
COMMON_USERNAMES = [
    "root", "admin", "test", "ubuntu", "oracle",
    "postgres", "user", "guest", "pi", "git", "deploy",
]


def failed_messages(rng, ip, user):
    """One failed attempt. Unknown users produce two log lines, like real sshd."""
    port = rng.randint(30000, 65000)
    if user in VALID_USERS:
        return [f"Failed password for {user} from {ip} port {port} ssh2"]
    return [
        f"Invalid user {user} from {ip} port {port}",
        f"Failed password for invalid user {user} from {ip} port {port} ssh2",
    ]


def attack(events, rng, ip, start, attempts, gap, users):
    """Add failed logins from one IP. Returns the time of the last attempt."""
    when = start
    for _ in range(attempts):
        user = rng.choice(users)
        for message in failed_messages(rng, ip, user):
            events.append((when, message))
        when += timedelta(seconds=rng.randint(*gap))
    return when


def background(events, rng, start, hours):
    """Legitimate traffic: key logins and the occasional mistyped password."""
    span = hours * 3600
    for _ in range(rng.randint(8, 14)):
        user = rng.choice(list(LEGIT_IPS))
        when = start + timedelta(seconds=rng.randint(0, span))
        port = rng.randint(30000, 65000)
        events.append(
            (when, f"Accepted publickey for {user} from {LEGIT_IPS[user]} port {port} ssh2")
        )
    for _ in range(rng.randint(3, 6)):
        user = rng.choice(list(LEGIT_IPS))
        when = start + timedelta(seconds=rng.randint(0, span))
        events.extend((when, m) for m in failed_messages(rng, LEGIT_IPS[user], user))


def format_line(when, pid, message):
    # Syslog pads the day with a space ("Nov  4"), not a zero.
    return f"{when:%b} {when.day:>2} {when:%H:%M:%S} {HOST} sshd[{pid}]: {message}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--out", default="samples/auth.log")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    start = datetime(2026, 11, 23)
    events = []

    background(events, rng, start, args.hours)

    # 1. Classic brute force, followed by a successful login from the same IP
    burst_start = start + timedelta(hours=3, minutes=12)
    burst_end = attack(events, rng, "203.0.113.45", burst_start, 180, (1, 3), COMMON_USERNAMES)
    port = rng.randint(30000, 65000)
    events.append(
        (burst_end + timedelta(seconds=5),
         f"Accepted password for deploy from 203.0.113.45 port {port} ssh2")
    )

    # 2. Slow and low: one attempt every 5-20 minutes
    attack(events, rng, "192.0.2.88", start + timedelta(hours=9), 40, (300, 1200), COMMON_USERNAMES)

    # 3. Distributed: five IPs all guessing root
    for i in range(101, 106):
        begin = start + timedelta(hours=14, minutes=rng.randint(0, 10))
        attack(events, rng, f"203.0.113.{i}", begin, 25, (20, 60), ["root"])

    events.sort(key=lambda e: e[0])  # time only, so same-second lines keep their order

    pid = 2000
    lines = []
    for when, message in events:
        pid += rng.randint(1, 5)
        lines.append(format_line(when, pid, message))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" stops Windows from writing CRLF line endings
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to {out}")


if __name__ == "__main__":
    main()
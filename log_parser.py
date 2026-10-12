import re
import subprocess
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

import db

SSH_HOST = "edi@127.0.0.1"
SSH_PORT = "2222"

PATTERN = re.compile(
    r"^(?P<time>\S+) .*Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)\b"
)


@dataclass
class LogEntry:
    time: datetime
    user: str
    ip: str
    source_port: str = ""


def fetch_lines():
    result = subprocess.run(
        [
            "ssh", "-o", "BatchMode=yes", "-p", SSH_PORT, SSH_HOST,
            "grep -a 'Failed password' /var/log/auth.log",
        ],
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )

    if result.returncode == 255:
        raise SystemExit(
            "SSH connection failed. Is the VM running? "
            "Is the SSH key configured?"
        )

    return result.stdout.splitlines()


def parse_line(line):
    match = PATTERN.search(line)

    if not match:
        return None

    return LogEntry(
        time=datetime.fromisoformat(match.group("time")),
        user=match.group("user"),
        ip=match.group("ip"),
        source_port=match.group("port"),
    )


def parse_lines(lines):
    entries = []

    for line in lines:
        entry = parse_line(line)

        if entry:
            entries.append(entry)

    return entries


class Detector:
    def __init__(self, window_seconds=120, threshold=5):
        self.window_seconds = window_seconds
        self.threshold = threshold

    def find_bruteforce(self, entries):
        times_by_ip = defaultdict(list)

        for entry in entries:
            times_by_ip[entry.ip].append(entry.time)

        alerts = []

        for ip, times in times_by_ip.items():
            times.sort()
            window = deque()

            for timestamp in times:
                window.append(timestamp)

                while (
                    timestamp - window[0]
                ).total_seconds() > self.window_seconds:
                    window.popleft()

                if len(window) > self.threshold:
                    alerts.append((ip, timestamp, len(window)))
                    window.clear()

        return alerts


if __name__ == "__main__":
    fetched_entries = parse_lines(fetch_lines())
    conn = db.connect()

    try:
        new_entries = db.save_entries(conn, fetched_entries)
        rows = db.load_rows(conn)

        entries = [
            LogEntry(
                time=datetime.fromisoformat(timestamp),
                user=user,
                ip=ip,
                source_port=source_port,
            )
            for timestamp, user, ip, source_port in rows
        ]

        print(
            f"{len(fetched_entries)} entries fetched, "
            f"{new_entries} new entries saved"
        )
        print(f"{len(entries)} total entries in the database\n")

        detector = Detector(window_seconds=120, threshold=5)
        detected_alerts = detector.find_bruteforce(entries)

        new_alerts = db.save_alerts(
            conn,
            detected_alerts,
            detector.window_seconds,
            detector.threshold,
        )

        if new_alerts:
            for ip, timestamp, attempts in new_alerts:
                print(
                    f"NEW ALERT: {ip} had {attempts} failed login attempts, "
                    f"detected at {timestamp}"
                )

        elif detected_alerts:
            print(
                f"{len(detected_alerts)} previously detected alert(s); "
                "no new alerts."
            )

        else:
            print("No suspicious activity detected.")

        print("\nTop source IPs:")

        for ip, count in Counter(
            entry.ip for entry in entries
        ).most_common(5):
            print(f"  {ip}: {count}")

        print("\nTop usernames:")

        for user, count in Counter(
            entry.user for entry in entries
        ).most_common(5):
            print(f"  {user}: {count}")

    finally:
        conn.close()

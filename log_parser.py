import re
import subprocess
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

SSH_HOST = "edi@127.0.0.1"
SSH_PORT = "2222"

PATTERN = re.compile(
    r"^(?P<time>\S+) .*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port"
)


@dataclass
class LogEntry:
    time: datetime
    user: str
    ip: str


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
            "SSH-Verbindung fehlgeschlagen. Läuft die VM? Ist der SSH-Schlüssel eingerichtet?"
        )
    return result.stdout.splitlines()


def parse_line(line):
    m = PATTERN.search(line)
    if not m:
        return None
    return LogEntry(
        time=datetime.fromisoformat(m.group("time")),
        user=m.group("user"),
        ip=m.group("ip"),
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
        for e in entries:
            times_by_ip[e.ip].append(e.time)

        alerts = []
        for ip, times in times_by_ip.items():
            times.sort()
            window = deque()
            for t in times:
                window.append(t)
                while (t - window[0]).total_seconds() > self.window_seconds:
                    window.popleft()
                if len(window) > self.threshold:
                    alerts.append((ip, t, len(window)))
                    window.clear()
        return alerts


if __name__ == "__main__":
    entries = parse_lines(fetch_lines())
    print(f"{len(entries)} Fehlversuche eingelesen\n")

    detector = Detector(window_seconds=120, threshold=5)
    alerts = detector.find_bruteforce(entries)
    if alerts:
        for ip, t, n in alerts:
            print(f"ALARM: {ip} hatte {n} Fehlversuche, erkannt um {t}")
    else:
        print("Keine Auffälligkeiten.")

    print("\nTop IPs:")
    for ip, n in Counter(e.ip for e in entries).most_common(5):
        print(f"  {ip}: {n}")

    print("\nTop Usernamen:")
    for user, n in Counter(e.user for e in entries).most_common(5):
        print(f"  {user}: {n}")
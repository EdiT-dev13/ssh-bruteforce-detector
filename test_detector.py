from datetime import datetime, timedelta
from parser import Detector, LogEntry, parse_line


def make_entries(ip, offsets_seconds):
    start = datetime(2026, 10, 12, 13, 0, 0)
    return [LogEntry(time=start + timedelta(seconds=s), user="x", ip=ip) for s in offsets_seconds]


def test_alarm_bei_schnellen_versuchen():
    entries = make_entries("1.2.3.4", [0, 5, 10, 15, 20, 25])  # 6 in 25 Sekunden
    alerts = Detector(window_seconds=120, threshold=5).find_bruteforce(entries)
    assert len(alerts) == 1


def test_kein_alarm_bei_verstreuten_versuchen():
    entries = make_entries("1.2.3.4", [0, 600, 1200, 1800, 2400, 3000])  # 6 in 50 Minuten
    alerts = Detector(window_seconds=120, threshold=5).find_bruteforce(entries)
    assert alerts == []


def test_parse_line_normaler_user():
    line = "2026-10-12T13:01:22.123456+02:00 edi-VirtualBox sshd[1234]: Failed password for edi from 10.0.2.2 port 54321 ssh2"
    entry = parse_line(line)
    assert entry.user == "edi"
    assert entry.ip == "10.0.2.2"


def test_parse_line_invalid_user():
    line = "2026-10-12T13:01:30.654321+02:00 edi-VirtualBox sshd[1236]: Failed password for invalid user admin from 10.0.2.2 port 54322 ssh2"
    entry = parse_line(line)
    assert entry.user == "admin"
    assert entry.ip == "10.0.2.2"


def test_parse_line_ignoriert_fremde_zeilen():
    assert parse_line("irgendeine andere Logzeile") is None
from datetime import datetime
import sqlite3

import db
from log_parser import LogEntry


def test_duplikate_werden_ignoriert():
    conn = db.connect(":memory:")
    try:
        entries = [LogEntry(datetime(2026, 10, 12, 13, 0, 0), "x", "1.2.3.4", "12345")]
        assert db.save_entries(conn, entries) == 1
        assert db.save_entries(conn, entries) == 0
        assert len(db.load_rows(conn)) == 1
    finally:
        conn.close()


def test_anderer_quellport_ist_ein_separates_ereignis():
    conn = db.connect(":memory:")
    try:
        timestamp = datetime(2026, 10, 12, 13, 0, 0)
        entries = [
            LogEntry(timestamp, "x", "1.2.3.4", "12345"),
            LogEntry(timestamp, "x", "1.2.3.4", "12346"),
        ]
        assert db.save_entries(conn, entries) == 2
        assert len(db.load_rows(conn)) == 2
    finally:
        conn.close()


def test_alarme_werden_nur_einmal_als_neu_gemeldet():
    conn = db.connect(":memory:")
    try:
        timestamp = datetime(2026, 10, 12, 13, 0, 30)
        alerts = [("1.2.3.4", timestamp, 6)]
        assert db.save_alerts(conn, alerts, 120, 5) == alerts
        assert db.save_alerts(conn, alerts, 120, 5) == []
    finally:
        conn.close()


def test_alte_datenbank_wird_migriert_ohne_logduplikat(tmp_path):
    path = tmp_path / "legacy.db"
    old_conn = sqlite3.connect(path)
    old_conn.executescript(
        """
        CREATE TABLE failed_logins (
            id INTEGER PRIMARY KEY,
            time TEXT NOT NULL,
            user TEXT NOT NULL,
            ip TEXT NOT NULL,
            UNIQUE (time, user, ip)
        );
        INSERT INTO failed_logins (time, user, ip)
        VALUES ('2026-10-12T13:00:00', 'x', '1.2.3.4');

        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY,
            ip TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            attempts INTEGER NOT NULL,
            window_seconds INTEGER NOT NULL,
            threshold INTEGER NOT NULL,
            UNIQUE (ip, detected_at)
        );
        INSERT INTO alerts (ip, detected_at, attempts, window_seconds, threshold)
        VALUES ('1.2.3.4', '2026-10-12T13:00:30', 6, 120, 5);
        """
    )
    old_conn.commit()
    old_conn.close()

    conn = db.connect(str(path))
    try:
        old_rows = db.load_rows(conn)
        assert len(old_rows) == 1
        assert old_rows[0][3] == ""

        repeated_old_event = LogEntry(
            datetime.fromisoformat(old_rows[0][0]), "x", "1.2.3.4", "54321"
        )
        assert db.save_entries(conn, [repeated_old_event]) == 0
        rows_after_import = db.load_rows(conn)
        assert len(rows_after_import) == 1
        assert rows_after_import[0][3] == "54321"

        old_alert = ("1.2.3.4", datetime(2026, 10, 12, 13, 0, 30), 6)
        assert db.save_alerts(conn, [old_alert], 120, 5) == []
    finally:
        conn.close()

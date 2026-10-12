import sqlite3

FAILED_LOGINS_UNIQUE = ("time", "user", "ip", "source_port")
ALERTS_UNIQUE = ("ip", "detected_at", "attempts", "window_seconds", "threshold")


def _table_columns(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _unique_indexes(conn, table):
    unique_sets = set()
    for row in conn.execute(f"PRAGMA index_list({table})"):
        # PRAGMA index_list columns: seq, name, unique, origin, partial
        if row[2]:
            index_name = row[1].replace('"', '""')
            columns = tuple(
                info[2] for info in conn.execute(f'PRAGMA index_info("{index_name}")')
            )
            unique_sets.add(columns)
    return unique_sets


def _create_failed_logins(conn, table_name="failed_logins"):
    # table_name is an internal constant, never user input.
    conn.execute(
        f"""CREATE TABLE {table_name} (
            id INTEGER PRIMARY KEY,
            time TEXT NOT NULL,
            user TEXT NOT NULL,
            ip TEXT NOT NULL,
            source_port TEXT NOT NULL DEFAULT '',
            UNIQUE (time, user, ip, source_port)
        )"""
    )


def _create_alerts(conn, table_name="alerts"):
    # table_name is an internal constant, never user input.
    conn.execute(
        f"""CREATE TABLE {table_name} (
            id INTEGER PRIMARY KEY,
            ip TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            attempts INTEGER NOT NULL,
            window_seconds INTEGER NOT NULL,
            threshold INTEGER NOT NULL,
            UNIQUE (ip, detected_at, attempts, window_seconds, threshold)
        )"""
    )


def _ensure_failed_logins(conn):
    columns = _table_columns(conn, "failed_logins")
    if not columns:
        _create_failed_logins(conn)
        return

    if "id" not in columns or not {"time", "user", "ip"}.issubset(columns):
        raise RuntimeError("Unbekanntes Schema der Tabelle failed_logins; bitte Datenbank prüfen.")

    if "source_port" in columns and FAILED_LOGINS_UNIQUE in _unique_indexes(conn, "failed_logins"):
        return

    # Migrate the first version of db.py (which had no source_port column).
    source_port_expr = "source_port" if "source_port" in columns else "''"
    conn.execute("DROP TABLE IF EXISTS failed_logins_new")
    _create_failed_logins(conn, "failed_logins_new")
    conn.execute(
        f"""INSERT OR IGNORE INTO failed_logins_new (id, time, user, ip, source_port)
            SELECT id, time, user, ip, {source_port_expr} FROM failed_logins"""
    )
    conn.execute("DROP TABLE failed_logins")
    conn.execute("ALTER TABLE failed_logins_new RENAME TO failed_logins")


def _ensure_alerts(conn):
    columns = _table_columns(conn, "alerts")
    if not columns:
        _create_alerts(conn)
        return

    required = {"id", "ip", "detected_at", "attempts", "window_seconds", "threshold"}
    if not required.issubset(columns):
        raise RuntimeError("Unbekanntes Schema der Tabelle alerts; bitte Datenbank prüfen.")

    if ALERTS_UNIQUE in _unique_indexes(conn, "alerts"):
        return

    # Migrate the first version, whose uniqueness key was only (ip, detected_at).
    conn.execute("DROP TABLE IF EXISTS alerts_new")
    _create_alerts(conn, "alerts_new")
    conn.execute(
        """INSERT OR IGNORE INTO alerts_new
           (id, ip, detected_at, attempts, window_seconds, threshold)
           SELECT id, ip, detected_at, attempts, window_seconds, threshold FROM alerts"""
    )
    conn.execute("DROP TABLE alerts")
    conn.execute("ALTER TABLE alerts_new RENAME TO alerts")


def connect(path="security.db"):
    """Open the database and create or migrate its schema."""
    conn = sqlite3.connect(path)
    try:
        conn.execute("BEGIN")
        _ensure_failed_logins(conn)
        _ensure_alerts(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise
    return conn


def save_entries(conn, entries):
    """Store parsed log entries; return how many genuinely new rows were inserted.

    During migration, old rows have an empty source_port. If the same log entry
    is fetched again with a known source port, enrich that old row rather than
    inserting a second copy of the event.
    """
    inserted = 0
    for entry in entries:
        timestamp = entry.time.isoformat()

        if entry.source_port:
            migrated = conn.execute(
                """UPDATE failed_logins SET source_port = ?
                   WHERE time = ? AND user = ? AND ip = ? AND source_port = ''""",
                (entry.source_port, timestamp, entry.user, entry.ip),
            )
            if migrated.rowcount == 1:
                # Existing legacy row was enriched, not newly inserted.
                continue

        cursor = conn.execute(
            """INSERT OR IGNORE INTO failed_logins (time, user, ip, source_port)
               VALUES (?, ?, ?, ?)""",
            (timestamp, entry.user, entry.ip, entry.source_port),
        )
        if cursor.rowcount == 1:
            inserted += 1

    conn.commit()
    return inserted


def load_rows(conn):
    """Return stored rows as (time, user, ip, source_port) tuples."""
    return conn.execute(
        "SELECT time, user, ip, source_port FROM failed_logins ORDER BY time, id"
    ).fetchall()


def save_alerts(conn, alerts, window_seconds, threshold):
    """Persist alerts and return only alerts that were newly inserted."""
    new_alerts = []
    for ip, detected_at, attempts in alerts:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO alerts
               (ip, detected_at, attempts, window_seconds, threshold)
               VALUES (?, ?, ?, ?, ?)""",
            (ip, detected_at.isoformat(), attempts, window_seconds, threshold),
        )
        if cursor.rowcount == 1:
            new_alerts.append((ip, detected_at, attempts))
    conn.commit()
    return new_alerts

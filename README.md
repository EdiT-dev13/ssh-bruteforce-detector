# SSH Brute-Force Detector

A small Python tool that detects SSH brute-force attempts by analysing failed login events from a Linux server's authentication log. Built as a hands-on learning project in a local lab environment.

## How It Works

1. Fetches `Failed password` entries from `/var/log/auth.log` on a lab VM via SSH.
2. Parses each line with a regular expression into a `LogEntry` containing the timestamp, username, source IP address, and source port.
3. Groups entries by source IP and applies a **sliding-window algorithm**. An alert is raised if an IP address has more than `threshold` failed attempts within `window_seconds`.
4. Stores failed login events and detected alerts in a local SQLite database.
5. Analyses stored login history and prints alerts, the most frequent source IPs, and the most frequently attempted usernames.

The parser handles both normal failed login attempts and `invalid user` entries.

## Lab Setup

- Ubuntu Server running in VirtualBox (NAT, port forwarding from host port `2222` to guest port `22`).
- OpenSSH server enabled on the Ubuntu VM.
- Key-based SSH authentication configured for the analyzer, avoiding interactive password prompts.
- Failed login attempts generated manually to produce test data.

## Usage

Run the detector from the project directory:

```bash
python log_parser.py
```

The program reads the available SSH authentication logs, parses failed login events, stores new entries in the database, analyses the stored history, and reports detected alerts.

### Detection Settings

The default settings are:

- **Threshold:** 5 failed attempts
- **Time window:** 120 seconds

An alert is triggered when an IP address has **more than 5 failed attempts within the configured time window**. With these defaults, the sixth attempt within the window triggers an alert.

The settings can be adjusted where the `Detector` is instantiated in `log_parser.py`.

## SQLite Storage

The application uses SQLite to persist failed login events and detected alerts between program runs.

### Features

- Persistent storage of failed SSH login events.
- Persistent storage of detected brute-force alerts.
- Duplicate detection to avoid repeatedly storing the same events.
- Database migration to support the previous database schema.
- Historical analysis of stored login events.
- Automated tests for database operations and migration behaviour.

### Database

The database is stored locally in `security.db` by default. SQLite is included in Python's standard library, so no separate database server is required.

The database contains information such as IP addresses, usernames, source ports, and timestamps. These details may be sensitive and should not be published.

Database files are excluded through `.gitignore`. The local database should not be committed to the public repository.

## Example Output

The following is an illustrative example of the detector's output:

```text
24 failed attempts parsed
24 new entries saved

ALARM: 10.0.2.2 had 6 failed attempts, detected at 2026-10-12 13:00:20+02:00

Top IPs:
  10.0.2.2: 24

Top usernames:
  test: 6
  edi: 3
  admin: 3
```

The exact output depends on the available log data. When the same events are processed again, already stored entries should not be inserted a second time.

## Tests

Install `pytest` if necessary:

```bash
python -m pip install pytest
```

Run the automated test suite:

```bash
python -m pytest -v
```

The tests cover:

- Detection of repeated failed login attempts within a time window.
- Login attempts spread over time that should not trigger an alert.
- Parsing normal failed login entries.
- Parsing entries involving invalid usernames.
- Ignoring unrelated log lines.
- Database persistence and duplicate detection.
- Handling of different source ports.
- Avoiding repeated reporting of already stored alerts.
- Migration from the previous database schema.

## Ideas for Future Improvements

- Map findings to MITRE ATT&CK technique [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/).
- Detect successful logins following repeated failed attempts.
- Export reports as CSV or Markdown.
- Add command-line arguments for the detection window and threshold.
- Build a dashboard with Streamlit to visualise login activity and alerts.
- Add SQL and pandas analytics for attack trends and historical statistics.
- Generate periodic security reports with risk assessments and recommendations.
- Package the application with Docker for easier deployment.

## Limitations

This project is a learning prototype for SSH log analysis and brute-force detection. It is not a production-ready SIEM solution.

Detection accuracy depends on the available log data, the configured threshold, and the detection window. The current approach also depends on the configured SSH connection and the log format used by the Linux system.

The tool identifies suspicious patterns in failed login attempts. An alert does not, by itself, prove that a successful compromise has occurred.

## What I Learned

- Understanding SSH authentication logs and recognising brute-force patterns.
- Implementing a sliding-window algorithm using `collections.deque`.
- Parsing structured information from log lines using regular expressions.
- Configuring key-based SSH authentication and applying the principle of least privilege.
- Storing and querying persistent data with SQLite and SQL.
- Preventing duplicate records using database constraints.
- Handling database schema changes through migrations.
- Writing automated tests with `pytest`.
- Separating log processing, detection logic, database operations, and tests into different modules.
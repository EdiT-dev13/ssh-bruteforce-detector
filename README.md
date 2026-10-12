\# SSH Brute-Force Detector



A small Python tool that detects SSH brute-force attempts by analysing failed login events from a Linux server's auth log. Built as a hands-on learning project in a local lab environment.



\## How it works



1\. Fetches `Failed password` entries from `/var/log/auth.log` of a lab VM via SSH

2\. Parses each line with a regex into a `LogEntry` (timestamp, username, source IP)

3\. Groups entries by source IP and applies a \*\*sliding window\*\*: an alert is raised if an IP has more than `threshold` failed attempts within `window\_seconds`

4\. Prints alerts plus the most frequent source IPs and attempted usernames



Handles both normal failures and `invalid user` entries.



\## Lab setup



\- Ubuntu Server in VirtualBox (NAT, port forwarding host `2222` -> guest `22`)

\- OpenSSH server enabled

\- Key-based SSH login for the analyzer, no password prompt

\- Failed logins generated manually to produce test data



\## Usage



```

python log\_parser.py

```



Default settings: more than 5 failed attempts within 120 seconds trigger an alert. Adjust them where `Detector` is created in `log\_parser.py`.



\## Example output



```

24 failed attempts parsed



ALARM: 10.0.2.2 had 6 failed attempts, detected at 2026-10-12 13:00:20+02:00



Top IPs:

&#x20; 10.0.2.2: 24



Top usernames:

&#x20; test: 6

&#x20; edi: 3

&#x20; admin: 3

```



\## Tests



```

pip install pytest

python -m pytest

```



Covers alert detection, scattered attempts (no alert), and parsing of normal, `invalid user` and unrelated log lines.



\## Ideas for extension



\- Map findings to MITRE ATT\&CK T1110 (Brute Force)

\- Detect successful logins following many failures

\- Export reports as CSV/Markdown

\- Command-line arguments for window and threshold



\## What I learned



\- Structure of SSH authentication logs and how brute force looks in them

\- Sliding-window algorithm with `collections.deque`

\- Key-based SSH authentication and least privilege (log access via the `adm` group instead of root)

\- Writing unit tests with pytest


"""Syslog parser — handles auth.log lines (sshd, sudo, cron, kernel).

Recognised event types (locked Week 4):
- auth.login_failed      (sshd Failed password)
- auth.login_success     (sshd Accepted)
- auth.sudo_anomaly      (sudo: N INCORRECT password attempts)
- auth.user_login         (sshd session opened)
- system.service         (systemd messages)

Everything else → parse_failed with the original line preserved.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from app.ingestion.normalizer import NormalisedEvent, parse_failed_event

PARSER_NAME = "syslog"

# sshd Failed password for root from 203.0.113.42 port 12345 ssh2
_RE_FAILED = re.compile(
    r"Failed (?P<method>\S+) for (?P<user>\S+) from (?P<src>[\d\.]+) port \d+ ssh2"
)
# sshd Accepted publickey for manu from 10.0.0.5 port 54321 ssh2
_RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<src>[\d\.]+) port \d+"
)
# sudo: pam_unix(sudo:auth): authentication failure
_RE_SUDO_FAIL = re.compile(
    r"pam_unix\(sudo:auth\): authentication failure.*?user=(?P<user>\S+)"
)
# sshd session opened
_RE_SESSION = re.compile(r"session opened for user (?P<user>\S+)")
# systemd message
_RE_SYSTEMD = re.compile(r"^(?P<unit>[\w\-\.]+)\[(?P<pid>\d+)\]: (?P<msg>.*)")


def parse(line: str, *, host: str | None = None) -> NormalisedEvent:
    """Parse a syslog line into a NormalisedEvent."""
    observed = datetime.now(timezone.utc)

    if m := _RE_FAILED.search(line):
        return NormalisedEvent(
            observed_at=observed,
            domain="it",
            event_type="auth.login_failed",
            severity=4,  # raw signal; Triage agent will escalate on burst
            src=m["src"],
            user=m["user"],
            host=host,
            raw=line,
            parser=PARSER_NAME,
            vendor="linux",
            tags=["sshd"],
            labels={"method": m["method"]},
        )

    if m := _RE_ACCEPTED.search(line):
        return NormalisedEvent(
            observed_at=observed,
            domain="it",
            event_type="auth.login_success",
            severity=2,
            src=m["src"],
            user=m["user"],
            host=host,
            raw=line,
            parser=PARSER_NAME,
            vendor="linux",
            tags=["sshd"],
            labels={"method": m["method"]},
        )

    if m := _RE_SUDO_FAIL.search(line):
        return NormalisedEvent(
            observed_at=observed,
            domain="it",
            event_type="auth.sudo_anomaly",
            severity=5,
            user=m["user"],
            host=host,
            raw=line,
            parser=PARSER_NAME,
            vendor="linux",
            tags=["sudo"],
        )

    if m := _RE_SESSION.search(line):
        return NormalisedEvent(
            observed_at=observed,
            domain="it",
            event_type="auth.user_login",
            severity=2,
            user=m["user"],
            host=host,
            raw=line,
            parser=PARSER_NAME,
            vendor="linux",
            tags=["sshd", "session"],
        )

    if m := _RE_SYSTEMD.search(line):
        return NormalisedEvent(
            observed_at=observed,
            domain="it",
            event_type="system.service",
            severity=1,
            host=host,
            raw=line,
            parser=PARSER_NAME,
            vendor="linux",
            tags=["systemd"],
            labels={"unit": m["unit"], "pid": m["pid"]},
        )

    return parse_failed_event(line, PARSER_NAME, "no syslog pattern matched")

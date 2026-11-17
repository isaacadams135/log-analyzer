# log-analyzer

A small CLI that reads ssh/sudo auth logs and flags brute-force attacks and
logins that look like credential stuffing. I built it while studying for
Security+ because working through real auth logs by hand was slow, and I
wanted a tool that does exactly what I kept doing with grep and a
spreadsheet. It works offline, needs no special privileges, and only reads
the files you point it at.

## Features

- Parses syslog-style (`Oct 12 10:22:33 host sshd[1234]: ...`) and ISO-style
  (`2026-10-12T10:22:33 host sshd[1234]: ...`) lines; unparseable lines are
  skipped and counted
- Classifies events: failed passwords, invalid-user attempts, successful
  logins, and sudo failures
- Flags brute force: 5+ failures from the same IP inside a 10-minute sliding
  window (both configurable)
- Flags suspicious logins: a successful login from an IP that hit the failure
  threshold just before it
- Prints totals, each brute-force episode with first and last time, each
  suspicious login with the username, and the top 5 offending IPs

## Build

Requires JDK 21+.

```bash
./gradlew build
./gradlew jar
```

On Windows use `gradlew.bat`.

## Usage

```bash
java -jar build/libs/log-analyzer-1.0.0.jar samples/auth.log
java -jar build/libs/log-analyzer-1.0.0.jar -w 5 -n 3 samples/auth.log
./gradlew run --args="samples/auth.log"
```

Options: `-w <minutes>` sliding window (default 10), `-n <count>` failure
threshold (default 5), `-h/--help`. Exit codes: 0 ok, 1 file missing or
unreadable, 2 usage error.

Real output against `samples/auth.log` (38 lines of crafted auth log with an
attack, a few probes, and some normal logins):

```
files   samples\auth.log
lines   37 parsed, 1 skipped
events  15 failures, 5 invalid-user, 5 successes, 3 sudo failures, 9 other

brute force
  203.0.113.50    12 failures  2026-10-12T10:22:33 -> 2026-10-12T10:24:50

suspicious logins
  203.0.113.50    user root       2026-10-12T10:26:30

top offending ips
  ip              failures
  203.0.113.50    12
  198.51.100.7    3
```

## How it works

Each line is parsed into a timestamp, host, message, and the first sane IPv4
address found in the message. Failures are grouped per IP; a sliding window
walks each IP's failure times and merges any overlapping run of threshold-or-
more failures into one brute-force episode. A successful login is suspicious
when that same IP accumulated at least the threshold number of failures
inside the window immediately before it. No machine learning, just time
windows and counting — easy to explain and easy to tune.

## Only use it on stuff you're allowed to

Only run this on log files you are authorized to read.

## License

MIT

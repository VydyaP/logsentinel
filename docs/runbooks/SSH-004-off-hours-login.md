# SSH-004 SSH login outside business hours

**Severity:** Medium · **MITRE ATT&CK:** T1078 Valid Accounts

## What it means

A successful SSH login happened outside 07:00-21:00 IST. Often legitimate (on-call work, other time zones), so this is medium severity and needs a quick human check.

## How to verify

1. Is the user on call, travelling, or in another time zone? Check the rota/change calendar.
2. Is the source IP one this user normally uses? A new IP plus odd hours is much more suspicious.
3. Were there failed logins just before (see SSH-003)?

## How to contain

1. If the user does not recognise the login: reset credentials, kill sessions, block the IP and escalate.
2. If it was planned work: no containment needed.

## How to close

- **False positive** with a note such as "on-call, ticket CHG-123".
- If this user regularly works nights, consider an allow-list (a future rule option).

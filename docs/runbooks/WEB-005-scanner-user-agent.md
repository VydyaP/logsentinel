# WEB-005 Known attack tool user agent

**Severity:** Low · **MITRE ATT&CK:** T1595.002 Active Scanning: Vulnerability Scanning

## What it means

The User-Agent header names a known attack/scanning tool (Nikto, sqlmap, Nuclei, ...). Low severity because the header is trivial to fake and scanners are constant background noise, but it is useful context.

## How to verify

1. Look for other alerts from the same IP in the same incident. On its own this alert rarely needs work.
2. Is the IP an authorised vulnerability scanner (your own pentest or ASM vendor)? Check the change calendar.

## How to contain

1. Block or rate-limit the IP; legitimate users do not send these user agents.

## How to close

- **Resolved** together with the rest of the incident, or **False positive** for an authorised scan (note the ticket).

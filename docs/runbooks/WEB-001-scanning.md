# WEB-001 Directory / vulnerability scanning

**Severity:** Medium · **MITRE ATT&CK:** T1595.003 Active Scanning: Wordlist Scanning

## What it means

One IP received at least 25 `403`/`404` responses within 2 minutes. Scanners request thousands of guessed paths (`/.env`, `/wp-login.php`, `/backup.zip`) looking for something exposed.

## How to verify

1. Look at the requested paths: generic wordlist, or targeted at your technology?
2. **Most important:** did any scanned path return `200`? Filter the raw lines for status 200. An exposed `.env`, `.git/` or backup file is an incident.
3. Check the user agent (see WEB-005) and other alerts from the same IP (SQLi/XSS after a scan = active attack).

## How to contain

1. Rate-limit or block the IP at the WAF/load balancer.
2. Remove or protect anything that answered 200 but should not be public; rotate secrets that were in it.

## How to close

- **Resolved** when nothing sensitive was exposed and the IP is blocked or rate-limited.
- **False positive** for internal tools (link checkers, uptime monitors): add a note and consider excluding their IPs.

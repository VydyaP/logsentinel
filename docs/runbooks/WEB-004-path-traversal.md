# WEB-004 Path traversal attempt

**Severity:** High · **MITRE ATT&CK:** T1190 Exploit Public-Facing Application

## What it means

A URL tried to escape the web root (`../`, encoded `%2e%2e%2f`) or named sensitive files like `/etc/passwd`. If it worked, the attacker can read any file the web server can read.

## How to verify

1. Filter the raw lines for `200` responses. A 200 for `/etc/passwd` is a confirmed compromise.
2. Compare response sizes: a traversal that returns the normal page size usually failed.

## How to contain

1. Block the IP.
2. If any request succeeded: patch the file-serving code (normalise paths, allow-list directories), and rotate any secrets readable by the web server (config files, keys).

## How to close

- **Resolved** when no request succeeded (or the hole is fixed and secrets rotated).

# WEB-003 Cross-site scripting (XSS) attempt

**Severity:** Medium · **MITRE ATT&CK:** T1190 Exploit Public-Facing Application

## What it means

A URL contained script injection (`<script>`, `onerror=`, `javascript:`). The attacker is checking whether input is reflected into pages without escaping, which would let them run JavaScript in other users' browsers.

## How to verify

1. Request the same URL safely (e.g. curl, not a browser) and check whether the payload appears unescaped in the HTML.
2. Check other alerts from the IP: XSS probes often come with scanning and SQLi.

## How to contain

1. Block the IP; enable WAF XSS rules.
2. If reflected: fix output encoding in the page and add a Content-Security-Policy header.

## How to close

- **Resolved** when the page is confirmed to escape output (or is fixed).

# SSH-002 SSH password spraying

**Severity:** High · **MITRE ATT&CK:** T1110.003 Brute Force: Password Spraying

## What it means

One IP tried at least 8 **different** usernames within 30 minutes. Spraying tries one or two common passwords across many accounts, staying under per-account lockout limits.

## How to verify

1. List the usernames tried (alert details: `top_usernames`). Are any of them **real** accounts in your directory?
2. For every real account in that list, check for a successful login from any IP in the same period.
3. Check for the same pattern from neighbouring IPs (same /24): sprays are often distributed.

## How to contain

1. Block the IP (and the range, if several neighbours are involved).
2. Force a password reset for real accounts that were targeted and have weak or old passwords.
3. Enforce MFA; remove default/unused accounts (`test`, `guest`, `oracle`).

## How to close

- **Resolved** when the source is blocked and no targeted account logged in.
- Escalate to an incident if any targeted account had a successful login.

# SSH-001 SSH brute force

**Severity:** High · **MITRE ATT&CK:** T1110.001 Brute Force: Password Guessing

## What it means

One IP sent at least 10 failed SSH logins within 5 minutes. Automated tools try common passwords against one or a few accounts (usually `root` or `admin`).

## How to verify

1. Open the alert and read the raw lines: which accounts were tried, and over how long?
2. Filter alerts/events for the same IP: is there **any** `Accepted` line? If yes, escalate as SSH-003.
3. Check whether the targeted accounts exist and allow password login.
4. Look the IP up in threat intel (AbuseIPDB, your SIEM's reputation feed). Internet scanners are common; an internal IP is not.

## How to contain

1. Block the IP at the firewall or security group (or let fail2ban do it).
2. If the attack continues from many IPs, rate-limit SSH or restrict it to the VPN.
3. Long term: disable password authentication (`PasswordAuthentication no`) and use keys + MFA.

## How to close

- **Resolved** when the IP is blocked and no login succeeded.
- **False positive** only if the source is a known internal tool (e.g. a misconfigured backup job); fix the job.
- Add a note with what you checked and the action taken.

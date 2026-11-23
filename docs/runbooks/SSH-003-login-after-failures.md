# SSH-003 Successful SSH login after repeated failures

**Severity:** Critical · **MITRE ATT&CK:** T1078 Valid Accounts

## What it means

An IP failed at least 5 times and then logged in successfully within 30 minutes. The attacker has probably **guessed a valid password**. Treat the account as compromised until proven otherwise.

## How to verify

1. Confirm with the account owner **out of band** (phone/chat, not e-mail to that account) whether it was them.
2. Check where the IP is from and whether this user has ever logged in from it before.
3. On the host: `last -i <user>`, `who`, shell history, new files in `~/.ssh/authorized_keys`, new cron jobs, new users (`/etc/passwd`).

## How to contain

1. Disable the account or reset its password **now**; kill its sessions (`pkill -KILL -u <user>`).
2. Block the source IP.
3. If anything was changed on the host, isolate it and escalate to incident response (preserve logs first).

## How to close

- **Resolved** only after credentials are reset and the host is checked for persistence.
- **False positive** only if the owner confirms the failures were their own typos *and* the IP is theirs.
- Record who confirmed and how in the notes. This is a critical alert: SLA is 15 min to acknowledge.

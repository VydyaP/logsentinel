# Runbooks

One page per detection. Each answers: what does it mean, how do I verify it, how do I contain it, how do I close it.

| Runbook | Severity | MITRE ATT&CK |
|---|---|---|
| [SSH-001 SSH brute force](SSH-001-brute-force.md) | High | T1110.001 Brute Force: Password Guessing |
| [SSH-002 SSH password spraying](SSH-002-password-spraying.md) | High | T1110.003 Brute Force: Password Spraying |
| [SSH-003 Successful SSH login after repeated failures](SSH-003-login-after-failures.md) | Critical | T1078 Valid Accounts |
| [SSH-004 SSH login outside business hours](SSH-004-off-hours-login.md) | Medium | T1078 Valid Accounts |
| [WEB-001 Directory / vulnerability scanning](WEB-001-scanning.md) | Medium | T1595.003 Active Scanning: Wordlist Scanning |
| [WEB-002 SQL injection attempt](WEB-002-sql-injection.md) | High | T1190 Exploit Public-Facing Application |
| [WEB-003 Cross-site scripting (XSS) attempt](WEB-003-xss.md) | Medium | T1190 Exploit Public-Facing Application |
| [WEB-004 Path traversal attempt](WEB-004-path-traversal.md) | High | T1190 Exploit Public-Facing Application |
| [WEB-005 Known attack tool user agent](WEB-005-scanner-user-agent.md) | Low | T1595.002 Active Scanning: Vulnerability Scanning |
| [ANOM-001 Anomalous behaviour (Isolation Forest)](ANOM-001-anomaly.md) | Medium | none (behavioural) |

Operational runbooks:

- [ServiceNow integration](servicenow-integration.md): auth errors, rate limits, a hibernating developer instance, duplicate or missing tickets.

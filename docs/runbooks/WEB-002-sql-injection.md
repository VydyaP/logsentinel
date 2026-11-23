# WEB-002 SQL injection attempt

**Severity:** High · **MITRE ATT&CK:** T1190 Exploit Public-Facing Application

## What it means

A URL contained SQL injection syntax (`' OR 1=1`, `UNION SELECT`, `SLEEP(5)`). The attacker is testing whether input reaches the database unescaped.

## How to verify

1. Check the response codes and sizes. `500` errors suggest the payload reached the database; `200` with an unusually large response may mean data was returned.
2. Time-based payloads (`SLEEP`, `pg_sleep`): did those requests take longer? (check upstream response time if logged).
3. Identify the endpoint and parameter; ask the developers whether it uses parameterised queries.

## How to contain

1. Block the IP and enable/strengthen WAF SQL-injection rules for that endpoint.
2. If injection worked: take the endpoint offline or patch it, check the database for data access, rotate DB credentials.

## How to close

- **Resolved** when the endpoint is confirmed safe (parameterised) or patched, and the source is blocked.

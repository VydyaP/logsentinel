# Runbook: ServiceNow integration

**Component:** `logsentinel.servicenow.ServiceNowProvider` + `logsentinel sync-tickets`
**Owner:** whoever runs LogSentinel. **Design:** [README: ServiceNow integration](../../README.md#servicenow-integration)

Detection never depends on ServiceNow. If ServiceNow is down, alerts and incidents
are still stored; failed ticket creations are marked **Create failed** and the
sync job retries them. So nothing here is an emergency for detection, only for
ticket hygiene.

## First check (always)

```bash
logsentinel ticketing-check          # login + read access to the incident table
logsentinel -v sync-tickets          # one sync run with per-call logs
```

Every HTTP call logs one line, with no secrets:

```
servicenow_call provider=servicenow method=POST path=/api/now/table/incident status=201 attempt=1 duration_ms=412
```

`status=None error=ConnectTimeout` means no HTTP response at all (network, DNS, or the instance is asleep).

## Symptom → cause → fix

### `401 Unauthorized`

| Likely cause | How to verify | Fix |
|---|---|---|
| Wrong username/password in `.env` | Sign in to the instance in a private browser window with the same user. A user with *Web service access only* can't use the UI, so test it with `ticketing-check` instead. | Fix `.env`. Watch for quotes or trailing spaces. |
| **Password needs reset** ticked on the user record | User record → *Password needs reset* checkbox | Untick it. The API cannot change passwords, so it gets a 401. |
| User locked out after failed logins | User record → *Locked out* | Untick it, then fix the password. |
| User inactive | User record → *Active* | Tick *Active*. |
| Wrong instance URL | `SERVICENOW_INSTANCE_URL` must be `https://devNNNNN.service-now.com` with no path | Fix it. |

LogSentinel does **not** retry 401/403. Retrying bad credentials only gets the account locked.

### `403 Forbidden`

The user signed in but is not allowed to do this.

- Missing role: the integration user needs **`itil`** to create, update and read incidents.
  Don't fix this by adding `admin`.
- ACL or a REST API access policy restricts the incident table or the Table API
  (*System Web Services → REST API Access Policies*).
- IP address access control (*System Security → IP Address Access Control*)
  blocks the host LogSentinel runs on.

The error message includes ServiceNow's own `error.message`, which usually names the ACL.

### Instance hibernating (developer instances)

Personal Developer Instances go to sleep when nobody uses them. A sleeping
instance doesn't serve the REST API. It returns a redirect or an HTML page instead,
which LogSentinel reports as:

```
ServiceNowUnavailableError: ServiceNow answered 200 with non-JSON content ... hibernating
```

Fix: sign in at <https://developer.servicenow.com>, open *My instance* and wake it
(this takes a few minutes). If a PDI goes unused for a long time it can be
reclaimed entirely; the portal shows the current policy. After waking it, run
`logsentinel sync-tickets`: it retries any **Create failed** incidents.

### `429 Too Many Requests` / rate limits

ServiceNow can enforce REST rate-limit rules per user or role
(*System Web Services → REST → Rate Limit Rules*). LogSentinel retries 429 with
exponential backoff and jitter, and follows `Retry-After` when present (capped at 60 s).
If it still fails after `SERVICENOW_MAX_RETRIES`:

- Increase the polling interval: `sync-tickets --every 300`.
- Ask the ServiceNow admin for a rate-limit rule just for the integration user.
- Status sync already batches 50 tickets per request and pages 100 records at a time.
  If thousands of tickets are open, that's the real problem to fix.

### `5xx` / timeouts

GET and PATCH retry automatically. **POST (create) is not retried after a 500,
502, 504 or read timeout**, because ServiceNow may already have created the ticket.
The incident is marked **Create failed**, and the next `sync-tickets` run looks up
the correlation ID first. If the earlier POST did create a ticket, LogSentinel
links to it instead of creating a second one.

### Duplicate tickets

These shouldn't happen: every create first searches for `correlation_id`. If you see one:

1. In ServiceNow, filter incidents on *Correlation ID* starts with `logsentinel-`.
2. If two tickets share a correlation ID, two LogSentinel processes created them
   at the same moment (for example, two `watch` processes on one database). Run one detector.
3. If they have different correlation IDs, they belong to two different LogSentinel
   incidents (for example, the same IP attacking again after the first incident was closed). That's correct.

### Ticket resolved in ServiceNow but still open in LogSentinel

- Is the sync job running? `docker compose --profile servicenow ps`, or run `logsentinel sync-tickets` by hand.
- Status is synced on **Resolved (6), Closed (7)** and **Canceled (8)**. *On Hold* and
  *In Progress* only update the state shown on the dashboard.
- Sync is one-way (ServiceNow → LogSentinel). Closing an alert in LogSentinel does
  not close the ticket; close it in ServiceNow.

### "Data Policy Exception: Resolution code is mandatory"

You get this when resolving a ticket through the API (for example a script or test) without a valid
`close_code`. Newer releases use different labels from older ones (e.g. *Resolved – Fixed by Caller*),
and an unknown value counts as empty. Send the label with `sysparm_input_display_value=true`, or
resolve in the UI. LogSentinel itself never resolves tickets: it only reads their state.

### Tickets not created at all

- `TICKETING_PROVIDER` must be `servicenow`. If it's set but a URL or credential is
  missing, the app logs `using the noop provider` and keeps running.
- Only incidents at or above `TICKET_MIN_SEVERITY` (default `high`) are ticketed.
- `logsentinel demo-seed` never opens tickets, by design.

## Rotating the integration password

1. Set a new password on the integration user (leave *Password needs reset* unticked).
2. Update `SERVICENOW_PASSWORD` in `.env` (or the secret store) and restart `ticket-sync`.
3. `logsentinel ticketing-check`.

# ANOM-001 Anomalous behaviour (Isolation Forest)

**Severity:** Medium · **MITRE ATT&CK:** none (behavioural)

## What it means

The Isolation Forest model found an IP whose activity in one hour looks unlike everything else (very high rate, many errors, many URLs or usernames, odd hour). It does **not** say what attack it is: it says "look here".

## How to verify

1. Read the alert's `unusual_features` and the feature values in the details: why did it stand out?
2. Read the raw events. Is it a known crawler, monitor or batch job? Then it is benign.
3. Is there a rule alert for the same IP? The anomaly alert then just confirms it. If not, the model may have found something rules miss (e.g. a slow brute force).

## How to contain

1. Contain according to what the events show (use the matching rule's runbook).

## How to close

- **False positive** for known benign sources (note why: these notes are how you would tune the model).
- If it revealed a real attack no rule caught, write a new YAML rule for that pattern.

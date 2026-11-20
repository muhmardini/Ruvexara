#!/usr/bin/env python3
"""
Ruvexara.py - simple website security checker (v2).

Checks:
  - Security headers on the homepage
  - Hard-coded keys / tokens in JS files (follows JS chunks one level deep)
  - Public source maps (.map files)
  - robots.txt, sitemap.xml, and whether the "hidden" paths really answer
  - .htaccess and other sensitive files
  - Admin / dashboard / API routes (with and without login)

Every finding gets a severity (HIGH / MEDIUM / LOW / INFO).
Reports: console, --json FILE, --html FILE.

Only run this against sites you own or have written permission to test.

Usage:
  pip install requests
  python Ruvexara.py https://example.com
  python Ruvexara.py https://example.com --html report.html --json report.json
  python Ruvexara.py https://example.com --cookie "session=abc123"
  python Ruvexara.py https://example.com --header "Authorization: Bearer TOKEN"
"""

import re
import json
import time
import uuid
import argparse
from datetime import datetime
from html import escape
from urllib.parse import urljoin, urlparse

import requests

# ---------------------------------------------------------------- settings
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"}
AUTH_HEADERS = {}          # filled from --cookie / --header
TARGET_HOST = ""           # credentials are ONLY sent to this host
DELAY = 0.3                # seconds between requests (--delay)
MAX_BYTES = 5_000_000      # never download more than 5 MB per file
MAX_JS_FILES = 100         # safety cap

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
FINDINGS = []
_seen = set()

# ---------------------------------------------------------------- what to look for
SECRET_PATTERNS = {
    # name: (severity, regex)
    "AWS Access Key": ("HIGH", r"AKIA[0-9A-Z]{16}"),
    "Google API Key": ("MEDIUM", r"AIza[0-9A-Za-z_\-]{35}"),
    "Stripe Live Secret Key": ("HIGH", r"[sr]k_live_[0-9a-zA-Z]{20,}"),
    "GitHub Token": ("HIGH", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    "Slack Token": ("HIGH", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "SendGrid API Key": ("HIGH", r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
    "Twilio API Key": ("MEDIUM", r"\bSK[0-9a-fA-F]{32}\b"),
    "Mailgun API Key": ("HIGH", r"\bkey-[0-9a-zA-Z]{32}\b"),
    "OpenAI API Key": ("HIGH", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}"),
    "Azure Storage Key": ("HIGH", r"AccountKey=[A-Za-z0-9+/=]{40,}"),
    "Firebase Database URL": ("LOW", r"https://[a-z0-9\-]+\.firebaseio\.com"),
    "Hard-coded Bearer token": ("MEDIUM", r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),
    "JWT": ("MEDIUM", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Private Key": ("HIGH", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Generic secret": ("MEDIUM", r"""(?i)(?:api[_-]?key|secret|token|passwd|password|auth)["']?\s*[:=]\s*["'](?P<v>[A-Za-z0-9_\-/+=]{16,})["']"""),
}
FAKE_WORDS = ("example", "your", "xxxx", "placeholder", "changeme", "000000")

SECURITY_HEADERS = [
    # (header, severity, why it matters)
    ("Content-Security-Policy", "MEDIUM", "Helps block XSS"),
    ("Strict-Transport-Security", "MEDIUM", "Forces HTTPS"),
    ("X-Frame-Options", "LOW", "Prevents clickjacking"),
    ("X-Content-Type-Options", "LOW", "Stops MIME sniffing"),
    ("Referrer-Policy", "LOW", "Controls what the Referer header leaks"),
    ("Permissions-Policy", "LOW", "Restricts browser features"),
]

SENSITIVE_FILES = [
    # (path, severity, text that must appear so we know the file is real)
    (".htaccess", "MEDIUM", r"(?i)rewrite|options|header|deny|allow|require|authtype|redirect|php_value"),
    (".htpasswd", "HIGH", r"^\S+:\S+"),
    (".env", "HIGH", r"^[A-Za-z_][A-Za-z0-9_]*\s*="),
    (".git/config", "HIGH", r"\[core\]"),
    (".git/HEAD", "HIGH", r"^ref:"),
    (".DS_Store", "LOW", r"Bud1"),
    ("phpinfo.php", "MEDIUM", r"phpinfo|PHP Version"),
    ("server-status", "MEDIUM", r"(?i)apache server status"),
    ("package.json", "LOW", r'"(?:name|dependencies|scripts)"'),
    ("composer.json", "LOW", r'"(?:require|name)"'),
    ("wp-config.php.bak", "HIGH", r"DB_PASSWORD|DB_NAME"),
    ("database.sql", "HIGH", r"(?i)create table|insert into"),
    ("backup.zip", "HIGH", r"^PK"),
    ("config.json", "MEDIUM", r"^\s*[\{\[]"),
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/dashboard",
    "/administrator", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/console",
    "/api/admin", "/api/users", "/api/config", "/api/v1/admin",
    "/actuator", "/actuator/env", "/swagger", "/swagger-ui", "/api-docs", "/graphql",
]

INTERESTING_WORDS = ["admin", "backup", "private", "secret", "config", "internal",
                     "dashboard", "staging", "debug", "upload", "sql"]


# ---------------------------------------------------------------- helpers
def add(severity, category, title, where="", detail=""):
    """Store one finding (duplicates are ignored)."""
    key = (severity, category, title, where, detail)
    if key in _seen:
        return
    _seen.add(key)
    FINDINGS.append({"severity": severity, "category": category,
                     "title": title, "where": where, "detail": detail})


class Resp:
    """Tiny response object: status, headers, url, text."""
    def __init__(self, r, body):
        self.status_code = r.status_code
        self.headers = r.headers
        self.url = r.url
        self.text = body.decode("utf-8", errors="ignore")


def get(url, redirects=True, auth=True, limit=MAX_BYTES):
    """
    One place for every HTTP request.
    - waits DELAY seconds first (rate limiting)
    - reads at most `limit` bytes (so a huge file can't hurt us)
    - follows redirects by hand so login credentials are only sent to TARGET_HOST
    """
    for _ in range(6):
        time.sleep(DELAY)
        headers = dict(HEADERS)
        if auth and urlparse(url).netloc == TARGET_HOST:
            headers.update(AUTH_HEADERS)
        try:
            r = requests.get(url, headers=headers, timeout=10,
                             allow_redirects=False, stream=True)
            body = r.raw.read(limit, decode_content=True)
            r.close()
        except Exception:
            return None
        if redirects and r.status_code in (301, 302, 303, 307, 308) and "Location" in r.headers:
            url = urljoin(url, r.headers["Location"])
            continue
        return Resp(r, body)
    return None


def looks_like_html(r):
    return "text/html" in r.headers.get("Content-Type", "").lower() or "<html" in r.text[:500].lower()


def mask(s):
    return s if len(s) <= 10 else s[:6] + "..." + s[-3:]


def looks_fake(s):
    return any(w in s.lower() for w in FAKE_WORDS)


def get_baseline(base):
    """How does the site answer a page that cannot exist? (detects 'soft 404' sites)"""
    r = get(urljoin(base, "/" + uuid.uuid4().hex), redirects=False, auth=False)
    return (r.status_code, len(r.text)) if r else (None, 0)


def is_soft_404(r, baseline):
    return r.status_code == baseline[0] and abs(len(r.text) - baseline[1]) < 50


# ---------------------------------------------------------------- check 1: security headers
def check_headers(r):
    print("[*] Checking security headers ...")
    if not r.url.startswith("https"):
        add("MEDIUM", "Transport", "Site is served over plain HTTP", r.url)
    for name, severity, why in SECURITY_HEADERS:
        if name in r.headers:
            continue
        if name == "Strict-Transport-Security" and not r.url.startswith("https"):
            continue
        if name == "X-Frame-Options" and "frame-ancestors" in r.headers.get("Content-Security-Policy", "").lower():
            continue  # CSP frame-ancestors does the same job
        add(severity, "Security header", f"Missing {name}", r.url, why)


# ---------------------------------------------------------------- check 2: JS files
def scan_text(text, where):
    for label, (severity, pattern) in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, text):
            value = m.groupdict().get("v") or m.group(0)
            if looks_fake(value):
                continue
            add(severity, "Secret in JS", label, where, mask(value))


def find_endpoints(text):
    return set(re.findall(r"""["'](/(?:api|admin)[^"'\s]*)["']""", text))


def find_js_refs(text, js_url, page_url):
    """Other .js files mentioned inside a JS file (chunks, dynamic imports)."""
    refs = set()
    for ref in re.findall(r"""["']((?:\.{1,2}/|/)?[A-Za-z0-9_\-./]+\.js(?:\?[^"'\s]*)?)["']""", text):
        # "./x.js" is relative to the JS file, "assets/x.js" is relative to the site
        refs.add(urljoin(js_url if ref.startswith(".") else page_url, ref))
    return refs


def check_source_map(js_url, text):
    m = re.search(r"//[#@]\s*sourceMappingURL=(\S+)", text)
    if m and m.group(1).startswith("data:"):
        add("MEDIUM", "Source map", "Source map is embedded inside the JS file", js_url)
        return
    map_url = urljoin(js_url, m.group(1)) if m else js_url.split("?")[0] + ".map"
    r = get(map_url, limit=4096)
    if r and r.status_code == 200 and not looks_like_html(r) and re.search(r'"(?:sources|mappings)"', r.text):
        add("MEDIUM", "Source map", "Source map is public (original source code can be recovered)", map_url)


def check_js(home, depth, include_external):
    print("[*] Scanning JS files ...")
    page_url = home.url
    scripts = {urljoin(page_url, s) for s in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', home.text)}
    inline = re.findall(r"<script(?![^>]*src)[^>]*>(.*?)</script>", home.text, re.S)

    endpoints = set()
    for i, code in enumerate(inline, 1):
        scan_text(code, f"inline script #{i}")
        endpoints |= find_endpoints(code)

    queue = [(u, 0) for u in sorted(scripts)]
    seen = set(scripts)
    scanned = skipped = 0
    while queue and scanned < MAX_JS_FILES:
        url, level = queue.pop(0)
        same_host = urlparse(url).netloc == TARGET_HOST
        if not same_host and not include_external:
            skipped += 1
            continue
        r = get(url)
        if not r or r.status_code != 200 or looks_like_html(r):
            continue
        scanned += 1
        scan_text(r.text, url)
        endpoints |= find_endpoints(r.text)
        check_source_map(url, r.text)
        if level < depth and same_host:
            for ref in find_js_refs(r.text, url, page_url):
                if ref not in seen:
                    seen.add(ref)
                    queue.append((ref, level + 1))

    print(f"    scanned {scanned} JS files + {len(inline)} inline scripts"
          f" ({skipped} third-party skipped, use --external to include)")
    return sorted(endpoints)


# ---------------------------------------------------------------- check 3: robots.txt + sitemap
def check_robots(base):
    print("[*] Checking robots.txt ...")
    url = urljoin(base, "/robots.txt")
    r = get(url)
    disallowed, sitemaps = [], []
    if not r or r.status_code != 200 or looks_like_html(r):
        add("INFO", "robots.txt", "No robots.txt found", url)
        return disallowed, sitemaps
    for line in r.text.splitlines():
        key, _, value = line.split("#")[0].strip().partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "disallow" and value and value != "/":
            disallowed.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)
    add("INFO", "robots.txt", f"robots.txt found with {len(disallowed)} Disallow entries", url)
    for d in disallowed:
        if any(w in d.lower() for w in INTERESTING_WORDS):
            add("LOW", "robots.txt", f"Sensitive-looking path listed: {d}", url)
    return disallowed, sitemaps


def check_disallowed(base, disallowed, baseline):
    """robots.txt says 'do not index' - but is the path actually reachable?"""
    print("[*] Testing the paths listed in robots.txt ...")
    for d in disallowed[:30]:
        if "*" in d or "$" in d:
            continue
        url = urljoin(base, d)
        r = get(url, redirects=False)
        if r and r.status_code == 200 and not is_soft_404(r, baseline):
            severity = "MEDIUM" if any(w in d.lower() for w in INTERESTING_WORDS) else "LOW"
            add(severity, "robots.txt", f"Disallowed path is publicly reachable: {d}", url)


def check_sitemap(base, sitemaps):
    print("[*] Checking sitemap ...")
    for sm in (sitemaps or [urljoin(base, "/sitemap.xml")])[:3]:
        r = get(sm)
        if not r or r.status_code != 200 or looks_like_html(r):
            continue
        locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", r.text, re.S)
        add("INFO", "Sitemap", f"Sitemap lists {len(locs)} URLs", sm)
        for u in [u for u in locs if any(w in u.lower() for w in INTERESTING_WORDS)][:20]:
            add("LOW", "Sitemap", f"Sensitive-looking URL in sitemap: {u}", sm)


# ---------------------------------------------------------------- check 4: sensitive files
def check_sensitive_files(base):
    print("[*] Checking .htaccess and other sensitive files ...")
    for path, severity, must_match in SENSITIVE_FILES:
        url = urljoin(base, "/" + path)
        r = get(url, redirects=False, limit=4096)
        if r is None:
            continue
        if r.status_code == 200 and r.text and not looks_like_html(r):
            if must_match and not re.search(must_match, r.text, re.M):
                continue  # 200 but it doesn't look like the real file
            add(severity, "Exposed file", f"/{path} is publicly readable", url)
        elif r.status_code == 403:
            add("INFO", "Exposed file", f"/{path} returned 403 (blocked)", url)


# ---------------------------------------------------------------- check 5: admin routes
def check_admin_routes(base, js_endpoints, baseline):
    print("[*] Checking admin / dashboard / API routes ...")
    from_js = [e for e in js_endpoints if "$" not in e and "{" not in e][:40]
    for p in dict.fromkeys(ADMIN_PATHS + from_js):
        url = urljoin(base, p)

        # 1) as an anonymous visitor
        u = get(url, redirects=False, auth=False)
        if u and not is_soft_404(u, baseline):
            if u.status_code == 200:
                severity = "LOW" if "login" in p else "MEDIUM"
                add(severity, "Routes", f"{p} answers 200 without login - verify manually", url)
            elif u.status_code in (401, 403):
                add("INFO", "Routes", f"{p} exists and is protected ({u.status_code})", url)
            elif u.status_code in (301, 302, 303, 307, 308):
                add("INFO", "Routes", f"{p} redirects to {u.headers.get('Location', '?')}", url)

        # 2) with your credentials (only when --cookie / --header was given)
        if AUTH_HEADERS:
            a = get(url, redirects=False, auth=True)
            if a and a.status_code == 200 and not is_soft_404(a, baseline) \
                    and not (u and u.status_code == 200):
                add("INFO", "Routes", f"{p} is reachable only with your credentials (expected)", url)


# ---------------------------------------------------------------- reports
COLORS = {"HIGH": "#c62828", "MEDIUM": "#e65100", "LOW": "#9e7b00", "INFO": "#1565c0"}

HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Ruvexara report</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem;color:#222;background:#fafafa}
h1{margin-bottom:.2rem}
.meta{color:#666;margin-bottom:1.5rem}
.cards{display:flex;gap:1rem;margin-bottom:1.5rem}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:.8rem 1.4rem;text-align:center}
.card b{display:block;font-size:1.8rem}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{border:1px solid #ddd;padding:.5rem .7rem;text-align:left;vertical-align:top}
th{background:#f0f0f0}
.badge{color:#fff;border-radius:4px;padding:.1rem .5rem;font-size:.8rem;font-weight:600}
.mono{font-family:ui-monospace,monospace;font-size:.85rem;word-break:break-all}
</style></head><body>
<h1>Ruvexara report</h1>
<div class="meta">Target: %%TARGET%% &middot; Scanned: %%TIME%% &middot; %%AUTH%%</div>
<div class="cards">%%CARDS%%</div>
<table>
<tr><th>Severity</th><th>Category</th><th>Finding</th><th>Where</th><th>Detail</th></tr>
%%ROWS%%
</table>
<p class="meta">Secrets are masked, but treat this report as sensitive.</p>
</body></html>"""


def sorted_findings():
    return sorted(FINDINGS, key=lambda f: SEVERITY_ORDER[f["severity"]])


def counts():
    return {s: sum(1 for f in FINDINGS if f["severity"] == s) for s in SEVERITY_ORDER}


def print_report():
    print("\n" + "=" * 60)
    print("RESULTS: " + "  ".join(f"{s}: {n}" for s, n in counts().items()))
    print("=" * 60)
    for f in sorted_findings():
        print(f"[{f['severity']:<6}] {f['category']}: {f['title']}")
        if f["where"]:
            print(f"           where:  {f['where']}")
        if f["detail"]:
            print(f"           detail: {f['detail']}")


def write_json(path, target):
    data = {"target": target, "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "authenticated": bool(AUTH_HEADERS), "summary": counts(), "findings": sorted_findings()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] JSON report saved to {path}")


def write_html(path, target):
    cards = "".join(
        f"<div class='card'><b style='color:{COLORS[s]}'>{n}</b>{s}</div>" for s, n in counts().items())
    rows = "".join(
        f"<tr><td><span class='badge' style='background:{COLORS[f['severity']]}'>{f['severity']}</span></td>"
        f"<td>{escape(f['category'])}</td><td>{escape(f['title'])}</td>"
        f"<td class='mono'>{escape(f['where'])}</td><td class='mono'>{escape(f['detail'])}</td></tr>\n"
        for f in sorted_findings())
    page = (HTML_TEMPLATE
            .replace("%%TARGET%%", escape(target))
            .replace("%%TIME%%", datetime.now().strftime("%Y-%m-%d %H:%M"))
            .replace("%%AUTH%%", "authenticated scan" if AUTH_HEADERS else "anonymous scan")
            .replace("%%CARDS%%", cards)
            .replace("%%ROWS%%", rows))
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"[+] HTML report saved to {path}")


# ---------------------------------------------------------------- main
def main():
    global DELAY, TARGET_HOST

    ap = argparse.ArgumentParser(description="Simple website security checker")
    ap.add_argument("url", help="e.g. https://example.com")
    ap.add_argument("--cookie", help='session cookie, e.g. "session=abc123; csrf=xyz"')
    ap.add_argument("--header", action="append", default=[],
                    help='extra header, e.g. "Authorization: Bearer TOKEN" (can be repeated)')
    ap.add_argument("--delay", type=float, default=0.3, help="seconds between requests (default 0.3)")
    ap.add_argument("--depth", type=int, default=1, help="how many levels of JS chunks to follow (default 1)")
    ap.add_argument("--external", action="store_true", help="also scan third-party JS (CDNs)")
    ap.add_argument("--json", metavar="FILE", help="save a JSON report")
    ap.add_argument("--html", metavar="FILE", help="save an HTML report")
    args = ap.parse_args()

    DELAY = args.delay
    if args.cookie:
        AUTH_HEADERS["Cookie"] = args.cookie
    for h in args.header:
        name, _, value = h.partition(":")
        if value:
            AUTH_HEADERS[name.strip()] = value.strip()

    base = args.url if args.url.startswith("http") else "https://" + args.url
    TARGET_HOST = urlparse(base).netloc

    print(f"Target: {base}")
    print("Only scan sites you own or have permission to test.")
    if AUTH_HEADERS:
        print(f"Authenticated scan: credentials are only sent to {TARGET_HOST}")

    home = get(base)
    if home is None:
        print("[!] Could not reach the site")
        return
    # use the final address (after redirects) from now on
    p = urlparse(home.url)
    TARGET_HOST = p.netloc
    base = f"{p.scheme}://{p.netloc}"

    check_headers(home)
    endpoints = check_js(home, args.depth, args.external)
    baseline = get_baseline(base)
    disallowed, sitemaps = check_robots(base)
    check_disallowed(base, disallowed, baseline)
    check_sitemap(base, sitemaps)
    check_sensitive_files(base)
    check_admin_routes(base, endpoints, baseline)

    print_report()
    if args.json:
        write_json(args.json, base)
    if args.html:
        write_html(args.html, base)


if __name__ == "__main__":
    main()

import os
import sqlite3
import hashlib
import hmac
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Flask, request, abort, Response, g, render_template_string, jsonify

import geoip2.database
import geoip2.errors

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
DB_PATH = os.environ.get("ANALYTICS_DB", "analytics.sqlite3")
DASH_TOKEN = os.environ.get("ANALYTICS_DASH_TOKEN", "changeme")
IP_SALT = os.environ.get("ANALYTICS_IP_SALT", "please-change-me-and-keep-secret")
RETENTION_DAYS = int(os.environ.get("ANALYTICS_RETENTION_DAYS", "180"))
GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "/geoip/GeoLite2-Country.mmdb")
CORS_ALLOW_ORIGINS = os.environ.get(
    "CORS_ALLOW_ORIGINS",
    "https://mbh.photos"
).split(",")
CORS_ALLOW_ORIGINS = [o.strip() for o in CORS_ALLOW_ORIGINS if o.strip()]

# 1x1 transparent gif
PIXEL_BYTES = (
    b"GIF89a"
    b"\x01\x00\x01\x00"
    b"\x80"
    b"\x00"
    b"\x00"
    b"\x00\x00\x00"
    b"\xff\xff\xff"
    b"\x21\xf9\x04\x01\x00\x00\x00\x00"
    b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00"
    b"\x02\x02\x44\x01\x00"
    b"\x3b"
)

app = Flask(__name__)

geoip_reader = None
def get_geoip_reader():
    global geoip_reader
    if geoip_reader is None:
        if os.path.exists(GEOIP_DB_PATH):
            geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        else:
            geoip_reader = None
    return geoip_reader


# -----------------------------------------------------------------------------
# DB helpers
# -----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()

def ensure_columns(db):
    """
    Create / migrate tables if needed. This gets called on every request and
    is idempotent.
    """
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS pageviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            path TEXT NOT NULL,
            referrer TEXT,
            ua_browser TEXT,
            ua_os TEXT,
            ip_bucket TEXT,
            country TEXT
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            event_type TEXT NOT NULL,
            page_path TEXT,
            target TEXT,
            ua_browser TEXT,
            ua_os TEXT,
            ip_bucket TEXT,
            country TEXT
        );
        """
    )

    # Try to add any missing columns in case of older DB
    for table, coldefs in {
        "pageviews": ["country TEXT", "ua_browser TEXT", "ua_os TEXT", "ip_bucket TEXT", "referrer TEXT"],
        "events": [
            "page_path TEXT",
            "target TEXT",
            "ua_browser TEXT",
            "ua_os TEXT",
            "ip_bucket TEXT",
            "country TEXT"
        ],
    }.items():
        for coldef in coldefs:
            colname = coldef.split()[0]
            try:
                db.execute(f"SELECT {colname} FROM {table} LIMIT 1;")
            except sqlite3.OperationalError:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {coldef};")

    db.commit()

@app.before_request
def before():
    db = get_db()
    ensure_columns(db)
    # retention cleanup for both tables
    db.execute(
        """
        DELETE FROM pageviews
        WHERE ts < datetime('now', ?)
        """,
        (f"-{RETENTION_DAYS} days",),
    )
    db.execute(
        """
        DELETE FROM events
        WHERE ts < datetime('now', ?)
        """,
        (f"-{RETENTION_DAYS} days",),
    )
    db.commit()


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def pick_cors_origin(request_origin: str | None) -> str | None:
    if not request_origin:
        return None
    for allowed in CORS_ALLOW_ORIGINS:
        if request_origin == allowed:
            return allowed
    return None


def anonymize_ip(raw_ip: str) -> str:
    """
    Truncate the IP (coarse bucket), then HMAC with a secret salt.
    Result is something like v4:abcd1234....
    """
    try:
        ip_obj = ipaddress.ip_address(raw_ip)
    except ValueError:
        return "invalid"

    if isinstance(ip_obj, ipaddress.IPv4Address):
        octets = raw_ip.split(".")
        if len(octets) == 4:
            truncated = f"{octets[0]}.{octets[1]}.0.0"
            version = "v4"
        else:
            truncated = "0.0.0.0"
            version = "v4"
    else:
        # IPv6: keep ~top /32 bits
        as_int = int(ip_obj)
        mask = (2**128 - 1) ^ (2**96 - 1)
        truncated_int = as_int & mask
        truncated_ip = ipaddress.IPv6Address(truncated_int)
        truncated = truncated_ip.exploded
        version = "v6"

    digest = hmac.new(IP_SALT.encode("utf-8"), truncated.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{version}:{digest[:16]}"

def parse_user_agent(ua: str):
    """
    We classify browser + OS coarsely so it's not fingerprinty.
    """
    ua_lower = ua.lower()

    if "firefox" in ua_lower and "seamonkey" not in ua_lower:
        browser = "Firefox"
    elif "chrome" in ua_lower and "chromium" not in ua_lower and "edg" not in ua_lower:
        browser = "Chrome"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        browser = "Safari"
    elif "edg" in ua_lower:
        browser = "Edge"
    elif "chromium" in ua_lower:
        browser = "Chromium"
    else:
        browser = "Other"

    if "windows" in ua_lower:
        os_name = "Windows"
    elif "mac os x" in ua_lower or "macintosh" in ua_lower:
        os_name = "macOS"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower or "ios" in ua_lower:
        os_name = "iOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
    else:
        os_name = "Other"

    return browser, os_name

def sanitize_referrer(raw_ref):
    """
    Only keep the referrer's hostname, not full URL.
    """
    if not raw_ref:
        return None
    try:
        u = urlparse(raw_ref)
        return u.hostname
    except Exception:
        return None

def lookup_country(raw_ip: str) -> str:
    """
    Return ISO country code ('CH', 'DE', etc.) or 'UNK'.
    We do NOT store the raw IP.
    """
    reader = get_geoip_reader()
    if reader is None or not raw_ip:
        return "UNK"
    try:
        resp = reader.country(raw_ip)
        code = resp.country.iso_code or resp.registered_country.iso_code
        return code if code else "UNK"
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return "UNK"

def request_fingerprint(req):
    """
    Produce the anon metadata we reuse for pageviews and events.
    """
    src_ip = req.headers.get("X-Forwarded-For", req.remote_addr)
    ip_bucket = anonymize_ip(src_ip)
    country_code = lookup_country(src_ip)
    ua_browser, ua_os = parse_user_agent(req.headers.get("User-Agent", ""))

    return {
        "ip_bucket": ip_bucket,
        "country": country_code,
        "ua_browser": ua_browser,
        "ua_os": ua_os,
    }

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/148a2801968b695634b116e620005dbb.gif")
def pixel():
    meta = request_fingerprint(request)

    path = request.args.get("p", "/")
    ref = sanitize_referrer(request.headers.get("Referer"))

    db = get_db()
    db.execute(
        """
        INSERT INTO pageviews (ts, path, referrer, ua_browser, ua_os, ip_bucket, country)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            path[:500],
            (ref[:255] if ref else None),
            meta["ua_browser"][:50],
            meta["ua_os"][:50],
            meta["ip_bucket"][:80],
            meta["country"][:4],
        ),
    )
    db.commit()

    resp = Response(PIXEL_BYTES, mimetype="image/gif")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/event", methods=["POST", "OPTIONS"])
def event():
    if request.method == "OPTIONS":
        # Preflight passes through add_cors_headers(), so we just return 200
        return ("", 200)

    data = request.get_json(silent=True) or {}
    event_type = str(data.get("type", "unknown"))[:50]
    page_path = str(data.get("page", "/"))[:500]
    target = data.get("target")
    if target is not None:
        target = str(target)[:500]

    meta = request_fingerprint(request)

    db = get_db()
    db.execute(
        """
        INSERT INTO events (ts, event_type, page_path, target, ua_browser, ua_os, ip_bucket, country)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            event_type,
            page_path,
            target,
            meta["ua_browser"][:50],
            meta["ua_os"][:50],
            meta["ip_bucket"][:80],
            meta["country"][:4],
        ),
    )
    db.commit()

    return jsonify({"ok": True})


@app.route("/stats")
def stats():
    token = request.args.get("token", "")
    if token != DASH_TOKEN:
        return abort(403)

    db = get_db()

    # Top pages
    recent_paths = db.execute(
        """
        SELECT path, COUNT(*) as views
        FROM pageviews
        WHERE ts >= datetime('now', '-30 days')
        GROUP BY path
        ORDER BY views DESC
        LIMIT 50;
        """
    ).fetchall()

    # Countries
    recent_countries = db.execute(
        """
        SELECT country, COUNT(*) as hits
        FROM pageviews
        WHERE ts >= datetime('now', '-30 days')
        GROUP BY country
        ORDER BY hits DESC;
        """
    ).fetchall()

    # Browser / OS breakdown
    recent_agents = db.execute(
        """
        SELECT ua_browser, ua_os, COUNT(*) as hits
        FROM pageviews
        WHERE ts >= datetime('now', '-30 days')
        GROUP BY ua_browser, ua_os
        ORDER BY hits DESC;
        """
    ).fetchall()

    # Events
    recent_events = db.execute(
        """
        SELECT event_type, target, COUNT(*) as hits
        FROM events
        WHERE ts >= datetime('now', '-30 days')
        GROUP BY event_type, target
        ORDER BY hits DESC
        LIMIT 50;
        """
    ).fetchall()

    html = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Minimal Analytics</title>
<style>
body {
  font-family: system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background-color:#0f172a;
  color:#f8fafc;
  padding:2rem;
  line-height:1.4;
}
h1,h2 {
  font-weight:600;
  color:#fff;
  margin-top:1.5rem;
  margin-bottom:.5rem;
}
.card {
  background-color:#1e293b;
  border-radius:1rem;
  box-shadow:0 20px 40px rgb(0 0 0 / .6);
  padding:1rem 1.5rem;
  margin-bottom:2rem;
}
table {
  width:100%;
  border-collapse:collapse;
  font-size:.9rem;
}
th {
  text-align:left;
  font-weight:600;
  color:#e2e8f0;
  border-bottom:1px solid #475569;
  padding:.5rem .25rem;
}
td {
  border-bottom:1px solid #334155;
  padding:.5rem .25rem;
  color:#cbd5e1;
  vertical-align:top;
}
.footer {
  font-size:.75rem;
  color:#64748b;
  margin-top:3rem;
  max-width:600px;
}
@media(min-width:1100px){
  .layout{
    display:grid;
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:1.5rem;
  }
  .layout-wide{
    grid-column:span 2;
  }
}
.badge {
  background-color:#334155;
  border-radius:.5rem;
  padding:.125rem .5rem;
  font-size:.75rem;
  color:#94a3b8;
  display:inline-block;
}
code {
  background:#1e293b;
  color:#94a3b8;
  padding:.15rem .4rem;
  border-radius:.4rem;
  font-size:.75rem;
}
</style>
</head>
<body>
<h1>Minimal Analytics · last 30 days</h1>

<div class="layout">

  <div class="card">
    <h2>Page Views</h2>
    <table>
      <tr><th>Path</th><th style="text-align:right;">Views</th></tr>
      {% for row in recent_paths %}
      <tr>
        <td>{{ row["path"] }}</td>
        <td style="text-align:right;">{{ row["views"] }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Countries</h2>
    <table>
      <tr><th>Country</th><th style="text-align:right;">Hits</th></tr>
      {% for row in recent_countries %}
      <tr>
        <td>{{ row["country"] }}</td>
        <td style="text-align:right;">{{ row["hits"] }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Browsers / OS</h2>
    <table>
      <tr><th>Browser</th><th>OS</th><th style="text-align:right;">Hits</th></tr>
      {% for row in recent_agents %}
      <tr>
        <td>{{ row["ua_browser"] }}</td>
        <td>{{ row["ua_os"] }}</td>
        <td style="text-align:right;">{{ row["hits"] }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card layout-wide">
    <h2>Events</h2>
    <table>
      <tr>
        <th>Event</th>
        <th>Target (photo / size / etc.)</th>
        <th style="text-align:right;">Count</th>
      </tr>
      {% for row in recent_events %}
      <tr>
        <td>{{ row["event_type"] }}</td>
        <td>{{ row["target"] }}</td>
        <td style="text-align:right;">{{ row["hits"] }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

</div>

<div class="footer">
  <p>We store:</p>
  <ul>
    <li>Page path &amp; referrer domain (page views only)</li>
    <li>Anonymous country + anonymized IP bucket</li>
    <li>Browser / OS family (coarse, not full UA)</li>
    <li>Anonymous interaction events (lightbox opens, buy clicks, checkout attempts, contact starts)</li>
  </ul>
  <p>No cookies. No personal message content. Auto-delete after {{ retention }} days.</p>
  <p class="badge">Legal basis: legitimate interest in understanding site usage and preventing abuse.</p>
</div>

</body>
</html>
"""
    return render_template_string(
        html,
        recent_paths=recent_paths,
        recent_countries=recent_countries,
        recent_agents=recent_agents,
        recent_events=recent_events,
        retention=RETENTION_DAYS,
    )


@app.route("/healthz")
def healthz():
    return "ok", 200

@app.after_request
def add_cors_headers(resp):
    origin = pick_cors_origin(request.headers.get("Origin"))

    if origin:
        # Figure out which methods/headers Firefox just asked for, fall back to safe defaults
        req_method = request.headers.get("Access-Control-Request-Method", "GET,POST,OPTIONS")
        req_headers = request.headers.get("Access-Control-Request-Headers", "Content-Type")

        # Attach CORS headers
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Credentials"] = "false"
        resp.headers["Access-Control-Allow-Methods"] = req_method
        resp.headers["Access-Control-Allow-Headers"] = req_headers
        resp.headers["Access-Control-Max-Age"] = "600"  # cache preflight 10min

    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

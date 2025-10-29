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

# CORS allowlist (for cross-origin usage if you still call analytics.xmb.li from another domain)
CORS_ALLOW_ORIGINS = os.environ.get(
    "CORS_ALLOW_ORIGINS",
    "https://mbh.photos"
).split(",")
CORS_ALLOW_ORIGINS = [o.strip() for o in CORS_ALLOW_ORIGINS if o.strip()]

# 1x1 transparent gif bytes (tracking pixel)
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
# DB helpers / migrations
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
    Create tables if missing and try to backfill new columns.
    Safe to run every request.
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

    # try to add missing columns on upgrade
    for table, coldefs in {
        "pageviews": [
            "ts TEXT",
            "path TEXT",
            "referrer TEXT",
            "ua_browser TEXT",
            "ua_os TEXT",
            "ip_bucket TEXT",
            "country TEXT"
        ],
        "events": [
            "ts TEXT",
            "event_type TEXT",
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

    # retention cleanup
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
# Privacy helpers
# -----------------------------------------------------------------------------
def anonymize_ip(raw_ip: str) -> str:
    """
    Bucket/truncate IP then HMAC with secret salt.
    Returns something like "v4:abcd1234..." or "v6:abcd1234...".
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
    Rough browser + OS classification (coarse on purpose).
    """
    ua_lower = ua.lower()

    # browser
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

    # OS
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
    Keep only the hostname of Referer. (Don't store full URL/query/etc.)
    """
    if not raw_ref:
        return None
    try:
        u = urlparse(raw_ref)
        return u.hostname
    except Exception:
        return None

def get_country_from_ip(raw_ip: str) -> str:
    """
    Return ISO country code from IP using local MaxMind DB.
    Store only the 2-letter code, never the full IP.
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
    Extract anonymized metadata for pageviews and events.
    """
    src_ip = req.headers.get("X-Forwarded-For", req.remote_addr)
    ip_bucket = anonymize_ip(src_ip)
    country_code = get_country_from_ip(src_ip)
    ua_browser, ua_os = parse_user_agent(req.headers.get("User-Agent", ""))

    return {
        "ip_bucket": ip_bucket,
        "country": country_code,
        "ua_browser": ua_browser,
        "ua_os": ua_os,
    }

def pick_cors_origin(request_origin: str | None) -> str | None:
    """
    Return allowed origin if it matches our allowlist.
    """
    if not request_origin:
        return None
    for allowed in CORS_ALLOW_ORIGINS:
        if request_origin == allowed:
            return allowed
    return None

@app.after_request
def add_cors_headers(resp):
    """
    Attach CORS headers if this was a cross-origin call from an allowed Origin.
    For same-origin (/analytics/... reverse proxy) CORS won't be needed.
    """
    origin = pick_cors_origin(request.headers.get("Origin"))

    if origin:
        req_method = request.headers.get("Access-Control-Request-Method", "GET,POST,OPTIONS")
        req_headers = request.headers.get("Access-Control-Request-Headers", "Content-Type")

        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Credentials"] = "false"
        resp.headers["Access-Control-Allow-Methods"] = req_method
        resp.headers["Access-Control-Allow-Headers"] = req_headers
        resp.headers["Access-Control-Max-Age"] = "600"
    return resp


# -----------------------------------------------------------------------------
# Ingest routes
# -----------------------------------------------------------------------------
@app.route("/148a2801968b695634b116e620005dbb.gif")
def pixel():
    """
    Tracking pixel endpoint.
    IMPORTANT: this route name stays EXACTLY as provided.
    You include it like:
      <img src="/analytics/148a2801968b695634b116e620005dbb.gif?p=/path">
    """
    meta = request_fingerprint(request)

    # capture the path being viewed (from the query param you add in HTML/JS)
    path = request.args.get("p", "/")
    # capture referring site (domain only)
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
    """
    Custom event endpoint.
    Body example:
      { "type": "buy_checkout",
        "target": "Snowy Owl :: 60x40",
        "page": "/" }
    No personal data (no email/name/message).
    """
    if request.method == "OPTIONS":
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


# -----------------------------------------------------------------------------
# Sparkline builder (inline SVG chart)
# -----------------------------------------------------------------------------
def build_sparkline(points, width=320, height=60, stroke="#38bdf8"):
    """
    Tiny inline SVG sparkline.
    points: list[(day_string, views_int)], ascending by day.
    """
    if not points:
        svg = f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" ' \
              f'fill="none" stroke="{stroke}" stroke-width="2" stroke-linecap="round" ' \
              f'shape-rendering="geometricPrecision"></svg>'
        return {"svg": svg, "last_count": 0}

    counts = [p[1] for p in points]
    max_c = max(counts) or 1
    min_c = min(counts)
    span_c = max_c - min_c or 1

    n = len(points)
    if n == 1:
        xs = [width / 2]
    else:
        xs = [i * (width / (n - 1)) for i in range(n)]

    ys = [
        height - ((c - min_c) / span_c) * (height - 4) - 2
        for c in counts
    ]

    d_parts = []
    for i, (x, y) in enumerate(zip(xs, ys)):
        cmd = "M" if i == 0 else "L"
        d_parts.append(f"{cmd}{x:.1f},{y:.1f}")
    d_attr = " ".join(d_parts)

    svg = f'''
<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}"
     fill="none" stroke="{stroke}" stroke-width="2" stroke-linecap="round"
     shape-rendering="geometricPrecision">
  <path d="{d_attr}" />
</svg>'''.strip()

    return {"svg": svg, "last_count": counts[-1]}


# -----------------------------------------------------------------------------
# Dashboard
# -----------------------------------------------------------------------------
@app.route("/stats")
def stats():
    token = request.args.get("token", "")
    if token != DASH_TOKEN:
        return abort(403)

    db = get_db()

    # Top pages (30d)
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

    total_views_30d = sum(row["views"] for row in recent_paths)

    # Top referrers (30d)
    recent_referrers = db.execute(
        """
        SELECT referrer, COUNT(*) as hits
        FROM pageviews
        WHERE ts >= datetime('now', '-30 days') AND referrer IS NOT NULL
        GROUP BY referrer
        ORDER BY hits DESC
        LIMIT 50;
        """
    ).fetchall()

    # Countries (30d)
    recent_countries = db.execute(
        """
        SELECT country, COUNT(*) as hits
        FROM pageviews
        WHERE ts >= datetime('now', '-30 days')
        GROUP BY country
        ORDER BY hits DESC;
        """
    ).fetchall()

    # Browser / OS (30d)
    recent_agents = db.execute(
        """
        SELECT ua_browser, ua_os, COUNT(*) as hits
        FROM pageviews
        WHERE ts >= datetime('now', '-30 days')
        GROUP BY ua_browser, ua_os
        ORDER BY hits DESC;
        """
    ).fetchall()

    # Events (30d)
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

    total_events_30d = sum(row["hits"] for row in recent_events)

    # pick top page / country
    top_page = recent_paths[0]["path"] if recent_paths else "-"
    top_country = recent_countries[0]["country"] if recent_countries else "-"

    # views per day for sparkline
    by_day = db.execute(
        """
        SELECT strftime('%Y-%m-%d', ts) AS day, COUNT(*) AS views
        FROM pageviews
        WHERE ts >= datetime('now', '-30 days')
        GROUP BY day
        ORDER BY day ASC;
        """
    ).fetchall()

    day_points = [(row["day"], row["views"]) for row in by_day]
    spark = build_sparkline(day_points, width=320, height=60, stroke="#38bdf8")
    spark_svg = spark["svg"]
    spark_last = spark["last_count"]

    # dashboard HTML with Referrers card added
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Minimal Analytics</title>
<style>
:root {
  --bg-main:#0f172a;
  --bg-card:#1e293b;
  --text-main:#f8fafc;
  --text-dim:#94a3b8;
  --text-dimmer:#64748b;
  --border-card:#334155;
  --border-head:#475569;
  --accent:#38bdf8;
  --radius-lg:1rem;
  --shadow-card:0 20px 40px rgb(0 0 0 / .6);
  --font:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:var(--font);
  background-color:var(--bg-main);
  color:var(--text-main);
  padding:2rem;
  line-height:1.4;
  -webkit-font-smoothing:antialiased;
}
header{
  display:flex;
  flex-direction:column;
  gap:.5rem;
  margin-bottom:2rem;
}
@media(min-width:600px){
  header{flex-direction:row;justify-content:space-between;align-items:flex-end}
}
.title{
  font-size:1.2rem;
  font-weight:600;
  color:#fff;
}
.subtitle{
  font-size:.8rem;
  color:var(--text-dimmer);
  max-width:480px;
  line-height:1.4;
}

.grid-cards{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(min(180px,100%),1fr));
  gap:1rem;
  margin-bottom:2rem;
}
.metric-card{
  background:var(--bg-card);
  border-radius:var(--radius-lg);
  box-shadow:var(--shadow-card);
  padding:1rem 1.25rem;
  min-width:0;
}
.metric-head{
  font-size:.7rem;
  font-weight:500;
  color:var(--text-dim);
  display:flex;
  align-items:center;
  justify-content:space-between;
  margin-bottom:.5rem;
}
.metric-value{
  font-size:1.4rem;
  font-weight:600;
  color:var(--text-main);
  line-height:1.2;
}
.metric-foot{
  font-size:.7rem;
  color:var(--text-dimmer);
  margin-top:.4rem;
  line-height:1.3;
  word-break:break-word;
}
.metric-accent{
  color:var(--accent);
  font-weight:600;
}
.spark-card{
  display:grid;
  grid-template-columns:1fr auto;
  align-items:center;
  gap:1rem;
}
.spark-svg{
  width:100%;
  max-width:320px;
  height:auto;
}
.spark-info{
  text-align:right;
}
.spark-label{
  font-size:.7rem;
  color:var(--text-dim);
}
.spark-value{
  font-size:1.2rem;
  font-weight:600;
  color:var(--accent);
  line-height:1.2;
}

.sections{
  display:grid;
  gap:1.5rem;
  margin-bottom:2rem;
}
@media(min-width:1100px){
  .sections{
    grid-template-columns:repeat(2,minmax(0,1fr));
  }
}
.card{
  background-color:var(--bg-card);
  border-radius:var(--radius-lg);
  box-shadow:var(--shadow-card);
  padding:1rem 1.5rem;
}
.card-header{
  display:flex;
  align-items:baseline;
  justify-content:space-between;
  margin-bottom:.75rem;
  flex-wrap:wrap;
  gap:.5rem;
}
.card-title{
  font-weight:600;
  color:#fff;
  font-size:1rem;
  line-height:1.2;
}
.card-hint{
  font-size:.7rem;
  color:var(--text-dim);
  line-height:1.2;
}

table{
  width:100%;
  border-collapse:collapse;
  font-size:.8rem;
}
th{
  text-align:left;
  font-weight:600;
  color:#e2e8f0;
  border-bottom:1px solid var(--border-head);
  padding:.5rem .25rem;
  font-size:.7rem;
  text-transform:uppercase;
  letter-spacing:.03em;
}
td{
  border-bottom:1px solid var(--border-card);
  padding:.5rem .25rem;
  color:#cbd5e1;
  vertical-align:top;
  line-height:1.4;
  word-break:break-word;
}
td.num{
  text-align:right;
  font-variant-numeric:tabular-nums;
  white-space:nowrap;
}

.footer{
  font-size:.7rem;
  color:var(--text-dimmer);
  line-height:1.5;
  max-width:650px;
  margin-top:3rem;
}
.footer ul{
  margin:.5rem 0 .5rem 1rem;
}
.footer li{
  margin-bottom:.4rem;
}
.badge{
  background-color:#334155;
  border-radius:.5rem;
  padding:.2rem .5rem;
  font-size:.7rem;
  color:#94a3b8;
  display:inline-block;
  line-height:1.2;
  margin-top:.5rem;
  font-weight:500;
}

@media(min-width:1300px){
  .wide-2col{
    grid-column:span 2;
  }
}
</style>
</head>
<body>

<header>
  <div class="title">Minimal Analytics · last 30 days</div>
  <div class="subtitle">
    Anonymous, cookie-less, first-party style metrics. No personal data, auto-purged after {{ retention }} days.
  </div>
</header>

<section class="grid-cards">

  <div class="metric-card">
    <div class="metric-head">
      <span>Pageviews</span>
      <span class="metric-accent">30d</span>
    </div>
    <div class="metric-value">{{ total_views_30d }}</div>
    <div class="metric-foot">
      Raw view count (we don't try to de-dupe people).
    </div>
  </div>

  <div class="metric-card">
    <div class="metric-head">
      <span>Tracked Events</span>
      <span class="metric-accent">30d</span>
    </div>
    <div class="metric-value">{{ total_events_30d }}</div>
    <div class="metric-foot">
      lightbox_open / buy_open / buy_checkout / contact_start ...
    </div>
  </div>

  <div class="metric-card">
    <div class="metric-head">
      <span>Top Page</span>
      <span class="metric-accent">traffic</span>
    </div>
    <div class="metric-value" style="font-size:1rem;word-break:break-word;">
      {{ top_page }}
    </div>
    <div class="metric-foot">
      Most viewed path.
    </div>
  </div>

  <div class="metric-card spark-card">
    <div class="spark-svg">
      {{ spark_svg | safe }}
    </div>
    <div class="spark-info">
      <div class="spark-label">Latest day</div>
      <div class="spark-value">{{ spark_last }}</div>
      <div class="metric-foot" style="margin-top:.4rem;">
        Pageviews / day (30d)
      </div>
    </div>
  </div>

  <div class="metric-card">
    <div class="metric-head">
      <span>Top Country</span>
      <span class="metric-accent">30d</span>
    </div>
    <div class="metric-value">{{ top_country }}</div>
    <div class="metric-foot">
      Based on coarse IP → country lookup.
    </div>
  </div>

</section>

<section class="sections">

  <div class="card">
    <div class="card-header">
      <div class="card-title">Pages</div>
      <div class="card-hint">Which URLs get viewed most</div>
    </div>
    <table>
      <tr><th>Path</th><th class="num">Views</th></tr>
      {% for row in recent_paths %}
      <tr>
        <td>{{ row["path"] }}</td>
        <td class="num">{{ row["views"] }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <div class="card-header">
      <div class="card-title">Referrers</div>
      <div class="card-hint">Who sent traffic</div>
    </div>
    <table>
      <tr><th>Domain</th><th class="num">Hits</th></tr>
      {% for row in recent_referrers %}
      <tr>
        <td>{{ row["referrer"] }}</td>
        <td class="num">{{ row["hits"] }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <div class="card-header">
      <div class="card-title">Countries</div>
      <div class="card-hint">Visitor origin (coarse)</div>
    </div>
    <table>
      <tr><th>Country</th><th class="num">Hits</th></tr>
      {% for row in recent_countries %}
      <tr>
        <td>{{ row["country"] }}</td>
        <td class="num">{{ row["hits"] }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <div class="card-header">
      <div class="card-title">Browsers / OS</div>
      <div class="card-hint">Agent families (coarse)</div>
    </div>
    <table>
      <tr><th>Browser</th><th>OS</th><th class="num">Hits</th></tr>
      {% for row in recent_agents %}
      <tr>
        <td>{{ row["ua_browser"] }}</td>
        <td>{{ row["ua_os"] }}</td>
        <td class="num">{{ row["hits"] }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card wide-2col">
    <div class="card-header">
      <div class="card-title">Events</div>
      <div class="card-hint">
        Which actions people actually tried
      </div>
    </div>
    <table>
      <tr>
        <th>Event</th>
        <th>Target</th>
        <th class="num">Count</th>
      </tr>
      {% for row in recent_events %}
      <tr>
        <td>{{ row["event_type"] }}</td>
        <td>{{ row["target"] }}</td>
        <td class="num">{{ row["hits"] }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

</section>

<section class="footer">
  <p>We store:</p>
  <ul>
    <li>Page path + timestamp</li>
    <li>Referrer domain (if any)</li>
    <li>Approx country from IP (2-letter code, never raw IP)</li>
    <li>Browser / OS family (coarse)</li>
    <li>Anonymous interaction events like <code>lightbox_open</code>, <code>buy_open</code>, <code>buy_checkout</code>, <code>contact_start</code></li>
  </ul>

  <p>
    No cookies. No personal message contents. Auto-delete after {{ retention }} days.
  </p>

  <div class="badge">
    Legal basis: legitimate interest in understanding site usage and preventing abuse.
  </div>
</section>

</body>
</html>
"""

    return render_template_string(
        html,
        retention=RETENTION_DAYS,
        total_views_30d=total_views_30d,
        total_events_30d=total_events_30d,
        top_page=top_page,
        top_country=top_country,
        spark_svg=spark_svg,
        spark_last=spark_last,
        recent_paths=recent_paths,
        recent_referrers=recent_referrers,
        recent_countries=recent_countries,
        recent_agents=recent_agents,
        recent_events=recent_events,
    )


# -----------------------------------------------------------------------------
# health
# -----------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    # Dev mode, container uses gunicorn
    app.run(host="0.0.0.0", port=8000)

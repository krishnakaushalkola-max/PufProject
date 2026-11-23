"""
PUF device-authentication cloud  (Flask + SQLite)  -  ONE server, ONE port (5000).

  Dashboard : http://localhost:5000        (pick an ESP32, press "Send GET request")
  ESP32s    : http://<this laptop's IP>:5000

Protocol (matches the methodology slide)
  GET  /api/nonce?device_id=ID        -> {"status":"success","nonce":"<32 hex = 128 bit>","ttl_seconds":30}
  POST /api/auth  {device_id, nonce, response}
        response = HMAC-SHA256(PUF key, "<device_id>:<nonce>")  (hex)
        The server recomputes it, then BURNS the nonce (single use, 30 s lifetime).
        Success -> {"status":"success","token":"...","expires_in":900}
  GET  /api/data   (Authorization: Bearer <token>)              protected resource

Selecting which ESP32 sends the request
  The ESP32s sit behind the router, so the server cannot call them. Instead each ESP32 asks
  "anything for me?" every ~2 s:
  GET  /api/poll?device_id=ID         -> {"command":"none"}  or  {"command":"authenticate","job":N}
  POST /api/devices/<id>/trigger      (admin)  queue a job for exactly that ESP32; only it picks it up.

Telemetry (only after the nonce/HMAC handshake):
  POST /api/telemetry  (Authorization: Bearer <token>)  JSON object of numbers/short strings, stored for the
        device the token belongs to. No token (= no successful nonce challenge) -> 401, nothing is stored.
  GET  /puf                              the PUF dashboard (enrol, register, configure the ESP32)
  GET  /device/<id>                      the device's own page (HTML; it asks for the admin token)
  GET  /api/devices/<id>/telemetry       (admin) device info, last accepted handshake, recent telemetry

Admin (header X-Admin-Token): POST /api/register, GET /api/devices | /api/stats | /api/events |
  /api/handshakes | /api/jobs, POST /api/devices/<id>/unlock|trigger|block|unblock,
  DELETE /api/devices/<id>   (deletes the device AND every log row about it: nonces, tokens, jobs, events)
  Blocked device: no nonce, no authentication, no session, until it is unblocked.

Registration accepts only a fuzzy-extractor KDF output: 256-bit key (64 hex), key_check =
SHA-256("PUFFE-check" || key) and an info label  SRAM-PUF-FE-v4|BCH(256,k,t=t)  (v3 also accepted).
After registration the key never crosses the network again; the ESP32 only sends HMACs.

Config (environment variables, all optional):
  CLOUD_ADMIN_TOKEN  admin password. If unset, one is generated once and saved in admin_token.txt
  CLOUD_PORT         default 5000          CLOUD_DB   default cloud.db next to this file
HTTP is used for the LAN demo only. For anything real, put HTTPS in front of it.
"""
import hashlib, hmac, json, math, os, re, secrets, sqlite3, time
from flask import Flask, g, jsonify, request, send_file

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("CLOUD_DB", os.path.join(HERE, "cloud.db"))
PORT = int(os.environ.get("CLOUD_PORT", 5000))
NONCE_TTL = 30            # seconds a nonce is valid. Fixed by the project spec.
TOKEN_TTL = 900           # session token lifetime
MAX_FAILS, LOCK_SECS = 5, 300
ONLINE_SECS = 10          # an ESP32 counts as online if it polled within this many seconds
TELE_KEEP = 1000          # telemetry rows kept per device
PICKUP_SECS = 20          # a queued job is dropped if the ESP32 does not collect it in time

DEVID = re.compile(r"[A-Za-z0-9_.-]{1,64}")
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TELE_KEY = re.compile(r"[A-Za-z0-9_]{1,32}")
INFO = re.compile(r"SRAM-PUF-FE-v[34]\|BCH\(256,\d{1,3},t=\d{1,2}\)")   # v4 = current dashboard label


def load_admin_token():
    t = os.environ.get("CLOUD_ADMIN_TOKEN", "").strip()
    if t:
        return t
    path = os.path.join(HERE, "admin_token.txt")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read().strip()
    t = secrets.token_urlsafe(18)
    with open(path, "w", encoding="utf-8") as f:
        f.write(t)
    return t


ADMIN = load_admin_token()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(device_id TEXT PRIMARY KEY, key TEXT NOT NULL, created REAL,
  fails INT DEFAULT 0, locked_until REAL DEFAULT 0, last_auth REAL, key_fp TEXT, info TEXT,
  last_seen REAL, last_ip TEXT, blocked INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, device_id TEXT, expires REAL, used INT DEFAULT 0,
  issued REAL, ip TEXT, outcome TEXT, responded REAL, resp_ip TEXT, job_id INT);
CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, device_id TEXT, expires REAL);
CREATE TABLE IF NOT EXISTS events(ts REAL, device_id TEXT, event TEXT, ok INT, ip TEXT);
CREATE TABLE IF NOT EXISTS telemetry(id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, ts REAL, data TEXT);
CREATE INDEX IF NOT EXISTS telemetry_dev ON telemetry(device_id, id);
CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, created REAL, state TEXT,
  picked REAL, nonce TEXT, nonce_at REAL, detail TEXT, finished REAL);
"""
ADD_COLUMNS = {   # lets a cloud.db made by an older version keep working
    "devices": [("key_fp", "TEXT"), ("info", "TEXT"), ("last_seen", "REAL"), ("last_ip", "TEXT"),
                ("blocked", "INT DEFAULT 0")],
    "nonces": [("issued", "REAL"), ("ip", "TEXT"), ("outcome", "TEXT"), ("responded", "REAL"),
               ("resp_ip", "TEXT"), ("job_id", "INT")],
    "events": [("ip", "TEXT")],
}


def init_db():
    with sqlite3.connect(DB, timeout=10) as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        for table, cols in ADD_COLUMNS.items():
            have = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
            for name, typ in cols:
                if name not in have:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typ}")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB, isolation_level=None, timeout=10)   # autocommit
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def now():
    return time.time()        # float seconds: a 30 s nonce really lasts 30 s, not 30.99 s


def src_ip():
    return request.remote_addr or ""


def audit(did, event, ok):
    db().execute("INSERT INTO events(ts,device_id,event,ok,ip) VALUES(?,?,?,?,?)", (now(), did, event, int(ok), src_ip()))


def err(msg, code, **extra):
    return jsonify(status="error", error=msg, **extra), code


def admin_only():
    ok = hmac.compare_digest(request.headers.get("X-Admin-Token", "").encode(), ADMIN.encode())
    return None if ok else err("admin token required", 403)


@app.errorhandler(sqlite3.Error)
def on_db_error(e):
    app.logger.error("database error: %s", e)
    return err("database error", 500)


@app.errorhandler(404)
def on_404(_): return err("not found", 404)


@app.errorhandler(405)
def on_405(_): return err("method not allowed", 405)


@app.errorhandler(413)
def on_413(_): return err("request too large", 413)


@app.get("/")
def index(): return send_file(os.path.join(HERE, "dashboard.html"))


@app.get("/favicon.ico")
def favicon(): return "", 204


def device(did):
    return db().execute("SELECT * FROM devices WHERE device_id=?", (did,)).fetchone()


def locked(row): return row["locked_until"] and row["locked_until"] > now()


# ---------------------------------------------------------------- registration
@app.post("/api/register")
def register():
    if (e := admin_only()): return e
    d = request.get_json(silent=True)
    if not isinstance(d, dict): return err("JSON body required", 400)
    did, key = str(d.get("device_id", "")), str(d.get("key", "")).lower()
    chk, info = str(d.get("key_check", "")).lower(), str(d.get("info", ""))
    if not DEVID.fullmatch(did): return err("bad device_id (letters, digits, . _ -, max 64)", 400)
    if not HEX64.fullmatch(key): return err("key must be the 256-bit KDF output as 64 hex chars", 400)
    if not HEX64.fullmatch(chk) or hashlib.sha256(b"PUFFE-check" + bytes.fromhex(key)).hexdigest() != chk:
        return err("key_check does not match this key: not a fuzzy-extractor KDF output", 400)
    if not INFO.fullmatch(info): return err("info must look like SRAM-PUF-FE-v4|BCH(256,k,t=t)", 400)
    if device(did) and request.args.get("replace") != "1":
        return err("device already registered (tick 'replace' to re-enroll)", 409)
    db().execute("INSERT OR REPLACE INTO devices(device_id,key,created,key_fp,info) VALUES(?,?,?,?,?)",
                 (did, key, now(), chk[:12], info))
    audit(did, "register", True)
    return jsonify(status="success", device_id=did, key_fp=chk[:12]), 201


# ---------------------------------------------------------------- jobs (admin picks an ESP32)
def finish_job(jid, state, detail):
    if jid:
        db().execute("UPDATE jobs SET state=?, detail=?, finished=? WHERE id=?", (state, detail, now(), jid))


def sweep_jobs():
    t, d = now(), db()
    q = "UPDATE jobs SET state='timeout', finished=?, detail=? WHERE state=? AND {}<?"
    d.execute(q.format("created"), (t, "the ESP32 did not poll within %d s (offline, or sketch not running)" % PICKUP_SECS, "queued", t - PICKUP_SECS))
    d.execute(q.format("picked"), (t, "the ESP32 took the command but never asked for a nonce", "picked", t - PICKUP_SECS))
    d.execute(q.format("nonce_at"), (t, "nonce issued but no response arrived within %d s" % NONCE_TTL, "nonce_issued", t - NONCE_TTL - 2))


@app.post("/api/devices/<did>/trigger")
def trigger(did):
    if (e := admin_only()): return e
    row = device(did)
    if not row: return err("unknown device", 404)
    if row["blocked"]: return err("device is blocked: unblock it first", 409)
    sweep_jobs()
    t = now()
    db().execute("UPDATE jobs SET state='superseded', finished=? WHERE device_id=? AND state='queued'", (t, did))
    cur = db().execute("INSERT INTO jobs(device_id,created,state) VALUES(?,?,'queued')", (did, t))
    audit(did, "trigger", True)
    online = bool(row["last_seen"] and row["last_seen"] > t - ONLINE_SECS)
    return jsonify(status="success", job=cur.lastrowid, online=online)


@app.get("/api/poll")
def poll():
    """Called by every ESP32 about every 2 s. Doubles as a heartbeat (online status + IP)."""
    did = request.args.get("device_id", "")
    if not device(did): return err("unknown device", 404)
    sweep_jobs()
    t = now()
    db().execute("UPDATE devices SET last_seen=?, last_ip=? WHERE device_id=?", (t, src_ip(), did))
    if device(did)["blocked"]: return jsonify(status="success", command="none", blocked=True)   # still shown online, never gets work
    job = db().execute("SELECT id FROM jobs WHERE device_id=? AND state='queued' ORDER BY id LIMIT 1", (did,)).fetchone()
    if job and db().execute("UPDATE jobs SET state='picked', picked=? WHERE id=? AND state='queued'", (t, job["id"])).rowcount == 1:
        return jsonify(status="success", command="authenticate", job=job["id"])
    return jsonify(status="success", command="none")


# ---------------------------------------------------------------- challenge / response
@app.get("/api/nonce")
def nonce():
    did = request.args.get("device_id", "")
    row = device(did)
    if not row: return err("unknown device", 404)
    if row["blocked"]:
        audit(did, "nonce:blocked", False)
        return err("device blocked", 403, reason="blocked")
    if locked(row): return err("device temporarily locked", 429)
    sweep_jobs()
    t = now()
    db().execute("DELETE FROM nonces WHERE expires<?", (t - 3600,))        # keep an hour of handshake history
    db().execute("DELETE FROM tokens WHERE expires<?", (t,))
    n = secrets.token_hex(16)                                              # 128-bit, from the OS CSPRNG
    job = db().execute("SELECT id FROM jobs WHERE device_id=? AND state='picked' ORDER BY id DESC LIMIT 1", (did,)).fetchone()
    jid = job["id"] if job else None
    db().execute("INSERT INTO nonces(nonce,device_id,expires,issued,ip,job_id) VALUES(?,?,?,?,?,?)",
                 (n, did, t + NONCE_TTL, t, src_ip(), jid))
    if jid:
        db().execute("UPDATE jobs SET state='nonce_issued', nonce=?, nonce_at=? WHERE id=?", (n, t, jid))
    audit(did, "nonce", True)
    return jsonify(status="success", nonce=n, ttl_seconds=NONCE_TTL)


def reject(did, why, jid=None, count=False):
    if count:
        db().execute("UPDATE devices SET fails=fails+1 WHERE device_id=?", (did,))
        db().execute("UPDATE devices SET locked_until=? WHERE device_id=? AND fails>=?", (now() + LOCK_SECS, did, MAX_FAILS))
    audit(did, "auth:" + why, False)
    finish_job(jid, "rejected", why)
    return err("authentication failed", 401, reason=why)


@app.post("/api/auth")
def auth():
    d = request.get_json(silent=True)
    if not isinstance(d, dict): return err("JSON body required: {device_id, nonce, response}", 400)
    did, n, resp = str(d.get("device_id", "")), str(d.get("nonce", "")).lower(), str(d.get("response", "")).lower()
    if not (HEX32.fullmatch(n) and HEX64.fullmatch(resp)): return err("malformed nonce or response", 400)
    row = device(did)
    if not row: return err("authentication failed", 401, reason="unknown-device")
    if row["blocked"]:
        audit(did, "auth:blocked", False)
        return err("device blocked", 403, reason="blocked")
    if locked(row): return err("device temporarily locked", 429)
    t = now()
    # Burn the nonce atomically: only one request can ever flip used 0 -> 1, and only before it expires.
    burned = db().execute("UPDATE nonces SET used=1 WHERE nonce=? AND device_id=? AND used=0 AND expires>?", (n, did, t))
    if burned.rowcount != 1:
        r = db().execute("SELECT used, job_id FROM nonces WHERE nonce=? AND device_id=?", (n, did)).fetchone()
        why = "unknown-nonce" if not r else ("replayed" if r["used"] else "expired")
        if r and not r["used"]:
            db().execute("UPDATE nonces SET used=1, outcome='expired', responded=?, resp_ip=? WHERE nonce=?", (t, src_ip(), n))
        return reject(did, why, r["job_id"] if r else None)
    jid = db().execute("SELECT job_id FROM nonces WHERE nonce=?", (n,)).fetchone()["job_id"]
    expected = hmac.new(bytes.fromhex(row["key"]), f"{did}:{n}".encode(), hashlib.sha256).hexdigest()
    good = hmac.compare_digest(expected, resp)
    db().execute("UPDATE nonces SET outcome=?, responded=?, resp_ip=? WHERE nonce=?",
                 ("accepted" if good else "bad-response", t, src_ip(), n))
    if not good:
        return reject(did, "bad-response", jid, count=True)
    token = secrets.token_urlsafe(32)
    db().execute("INSERT INTO tokens VALUES(?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), did, t + TOKEN_TTL))
    db().execute("UPDATE devices SET fails=0, locked_until=0, last_auth=? WHERE device_id=?", (t, did))
    audit(did, "auth", True)
    finish_job(jid, "accepted", "HMAC verified, nonce burned")
    return jsonify(status="success", token=token, expires_in=TOKEN_TTL)


@app.get("/api/data")
def data():
    tok = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    row = db().execute("SELECT * FROM tokens WHERE hash=? AND expires>=?", (hashlib.sha256(tok.encode()).hexdigest(), now())).fetchone()
    dev = device(row["device_id"]) if row else None
    if not dev or dev["blocked"]: return err("invalid or expired token", 401)
    return jsonify(status="success", device_id=row["device_id"], message="authenticated with a PUF-derived key",
                   server_time=now())


# ---------------------------------------------------------------- telemetry
def token_device():
    """The device behind a valid, unexpired session token (obtained only through the nonce/HMAC handshake)."""
    tok = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    row = db().execute("SELECT * FROM tokens WHERE hash=? AND expires>=?", (hashlib.sha256(tok.encode()).hexdigest(), now())).fetchone()
    dev = device(row["device_id"]) if row else None
    return dev if dev and not dev["blocked"] else None


@app.post("/api/telemetry")
def post_telemetry():
    dev = token_device()
    if not dev: return err("invalid or expired token: authenticate with a nonce first", 401)
    d = request.get_json(silent=True)
    if not isinstance(d, dict) or not 1 <= len(d) <= 20: return err("JSON object with 1-20 fields required", 400)
    clean = {}
    for k, v in d.items():
        if not TELE_KEY.fullmatch(str(k)): return err("bad field name (letters, digits, _; max 32)", 400)
        if isinstance(v, bool): v = int(v)
        if isinstance(v, (int, float)):
            if not math.isfinite(v): return err("numbers must be finite", 400)
        elif isinstance(v, str):
            if len(v) > 64 or any(ord(ch) < 32 for ch in v): return err("text values: max 64 printable characters", 400)
        else: return err("values must be numbers or short text", 400)
        clean[str(k)] = v
    did = dev["device_id"]                     # taken from the token, never from the body
    db().execute("INSERT INTO telemetry(device_id,ts,data) VALUES(?,?,?)", (did, now(), json.dumps(clean, separators=(",", ":"))))
    db().execute("DELETE FROM telemetry WHERE device_id=? AND id NOT IN "
                 "(SELECT id FROM telemetry WHERE device_id=? ORDER BY id DESC LIMIT ?)", (did, did, TELE_KEEP))
    return jsonify(status="success")


@app.get("/device/<did>")
def device_page(did):
    if not DEVID.fullmatch(did): return err("bad device id", 400)
    return send_file(os.path.join(HERE, "device.html"))      # the page itself holds no data; it fetches with the admin token


@app.get("/puf")
def puf_page():
    """The PUF dashboard, served by the cloud so it can register devices without CORS (open it via http://localhost:5000/puf)."""
    return send_file(os.path.join(HERE, "puf_dashboard.html"))


@app.get("/api/devices/<did>/telemetry")
def device_telemetry(did):
    if (e := admin_only()): return e
    row = device(did)
    if not row: return err("unknown device", 404)
    t = now()
    info = {k: row[k] for k in ("device_id", "created", "fails", "locked_until", "last_auth", "key_fp", "info", "last_seen", "last_ip")}
    info["blocked"] = bool(row["blocked"])
    info["online"] = bool(row["last_seen"] and row["last_seen"] > t - ONLINE_SECS)
    hs = db().execute("SELECT nonce,issued,responded,ip FROM nonces WHERE device_id=? AND outcome='accepted' "
                      "ORDER BY responded DESC LIMIT 1", (did,)).fetchone()
    sessions = db().execute("SELECT COUNT(*) FROM tokens WHERE device_id=? AND expires>=?", (did, t)).fetchone()[0]
    rows = db().execute("SELECT ts,data FROM telemetry WHERE device_id=? ORDER BY id DESC LIMIT ?", (did, limit(120, 1000))).fetchall()
    series = [{"ts": r["ts"], "data": json.loads(r["data"])} for r in reversed(rows)]
    return jsonify(device=info, last_handshake=dict(hs) if hs else None, sessions=sessions, telemetry=series, server_time=t)


# ---------------------------------------------------------------- dashboard data (admin)
@app.get("/api/devices")
def devices():
    if (e := admin_only()): return e
    t = now()
    rows = db().execute("SELECT device_id,created,fails,locked_until,last_auth,key_fp,info,last_seen,last_ip,blocked "
                        "FROM devices ORDER BY created DESC").fetchall()
    out = []
    for r in rows:
        o = dict(r)
        o["online"] = bool(r["last_seen"] and r["last_seen"] > t - ONLINE_SECS)
        o["blocked"] = bool(r["blocked"])
        out.append(o)
    return jsonify(out)


@app.post("/api/devices/<did>/unlock")
def unlock(did):
    if (e := admin_only()): return e
    db().execute("UPDATE devices SET fails=0, locked_until=0 WHERE device_id=?", (did,))
    audit(did, "unlock", True)
    return jsonify(status="success")


@app.post("/api/devices/<did>/block")
def block(did):
    """Blocked = no nonce, no authentication, no session, until unblocked. Key and history are kept."""
    if (e := admin_only()): return e
    if not device(did): return err("unknown device", 404)
    t = now()
    db().execute("UPDATE devices SET blocked=1 WHERE device_id=?", (did,))
    db().execute("DELETE FROM tokens WHERE device_id=?", (did,))                       # end its sessions
    db().execute("UPDATE nonces SET used=1 WHERE device_id=? AND used=0", (did,))      # kill open challenges
    db().execute("UPDATE jobs SET state='rejected', detail='device blocked', finished=? WHERE device_id=? "
                 "AND state IN ('queued','picked','nonce_issued')", (t, did))
    audit(did, "block", True)
    return jsonify(status="success", blocked=True)


@app.post("/api/devices/<did>/unblock")
def unblock(did):
    if (e := admin_only()): return e
    if not device(did): return err("unknown device", 404)
    db().execute("UPDATE devices SET blocked=0 WHERE device_id=?", (did,))
    audit(did, "unblock", True)
    return jsonify(status="success", blocked=False)


@app.delete("/api/devices/<did>")
def revoke(did):
    """Delete the device and forget everything about it: key, nonces/handshakes, sessions, jobs and ALL events.
    Nothing is written afterwards, so no trace of the device remains in the database."""
    if (e := admin_only()): return e
    for table in ("devices", "nonces", "tokens", "jobs", "events", "telemetry"):
        db().execute(f"DELETE FROM {table} WHERE device_id=?", (did,))
    return jsonify(status="success")


@app.get("/api/stats")
def stats():
    if (e := admin_only()): return e
    t = now()
    q = lambda s, *a: db().execute(s, a).fetchone()[0]
    return jsonify(devices=q("SELECT COUNT(*) FROM devices"),
                   online=q("SELECT COUNT(*) FROM devices WHERE last_seen>?", t - ONLINE_SECS),
                   locked=q("SELECT COUNT(*) FROM devices WHERE locked_until>?", t),
                   blocked=q("SELECT COUNT(*) FROM devices WHERE blocked=1"),
                   sessions=q("SELECT COUNT(*) FROM tokens WHERE expires>=?", t),
                   ok24=q("SELECT COUNT(*) FROM events WHERE event='auth' AND ok=1 AND ts>?", t - 86400),
                   fail24=q("SELECT COUNT(*) FROM events WHERE event LIKE 'auth:%' AND ok=0 AND ts>?", t - 86400),
                   server_time=t, nonce_ttl=NONCE_TTL)


def limit(default, top):
    try: return min(max(int(request.args.get("limit", default)), 1), top)
    except ValueError: return default


@app.get("/api/jobs")
def jobs():
    if (e := admin_only()): return e
    sweep_jobs()
    rows = db().execute("SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit(20, 200),)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/handshakes")
def handshakes():
    if (e := admin_only()): return e
    rows = db().execute("SELECT device_id,nonce,issued,expires,ip,outcome,responded,resp_ip FROM nonces "
                        "WHERE issued IS NOT NULL ORDER BY issued DESC, rowid DESC LIMIT ?", (limit(50, 500),)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/events")
def events():
    if (e := admin_only()): return e
    rows = db().execute("SELECT * FROM events ORDER BY ts DESC, rowid DESC LIMIT ?", (limit(100, 1000),)).fetchall()
    return jsonify([dict(r) for r in rows])


init_db()
if __name__ == "__main__":
    print(f"\nDashboard : http://localhost:{PORT}")
    print(f"ESP32s use: http://<this laptop's Wi-Fi IP>:{PORT}     (find it with: ipconfig)")
    print(f"Admin token (type it into the dashboard): {ADMIN}\n")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
"""
MIHU - case management for lawyers.

Backend: Flask + SQLite. Serves the HTML/CSS/JS frontend from ./static and a JSON API under /api.

Run:
    pip install -r requirements.txt
    python app.py create-admin you@example.com "a-strong-password"
    python app.py            # http://127.0.0.1:5000
"""
import os
import re
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, g, jsonify, redirect, request, send_from_directory,
                   session)
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
UPLOADS = DATA / "uploads"
DB_PATH = Path(os.environ.get("MIHU_DB", DATA / "mihu.db"))
DATA.mkdir(exist_ok=True)
UPLOADS.mkdir(exist_ok=True)

# Hearing times are compared against "now" in this timezone (default: India).
try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo(os.environ.get("MIHU_TZ", "Asia/Kolkata"))
except Exception:  # tzdata missing
    TZ = timezone(timedelta(hours=5, minutes=30))

STATUSES = ("Open", "On Hold", "Closed")
ALLOWED_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"}
MAX_UPLOAD_MB = 12
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------------------------------- app setup
def load_secret_key():
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    key_file = DATA / "secret_key"
    if not key_file.exists():
        key_file.write_text(uuid.uuid4().hex + uuid.uuid4().hex)
        try:
            key_file.chmod(0o600)
        except OSError:
            pass
    return key_file.read_text().strip()


app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config.update(
    SECRET_KEY=load_secret_key(),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("MIHU_SECURE_COOKIES") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    JSON_SORT_KEYS=False,
)


# --------------------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'lawyer',
    phone         TEXT DEFAULT '',
    firm          TEXT DEFAULT '',
    bar_id        TEXT DEFAULT '',
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cases (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    case_number    TEXT DEFAULT '',
    title          TEXT NOT NULL,
    court          TEXT DEFAULT '',
    case_type      TEXT DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'Open',
    client_name    TEXT NOT NULL,
    client_phone   TEXT DEFAULT '',
    client_email   TEXT DEFAULT '',
    client_address TEXT DEFAULT '',
    opposing_party TEXT DEFAULT '',
    notes          TEXT DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hearings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id      INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    hearing_date TEXT NOT NULL,           -- 'YYYY-MM-DDTHH:MM' (local time)
    purpose      TEXT DEFAULT '',
    outcome      TEXT DEFAULT '',
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    filename    TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    size        INTEGER NOT NULL DEFAULT 0,
    uploaded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_user ON cases(user_id);
CREATE INDEX IF NOT EXISTS idx_hearings_case ON hearings(case_id, hearing_date);
CREATE INDEX IF NOT EXISTS idx_files_case ON case_files(case_id);
"""


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = connect()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------- helpers
def now_local():
    return datetime.now(TZ).replace(tzinfo=None, second=0, microsecond=0)


def stamp():
    return now_local().strftime("%Y-%m-%d %H:%M:%S")


def clean(value, maxlen=200):
    return (value or "").strip()[:maxlen] if isinstance(value, str) else ""


def parse_hearing(value):
    """Accept 'YYYY-MM-DDTHH:MM' (or with seconds / space) and normalise it."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace(" ", "T"))
    except ValueError:
        return None
    return dt.replace(tzinfo=None, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M")


def err(message, code=400):
    return jsonify(error=message), code


def public_user(u):
    return {k: u[k] for k in ("id", "name", "email", "role", "phone", "firm", "bar_id")}


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        uid = session.get("uid")
        if not uid:
            return err("Please log in.", 401)
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if not user or not user["active"]:
            session.clear()
            return err("This account is not available.", 401)
        g.user = user
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @login_required
    @wraps(f)
    def wrapper(*args, **kwargs):
        if g.user["role"] != "admin":
            return err("Admin access only.", 403)
        return f(*args, **kwargs)
    return wrapper


_attempts = {}


def throttled(key, limit=8, window=600):
    now = time.time()
    recent = [t for t in _attempts.get(key, []) if now - t < window]
    _attempts[key] = recent
    return len(recent) >= limit


def record_failure(key):
    _attempts.setdefault(key, []).append(time.time())


# --------------------------------------------------------------------------- request hooks
@app.before_request
def csrf_guard():
    # Cross-site pages cannot add this custom header without a CORS preflight, which we never allow.
    if request.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
        if request.headers.get("X-Requested-With") != "MIHU":
            return err("Bad request.", 400)


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; connect-src 'self' https://api.web3forms.com; "
        "form-action 'self' https://api.web3forms.com; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'"
    )
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(RequestEntityTooLarge)
def too_large(_e):
    return err(f"File is too large (max {MAX_UPLOAD_MB} MB).", 413)


@app.errorhandler(HTTPException)
def http_error(e):
    if request.path.startswith("/api/"):
        return err(e.description if e.code != 404 else "Not found.", e.code)
    return e


# --------------------------------------------------------------------------- pages
def page(name):
    return send_from_directory(app.static_folder, name)


@app.get("/")
def index():
    return page("index.html")


@app.get("/login")
def login_page():
    return page("login.html")


@app.get("/app")
def app_page():
    if not session.get("uid"):
        return redirect("/login")
    return page("app.html")


@app.get("/admin")
def admin_page():
    uid = session.get("uid")
    user = get_db().execute("SELECT role, active FROM users WHERE id = ?", (uid,)).fetchone() if uid else None
    if not user or not user["active"] or user["role"] != "admin":
        return redirect("/login")
    return page("admin.html")


# --------------------------------------------------------------------------- auth API
@app.post("/api/signup")
def signup():
    d = request.get_json(silent=True) or {}
    name = clean(d.get("name"), 80)
    email = clean(d.get("email"), 120).lower()
    password = d.get("password") if isinstance(d.get("password"), str) else ""
    if not name:
        return err("Please enter your name.")
    if not EMAIL_RE.match(email):
        return err("Please enter a valid email address.")
    if len(password) < 8:
        return err("Password must be at least 8 characters.")
    if len(password) > 128:
        return err("Password is too long.")
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        return err("An account with this email already exists.", 409)
    cur = db.execute(
        "INSERT INTO users (name, email, password_hash, role, phone, firm, bar_id, created_at) "
        "VALUES (?, ?, ?, 'lawyer', ?, ?, ?, ?)",
        (name, email, generate_password_hash(password), clean(d.get("phone"), 30),
         clean(d.get("firm"), 120), clean(d.get("bar_id"), 60), stamp()),
    )
    db.commit()
    session.clear()
    session.permanent = True
    session["uid"] = cur.lastrowid
    user = db.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify(user=public_user(user)), 201


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    email = clean(d.get("email"), 120).lower()
    password = d.get("password") if isinstance(d.get("password"), str) else ""
    key = f"{request.remote_addr}|{email}"
    if throttled(key):
        return err("Too many attempts. Please wait a few minutes and try again.", 429)
    user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        record_failure(key)
        return err("Incorrect email or password.", 401)
    if not user["active"]:
        return err("This account has been disabled. Please contact the administrator.", 403)
    _attempts.pop(key, None)
    session.clear()
    session.permanent = True
    session["uid"] = user["id"]
    return jsonify(user=public_user(user))


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
@login_required
def me():
    return jsonify(user=public_user(g.user))


@app.put("/api/me")
@login_required
def update_me():
    d = request.get_json(silent=True) or {}
    name = clean(d.get("name"), 80) or g.user["name"]
    db = get_db()
    db.execute("UPDATE users SET name=?, phone=?, firm=?, bar_id=? WHERE id=?",
               (name, clean(d.get("phone"), 30), clean(d.get("firm"), 120),
                clean(d.get("bar_id"), 60), g.user["id"]))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    return jsonify(user=public_user(user))


@app.post("/api/me/password")
@login_required
def change_password():
    d = request.get_json(silent=True) or {}
    current, new = d.get("current"), d.get("new")
    if not isinstance(current, str) or not check_password_hash(g.user["password_hash"], current):
        return err("Current password is incorrect.", 403)
    if not isinstance(new, str) or not 8 <= len(new) <= 128:
        return err("New password must be 8 to 128 characters.")
    db = get_db()
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), g.user["id"]))
    db.commit()
    return jsonify(ok=True)


# --------------------------------------------------------------------------- cases API
CASE_SELECT = """
SELECT c.*,
  (SELECT MIN(hearing_date) FROM hearings h WHERE h.case_id = c.id AND h.hearing_date >= :now) AS next_hearing,
  (SELECT MAX(hearing_date) FROM hearings h WHERE h.case_id = c.id AND h.hearing_date <  :now) AS previous_hearing,
  (SELECT COUNT(*) FROM hearings h WHERE h.case_id = c.id) AS hearing_count,
  (SELECT COUNT(*) FROM case_files f WHERE f.case_id = c.id) AS file_count
FROM cases c
"""

CASE_FIELDS = (("case_number", 60), ("title", 160), ("court", 120), ("case_type", 60),
               ("client_name", 120), ("client_phone", 30), ("client_email", 120),
               ("client_address", 300), ("opposing_party", 120), ("notes", 4000))


def case_dict(row):
    return {k: row[k] for k in row.keys() if k != "user_id"}


def own_case(case_id):
    row = get_db().execute(CASE_SELECT + " WHERE c.id = :id AND c.user_id = :uid",
                           {"id": case_id, "uid": g.user["id"], "now": now_str()}).fetchone()
    if not row:
        abort(404)
    return row


def now_str():
    return now_local().strftime("%Y-%m-%dT%H:%M")


def read_case_payload(d, partial=False):
    values = {f: clean(d.get(f), n) for f, n in CASE_FIELDS}
    status = clean(d.get("status"), 20) or "Open"
    if status not in STATUSES:
        return None, "Status must be one of: " + ", ".join(STATUSES) + "."
    values["status"] = status
    if not values["title"]:
        return None, "Please enter a case title."
    if not values["client_name"]:
        return None, "Please enter the client's name."
    if values["client_email"] and not EMAIL_RE.match(values["client_email"]):
        return None, "The client's email address does not look valid."
    return values, None


@app.get("/api/cases")
@login_required
def list_cases():
    q = clean(request.args.get("q"), 100)
    status = clean(request.args.get("status"), 20)
    sql = CASE_SELECT + " WHERE c.user_id = :uid"
    params = {"uid": g.user["id"], "now": now_str()}
    if status in STATUSES:
        sql += " AND c.status = :status"
        params["status"] = status
    if q:
        sql += (" AND (c.title LIKE :q ESCAPE '\\' OR c.case_number LIKE :q ESCAPE '\\' "
                "OR c.client_name LIKE :q ESCAPE '\\' OR c.court LIKE :q ESCAPE '\\')")
        params["q"] = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    # nearest upcoming hearing first, cases without one last
    sql += " ORDER BY next_hearing IS NULL, next_hearing ASC, c.updated_at DESC"
    rows = get_db().execute(sql, params).fetchall()
    return jsonify(cases=[case_dict(r) for r in rows])


@app.post("/api/cases")
@login_required
def create_case():
    d = request.get_json(silent=True) or {}
    values, problem = read_case_payload(d)
    if problem:
        return err(problem)
    first_hearing = None
    if d.get("next_hearing"):
        first_hearing = parse_hearing(d.get("next_hearing"))
        if not first_hearing:
            return err("The next hearing date/time is not valid.")
    db = get_db()
    t = stamp()
    cols = list(values) + ["user_id", "created_at", "updated_at"]
    cur = db.execute(
        f"INSERT INTO cases ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
        list(values.values()) + [g.user["id"], t, t],
    )
    case_id = cur.lastrowid
    if first_hearing:
        db.execute("INSERT INTO hearings (case_id, hearing_date, purpose, created_at) VALUES (?, ?, ?, ?)",
                   (case_id, first_hearing, clean(d.get("hearing_purpose"), 200), t))
    db.commit()
    return jsonify(case=case_dict(own_case(case_id))), 201


@app.get("/api/cases/<int:case_id>")
@login_required
def get_case(case_id):
    case = own_case(case_id)
    db = get_db()
    hearings = db.execute("SELECT * FROM hearings WHERE case_id = ? ORDER BY hearing_date ASC", (case_id,)).fetchall()
    files = db.execute("SELECT id, filename, size, uploaded_at FROM case_files WHERE case_id = ? ORDER BY id DESC",
                       (case_id,)).fetchall()
    return jsonify(case=case_dict(case), hearings=[dict(h) for h in hearings], files=[dict(f) for f in files])


@app.put("/api/cases/<int:case_id>")
@login_required
def update_case(case_id):
    own_case(case_id)
    values, problem = read_case_payload(request.get_json(silent=True) or {})
    if problem:
        return err(problem)
    db = get_db()
    sets = ", ".join(f"{k} = ?" for k in values)
    db.execute(f"UPDATE cases SET {sets}, updated_at = ? WHERE id = ? AND user_id = ?",
               list(values.values()) + [stamp(), case_id, g.user["id"]])
    db.commit()
    return jsonify(case=case_dict(own_case(case_id)))


def remove_stored_files(rows):
    for r in rows:
        try:
            (UPLOADS / r["stored_name"]).unlink()
        except OSError:
            pass


@app.delete("/api/cases/<int:case_id>")
@login_required
def delete_case(case_id):
    own_case(case_id)
    db = get_db()
    files = db.execute("SELECT stored_name FROM case_files WHERE case_id = ?", (case_id,)).fetchall()
    db.execute("DELETE FROM cases WHERE id = ? AND user_id = ?", (case_id, g.user["id"]))
    db.commit()
    remove_stored_files(files)
    return jsonify(ok=True)


# --------------------------------------------------------------------------- hearings API
def own_hearing(hearing_id):
    row = get_db().execute(
        "SELECT h.* FROM hearings h JOIN cases c ON c.id = h.case_id WHERE h.id = ? AND c.user_id = ?",
        (hearing_id, g.user["id"])).fetchone()
    if not row:
        abort(404)
    return row


@app.post("/api/cases/<int:case_id>/hearings")
@login_required
def add_hearing(case_id):
    own_case(case_id)
    d = request.get_json(silent=True) or {}
    when = parse_hearing(d.get("hearing_date"))
    if not when:
        return err("Please choose a valid hearing date and time.")
    db = get_db()
    cur = db.execute("INSERT INTO hearings (case_id, hearing_date, purpose, outcome, created_at) VALUES (?,?,?,?,?)",
                     (case_id, when, clean(d.get("purpose"), 200), clean(d.get("outcome"), 2000), stamp()))
    db.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (stamp(), case_id))
    db.commit()
    return jsonify(hearing=dict(db.execute("SELECT * FROM hearings WHERE id = ?", (cur.lastrowid,)).fetchone())), 201


@app.put("/api/hearings/<int:hearing_id>")
@login_required
def update_hearing(hearing_id):
    h = own_hearing(hearing_id)
    d = request.get_json(silent=True) or {}
    when = h["hearing_date"]
    if "hearing_date" in d:
        when = parse_hearing(d.get("hearing_date"))
        if not when:
            return err("Please choose a valid hearing date and time.")
    purpose = clean(d.get("purpose"), 200) if "purpose" in d else h["purpose"]
    outcome = clean(d.get("outcome"), 2000) if "outcome" in d else h["outcome"]
    db = get_db()
    db.execute("UPDATE hearings SET hearing_date=?, purpose=?, outcome=? WHERE id=?",
               (when, purpose, outcome, hearing_id))
    db.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (stamp(), h["case_id"]))
    db.commit()
    return jsonify(hearing=dict(db.execute("SELECT * FROM hearings WHERE id = ?", (hearing_id,)).fetchone()))


@app.delete("/api/hearings/<int:hearing_id>")
@login_required
def delete_hearing(hearing_id):
    h = own_hearing(hearing_id)
    db = get_db()
    db.execute("DELETE FROM hearings WHERE id = ?", (hearing_id,))
    db.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (stamp(), h["case_id"]))
    db.commit()
    return jsonify(ok=True)


# --------------------------------------------------------------------------- case files API
def display_name(raw):
    name = (raw or "").replace("\\", "/").split("/")[-1].strip()
    return name[:150] or "file"


@app.post("/api/cases/<int:case_id>/files")
@login_required
def upload_file(case_id):
    own_case(case_id)
    f = request.files.get("file")
    if not f or not f.filename:
        return err("Please choose a file to upload.")
    name = display_name(f.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXT:
        return err("File type not allowed. Allowed: " + ", ".join(sorted(ALLOWED_EXT)) + ".")
    stored = f"{uuid.uuid4().hex}.{ext}"
    path = UPLOADS / stored
    f.save(path)
    db = get_db()
    cur = db.execute("INSERT INTO case_files (case_id, filename, stored_name, size, uploaded_at) VALUES (?,?,?,?,?)",
                     (case_id, name, stored, path.stat().st_size, stamp()))
    db.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (stamp(), case_id))
    db.commit()
    row = db.execute("SELECT id, filename, size, uploaded_at FROM case_files WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify(file=dict(row)), 201


def file_for_user(file_id):
    db = get_db()
    row = db.execute(
        "SELECT f.*, c.user_id FROM case_files f JOIN cases c ON c.id = f.case_id WHERE f.id = ?",
        (file_id,)).fetchone()
    if not row or (row["user_id"] != g.user["id"] and g.user["role"] != "admin"):
        abort(404)
    return row


@app.get("/api/files/<int:file_id>")
@login_required
def download_file(file_id):
    row = file_for_user(file_id)
    return send_from_directory(UPLOADS, row["stored_name"], as_attachment=True, download_name=row["filename"])


@app.delete("/api/files/<int:file_id>")
@login_required
def delete_file(file_id):
    row = file_for_user(file_id)
    if row["user_id"] != g.user["id"]:
        abort(404)
    db = get_db()
    db.execute("DELETE FROM case_files WHERE id = ?", (file_id,))
    db.commit()
    remove_stored_files([row])
    return jsonify(ok=True)


# --------------------------------------------------------------------------- dashboard API
@app.get("/api/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = g.user["id"]
    now = now_str()
    today = now_local().strftime("%Y-%m-%d")
    tomorrow = (now_local() + timedelta(days=1)).strftime("%Y-%m-%d")
    counts = {s: 0 for s in STATUSES}
    for r in db.execute("SELECT status, COUNT(*) n FROM cases WHERE user_id = ? GROUP BY status", (uid,)):
        counts[r["status"]] = r["n"]
    base = ("SELECT h.*, c.title, c.case_number, c.client_name, c.court, c.status "
            "FROM hearings h JOIN cases c ON c.id = h.case_id WHERE c.user_id = ? ")
    todays = db.execute(base + "AND h.hearing_date >= ? AND h.hearing_date < ? ORDER BY h.hearing_date",
                        (uid, today, tomorrow)).fetchall()
    upcoming = db.execute(base + "AND h.hearing_date >= ? AND c.status != 'Closed' ORDER BY h.hearing_date LIMIT 10",
                          (uid, now)).fetchall()
    # Automation: hearings that have passed but still have no outcome written down.
    needs_update = db.execute(
        base + "AND h.hearing_date < ? AND COALESCE(h.outcome, '') = '' AND c.status != 'Closed' "
               "ORDER BY h.hearing_date DESC LIMIT 10", (uid, now)).fetchall()
    no_next = db.execute(
        "SELECT c.id, c.title, c.case_number, c.client_name FROM cases c WHERE c.user_id = ? AND c.status = 'Open' "
        "AND NOT EXISTS (SELECT 1 FROM hearings h WHERE h.case_id = c.id AND h.hearing_date >= ?) "
        "ORDER BY c.updated_at DESC LIMIT 10", (uid, now)).fetchall()
    return jsonify(
        counts=counts, total=sum(counts.values()), now=now,
        today=[dict(r) for r in todays], upcoming=[dict(r) for r in upcoming],
        needs_update=[dict(r) for r in needs_update], no_next_hearing=[dict(r) for r in no_next],
    )


# --------------------------------------------------------------------------- admin API
@app.get("/api/admin/stats")
@admin_required
def admin_stats():
    db = get_db()
    one = lambda sql, *a: db.execute(sql, a).fetchone()[0]
    return jsonify(
        lawyers=one("SELECT COUNT(*) FROM users WHERE role = 'lawyer'"),
        admins=one("SELECT COUNT(*) FROM users WHERE role = 'admin'"),
        disabled=one("SELECT COUNT(*) FROM users WHERE active = 0"),
        cases=one("SELECT COUNT(*) FROM cases"),
        open_cases=one("SELECT COUNT(*) FROM cases WHERE status = 'Open'"),
        upcoming_hearings=one("SELECT COUNT(*) FROM hearings WHERE hearing_date >= ?", now_str()),
        files=one("SELECT COUNT(*) FROM case_files"),
    )


@app.get("/api/admin/users")
@admin_required
def admin_users():
    rows = get_db().execute(
        "SELECT u.id, u.name, u.email, u.role, u.phone, u.firm, u.bar_id, u.active, u.created_at, "
        "(SELECT COUNT(*) FROM cases c WHERE c.user_id = u.id) AS case_count "
        "FROM users u ORDER BY u.created_at DESC").fetchall()
    return jsonify(users=[dict(r) for r in rows])


@app.patch("/api/admin/users/<int:user_id>")
@admin_required
def admin_update_user(user_id):
    d = request.get_json(silent=True) or {}
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        abort(404)
    if user_id == g.user["id"] and (d.get("active") is False or d.get("role") not in (None, "admin")):
        return err("You cannot disable or demote your own account.")
    active = target["active"]
    role = target["role"]
    if "active" in d:
        active = 1 if d["active"] else 0
    if "role" in d:
        if d["role"] not in ("lawyer", "admin"):
            return err("Role must be 'lawyer' or 'admin'.")
        role = d["role"]
    db.execute("UPDATE users SET active = ?, role = ? WHERE id = ?", (active, role, user_id))
    db.commit()
    return jsonify(ok=True)


@app.post("/api/admin/users/<int:user_id>/password")
@admin_required
def admin_reset_password(user_id):
    d = request.get_json(silent=True) or {}
    new = d.get("password")
    if not isinstance(new, str) or not 8 <= len(new) <= 128:
        return err("Password must be 8 to 128 characters.")
    db = get_db()
    if not db.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone():
        abort(404)
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new), user_id))
    db.commit()
    return jsonify(ok=True)


@app.delete("/api/admin/users/<int:user_id>")
@admin_required
def admin_delete_user(user_id):
    if user_id == g.user["id"]:
        return err("You cannot delete your own account.")
    db = get_db()
    if not db.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone():
        abort(404)
    files = db.execute("SELECT f.stored_name FROM case_files f JOIN cases c ON c.id = f.case_id "
                       "WHERE c.user_id = ?", (user_id,)).fetchall()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    remove_stored_files(files)
    return jsonify(ok=True)


@app.get("/api/admin/cases")
@admin_required
def admin_cases():
    q = clean(request.args.get("q"), 100)
    sql = ("SELECT c.id, c.case_number, c.title, c.court, c.status, c.client_name, c.updated_at, "
           "u.name AS lawyer, u.email AS lawyer_email, "
           "(SELECT MIN(hearing_date) FROM hearings h WHERE h.case_id = c.id AND h.hearing_date >= :now) AS next_hearing "
           "FROM cases c JOIN users u ON u.id = c.user_id")
    params = {"now": now_str()}
    if q:
        sql += (" WHERE c.title LIKE :q ESCAPE '\\' OR c.case_number LIKE :q ESCAPE '\\' "
                "OR c.client_name LIKE :q ESCAPE '\\' OR u.name LIKE :q ESCAPE '\\'")
        params["q"] = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    sql += " ORDER BY c.updated_at DESC LIMIT 500"
    return jsonify(cases=[dict(r) for r in get_db().execute(sql, params).fetchall()])


# --------------------------------------------------------------------------- command line
def create_admin(email, password, name="Administrator"):
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        sys.exit("That email address does not look valid.")
    if len(password) < 8:
        sys.exit("Password must be at least 8 characters.")
    init_db()
    conn = connect()
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.execute("UPDATE users SET role='admin', active=1, password_hash=? WHERE id=?",
                     (generate_password_hash(password), existing["id"]))
        print(f"Updated existing account {email}: now an admin with the new password.")
    else:
        conn.execute("INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?,?,?,'admin',?)",
                     (name, email, generate_password_hash(password), stamp()))
        print(f"Admin account created: {email}")
    conn.commit()
    conn.close()


init_db()

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "create-admin":
        if len(sys.argv) < 4:
            sys.exit('Usage: python app.py create-admin EMAIL "PASSWORD" ["Full Name"]')
        create_admin(sys.argv[2], sys.argv[3], *(sys.argv[4:5]))
    else:
        app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)),
                debug=os.environ.get("MIHU_DEBUG") == "1")
